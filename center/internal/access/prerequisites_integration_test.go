// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The prerequisites of the first gated operation in the authorizer (AF-CTR-05 part E0; EVIDENCE: REAL ingress pipeline, REAL bearer
// verifier, REAL PostgreSQL, REAL entitlement service and gate; MOCKED: the test-only probe rows of gate_integration_test.go, and the
// fault injection of a commit without an answer and of a refresh that lost its race, which a stub gate answers; a center without an
// entitlement store and a replica of superseded definitions are the real gate over the real store).

// otherDefinitions is the catalogue's definitions under another version: the definitions of a revision that started after this one.
type otherDefinitions struct {
	inner   entitlement.DefinitionSource
	version string
}

func (o otherDefinitions) Current() entitlement.Definitions {
	definitions := o.inner.Current()
	definitions.Version = o.version
	return definitions
}

// TestEachGateFailureCauseIsLoggedAndAudited is E0-3 (gate-3): each cause a gate cannot decide on answers RESOURCE/overloaded, wraps
// its cause (errors.Is finds it behind the refusal), appends exactly one access.gateFailure row with its closed reason, the payload of
// the operation, the feature and the reason (no request text) and the call's correlation ID, appends no access.gated row, and writes
// its log line with the correlation ID and the reason.
func TestEachGateFailureCauseIsLoggedAndAudited(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	unknown := &entitlement.Refusal{Kind: entitlement.RefusedOutcomeUnknown, Detail: "unanswered"}
	contended := &entitlement.Refusal{Kind: entitlement.RefusedConcurrentUpdate, Detail: "concurrent"}
	unanswered := &store.Error{Operation: "store the entitlement snapshot", Kind: store.ErrCommitUnknown}
	cases := []struct {
		name, reason string
		cause        error
		// gate is the gate of the case; nil sets the stub that answers the cause.
		gate func() feature.Gate
	}{
		{"a commit without an answer", GateFailureCommitUnknown, unknown, nil},
		{"a store commit without an answer", GateFailureCommitUnknown, unanswered, nil},
		{"a refresh that lost its race on every attempt", GateFailureRefreshContended, contended, nil},
		{"no entitlement store (the real gate without a reader)", GateFailureNoEntitlementStore, feature.ErrNoEntitlementStore,
			func() feature.Gate { return feature.NewGate(r.conf, nil) }},
		{"a replica of superseded definitions (the real gate and store)", GateFailureDefinitionsSuperseded, entitlement.ErrDefinitionsSuperseded,
			func() feature.Gate {
				// A newer revision started with other definitions and recorded them; this replica's service may not compute.
				newer := entitlement.NewService(r.db.Runtime, otherDefinitions{inner: r.conf, version: "dev-next"}, nil, nil)
				if _, err := newer.RecordDefinitions(context.Background(), time.Now()); err != nil {
					t.Fatal(err)
				}
				return feature.NewGate(r.conf, r.service)
			}},
	}
	if len(cases) != len(GateFailureReasons())+1 {
		t.Fatalf("%d cases for %d reasons", len(cases), len(GateFailureReasons()))
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			account := r.db.Account(1)
			token, _ := r.credential(account, session.ScopeAccount)
			if item.gate == nil {
				r.authorizer.gate = failing{err: item.cause}
			} else {
				r.authorizer.gate = item.gate()
			}
			before := r.audits(AuditGateFailure, "probe.remote.view", item.reason)
			got, _ := r.call("RemoteView", token, nil)
			if got.reached || got.failure != "RESOURCE/overloaded" {
				t.Fatalf("%+v, want RESOURCE/overloaded", got)
			}
			if !errors.Is(r.lastErr, item.cause) {
				t.Errorf("the answer does not wrap its cause: %v", r.lastErr)
			}
			var failure *GateFailure
			if !errors.As(r.lastErr, &failure) || failure.Reason != item.reason {
				t.Fatalf("the answer is no gate failure of %s: %v", item.reason, r.lastErr)
			}
			if r.audits(AuditGateFailure, "probe.remote.view", item.reason) != before+1 {
				t.Fatalf("the cause wrote %d access.gateFailure rows", r.audits(AuditGateFailure, "probe.remote.view", item.reason)-before)
			}
			var payload, actor string
			var correlated bool
			if err := r.db.Migration.QueryRow(context.Background(), `SELECT convert_from(payload, 'UTF8'), actor_ref, correlation_id IS NOT NULL FROM audit.audit_event
WHERE event_type = $1 AND target_id = 'probe.remote.view' AND actor_ref = $2`, AuditGateFailure, "account:"+account.String()).Scan(&payload, &actor, &correlated); err != nil {
				t.Fatal(err)
			}
			if want := `{"feature":"remote.view","operation":"probe.remote.view","reason":"` + item.reason + `"}`; payload != want || !correlated {
				t.Errorf("the row: %s (correlated %v), want %s", payload, correlated, want)
			}
			if r.audits(AuditGated, "probe.remote.view", "") != 0 {
				t.Error("a gate failure was audited as a refusal of the feature")
			}
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			if !LogGateFailure(context.Background(), logger, "probe.method", "0123456789abcdef0123456789abcdef", r.lastErr) {
				t.Fatal("no log line for a gate failure")
			}
			var line map[string]any
			if err := json.Unmarshal(logs.Bytes(), &line); err != nil {
				t.Fatal(err)
			}
			if line["msg"] != "the feature gate could not decide" || line["reason"] != item.reason || line["correlationId"] != "0123456789abcdef0123456789abcdef" ||
				line["method"] != "probe.method" || !strings.Contains(line["error"].(string), item.cause.Error()) || line["level"] != "WARN" {
				t.Errorf("the log line: %s", logs.String())
			}
		})
	}
	// Anything else is no gate failure and writes neither a line nor a row.
	var logs bytes.Buffer
	if LogGateFailure(context.Background(), slog.New(slog.NewJSONHandler(&logs, nil)), "m", "c", arc.Unavailable()) || logs.Len() != 0 {
		t.Error("a plain refusal was logged as a gate failure")
	}
	if _, ok := NewGateFailure(&store.Error{Operation: "read", Kind: store.ErrUnavailable}); ok {
		t.Error("a store failure was made a gate failure")
	}
}

// TestAControlRunsBeforeTheAuditAndTheGate is E0-5 (CTR5-GATE-05): a counting control sees, at each call it admits, neither that
// call's access.authorized row nor its gate question; and once it refuses (the account is exhausted) the call writes no
// access.authorized row, asks the gate nothing and reaches no handler code.
func TestAControlRunsBeforeTheAuditAndTheGate(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := r.db.Account(1)
	r.grant(account, 30, gatedKeys()...)
	token, _ := r.credential(account, session.ScopeAccount)
	var authorizedSeen, questionsSeen []int
	exhausted := false
	*r.controls = []Control{ControlFunc{Key: "counting", Check: func(_ context.Context, _ *ingress.Call, operation Operation) error {
		authorizedSeen = append(authorizedSeen, r.audits(AuditAuthorized, operation.ID, ""))
		questionsSeen = append(questionsSeen, r.gate.questions())
		if exhausted {
			return arc.RateLimited("counting", 2, time.Now().Add(time.Minute))
		}
		return nil
	}}}
	for index := range 2 {
		if got, _ := r.call("RemoteView", token, nil); !got.reached {
			t.Fatalf("call %d: %+v", index, got)
		}
	}
	for index := range 2 {
		if authorizedSeen[index] != index || questionsSeen[index] != index {
			t.Fatalf("call %d: the control saw %d access.authorized rows and %d gate questions, want %d of each (it ran after the audit or the gate)",
				index, authorizedSeen[index], questionsSeen[index], index)
		}
	}
	exhausted = true
	if got, _ := r.call("RemoteView", token, nil); got.reached || got.failure != "RESOURCE/rate_limited" {
		t.Fatalf("an exhausted account: %+v", got)
	}
	if got := r.audits(AuditAuthorized, "probe.remote.view", ""); got != 2 {
		t.Errorf("an exhausted account's call wrote an access.authorized row: %d rows", got)
	}
	if r.gate.questions() != 2 || r.audits(AuditGated, "probe.remote.view", "") != 0 || r.audits(AuditGateFailure, "probe.remote.view", "") != 0 {
		t.Error("an exhausted account's call reached the gate")
	}
	// A control covers only its rows: one that covers none is never asked.
	asked := false
	*r.controls = []Control{ControlFunc{Key: "elsewhere", Rows: func(Operation) bool { return false }, Check: func(context.Context, *ingress.Call, Operation) error {
		asked = true
		return arc.RateLimited("elsewhere", 1, time.Now())
	}}}
	if got, _ := r.call("RemoteView", token, nil); !got.reached || asked {
		t.Errorf("a control that does not cover the row: %+v, asked %v", got, asked)
	}
}

// TestEveryFeatureRowCarriesTheKeyOfItsGroup is E0-6 (CTR5-SUR-04, CTR5-GATE-06): every row of the operation table that carries a
// Feature names its group of the routed task control table and carries that group's key (the set is empty at E0: AF-CTR-05 E1 and E2
// add the rows and this test keeps holding); a row without a Feature names no group. The table-driven negative fabricates a row for
// every group with every gated key and every malformed group: only the key of the row's own group is admitted, by CheckRow and by the
// composition's table check.
func TestEveryFeatureRowCarriesTheKeyOfItsGroup(t *testing.T) {
	gated := 0
	for _, operation := range Operations() {
		if operation.Feature == "" {
			if operation.Group != "" {
				t.Errorf("%s names the group %s without a Feature", operation.ID, operation.Group)
			}
			continue
		}
		gated++
		if key, named := feature.KeyOfGroup(operation.Group); !named || key != operation.Feature {
			t.Errorf("%s carries %s, its group %q names %q", operation.ID, operation.Feature, operation.Group, key)
		}
		if err := CheckRow(operation); err != nil {
			t.Error(err)
		}
	}
	t.Logf("%d gated rows in the operation table", gated)
	row := func(key feature.Key, group feature.Group) Operation {
		return Operation{Path: probePrefix + "Fabricated", ID: "probe.fabricated", Risk: "R2", Session: true, Feature: key, Group: group, Audit: AuditBeforeCall}
	}
	policy, err := ingress.NewUnary(probePrefix+"Fabricated", ingress.Session, ingress.NoScope, 4096, false)
	if err != nil {
		t.Fatal(err)
	}
	cases := 0
	for _, group := range feature.OperationKeys() {
		for _, key := range feature.Gated() {
			cases++
			fabricated := row(key, group.Group)
			rowErr, tableErr := CheckRow(fabricated), checkTable([]Operation{fabricated}, []ingress.Policy{policy})
			if key == group.Key {
				if rowErr != nil || tableErr != nil {
					t.Errorf("the key %s of the group %s was refused: %v %v", key, group.Group, rowErr, tableErr)
				}
				continue
			}
			if rowErr == nil || tableErr == nil || !strings.Contains(rowErr.Error(), "the key of its group") {
				t.Errorf("a %s row carrying %s was admitted: %v %v", group.Group, key, rowErr, tableErr)
			}
		}
	}
	for name, fabricated := range map[string]Operation{
		"a gated row without a group":       row(feature.RemoteView, ""),
		"a gated row of an unknown group":   row(feature.RemoteView, "status"),
		"a group on an essential row":       {Path: probePrefix + "Fabricated", ID: "probe.fabricated", Risk: "R1", Session: true, Group: feature.GroupStatusAndOutput},
		"a group on an essential R3 row":    {Path: probePrefix + "Fabricated", ID: "probe.fabricated", Risk: "R3", Session: true, Group: feature.GroupControl, Audit: AuditInTransaction},
		"the push key on the control group": row(feature.Push, feature.GroupControl),
	} {
		cases++
		if CheckRow(fabricated) == nil {
			t.Errorf("%s was admitted", name)
		}
	}
	if cases != len(feature.OperationKeys())*len(feature.Gated())+5 {
		t.Fatalf("%d cases", cases)
	}
}

// TestAGatedRowWithoutAControlFailsComposition is E0-7 (CTR5-GATE-05): the composition rule refuses a table whose gated row no
// registered control covers, names the row, refuses a control without a name, and admits the table once every gated row is covered.
func TestAGatedRowWithoutAControlFailsComposition(t *testing.T) {
	rows := probeRows()
	if err := CheckControls(rows, nil); err == nil || !strings.Contains(err.Error(), "has no resource control") {
		t.Fatalf("a table of gated rows without controls: %v", err)
	}
	routed := ControlFunc{Key: "routed", Rows: func(operation Operation) bool {
		return operation.Group == feature.GroupSubmission || operation.Group == feature.GroupStatusAndOutput || operation.Group == feature.GroupControl
	}}
	err := CheckControls(rows, []Control{routed})
	if err == nil || !strings.Contains(err.Error(), probePrefix+"CenterNodes") && !strings.Contains(err.Error(), probePrefix+"CenterMcp") &&
		!strings.Contains(err.Error(), probePrefix+"Push") && !strings.Contains(err.Error(), probePrefix+"Agent") {
		t.Fatalf("gated rows of other groups without a control: %v", err)
	}
	everything := ControlFunc{Key: "everything", Rows: func(operation Operation) bool { return operation.Feature != "" }}
	if err = CheckControls(rows, []Control{routed, everything}); err != nil {
		t.Fatalf("every gated row covered: %v", err)
	}
	if CheckControls(rows, []Control{everything, ControlFunc{Rows: everything.Rows}}) == nil {
		t.Fatal("a control without a name was admitted")
	}
	// N-9 (routed from E0): the served table has its first gated row (fleet.nodeChannel, AF-CTR-05 E1a), so a composition without a
	// control in front of the node connection group fails, and one with it composes; the essential rows need none.
	if err = CheckControls(Operations(), nil); err == nil || !strings.Contains(err.Error(), "/fleet/v1/node") {
		t.Fatalf("the served operation table without a control: %v", err)
	}
	if err = NewAuthorizer(nil, nil, WithControls(routed)).CheckComposition(); err == nil || !strings.Contains(err.Error(), "/fleet/v1/node") {
		t.Fatalf("an authorizer whose controls omit the node connection group: %v", err)
	}
	channel := ControlFunc{Key: "channel", Rows: func(operation Operation) bool { return operation.Group == feature.GroupNodeConnection }}
	if err = NewAuthorizer(nil, nil, WithControls(routed, channel)).CheckComposition(); err != nil {
		t.Fatalf("an authorizer over the served table: %v", err)
	}
}
