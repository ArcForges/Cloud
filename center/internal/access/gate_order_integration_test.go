// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The order of the stages of Authorize, the fail-closed branches and the audit rows of the stages, pinned by their effects
// (EVIDENCE: REAL pipeline, REAL verifier, REAL store, REAL entitlement service and gate; the operations are test-only rows).

// counter is a resource control that only counts the calls it was asked about.
type counter struct{ runs atomic.Int32 }

func (c *counter) control(context.Context, *ingress.Call, Operation) error {
	c.runs.Add(1)
	return nil
}

// TestResourceControlsAreChargedOnlyByCallsEveryEarlierStageAdmitted is gate-1: a counting control stands for the owner's rate or
// quota budget. A call that authentication, ownership, scope and risk or the AGENT/HUMAN separation refused must not have charged it,
// and the stages 2, 3 and 4 decide in that order (the refusal of a foreign device is not_found whoever asks, and a restricted
// account is refused as restricted before its principal is looked at).
func TestResourceControlsAreChargedOnlyByCallsEveryEarlierStageAdmitted(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := r.db.Account(1)
	r.grant(account, 30, gatedKeys()...)
	human, humanDevice := r.credential(account, session.ScopeAccount)
	node, _ := r.credential(account, session.ScopeNode)
	automation, _ := r.credential(account, session.ScopeAutomation)
	push, _ := r.credential(account, session.ScopePush)
	limited, _ := r.credential(account, session.ScopeMobileLimited)
	restricted := r.db.Account(2)
	restrictedHuman, _ := r.credential(restricted, session.ScopeAccount)
	restrictedNode, _ := r.credential(restricted, session.ScopeNode)
	_, foreignDevice := r.credential(r.db.Account(1), session.ScopeAccount)
	foreign := map[string]string{"X-Probe-Device": foreignDevice.String()}

	var charged counter
	*r.controls = []Control{charged.control}
	refused := []struct {
		name, operation, token string
		header                 map[string]string
		key                    string
	}{
		{"a node credential on a HUMAN operation", "RemoteView", node, nil, "AUTHORIZATION/permission_denied"},
		{"an automation credential on a HUMAN operation", "Push", automation, nil, "AUTHORIZATION/permission_denied"},
		{"an account session on an AGENT operation", "Agent", human, nil, "AUTHORIZATION/permission_denied"},
		{"a push credential", "RemoteView", push, nil, "AUTHORIZATION/permission_denied"},
		{"a restricted account", "RemoteView", restrictedHuman, nil, "AUTHORIZATION/permission_denied"},
		{"a restricted account with an AGENT credential on a HUMAN operation", "RemoteView", restrictedNode, nil, "AUTHORIZATION/permission_denied"},
		{"a mobile.limited session that must upgrade", "Upgrade", limited, nil, "AUTHENTICATION/step_up_required"},
		{"a foreign device", "Device", human, foreign, "STATE/not_found"},
		{"a push credential asking for a foreign device", "Device", push, foreign, "STATE/not_found"},
		{"a restricted account asking for a foreign device", "Device", restrictedHuman, foreign, "STATE/not_found"},
		{"an AGENT credential asking for a foreign device", "Device", node, foreign, "STATE/not_found"},
	}
	for _, item := range refused {
		if got, _ := r.call(item.operation, item.token, item.header); got.reached || got.failure != item.key {
			t.Errorf("%s: %+v, want %s", item.name, got, item.key)
		}
	}
	if runs := charged.runs.Load(); runs != 0 {
		t.Fatalf("%d resource controls ran for calls that an earlier stage refused", runs)
	}
	if r.gate.questions() != 0 {
		t.Fatalf("the gate was asked %d times by refused calls", r.gate.questions())
	}
	// Stage 3 comes before stage 4: a restricted account with the wrong principal is refused as restricted, not as principal; the
	// foreign devices were refused by ownership before either stage looked at them.
	for reason, count := range map[string]int{"scope": 1, "restricted": 2, "principal": 3} {
		if got := r.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND reason = $2", AuditRefused, reason); got != count {
			t.Errorf("%d access.refused events with the reason %s, want %d", got, reason, count)
		}
	}
	// The calls that every stage admits charge the control once each, and reach the gate.
	for index, item := range []struct{ operation, token string }{{"RemoteView", human}, {"Agent", node}} {
		if got, _ := r.call(item.operation, item.token, nil); !got.reached {
			t.Fatalf("%s: %+v", item.operation, got)
		}
		if runs := charged.runs.Load(); runs != int32(index+1) {
			t.Fatalf("%d resource controls ran after %d admitted calls", runs, index+1)
		}
	}
	if got, _ := r.call("Device", human, map[string]string{"X-Probe-Device": humanDevice.String()}); !got.reached || charged.runs.Load() != 3 {
		t.Fatalf("an own device: %+v, %d controls", got, charged.runs.Load())
	}
	// A control that refuses stops the call before the audit and the gate (stage 5 before 6 and 7).
	questions, authorized := r.gate.questions(), r.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", AuditAuthorized)
	*r.controls = []Control{func(context.Context, *ingress.Call, Operation) error {
		return arc.RateLimited("probe", 1, r.authorizer.clock())
	}}
	if got, _ := r.call("RemoteView", human, nil); got.reached || got.failure != "RESOURCE/rate_limited" {
		t.Fatalf("an exhausted resource: %+v", got)
	}
	if r.gate.questions() != questions || r.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", AuditAuthorized) != authorized {
		t.Fatal("a call that exhausted a resource was audited or reached the gate")
	}
}

// TestTheAuditRowsOfTheStagesAreClosed is gate-5: the actor, the target and the exact payload of one access.authorized, one
// access.gated and one access.refused row, and a high-risk row whose handler audits it gets no access.authorized from Authorize.
func TestTheAuditRowsOfTheStagesAreClosed(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := r.db.Account(1)
	r.grant(account, 30, "remote.view")
	token, device := r.credential(account, session.ScopeAccount)
	push, _ := r.credential(account, session.ScopePush)
	if got, _ := r.call("RemoteView", token, nil); !got.reached {
		t.Fatalf("%+v", got)
	}
	if got, _ := r.call("Push", token, nil); got.failure != "ENTITLEMENT/feature_not_entitled" {
		t.Fatalf("%+v", got)
	}
	if got, _ := r.call("RemoteView", push, nil); got.failure != "AUTHORIZATION/permission_denied" {
		t.Fatalf("%+v", got)
	}
	if got, _ := r.call("Sensitive", token, nil); !got.reached {
		t.Fatalf("%+v", got)
	}
	// The call addressing a device is audited with the caller as the actor, never the device or the session.
	if got, _ := r.call("Device", token, map[string]string{"X-Probe-Device": device.String()}); !got.reached {
		t.Fatalf("%+v", got)
	}
	actor := "account:" + account.String()
	rows := []struct{ eventType, operation, reason, payload string }{
		{AuditAuthorized, "probe.remote.view", "", `{"feature":"remote.view","operation":"probe.remote.view","risk":"R2","scope":"account"}`},
		{AuditAuthorized, "probe.device", "", `{"feature":"remote.view","operation":"probe.device","risk":"R2","scope":"account"}`},
		{AuditAuthorized, "probe.push", "", `{"feature":"push","operation":"probe.push","risk":"R2","scope":"account"}`},
		{AuditGated, "probe.push", "no_entitlement", `{"feature":"push","operation":"probe.push","reason":"no_entitlement"}`},
		{AuditRefused, "probe.remote.view", "scope", `{"operation":"probe.remote.view","reason":"scope","scope":"push"}`},
	}
	total := 0
	for _, row := range rows {
		var count int
		var gotActor, gotPayload, gotTarget string
		err := r.db.Migration.QueryRow(context.Background(), `SELECT count(*) OVER (), actor_ref, target_kind, convert_from(payload, 'UTF8') FROM audit.audit_event
WHERE event_type = $1 AND target_id = $2 AND reason = $3`, row.eventType, row.operation, row.reason).Scan(&count, &gotActor, &gotTarget, &gotPayload)
		if err != nil || count != 1 {
			t.Errorf("%s of %s: %d rows, %v", row.eventType, row.operation, count, err)
			continue
		}
		if gotActor != actor || gotTarget != "operation" || gotPayload != row.payload {
			t.Errorf("%s of %s: actor %q target %q payload %s", row.eventType, row.operation, gotActor, gotTarget, gotPayload)
		}
		total++
	}
	// Nothing else was appended by the stages: the three event types hold exactly these rows, and the sensitive row has none.
	if all := r.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type IN ($1, $2, $3)", AuditAuthorized, AuditGated, AuditRefused); all != total {
		t.Errorf("%d stage events, %d expected", all, total)
	}
	if r.db.Count("SELECT count(*) FROM audit.audit_event WHERE target_id = 'probe.sensitive'") != 0 {
		t.Error("Authorize audited a row whose handler audits it in the transaction of its effect")
	}
}

// TestTheGateFailsClosedWithoutAReader is gate-4: a hosted center with a valid catalogue and no entitlement store answers no
// availability and an error, never an entitlement; through Authorize it is an unavailable store and nothing is audited as gated.
func TestTheGateFailsClosedWithoutAReader(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := r.db.Account(1)
	conf := feature.Configure(feature.Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	gate := feature.NewGate(conf, nil)
	decision := gate.Availability(feature.WithAccount(context.Background(), account.String()), feature.RemoteView)
	if decision.Available || !errors.Is(decision.Err, feature.ErrNoEntitlementStore) {
		t.Fatalf("a gate without a reader: %+v", decision)
	}
	r.authorizer.gate = gate
	token, _ := r.credential(account, session.ScopeAccount)
	if got, _ := r.call("RemoteView", token, nil); got.reached || got.failure != "RESOURCE/overloaded" {
		t.Fatalf("a call behind a gate without a reader: %+v", got)
	}
	if r.audits(AuditGated, "probe.remote.view", "") != 0 {
		t.Error("a gate that could not read was audited as a refusal of the feature")
	}
}

// TestAnOwnerThatCannotBeReadIsAStoreFailureNotAMissingObject is gate-4: a database that fails while the object's owner is read must
// not tell the client that its own device does not exist.
func TestAnOwnerThatCannotBeReadIsAStoreFailureNotAMissingObject(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.SelfHosted, PushSender: true})
	account := r.db.Account(1)
	token, device := r.credential(account, session.ScopeAccount)
	got, _ := r.call("Device", token, map[string]string{"X-Probe-Device": device.String(), "X-Probe-Owner-Error": "1"})
	if got.reached || got.failure != "store-failure" {
		t.Fatalf("%+v", got)
	}
	if r.gate.questions() != 0 {
		t.Fatal("the gate was asked about a call whose object could not be read")
	}
}

// TestASubjectThatIsNotTheRowsObjectIsRefused is gate-4 and gate-8: a subject of another kind than the row's Object, and a subject
// for a row that names no Object, are handler defects and are refused as such (permission_denied, audited with the reason subject).
func TestASubjectThatIsNotTheRowsObjectIsRefused(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.SelfHosted, PushSender: true})
	account := r.db.Account(1)
	token, device := r.credential(account, session.ScopeAccount)
	own := map[string]string{"X-Probe-Device": device.String()}
	if got, _ := r.call("Device", token, own); !got.reached {
		t.Fatalf("the sanity check: %+v", got)
	}
	got, _ := r.call("Device", token, map[string]string{"X-Probe-Device": device.String(), "X-Probe-Kind": "task"})
	if got.reached || got.failure != "AUTHORIZATION/permission_denied" || got.reason != "probe.device" {
		t.Errorf("a subject of another kind: %+v", got)
	}
	got, _ = r.call("RemoteView", token, own)
	if got.reached || got.failure != "AUTHORIZATION/permission_denied" || got.reason != "probe.remote.view" {
		t.Errorf("a subject for a row that names no object: %+v", got)
	}
	if got := r.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND reason = 'subject'", AuditRefused); got != 2 {
		t.Errorf("%d access.refused events with the reason subject, want 2", got)
	}
}

// failing is a gate that answers one failure.
type failing struct{ err error }

func (f failing) Availability(context.Context, feature.Key) feature.Decision {
	return feature.Decision{Reason: feature.ReasonEntitlementUnavailable, Err: f.err}
}

// TestGateFailuresAreAnsweredAsTheDesignCatalogueSays is gate-3: a gate that cannot decide is an unavailable store
// (RESOURCE/overloaded, the call did not happen) when the failure is the store's (a commit without an answer, a refresh that lost
// its race on every attempt, a center without an entitlement store); a store.Error keeps its own classification for the transport;
// anything else is a defect and stays what it is for INTERNAL/internal. None of them is audited as a gated refusal.
func TestGateFailuresAreAnsweredAsTheDesignCatalogueSays(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := r.db.Account(1)
	token, _ := r.credential(account, session.ScopeAccount)
	defect := errors.New("a defect of the history")
	unanswered := &store.Error{Operation: "commit", Kind: store.ErrCommitUnknown}
	cases := []struct {
		name string
		err  error
		// want is the refusal key, or "store-failure" for an error that is passed on as it is.
		want string
	}{
		{"a commit without an answer", &entitlement.Refusal{Kind: entitlement.RefusedOutcomeUnknown, Detail: "unanswered"}, "RESOURCE/overloaded"},
		{"a store commit without an answer", unanswered, "RESOURCE/overloaded"},
		{"a refresh that lost its race on every attempt", &entitlement.Refusal{Kind: entitlement.RefusedConcurrentUpdate, Detail: "concurrent"}, "RESOURCE/overloaded"},
		{"no entitlement store", feature.ErrNoEntitlementStore, "RESOURCE/overloaded"},
		{"no entitlement store, wrapped", fmt.Errorf("gate: %w", feature.ErrNoEntitlementStore), "RESOURCE/overloaded"},
		{"an unreachable store", &store.Error{Operation: "read the entitlement snapshot", Kind: store.ErrUnavailable}, "store-failure"},
		{"a canceled context", context.Canceled, "store-failure"},
		{"a defect", defect, "store-failure"},
		{"an invalid history", &entitlement.Refusal{Kind: entitlement.RefusedInvalidHistory, Detail: "history"}, "store-failure"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			r.authorizer.gate = failing{err: item.err}
			got, _ := r.call("RemoteView", token, nil)
			if got.reached || got.failure != item.want {
				t.Fatalf("%+v, want %s", got, item.want)
			}
			if r.audits(AuditGated, "probe.remote.view", "") != 0 {
				t.Error("a gate failure was audited as a refusal of the feature")
			}
			// What the transport does with it: the failure itself keeps its classification.
			if err := gateFailure(item.err); item.want == "store-failure" && err != item.err {
				t.Errorf("gateFailure changed %v into %v", item.err, err)
			}
		})
	}
	// The sentinels themselves, without a wrapper.
	for _, err := range []error{store.ErrCommitUnknown, feature.ErrNoEntitlementStore} {
		var refusal *arc.Refusal
		if !errors.As(gateFailure(err), &refusal) || refusal.Key() != "RESOURCE/overloaded" {
			t.Errorf("gateFailure(%v) = %v", err, gateFailure(err))
		}
	}
}

// TestAFailedRefusalAuditIsNotSwallowed is gate-8: the append of access.refused fails inside PostgreSQL itself, and the caller gets
// the store failure, not a refusal that left no trace.
func TestAFailedRefusalAuditIsNotSwallowed(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.SelfHosted, PushSender: true})
	account := r.db.Account(1)
	push, _ := r.credential(account, session.ScopePush)
	r.db.Exec("CREATE SCHEMA testfault",
		"CREATE FUNCTION testfault.refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'access.refused' THEN RAISE EXCEPTION 'the audit is refused (test)' USING ERRCODE = '57P01'; END IF; RETURN NEW; END; $$",
		"CREATE TRIGGER test_refuse BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION testfault.refuse()")
	if got, _ := r.call("RemoteView", push, nil); got.reached || got.failure != "store-failure" {
		t.Fatalf("a refusal that cannot be audited: %+v", got)
	}
}

// TestAnUnknownMethodAndAnUnauthenticatedCallAreRefused is gate-8 (A38): a method that has no row is refused, never admitted.
func TestAnUnknownMethodAndAnUnauthenticatedCallAreRefused(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.SelfHosted})
	unknown := &ingress.Call{Policy: ingress.Policy{FullName: probePrefix + "Nothing"}}
	var refusal *arc.Refusal
	if _, err := r.authorizer.Authorize(context.Background(), unknown); !errors.As(err, &refusal) || refusal.Key() != "AUTHORIZATION/permission_denied" {
		t.Fatalf("an unknown method: %v", err)
	}
}

// TestACheckedTableRefusesARowThatContradictsItselfAndARowTwice is gate-8 (C14, C18): the table check runs CheckRow on every served
// row and refuses a path named twice.
func TestACheckedTableRefusesARowThatContradictsItselfAndARowTwice(t *testing.T) {
	row := Operation{Path: probePrefix + "RemoteView", ID: "probe.remote.view", Risk: "R2", Session: true, Feature: feature.RemoteView, Audit: AuditBeforeCall}
	policy, err := ingress.NewUnary(row.Path, ingress.Session, ingress.NoScope, 4096, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = checkTable([]Operation{row}, []ingress.Policy{policy}); err != nil {
		t.Fatal(err)
	}
	if checkTable([]Operation{row, row}, []ingress.Policy{policy}) == nil {
		t.Error("a path named twice was admitted")
	}
	broken := row
	broken.Audit = NoAudit
	if checkTable([]Operation{broken}, []ingress.Policy{policy}) == nil {
		t.Error("a served row that contradicts itself was admitted")
	}
}
