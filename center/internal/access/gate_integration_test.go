// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The gate of Authorize behind the real ingress pipeline and the real bearer verifier, over real PostgreSQL (F9; EVIDENCE: REAL
// pipeline, REAL verifier, REAL store, REAL entitlement service and gate). What is MOCKED: the operations are test-only rows of a
// probe service (the center serves no gated operation until AF-CTR-04), the handler behind the pipeline only reports what happened,
// the plan catalogue is the illustrative development fixture or a test-injected production-classified document, and the evidence
// of an operator grant is stubbed (the step-up consumption is tested in package entitlement).

const probePrefix = "/arcforges.test.v1.GateProbe/"

// method is the probe method name of a key: center.nodes is CenterNodes.
func method(key feature.Key) string {
	var name strings.Builder
	for _, part := range strings.Split(string(key), ".") {
		name.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return name.String()
}

// probeRows are the test-only operations: one gated HUMAN operation per key, an AGENT one, one that addresses a device, one that a
// mobile.limited session must upgrade for, and an essential one.
func probeRows() []Operation {
	var rows []Operation
	for _, key := range feature.Gated() {
		rows = append(rows, Operation{Path: probePrefix + method(key), ID: "probe." + string(key), Risk: "R2", Session: true, Feature: key, Audit: AuditBeforeCall})
	}
	return append(rows,
		Operation{Path: probePrefix + "Agent", ID: "probe.agent", Risk: "R2", Session: true, Agent: true, Feature: feature.CenterNodes, Audit: AuditBeforeCall},
		Operation{Path: probePrefix + "Device", ID: "probe.device", Risk: "R2", Session: true, Object: "device", Feature: feature.RemoteView, Audit: AuditBeforeCall},
		Operation{Path: probePrefix + "Upgrade", ID: "probe.upgrade", Risk: "R2", Session: true, MobileLimited: Upgrade, Feature: feature.CenterExecute, Audit: AuditBeforeCall},
		Operation{Path: probePrefix + "Essential", ID: "probe.essential", Risk: "R1", Session: true},
		// A high-risk essential row is audited by its own handler, in the transaction of its effect: Authorize appends nothing for it.
		Operation{Path: probePrefix + "Sensitive", ID: "probe.sensitive", Risk: "R3", Session: true, Audit: AuditInTransaction},
	)
}

// spy delegates to the real gate and remembers every question, and what had been audited when it was asked.
type spy struct {
	inner feature.Gate
	db    *dbtest.Database
	mu    sync.Mutex
	asked []feature.Key
	// authorizedWhenAsked says, per question, whether an access.authorized event naming the key existed already.
	authorizedWhenAsked []bool
}

func (s *spy) Availability(ctx context.Context, key feature.Key) feature.Decision {
	// The question is asked after the call's audit: the event naming the key exists by now.
	authorized := s.db.Count(`SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND convert_from(payload, 'UTF8') LIKE $2`, AuditAuthorized, `%"feature":"`+string(key)+`"%`) > 0
	s.mu.Lock()
	s.asked = append(s.asked, key)
	s.authorizedWhenAsked = append(s.authorizedWhenAsked, authorized)
	s.mu.Unlock()
	return s.inner.Availability(ctx, key)
}

func (s *spy) questions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.asked)
}

// answer is what the probe handler reports about a call that went through the pipeline.
type answer struct {
	reached bool
	failure string // the refusal key, or "store-failure"
	reason  string // the refusal's state.reason
}

type rig struct {
	t          *testing.T
	db         *dbtest.Database
	pipeline   http.Handler
	gate       *spy
	authorizer *Authorizer
	service    *entitlement.Service
	operator   *entitlement.Operator
	conf       feature.Configuration
	handled    int
	controls   *[]Control
}

func newRig(t *testing.T, settings feature.Settings) *rig {
	t.Helper()
	db := dbtest.New(t)
	conf := feature.Configure(settings)
	service := entitlement.NewService(db.Runtime, conf, nil, nil)
	gate := &spy{inner: feature.NewGate(conf, service), db: db}
	controls := &[]Control{}
	authorizer := NewAuthorizer(db.Runtime, nil, WithGate(gate), WithControls(func(ctx context.Context, call *ingress.Call, operation Operation) error {
		for _, control := range *controls {
			if err := control(ctx, call, operation); err != nil {
				return err
			}
		}
		return nil
	}))
	rows := map[string]Operation{}
	for _, row := range probeRows() {
		if err := CheckRow(row); err != nil {
			t.Fatal(err)
		}
		rows[row.Path] = row
	}
	authorizer.lookup = func(path string) (Operation, bool) { row, ok := rows[path]; return row, ok }
	var policies []ingress.Policy
	for _, row := range probeRows() {
		policy, err := ingress.NewUnary(row.Path, ingress.Session, ingress.NoScope, 4096, false)
		if err != nil {
			t.Fatal(err)
		}
		policies = append(policies, policy)
	}
	registry, err := ingress.NewRegistry(policies...)
	if err != nil {
		t.Fatal(err)
	}
	verifier := session.NewVerifier(db.Runtime, "https://center.example.test", nil)
	r := &rig{t: t, db: db, gate: gate, authorizer: authorizer, service: service, conf: conf, controls: controls,
		operator: entitlement.NewOperator(db.Runtime, service, conf.OperatorGrants, nil)}
	r.pipeline = ingress.NewPipeline(ingress.Options{Routes: ingress.NewRoutes(registry, nil, nil), Bearer: verifier, Browser: verifier}, http.HandlerFunc(r.handle))
	return r
}

// handle is the probe service behind the pipeline: it asks Authorize and reports what happened; reaching the end is the business
// code of a real operation.
func (r *rig) handle(writer http.ResponseWriter, request *http.Request) {
	r.handled++
	call, ok := ingress.CallFrom(request.Context())
	if !ok {
		r.t.Error("a request reached the probe handler without a call")
		return
	}
	var subject *Subject
	if raw := request.Header.Get("X-Probe-Device"); raw != "" && request.Header.Get("X-Probe-No-Subject") == "" {
		id := correlation.IDBytes(raw)
		kind := "device"
		if other := request.Header.Get("X-Probe-Kind"); other != "" {
			kind = other
		}
		subject = &Subject{Kind: kind, ID: id, Owner: func(ctx context.Context) (string, bool, error) {
			if request.Header.Get("X-Probe-Owner-Error") != "" {
				return "", false, &store.Error{Operation: "read a device", Kind: store.ErrUnavailable}
			}
			var owner string
			err := r.db.Runtime.InTx(ctx, "read a device", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
				err := tx.QueryRow(ctx, "SELECT user_id::text FROM device.device WHERE device_id = $1", raw).Scan(&owner)
				if errors.Is(err, pgx.ErrNoRows) {
					owner = ""
					return nil
				}
				return err
			})
			return owner, owner != "", err
		}}
	}
	_, err := r.authorizer.AuthorizeSubject(request.Context(), call, subject)
	var refusal *arc.Refusal
	switch {
	case err == nil:
		writer.Header().Set("X-Probe", "reached")
	case errors.As(err, &refusal):
		writer.Header().Set("X-Probe", refusal.Key())
		writer.Header().Set("X-Probe-Reason", refusal.Reason)
	default:
		writer.Header().Set("X-Probe", "store-failure")
	}
}

// call sends one request through the pipeline and reports what the handler said; a request the pipeline refused never reaches it.
func (r *rig) call(operation string, token string, header map[string]string) (answer, *httptest.ResponseRecorder) {
	r.t.Helper()
	request := httptest.NewRequest(http.MethodPost, probePrefix+operation, bytes.NewReader(nil))
	request.Header.Set("Content-Type", "application/grpc-web+proto")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	for name, value := range header {
		request.Header.Set(name, value)
	}
	before := r.handled
	recorder := httptest.NewRecorder()
	r.pipeline.ServeHTTP(recorder, request)
	if r.handled == before {
		return answer{}, recorder
	}
	outcome := recorder.Header().Get("X-Probe")
	return answer{reached: outcome == "reached", failure: strings.TrimPrefix(outcome, "reached"), reason: recorder.Header().Get("X-Probe-Reason")}, recorder
}

func (r *rig) audits(eventType, operation, reason string) int {
	r.t.Helper()
	query := "SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND target_id = $2"
	arguments := []any{eventType, operation}
	if reason != "" {
		query += " AND reason = $3"
		arguments = append(arguments, reason)
	}
	return r.db.Count(query, arguments...)
}

// credential issues a live native session of a scope for an account and returns its bearer token and device.
func (r *rig) credential(user platform.ID, scope session.Scope) (string, platform.ID) {
	r.t.Helper()
	ctx := context.Background()
	tx, err := r.db.Migration.Begin(ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := time.Now()
	grant := session.Grant{UserID: user, Scope: scope, Purpose: session.PurposeAuthenticate, AuthMethod: 1, AuthenticatedAt: now}
	grant.DeviceID, grant.InstallationID, grant.Product = platform.NewID(), platform.NewID(), device.ProductMobile
	platformNumber, platformText := int16(device.PlatformAndroid), "android-15"
	if scope == session.ScopeNode {
		grant.Product, platformNumber, platformText = device.ProductNode, int16(device.PlatformLinux), "linux-x64"
	}
	if _, err = tx.Exec(ctx, `INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev)
VALUES ($1, $2, 'Probe', $3, 1, false, $4, $4, 1)`, grant.DeviceID, user, platformNumber, now); err != nil {
		r.t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev)
VALUES ($1, $2, $3, $4, '1.0.0', $5, $6, $6, 1)`, grant.InstallationID, grant.DeviceID, user, grant.Product, platformText, now); err != nil {
		r.t.Fatal(err)
	}
	native, err := session.IssueNative(ctx, tx, config.DefaultIdentityPolicy(), grant, now)
	if err != nil {
		r.t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		r.t.Fatal(err)
	}
	return native.AccessToken, grant.DeviceID
}

// grant gives an account the keys through the real operator grant (the step-up evidence is stubbed: MOCKED).
func (r *rig) grant(account platform.ID, days int, keys ...string) {
	r.t.Helper()
	operator := r.db.Account(1)
	r.db.Exec("INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '" + operator.String() +
		"', now() - interval '1 day', now() + interval '30 days', 'operator:cli', 'test operator')")
	_, err := r.operator.Grant(context.Background(), entitlement.GrantCall{Caller: entitlement.OperatorCaller{UserID: operator, Scope: "account"},
		Request: entitlement.OperatorRequest{Account: account.String(), Features: keys, Reason: "goodwill", ExpiresAt: entitlement.FromTime(time.Now().Add(time.Duration(days) * 24 * time.Hour)),
			SourceRef: "ticket-" + platform.NewID().String()[:8]},
		CommandID: platform.NewID(),
		Consume:   func(context.Context, pgx.Tx, [32]byte, time.Time) error { return nil }})
	if err != nil {
		r.t.Fatal(err)
	}
}

const productionCatalogue = `{"version":"2026-q4","fixture":false,"capabilities":["center.nodes","center.execute","remote.view","remote.control","center.mcp","push"],
"plans":[{"id":"plan-test","name":"Plan under test","features":["remote.view","push"]}]}`

var fixtureCatalogue = `{"version":"dev-test","fixture":true,"capabilities":["center.nodes","center.execute","remote.view","remote.control","center.mcp","push"],
"plans":[{"id":"fixture-all","name":"Fixture","illustrativePriceUSD":15,"features":["center.nodes","center.execute","remote.view","remote.control","center.mcp","push"]}]}`

func gatedKeys() []string {
	var keys []string
	for _, key := range feature.Gated() {
		keys = append(keys, string(key))
	}
	return keys
}

// TestEachCatalogueStateDecidesEveryGatedKey is F9: one test-only operation per key, every state of the plan configuration.
func TestEachCatalogueStateDecidesEveryGatedKey(t *testing.T) {
	hosted := func(settings feature.Settings) feature.Settings {
		settings.Mode = config.OfficialHosted
		return settings
	}
	cases := []struct {
		name     string
		settings feature.Settings
		grant    []string
		// open are the keys the call reaches; every other key is refused with the reason.
		open   []string
		reason string
	}{
		{"no plan configuration", hosted(feature.Settings{}), nil, nil, "plan_configuration_missing"},
		{"an invalid catalogue", hosted(feature.Settings{Injected: []byte("{"), InjectedClass: feature.ClassProduction}), nil, nil, "plan_configuration_invalid"},
		{"a fixture catalogue under the production classification", hosted(feature.Settings{Injected: []byte(fixtureCatalogue), InjectedClass: feature.ClassProduction}), nil, nil, "plan_configuration_invalid"},
		{"the development fixtures without a grant", hosted(feature.Settings{Plan: config.PlanDevelopmentFixtures}), nil, nil, "no_entitlement"},
		{"the development fixtures with a grant of two keys", hosted(feature.Settings{Plan: config.PlanDevelopmentFixtures}), []string{"remote.view", "push"}, []string{"remote.view", "push"}, "no_entitlement"},
		{"a production-classified test catalogue without a grant", hosted(feature.Settings{Injected: []byte(productionCatalogue), InjectedClass: feature.ClassProduction}), nil, nil, "no_entitlement"},
		{"a production-classified test catalogue with a grant", hosted(feature.Settings{Injected: []byte(productionCatalogue), InjectedClass: feature.ClassProduction}), []string{"remote.view"}, []string{"remote.view"}, "no_entitlement"},
		{"a self-hosted center", feature.Settings{Mode: config.SelfHosted, PushSender: true}, nil, gatedKeys(), ""},
		{"a self-hosted center without a push sender", feature.Settings{Mode: config.SelfHosted}, nil, []string{"center.nodes", "center.execute", "remote.view", "remote.control", "center.mcp"}, "push_sender_not_configured"},
		{"a self-hosted center with a key disabled", feature.Settings{Mode: config.SelfHosted, PushSender: true, Disabled: []feature.Key{feature.CenterExecute}},
			nil, []string{"center.nodes", "remote.view", "remote.control", "center.mcp", "push"}, "operator_limit"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			r := newRig(t, item.settings)
			account := r.db.Account(1)
			if len(item.grant) > 0 && item.settings.Mode == config.OfficialHosted && r.conf.State == feature.StateValid {
				r.grant(account, 30, item.grant...)
			}
			token, _ := r.credential(account, session.ScopeAccount)
			for _, key := range feature.Gated() {
				got, _ := r.call(method(key), token, nil)
				open := false
				for _, name := range item.open {
					open = open || name == string(key)
				}
				switch {
				case open && !got.reached:
					t.Errorf("%s: want the call to reach the operation, got %+v", key, got)
				case !open && (got.reached || got.failure != "ENTITLEMENT/feature_not_entitled" || got.reason != string(key)):
					t.Errorf("%s: want ENTITLEMENT/feature_not_entitled with state.reason = the key, got %+v", key, got)
				}
				operation := "probe." + string(key)
				// Every call is audited before the gate; a refusal is audited with the gate's reason, and a call that passed is not.
				if r.audits(AuditAuthorized, operation, "") != 1 {
					t.Errorf("%s: the call before the gate is not audited exactly once", key)
				}
				if wanted := map[bool]int{true: 0, false: 1}[open]; r.audits(AuditGated, operation, item.reason) != wanted {
					t.Errorf("%s: %d gated events with reason %q, want %d", key, r.audits(AuditGated, operation, item.reason), item.reason, wanted)
				}
			}
			if r.gate.questions() != len(feature.Gated()) {
				t.Errorf("the gate was asked %d times for %d calls", r.gate.questions(), len(feature.Gated()))
			}
			for index, authorized := range r.gate.authorizedWhenAsked {
				if !authorized {
					t.Errorf("the gate was asked about %s before the call was audited", r.gate.asked[index])
				}
			}
			if r.handled != len(feature.Gated()) {
				t.Errorf("%d calls reached the handler", r.handled)
			}
		})
	}
}

// TestAnEssentialOperationIsNeverGated: no key, no gate question, no audit, whatever the catalogue says.
func TestAnEssentialOperationIsNeverGated(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.OfficialHosted})
	token, _ := r.credential(r.db.Account(1), session.ScopeAccount)
	if got, _ := r.call("Essential", token, nil); !got.reached {
		t.Fatalf("%+v", got)
	}
	if r.gate.questions() != 0 || r.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type IN ($1, $2)", AuditAuthorized, AuditGated) != 0 {
		t.Fatal("an essential operation was gated or audited before the call")
	}
}

// TestTheGateIsNeverReachedByACallAnEarlierStageRefuses: every refusal of the earlier stages, one by one, with the gate's spy
// delegating to the real gate on a catalogue that would have admitted the caller.
func TestTheGateIsNeverReachedByACallAnEarlierStageRefuses(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := r.db.Account(1)
	r.grant(account, 30, gatedKeys()...)
	human, humanDevice := r.credential(account, session.ScopeAccount)
	node, _ := r.credential(account, session.ScopeNode)
	automation, _ := r.credential(account, session.ScopeAutomation)
	push, _ := r.credential(account, session.ScopePush)
	limited, _ := r.credential(account, session.ScopeMobileLimited)
	restricted := r.db.Account(2)
	restrictedToken, _ := r.credential(restricted, session.ScopeAccount)
	stranger := r.db.Account(1)
	_, strangerDevice := r.credential(stranger, session.ScopeAccount)
	// The sanity check: the same operation reaches the gate and is admitted for the owner.
	if got, _ := r.call("RemoteView", human, nil); !got.reached {
		t.Fatalf("the admitted call: %+v", got)
	}
	if got, _ := r.call("Agent", node, nil); !got.reached {
		t.Fatalf("the admitted agent call: %+v", got)
	}
	if got, _ := r.call("Device", human, map[string]string{"X-Probe-Device": humanDevice.String()}); !got.reached {
		t.Fatalf("the admitted device call: %+v", got)
	}
	baseline := r.gate.questions()
	if baseline != 3 {
		t.Fatalf("%d questions", baseline)
	}
	authorizedBefore := r.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", AuditAuthorized)
	refused := func(name string, got answer, key, reason string) {
		t.Helper()
		if got.reached || got.failure != key || got.reason != reason {
			t.Errorf("%s: %+v, want %s with the reason %q", name, got, key, reason)
		}
	}
	// 1. Authentication: the pipeline refuses a missing or invalid credential before any handler runs, and Authorize refuses a call
	// that has none.
	if got, recorder := r.call("RemoteView", "", nil); got.reached || recorder.Code != http.StatusOK || r.handled != 3 {
		t.Errorf("unauthenticated: %+v %d handled %d", got, recorder.Code, r.handled)
	}
	if got, _ := r.call("RemoteView", "af_at_not-a-credential-0123456789", nil); got.reached || r.handled != 3 {
		t.Errorf("a credential that is not one: %+v handled %d", got, r.handled)
	}
	bare := &ingress.Call{Policy: ingress.Policy{FullName: probePrefix + "RemoteView"}}
	var unauthenticated *arc.Refusal
	if _, err := r.authorizer.Authorize(context.Background(), bare); !errors.As(err, &unauthenticated) || unauthenticated.Key() != "AUTHENTICATION/unauthenticated" {
		t.Errorf("a call without a credential: %v", err)
	}
	// 2. Ownership: another account's device, a device that does not exist and a handler that forgot the subject.
	got, _ := r.call("Device", human, map[string]string{"X-Probe-Device": strangerDevice.String()})
	refused("a foreign device", got, "STATE/not_found", "not_found")
	notFound := got
	got, _ = r.call("Device", human, map[string]string{"X-Probe-Device": platform.NewID().String()})
	refused("a device that does not exist", got, "STATE/not_found", "not_found")
	if got != notFound {
		t.Error("a foreign device and a missing device are told apart")
	}
	got, _ = r.call("Device", human, map[string]string{"X-Probe-Device": humanDevice.String(), "X-Probe-No-Subject": "1"})
	refused("a call without its subject", got, "AUTHORIZATION/permission_denied", "probe.device")
	// An agent for a device of another account is not found either: ownership comes before the principal.
	got, _ = r.call("Device", node, map[string]string{"X-Probe-Device": strangerDevice.String()})
	refused("an agent on a foreign device", got, "STATE/not_found", "not_found")
	// 3. Scope and risk.
	got, _ = r.call("RemoteView", push, nil)
	refused("a push credential", got, "AUTHORIZATION/permission_denied", "probe.remote.view")
	got, _ = r.call("Upgrade", limited, nil)
	refused("a mobile.limited session", got, "AUTHENTICATION/step_up_required", "")
	got, _ = r.call("RemoteView", restrictedToken, nil)
	refused("a restricted account", got, "AUTHORIZATION/permission_denied", "probe.remote.view")
	// 4. AGENT/HUMAN separation, both ways.
	got, _ = r.call("RemoteView", node, nil)
	refused("a node credential on a HUMAN operation", got, "AUTHORIZATION/permission_denied", "probe.remote.view")
	got, _ = r.call("Push", automation, nil)
	refused("an automation credential on a HUMAN operation", got, "AUTHORIZATION/permission_denied", "probe.push")
	got, _ = r.call("Agent", human, nil)
	refused("an account session on an AGENT operation", got, "AUTHORIZATION/permission_denied", "probe.agent")
	// 5. Resource controls.
	*r.controls = []Control{func(context.Context, *ingress.Call, Operation) error {
		return arc.RateLimited("probe", 1, time.Now().Add(time.Minute))
	}}
	got, _ = r.call("RemoteView", human, nil)
	refused("an exhausted resource", got, "RESOURCE/rate_limited", "")
	*r.controls = nil

	if r.gate.questions() != baseline {
		t.Fatalf("the gate was asked %d times after the %d admitted calls: it was reached by a refused call (%v)", r.gate.questions(), baseline, r.gate.asked)
	}
	if r.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", AuditAuthorized) != authorizedBefore {
		t.Error("a refused call was audited as authorized")
	}
	if r.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", AuditGated) != 0 {
		t.Error("a call that the gate admitted or never saw was audited as gated")
	}
	// The refusals of stages 3 and 4 are audited with their reasons.
	for reason, count := range map[string]int{"scope": 1, "restricted": 1, "principal": 3, "subject": 1} {
		if got := r.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND reason = $2", AuditRefused, reason); got != count {
			t.Errorf("%d access.refused events with the reason %s, want %d", got, reason, count)
		}
	}
}

// TestACallThatCannotBeAuditedNeverReachesTheGate is the fault injection of F5: the audit append that comes before the gate fails in
// PostgreSQL itself, and the call is refused as an unavailable store without the gate being asked.
func TestACallThatCannotBeAuditedNeverReachesTheGate(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := r.db.Account(1)
	r.grant(account, 30, "remote.view")
	token, _ := r.credential(account, session.ScopeAccount)
	r.db.Exec("CREATE SCHEMA testfault",
		"CREATE FUNCTION testfault.refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'access.authorized' THEN RAISE EXCEPTION 'the audit is refused (test)' USING ERRCODE = '57P01'; END IF; RETURN NEW; END; $$",
		"CREATE TRIGGER test_refuse BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION testfault.refuse()")
	if got, _ := r.call("RemoteView", token, nil); got.reached || got.failure != "store-failure" {
		t.Fatalf("an unaudited call: %+v", got)
	}
	if r.gate.questions() != 0 {
		t.Fatalf("the gate was asked about an unaudited call: %v", r.gate.asked)
	}
	r.db.Exec("DROP TRIGGER test_refuse ON audit.audit_event")
	if got, _ := r.call("RemoteView", token, nil); !got.reached || r.gate.questions() != 1 {
		t.Fatalf("after the fault is gone: %+v, %d questions", got, r.gate.questions())
	}
	// A refusal of the gate whose audit fails is not silent either: the caller gets the store failure, not a refusal that left no trace.
	r.db.Exec("CREATE TRIGGER test_refuse BEFORE INSERT ON audit.audit_event FOR EACH ROW WHEN (NEW.event_type = 'access.gated') EXECUTE FUNCTION testfault.refuse()")
	r.db.Exec("CREATE OR REPLACE FUNCTION testfault.refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'the audit is refused (test)' USING ERRCODE = '57P01'; END; $$")
	if got, _ := r.call("Push", token, nil); got.reached || got.failure != "store-failure" {
		t.Fatalf("a gate refusal that cannot be audited: %+v", got)
	}
}

// TestAStoreThatCannotAnswerIsNotAMissingEntitlement: the gate's store failure is the caller's UNAVAILABLE, never a refusal that
// says the plan lacks the feature, and nothing is audited as gated.
func TestAStoreThatCannotAnswerIsNotAMissingEntitlement(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := r.db.Account(1)
	r.grant(account, 30, "remote.view")
	token, _ := r.credential(account, session.ScopeAccount)
	r.db.Exec("ALTER TABLE entitlement.snapshot RENAME TO snapshot_unavailable_for_test", "ALTER TABLE entitlement.revision RENAME TO revision_unavailable_for_test")
	got, _ := r.call("RemoteView", token, nil)
	if got.reached || got.failure != "store-failure" {
		t.Fatalf("%+v", got)
	}
	if r.gate.questions() != 1 || r.audits(AuditGated, "probe.remote.view", "") != 0 {
		t.Fatalf("%d questions, %d gated events", r.gate.questions(), r.audits(AuditGated, "probe.remote.view", ""))
	}
}

// TestAGateIsRequiredForAGatedRow: an authorizer composed without a gate refuses a gated operation (fail closed).
func TestAGateIsRequiredForAGatedRow(t *testing.T) {
	r := newRig(t, feature.Settings{Mode: config.SelfHosted})
	r.authorizer.gate = nil
	token, _ := r.credential(r.db.Account(1), session.ScopeAccount)
	got, _ := r.call("RemoteView", token, nil)
	if got.reached || got.failure != "ENTITLEMENT/feature_not_entitled" || got.reason != "remote.view" || r.audits(AuditGated, "probe.remote.view", string(feature.ReasonModeInvalid)) != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestOperationRowsAreCheckedForConsistency(t *testing.T) {
	good := Operation{Path: probePrefix + "RemoteView", ID: "probe.remote.view", Risk: "R2", Session: true, Feature: feature.RemoteView, Audit: AuditBeforeCall}
	if err := CheckRow(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Operation){
		"a feature that is not gated":                     func(o *Operation) { o.Feature = "billing" },
		"a gated row that is not audited":                 func(o *Operation) { o.Audit = NoAudit },
		"a gated row audited in its transaction":          func(o *Operation) { o.Audit = AuditInTransaction },
		"an anonymous gated row":                          func(o *Operation) { o.Session = false },
		"an anonymous agent row":                          func(o *Operation) { o.Session, o.Feature, o.Audit, o.Agent = false, "", NoAudit, true },
		"an anonymous row that names an object":           func(o *Operation) { o.Session, o.Feature, o.Audit, o.Object = false, "", NoAudit, "device" },
		"an anonymous row with a receipt":                 func(o *Operation) { o.Session, o.Feature, o.Audit, o.Receipt = false, "", NoAudit, true },
		"an anonymous row a restricted account may reach": func(o *Operation) { o.Session, o.Feature, o.Audit, o.Restricted = false, "", NoAudit, true },
		"a gated row a restricted account may reach":      func(o *Operation) { o.Restricted = true },
		"an R3 row that is not audited":                   func(o *Operation) { o.Feature, o.Audit, o.Risk = "", NoAudit, "R3" },
		"an R4 row that is not audited":                   func(o *Operation) { o.Feature, o.Audit, o.Risk = "", NoAudit, "R4" },
		"an R1 row audited before the call":               func(o *Operation) { o.Feature, o.Risk = "", "R1" },
		"an agent row with a mobile.limited rule":         func(o *Operation) { o.Agent, o.MobileLimited = true, Upgrade },
		"an agent row a restricted account may reach":     func(o *Operation) { o.Agent, o.Restricted = true, true },
		"an agent row that needs step-up evidence":        func(o *Operation) { o.Agent, o.StepUp, o.Target = true, Evidence, TargetAccount },
		"evidence without a target":                       func(o *Operation) { o.StepUp = Evidence },
		"a target without evidence":                       func(o *Operation) { o.Target = TargetDevice },
	} {
		row := good
		mutate(&row)
		if CheckRow(row) == nil {
			t.Errorf("%s was admitted", name)
		}
	}
	// The R3 identity rows are audited by their handlers, and no identity row is gated, agent or object-addressed.
	for _, operation := range Operations() {
		if err := CheckRow(operation); err != nil {
			t.Error(err)
		}
		if operation.Feature != "" || operation.Agent || operation.Object != "" || operation.Audit == AuditBeforeCall {
			t.Errorf("%s: an essential identity row carries a gate rule", operation.ID)
		}
		if (operation.Risk == "R3") != (operation.Audit == AuditInTransaction) {
			t.Errorf("%s: risk %s, audit %d", operation.ID, operation.Risk, operation.Audit)
		}
	}
}

func TestEveryGatedKeyHasARoutedOperationGroup(t *testing.T) {
	seen := map[feature.Key]bool{}
	for _, row := range feature.OperationKeys() {
		if !feature.IsGated(row.Key) || seen[row.Key] || row.Gates == "" {
			t.Errorf("the routed task control table row %+v", row)
		}
		seen[row.Key] = true
	}
	if len(seen) != len(feature.Gated()) {
		t.Errorf("%d keys in the routed table, %d gated keys", len(seen), len(feature.Gated()))
	}
}
