// SPDX-License-Identifier: AGPL-3.0-only

package entitlement_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The operator grant on real PostgreSQL (EVIDENCE: REAL logic, REAL store, REAL step-up consumption; the catalogue is a MOCKED
// illustrative fixture or a test-injected production-classified document, and the step-up proof is seeded as a proved challenge row,
// the WebAuthn ceremony itself being proved by the identity tests).

const productionCatalogue = `{"version":"2026-q4","fixture":false,"capabilities":["center.nodes","center.execute","remote.view","remote.control","center.mcp","push"],
"plans":[{"id":"plan-test","name":"Plan under test","features":["remote.view","push"]}]}`

type grantFixture struct {
	t             *testing.T
	db            *dbtest.Database
	configuration feature.Configuration
	service       *entitlement.Service
	operator      *entitlement.Operator
}

func newGrantFixture(t *testing.T, settings feature.Settings) *grantFixture {
	t.Helper()
	db := dbtest.New(t)
	configuration := feature.Configure(settings)
	service := entitlement.NewService(db.Runtime, configuration, nil, nil)
	return &grantFixture{t: t, db: db, configuration: configuration, service: service,
		operator: entitlement.NewOperator(db.Runtime, service, configuration.OperatorGrants, nil)}
}

var development = feature.Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures}

// operatorAccount seeds an account with a live operator row and a live account session.
func (f *grantFixture) operatorAccount() (platform.ID, dbtest.Session) {
	f.t.Helper()
	user := f.db.Account(1)
	f.db.Exec("INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '" + user.String() +
		"', now() - interval '1 day', now() + interval '30 days', 'operator:cli', 'test operator')")
	return user, f.db.Session(user, 1)
}

func (f *grantFixture) request(account platform.ID, features ...string) entitlement.OperatorRequest {
	return entitlement.OperatorRequest{Account: account.String(), Features: features, Reason: "support goodwill for ticket 42", ExpiresAt: entitlement.FromTime(time.Now().Add(30 * 24 * time.Hour)),
		SourceRef: "ticket-42"}
}

// call is a grant call with its evidence consumer; proved says whether a proved step-up for the request's hash exists.
func (f *grantFixture) call(user platform.ID, session dbtest.Session, request entitlement.OperatorRequest, proved bool) entitlement.GrantCall {
	f.t.Helper()
	if proved {
		// The page proves the request as its review shows it: normalized, so a catalogue-wide grant names its keys.
		reviewed, err := f.operator.Review(context.Background(), entitlement.OperatorCaller{UserID: user, Scope: "account"}, request)
		if err != nil {
			reviewed = request
		}
		hash := reviewed.TargetHash(user)
		f.db.ProveStepUp(session, entitlement.OperatorGrantClass, hash[:], time.Now())
	}
	return entitlement.GrantCall{Caller: entitlement.OperatorCaller{UserID: user, Scope: "account"}, Request: request, CommandID: platform.NewID(),
		Consume: func(ctx context.Context, tx pgx.Tx, target [32]byte, now time.Time) error {
			return identity.ConsumeEvidenceFor(ctx, tx, identity.Caller{UserID: user, SessionID: session.ID, Scope: "account"}, entitlement.OperatorGrantClass, target[:], now)
		}}
}

func (f *grantFixture) audits(eventType, reason string) int {
	if reason == "" {
		return f.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", eventType)
	}
	return f.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND reason = $2", eventType, reason)
}

func (f *grantFixture) written() int {
	return f.db.Count("SELECT (SELECT count(*) FROM entitlement.grant) + (SELECT count(*) FROM entitlement.service_term) + (SELECT count(*) FROM entitlement.snapshot)")
}

func (f *grantFixture) consumed() int {
	return f.db.Count("SELECT count(*) FROM identity.step_up_challenge WHERE state = 3")
}

func wantArc(t *testing.T, err error, key string) *arc.Refusal {
	t.Helper()
	var refusal *arc.Refusal
	if !errors.As(err, &refusal) || refusal.Key() != key {
		t.Fatalf("want the refusal %s, got %v", key, err)
	}
	return refusal
}

func TestAnOperatorGrantsFeaturesWithItsEvidenceInOneTransaction(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	target := f.db.Account(1)
	request := f.request(target, "remote.view", "push")
	call := f.call(user, session, request, true)
	result, err := f.operator.Grant(context.Background(), call)
	if err != nil || result.Replayed || len(result.GrantIDs) != 2 || result.TermID == "" {
		t.Fatalf("the grant: %+v %v", result, err)
	}
	snapshot, err := f.service.Read(context.Background(), target.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"center.nodes", "center.execute", "remote.view", "remote.control", "center.mcp", "push"} {
		entry, ok := snapshot.Capability(key)
		want := key == "remote.view" || key == "push"
		if !ok || entry.Granted != want {
			t.Errorf("%s: %+v %v", key, entry, ok)
		}
	}
	// One compensation term and one AdminGrant per feature, all ending at the request's expiry, every record naming the operator.
	if f.db.Count("SELECT count(*) FROM entitlement.service_term WHERE account_id = $1 AND kind = 3 AND period_ref = 'ticket-42' AND ends_at = $2", target, request.ExpiresAt.Time()) != 1 ||
		f.db.Count("SELECT count(*) FROM entitlement.grant WHERE account_id = $1 AND source = 5 AND effective_until = $2 AND issued_by_actor = $3 AND reason = $4 AND source_ref LIKE 'ticket-42:%'",
			target, request.ExpiresAt.Time(), "operator:"+user.String(), request.Reason) != 2 {
		t.Fatalf("the records of the grant")
	}
	// The evidence is spent, the receipt and one audit event exist, and the audit holds a digest of the reason, never the reason.
	if f.consumed() != 1 || f.db.Count("SELECT count(*) FROM platform.command_receipt WHERE operation = 'center.operatorGrant' AND status = 2") != 1 || f.audits(entitlement.AuditOperatorGrantIssued, "") != 1 {
		t.Fatalf("evidence %d receipts audits %d", f.consumed(), f.audits(entitlement.AuditOperatorGrantIssued, ""))
	}
	var raw []byte
	if err = f.db.Migration.QueryRow(context.Background(), "SELECT payload FROM audit.audit_event WHERE event_type = $1", entitlement.AuditOperatorGrantIssued).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	payload := string(raw)
	if strings.Contains(payload, "goodwill") || !strings.Contains(payload, "reasonSha256") || !strings.Contains(payload, target.String()) {
		t.Fatalf("the audit payload: %s", payload)
	}
	// The same command again answers its stored result: nothing is written, no second evidence is needed.
	before := f.written()
	replay, err := f.operator.Grant(context.Background(), call)
	if err != nil || !replay.Replayed || replay.TermID != result.TermID || f.written() != before || f.audits(entitlement.AuditOperatorGrantIssued, "") != 1 {
		t.Fatalf("the replay: %+v %v", replay, err)
	}
	// The same command with another request is refused.
	other := call
	other.Request = f.request(target, "remote.view")
	other.Request.SourceRef = "ticket-43"
	_, err = f.operator.Grant(context.Background(), other)
	wantArc(t, err, "CONFLICT/command_id_reused")
}

func TestTheBootstrapOwnerCountsAsAnOperator(t *testing.T) {
	f := newGrantFixture(t, development)
	owner := f.db.Account(1)
	f.db.Exec("INSERT INTO identity.bootstrap (singleton, token_sha256, user_id, consumed_at) VALUES (true, decode(repeat('cc', 32), 'hex'), '" + owner.String() + "', now())")
	session := f.db.Session(owner, 1)
	target := f.db.Account(1)
	if _, err := f.operator.Grant(context.Background(), f.call(owner, session, f.request(target, "remote.view"), true)); err != nil {
		t.Fatal(err)
	}
	if operator, err := f.operator.CanOperate(context.Background(), owner); err != nil || !operator {
		t.Fatalf("%v %v", operator, err)
	}
	if operator, err := f.operator.CanOperate(context.Background(), target); err != nil || operator {
		t.Fatalf("%v %v", operator, err)
	}
}

func TestOnlyALiveOperatorOnAnAccountSessionMayGrant(t *testing.T) {
	f := newGrantFixture(t, development)
	target := f.db.Account(1)
	plain := f.db.Account(1)
	expired := f.db.Account(1)
	revoked := f.db.Account(1)
	f.db.Exec("INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '"+expired.String()+
		"', now() - interval '3 days', now() - interval '1 day', 'operator:cli', 'expired')",
		"INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, revoked_at, granted_by, reason) VALUES (gen_random_uuid(), '"+revoked.String()+
			"', now() - interval '3 days', now() + interval '30 days', now() - interval '1 hour', 'operator:cli', 'revoked')")
	live, liveSession := f.operatorAccount()
	cases := map[string]entitlement.GrantCall{
		"an account that is no operator": f.call(plain, f.db.Session(plain, 1), f.request(target, "remote.view"), true),
		"an operator that expired":       f.call(expired, f.db.Session(expired, 1), f.request(target, "remote.view"), true),
		"an operator that was revoked":   f.call(revoked, f.db.Session(revoked, 1), f.request(target, "remote.view"), true),
	}
	mobile := f.call(live, f.db.Session(live, 2), f.request(target, "remote.view"), true)
	mobile.Caller.Scope = "mobile.limited"
	cases["a mobile.limited session of an operator"] = mobile
	node := f.call(live, liveSession, f.request(target, "remote.view"), true)
	node.Caller.Scope = "node"
	cases["a node credential of an operator"] = node
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			before := f.written()
			_, err := f.operator.Grant(context.Background(), call)
			wantArc(t, err, "AUTHORIZATION/permission_denied")
			if f.written() != before {
				t.Fatal("a refused grant wrote")
			}
		})
	}
	if f.audits(entitlement.AuditOperatorGrantRefused, "not_operator") != len(cases) || f.consumed() != 0 {
		t.Fatalf("audited %d of %d, evidence consumed %d", f.audits(entitlement.AuditOperatorGrantRefused, "not_operator"), len(cases), f.consumed())
	}
}

func TestStepUpEvidenceIsExactSingleUseAndFresh(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	target := f.db.Account(1)
	request := f.request(target, "remote.view")
	// No evidence at all.
	_, err := f.operator.Grant(context.Background(), f.call(user, session, request, false))
	wantArc(t, err, "AUTHENTICATION/step_up_required")
	if f.written() != 0 || f.audits(entitlement.AuditOperatorGrantRefused, "step_up_required") != 1 {
		t.Fatalf("written %d audited %d", f.written(), f.audits(entitlement.AuditOperatorGrantRefused, "step_up_required"))
	}
	// Evidence for another request (the reason differs by one character).
	changed := request
	changed.Reason += "!"
	changedHash := changed.TargetHash(user)
	f.db.ProveStepUp(session, entitlement.OperatorGrantClass, changedHash[:], time.Now())
	_, err = f.operator.Grant(context.Background(), f.call(user, session, request, false))
	wantArc(t, err, "AUTHENTICATION/step_up_required")
	// Evidence of another operation class for the same hash.
	hash := request.TargetHash(user)
	f.db.ProveStepUp(session, "identity.revokeAllSessions", hash[:], time.Now())
	_, err = f.operator.Grant(context.Background(), f.call(user, session, request, false))
	wantArc(t, err, "AUTHENTICATION/step_up_required")
	// Evidence of another session of the same account.
	f.db.ProveStepUp(f.db.Session(user, 1), entitlement.OperatorGrantClass, hash[:], time.Now())
	_, err = f.operator.Grant(context.Background(), f.call(user, session, request, false))
	wantArc(t, err, "AUTHENTICATION/step_up_required")
	// Evidence older than five minutes.
	f.db.ProveStepUp(session, entitlement.OperatorGrantClass, hash[:], time.Now().Add(-6*time.Minute))
	_, err = f.operator.Grant(context.Background(), f.call(user, session, request, false))
	wantArc(t, err, "AUTHENTICATION/step_up_required")
	if f.written() != 0 || f.consumed() != 0 {
		t.Fatalf("a refused grant wrote %d or consumed %d", f.written(), f.consumed())
	}
	// The right evidence works once; a second grant with the same hash needs a new proof.
	if _, err = f.operator.Grant(context.Background(), f.call(user, session, request, true)); err != nil {
		t.Fatal(err)
	}
	second := request
	second.Features = []string{"remote.view"}
	_, err = f.operator.Grant(context.Background(), f.call(user, session, second, false))
	wantArc(t, err, "AUTHENTICATION/step_up_required")
}

func TestTheBoundsOfAnOperatorGrantRequest(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	target := f.db.Account(1)
	suspended := f.db.Account(3)
	deleted := f.db.Account(5)
	long := strings.Repeat("r", 513)
	cases := []struct {
		name   string
		mutate func(*entitlement.OperatorRequest)
		key    string
		reason string
	}{
		{"no features", func(r *entitlement.OperatorRequest) { r.Features = nil }, "VALIDATION/invalid_argument", "invalid_argument"},
		{"an unknown feature", func(r *entitlement.OperatorRequest) { r.Features = []string{"remote.nothing"} }, "VALIDATION/invalid_argument", "invalid_argument"},
		{"a repeated feature", func(r *entitlement.OperatorRequest) { r.Features = []string{"push", "push"} }, "VALIDATION/invalid_argument", "invalid_argument"},
		{"a blank reason", func(r *entitlement.OperatorRequest) { r.Reason = "   " }, "VALIDATION/invalid_argument", "invalid_argument"},
		{"a reason with a control character", func(r *entitlement.OperatorRequest) { r.Reason = "a\nb" }, "VALIDATION/invalid_argument", "invalid_argument"},
		{"a reason of 513 characters", func(r *entitlement.OperatorRequest) { r.Reason = long }, "VALIDATION/invalid_argument", "invalid_argument"},
		{"no source reference", func(r *entitlement.OperatorRequest) { r.SourceRef = "" }, "VALIDATION/invalid_argument", "invalid_argument"},
		{"a source reference of 97 characters", func(r *entitlement.OperatorRequest) { r.SourceRef = strings.Repeat("a", 97) }, "VALIDATION/invalid_argument", "invalid_argument"},
		{"a source reference with a slash", func(r *entitlement.OperatorRequest) { r.SourceRef = "a/b" }, "VALIDATION/invalid_argument", "invalid_argument"},
		{"an expiry in the past", func(r *entitlement.OperatorRequest) { r.ExpiresAt = entitlement.FromTime(time.Now().Add(-time.Hour)) }, "VALIDATION/invalid_argument", "invalid_argument"},
		{"an expiry beyond 400 days", func(r *entitlement.OperatorRequest) {
			r.ExpiresAt = entitlement.FromTime(time.Now().Add(401 * 24 * time.Hour))
		}, "VALIDATION/invalid_argument", "invalid_argument"},
		{"a justification for a grant to another account", func(r *entitlement.OperatorRequest) { r.SelfApproval = "because" }, "VALIDATION/invalid_argument", "invalid_argument"},
		{"an account that is not a uuid", func(r *entitlement.OperatorRequest) { r.Account = "not-a-uuid" }, "VALIDATION/invalid_argument", "invalid_argument"},
		{"an account that does not exist", func(r *entitlement.OperatorRequest) { r.Account = platform.NewID().String() }, "STATE/not_found", "account_not_found"},
		{"a suspended account", func(r *entitlement.OperatorRequest) { r.Account = suspended.String() }, "STATE/invalid_state", "account_state"},
		{"a deleted account", func(r *entitlement.OperatorRequest) { r.Account = deleted.String() }, "STATE/invalid_state", "account_state"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			request := f.request(target, "remote.view")
			item.mutate(&request)
			before := f.written()
			// The review the page shows before the step-up refuses every bound that needs no read of the target account.
			if item.key == "VALIDATION/invalid_argument" {
				_, reviewErr := f.operator.Review(context.Background(), entitlement.OperatorCaller{UserID: user, Scope: "account"}, request)
				wantArc(t, reviewErr, item.key)
			}
			_, err := f.operator.Grant(context.Background(), f.call(user, session, request, true))
			wantArc(t, err, item.key)
			if f.written() != before || f.consumed() != 0 {
				t.Fatalf("a refused grant wrote or consumed evidence")
			}
		})
	}
	// Every refusal is audited, with a closed reason.
	if got := f.audits(entitlement.AuditOperatorGrantRefused, ""); got != len(cases) {
		t.Fatalf("%d refusals audited of %d", got, len(cases))
	}
	// 400 days exactly is the bound of a non-production configuration.
	atBound := f.request(target, "remote.view")
	atBound.ExpiresAt = entitlement.FromTime(time.Now().Add(400*24*time.Hour - time.Minute))
	if _, err := f.operator.Grant(context.Background(), f.call(user, session, atBound, true)); err != nil {
		t.Fatalf("an expiry within 400 days: %v", err)
	}
}

func TestTheProductionConfigurationBoundsTheGrant(t *testing.T) {
	f := newGrantFixture(t, feature.Settings{Mode: config.OfficialHosted, Injected: []byte(productionCatalogue), InjectedClass: feature.ClassProduction})
	user, session := f.operatorAccount()
	target := f.db.Account(1)
	all := []string{"center.nodes", "center.execute", "remote.view", "remote.control", "center.mcp", "push"}
	for name, mutate := range map[string]func(*entitlement.OperatorRequest){
		"every key named":              func(r *entitlement.OperatorRequest) { r.Features = all },
		"the catalogue-wide shorthand": func(r *entitlement.OperatorRequest) { r.Features, r.All = nil, true },
		"an expiry beyond 90 days": func(r *entitlement.OperatorRequest) {
			r.ExpiresAt = entitlement.FromTime(time.Now().Add(91 * 24 * time.Hour))
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := f.request(target, "remote.view")
			mutate(&request)
			before := f.written()
			_, err := f.operator.Grant(context.Background(), f.call(user, session, request, true))
			if request.ExpiresAt > entitlement.FromTime(time.Now().Add(90*24*time.Hour)) {
				wantArc(t, err, "VALIDATION/invalid_argument")
			} else {
				refusal := wantArc(t, err, "STATE/invalid_state")
				if refusal.Reason != "catalogue_wide" {
					t.Fatalf("the reason %q", refusal.Reason)
				}
			}
			if f.written() != before {
				t.Fatal("a refused grant wrote")
			}
		})
	}
	// Five of six keys for 89 days are admitted.
	request := f.request(target, all[:5]...)
	request.ExpiresAt = entitlement.FromTime(time.Now().Add(89 * 24 * time.Hour))
	if _, err := f.operator.Grant(context.Background(), f.call(user, session, request, true)); err != nil {
		t.Fatal(err)
	}
	// A development fixture allows the catalogue-wide grant.
	dev := newGrantFixture(t, development)
	devUser, devSession := dev.operatorAccount()
	devTarget := dev.db.Account(1)
	wide := dev.request(devTarget)
	wide.All = true
	if result, err := dev.operator.Grant(context.Background(), dev.call(devUser, devSession, wide, true)); err != nil || len(result.Features) != 6 {
		t.Fatalf("a catalogue-wide grant under the fixtures: %+v %v", result, err)
	}
}

func TestOperatorGrantsAreRefusedWithoutACatalogueAndOnASelfHostedCenter(t *testing.T) {
	for name, settings := range map[string]feature.Settings{
		"a production configuration without a catalogue": {Mode: config.OfficialHosted},
		"an invalid catalogue":                           {Mode: config.OfficialHosted, Injected: []byte("{"), InjectedClass: feature.ClassProduction},
		"a self-hosted center":                           {Mode: config.SelfHosted},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGrantFixture(t, settings)
			user, session := f.operatorAccount()
			target := f.db.Account(1)
			_, err := f.operator.Grant(context.Background(), f.call(user, session, f.request(target, "remote.view"), true))
			refusal := wantArc(t, err, "STATE/invalid_state")
			want := "no_catalogue"
			if settings.Mode == config.SelfHosted {
				want = "self_hosted"
			}
			if refusal.Reason != want || f.written() != 0 || f.consumed() != 0 || f.audits(entitlement.AuditOperatorGrantRefused, want) != 1 {
				t.Fatalf("%q written %d consumed %d audited %d", refusal.Reason, f.written(), f.consumed(), f.audits(entitlement.AuditOperatorGrantRefused, want))
			}
		})
	}
}

func TestASelfGrantNeedsItsJustificationAndRecordsIt(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	request := f.request(user, "remote.view")
	_, err := f.operator.Grant(context.Background(), f.call(user, session, request, true))
	if refusal := wantArc(t, err, "STATE/invalid_state"); refusal.Reason != "self_approval_required" {
		t.Fatalf("%q", refusal.Reason)
	}
	request.SelfApproval = "I test the proof environment and approved this myself with the owner"
	if _, err = f.operator.Grant(context.Background(), f.call(user, session, request, true)); err != nil {
		t.Fatal(err)
	}
	var reason string
	if err = f.db.Migration.QueryRow(context.Background(), "SELECT reason FROM entitlement.grant WHERE account_id = $1", user).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reason, request.Reason) || !strings.Contains(reason, "self-approval: "+request.SelfApproval) {
		t.Fatalf("the stored reason: %q", reason)
	}
	// The reason and the justification together fit one stored reason.
	long := f.request(user, "push")
	long.SourceRef = "ticket-long"
	long.Reason, long.SelfApproval = strings.Repeat("r", 300), strings.Repeat("s", 300)
	_, err = f.operator.Grant(context.Background(), f.call(user, session, long, true))
	wantArc(t, err, "VALIDATION/invalid_argument")
}

func TestAReusedSourceReferenceIsRefusedAndWritesNothing(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	target := f.db.Account(1)
	if _, err := f.operator.Grant(context.Background(), f.call(user, session, f.request(target, "remote.view"), true)); err != nil {
		t.Fatal(err)
	}
	before := f.written()
	_, err := f.operator.Grant(context.Background(), f.call(user, session, f.request(target, "remote.view", "push"), true))
	wantArc(t, err, "CONFLICT/already_exists")
	if f.written() != before {
		t.Fatal("a refused grant wrote")
	}
}

func TestAFailedAuditAppendRefusesTheGrantAndSpendsNoEvidence(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	target := f.db.Account(1)
	f.db.Exec("CREATE SCHEMA testfault",
		"CREATE FUNCTION testfault.refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'entitlement.operator_grant.issued' THEN RAISE EXCEPTION 'the audit is refused (test)' USING ERRCODE = '57P01'; END IF; RETURN NEW; END; $$",
		"CREATE TRIGGER test_refuse BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION testfault.refuse()")
	call := f.call(user, session, f.request(target, "remote.view"), true)
	_, err := f.operator.Grant(context.Background(), call)
	if err == nil || !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a grant whose audit is refused: %v", err)
	}
	if f.written() != 0 || f.consumed() != 0 || f.db.Count("SELECT count(*) FROM platform.command_receipt") != 0 {
		t.Fatalf("written %d consumed %d: the refused audit left effects", f.written(), f.consumed())
	}
	f.db.Exec("DROP TRIGGER test_refuse ON audit.audit_event")
	// After the fault is gone the same command with the same evidence is granted: nothing was spent.
	if _, err = f.operator.Grant(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	if count, err := platform.VerifyAudit(context.Background(), f.db.Migration); err != nil || count < 1 {
		t.Fatalf("the audit chain: %d %v", count, err)
	}
}

func TestARoleThatEndedBetweenTheCheckAndTheGrantRefusesTheGrant(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	target := f.db.Account(1)
	call := f.call(user, session, f.request(target, "remote.view"), true)
	// The first reading of the clock is the check's; the grant's own transaction reads a later one, after the operator row expired.
	var readings atomic.Int32
	start := time.Now()
	stepping := entitlement.NewOperator(f.db.Runtime, f.service, f.configuration.OperatorGrants, func() time.Time {
		if readings.Add(1) == 1 {
			return start
		}
		return start.Add(40 * 24 * time.Hour)
	})
	_, err := stepping.Grant(context.Background(), call)
	wantArc(t, err, "AUTHORIZATION/permission_denied")
	if f.written() != 0 || f.consumed() != 0 {
		t.Fatalf("written %d consumed %d: a role that ended still granted", f.written(), f.consumed())
	}
}

func TestAFailedAuditOfARefusalIsNeverSilent(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	target := f.db.Account(1)
	f.db.Exec("CREATE SCHEMA testfault",
		"CREATE FUNCTION testfault.refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'entitlement.operator_grant.refused' THEN RAISE EXCEPTION 'the audit is refused (test)' USING ERRCODE = '57P01'; END IF; RETURN NEW; END; $$",
		"CREATE TRIGGER test_refuse BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION testfault.refuse()")
	request := f.request(target, "remote.view")
	request.ExpiresAt = entitlement.FromTime(time.Now().Add(-time.Hour))
	_, err := f.operator.Grant(context.Background(), f.call(user, session, request, false))
	var refusal *arc.Refusal
	if err == nil || errors.As(err, &refusal) || !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a refusal whose audit is refused must surface the store failure, got %v", err)
	}
}

func TestTwoOperatorsGrantingTheSameAccountAtOnceBothSucceed(t *testing.T) {
	f := newGrantFixture(t, development)
	target := f.db.Account(1)
	var group sync.WaitGroup
	errs := make([]error, 3)
	for i := range errs {
		user, session := f.operatorAccount()
		request := f.request(target, []string{"remote.view", "push", "center.nodes"}[i])
		request.SourceRef = "ticket-" + string(rune('a'+i))
		call := f.call(user, session, request, true)
		group.Add(1)
		go func() {
			defer group.Done()
			_, errs[i] = f.operator.Grant(context.Background(), call)
		}()
	}
	group.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("a concurrent operator: %v", err)
		}
	}
	snapshot, err := f.service.Read(context.Background(), target.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"remote.view", "push", "center.nodes"} {
		if entry, ok := snapshot.Capability(key); !ok || !entry.Granted {
			t.Errorf("%s: %+v", key, entry)
		}
	}
	report, err := f.service.VerifyRebuild(context.Background(), target.String())
	if err != nil || report.Status != entitlement.RebuildEqual {
		t.Fatalf("%+v %v", report, err)
	}
}

func TestTheCanonicalRequestCoversEveryFieldAndHashesTheSameWhateverTheOrder(t *testing.T) {
	operator, other := platform.NewID(), platform.NewID()
	base := entitlement.OperatorRequest{Account: platform.NewID().String(), Features: []string{"push", "remote.view"}, Reason: "r", ExpiresAt: 5, SourceRef: "ref", SelfApproval: ""}
	hash := base.TargetHashHex(operator)
	if len(hash) != 64 {
		t.Fatal(hash)
	}
	if _, err := hex.DecodeString(hash); err != nil {
		t.Fatal(err)
	}
	reordered := base
	reordered.Features = []string{"remote.view", "push"}
	if reordered.TargetHashHex(operator) != hash {
		t.Fatal("the order of the features changed the hash")
	}
	for name, change := range map[string]func(*entitlement.OperatorRequest){
		"account":      func(r *entitlement.OperatorRequest) { r.Account = platform.NewID().String() },
		"features":     func(r *entitlement.OperatorRequest) { r.Features = []string{"push"} },
		"all":          func(r *entitlement.OperatorRequest) { r.All = true },
		"reason":       func(r *entitlement.OperatorRequest) { r.Reason = "r " },
		"expiry":       func(r *entitlement.OperatorRequest) { r.ExpiresAt = 6 },
		"source":       func(r *entitlement.OperatorRequest) { r.SourceRef = "ref2" },
		"self-approve": func(r *entitlement.OperatorRequest) { r.SelfApproval = "x" },
	} {
		changed := base
		change(&changed)
		if changed.TargetHashHex(operator) == hash {
			t.Errorf("the %s is not part of the hash", name)
		}
	}
	if base.TargetHashHex(other) == hash {
		t.Error("the operator is not part of the hash")
	}
	var parsed map[string]any
	if err := json.Unmarshal(base.Canonical(operator), &parsed); err != nil || parsed["operation"] != "center.operatorGrant" {
		t.Fatalf("%v %v", parsed, err)
	}
}
