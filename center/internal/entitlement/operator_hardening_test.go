// SPDX-License-Identifier: AGPL-3.0-only

package entitlement_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The operator grant's hardening (fix round 1 of the review of part B): who may be an operator, the lock that orders a revocation
// against a grant in flight, the boundaries of the request, the audit of refusals and the concurrency of grants (EVIDENCE: REAL
// PostgreSQL and the real consumption of the step-up evidence; the catalogue is the MOCKED illustrative fixture).

func TestAnOperatorWhoseAccountIsNotActiveIsNoOperator(t *testing.T) {
	f := newGrantFixture(t, development)
	target := f.db.Account(1)
	for name, state := range map[string]int16{"restricted": 2, "suspended": 3, "pending deletion": 4, "deleted": 5} {
		t.Run(name, func(t *testing.T) {
			user := f.db.Account(state)
			f.db.Exec("INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '" + user.String() +
				"', now() - interval '1 day', now() + interval '30 days', 'operator:cli', 'test operator')")
			session := f.db.Session(user, 1)
			before := f.written()
			_, err := f.operator.Grant(context.Background(), f.call(user, session, f.request(target, "remote.view"), true))
			wantArc(t, err, "AUTHORIZATION/permission_denied")
			_, err = f.operator.Review(context.Background(), entitlement.OperatorCaller{UserID: user, Scope: "account"}, f.request(target, "remote.view"))
			wantArc(t, err, "AUTHORIZATION/permission_denied")
			if operator, err := f.operator.CanOperate(context.Background(), user); err != nil || operator {
				t.Fatalf("an account in state %d is an operator: %v %v", state, operator, err)
			}
			if f.written() != before || f.consumed() != 0 {
				t.Fatal("a refused operator wrote or spent evidence")
			}
		})
	}
	// The owner who bootstrapped the center is no operator while the account is restricted, and is again when it is active.
	owner := f.db.Account(2)
	f.db.Exec("INSERT INTO identity.bootstrap (singleton, token_sha256, user_id, consumed_at) VALUES (true, decode(repeat('cc', 32), 'hex'), '" + owner.String() + "', now())")
	if operator, err := f.operator.CanOperate(context.Background(), owner); err != nil || operator {
		t.Fatalf("a restricted bootstrap owner: %v %v", operator, err)
	}
	f.db.Exec("UPDATE identity.user SET state = 1, rev = rev + 1 WHERE user_id = '" + owner.String() + "'")
	if operator, err := f.operator.CanOperate(context.Background(), owner); err != nil || !operator {
		t.Fatalf("an active bootstrap owner: %v %v", operator, err)
	}
}

func TestAReviewIsRefusedToAnAccountThatIsNoOperator(t *testing.T) {
	f := newGrantFixture(t, development)
	target := f.db.Account(1)
	stranger := f.db.Account(1)
	_, err := f.operator.Review(context.Background(), entitlement.OperatorCaller{UserID: stranger, Scope: "account"}, f.request(target, "remote.view"))
	wantArc(t, err, "AUTHORIZATION/permission_denied")
	if f.written() != 0 || f.audits(entitlement.AuditOperatorGrantRefused, "") != 0 {
		t.Fatal("a review wrote or audited")
	}
}

// TestARevocationThatCommitsWhileAGrantIsInFlightIsHonoured: a revocation that has locked the operator's account and not yet
// committed holds the grant at the lock; when it commits, the grant reads the revoked role and is refused.
func TestARevocationThatCommitsWhileAGrantIsInFlightIsHonoured(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	target := f.db.Account(1)
	call := f.call(user, session, f.request(target, "remote.view"), true)
	ctx := context.Background()
	tx, err := f.db.Migration.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ended, err := entitlement.RevokeOperatorRole(ctx, tx, user, time.Now()); err != nil || ended != 1 {
		t.Fatalf("the revocation: %d %v", ended, err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := f.operator.Grant(ctx, call)
		done <- err
	}()
	select {
	case err := <-done:
		_ = tx.Rollback(ctx)
		t.Fatalf("the grant did not wait for the revocation that was in flight: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		wantArc(t, err, "AUTHORIZATION/permission_denied")
	case <-time.After(10 * time.Second):
		t.Fatal("the grant never finished")
	}
	if f.written() != 0 || f.consumed() != 0 {
		t.Fatalf("written %d, consumed %d: a revoked operator granted", f.written(), f.consumed())
	}
}

func TestTheBoundariesOfTheExpiryAreExact(t *testing.T) {
	operator := platform.NewID()
	policy := entitlement.OperatorPolicy{MaxExpiry: 90 * 24 * time.Hour, AllowCatalogueWide: true, Keys: []string{"push", "remote.view"}}
	now := entitlement.Micros(1_800_000_000_000_000)
	request := func(expires entitlement.Micros) entitlement.OperatorRequest {
		return entitlement.OperatorRequest{Account: platform.NewID().String(), Features: []string{"push"}, Reason: "r", ExpiresAt: expires, SourceRef: "ticket-1"}
	}
	longest := entitlement.Micros(policy.MaxExpiry.Microseconds())
	for name, test := range map[string]struct {
		expires entitlement.Micros
		reason  string // the refusal reason, or "" for an admitted request
	}{
		"exactly now":                        {now, "expires_at: not_in_the_future"},
		"one microsecond before now":         {now - 1, "expires_at: not_in_the_future"},
		"one microsecond after now":          {now + 1, ""},
		"exactly the longest expiry":         {now + longest, ""},
		"one microsecond beyond the longest": {now + longest + 1, "expires_at: too_far"},
		"far beyond the longest":             {now + 10*longest, "expires_at: too_far"},
	} {
		_, refusal := entitlement.Normalize(request(test.expires), policy, operator, now)
		switch {
		case test.reason == "" && refusal != nil:
			t.Errorf("%s: refused: %s", name, refusal.Reason)
		case test.reason != "" && (refusal == nil || refusal.Reason != test.reason):
			t.Errorf("%s: want %s, got %v", name, test.reason, refusal)
		}
	}
}

func TestTwoOperatorsMayUseTheSameCommandID(t *testing.T) {
	f := newGrantFixture(t, development)
	target := f.db.Account(1)
	command := platform.NewID()
	for _, key := range []string{"remote.view", "push"} {
		user, session := f.operatorAccount()
		request := f.request(target, key)
		request.SourceRef = "ticket-" + key
		call := f.call(user, session, request, true)
		call.CommandID = command
		if _, err := f.operator.Grant(context.Background(), call); err != nil {
			t.Fatalf("%s: a command ID another operator used must not collide: %v", key, err)
		}
	}
	if f.db.Count("SELECT count(*) FROM platform.command_receipt WHERE operation = 'center.operatorGrant'") != 2 {
		t.Fatal("each operator has a receipt of its own")
	}
}

func TestOneEvidenceServesOneGrantWhoeverAsksFirst(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	target := f.db.Account(1)
	first := f.call(user, session, f.request(target, "remote.view"), true)
	second := first
	second.CommandID = platform.NewID()
	var group sync.WaitGroup
	errs := make([]error, 2)
	for i, call := range []entitlement.GrantCall{first, second} {
		group.Add(1)
		go func() {
			defer group.Done()
			_, errs[i] = f.operator.Grant(context.Background(), call)
		}()
	}
	group.Wait()
	succeeded := 0
	for _, err := range errs {
		var refusal *arc.Refusal
		switch {
		case err == nil:
			succeeded++
		case !errors.As(err, &refusal) || refusal.Key() != "AUTHENTICATION/step_up_required":
			t.Fatalf("the loser: %v", err)
		}
	}
	if succeeded != 1 || f.consumed() != 1 || f.db.Count("SELECT count(*) FROM entitlement.service_term") != 1 {
		t.Fatalf("%d grants succeeded on one evidence, %d spent", succeeded, f.consumed())
	}
}

// TestManyOperatorsGrantingToOneAccountAtOnceAllSucceed pins the revision row's lock: 24 distinct operators (one shared session would
// be serialized by the evidence's consumption first), each with its own evidence, grant to one account concurrently. Without the
// lock the optimistic fence lets only a few through within the bounded retries.
func TestManyOperatorsGrantingToOneAccountAtOnceAllSucceed(t *testing.T) {
	f := newGrantFixture(t, development)
	target := f.db.Account(1)
	const operators = 24
	calls := make([]entitlement.GrantCall, operators)
	for i := range calls {
		user, session := f.operatorAccount()
		request := f.request(target, "remote.view")
		request.SourceRef = "ticket-" + platform.NewID().String()[:8]
		calls[i] = f.call(user, session, request, true)
	}
	var group sync.WaitGroup
	errs := make([]error, operators)
	for i := range calls {
		group.Add(1)
		go func() {
			defer group.Done()
			_, errs[i] = f.operator.Grant(context.Background(), calls[i])
		}()
	}
	group.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("operator %d: %v", i, err)
		}
	}
	if got := f.db.Count("SELECT count(*) FROM entitlement.grant WHERE account_id = $1", target); got != operators {
		t.Fatalf("%d grants of %d", got, operators)
	}
}

func TestARefusedGrantAuditsNoRawFeatureText(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	target := f.db.Account(1)
	request := f.request(target, "Jane Doe passport 123456789", "line\nbreak", "remote.view")
	_, err := f.operator.Grant(context.Background(), f.call(user, session, request, true))
	wantArc(t, err, "VALIDATION/invalid_argument")
	var raw []byte
	if err = f.db.Migration.QueryRow(context.Background(), "SELECT payload FROM audit.audit_event WHERE event_type = $1", entitlement.AuditOperatorGrantRefused).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "Jane") || strings.Contains(string(raw), "passport") || strings.IndexFunc(string(raw), unicode.IsControl) >= 0 {
		t.Fatalf("the audit repeats the operator's text: %q", raw)
	}
	var payload struct {
		Features       []string `json:"features"`
		FeatureCount   int      `json:"featureCount"`
		FeaturesSha256 string   `json:"featuresSha256"`
		Reason         string   `json:"reason"`
	}
	if err = json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.FeatureCount != 3 || len(payload.FeaturesSha256) != 64 || len(payload.Features) != 1 || payload.Features[0] != "remote.view" || payload.Reason != "invalid_argument" {
		t.Fatalf("the payload: %s", raw)
	}
	// A request with an enormous list is audited by its count and digest as well (the payload stays small).
	many := make([]string, 5000)
	for i := range many {
		many[i] = strings.Repeat("x", 40)
	}
	user, session = f.operatorAccount()
	huge := f.request(target, many...)
	if _, err = f.operator.Grant(context.Background(), f.call(user, session, huge, true)); err == nil {
		t.Fatal("a request with 5000 features was admitted")
	}
	var size int
	if err = f.db.Migration.QueryRow(context.Background(), "SELECT max(length(payload)) FROM audit.audit_event WHERE event_type = $1", entitlement.AuditOperatorGrantRefused).Scan(&size); err != nil || size > 1024 {
		t.Fatalf("the refusal payload is %d bytes: %v", size, err)
	}
}

func TestAStrangersRefusedRequestIsAuditedOncePerWindowAndAccount(t *testing.T) {
	f := newGrantFixture(t, development)
	target := f.db.Account(1)
	stranger := f.db.Account(1)
	other := f.db.Account(1)
	for i := 0; i < 5; i++ {
		if err := f.operator.RefuseAccess(context.Background(), entitlement.OperatorCaller{UserID: stranger, Scope: "account"}, "operations.grant"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.operator.Grant(context.Background(), f.call(stranger, f.db.Session(stranger, 1), f.request(target, "remote.view"), false)); err == nil {
			t.Fatal("a stranger granted")
		}
	}
	if err := f.operator.RefuseAccess(context.Background(), entitlement.OperatorCaller{UserID: other, Scope: "account"}, "operations.review"); err != nil {
		t.Fatal(err)
	}
	if got := f.audits(entitlement.AuditOperatorGrantRefused, "not_operator"); got != 2 {
		t.Fatalf("%d events for ten refusals of one account and one of another", got)
	}
	var raw []byte
	var actor string
	if err := f.db.Migration.QueryRow(context.Background(), "SELECT actor_ref, payload FROM audit.audit_event WHERE event_type = $1 AND target_id = $2", entitlement.AuditOperatorGrantRefused, stranger.String()).Scan(&actor, &raw); err != nil {
		t.Fatal(err)
	}
	if actor != "account:"+stranger.String() || string(raw) != `{"action":"operations.grant","code":"AUTHORIZATION/permission_denied","reason":"not_operator"}` {
		t.Fatalf("the event: %s %s", actor, raw)
	}
}
