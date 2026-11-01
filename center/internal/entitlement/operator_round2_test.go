// SPDX-License-Identifier: AGPL-3.0-only

package entitlement_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Fix round 2 of the operator grant: the window of the stranger audit, the raw account text, the deadlock of two grants, and a
// stranger on a center that has no policy (EVIDENCE: REAL PostgreSQL; the catalogue is the MOCKED illustrative fixture).

// settableClock is the one clock of a scenario that moves on purpose.
type settableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *settableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *settableClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

// newGrantFixtureOn is newGrantFixture with the operator on a clock the test sets.
func newGrantFixtureOn(t *testing.T, settings feature.Settings, clock func() time.Time) *grantFixture {
	t.Helper()
	db := dbtest.New(t)
	configuration := feature.Configure(settings)
	service := entitlement.NewService(db.Runtime, configuration, nil, nil)
	return &grantFixture{t: t, db: db, configuration: configuration, service: service, operator: entitlement.NewOperator(db.Runtime, service, configuration.OperatorGrants, clock)}
}

// TestTheWindowOfTheStrangerAuditIsOneHour (operator-3): two refusals in a window are one event, and the next window audits again.
func TestTheWindowOfTheStrangerAuditIsOneHour(t *testing.T) {
	clock := &settableClock{}
	start := time.Now().UTC().Truncate(time.Hour)
	clock.Set(start)
	f := newGrantFixtureOn(t, development, clock.Now)
	stranger := f.db.Account(1)
	caller := entitlement.OperatorCaller{UserID: stranger, Scope: "account"}
	refuse := func(at time.Duration) int {
		t.Helper()
		clock.Set(start.Add(at))
		if err := f.operator.RefuseAccess(context.Background(), caller, "operations.grant"); err != nil {
			t.Fatal(err)
		}
		return f.audits(entitlement.AuditOperatorGrantRefused, "not_operator")
	}
	for step, want := range []struct {
		at     time.Duration
		events int
	}{{0, 1}, {time.Second, 1}, {59 * time.Minute, 1}, {61 * time.Minute, 2}, {62 * time.Minute, 2}, {2*time.Hour + 2*time.Minute, 3}} {
		if got := refuse(want.at); got != want.events {
			t.Fatalf("step %d at %v: %d events, want %d", step, want.at, got, want.events)
		}
	}
}

// TestARefusedGrantNeverAuditsTheRawAccountText (operator-5): an account that is no uuid is the caller's text; the audit holds
// neither it nor anything near its size.
func TestARefusedGrantNeverAuditsTheRawAccountText(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	request := f.request(f.db.Account(1), "remote.view")
	request.Account = "Jane Doe passport " + strings.Repeat("A", 3000)
	_, err := f.operator.Grant(context.Background(), f.call(user, session, request, true))
	wantArc(t, err, "VALIDATION/invalid_argument")
	var payload []byte
	if err = f.db.Migration.QueryRow(context.Background(), "SELECT payload FROM audit.audit_event WHERE event_type = $1 AND actor_ref = $2",
		entitlement.AuditOperatorGrantRefused, "account:"+user.String()).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), "Jane Doe") || len(payload) > 512 {
		t.Fatalf("the audit holds the account text (%d bytes): %s", len(payload), payload)
	}
	// A well-formed account that does not exist is a value the audit may name.
	missing := f.request(f.db.Account(1), "remote.view")
	missing.Account = "00000000-0000-4000-8000-00000000abcd"
	if _, err = f.operator.Grant(context.Background(), f.call(user, session, missing, true)); err == nil {
		t.Fatal("a grant to an account that does not exist")
	}
	if got := f.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND convert_from(payload, 'UTF8') LIKE '%00000000-0000-4000-8000-00000000abcd%'",
		entitlement.AuditOperatorGrantRefused); got != 1 {
		t.Fatalf("the refusal of a missing account names it %d times", got)
	}
}

// TestTwoOperatorsGrantingToEachOtherAreBothServed (operator-1): operator A grants to B while B grants to A (or to B's own account).
// Each grant holds its operator's user row and takes a share of the target's through the foreign keys of the rows it writes, so
// PostgreSQL ends one of them as a deadlock victim after its deadlock timeout; the victim runs again and both are made.
func TestTwoOperatorsGrantingToEachOtherAreBothServed(t *testing.T) {
	f := newGrantFixture(t, development)
	one, oneSession := f.operatorAccount()
	two, twoSession := f.operatorAccount()
	for round := 0; round < 4; round++ {
		first := f.request(two, "remote.view")
		first.SourceRef = fmt.Sprintf("round-%d-a", round)
		second := f.request(one, "remote.view")
		if round%2 == 1 {
			second = f.request(two, "push")
			second.SelfApproval = "covering the on-call shift"
		}
		second.SourceRef = fmt.Sprintf("round-%d-b", round)
		calls := []entitlement.GrantCall{f.call(one, oneSession, first, true), f.call(two, twoSession, second, true)}
		start := make(chan struct{})
		errs := make([]error, len(calls))
		var wait sync.WaitGroup
		for index := range calls {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				_, errs[index] = f.operator.Grant(context.Background(), calls[index])
			}()
		}
		close(start)
		wait.Wait()
		for index, err := range errs {
			if err != nil {
				t.Fatalf("round %d, grant %d: %v", round, index, err)
			}
		}
	}
	if got := f.db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", entitlement.AuditOperatorGrantIssued); got != 8 {
		t.Fatalf("%d grants issued", got)
	}
}

// TestAStrangerIsBoundedWhateverThePolicyIs (operator-2): on a center that has no policy a stranger is still a stranger, audited once
// per window; an operator is told why the center cannot grant.
func TestAStrangerIsBoundedWhateverThePolicyIs(t *testing.T) {
	for name, item := range map[string]struct {
		settings feature.Settings
		reason   string
	}{
		"a self-hosted center":                         {feature.Settings{Mode: config.SelfHosted}, "self_hosted"},
		"a hosted center without a plan configuration": {feature.Settings{Mode: config.OfficialHosted}, "no_catalogue"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newGrantFixture(t, item.settings)
			target := f.db.Account(1)
			stranger := f.db.Account(1)
			strangerSession := f.db.Session(stranger, 1)
			for i := 0; i < 5; i++ {
				_, err := f.operator.Grant(context.Background(), f.call(stranger, strangerSession, f.request(target, "remote.view"), false))
				wantArc(t, err, "AUTHORIZATION/permission_denied")
				_, err = f.operator.Review(context.Background(), entitlement.OperatorCaller{UserID: stranger, Scope: "account"}, f.request(target, "remote.view"))
				wantArc(t, err, "AUTHORIZATION/permission_denied")
			}
			if got := f.audits(entitlement.AuditOperatorGrantRefused, ""); got != 1 || f.audits(entitlement.AuditOperatorGrantRefused, "not_operator") != 1 {
				t.Fatalf("%d refusals audited for a stranger who asked ten times", got)
			}
			// An operator gets the reason of the center.
			user, session := f.operatorAccount()
			_, err := f.operator.Grant(context.Background(), f.call(user, session, f.request(target, "remote.view"), false))
			if refusal := wantArc(t, err, "STATE/invalid_state"); refusal.Reason != item.reason {
				t.Fatalf("the operator's refusal: %q, want %q", refusal.Reason, item.reason)
			}
		})
	}
}

// TestAGrantStopsAfterFourAttemptsOfADeadlockVictim pins the documented bound of four (tests-1): the evidence's consumption, which the
// test injects, ends every attempt as a deadlock victim, so no race is needed to reach the bound. Four attempts are made, none
// more and none fewer, the answer is the store's contention (RESOURCE/overloaded; the same command may be sent again), and
// nothing is written or spent. The Service writers share the constant; TestAWriterThatNeverWinsTheRaceFailsClosedWithATypedError
// counts their attempts.
func TestAGrantStopsAfterFourAttemptsOfADeadlockVictim(t *testing.T) {
	f := newGrantFixture(t, development)
	user, session := f.operatorAccount()
	call := f.call(user, session, f.request(f.db.Account(1), "remote.view"), true)
	calls := 0
	call.Consume = func(context.Context, pgx.Tx, [32]byte, time.Time) error {
		calls++
		return &store.Error{Operation: "consume the evidence", Kind: store.ErrContention, SQLState: "40P01"}
	}
	_, err := f.operator.Grant(context.Background(), call)
	if calls != 4 {
		t.Fatalf("%d attempts, the documented bound is four", calls)
	}
	if !errors.Is(err, store.ErrContention) {
		t.Fatalf("the answer after the last attempt: %v", err)
	}
	if f.written() != 0 || f.consumed() != 0 {
		t.Fatal("a grant that never got through wrote or spent evidence")
	}
	// A failure that is not a deadlock victim is not retried at all.
	calls = 0
	call.Consume = func(context.Context, pgx.Tx, [32]byte, time.Time) error {
		calls++
		return &store.Error{Operation: "consume the evidence", Kind: store.ErrUnavailable, SQLState: "57P01"}
	}
	if _, err = f.operator.Grant(context.Background(), call); err == nil || calls != 1 {
		t.Fatalf("an unavailable store: %d attempts, %v", calls, err)
	}
}
