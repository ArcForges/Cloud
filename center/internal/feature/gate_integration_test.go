// SPDX-License-Identifier: AGPL-3.0-only

package feature

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The gate over the real entitlement service on real PostgreSQL (EVIDENCE: REAL logic and store; the catalogue is a MOCKED
// illustrative fixture, or, for the production classification, a test-only document injected in process).

type settableClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *settableClock) Now() time.Time    { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *settableClock) Set(now time.Time) { c.mu.Lock(); defer c.mu.Unlock(); c.now = now }

type fixture struct {
	t       *testing.T
	db      *dbtest.Database
	service *entitlement.Service
	gate    Gate
	clock   *settableClock
}

func newFixture(t *testing.T, settings Settings) *fixture {
	t.Helper()
	db := dbtest.New(t)
	configuration := Configure(settings)
	clock := &settableClock{now: time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)}
	service := entitlement.NewService(db.Runtime, configuration, nil, clock.Now)
	return &fixture{t: t, db: db, service: service, gate: NewGate(configuration, service), clock: clock}
}

func (f *fixture) decision(account platform.ID, key Key) Decision {
	return f.gate.Availability(WithAccount(context.Background(), account.String()), key)
}

// operatorGrant writes what an operator grant writes (package entitlement's operator flow tests the real thing): an AdminGrant
// capability grant per key and one compensation term over the same window, the term inserted by the migration role.
func (f *fixture) operatorGrant(account platform.ID, days int, keys ...Key) {
	f.t.Helper()
	now := f.clock.Now()
	reference := "ticket-" + platform.NewID().String()[:8]
	for _, key := range keys {
		reason := "operator goodwill"
		sourceRef := reference + "-" + string(key)
		if _, _, err := f.service.IssueGrant(context.Background(), entitlement.IssueGrantRequest{AccountID: account.String(), Kind: entitlement.KindCapability, Subject: string(key),
			Value: entitlement.CapabilityValue{}, Source: entitlement.SourceAdminGrant, SourceRef: &sourceRef, EffectiveFrom: entitlement.FromTime(now),
			EffectiveUntil: untilOf(now.Add(time.Duration(days) * 24 * time.Hour)), IssuedByActor: "operator:test", Reason: &reason}); err != nil {
			f.t.Fatal(err)
		}
	}
	f.term(account, 3, reference, now, now.Add(time.Duration(days)*24*time.Hour), nil)
}

func untilOf(at time.Time) *entitlement.Micros {
	value := entitlement.FromTime(at)
	return &value
}

// term inserts a service term as its owner admission would, created at the clock's instant, then refreshes the account.
func (f *fixture) term(account platform.ID, kind int, period string, starts, ends time.Time, grace *time.Time) {
	f.t.Helper()
	var subscription any
	if kind == 1 {
		subscription = "sub-" + period
	}
	if _, err := f.db.Migration.Exec(context.Background(), `INSERT INTO entitlement.service_term (term_id, account_id, kind, subscription_ref, period_ref, starts_at, ends_at, grace_ends_at, authorized_at, created_at)
VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $5, $8)`, account, kind, subscription, period, starts, ends, grace, f.clock.Now()); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.service.Refresh(context.Background(), account.String()); err != nil {
		f.t.Fatal(err)
	}
}

func TestTheFixtureCatalogueWithoutAGrantEnablesNothing(t *testing.T) {
	f := newFixture(t, Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := f.db.Account(1)
	for _, key := range Gated() {
		if decision := f.decision(account, key); decision.Available || decision.Reason != ReasonNoEntitlement {
			t.Fatalf("%s: %+v", key, decision)
		}
	}
	// A key outside the catalogue is unknown whatever the account holds.
	if decision := f.decision(account, "remote.nothing"); decision.Available || decision.Reason != ReasonUnknownFeature {
		t.Fatalf("an unknown key: %+v", decision)
	}
}

func TestAnOperatorGrantEnablesTheNamedKeysOfThatAccountOnly(t *testing.T) {
	f := newFixture(t, Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	granted, other := f.db.Account(1), f.db.Account(1)
	f.operatorGrant(granted, 30, RemoteView, Push)
	for _, key := range Gated() {
		want := key == RemoteView || key == Push
		decision := f.decision(granted, key)
		if decision.Available != want || want && decision.Reason != ReasonEntitled || !want && decision.Reason != ReasonNoEntitlement {
			t.Errorf("granted account, %s: %+v", key, decision)
		}
		if decision := f.decision(other, key); decision.Available || decision.Reason != ReasonNoEntitlement {
			t.Errorf("another account, %s: %+v", key, decision)
		}
	}
	// A grant lapses with its own end: after thirty days the account has nothing again.
	f.clock.Set(f.clock.Now().Add(31 * 24 * time.Hour))
	if decision := f.decision(granted, RemoteView); decision.Available {
		t.Fatalf("a lapsed operator grant: %+v", decision)
	}
}

// TestALapsedPaidGrantPlusAnOperatorGrant (DC-22): a subscription whose term ended reads as expired; an operator grant for the same
// key on the same account enables it again, and its end returns the account to the lapsed state.
func TestALapsedPaidGrantPlusAnOperatorGrant(t *testing.T) {
	f := newFixture(t, Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := f.db.Account(1)
	start := f.clock.Now()
	paid := "order-1"
	if _, _, err := f.service.IssueGrant(context.Background(), entitlement.IssueGrantRequest{AccountID: account.String(), Kind: entitlement.KindCapability, Subject: string(RemoteView),
		Value: entitlement.CapabilityValue{}, Source: entitlement.SourceSubscription, SourceRef: &paid, EffectiveFrom: entitlement.FromTime(start), IssuedByActor: "commerce"}); err != nil {
		t.Fatal(err)
	}
	f.term(account, 1, "p1", start, start.Add(30*24*time.Hour), ptr(start.Add(37*24*time.Hour)))
	if decision := f.decision(account, RemoteView); !decision.Available || decision.Reason != ReasonEntitled {
		t.Fatalf("while the paid term runs: %+v", decision)
	}
	f.clock.Set(start.Add(45 * 24 * time.Hour))
	if decision := f.decision(account, RemoteView); decision.Available || decision.Reason != ReasonSubscriptionExpired {
		t.Fatalf("after the paid term and its grace: %+v", decision)
	}
	f.clock.Set(start.Add(46 * 24 * time.Hour))
	f.operatorGrant(account, 10, RemoteView)
	if decision := f.decision(account, RemoteView); !decision.Available || decision.Reason != ReasonEntitled {
		t.Fatalf("with the operator grant: %+v", decision)
	}
	if decision := f.decision(account, Push); decision.Available {
		t.Fatalf("a key the operator did not name: %+v", decision)
	}
	f.clock.Set(start.Add(60 * 24 * time.Hour))
	if decision := f.decision(account, RemoteView); decision.Available || decision.Reason != ReasonSubscriptionExpired {
		t.Fatalf("after the operator grant ended: %+v", decision)
	}
}

func ptr(at time.Time) *time.Time { return &at }

func TestASuspendedAccountHasNoFeatureWhateverItHolds(t *testing.T) {
	f := newFixture(t, Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := f.db.Account(1)
	f.operatorGrant(account, 30, RemoteView)
	f.clock.Set(f.clock.Now().Add(time.Minute))
	f.db.Exec("INSERT INTO entitlement.account_status_fact (status_fact_id, account_id, recorded_at, status, auto_renew, purchase_pending, source_ref) VALUES (gen_random_uuid(), '" +
		account.String() + "', '" + f.clock.Now().Format(time.RFC3339Nano) + "', 3, true, false, 'suspend-1')")
	f.clock.Set(f.clock.Now().Add(time.Minute))
	// A status fact is not a boundary of the snapshot's validity: its owner admission refreshes the snapshot in the same unit (the C#
	// rule), which this test does by hand. Until then the stored snapshot still holds and the gate follows it.
	if decision := f.decision(account, RemoteView); !decision.Available {
		t.Fatalf("before the owner refreshes the snapshot: %+v", decision)
	}
	if _, err := f.service.Refresh(context.Background(), account.String()); err != nil {
		t.Fatal(err)
	}
	if decision := f.decision(account, RemoteView); decision.Available || decision.Reason != ReasonAccountSuspended {
		t.Fatalf("a suspended account: %+v", decision)
	}
}

func TestTheProductionClassifiedTestCatalogueGatesTheSameWay(t *testing.T) {
	f := newFixture(t, Settings{Mode: config.OfficialHosted, Injected: []byte(validProduction), InjectedClass: ClassProduction})
	account := f.db.Account(1)
	if decision := f.decision(account, RemoteView); decision.Available || decision.Reason != ReasonNoEntitlement {
		t.Fatalf("without a grant: %+v", decision)
	}
	f.operatorGrant(account, 30, RemoteView)
	if decision := f.decision(account, RemoteView); !decision.Available || decision.Reason != ReasonEntitled {
		t.Fatalf("with a grant: %+v", decision)
	}
}

func TestADefinitionsChangeIsOneVersionStepForTheAccount(t *testing.T) {
	f := newFixture(t, Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := f.db.Account(1)
	f.operatorGrant(account, 30, RemoteView)
	first, err := f.service.Read(context.Background(), account.String())
	if err != nil {
		t.Fatal(err)
	}
	// The same grants under another catalogue (a new definitions version) are one change for the client, not zero and not two.
	other := newGate(t, f, Settings{Mode: config.OfficialHosted, Injected: []byte(validProduction), InjectedClass: ClassProduction})
	second, err := other.Read(context.Background(), account.String())
	if err != nil || second.Version != first.Version+1 || second.DefinitionsVersion != "2026-q4" {
		t.Fatalf("%+v -> %+v %v", first, second, err)
	}
}

func newGate(t *testing.T, f *fixture, settings Settings) *entitlement.Service {
	t.Helper()
	return entitlement.NewService(f.db.Runtime, Configure(settings), nil, f.clock.Now)
}

func TestTheGateFailsClosedWhenTheStoreCannotAnswer(t *testing.T) {
	f := newFixture(t, Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	account := f.db.Account(1)
	f.operatorGrant(account, 30, RemoteView)
	f.db.Exec("ALTER TABLE entitlement.snapshot RENAME TO snapshot_away")
	decision := f.decision(account, RemoteView)
	if decision.Available || decision.Reason != ReasonEntitlementUnavailable || decision.Err == nil {
		t.Fatalf("a store that cannot answer: %+v", decision)
	}
	canceled, cancel := context.WithCancel(WithAccount(context.Background(), account.String()))
	cancel()
	if decision = f.gate.Availability(canceled, RemoteView); decision.Available || decision.Reason != ReasonEntitlementUnavailable {
		t.Fatalf("a canceled call: %+v", decision)
	}
}

func TestASelfHostedCenterNeverReadsAnEntitlement(t *testing.T) {
	f := newFixture(t, Settings{Mode: config.SelfHosted, Disabled: []Key{CenterMCP}})
	account := f.db.Account(1)
	f.db.Exec("ALTER TABLE entitlement.snapshot RENAME TO snapshot_away")
	if decision := f.decision(account, RemoteView); !decision.Available || decision.Reason != ReasonSelfHostedDefault {
		t.Fatalf("%+v", decision)
	}
	if decision := f.decision(account, CenterMCP); decision.Available || decision.Reason != ReasonOperatorLimit {
		t.Fatalf("%+v", decision)
	}
}
