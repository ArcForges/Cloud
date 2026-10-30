// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Day is a day in seconds, the unit the scenarios count in (the C# Fixtures.Day).
const Day = 86_400

// at is an instant of a scenario, in seconds since the epoch.
func at(seconds int64) Micros { return Micros(seconds * 1_000_000) }

// database is a migrated test database with the runtime role's store on it (EVIDENCE: REAL PostgreSQL 18, the pinned image).
type database struct {
	t         *testing.T
	migration *pgx.Conn
	runtime   *store.DB
	d         *dbtest.Database
}

func newDatabase(t *testing.T) *database {
	t.Helper()
	d := dbtest.New(t)
	return &database{t: t, migration: d.Migration, runtime: d.Runtime, d: d}
}

// exec runs statements as the migration role.
func (d *database) exec(statements ...string) { d.t.Helper(); d.d.Exec(statements...) }

func (d *database) count(query string, arguments ...any) int {
	d.t.Helper()
	return d.d.Count(query, arguments...)
}

// account creates an account and returns its uuid text.
func (d *database) account() string { d.t.Helper(); return d.d.Account(1).String() }

// testClock is the one settable clock of a scenario.
type testClock struct {
	mu  sync.Mutex
	now Micros
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now.Time()
}

func (c *testClock) Set(now Micros) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

func (c *testClock) At(seconds int64) { c.Set(at(seconds)) }

// fixedDefinitions is a settable definition source.
type fixedDefinitions struct {
	mu          sync.Mutex
	definitions Definitions
}

func (f *fixedDefinitions) Current() Definitions {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.definitions
}

func (f *fixedDefinitions) Set(definitions Definitions) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.definitions = definitions
}

// sequentialIDs are uuids in order, so a scenario's identifiers are predictable and sort as they were drawn.
type sequentialIDs struct{ next atomic.Int64 }

func (s *sequentialIDs) NewID() string {
	return fmt.Sprintf("00000000-0000-4000-8000-%012x", s.next.Add(1))
}

// testDefinitions are the definitions of the scenarios: the C# test fixtures' bundle (ordinary names, not the catalogue's).
func testDefinitions(selfHost bool) Definitions {
	gate := "feature.ai"
	return Definitions{Version: "bundle-1", IsSelfHostRealm: selfHost,
		Capabilities: []CapabilityDefinition{{Key: "cloud.sync", RequiresPaidTerm: true}, {Key: "cloud.ai", RequiresPaidTerm: true, FeatureGate: &gate},
			{Key: "cloud.web_continuity", RequiresPaidTerm: true}, {Key: "account.manage"}},
		Quotas: []QuotaDefinition{{Key: "cloud.storage.bytes", Combination: CombineSum}, {Key: "cloud.devices.max", Combination: CombineMax},
			{Key: "support.level", Combination: CombinePriorityReplace}},
		Allowances: []AllowanceDefinition{{Key: "ai.capacity"}}}
}

// scenario is one account served by a service over the runtime store, with one clock and one definition source.
type scenario struct {
	t           *testing.T
	db          *database
	service     *Service
	clock       *testClock
	definitions *fixedDefinitions
	account     string
}

func newScenario(t *testing.T) *scenario {
	t.Helper()
	d := newDatabase(t)
	return scenarioOn(t, d, d.account())
}

func scenarioOn(t *testing.T, d *database, account string) *scenario {
	t.Helper()
	clock := &testClock{}
	definitions := &fixedDefinitions{definitions: testDefinitions(false)}
	return &scenario{t: t, db: d, service: NewService(d.runtime, definitions, &sequentialIDs{}, clock.Now), clock: clock, definitions: definitions, account: account}
}

func (s *scenario) at(seconds int64) *scenario {
	s.clock.At(seconds)
	return s
}

func (s *scenario) read() StoredSnapshot {
	s.t.Helper()
	snapshot, err := s.service.Read(context.Background(), s.account)
	if err != nil {
		s.t.Fatalf("read: %v", err)
	}
	return snapshot
}

func (s *scenario) refresh() StoredSnapshot {
	s.t.Helper()
	snapshot, err := s.service.Refresh(context.Background(), s.account)
	if err != nil {
		s.t.Fatalf("refresh: %v", err)
	}
	return snapshot
}

func (s *scenario) issue(request IssueGrantRequest) Grant {
	s.t.Helper()
	request.AccountID = s.account
	grant, _, err := s.service.IssueGrant(context.Background(), request)
	if err != nil {
		s.t.Fatalf("issue: %v", err)
	}
	return grant
}

func (s *scenario) revoke(grantID string, expected int64, effective *Micros, reason string) Revocation {
	s.t.Helper()
	revocation, _, err := s.service.RevokeGrant(context.Background(), RevokeGrantRequest{AccountID: s.account, GrantID: grantID, ReasonCode: reason, EffectiveFrom: effective,
		IssuedByActor: "operator", ExpectedSnapshotVersion: expected})
	if err != nil {
		s.t.Fatalf("revoke: %v", err)
	}
	return revocation
}

// addTerm appends a service term as its owner admission would: with the migration role (the runtime role may insert terms, but the
// owners of terms are later tasks), then refreshes the snapshot at the current instant.
func (s *scenario) addTerm(id string, startsAt, endsAt int64, options ...func(*termSpec)) {
	s.t.Helper()
	spec := &termSpec{kind: 1, grace: -1, authorized: startsAt, created: -1}
	for _, option := range options {
		option(spec)
	}
	created := spec.created
	if created < 0 {
		created = int64(FromTime(s.clock.Now())) / 1_000_000
	}
	var subscription any
	if spec.kind == 1 {
		subscription = "sub-" + id
	}
	var grace any
	if spec.grace >= 0 {
		grace = at(spec.grace).Time()
	}
	if _, err := s.db.migration.Exec(context.Background(), `INSERT INTO entitlement.service_term (term_id, account_id, kind, subscription_ref, period_ref, starts_at, ends_at, grace_ends_at, authorized_at, created_at)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10)`, termUUID(id), s.account, spec.kind, subscription, "period-"+id, at(startsAt).Time(), at(endsAt).Time(), grace,
		at(spec.authorized).Time(), at(created).Time()); err != nil {
		s.t.Fatal(err)
	}
	s.refresh()
}

type termSpec struct {
	kind                       int
	grace, authorized, created int64
}

func withGrace(seconds int64) func(*termSpec)   { return func(t *termSpec) { t.grace = seconds } }
func withCreated(seconds int64) func(*termSpec) { return func(t *termSpec) { t.created = seconds } }
func withAuthorized(seconds int64) func(*termSpec) {
	return func(t *termSpec) { t.authorized = seconds }
}

// termUUID maps a scenario's term name to a stable uuid.
func termUUID(name string) string {
	var sum [16]byte
	copy(sum[:], name)
	sum[6], sum[8] = sum[6]&0x0f|0x40, sum[8]&0x3f|0x80
	return platform.ID(sum).String()
}

func ref(value string) *string { return &value }

// capabilityRequest is a capability grant request the scenarios issue (the C# Fixtures.Capability).
func capabilityRequest(subject string, from int64, until *int64, sourceRef string, options ...func(*IssueGrantRequest)) IssueGrantRequest {
	request := IssueGrantRequest{Kind: KindCapability, Subject: subject, Value: CapabilityValue{}, Source: SourceSubscription, SourceRef: ref(sourceRef), EffectiveFrom: at(from),
		IssuedByActor: "commerce"}
	if until != nil {
		value := at(*until)
		request.EffectiveUntil = &value
	}
	for _, option := range options {
		option(&request)
	}
	return request
}

func administrative(reason string) func(*IssueGrantRequest) {
	return func(r *IssueGrantRequest) { r.Source, r.Reason = SourceAdminGrant, &reason }
}

func capabilityOf(snapshot StoredSnapshot, key string) CapabilityEntry {
	entry, ok := snapshot.Capability(key)
	if !ok {
		panic("the snapshot has no capability " + key)
	}
	return entry
}

func (s *scenario) assertRebuildEqual() {
	s.t.Helper()
	report, err := s.service.VerifyRebuild(context.Background(), s.account)
	if err != nil {
		s.t.Fatal(err)
	}
	if report.Status != RebuildEqual && report.Status != RebuildNoSnapshot {
		s.t.Fatalf("the rebuild differs (%d): %v", report.Status, report.Differences)
	}
}

func microsPtr(value Micros) *Micros { return &value }
