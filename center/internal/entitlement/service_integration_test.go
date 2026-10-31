// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/store"
)

// The store and service behaviours of the C# suites that no pure vector can show, ported by hand onto real PostgreSQL
// (EVIDENCE: REAL logic, REAL PostgreSQL 18): idempotent issue by source reference, the stale-revision refusal, concurrent writers, a
// clock that moves backwards, rebuild equivalence, and the typed outcomes of a store that fails.

func wantRefusal(t *testing.T, err error, kind RefusalKind) *Refusal {
	t.Helper()
	refusal, ok := RefusalOf(err)
	if !ok || refusal.Kind != kind {
		t.Fatalf("want the refusal %v, got %v", kind, err)
	}
	return refusal
}

func TestAnIssuedGrantIsIdempotentBySourceReference(t *testing.T) {
	s := newScenario(t).at(0)
	request := capabilityRequest("cloud.sync", 0, nil, "order-1")
	request.AccountID = s.account
	first, duplicate, err := s.service.IssueGrant(context.Background(), request)
	if err != nil || duplicate {
		t.Fatalf("first issue: %v %v", duplicate, err)
	}
	replay, duplicate, err := s.service.IssueGrant(context.Background(), request)
	if err != nil || !duplicate || replay.GrantID != first.GrantID {
		t.Fatalf("a replay: %+v %v %v", replay, duplicate, err)
	}
	if rows := s.db.count("SELECT count(*) FROM entitlement.grant WHERE account_id = $1::uuid", s.account); rows != 1 {
		t.Fatalf("a replay wrote a second grant: %d rows", rows)
	}
	// The same reference for a different grant is a conflict and writes nothing.
	different := request
	different.Subject = "cloud.web_continuity"
	_, _, err = s.service.IssueGrant(context.Background(), different)
	wantRefusal(t, err, RefusedConflict)
	if rows := s.db.count("SELECT count(*) FROM entitlement.grant WHERE account_id = $1::uuid", s.account); rows != 1 {
		t.Fatalf("a conflicting issue wrote a grant: %d rows", rows)
	}
	// A reference is per account and per source: another source with the same reference is a different issuance.
	other := request
	other.Source, other.Reason = SourceAdminGrant, ref("goodwill")
	if _, duplicate, err = s.service.IssueGrant(context.Background(), other); err != nil || duplicate {
		t.Fatalf("another source, same reference: %v %v", duplicate, err)
	}
	s.assertRebuildEqual()
}

func TestAnInadmissibleIssueWritesNothingAndIsRefusedBeforeTheStore(t *testing.T) {
	s := newScenario(t).at(0)
	bad := capabilityRequest("Cloud.Sync", 0, nil, "x")
	bad.AccountID = s.account
	_, _, err := s.service.IssueGrant(context.Background(), bad)
	refusal := wantRefusal(t, err, RefusedInvalidRequest)
	if refusal.Detail != "The grant subject is malformed." {
		t.Fatalf("the reason: %q", refusal.Detail)
	}
	missing := capabilityRequest("cloud.sync", 0, nil, "x", administrative(""))
	missing.AccountID = s.account
	_, _, err = s.service.IssueGrant(context.Background(), missing)
	wantRefusal(t, err, RefusedInvalidRequest)
	if rows := s.db.count("SELECT count(*) FROM entitlement.revision"); rows != 0 {
		t.Fatalf("a refused issue touched the store: %d revisions", rows)
	}
}

func TestAStaleRevisionIsRefusedAndWritesNothing(t *testing.T) {
	s := newScenario(t).at(5)
	s.issue(capabilityRequest("cloud.sync", 0, nil, "first"))
	ctx := context.Background()
	var stale State
	if err := s.db.runtime.InTx(ctx, "load", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) (err error) {
		stale, err = Load(ctx, tx, s.account)
		return err
	}); err != nil || stale.Revision != 1 {
		t.Fatalf("load: %+v %v", stale, err)
	}
	s.at(6).issue(capabilityRequest("cloud.web_continuity", 0, nil, "second"))
	late := Grant{GrantID: "00000000-0000-4000-8000-0000000000ff", AccountID: s.account, Kind: KindCapability, Subject: "cloud.sync", Value: CapabilityValue{}, Source: SourceSubscription,
		SourceRef: ref("late"), EffectiveFrom: at(0), IssuedByActor: "commerce", CreatedAt: at(7)}
	records := stale.Records
	records.Grants = append(append([]Grant(nil), records.Grants...), late)
	snapshot, err := Resolve(records, testDefinitions(false), at(7))
	if err != nil {
		t.Fatal(err)
	}
	var outcome CommitOutcome
	if err = s.db.runtime.InTx(ctx, "commit", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) (err error) {
		outcome, err = Commit(ctx, tx, s.account, stale.Revision, Append{Grants: []Grant{late}}, snapshot, s.clock.Now())
		return err
	}); err != nil || outcome != RevisionConflict {
		t.Fatalf("a stale commit: %v %v", outcome, err)
	}
	if rows := s.db.count("SELECT count(*) FROM entitlement.grant WHERE source_ref = 'late'"); rows != 0 {
		t.Fatalf("a stale commit wrote its grant")
	}
	// A first commit over an existing fence is stale too.
	if err = s.db.runtime.InTx(ctx, "commit", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) (err error) {
		outcome, err = Commit(ctx, tx, s.account, 0, Append{}, snapshot, s.clock.Now())
		return err
	}); err != nil || outcome != RevisionConflict {
		t.Fatalf("a first commit over an existing fence: %v %v", outcome, err)
	}
}

func TestTwoSimultaneousFirstCommitsOfAnAccountCannotBothSucceed(t *testing.T) {
	d := newDatabase(t)
	account := d.account()
	snapshot, err := Resolve(EmptyRecords(account), testDefinitions(false), at(1))
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	outcomes := make([]CommitOutcome, 2)
	for i := range outcomes {
		group.Add(1)
		go func() {
			defer group.Done()
			err := d.runtime.InTx(context.Background(), "first commit", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) (err error) {
				outcomes[i], err = Commit(ctx, tx, account, 0, Append{}, snapshot, at(1).Time())
				return err
			})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	committed, conflicts := 0, 0
	for _, outcome := range outcomes {
		switch outcome {
		case Committed:
			committed++
		case RevisionConflict:
			conflicts++
		}
	}
	if committed != 1 || conflicts != 1 || d.count("SELECT rev FROM entitlement.revision WHERE account_id = $1::uuid", account) != 1 {
		t.Fatalf("outcomes %v", outcomes)
	}
}

func TestConcurrentIssuersNeverLoseAGrantOrLeaveAStaleSnapshot(t *testing.T) {
	s := newScenario(t).at(0)
	s.addTerm("t1", 0, 30*Day)
	var group sync.WaitGroup
	errs := make([]error, 3)
	for i := range errs {
		group.Add(1)
		go func() {
			defer group.Done()
			request := capabilityRequest("cloud.sync", 0, nil, "ref"+string(rune('a'+i)))
			request.AccountID = s.account
			_, _, errs[i] = s.service.IssueGrant(context.Background(), request)
		}()
	}
	group.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("a concurrent issuer: %v", err)
		}
	}
	if rows := s.db.count("SELECT count(*) FROM entitlement.grant WHERE account_id = $1::uuid", s.account); rows != 3 {
		t.Fatalf("%d grants of three issuers", rows)
	}
	if entry := capabilityOf(s.read(), "cloud.sync"); !entry.Granted {
		t.Fatalf("the snapshot is stale: %+v", entry)
	}
	line := strings.SplitN(strings.SplitN(s.read().Content, "cap=cloud.sync|", 2)[1], "\n", 2)[0]
	if strings.Count(line, ",") != 2 {
		t.Fatalf("the snapshot does not list the three grants: %s", line)
	}
	s.assertRebuildEqual()
}

func TestAWriterThatLosesTheRaceRederivesItsSnapshotFromTheNewHistory(t *testing.T) {
	s := newScenario(t).at(0)
	s.addTerm("t1", 0, 30*Day)
	rival := NewService(s.db.runtime, s.definitions, &sequentialIDs{}, s.clock.Now)
	interleaved := false
	s.service.beforeCommit = func() {
		if interleaved {
			return
		}
		interleaved = true
		request := capabilityRequest("cloud.web_continuity", 0, nil, "other")
		request.AccountID = s.account
		if _, _, err := rival.IssueGrant(context.Background(), request); err != nil {
			t.Error(err)
		}
	}
	mine := s.issue(capabilityRequest("cloud.sync", 0, nil, "mine"))
	snapshot := s.read()
	if !capabilityOf(snapshot, "cloud.sync").Granted || !capabilityOf(snapshot, "cloud.web_continuity").Granted {
		t.Fatalf("a writer that lost the race dropped a record: %s", snapshot.Content)
	}
	if !strings.Contains(snapshot.Content, "cap=cloud.sync|1|Available|"+mine.GrantID+"\n") {
		t.Fatalf("my grant is missing: %s", snapshot.Content)
	}
	s.assertRebuildEqual()
}

func TestAWriterThatNeverWinsTheRaceFailsClosedWithATypedError(t *testing.T) {
	s := newScenario(t).at(0)
	rival := NewService(s.db.runtime, s.definitions, &sequentialIDs{}, s.clock.Now)
	bump := 0
	var interfere func()
	interfere = func() {
		request := capabilityRequest("cloud.web_continuity", 0, nil, "bump"+string(rune('a'+bump)))
		request.AccountID = s.account
		bump++
		if _, _, err := rival.IssueGrant(context.Background(), request); err != nil {
			t.Error(err)
		}
		s.service.beforeCommit = interfere
	}
	s.service.beforeCommit = interfere
	request := capabilityRequest("cloud.sync", 0, nil, "mine")
	request.AccountID = s.account
	_, _, err := s.service.IssueGrant(context.Background(), request)
	wantRefusal(t, err, RefusedConcurrentUpdate)
	if rows := s.db.count("SELECT count(*) FROM entitlement.grant WHERE source_ref = 'mine'"); rows != 0 {
		t.Fatalf("a writer that never won wrote its grant")
	}
}

func TestAClockThatMovesBackwardsNeverRewindsAStoredComputationOrBackdatesARecord(t *testing.T) {
	s := newScenario(t).at(10 * Day)
	s.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
	stored := s.refresh()
	s.at(5 * Day)
	after := s.refresh()
	if after.ComputedAt != stored.ComputedAt {
		t.Fatalf("the stored computation moved: %d -> %d", stored.ComputedAt, after.ComputedAt)
	}
	grant := s.issue(capabilityRequest("cloud.web_continuity", 0, nil, "s2"))
	// Admitted strictly after the stored computation (one microsecond), never at the rolled-back clock's earlier instant.
	if grant.CreatedAt != stored.ComputedAt+1 {
		t.Fatalf("a record was admitted at %d, not one microsecond after the stored computation %d", grant.CreatedAt, stored.ComputedAt)
	}
	s.assertRebuildEqual()
}

func TestTwoReplicasAtTheSameInstantProduceTheSameSnapshot(t *testing.T) {
	one := newScenario(t).at(0)
	one.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
	one.addTerm("t1", 0, 30*Day)
	first := one.at(Day).refresh()
	replicaClock := &testClock{}
	replicaClock.At(Day)
	replica := NewService(one.db.runtime, one.definitions, &sequentialIDs{}, replicaClock.Now)
	second, err := replica.Read(context.Background(), one.account)
	if err != nil || !first.SameAs(second) {
		t.Fatalf("the replicas differ: %v\n%+v\n%+v", err, first, second)
	}
}

func TestAReadReturnsTheStoredSnapshotWhileItsValidityHoldsAndRecomputesAfter(t *testing.T) {
	s := newScenario(t).at(0)
	s.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
	s.addTerm("t1", Day, 31*Day, withGrace(38*Day))
	first := s.at(2 * Day).read()
	if first.ValidUntil == nil || *first.ValidUntil != at(31*Day) {
		t.Fatalf("validUntil: %v", first.ValidUntil)
	}
	revisions := s.db.count("SELECT rev FROM entitlement.revision WHERE account_id = $1::uuid", s.account)
	if again := s.at(20 * Day).read(); !again.SameAs(first) || s.db.count("SELECT rev FROM entitlement.revision WHERE account_id = $1::uuid", s.account) != revisions {
		t.Fatalf("a read inside the validity rewrote the snapshot")
	}
	// Exactly at the instant the validity ends, the snapshot is recomputed (the end is exclusive).
	if boundary := s.at(31 * Day).read(); boundary.Version <= first.Version || capabilityOf(boundary, "cloud.sync").Reason != ReasonPaymentGrace {
		t.Fatalf("at the exact end of the validity: %+v", boundary)
	}
	grace := s.at(33 * Day).read()
	if grace.Version <= first.Version || capabilityOf(grace, "cloud.sync").Reason != ReasonPaymentGrace {
		t.Fatalf("after the validity: %+v", grace)
	}
	// An unchanged account is not rewritten at every later instant.
	rev := s.db.count("SELECT rev FROM entitlement.revision WHERE account_id = $1::uuid", s.account)
	s.at(34 * Day).refresh()
	s.at(35 * Day).refresh()
	if s.db.count("SELECT rev FROM entitlement.revision WHERE account_id = $1::uuid", s.account) != rev {
		t.Fatalf("an unchanged account was rewritten by a later refresh")
	}
	s.assertRebuildEqual()
}

func TestADefinitionsChangeRaisesTheVersionOnceAndIsRecorded(t *testing.T) {
	s := newScenario(t).at(0)
	s.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
	first := s.refresh()
	changed := testDefinitions(false)
	changed.Version = "bundle-2"
	s.definitions.Set(changed)
	second := s.at(Day).read()
	if second.Version != first.Version+1 || second.DefinitionsVersion != "bundle-2" {
		t.Fatalf("a definitions activation: %d -> %d (%s)", first.Version, second.Version, second.DefinitionsVersion)
	}
	if third := s.at(2 * Day).read(); third.Version != second.Version {
		t.Fatalf("the activation raised the version twice: %d", third.Version)
	}
	if rows := s.db.count("SELECT count(*) FROM entitlement.definitions_activation WHERE account_id = $1::uuid", s.account); rows != 2 {
		t.Fatalf("%d activations recorded", rows)
	}
	s.definitions.Set(testDefinitions(false))
	if back := s.at(3 * Day).read(); back.Version != second.Version+1 {
		t.Fatalf("returning to the first definitions: %d", back.Version)
	}
	s.assertRebuildEqual()
	// The definitions of a snapshot are the ones the rebuild must use; others are reported, not applied.
	s.definitions.Set(changed)
	report, err := s.service.VerifyRebuild(context.Background(), s.account)
	if err != nil || report.Status != RebuildDefinitionsChanged {
		t.Fatalf("the rebuild under other definitions: %+v %v", report, err)
	}
}

func TestARevocationEndsAGrantWithoutEditingItAndAStaleVersionWritesNothing(t *testing.T) {
	s := newScenario(t).at(0)
	grant := s.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
	s.addTerm("t1", 0, 30*Day)
	version := s.at(Day).read().Version
	_, _, err := s.service.RevokeGrant(context.Background(), RevokeGrantRequest{AccountID: s.account, GrantID: grant.GrantID, ReasonCode: "refund", IssuedByActor: "operator",
		ExpectedSnapshotVersion: version - 1})
	wantRefusal(t, err, RefusedStaleVersion)
	_, _, err = s.service.RevokeGrant(context.Background(), RevokeGrantRequest{AccountID: s.account, GrantID: "nope", ReasonCode: "refund", IssuedByActor: "operator", ExpectedSnapshotVersion: version})
	wantRefusal(t, err, RefusedUnknownGrant)
	_, _, err = s.service.RevokeGrant(context.Background(), RevokeGrantRequest{AccountID: s.account, GrantID: grant.GrantID, ReasonCode: "Not A Code", IssuedByActor: "operator", ExpectedSnapshotVersion: version})
	wantRefusal(t, err, RefusedInvalidRequest)
	if rows := s.db.count("SELECT count(*) FROM entitlement.revocation"); rows != 0 {
		t.Fatalf("a refused revocation wrote a row")
	}
	revocation := s.revoke(grant.GrantID, version, microsPtr(at(0)), "refund")
	if capabilityOf(s.read(), "cloud.sync").Granted {
		t.Fatalf("a revoked grant still grants")
	}
	// A replay without an explicit instant writes nothing, and the grant row is as issued.
	replay, duplicate, err := s.service.RevokeGrant(context.Background(), RevokeGrantRequest{AccountID: s.account, GrantID: grant.GrantID, ReasonCode: "refund", IssuedByActor: "operator",
		ExpectedSnapshotVersion: s.read().Version})
	if err != nil || !duplicate || replay.RevocationID != revocation.RevocationID {
		t.Fatalf("a replayed revocation: %+v %v %v", replay, duplicate, err)
	}
	if rows := s.db.count("SELECT count(*) FROM entitlement.revocation"); rows != 1 {
		t.Fatalf("%d revocations", rows)
	}
	if rows := s.db.count("SELECT count(*) FROM entitlement.grant WHERE grant_id = $1::uuid AND effective_until IS NULL", grant.GrantID); rows != 1 {
		t.Fatalf("a revocation edited its grant")
	}
	s.assertRebuildEqual()
}

func TestAHistoryTheResolverCannotInterpretYieldsNoSnapshotAndNoWrite(t *testing.T) {
	// The schema's constraints keep almost every history the validator refuses out of the store (the parity vectors hold the validator);
	// a history over the replay bound is the one a store can hold, and the service fails closed on it: no snapshot, no write.
	s := newScenario(t).at(10)
	s.issue(capabilityRequest("cloud.sync", 0, nil, "sub1"))
	revision := s.db.count("SELECT rev FROM entitlement.revision WHERE account_id = $1::uuid", s.account)
	s.db.exec("INSERT INTO entitlement.account_status_fact (status_fact_id, account_id, recorded_at, status, auto_renew, purchase_pending, source_ref) " +
		"SELECT gen_random_uuid(), '" + s.account + "'::uuid, to_timestamp(i), 1, true, false, 'bulk-' || i FROM generate_series(1, 2000) AS i")
	_, err := s.service.Refresh(context.Background(), s.account)
	refusal := wantRefusal(t, err, RefusedInvalidHistory)
	if refusal.Detail != "The record history exceeds the replay bound." {
		t.Fatalf("the reason: %q", refusal.Detail)
	}
	request := capabilityRequest("cloud.web_continuity", 0, nil, "next")
	request.AccountID = s.account
	_, _, err = s.service.IssueGrant(context.Background(), request)
	wantRefusal(t, err, RefusedInvalidHistory)
	if s.db.count("SELECT rev FROM entitlement.revision WHERE account_id = $1::uuid", s.account) != revision || s.db.count("SELECT count(*) FROM entitlement.grant") != 1 {
		t.Fatalf("a refused history wrote something")
	}
}

func TestARecordAdmittedBeforeTheStoredComputationCannotLowerTheVersion(t *testing.T) {
	s := newScenario(t).at(0)
	s.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
	s.addTerm("t1", Day, 100*Day, withCreated(0))
	stored := s.at(10 * Day).refresh()
	if stored.Version < 2 {
		t.Fatalf("version %d", stored.Version)
	}
	// A term stamped with an old creation time and a start of zero would make the replay see service from the start, which collapses
	// two earlier changes into one and derives a lower version than the one clients may already hold.
	s.db.exec("INSERT INTO entitlement.service_term (term_id, account_id, kind, subscription_ref, period_ref, starts_at, ends_at, authorized_at, created_at) VALUES ('" +
		termUUID("t2") + "', '" + s.account + "', 1, 'sub-t2', 'period-t2', to_timestamp(0), to_timestamp(8640000), to_timestamp(0), to_timestamp(0))")
	_, err := s.service.Refresh(context.Background(), s.account)
	refusal := wantRefusal(t, err, RefusedInvalidHistory)
	if !strings.Contains(refusal.Detail, "fell below") {
		t.Fatalf("the reason: %q", refusal.Detail)
	}
	report, err := s.service.VerifyRebuild(context.Background(), s.account)
	if err != nil || report.Stored == nil || report.Stored.Version != stored.Version {
		t.Fatalf("the stored snapshot changed: %+v %v", report, err)
	}
}

func TestATamperedSnapshotIsAMismatchAndIsNeverOverwrittenByTheRebuild(t *testing.T) {
	s := newScenario(t).at(0)
	s.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
	s.addTerm("t1", 0, 30*Day)
	s.at(Day).refresh()
	s.assertRebuildEqual()
	s.db.exec("UPDATE entitlement.snapshot SET content = replace(content, 'cap=cloud.sync|1|Available', 'cap=cloud.sync|0|NoEntitlement') WHERE account_id = '" + s.account + "'::uuid")
	report, err := s.service.VerifyRebuild(context.Background(), s.account)
	if err != nil || report.Status != RebuildMismatch || len(report.Differences) == 0 {
		t.Fatalf("a tampered snapshot: %+v %v", report, err)
	}
	if rows := s.db.count("SELECT count(*) FROM entitlement.snapshot WHERE content LIKE '%cap=cloud.sync|0|NoEntitlement%'"); rows != 1 {
		t.Fatalf("the rebuild overwrote the stored snapshot")
	}
	// The next refresh repairs it (the content differs from the derivation), and the rebuild is equal again.
	s.at(2 * Day).refresh()
	s.assertRebuildEqual()
}

func TestRebuildEquivalenceOverTheFixtureAccounts(t *testing.T) {
	accounts := map[string]func(s *scenario){
		"empty": func(s *scenario) {},
		"monthly-with-renewal-addon-and-cancel": func(s *scenario) {
			s.issue(capabilityRequest("cloud.sync", 0, nil, "sub1-p1"))
			s.issue(IssueGrantRequest{Kind: KindQuota, Subject: "cloud.storage.bytes", Value: QuotaValue{Limit: 50}, Source: SourceSubscription, SourceRef: ref("base"), EffectiveFrom: at(0), IssuedByActor: "commerce"})
			s.addTerm("t1", Day, 31*Day, withGrace(38*Day))
			s.at(20*Day).addTerm("t2", 31*Day, 61*Day, withGrace(68*Day))
			s.at(24 * Day).issue(IssueGrantRequest{Kind: KindQuota, Subject: "cloud.storage.bytes", Value: QuotaValue{Limit: 100}, Source: SourceStorageAddOn, SourceRef: ref("addon"),
				EffectiveFrom: at(25 * Day), EffectiveUntil: microsPtr(at(50 * Day)), IssuedByActor: "commerce"})
			s.at(40 * Day).refresh()
		},
		"grace-then-late-recovery": func(s *scenario) {
			s.issue(capabilityRequest("cloud.sync", 0, nil, "sub1"))
			s.addTerm("t1", 0, 30*Day, withGrace(37*Day))
			s.at(33*Day).addTerm("t2", 30*Day, 60*Day, withAuthorized(33*Day))
		},
		"late-issued-grant-with-earlier-start": func(s *scenario) {
			s.addTerm("t1", 0, 100*Day)
			s.at(10 * Day).issue(capabilityRequest("cloud.sync", 2*Day, nil, "late1"))
		},
		"self-host-realm-ignores-official-terms": func(s *scenario) {
			s.definitions.Set(testDefinitions(true))
			s.issue(capabilityRequest("cloud.sync", 0, nil, "sub1"))
			s.addTerm("t1", 0, 30*Day)
		},
	}
	for name, run := range accounts {
		t.Run(name, func(t *testing.T) {
			s := newScenario(t).at(0)
			run(s)
			for _, day := range []int64{1, 20, 33, 45, 70, 100} {
				stored := s.at(day * Day).refresh()
				s.assertRebuildEqual()
				// However often it was evaluated in between, a fresh service from nothing derives the same snapshot.
				fresh := NewService(s.db.runtime, s.definitions, &sequentialIDs{}, s.clock.Now)
				read, err := fresh.Read(context.Background(), s.account)
				if err != nil || !read.SameAs(stored) {
					t.Fatalf("day %d: a fresh service differs: %v\n%+v\n%+v", day, err, read, stored)
				}
			}
		})
	}
}

// TestTheRuntimeRoleCannotEditOrDeleteARecord holds the privileges of 0003 from the runtime role's side: it appends, and it never
// updates or deletes a record (the snapshot and the revision are derived and may be rewritten).
func TestTheRuntimeRoleCannotEditOrDeleteARecord(t *testing.T) {
	s := newScenario(t).at(0)
	grant := s.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
	ctx := context.Background()
	for _, statement := range []string{
		"UPDATE entitlement.grant SET reason = 'x' WHERE grant_id = '" + grant.GrantID + "'::uuid",
		"DELETE FROM entitlement.grant WHERE grant_id = '" + grant.GrantID + "'::uuid",
		"UPDATE entitlement.revocation SET reason_code = 'x'",
		"INSERT INTO entitlement.account_status_fact (status_fact_id, account_id, recorded_at, status, auto_renew, purchase_pending, source_ref) VALUES (gen_random_uuid(), '" + s.account + "'::uuid, now(), 1, true, false, 'x')",
		"INSERT INTO entitlement.feature_release (feature_key, released_at) VALUES ('x.y', now())",
		"INSERT INTO entitlement.service_term_action (action_id, account_id, term_id, kind, effective_at, recorded_at, source_ref) VALUES (gen_random_uuid(), '" + s.account + "'::uuid, gen_random_uuid(), 2, now(), now(), 'x')",
		"INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '" + s.account + "'::uuid, now(), now() + interval '1 day', 'x', 'x')",
		"DELETE FROM entitlement.snapshot",
	} {
		err := s.db.runtime.InTx(ctx, "edit", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, statement)
			return err
		})
		var stored *store.Error
		if !errors.As(err, &stored) || stored.SQLState != "42501" {
			t.Errorf("the runtime role was not refused (%v): %s", err, statement)
		}
	}
	// What it may do: rewrite the derived snapshot.
	err := s.db.runtime.InTx(ctx, "rewrite", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE entitlement.snapshot SET entitlement_version = entitlement_version WHERE account_id = $1::uuid", s.account)
		return err
	})
	if err != nil {
		t.Errorf("the runtime role may not rewrite the snapshot: %v", err)
	}
}

// TestALostCommitIsTheTypedUnknownOutcomeAndAFailedStoreFailsClosed (D10, F6): a COMMIT without an answer is OutcomeUnknown (the
// same request may be sent again, and it finds the committed grant by its reference), a refused statement is a store error, and
// nothing is half written either way.
func TestALostCommitIsTheTypedUnknownOutcomeAndAFailedStoreFailsClosed(t *testing.T) {
	s := newScenario(t).at(0)
	s.db.exec("CREATE SCHEMA testfault",
		"CREATE FUNCTION testfault.lost() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'the commit was lost (test)' USING ERRCODE = '08P01'; END; $$",
		"CREATE CONSTRAINT TRIGGER test_lost AFTER INSERT ON entitlement.snapshot DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION testfault.lost()")
	request := capabilityRequest("cloud.sync", 0, nil, "s1")
	request.AccountID = s.account
	_, _, err := s.service.IssueGrant(context.Background(), request)
	wantRefusal(t, err, RefusedOutcomeUnknown)
	s.db.exec("DROP TRIGGER test_lost ON entitlement.snapshot")
	if rows := s.db.count("SELECT count(*) FROM entitlement.grant"); rows != 0 {
		t.Fatalf("the failed COMMIT left %d grants", rows)
	}
	if _, duplicate, err := s.service.IssueGrant(context.Background(), request); err != nil || duplicate {
		t.Fatalf("the same request again: %v %v", duplicate, err)
	}
	// A refused statement is an ordinary store error, not a typed refusal.
	s.db.exec("CREATE FUNCTION testfault.unavailable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'the store is unavailable (test)' USING ERRCODE = '57P01'; END; $$",
		"CREATE TRIGGER test_unavailable BEFORE INSERT ON entitlement.grant FOR EACH ROW EXECUTE FUNCTION testfault.unavailable()")
	second := capabilityRequest("cloud.web_continuity", 0, nil, "s2")
	second.AccountID = s.account
	_, _, err = s.service.IssueGrant(context.Background(), second)
	var stored *store.Error
	if _, typed := RefusalOf(err); typed || !errors.As(err, &stored) || !errors.Is(err, store.ErrUnavailable) {
		t.Fatalf("a failing store: %v", err)
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		t.Fatalf("the store error leaks the server's error")
	}
}

func TestAnUnknownGrantValueInTheStoreIsADefectNotAGuess(t *testing.T) {
	s := newScenario(t).at(0)
	grant := s.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
	// The constraints keep a malformed payload out; a payload that is well formed for another kind is still refused by the reader.
	s.db.exec("ALTER TABLE entitlement.grant DISABLE TRIGGER grant_append_only",
		"ALTER TABLE entitlement.grant DROP CONSTRAINT grant_value_shape",
		"UPDATE entitlement.grant SET value = '{\"limit\":1}'::jsonb WHERE grant_id = '"+grant.GrantID+"'::uuid")
	_, err := s.service.Refresh(context.Background(), s.account)
	if !errors.Is(err, ErrStoreDefect) {
		t.Fatalf("a payload of another kind: %v", err)
	}
}

// TestALoadNeverReadsAHistoryWithoutALimit: each kind of record is read one past the replay bound and no further, so a history that
// outgrew the bound costs a bounded read and is then refused by the resolver.
func TestALoadNeverReadsAHistoryWithoutALimit(t *testing.T) {
	s := newScenario(t).at(10)
	s.db.exec("INSERT INTO entitlement.account_status_fact (status_fact_id, account_id, recorded_at, status, auto_renew, purchase_pending, source_ref) " +
		"SELECT gen_random_uuid(), '" + s.account + "'::uuid, to_timestamp(i), 1, true, false, 'bulk-' || i FROM generate_series(1, 2100) AS i")
	var state State
	if err := s.db.runtime.InTx(context.Background(), "load", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) (err error) {
		state, err = Load(ctx, tx, s.account)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(state.Records.StatusFacts) != MaxRecords+1 {
		t.Fatalf("%d status facts were read of 2100", len(state.Records.StatusFacts))
	}
}
