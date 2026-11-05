// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/store"
)

// The prerequisites of the first gated operation in the entitlement store (AF-CTR-05 part E0; EVIDENCE: REAL PostgreSQL 18, REAL
// service and resolver; the two replicas of a rolling deploy are two services over one database, each with its own definitions and
// clock): store-1, the deploy-level fact of the current definitions version, and the clock floor at the newest record.

// replicaOf is a second service over the scenario's database with definitions of another version and its own clock.
func replicaOf(s *scenario, version string) (*Service, *testClock) {
	definitions := testDefinitions(false)
	definitions.Version = version
	clock := &testClock{}
	clock.Set(FromTime(s.clock.Now()))
	ids := &sequentialIDs{}
	ids.next.Store(1 << 32) // identifiers apart from the scenario's own
	return NewService(s.db.runtime, &fixedDefinitions{definitions: definitions}, ids, clock.Now), clock
}

func (s *scenario) snapshotVersion() (int64, int) {
	s.t.Helper()
	var version int64
	if err := s.db.migration.QueryRow(context.Background(), "SELECT entitlement_version FROM entitlement.snapshot WHERE account_id = $1::uuid", s.account).Scan(&version); err != nil {
		s.t.Fatal(err)
	}
	return version, s.db.count("SELECT count(*) FROM entitlement.definitions_activation WHERE account_id = $1::uuid", s.account)
}

// TestRollingDeployReadsNeverRaiseTheSnapshotVersion is E0-1 (store-1, the two-service wedge): two revisions with different
// definitions versions alternate 200 reads of one account. Without the deploy-level fact every read of the other revision recomputes
// and appends an activation, so the version climbs by one per read (the wedge of the 2000-record bound); with the fact the newer
// revision recorded at its start, the snapshot version and the activation count rise once and never again, the older revision reads
// the stored snapshot as it is, and every write of the older revision is refused without writing.
func TestRollingDeployReadsNeverRaiseTheSnapshotVersion(t *testing.T) {
	ctx := context.Background()
	t.Run("without the fact the reads wedge the account", func(t *testing.T) {
		old := newScenario(t).at(Day)
		old.issue(capabilityRequest("account.manage", 0, nil, "s1"))
		next, _ := replicaOf(old, "bundle-2")
		start, _ := old.snapshotVersion()
		for range 10 {
			if _, err := next.Read(ctx, old.account); err != nil {
				t.Fatal(err)
			}
			old.read()
		}
		if version, activations := old.snapshotVersion(); version < start+19 || activations < 21 {
			t.Fatalf("the control case did not wedge: version %d -> %d, %d activations", start, version, activations)
		}
	})
	t.Run("with the fact two revisions never raise the version", func(t *testing.T) {
		old := newScenario(t).at(Day)
		if recording, err := old.service.RecordDefinitions(ctx, at(Day).Time()); err != nil || recording != Recorded {
			t.Fatalf("the older revision's start: %v %v", recording, err)
		}
		old.issue(capabilityRequest("account.manage", 0, nil, "s1"))
		until := int64(30 * Day)
		old.issue(capabilityRequest("account.manage", 0, &until, "s2"))
		next, nextClock := replicaOf(old, "bundle-2")
		// The newer revision starts and records its version once; a second start of it writes nothing.
		if recording, err := next.RecordDefinitions(ctx, at(Day+60).Time()); err != nil || recording != Recorded {
			t.Fatalf("the newer revision's start: %v %v", recording, err)
		}
		if recording, err := next.RecordDefinitions(ctx, at(Day+120).Time()); err != nil || recording != AlreadyRecorded {
			t.Fatalf("a second start of the same version: %v %v", recording, err)
		}
		first, err := next.Read(ctx, old.account)
		if err != nil || first.DefinitionsVersion != "bundle-2" {
			t.Fatalf("the newer revision's first read: %+v %v", first, err)
		}
		version, activations := old.snapshotVersion()
		// N-5: the older revision answers its reads from the fast path, without loading the account's records.
		loads := 0
		old.service.onLoad = func() { loads++ }
		for index := range 200 {
			var read StoredSnapshot
			if index%2 == 0 {
				read, err = old.service.Read(ctx, old.account)
			} else {
				nextClock.Set(FromTime(old.clock.Now()))
				read, err = next.Read(ctx, old.account)
			}
			if err != nil || read.Version != version || read.DefinitionsVersion != "bundle-2" {
				t.Fatalf("read %d: %+v %v", index, read, err)
			}
			old.clock.Set(FromTime(old.clock.Now()) + 1_000_000)
		}
		if after, count := old.snapshotVersion(); after != version || count != activations {
			t.Fatalf("200 alternating reads moved the snapshot version %d -> %d and the activations %d -> %d", version, after, activations, count)
		}
		if loads != 0 {
			t.Fatalf("the superseded revision loaded the account's records %d times for 100 reads of a valid snapshot", loads)
		}
		old.service.onLoad = nil
		// A refresh of the older revision (a validity sweeper's call) returns the valid stored snapshot as it is: it never recomputes.
		if refreshed, err := old.service.Refresh(ctx, old.account); err != nil || refreshed.Version != version || refreshed.DefinitionsVersion != "bundle-2" {
			t.Fatalf("a refresh of the older revision: %+v %v", refreshed, err)
		}
		// The older revision writes nothing: an issue and a revocation are refused before the store.
		grants := old.db.count("SELECT count(*) FROM entitlement.grant")
		if _, _, err = old.service.IssueGrant(ctx, func() IssueGrantRequest {
			request := capabilityRequest("account.manage", 0, nil, "s3")
			request.AccountID = old.account
			return request
		}()); !errors.Is(err, ErrDefinitionsSuperseded) {
			t.Fatalf("an issue of the older revision: %v", err)
		}
		if old.db.count("SELECT count(*) FROM entitlement.grant") != grants {
			t.Fatal("the older revision wrote a grant")
		}
		var grantID string
		if err = old.db.migration.QueryRow(ctx, "SELECT grant_id::text FROM entitlement.grant WHERE source_ref = 's1'").Scan(&grantID); err != nil {
			t.Fatal(err)
		}
		if _, _, err = old.service.RevokeGrant(ctx, RevokeGrantRequest{AccountID: old.account, GrantID: grantID, ReasonCode: "refund", IssuedByActor: "operator",
			ExpectedSnapshotVersion: version}); !errors.Is(err, ErrDefinitionsSuperseded) {
			t.Fatalf("a revocation of the older revision: %v", err)
		}
		// A read that needs a recompute (the stored snapshot's validity passed) is the superseded error, never a recompute.
		old.clock.Set(at(31 * Day))
		if _, err = old.service.Read(ctx, old.account); !errors.Is(err, ErrDefinitionsSuperseded) {
			t.Fatalf("a read past the validity on the older revision: %v", err)
		}
		if after, count := old.snapshotVersion(); after != version || count != activations {
			t.Fatalf("the older revision recomputed: %d -> %d, %d -> %d", version, after, activations, count)
		}
		// The newer revision recomputes it, once.
		nextClock.Set(at(31 * Day))
		if read, err := next.Read(ctx, old.account); err != nil || read.Version != version+1 {
			t.Fatalf("the newer revision past the validity: %+v %v", read, err)
		}
		if _, count := old.snapshotVersion(); count != activations {
			t.Fatalf("a recompute of the current definitions appended an activation: %d -> %d", activations, count)
		}
	})
}

// TestAComputationNeverGoesBehindTheNewestRecord is E0-2 (the clock floor): a snapshot dropped while the replica's clock is behind
// the newest record (a term another replica admitted with its clock ahead, then an activation) is recomputed at that record's instant,
// not at the replica's clock, and a write after it is admitted strictly after it.
func TestAComputationNeverGoesBehindTheNewestRecord(t *testing.T) {
	ctx := context.Background()
	s := newScenario(t).at(10 * Day)
	s.issue(capabilityRequest("account.manage", 0, nil, "s1"))
	drop := func() {
		t.Helper()
		s.db.exec("DELETE FROM entitlement.snapshot WHERE account_id = '" + s.account + "'")
	}
	computedAt := func() Micros {
		t.Helper()
		snapshot, err := LoadSnapshotFor(ctx, s)
		if err != nil || snapshot == nil {
			t.Fatalf("%+v %v", snapshot, err)
		}
		return snapshot.ComputedAt
	}
	// A term created at day 20 by a replica whose clock ran ahead; this replica's clock reads day 15.
	if _, err := s.db.migration.Exec(ctx, `INSERT INTO entitlement.service_term (term_id, account_id, kind, subscription_ref, period_ref, starts_at, ends_at, authorized_at, created_at)
VALUES ($1::uuid, $2::uuid, 2, NULL, 'period-floor', $3, $4, $3, $5)`, termUUID("floor"), s.account, at(0).Time(), at(60*Day).Time(), at(20*Day).Time()); err != nil {
		t.Fatal(err)
	}
	drop()
	s.at(15 * Day)
	if read := s.read(); read.ComputedAt != at(20*Day) || computedAt() != at(20*Day) {
		t.Fatalf("a dropped snapshot was recomputed at %d, the newest record is at %d", read.ComputedAt, at(20*Day))
	}
	// An activation at day 25 (of the same definitions) is the newest instant now.
	s.db.exec("INSERT INTO entitlement.definitions_activation (account_id, activated_at, definitions_version) VALUES ('" + s.account + "', '" +
		at(25*Day).Time().Format("2006-01-02T15:04:05Z07:00") + "', 'bundle-1')")
	drop()
	if read := s.read(); read.ComputedAt != at(25*Day) {
		t.Fatalf("a dropped snapshot was recomputed at %d, the newest activation is at %d", read.ComputedAt, at(25*Day))
	}
	// A write admits its record strictly after the floor, whatever the clock says.
	drop()
	grant := s.issue(capabilityRequest("account.manage", 0, nil, "s2"))
	if grant.CreatedAt <= at(25*Day) {
		t.Fatalf("a grant admitted at %d, behind the newest instant %d", grant.CreatedAt, at(25*Day))
	}
}

// LoadSnapshotFor reads the stored snapshot of a scenario's account with the runtime role.
func LoadSnapshotFor(ctx context.Context, s *scenario) (*StoredSnapshot, error) {
	var snapshot *StoredSnapshot
	err := s.db.runtime.InTx(ctx, "read the snapshot (test)", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		snapshot, err = LoadSnapshot(ctx, tx, s.account)
		return err
	})
	return snapshot, err
}

// TestALateRetryOfAnOlderStartNeverDisplacesTheNewerFact is B-1 of the review of Cloud #143 (store-1): revision A starts while the
// store does not answer, so its first record fails; revision B starts later and records its version; A's retry, stamped with A's own
// start instant, then finds the newer start's fact and writes nothing (Superseded), and B keeps computing. A restart of A during the
// rollout is a newer start and records A again (the hazard the design keeps), and a restart of B recovers.
func TestALateRetryOfAnOlderStartNeverDisplacesTheNewerFact(t *testing.T) {
	ctx := context.Background()
	s := newScenario(t).at(Day)
	s.issue(capabilityRequest("account.manage", 0, nil, "s1"))
	a, startA := s.service, at(Day).Time()
	b, _ := replicaOf(s, "bundle-2")
	fact := func() (string, Micros) {
		t.Helper()
		var version string
		var recorded time.Time
		if err := s.db.migration.QueryRow(ctx, "SELECT definitions_version, recorded_at FROM entitlement.definitions_current").Scan(&version, &recorded); err != nil {
			t.Fatal(err)
		}
		return version, FromTime(recorded)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := a.RecordDefinitions(cancelled, startA); err == nil {
		t.Fatal("the first record of A succeeded on a store that did not answer")
	}
	if recording, err := b.RecordDefinitions(ctx, at(Day+60).Time()); err != nil || recording != Recorded {
		t.Fatalf("B's start: %v %v", recording, err)
	}
	// A's late retry: the same start instant as its first attempt.
	if recording, err := a.RecordDefinitions(ctx, startA); err != nil || recording != Superseded {
		t.Fatalf("A's late retry: %v %v", recording, err)
	}
	if version, recorded := fact(); version != "bundle-2" || recorded != at(Day+60) {
		t.Fatalf("A's late retry displaced B's fact: %s at %d", version, recorded)
	}
	// B still computes and writes; A neither recomputes nor writes.
	if read, err := b.Read(ctx, s.account); err != nil || read.DefinitionsVersion != "bundle-2" {
		t.Fatalf("B after A's retry: %+v %v", read, err)
	}
	request := capabilityRequest("account.manage", 0, nil, "s2")
	request.AccountID = s.account
	if _, _, err := b.IssueGrant(ctx, request); err != nil {
		t.Fatalf("B's write: %v", err)
	}
	request.SourceRef = ref("s3")
	if _, _, err := a.IssueGrant(ctx, request); !errors.Is(err, ErrDefinitionsSuperseded) {
		t.Fatalf("A's write: %v", err)
	}
	// The hazard the design keeps: A restarting during the rollout is a newer start and records A; restarting B recovers.
	if recording, err := a.RecordDefinitions(ctx, at(Day+120).Time()); err != nil || recording != Recorded {
		t.Fatalf("A's restart: %v %v", recording, err)
	}
	if recording, err := b.RecordDefinitions(ctx, at(Day+180).Time()); err != nil || recording != Recorded {
		t.Fatalf("B's restart: %v %v", recording, err)
	}
	if version, _ := fact(); version != "bundle-2" {
		t.Fatalf("after B's restart: %s", version)
	}
}

// TestACommitRereadsTheFactUnderALock is N-1 of the review of Cloud #143 (store-1): a replica that loaded the account before a newer
// revision recorded its version cannot write after the switch; the commit reads the fact again under a share lock and refuses with
// ErrDefinitionsSuperseded, having written nothing.
func TestACommitRereadsTheFactUnderALock(t *testing.T) {
	ctx := context.Background()
	s := newScenario(t).at(Day)
	s.issue(capabilityRequest("account.manage", 0, nil, "s1"))
	newer, _ := replicaOf(s, "bundle-2")
	grants, activations := s.db.count("SELECT count(*) FROM entitlement.grant"), s.db.count("SELECT count(*) FROM entitlement.definitions_activation")
	s.service.beforeCommit = func() {
		if recording, err := newer.RecordDefinitions(ctx, at(Day).Time()); err != nil || recording != Recorded {
			t.Errorf("the newer start between the load and the commit: %v %v", recording, err)
		}
	}
	request := capabilityRequest("account.manage", 0, nil, "s2")
	request.AccountID = s.account
	if _, _, err := s.service.IssueGrant(ctx, request); !errors.Is(err, ErrDefinitionsSuperseded) {
		t.Fatalf("a write that loaded before the switch: %v", err)
	}
	if s.db.count("SELECT count(*) FROM entitlement.grant") != grants || s.db.count("SELECT count(*) FROM entitlement.definitions_activation") != activations {
		t.Fatal("a superseded replica wrote after the switch")
	}
}

// TestTheFastPathChecksValidityAtTheFloor is N-2 of the review of Cloud #143 (the clock floor): a stored snapshot whose validity ended
// before the newest record of the account (a term another replica admitted with its clock ahead) is not served by the fast path while
// this replica's clock is behind; it is recomputed at the floor.
func TestTheFastPathChecksValidityAtTheFloor(t *testing.T) {
	ctx := context.Background()
	s := newScenario(t).at(10 * Day)
	until := int64(20 * Day)
	s.issue(capabilityRequest("account.manage", 0, &until, "s1"))
	first := s.read()
	if first.ValidUntil == nil || *first.ValidUntil > at(20*Day) {
		t.Fatalf("the snapshot's validity: %+v", first.ValidUntil)
	}
	if _, err := s.db.migration.Exec(ctx, `INSERT INTO entitlement.service_term (term_id, account_id, kind, subscription_ref, period_ref, starts_at, ends_at, authorized_at, created_at)
VALUES ($1::uuid, $2::uuid, 2, NULL, 'period-fast', $3, $4, $3, $5)`, termUUID("fast"), s.account, at(0).Time(), at(60*Day).Time(), at(25*Day).Time()); err != nil {
		t.Fatal(err)
	}
	s.at(15 * Day)
	if read := s.read(); read.ComputedAt != at(25*Day) || read.Version == first.Version {
		t.Fatalf("the fast path served a snapshot that expired before the newest record: computed at %d (version %d -> %d)", read.ComputedAt, first.Version, read.Version)
	}
}
