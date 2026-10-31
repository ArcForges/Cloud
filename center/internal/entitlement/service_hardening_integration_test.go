// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"context"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The service's guards, the equality a rebuild must satisfy and the determinism of a second replica, over real PostgreSQL (fix round 1:
// store-7, resolver-3, -4, -6 and -8; EVIDENCE: REAL logic, REAL PostgreSQL 18).

// TestAnAccountThatIsNoUUIDOrDoesNotExistIsATypedRefusal: a token that passes the opaque-identifier rule but is no uuid, and a uuid
// without an account, are refused as invalid requests by every entry point, with nothing written.
func TestAnAccountThatIsNoUUIDOrDoesNotExistIsATypedRefusal(t *testing.T) {
	s := newScenario(t).at(0)
	ctx := context.Background()
	unknown := platform.NewID().String()
	for _, account := range []string{"", "a b", "not-a-uuid", "account-one", "0123456789", s.account + "x", unknown} {
		_, err := s.service.Read(ctx, account)
		wantRefusal(t, err, RefusedInvalidRequest)
		_, err = s.service.Refresh(ctx, account)
		wantRefusal(t, err, RefusedInvalidRequest)
		_, err = s.service.VerifyRebuild(ctx, account)
		if account != unknown {
			wantRefusal(t, err, RefusedInvalidRequest)
		}
		request := capabilityRequest("cloud.sync", 0, nil, "order-1")
		request.AccountID = account
		_, _, err = s.service.IssueGrant(ctx, request)
		wantRefusal(t, err, RefusedInvalidRequest)
		_, _, err = s.service.RevokeGrant(ctx, RevokeGrantRequest{AccountID: account, GrantID: platform.NewID().String(), ReasonCode: "refund", IssuedByActor: "operator"})
		if account != unknown {
			wantRefusal(t, err, RefusedInvalidRequest)
		}
	}
	if refusal := wantRefusal(t, func() error { _, err := s.service.Read(ctx, unknown); return err }(), RefusedInvalidRequest); refusal.Detail != "The account does not exist." {
		t.Errorf("an unknown account: %q", refusal.Detail)
	}
	for _, table := range []string{"revision", "snapshot", "grant", "definitions_activation"} {
		if rows := s.db.count("SELECT count(*) FROM entitlement."+table+" WHERE account_id = $1::uuid", unknown); rows != 0 {
			t.Errorf("the unknown account has %d rows in %s", rows, table)
		}
	}
	// The account of the scenario is served as ever.
	s.issue(capabilityRequest("cloud.sync", 0, nil, "order-2"))
}

// TestAReasonOnAnOrdinarySourceIsATypedRefusalAndAnAdministrativeSourceNeedsOne (resolver-8): the admission admits a reason on an
// ordinary source (as the C# does), the schema refuses it; the service answers the refusal, not a constraint error.
func TestAReasonOnAnOrdinarySourceIsATypedRefusalAndAnAdministrativeSourceNeedsOne(t *testing.T) {
	s := newScenario(t).at(0)
	request := capabilityRequest("cloud.sync", 0, nil, "order-1")
	request.AccountID, request.Reason = s.account, ref("because")
	_, _, err := s.service.IssueGrant(context.Background(), request)
	wantRefusal(t, err, RefusedInvalidRequest)
	if rows := s.db.count("SELECT count(*) FROM entitlement.grant WHERE account_id = $1::uuid", s.account); rows != 0 {
		t.Fatalf("a refused grant left %d rows", rows)
	}
	administrative := request
	administrative.Source = SourceAdminGrant
	if _, _, err = s.service.IssueGrant(context.Background(), administrative); err != nil {
		t.Fatal(err)
	}
}

// TestADifferentSnapshotColumnIsAMismatch (resolver-4): the rebuild compares every column of the stored snapshot, not the content alone.
// The computation instant is the one column it cannot show: the rebuild resolves at the stored instant, so a stored instant that was
// changed is simply the instant resolved at; StoredSnapshot.SameAs and Snapshot.SameAs compare it, which TestSnapshotEqualityIsFull
// pins.
func TestADifferentSnapshotColumnIsAMismatch(t *testing.T) {
	for name, update := range map[string]string{
		"the version":             "entitlement_version = entitlement_version + 1",
		"the validity":            "valid_until = valid_until + interval '1 second'",
		"no validity":             "valid_until = NULL",
		"the definitions version": "definitions_version = 'bundle-9'",
	} {
		t.Run(name, func(t *testing.T) {
			s := newScenario(t).at(0)
			s.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
			s.addTerm("t1", 0, 30*Day)
			s.at(Day).refresh()
			s.assertRebuildEqual()
			s.db.exec("UPDATE entitlement.snapshot SET " + update + " WHERE account_id = '" + s.account + "'::uuid")
			report, err := s.service.VerifyRebuild(context.Background(), s.account)
			if err != nil || report.Status == RebuildEqual || report.Status == RebuildNoSnapshot {
				t.Fatalf("a stored snapshot with %s changed: %+v %v", name, report, err)
			}
			if name != "the definitions version" && report.Status != RebuildMismatch {
				t.Fatalf("status %d, want a mismatch", report.Status)
			}
		})
	}
}

// TestARefreshThatOnlyChangesTheValidityIsStored (resolver-4): a record that sets a new boundary without changing what is effective
// still changes when the snapshot must be looked at again, and the refresh stores it.
func TestARefreshThatOnlyChangesTheValidityIsStored(t *testing.T) {
	s := newScenario(t).at(0)
	s.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
	s.addTerm("t1", 0, 30*Day)
	before := s.at(Day).refresh()
	if before.ValidUntil == nil || *before.ValidUntil != at(30*Day) {
		t.Fatalf("validUntil: %v", before.ValidUntil)
	}
	// A feature release in the near future changes no entry now, but it is a boundary.
	s.db.exec("INSERT INTO entitlement.feature_release (feature_key, released_at) VALUES ('feature.other', '" + at(10*Day).Time().Format("2006-01-02 15:04:05") + "+00')")
	after := s.at(Day).refresh()
	if after.ValidUntil == nil || *after.ValidUntil != at(10*Day) || after.Version != before.Version {
		t.Fatalf("the refresh did not store the new validity: %+v then %+v", before, after)
	}
	if again := s.read(); again.ValidUntil == nil || *again.ValidUntil != at(10*Day) {
		t.Fatalf("a read after the refresh: %+v", again)
	}
	s.assertRebuildEqual()
}

// TestADefinitionsChangeAtTheInstantOfTheStoredComputationIsRecordedAfterIt (resolver-4): the activation of new definitions is a write
// and takes the instant strictly after the stored computation, even where the clock stands still.
func TestADefinitionsChangeAtTheInstantOfTheStoredComputationIsRecordedAfterIt(t *testing.T) {
	s := newScenario(t).at(Day)
	s.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
	stored := s.refresh()
	changed := testDefinitions(false)
	changed.Version = "bundle-2"
	s.definitions.Set(changed)
	after := s.refresh()
	if after.DefinitionsVersion != "bundle-2" || after.ComputedAt != stored.ComputedAt+1 || after.Version <= stored.Version {
		t.Fatalf("the activation at a standing clock: %+v then %+v", stored, after)
	}
	if rows := s.db.count("SELECT count(*) FROM entitlement.definitions_activation WHERE account_id = $1::uuid", s.account); rows != 2 {
		t.Fatalf("%d activations", rows)
	}
	s.assertRebuildEqual()
}

// TestASecondReplicaReachesTheSameSnapshotByItsOwnResolution (resolver-3): the replica does not read the first one's stored row; it
// derives the snapshot from the records alone, at the stored instant, and the derivation must be the stored one in full. A resolver
// that depends on anything but its input fails here.
func TestASecondReplicaReachesTheSameSnapshotByItsOwnResolution(t *testing.T) {
	one := newScenario(t).at(0)
	one.issue(capabilityRequest("cloud.sync", 0, nil, "s1"))
	one.issue(capabilityRequest("cloud.web_continuity", 0, nil, "s2"))
	one.addTerm("t1", 0, 30*Day)
	first := one.at(Day).refresh()
	replicaClock := &testClock{}
	replicaClock.At(Day)
	replica := NewService(one.db.runtime, one.definitions, &sequentialIDs{}, replicaClock.Now)
	report, err := replica.VerifyRebuild(context.Background(), one.account)
	if err != nil || report.Status != RebuildEqual || report.Rebuilt == nil || !report.Rebuilt.SameAs(first) {
		t.Fatalf("the replica's own resolution differs: %+v %v\nstored  %+v", report, err, first)
	}
	// And a second resolution in this process is the same again (no state, no call counter, no clock).
	state, err := replica.load(context.Background(), one.account)
	if err != nil {
		t.Fatal(err)
	}
	left, err := Resolve(state.Records, one.definitions.Current(), first.ComputedAt)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Resolve(state.Records, one.definitions.Current(), first.ComputedAt)
	if err != nil || !left.SameAs(right) || !left.Stored().SameAs(first) {
		t.Fatalf("two resolutions of one input differ: %v", err)
	}
}
