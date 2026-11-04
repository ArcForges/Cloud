// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// EVIDENCE: REAL PostgreSQL, real row locks, goroutines released together, every transaction without retries (store.TxOptions
// Attempts 1), so a deadlock (40P01) is an error of the round and fails the test instead of being retried away (E1-14, cloud-1).

const rounds = 50

// deadlocked reports a deadlock in a transaction's error.
func deadlocked(err error) bool {
	var failure *store.Error
	var pgError *pgconn.PgError
	return errors.As(err, &failure) && failure.SQLState == "40P01" || errors.As(err, &pgError) && pgError.Code == "40P01"
}

// waitBlocked waits until a backend of the test's own database waits for a lock, and fails the test after five seconds. pg_locks and
// the pid and datname of pg_stat_activity are readable by every role; pg_locks covers the whole cluster, so a lock wait of another
// package's test (go test runs packages in parallel against one server) must not count.
func (r *rig) waitBlocked(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r.count(`SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
WHERE NOT l.granted AND a.datname = current_database()`) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the enrollment never waited for the held lock")
}

// free reports whether a row lock can be taken at once (FOR UPDATE NOWAIT in a transaction that is rolled back).
func (r *rig) free(t *testing.T, query string, arguments ...any) bool {
	t.Helper()
	ctx := context.Background()
	tx, err := r.db.Runtime.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, query+" FOR UPDATE NOWAIT", arguments...)
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && pgError.Code == "55P03" {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	return true
}

// hold takes a row lock in a transaction of its own and returns its release (a rollback, or a commit when commit is true).
func (r *rig) hold(t *testing.T, query string, arguments ...any) func(commit bool) {
	t.Helper()
	ctx := context.Background()
	tx, err := r.db.Runtime.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, query, arguments...); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	return func(commit bool) {
		if commit {
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			return
		}
		_ = tx.Rollback(ctx)
	}
}

// TestEnrollTakesItsLocksInTheGlobalOrder pins the order deterministically (N-1): a third transaction holds one row of the order;
// Enroll (a re-enrollment, the path that locks every row) must then wait for it while it already holds every row before it and
// none after it. The approving session is locked in the session slot (B-1): a plain read would not wait.
func TestEnrollTakesItsLocksInTheGlobalOrder(t *testing.T) {
	r := newRig(t)
	nodeID, key := platform.NewID(), nodeKey(t)
	enrolled := r.mustEnroll(r.request(nodeID, key))
	const (
		user         = "SELECT 1 FROM identity.user WHERE user_id = $1"
		deviceRow    = "SELECT 1 FROM device.device WHERE device_id = $1"
		installation = "SELECT 1 FROM device.installation WHERE installation_id = $1"
		sessionRow   = "SELECT 1 FROM identity.session WHERE session_id = $1"
		nodeRow      = "SELECT 1 FROM fleet.node WHERE enrollment_id = $1"
	)
	type probe struct {
		query string
		id    *platform.ID
	}
	// The old session is the live session of the node when a step starts (each step's enrollment supersedes it).
	oldSession := enrolled.Session.SessionID
	userP, deviceP, installationP, approverP, oldSessionP, nodeP := probe{user, &r.user}, probe{deviceRow, &enrolled.DeviceID},
		probe{installation, &enrolled.InstallationID}, probe{sessionRow, &r.approver.ID}, probe{sessionRow, &oldSession}, probe{nodeRow, &enrolled.EnrollmentID}
	for _, step := range []struct {
		name         string
		held         probe
		holds, frees []probe
	}{
		{"the device", deviceP, []probe{userP}, []probe{installationP, oldSessionP, nodeP}},
		{"the installation", installationP, []probe{userP, deviceP}, []probe{oldSessionP, nodeP}},
		{"the approving session", approverP, []probe{userP, deviceP, installationP}, []probe{oldSessionP, nodeP}},
		{"the node", nodeP, []probe{userP, deviceP, installationP, approverP, oldSessionP}, nil},
	} {
		t.Run(step.name, func(t *testing.T) {
			release := r.hold(t, step.held.query+" FOR UPDATE", *step.held.id)
			done := make(chan error, 1)
			go func() {
				fresh, err := r.enroll(r.request(nodeID, key))
				if err == nil {
					enrolled.Session = fresh.Session
				}
				done <- err
			}()
			r.waitBlocked(t)
			for _, held := range step.holds {
				if r.free(t, held.query, *held.id) {
					t.Errorf("Enroll does not yet hold %q while it waits for %s", held.query, step.name)
				}
			}
			for _, later := range step.frees {
				if !r.free(t, later.query, *later.id) {
					t.Errorf("Enroll already holds %q while it waits for %s", later.query, step.name)
				}
			}
			release(false)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			// The next step's old session is the one this enrollment issued.
			oldSession = enrolled.Session.SessionID
		})
	}
}

// TestOwnDeviceRevocationOfTheApproverDuringEnrollmentLapses (B-1): the approver revokes its own browser device (no step-up
// evidence, so no account lock) while an enrollment it approved runs. An enrollment never commits after that revocation: when the
// revocation holds the approving session first, the enrollment waits for it and lapses; raced, every round ends either way, never in
// a deadlock.
func TestOwnDeviceRevocationOfTheApproverDuringEnrollmentLapses(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	revoke := func(approver platform.ID, deviceID platform.ID) (func(commit bool), error) {
		tx, err := r.db.Runtime.Pool().Begin(ctx)
		if err != nil {
			return nil, err
		}
		if _, err = device.Revoke(ctx, tx, approver, deviceID, device.RevokedByOwner, []device.Participant{NodeParticipant{}}, time.Now()); err != nil {
			_ = tx.Rollback(ctx)
			return nil, err
		}
		return func(commit bool) {
			if commit {
				if err := tx.Commit(ctx); err != nil {
					t.Error(err)
				}
				return
			}
			_ = tx.Rollback(ctx)
		}, nil
	}
	// Deterministic: the revocation holds the approving session; the enrollment waits, then lapses with nothing written.
	release, err := revoke(r.user, r.approver.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	// A failure below must not leave the revocation's locks held (the database could not be dropped).
	t.Cleanup(func() { release(false) })
	done := make(chan error, 1)
	go func() {
		_, err := r.enroll(r.request(platform.NewID(), nodeKey(t)))
		done <- err
	}()
	r.waitBlocked(t)
	release(true)
	if err := <-done; key(err) != "lapsed" || r.count("SELECT count(*) FROM fleet.node") != 0 {
		t.Fatalf("an enrollment after its approver's device revocation: %v", key(err))
	}
	// Raced.
	for round := range rounds {
		user, approver := r.account(1)
		request := r.request(platform.NewID(), nodeKey(t))
		request.UserID, request.Approver.SessionID = user, approver.ID
		start := make(chan struct{})
		var wait sync.WaitGroup
		var enrollErr, revokeErr error
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, enrollErr = r.enroll(request)
		}()
		go func() {
			defer wait.Done()
			<-start
			revokeErr = r.db.Runtime.InTx(ctx, "revoke the approver's device", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
				_, err := device.Revoke(ctx, tx, user, approver.DeviceID, device.RevokedByOwner, []device.Participant{NodeParticipant{}}, time.Now())
				return err
			})
		}()
		close(start)
		wait.Wait()
		if deadlocked(enrollErr) || deadlocked(revokeErr) || revokeErr != nil || enrollErr != nil && key(enrollErr) != "lapsed" {
			t.Fatalf("round %d: enroll %v, revoke %v", round, key(enrollErr), revokeErr)
		}
	}
}

// TestRevokeDuringEnrollmentLeavesNoLiveSession races a re-enrollment with DeviceService.Revoke of the node's device through the
// evidence path (the account lock first, as ConsumeEvidence takes it): never a deadlock, and afterwards no live session on a revoked
// device or installation; the enrollment either committed first (the cascade then revoked its session) or met the revoked device and
// its retired key (credential_revoked).
func TestRevokeDuringEnrollmentLeavesNoLiveSession(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	for round := range rounds {
		nodeID, key := platform.NewID(), nodeKey(t)
		enrolled := r.mustEnroll(r.request(nodeID, key))
		start := make(chan struct{})
		var wait sync.WaitGroup
		var enrollErr, revokeErr error
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, enrollErr = r.enroll(r.request(nodeID, key))
		}()
		go func() {
			defer wait.Done()
			<-start
			revokeErr = r.db.Runtime.InTx(ctx, "revoke the node's device", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", r.user); err != nil {
					return err
				}
				_, err := device.Revoke(ctx, tx, r.user, enrolled.DeviceID, device.RevokedByOwner, []device.Participant{NodeParticipant{}}, time.Now())
				return err
			})
		}()
		close(start)
		wait.Wait()
		if deadlocked(enrollErr) || deadlocked(revokeErr) || revokeErr != nil ||
			enrollErr != nil && keyOf(enrollErr) != "AUTHENTICATION/credential_revoked" {
			t.Fatalf("round %d: enroll %v, revoke %v", round, keyOf(enrollErr), revokeErr)
		}
		if live := r.count(`SELECT count(*) FROM identity.session s JOIN device.device d ON d.device_id = s.device_id
JOIN device.installation i ON i.installation_id = s.installation_id
WHERE s.revoked_at IS NULL AND (d.revoked_at IS NOT NULL OR i.revoked_at IS NOT NULL)`); live != 0 {
			t.Fatalf("round %d: %d live sessions on a revoked device", round, live)
		}
	}
}

func keyOf(err error) string { return key(err) }

// TestConcurrentEnrollmentsNeverPassTheCap (cloud-15 item 7): three concurrent enrollments of different node IDs against a cap of two
// admit exactly two, round after round: the cap is counted under the account lock.
func TestConcurrentEnrollmentsNeverPassTheCap(t *testing.T) {
	r := newRig(t)
	r.policy.MaxNodesPerAccount = 2
	for round := range rounds {
		user, approver := r.account(1)
		start := make(chan struct{})
		results := make(chan error, 3)
		for range 3 {
			request := r.request(platform.NewID(), nodeKey(t))
			request.UserID, request.Approver.SessionID = user, approver.ID
			go func() {
				<-start
				_, err := r.enroll(request)
				results <- err
			}()
		}
		close(start)
		admitted, capped := 0, 0
		for range 3 {
			switch err := <-results; key(err) {
			case "":
				admitted++
			case "RESOURCE/quota_exceeded":
				capped++
			default:
				t.Fatalf("round %d: %v", round, key(err))
			}
		}
		if admitted != 2 || capped != 1 || r.count("SELECT count(*) FROM fleet.node WHERE user_id = $1 AND revoked_at IS NULL", user) != 2 {
			t.Fatalf("round %d: %d admitted, %d capped", round, admitted, capped)
		}
	}
}

// TestConcurrentEnrollmentsOfOneNodeIDOrOneKeyEnrollOnce: two accounts race for one node ID, and two accounts race for one key under
// different node IDs. Never two live rows of a node ID, never two installations of a key; the loser answers the rule that applies
// (already_exists of the node or of the key) or, when its insert met the winner's uncommitted row, store contention, whose identical
// retry then answers that rule.
func TestConcurrentEnrollmentsOfOneNodeIDOrOneKeyEnrollOnce(t *testing.T) {
	r := newRig(t)
	for round := range rounds {
		first, firstApprover := r.account(1)
		second, secondApprover := r.account(1)
		nodeID, sharedKey := platform.NewID(), nodeKey(t)
		for _, sameNode := range []bool{true, false} {
			a := r.request(nodeID, nodeKey(t))
			b := r.request(nodeID, nodeKey(t))
			if !sameNode {
				a, b = r.request(platform.NewID(), sharedKey), r.request(platform.NewID(), sharedKey)
			}
			a.UserID, a.Approver.SessionID = first, firstApprover.ID
			b.UserID, b.Approver.SessionID = second, secondApprover.ID
			start := make(chan struct{})
			results := make(chan error, 2)
			for _, request := range []EnrollRequest{a, b} {
				go func() {
					<-start
					_, err := r.enroll(request)
					results <- err
				}()
			}
			close(start)
			wins, retry := 0, false
			for range 2 {
				switch err := <-results; key(err) {
				case "":
					wins++
				case "CONFLICT/already_exists node/already_exists", "CONFLICT/already_exists node_key/already_registered":
				case "contention":
					retry = true
				default:
					t.Fatalf("round %d (same node %v): %v", round, sameNode, key(err))
				}
			}
			if wins != 1 {
				t.Fatalf("round %d (same node %v): %d enrollments", round, sameNode, wins)
			}
			if retry {
				if _, err := r.enroll(b); err == nil {
					if _, err = r.enroll(a); err == nil {
						t.Fatalf("round %d: both retries enrolled", round)
					}
				}
			}
		}
		if r.count("SELECT count(*) FROM fleet.node WHERE node_id = $1 AND revoked_at IS NULL", nodeID) != 1 ||
			r.count("SELECT count(*) FROM device.installation WHERE public_key = $1", sharedKey) != 1 {
			t.Fatalf("round %d: duplicates", round)
		}
	}
}
