// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// EVIDENCE: REAL PostgreSQL, the real fleet service (no transport), enrollment SEEDED through Enroll.

// service is the fleet service of the rig; its refresh rotation runs without retries, so a deadlock is a race test's error.
func (r *rig) service() *Service {
	return New(Options{DB: r.db.Runtime, Policy: r.policy, RefreshAttempts: 1})
}

var neighbour = Request{ClientIP: netip.MustParseAddr("192.0.2.77")}

// TestAThousandJunkRefreshesThenAValidOne (protocol-8, E1-15): a thousand refresh tokens that name nothing, from one /24, fill that
// prefix's failure bucket (120 per 10 minutes by default), and a valid node refresh from the same /24 still rotates.
func TestAThousandJunkRefreshesThenAValidOne(t *testing.T) {
	r := newRig(t)
	service := r.service()
	enrolled := r.mustEnroll(r.request(platform.NewID(), nodeKey(t)))
	limited := 0
	for range 1000 {
		_, err := service.Refresh(context.Background(), neighbour, session.RefreshPrefix+session.NewSecret().Text())
		switch key(err) {
		case "AUTHENTICATION/unauthenticated":
		case "RESOURCE/rate_limited":
			limited++
		default:
			t.Fatalf("junk: %v", key(err))
		}
	}
	if limited != 1000-r.policy.NodeRefreshPerPrefix.Limit {
		t.Fatalf("%d junk refreshes refused", limited)
	}
	if refreshed, err := service.Refresh(context.Background(), Request{ClientIP: netip.MustParseAddr("192.0.2.200")}, enrolled.Session.RefreshToken); err != nil ||
		refreshed.Session.AccessToken == "" {
		t.Fatalf("a valid refresh from the same /24: %v", key(err))
	}
}

// TestEnrollAndRefreshOfTheSupersededSessionNeverDeadlock (cloud-1 item 7): a re-enrollment (which supersedes the node's session and
// then locks the node row) races a refresh of that session (which locks the session and then updates the node row): never a deadlock;
// either the refresh rotated first and the enrollment superseded the rotated session, or the enrollment superseded it first and the
// refresh is credential_revoked.
func TestEnrollAndRefreshOfTheSupersededSessionNeverDeadlock(t *testing.T) {
	r := newRig(t)
	r.watchDeadlocks(t)
	r.policy.NodeRefreshPerSession.Limit = 10_000
	service := r.service()
	for round := range rounds {
		nodeID, nodeKeyBytes := platform.NewID(), nodeKey(t)
		enrolled := r.mustEnroll(r.request(nodeID, nodeKeyBytes))
		start := make(chan struct{})
		var wait sync.WaitGroup
		var enrollErr, refreshErr error
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, enrollErr = r.enroll(r.request(nodeID, nodeKeyBytes))
		}()
		go func() {
			defer wait.Done()
			<-start
			_, refreshErr = service.Refresh(context.Background(), neighbour, enrolled.Session.RefreshToken)
		}()
		close(start)
		wait.Wait()
		if deadlocked(enrollErr) || deadlocked(refreshErr) || enrollErr != nil || refreshErr != nil && key(refreshErr) != "AUTHENTICATION/credential_revoked" {
			t.Fatalf("round %d: enroll %v, refresh %v", round, key(enrollErr), key(refreshErr))
		}
		if r.count("SELECT count(*) FROM identity.session s JOIN fleet.node n ON n.installation_id = s.installation_id WHERE n.node_id = $1 AND s.revoked_at IS NULL",
			nodeID) != 1 {
			t.Fatalf("round %d: not exactly one live session", round)
		}
	}
}

// report runs Report in a receipt-like transaction of its own, without retries.
func (r *rig) report(service *Service, enrolled Enrolled, nodeID platform.ID, info NodeInfo) error {
	return r.db.Runtime.InTx(context.Background(), "report", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := service.Report(ctx, tx, neighbour, Node{UserID: r.user, SessionID: enrolled.Session.SessionID, InstallationID: enrolled.InstallationID},
			nodeID, info, time.Now())
		return err
	})
}

// TestReportNodeInfoAndRevokeNeverDeadlock (cloud-1 item 6, N-1): a renaming report (device, installation, node) races the device's
// revocation (device, installation, sessions, node): never a deadlock; and deterministically, a report that waits for the held
// node row already holds the device and the installation.
func TestReportNodeInfoAndRevokeNeverDeadlock(t *testing.T) {
	r := newRig(t)
	r.watchDeadlocks(t)
	service := r.service()
	ctx := context.Background()
	for round := range rounds {
		nodeID := platform.NewID()
		enrolled := r.mustEnroll(r.request(nodeID, nodeKey(t)))
		renamed := linuxNode("renamed", "0.1.0-dev")
		start := make(chan struct{})
		var wait sync.WaitGroup
		var reportErr, revokeErr error
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			reportErr = r.report(service, enrolled, nodeID, renamed)
		}()
		go func() {
			defer wait.Done()
			<-start
			revokeErr = r.db.Runtime.InTx(ctx, "revoke", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
				if _, err := tx.Exec(ctx, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", r.user); err != nil {
					return err
				}
				_, err := device.Revoke(ctx, tx, r.user, enrolled.DeviceID, device.RevokedByOwner, []device.Participant{NodeParticipant{}}, time.Now())
				return err
			})
		}()
		close(start)
		wait.Wait()
		if deadlocked(reportErr) || deadlocked(revokeErr) || revokeErr != nil ||
			reportErr != nil && key(reportErr) != "AUTHENTICATION/unauthenticated" && key(reportErr) != "contention" {
			t.Fatalf("round %d: report %v, revoke %v", round, key(reportErr), revokeErr)
		}
	}
	// Deterministic order: the node row held, the renaming report holds the device and the installation while it waits.
	nodeID := platform.NewID()
	enrolled := r.mustEnroll(r.request(nodeID, nodeKey(t)))
	release := r.hold(t, "SELECT 1 FROM fleet.node WHERE enrollment_id = $1 FOR UPDATE", enrolled.EnrollmentID)
	done := make(chan error, 1)
	go func() { done <- r.report(service, enrolled, nodeID, linuxNode("renamed", "0.1.0-dev")) }()
	r.waitBlocked(t)
	if r.free(t, "SELECT 1 FROM device.device WHERE device_id = $1", enrolled.DeviceID) ||
		r.free(t, "SELECT 1 FROM device.installation WHERE installation_id = $1", enrolled.InstallationID) {
		t.Fatal("the report waits for the node row without holding the device and the installation")
	}
	release(false)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// And with the installation held, it holds the device but not yet the node row.
	release = r.hold(t, "SELECT 1 FROM device.installation WHERE installation_id = $1 FOR UPDATE", enrolled.InstallationID)
	go func() { done <- r.report(service, enrolled, nodeID, linuxNode("renamed-again", "0.1.0-dev")) }()
	r.waitBlocked(t)
	if r.free(t, "SELECT 1 FROM device.device WHERE device_id = $1", enrolled.DeviceID) ||
		!r.free(t, "SELECT 1 FROM fleet.node WHERE enrollment_id = $1", enrolled.EnrollmentID) {
		t.Fatal("the report's locks before the installation")
	}
	release(false)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestAnAuditThatFailsUndoesTheEffect (E1-16, F5): with a trigger that refuses the audit event, an enrollment and a sign-out are
// refused and write nothing; after the trigger is dropped they are admitted and the audit chain verifies.
func TestAnAuditThatFailsUndoesTheEffect(t *testing.T) {
	r := newRig(t)
	service := r.service()
	enrolled := r.mustEnroll(r.request(platform.NewID(), nodeKey(t)))
	r.db.Exec(`CREATE FUNCTION audit.refuse_fleet() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.event_type LIKE 'fleet.%' THEN RAISE EXCEPTION 'refused by the test'; END IF;
    RETURN NEW;
END;
$$`, "CREATE TRIGGER refuse_fleet BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION audit.refuse_fleet()")
	before := r.count("SELECT (SELECT count(*) FROM fleet.node) + (SELECT count(*) FROM identity.session WHERE revoked_at IS NOT NULL)")
	if _, err := r.enroll(r.request(platform.NewID(), nodeKey(t))); err == nil {
		t.Fatal("an enrollment without its audit")
	}
	signOut := func() error {
		return r.db.Runtime.InTx(context.Background(), "sign out", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
			return service.SignOut(ctx, tx, neighbour, Node{UserID: r.user, SessionID: enrolled.Session.SessionID, InstallationID: enrolled.InstallationID}, time.Now())
		})
	}
	if err := signOut(); err == nil {
		t.Fatal("a sign-out without its audit")
	}
	if r.count("SELECT (SELECT count(*) FROM fleet.node) + (SELECT count(*) FROM identity.session WHERE revoked_at IS NOT NULL)") != before {
		t.Fatal("a refused audit left an effect")
	}
	r.db.Exec("DROP TRIGGER refuse_fleet ON audit.audit_event")
	if _, err := r.enroll(r.request(platform.NewID(), nodeKey(t))); err != nil {
		t.Fatal(err)
	}
	if err := signOut(); err != nil {
		t.Fatal(err)
	}
	if r.count("SELECT count(*) FROM audit.audit_event WHERE event_type IN ('fleet.node.enrolled', 'fleet.node.signed_out')") != 3 {
		t.Fatal("the audit events")
	}
	if _, err := platform.VerifyAudit(context.Background(), r.db.Migration); err != nil {
		t.Fatal(err)
	}
}

// TestRevokeDuringRefreshRefusesTheRefresh (E1-14, SEC-4): a node's refresh races the revocation of its device through the own-device
// path (no account lock: device, installations, sessions, then the node rows), both without retries: never a deadlock, no live
// session on the revoked device afterwards, and a token the refresh rotated is refused once the revocation committed.
func TestRevokeDuringRefreshRefusesTheRefresh(t *testing.T) {
	r := newRig(t)
	r.watchDeadlocks(t)
	r.policy.NodeRefreshPerSession.Limit = 10_000
	service := r.service()
	ctx := context.Background()
	for round := range rounds {
		enrolled := r.mustEnroll(r.request(platform.NewID(), nodeKey(t)))
		start := make(chan struct{})
		var wait sync.WaitGroup
		var refreshed Refreshed
		var refreshErr, revokeErr error
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			refreshed, refreshErr = service.Refresh(ctx, neighbour, enrolled.Session.RefreshToken)
		}()
		go func() {
			defer wait.Done()
			<-start
			revokeErr = r.db.Runtime.InTx(ctx, "revoke", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
				_, err := device.Revoke(ctx, tx, r.user, enrolled.DeviceID, device.RevokedByOwner, []device.Participant{NodeParticipant{}}, time.Now())
				return err
			})
		}()
		close(start)
		wait.Wait()
		if deadlocked(refreshErr) || deadlocked(revokeErr) || revokeErr != nil || refreshErr != nil && key(refreshErr) != "AUTHENTICATION/credential_revoked" {
			t.Fatalf("round %d: refresh %v, revoke %v", round, key(refreshErr), revokeErr)
		}
		if live := r.count("SELECT count(*) FROM identity.session WHERE device_id = $1 AND revoked_at IS NULL", enrolled.DeviceID); live != 0 {
			t.Fatalf("round %d: %d live sessions on the revoked device", round, live)
		}
		if refreshErr == nil {
			if _, err := service.Refresh(ctx, neighbour, refreshed.Session.RefreshToken); key(err) != "AUTHENTICATION/credential_revoked" {
				t.Fatalf("round %d: the rotated token after the revocation: %v", round, key(err))
			}
		}
	}
}

// TestOperatorRevocationDuringReenrollmentNeverDeadlocks (SEC-1): the operator's incident tool (admin revoke-sessions, for one account
// and for every account) races a re-enrollment approved by a session newer than the node's, both without retries. What the race
// proves: no round deadlocks or fails, and afterwards no session of the account is live (either the enrollment committed first and
// the tool revoked its new session, or the tool came first and the enrollment lapsed on its revoked approving session). The rounds
// do not reliably meet the interleaving that deadlocked when the tool took no account lock, so this race also passes on that code;
// TestOperatorRevocationTakesTheAccountLocksFirst is the deterministic test that fails on it.
func TestOperatorRevocationDuringReenrollmentNeverDeadlocks(t *testing.T) {
	r := newRig(t)
	r.watchDeadlocks(t)
	ctx := context.Background()
	for round := range rounds {
		for _, all := range []bool{false, true} {
			user, approver := r.account(1)
			nodeID, nodeKeyBytes := platform.NewID(), nodeKey(t)
			first := r.request(nodeID, nodeKeyBytes)
			first.UserID, first.Approver.SessionID = user, approver.ID
			r.mustEnroll(first)
			// The re-enrollment's approving session is newer than the node's session.
			newer := r.db.Session(user, 1)
			again := r.request(nodeID, nodeKeyBytes)
			again.UserID, again.Approver.SessionID = user, newer.ID
			target := &user
			if all {
				target = nil
			}
			start := make(chan struct{})
			var wait sync.WaitGroup
			var enrollErr, revokeErr error
			wait.Add(2)
			go func() {
				defer wait.Done()
				<-start
				_, enrollErr = r.enroll(again)
			}()
			go func() {
				defer wait.Done()
				<-start
				revokeErr = r.db.Runtime.InTx(ctx, "revoke sessions", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
					_, err := session.RevokeByOperator(ctx, tx, target, time.Now())
					return err
				})
			}()
			close(start)
			wait.Wait()
			if deadlocked(enrollErr) || deadlocked(revokeErr) || revokeErr != nil || enrollErr != nil && key(enrollErr) != "lapsed" {
				t.Fatalf("round %d (all %v): enroll %v, revoke %v", round, all, key(enrollErr), revokeErr)
			}
			if live := r.count("SELECT count(*) FROM identity.session WHERE user_id = $1 AND revoked_at IS NULL", user); live != 0 {
				t.Fatalf("round %d (all %v): %d live sessions after the operator's revocation", round, all, live)
			}
		}
	}
}

// TestOperatorRevocationTakesTheAccountLocksFirst (SEC-1) pins the order deterministically: while a third transaction holds the
// account row (as Enroll does from its first lock on), the operator's revocation, of that account and of every account, waits for
// it and holds no session row yet; released, it revokes every session of the account.
func TestOperatorRevocationTakesTheAccountLocksFirst(t *testing.T) {
	r := newRig(t)
	r.watchDeadlocks(t)
	ctx := context.Background()
	for _, all := range []bool{false, true} {
		user, approver := r.account(1)
		target := &user
		if all {
			target = nil
		}
		release := r.hold(t, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", user)
		done := make(chan error, 1)
		go func() {
			done <- r.db.Runtime.InTx(ctx, "revoke sessions", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
				_, err := session.RevokeByOperator(ctx, tx, target, time.Now())
				return err
			})
		}()
		r.waitBlocked(t)
		select {
		case err := <-done:
			t.Fatalf("all %v: the revocation did not wait for the account lock (%v)", all, err)
		default:
		}
		if !r.free(t, "SELECT 1 FROM identity.session WHERE session_id = $1", approver.ID) {
			t.Errorf("all %v: the revocation holds a session while it waits for the account", all)
		}
		release(false)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if live := r.count("SELECT count(*) FROM identity.session WHERE user_id = $1 AND revoked_at IS NULL", user); live != 0 {
			t.Fatalf("all %v: %d live sessions after the revocation", all, live)
		}
	}
}

// TestNothingOfARefusedEnrollmentRemains (SEC-2): Enroll rolls its savepoint back on a lapse and on every refusal, so a caller that
// commits its transaction afterwards (as a flow that ends EXPIRED will) keeps no device, installation, session or key: the lapse of a
// new node's approval after its device and installation were inserted, the lapse and the OS refusal of a re-enrollment; the key then
// enrolls normally.
func TestNothingOfARefusedEnrollmentRemains(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	rows := func() int {
		return r.count(`SELECT (SELECT count(*) FROM device.device) + (SELECT count(*) FROM device.installation) + (SELECT count(*) FROM identity.session)
    + (SELECT count(*) FROM fleet.node) + (SELECT count(*) FROM identity.session WHERE revoked_at IS NOT NULL) + (SELECT count(*) FROM audit.audit_event)`)
	}
	commitAfter := func(request EnrollRequest) error {
		var refused error
		if err := r.db.Runtime.InTx(ctx, "end the flow", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
			_, refused = Enroll(ctx, tx, r.policy, request, time.Now())
			// The caller ends its flow and commits: the outer transaction must still be usable.
			_, err := tx.Exec(ctx, "SELECT 1")
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return refused
	}
	// A new node whose approval lapsed after the device and installation were inserted (the approver's session revoked).
	user, approver := r.account(1)
	nodeID, nodeKeyBytes := platform.NewID(), nodeKey(t)
	request := r.request(nodeID, nodeKeyBytes)
	request.UserID, request.Approver.SessionID = user, approver.ID
	r.db.Exec("UPDATE identity.session SET revoked_at = now(), revoke_reason = 2 WHERE session_id = '" + approver.ID.String() + "'")
	before := rows()
	if err := commitAfter(request); key(err) != "lapsed" || rows() != before {
		t.Fatalf("a lapsed new node: %v, rows %d -> %d", key(err), before, rows())
	}
	// The key is free: the same node enrolls with a standing approval.
	request.Approver.SessionID = r.db.Session(user, 1).ID
	enrolled := r.mustEnroll(request)
	// A re-enrollment that lapses, and one on another OS: the live session stays, nothing changes.
	r.db.Exec("UPDATE identity.session SET auth_epoch = auth_epoch + 1 WHERE session_id = '" + request.Approver.SessionID.String() + "'")
	before = rows()
	if err := commitAfter(request); key(err) != "lapsed" || rows() != before ||
		r.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND revoked_at IS NULL", enrolled.Session.SessionID) != 1 {
		t.Fatalf("a lapsed re-enrollment: %v", key(err))
	}
	windows := request
	windows.Approver.SessionID = r.db.Session(user, 1).ID
	windows.Node.Platform, _ = PlatformOf(1)
	before = rows()
	if err := commitAfter(windows); key(err) != "VALIDATION/invalid_argument node.os/node.os: mismatch" || rows() != before {
		t.Fatalf("another OS: %v", key(err))
	}
}
