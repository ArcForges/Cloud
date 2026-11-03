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

func (r *rig) service() *Service { return New(Options{DB: r.db.Runtime, Policy: r.policy}) }

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
