// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// EVIDENCE: REAL PostgreSQL, real row locks, goroutines released together, every transaction without retries (Attempts 1), so a
// deadlock fails the round (E1-14, cloud-1); the deterministic tests hold one row of the global order in a third transaction and look
// at what the waiting transaction holds (pg_locks through FOR UPDATE NOWAIT). Accounts, sessions and evidence SEEDED; node MOCKED.

// proveRevokeAll seeds the approving session's evidence for RevokeAllSessions.
func (s *signIns) proveRevokeAll() {
	s.t.Helper()
	target, err := hex.DecodeString(identity.TargetHash(identity.ClassRevokeAllSessions, s.user, s.user))
	if err != nil {
		s.t.Fatal(err)
	}
	s.db.ProveStepUp(s.approver, identity.ClassRevokeAllSessions, target, s.clock.Now())
}

// TestPollTakesItsLocksInTheGlobalOrder (cloud-1, E1-14): a held account row makes the delivering poll wait holding the authorization
// row; a held authorization row makes it wait holding nothing of the account (Enroll's order follows:
// TestEnrollTakesItsLocksInTheGlobalOrder).
func TestPollTakesItsLocksInTheGlobalOrder(t *testing.T) {
	s := newSignIns(t)
	s.watchDeadlocks(t)
	a := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, a)
	release := s.hold(t, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", s.user)
	done := make(chan error, 1)
	go func() { _, err := s.poll(a); done <- err }()
	s.waitBlocked(t)
	if s.free(t, "SELECT 1 FROM fleet.device_authorization WHERE authorization_id = $1", a.started.AuthorizationID) {
		t.Fatal("the poll waits for the account without holding the authorization")
	}
	release(false)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	b := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, b)
	release = s.hold(t, "SELECT 1 FROM fleet.device_authorization WHERE authorization_id = $1 FOR UPDATE", b.started.AuthorizationID)
	go func() { _, err := s.poll(b); done <- err }()
	s.waitBlocked(t)
	if !s.free(t, "SELECT 1 FROM identity.user WHERE user_id = $1", s.user) {
		t.Fatal("the poll took the account before the authorization")
	}
	release(false)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestApproveDeviceCodeTakesTheAuthorizationBeforeTheAccount (cloud-1): an approval waits for a held authorization row holding nothing
// of the account, and for a held account row holding the authorization row.
func TestApproveDeviceCodeTakesTheAuthorizationBeforeTheAccount(t *testing.T) {
	s := newSignIns(t)
	s.watchDeadlocks(t)
	a := s.mustStart(s.newNode())
	if _, err := s.lookup(s.user, s.approver, a.started.UserCode); err != nil {
		t.Fatal(err)
	}
	s.proveCode(s.user, s.approver, a.started.UserCode)
	release := s.hold(t, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", s.user)
	done := make(chan error, 1)
	go func() { done <- s.decide(s.user, s.approver, a.started.UserCode, true) }()
	s.waitBlocked(t)
	if s.free(t, "SELECT 1 FROM fleet.device_authorization WHERE authorization_id = $1", a.started.AuthorizationID) {
		t.Fatal("the approval waits for the account without holding the authorization")
	}
	release(false)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	b := s.mustStart(s.newNode())
	if _, err := s.lookup(s.user, s.approver, b.started.UserCode); err != nil {
		t.Fatal(err)
	}
	s.proveCode(s.user, s.approver, b.started.UserCode)
	release = s.hold(t, "SELECT 1 FROM fleet.device_authorization WHERE authorization_id = $1 FOR UPDATE", b.started.AuthorizationID)
	go func() { done <- s.decide(s.user, s.approver, b.started.UserCode, true) }()
	s.waitBlocked(t)
	if !s.free(t, "SELECT 1 FROM identity.user WHERE user_id = $1", s.user) {
		t.Fatal("the approval took the account before the authorization")
	}
	release(false)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestRevokeAllSessionsCancelsTheAccountsDeviceApprovals (protocol-6, P(iv), SEC-24): after "sign out all other sessions" from the
// approving session the account's APPROVED device authorizations are DENIED (the node's poll answers DENIED); a PENDING one it
// reviewed, a COMPLETED one and another account's approval are untouched; the audit event counts the cancellation under
// fleet.device_authorization next to fleet.node_sign_in.
func TestRevokeAllSessionsCancelsTheAccountsDeviceApprovals(t *testing.T) {
	s := newSignIns(t)
	s.wide()
	service := s.identityService()
	approved := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, approved)
	pending := s.mustStart(s.newNode())
	if _, err := s.lookup(s.user, s.approver, pending.started.UserCode); err != nil {
		t.Fatal(err)
	}
	completed := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, completed)
	if _, err := s.poll(completed); err != nil {
		t.Fatal(err)
	}
	other, otherSession := s.account(1)
	foreign := s.mustStart(s.newNode())
	s.approveCode(other, otherSession, foreign)
	s.proveRevokeAll()
	if err := s.revokeAllSessions(service, false); err != nil {
		t.Fatal(err)
	}
	if s.authorizationState(approved) != AuthorizationDenied || s.authorizationState(pending) != AuthorizationPending ||
		s.authorizationState(completed) != AuthorizationCompleted || s.authorizationState(foreign) != AuthorizationApproved {
		t.Fatalf("states %d %d %d %d", s.authorizationState(approved), s.authorizationState(pending), s.authorizationState(completed), s.authorizationState(foreign))
	}
	if polled, err := s.poll(approved); err != nil || polled.State != AuthorizationDenied {
		t.Fatalf("the cancelled approval's poll: %+v %s", polled, key(err))
	}
	if s.count(`SELECT count(*) FROM audit.audit_event WHERE event_type = 'identity.sessions.revoked_all'
AND (convert_from(payload, 'UTF8')::jsonb->'participants'->>'fleet.device_authorization')::int = 1
AND (convert_from(payload, 'UTF8')::jsonb->'participants'->>'fleet.node_sign_in')::int = 0`) != 1 {
		t.Fatal("the cancellation is not counted in the audit event")
	}
}

// TestAStepUpRefusalOfRevokeAllSessionsCancelsNoDeviceApproval: without evidence the remediation is refused and the device approval
// stands and is delivered.
func TestAStepUpRefusalOfRevokeAllSessionsCancelsNoDeviceApproval(t *testing.T) {
	s := newSignIns(t)
	a := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, a)
	if err := s.revokeAllSessions(s.identityService(), false); key(err) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("no evidence: %s", key(err))
	}
	if polled, err := s.poll(a); err != nil || polled.State != AuthorizationApproved {
		t.Fatalf("the approval after a refused remediation: %+v %s", polled, key(err))
	}
}

// TestTheApprovalHooksTakeTheFlowsThenTheAuthorizationsBeforeTheAccount (cloud-1, E1b N-8): the remediation waits for a held browser
// flow row holding no authorization row; for a held authorization row holding the flow rows and not the account; for a held account
// row holding the authorization rows.
func TestTheApprovalHooksTakeTheFlowsThenTheAuthorizationsBeforeTheAccount(t *testing.T) {
	s := newSignIns(t)
	s.wide()
	s.watchDeadlocks(t)
	service := s.identityService()
	done := make(chan error, 1)
	for _, held := range []string{"flow", "authorization", "account"} {
		f := s.mustBegin(s.newNode())
		s.approve(f)
		a := s.mustStart(s.newNode())
		s.approveCode(s.user, s.approver, a)
		s.proveRevokeAll()
		var release func(bool)
		switch held {
		case "flow":
			release = s.hold(t, "SELECT 1 FROM fleet.node_sign_in WHERE flow_id = $1 FOR UPDATE", f.id)
		case "authorization":
			release = s.hold(t, "SELECT 1 FROM fleet.device_authorization WHERE authorization_id = $1 FOR UPDATE", a.started.AuthorizationID)
		default:
			release = s.hold(t, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", s.user)
		}
		go func() { done <- s.revokeAllSessions(service, false) }()
		s.waitBlocked(t)
		flowFree := s.free(t, "SELECT 1 FROM fleet.node_sign_in WHERE flow_id = $1", f.id)
		authorizationFree := s.free(t, "SELECT 1 FROM fleet.device_authorization WHERE authorization_id = $1", a.started.AuthorizationID)
		accountFree := s.free(t, "SELECT 1 FROM identity.user WHERE user_id = $1", s.user)
		switch {
		case held == "flow" && !authorizationFree, held == "flow" && !accountFree:
			t.Fatal("the remediation took an authorization or the account before the browser flows")
		case held == "authorization" && (flowFree || !accountFree):
			t.Fatalf("waiting for the authorization: flow free %v, account free %v", flowFree, accountFree)
		case held == "account" && (flowFree || authorizationFree):
			t.Fatalf("waiting for the account: flow free %v, authorization free %v", flowFree, authorizationFree)
		}
		release(false)
		if err := <-done; err != nil || s.authorizationState(a) != AuthorizationDenied || s.state(f) != FlowDenied {
			t.Fatalf("after the hold of the %s: %v", held, err)
		}
	}
}

// TestAnApprovalThatHoldsItsAuthorizationWhenTheHookStartsIsDenied (d.2, N-4): the approval of a reviewed code holds its row and waits
// for the account a third transaction holds; the remediation from the same session starts and waits for that row; released, the
// approval commits first and the hook's second statement denies it.
func TestAnApprovalThatHoldsItsAuthorizationWhenTheHookStartsIsDenied(t *testing.T) {
	s := newSignIns(t)
	s.watchDeadlocks(t)
	service := s.identityService()
	a := s.mustStart(s.newNode())
	if _, err := s.lookup(s.user, s.approver, a.started.UserCode); err != nil {
		t.Fatal(err)
	}
	s.proveCode(s.user, s.approver, a.started.UserCode)
	s.proveRevokeAll()
	release := s.hold(t, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", s.user)
	approved, remediated := make(chan error, 1), make(chan error, 1)
	go func() { approved <- s.decide(s.user, s.approver, a.started.UserCode, true) }()
	s.waitBlockedBy(t, 1)
	go func() { remediated <- s.revokeAllSessions(service, false) }()
	s.waitBlockedBy(t, 2)
	release(false)
	if err := <-approved; err != nil {
		t.Fatalf("the approval: %s", key(err))
	}
	if err := <-remediated; err != nil {
		t.Fatalf("the remediation: %v", err)
	}
	if s.authorizationState(a) != AuthorizationDenied {
		t.Fatalf("the approval that held its authorization survived: state %d", s.authorizationState(a))
	}
}

// TestRevokeAllSessionsRacingADeviceApprovalOrAPollNeverDeadlocks (E1-14, SEC-24, N-4): the remediation from the approving session
// races the delivering poll of an approved authorization and the approval of a reviewed one. There is never a deadlock; the approved
// authorization is COMPLETED (its poll committed first) or DENIED with no node session; the approval always succeeds and its
// authorization is DENIED when it committed before the remediation and APPROVED when after (the user's own act).
func TestRevokeAllSessionsRacingADeviceApprovalOrAPollNeverDeadlocks(t *testing.T) {
	s := newSignIns(t)
	s.wide()
	s.watchDeadlocks(t)
	service := s.identityService()
	for round := range rounds {
		approved := s.mustStart(s.newNode())
		s.approveCode(s.user, s.approver, approved)
		reviewed := s.mustStart(s.newNode())
		if _, err := s.lookup(s.user, s.approver, reviewed.started.UserCode); err != nil {
			t.Fatal(err)
		}
		s.proveCode(s.user, s.approver, reviewed.started.UserCode)
		s.proveRevokeAll()
		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(3)
		errs := make([]error, 3)
		var polled Polled
		go func() { defer done.Done(); start.Wait(); errs[0] = s.revokeAllSessions(service, false) }()
		go func() { defer done.Done(); start.Wait(); polled, errs[1] = s.poll(approved) }()
		go func() {
			defer done.Done()
			start.Wait()
			errs[2] = s.decide(s.user, s.approver, reviewed.started.UserCode, true)
		}()
		start.Done()
		done.Wait()
		for i, err := range errs {
			if deadlocked(err) {
				t.Fatalf("round %d: racer %d deadlocked", round, i)
			}
		}
		if errs[0] != nil || errs[1] != nil || errs[2] != nil {
			t.Fatalf("round %d: %v, %s, %s", round, errs[0], key(errs[1]), key(errs[2]))
		}
		switch s.authorizationState(approved) {
		case AuthorizationCompleted:
			if polled.State != AuthorizationApproved || polled.Completed == nil {
				t.Fatalf("round %d: completed with %+v", round, polled)
			}
		case AuthorizationDenied:
			if polled.State != AuthorizationDenied || s.count("SELECT count(*) FROM fleet.device_authorization WHERE authorization_id = $1 AND session_id IS NOT NULL",
				approved.started.AuthorizationID) != 0 {
				t.Fatalf("round %d: a denied authorization answered %+v", round, polled)
			}
		default:
			t.Fatalf("round %d: the approved authorization is %d", round, s.authorizationState(approved))
		}
		approvedAt := s.count("SELECT sequence FROM audit.audit_event WHERE event_type = 'fleet.device_authorization.approved' AND target_id = $1",
			reviewed.started.AuthorizationID.String())
		revokedAt := s.count("SELECT max(sequence) FROM audit.audit_event WHERE event_type = 'identity.sessions.revoked_all'")
		switch state := s.authorizationState(reviewed); {
		case state == AuthorizationDenied && approvedAt < revokedAt, state == AuthorizationApproved && approvedAt > revokedAt:
		default:
			t.Fatalf("round %d: the reviewed authorization is %d, approved at %d, revoked at %d", round, state, approvedAt, revokedAt)
		}
	}
}

// TestOperatorRevokeSessionsRacingADeviceApprovalOrPollNeverDeadlocks (NB-2): the operator's revoke-sessions (the accounts FOR NO KEY
// UPDATE, then the sessions; never an authorization row) races an approval of a reviewed code and the delivering poll of an approved
// one. Never a deadlock; a poll that comes after the revocation lapses (the approving session was revoked by the operator, reason 6)
// and ends EXPIRED with no node session; one that came first delivered credentials the operator then revoked.
func TestOperatorRevokeSessionsRacingADeviceApprovalOrPollNeverDeadlocks(t *testing.T) {
	s := newSignIns(t)
	s.wide()
	s.watchDeadlocks(t)
	ctx := context.Background()
	for round := range rounds {
		user, approver := s.account(1)
		approved := s.mustStart(s.newNode())
		s.approveCode(user, approver, approved)
		reviewed := s.mustStart(s.newNode())
		if _, err := s.lookup(user, approver, reviewed.started.UserCode); err != nil {
			t.Fatal(err)
		}
		s.proveCode(user, approver, reviewed.started.UserCode)
		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(3)
		errs := make([]error, 3)
		var polled Polled
		go func() {
			defer done.Done()
			start.Wait()
			errs[0] = s.db.Runtime.InTx(ctx, "revoke sessions", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
				_, err := session.RevokeByOperator(ctx, tx, &user, time.Now())
				return err
			})
		}()
		go func() { defer done.Done(); start.Wait(); polled, errs[1] = s.poll(approved) }()
		go func() {
			defer done.Done()
			start.Wait()
			errs[2] = s.decide(user, approver, reviewed.started.UserCode, true)
		}()
		start.Done()
		done.Wait()
		for i, err := range errs {
			if deadlocked(err) {
				t.Fatalf("round %d: racer %d deadlocked", round, i)
			}
		}
		if errs[0] != nil || errs[1] != nil {
			t.Fatalf("round %d: %v, %s", round, errs[0], key(errs[1]))
		}
		switch s.authorizationState(approved) {
		case AuthorizationCompleted:
		case AuthorizationExpired:
			if polled.State != AuthorizationExpired || s.count("SELECT count(*) FROM fleet.node WHERE user_id = $1", user) != 0 {
				t.Fatalf("round %d: a lapsed approval answered %+v", round, polled)
			}
		default:
			t.Fatalf("round %d: the approved authorization is %d", round, s.authorizationState(approved))
		}
		if live := s.count("SELECT count(*) FROM identity.session WHERE user_id = $1 AND revoked_at IS NULL", user); live != 0 {
			t.Fatalf("round %d: %d live sessions after the operator's revocation", round, live)
		}
	}
}

// TestTheLoserOfTwoPollsRevokesTheWinner (NB-6, the E1b C-1 class, deterministic): the first poll of an approved authorization waits
// for the account a third transaction holds while it holds the row; a second poll waits for the row; released, the first delivers and
// the second finds the authorization COMPLETED and takes the reuse path: the winner's family is revoked (reason 8), reused_at is set and
// the reuse is audited once.
func TestTheLoserOfTwoPollsRevokesTheWinner(t *testing.T) {
	s := newSignIns(t)
	s.watchDeadlocks(t)
	a := s.mustStart(s.newNode())
	s.approveCode(s.user, s.approver, a)
	release := s.hold(t, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", s.user)
	type answer struct {
		polled Polled
		err    error
	}
	won, lost := make(chan answer, 1), make(chan answer, 1)
	go func() { polled, err := s.poll(a); won <- answer{polled, err} }()
	s.waitBlockedBy(t, 1)
	go func() { polled, err := s.poll(a); lost <- answer{polled, err} }()
	s.waitBlockedBy(t, 2)
	release(false)
	winner, loser := <-won, <-lost
	if winner.err != nil || winner.polled.Completed == nil || loser.err != nil || loser.polled.State != AuthorizationCompleted || loser.polled.Completed != nil {
		t.Fatalf("winner %+v %s, loser %+v %s", winner.polled, key(winner.err), loser.polled, key(loser.err))
	}
	if s.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND revoke_reason = 8", winner.polled.Completed.Enrolled.Session.SessionID) != 1 ||
		s.count("SELECT count(*) FROM identity.session WHERE scope = 3 AND revoked_at IS NULL") != 0 ||
		s.count("SELECT count(*) FROM fleet.device_authorization WHERE authorization_id = $1 AND reused_at IS NOT NULL", a.started.AuthorizationID) != 1 ||
		s.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.device_authorization.code_reused'") != 1 {
		t.Fatal("the loser did not revoke the winner")
	}
}

// TestConcurrentPollsEnrollOnce (SEC-12, NB-6): two polls of an approved authorization released together enroll once; the loser
// finds it COMPLETED and revokes the winner's family, so no node session stays live; no deadlock.
func TestConcurrentPollsEnrollOnce(t *testing.T) {
	s := newSignIns(t)
	s.wide()
	s.watchDeadlocks(t)
	for round := range rounds {
		a := s.mustStart(s.newNode())
		s.approveCode(s.user, s.approver, a)
		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(2)
		answers := make([]Polled, 2)
		errs := make([]error, 2)
		for i := range 2 {
			go func() { defer done.Done(); start.Wait(); answers[i], errs[i] = s.poll(a) }()
		}
		start.Done()
		done.Wait()
		delivered := 0
		for i := range 2 {
			if deadlocked(errs[i]) || errs[i] != nil {
				t.Fatalf("round %d: poll %d: %s", round, i, key(errs[i]))
			}
			if answers[i].Completed != nil {
				delivered++
			}
		}
		if delivered != 1 || s.count("SELECT count(*) FROM fleet.node WHERE node_id = (SELECT node_id FROM fleet.device_authorization WHERE authorization_id = $1)",
			a.started.AuthorizationID) != 1 || s.count("SELECT count(*) FROM identity.session WHERE scope = 3 AND revoked_at IS NULL") != 0 ||
			s.count("SELECT count(*) FROM fleet.device_authorization WHERE authorization_id = $1 AND reused_at IS NOT NULL", a.started.AuthorizationID) != 1 {
			t.Fatalf("round %d: %d deliveries, or the winner's family stays live", round, delivered)
		}
	}
}

// TestRevokeDuringPollLeavesNoLiveSession (SEC-12): the device revocation of a node that re-enrolls races the delivering poll (the
// authorization row in front of the order). Never a deadlock and never a live node session on a revoked device.
func TestRevokeDuringPollLeavesNoLiveSession(t *testing.T) {
	s := newSignIns(t)
	s.wide()
	s.watchDeadlocks(t)
	for round := range rounds {
		node := s.newNode()
		enrolled := s.mustEnroll(s.request(node.ID, node.PublicKey))
		if _, err := s.db.Runtime.Pool().Exec(context.Background(), "UPDATE identity.session SET revoked_at = now(), revoke_reason = 1, rev = rev + 1 WHERE installation_id = $1",
			enrolled.InstallationID); err != nil {
			t.Fatal(err)
		}
		// The node signs in again after a sign-out, with a new key (C0: its old key is held).
		again := *node
		fresh := s.newNode()
		again.Key, again.PublicKey = fresh.Key, fresh.PublicKey
		a := s.mustStart(&again)
		s.approveCode(s.user, s.approver, a)
		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(2)
		var pollErr, revokeErr error
		go func() { defer done.Done(); start.Wait(); _, pollErr = s.poll(a) }()
		go func() { defer done.Done(); start.Wait(); revokeErr = s.revokeDevice(enrolled.DeviceID) }()
		start.Done()
		done.Wait()
		if deadlocked(pollErr) || deadlocked(revokeErr) || revokeErr != nil || pollErr != nil {
			t.Fatalf("round %d: poll %s, revoke %v", round, key(pollErr), revokeErr)
		}
		if live := s.count(`SELECT count(*) FROM identity.session s JOIN device.device d ON d.device_id = s.device_id
WHERE d.revoked_at IS NOT NULL AND s.revoked_at IS NULL`); live != 0 {
			t.Fatalf("round %d: %d live sessions on a revoked device", round, live)
		}
	}
}
