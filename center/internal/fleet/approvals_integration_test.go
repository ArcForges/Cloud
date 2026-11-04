// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// EVIDENCE: REAL PostgreSQL, the real identity service with the fleet's account participant, the real sign-in service; the
// remediation runs the statements of identityapi's RevokeAllSessions run in its order (the participants, the evidence, the
// revocation) in one transaction without retries; the approver and its evidence are SEEDED; the node is MOCKED (nodetest). The served
// path is fleetapi's TestApprovalDoesNotOutliveRevokeAllSessionsFromTheApprovingSession.

// identityService is the identity service with the fleet's account participant, as server.New composes it.
func (s *signIns) identityService() *identity.Service {
	return identity.New(identity.Options{DB: s.db.Runtime, Policy: s.policy, Clock: s.clock.Now,
		AccountParticipants: []identity.AccountParticipant{ApprovalParticipant{}}})
}

// revokeAllSessions is RevokeAllSessions from the approving session itself, with its step-up evidence seeded (prove), in the order
// of identityapi's run: the account participants, the evidence (which locks the account), the revocation.
func (s *signIns) revokeAllSessions(service *identity.Service, prove bool) error {
	caller := accountOf(s.user, s.approver, s.clock.Now()).Caller
	if prove {
		target, err := hex.DecodeString(identity.TargetHash(identity.ClassRevokeAllSessions, s.user, s.user))
		if err != nil {
			s.t.Fatal(err)
		}
		s.db.ProveStepUp(s.approver, identity.ClassRevokeAllSessions, target, s.clock.Now())
	}
	return s.db.Runtime.InTx(context.Background(), "revoke all other sessions", store.TxOptions{Attempts: 1}, func(ctx context.Context, tx pgx.Tx) error {
		now := s.clock.Now()
		cancelled, err := service.CancelApprovals(ctx, tx, s.user, now)
		if err != nil {
			return err
		}
		if err = identity.ConsumeEvidence(ctx, tx, caller, identity.ClassRevokeAllSessions, s.user, now); err != nil {
			return err
		}
		_, err = service.RevokeAllSessions(ctx, tx, caller, cancelled, now)
		return err
	})
}

// TestRevokeAllSessionsCancelsTheAccountsApprovals (protocol-6 finding A, SEC-24): after "sign out all other sessions" from the
// approving session, the account's APPROVED flows are DENIED and their codes complete nothing; another account's approval, a PENDING
// flow and a COMPLETED one are untouched; the audit event counts the cancellations.
func TestRevokeAllSessionsCancelsTheAccountsApprovals(t *testing.T) {
	s := newSignIns(t)
	service := s.identityService()
	approved := s.mustBegin(s.newNode())
	s.approve(approved)
	pending := s.mustBegin(s.newNode())
	if _, err := s.review(s.user, s.approver, pending); err != nil {
		t.Fatal(err)
	}
	completed := s.mustBegin(s.newNode())
	s.approve(completed)
	if _, err := s.complete(completed); err != nil {
		t.Fatal(err)
	}
	other, otherSession := s.account(1)
	foreign := s.mustBegin(s.newNode())
	s.approveBy(other, otherSession, foreign)
	if err := s.revokeAllSessions(service, true); err != nil {
		t.Fatal(err)
	}
	if s.state(approved) != FlowDenied || s.state(pending) != FlowPending || s.state(completed) != FlowCompleted || s.state(foreign) != FlowApproved {
		t.Fatalf("states: approved %d, pending %d, completed %d, foreign %d", s.state(approved), s.state(pending), s.state(completed), s.state(foreign))
	}
	if _, err := s.complete(approved); key(err) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("the cancelled approval's code: %s", key(err))
	}
	if s.count(`SELECT count(*) FROM audit.audit_event WHERE event_type = 'identity.sessions.revoked_all'
AND (convert_from(payload, 'UTF8')::jsonb->'participants'->>'fleet.node_sign_in')::int = 1`) != 1 {
		t.Fatal("the cancellation is not counted in the audit event")
	}
}

// TestAStepUpRefusalOfRevokeAllSessionsCancelsNothing: without evidence the remediation is refused and the cancellation rolls back.
func TestAStepUpRefusalOfRevokeAllSessionsCancelsNothing(t *testing.T) {
	s := newSignIns(t)
	f := s.mustBegin(s.newNode())
	s.approve(f)
	if err := s.revokeAllSessions(s.identityService(), false); key(err) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("no evidence: %s", key(err))
	}
	if s.state(f) != FlowApproved {
		t.Fatal("a refused remediation cancelled the approval")
	}
	if _, err := s.complete(f); err != nil {
		t.Fatalf("the approval after a refused remediation: %s", key(err))
	}
}

// TestTheApprovalHookTakesTheFlowsBeforeTheAccount (cloud-1): the remediation waits for a held flow row holding nothing, and for a
// held account row holding the flow rows.
func TestTheApprovalHookTakesTheFlowsBeforeTheAccount(t *testing.T) {
	s := newSignIns(t)
	s.watchDeadlocks(t)
	service := s.identityService()
	f := s.mustBegin(s.newNode())
	s.approve(f)
	target, err := hex.DecodeString(identity.TargetHash(identity.ClassRevokeAllSessions, s.user, s.user))
	if err != nil {
		t.Fatal(err)
	}
	s.db.ProveStepUp(s.approver, identity.ClassRevokeAllSessions, target, s.clock.Now())
	done := make(chan error, 1)
	release := s.hold(t, "SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", s.user)
	go func() { done <- s.revokeAllSessions(service, false) }()
	s.waitBlocked(t)
	if s.free(t, "SELECT 1 FROM fleet.node_sign_in WHERE flow_id = $1", f.id) {
		t.Fatal("the remediation waits for the account without holding the approved flow")
	}
	release(false)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	g := s.mustBegin(s.newNode())
	s.approve(g)
	s.db.ProveStepUp(s.approver, identity.ClassRevokeAllSessions, target, s.clock.Now())
	release = s.hold(t, "SELECT 1 FROM fleet.node_sign_in WHERE flow_id = $1 FOR UPDATE", g.id)
	go func() { done <- s.revokeAllSessions(service, false) }()
	s.waitBlocked(t)
	if !s.free(t, "SELECT 1 FROM identity.user WHERE user_id = $1", s.user) {
		t.Fatal("the remediation took the account before the flow rows")
	}
	release(false)
	if err = <-done; err != nil || s.state(g) != FlowDenied {
		t.Fatalf("after the hold: %v, state %d", err, s.state(g))
	}
}

// TestRevokeAllSessionsRacingAnApprovalOrACompleteNeverDeadlocks (E1-14, SEC-24, N-4): the remediation from the approving session
// races the completion of an approved flow and the approval of a reviewed one. There is never a deadlock; the approved flow is either
// COMPLETED (its completion committed first; the remedy is then revoking the device) or DENIED with no node session; the reviewed
// flow is DENIED when its approval committed first, and an approval by the remediating session itself that commits after the hook's
// scan stands (the user's own act).
func TestRevokeAllSessionsRacingAnApprovalOrACompleteNeverDeadlocks(t *testing.T) {
	s := newSignIns(t)
	s.watchDeadlocks(t)
	service := s.identityService()
	for round := range rounds {
		approved := s.mustBegin(s.newNode())
		s.approve(approved)
		reviewed := s.mustBegin(s.newNode())
		if _, err := s.review(s.user, s.approver, reviewed); err != nil {
			t.Fatal(err)
		}
		s.prove(s.user, s.approver, reviewed.id)
		target, err := hex.DecodeString(identity.TargetHash(identity.ClassRevokeAllSessions, s.user, s.user))
		if err != nil {
			t.Fatal(err)
		}
		s.db.ProveStepUp(s.approver, identity.ClassRevokeAllSessions, target, s.clock.Now())
		var start, done sync.WaitGroup
		start.Add(1)
		done.Add(3)
		errs := make([]error, 3)
		go func() { defer done.Done(); start.Wait(); errs[0] = s.revokeAllSessions(service, false) }()
		go func() { defer done.Done(); start.Wait(); _, errs[1] = s.complete(approved) }()
		go func() {
			defer done.Done()
			start.Wait()
			_, errs[2] = s.service.Decide(context.Background(), s.from, accountOf(s.user, s.approver, s.clock.Now()), reviewed.id, true)
		}()
		start.Done()
		done.Wait()
		for i, err := range errs {
			if deadlocked(err) {
				t.Fatalf("round %d: racer %d deadlocked", round, i)
			}
		}
		if errs[0] != nil {
			t.Fatalf("round %d: the remediation: %v", round, errs[0])
		}
		switch s.state(approved) {
		case FlowCompleted:
			if errs[1] != nil {
				t.Fatalf("round %d: completed with %v", round, errs[1])
			}
		case FlowDenied:
			if key(errs[1]) != "AUTHENTICATION/unauthenticated" || s.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND session_id IS NOT NULL", approved.id) != 0 {
				t.Fatalf("round %d: a denied flow answered %s", round, key(errs[1]))
			}
		default:
			t.Fatalf("round %d: the approved flow is %d", round, s.state(approved))
		}
		if state := s.state(reviewed); state != FlowDenied && state != FlowApproved && state != FlowPending {
			t.Fatalf("round %d: the reviewed flow is %d", round, state)
		}
	}
}
