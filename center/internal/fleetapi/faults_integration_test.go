// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi_test

import (
	"context"
	"strings"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"

	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// EVIDENCE: REAL PostgreSQL with fault injection (E1-16, E1-17): a deferred constraint trigger fails the COMMIT of exactly the
// transaction under test with the Neon pooler's protocol violation (08P01: the outcome is unknown); a BEFORE trigger fails a statement
// with 53300 (the database refused: the transaction rolled back); a trigger refuses an audit event. The rest as in
// signin_integration_test.go (MOCKED node, passkey and mail).

func unknownCommit(value *foundationv1.ArcError) bool {
	return failure(value) == "INTERNAL/internal" && value.GetRetry().GetMode() == foundationv1.RetryMode_RETRY_MODE_NEVER &&
		value.GetEffect() == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN
}

func undoneCommit(value *foundationv1.ArcError) bool {
	return failure(value) == "RESOURCE/overloaded" && value.GetRetry().GetMode() == foundationv1.RetryMode_RETRY_MODE_AFTER_TIME &&
		value.GetRetry().GetRetryAt() != nil && value.GetEffect() == foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN
}

// faulting installs a trigger on a table while run runs: kind "lost" fails the COMMIT of a transaction that changes a row as the
// condition says (08P01), "refused" fails the statement itself (53300).
func (h *harness) faulting(kind, event, table, condition string, run func()) {
	h.t.Helper()
	h.db.Exec("CREATE SCHEMA IF NOT EXISTS testfault",
		"CREATE OR REPLACE FUNCTION testfault.lost() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'the commit was lost (test)' USING ERRCODE = '08P01'; END; $$",
		"CREATE OR REPLACE FUNCTION testfault.refused() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'the database refused (test)' USING ERRCODE = '53300'; END; $$")
	when := ""
	if condition != "" {
		when = " WHEN (" + condition + ")"
	}
	if kind == "lost" {
		h.db.Exec("CREATE CONSTRAINT TRIGGER test_fault AFTER " + event + " ON " + table + " DEFERRABLE INITIALLY DEFERRED FOR EACH ROW" + when +
			" EXECUTE FUNCTION testfault.lost()")
	} else {
		h.db.Exec("CREATE TRIGGER test_fault BEFORE " + event + " ON " + table + " FOR EACH ROW" + when + " EXECUTE FUNCTION testfault.refused()")
	}
	defer h.db.Exec("DROP TRIGGER test_fault ON " + table)
	run()
}

func (h *harness) state(s *signIn) int {
	return h.count("SELECT state FROM fleet.node_sign_in WHERE flow_id = $1", s.flowID)
}

// TestALostCommitOfCompleteIsUnknown (E1-17): a completion whose COMMIT went unanswered may have enrolled the node, so it is
// INTERNAL/internal with effect UNKNOWN and retry NEVER, logged; the node signs in again (here the commit failed, so the flow is still
// APPROVED and unredeemed, and the identical retry completes).
func TestALostCommitOfCompleteIsUnknown(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	s, _ := h.begin()
	h.approve(owner, s, false)
	h.faulting("lost", "UPDATE", "fleet.node_sign_in", "NEW.state = 3", func() {
		if response := h.complete(s); !unknownCommit(response.GetError()) {
			t.Fatalf("a lost commit of the completion: %+v", response.GetError())
		}
	})
	if !strings.Contains(h.logs.String(), "the outcome of the commit is unknown") {
		t.Error("the unknown commit was not logged")
	}
	if h.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND state = 2 AND code_redeemed_at IS NULL", s.flowID) != 1 {
		t.Fatal("a failed commit redeemed the code")
	}
	if response := h.complete(s); response.GetError() != nil {
		t.Fatalf("the retry: %s", failure(response.GetError()))
	}
}

// TestAStoreFailureAfterTheProofLeavesTheCodeUnredeemed (cloud-2 item 4): a store failure inside the completion after verified
// proofs rolls everything back: RESOURCE/overloaded with AFTER_TIME, the flow APPROVED with its code unredeemed, nothing of the
// enrollment left; the identical retry succeeds. A failure while the failure marker is written leaves the flow APPROVED too.
func TestAStoreFailureAfterTheProofLeavesTheCodeUnredeemed(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	s, _ := h.begin()
	h.approve(owner, s, false)
	h.faulting("refused", "UPDATE", "fleet.node_sign_in", "NEW.state = 3", func() {
		if response := h.complete(s); !undoneCommit(response.GetError()) {
			t.Fatalf("a store failure: %+v", response.GetError())
		}
	})
	if h.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND state = 2 AND code_redeemed_at IS NULL", s.flowID) != 1 ||
		h.count("SELECT count(*) FROM device.installation WHERE product_id = 'arcforges-node'") != 0 {
		t.Fatal("a failed completion left an effect")
	}
	if response := h.complete(s); response.GetError() != nil {
		t.Fatalf("the identical retry: %s", failure(response.GetError()))
	}
	marked, _ := h.begin()
	h.approve(owner, marked, false)
	wrong := marked.node.CompleteRequest(marked.flowID, marked.code, nodetest.NewSignIn(), marked.node.CompleteProof(publicBaseURL, marked.flowID, marked.code))
	h.faulting("lost", "UPDATE", "fleet.node_sign_in", "NEW.state = 6", func() {
		// The failure marker is bookkeeping around a refusal: its lost commit is retryable, and the flow is still APPROVED.
		if response := h.completeWith(wrong); !undoneCommit(response.GetError()) {
			t.Fatalf("a lost commit of the failure marker: %+v", response.GetError())
		}
	})
	if h.state(marked) != 2 {
		t.Fatal("the lost marker changed the flow")
	}
	if response := h.completeWith(wrong); failure(response.GetError()) != "AUTHENTICATION/unauthenticated" || h.state(marked) != 6 {
		t.Fatalf("the marker afterwards: %s", failure(response.GetError()))
	}
}

// TestALostCommitOfTheReviewIsRetryable (E1-17): the review is a mark, not an effect: its lost commit is RESOURCE/overloaded and the
// retry records it.
func TestALostCommitOfTheReviewIsRetryable(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	s, _ := h.begin()
	h.faulting("lost", "UPDATE", "fleet.node_sign_in", "NEW.viewed_by IS NOT NULL", func() {
		if response := h.review(owner, s); !undoneCommit(response.GetError()) {
			t.Fatalf("a lost review: %+v", response.GetError())
		}
	})
	if response := h.review(owner, s); response.GetError() != nil || h.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND viewed_by = $2", s.flowID, owner.id) != 1 {
		t.Fatalf("the retried review: %s", failure(response.GetError()))
	}
}

// TestARefusedAuditUndoesTheApprovalAndTheReuse (E1-16, audit before effect): with the approval's event refused the approval is not
// made and its evidence is not consumed; with the reuse's event refused the reuse revokes nothing; once the trigger is dropped both
// happen, and the audit chain verifies.
func TestARefusedAuditUndoesTheApprovalAndTheReuse(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	s, _ := h.begin()
	h.db.Exec(`CREATE FUNCTION audit.refuse_sign_in() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.event_type IN ('fleet.node_sign_in.approved', 'fleet.node_sign_in.code_reused') THEN RAISE EXCEPTION 'refused by the test'; END IF;
    RETURN NEW;
END;
$$`, "CREATE TRIGGER refuse_sign_in BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION audit.refuse_sign_in()")
	if review := h.review(owner, s); review.GetError() != nil {
		t.Fatal(failure(review.GetError()))
	}
	h.stepUp(owner, "fleet.approveNodeSignIn", s.flowID, false)
	if response := h.decide(owner.bearer, s, true); response.GetError() == nil {
		t.Fatal("an approval without its audit")
	}
	if h.state(s) != 1 || h.count("SELECT count(*) FROM identity.step_up_challenge WHERE user_id = $1 AND state = 2", owner.id) != 1 {
		t.Fatal("a refused audit left the approval or consumed the evidence")
	}
	h.db.Exec("DROP TRIGGER refuse_sign_in ON audit.audit_event")
	decided := h.decide(owner.bearer, s, true)
	if decided.GetError() != nil {
		t.Fatalf("the approval with its audit: %s", failure(decided.GetError()))
	}
	s.code, _ = s.pkce.LoopbackCode(decided.GetValue().GetRedirectUrl())
	completed := h.complete(s)
	if completed.GetError() != nil {
		t.Fatal(failure(completed.GetError()))
	}
	h.db.Exec("CREATE TRIGGER refuse_sign_in BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION audit.refuse_sign_in()")
	if response := h.complete(s); response.GetError() == nil || failure(response.GetError()) == "CONFLICT/code_reused" {
		t.Fatalf("a reuse without its audit: %+v", response.GetError())
	}
	if h.state(s) != 3 || h.count("SELECT count(*) FROM identity.session WHERE scope = 3 AND revoked_at IS NULL") != 1 {
		t.Fatal("a refused audit left the reuse's revocation")
	}
	h.db.Exec("DROP TRIGGER refuse_sign_in ON audit.audit_event")
	if response := h.complete(s); failure(response.GetError()) != "CONFLICT/code_reused" || h.state(s) != 6 {
		t.Fatalf("the reuse with its audit: %s", failure(response.GetError()))
	}
	if _, err := platform.VerifyAudit(context.Background(), h.db.Migration); err != nil {
		t.Fatal(err)
	}
}
