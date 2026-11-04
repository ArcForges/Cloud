// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi_test

import (
	"context"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// EVIDENCE: as faults_integration_test.go (E1-16, E1-17 for the device-code sign-in): REAL PostgreSQL with fault injection; MOCKED node,
// passkey and mail.

func (h *harness) authorizationState(d *deviceSignIn) int {
	return h.count("SELECT state FROM fleet.device_authorization WHERE device_code_hash = sha256(decode(translate($1, '-_', '+/') || '=', 'base64'))",
		d.authorization.GetDeviceCode())
}

// approveDeviceSignIn looks the code up, steps up and approves it.
func (h *harness) approveDeviceSignIn(p *person, d *deviceSignIn) {
	h.t.Helper()
	code := d.authorization.GetUserCode()
	if looked := h.lookup(p, code); looked.GetError() != nil {
		h.t.Fatal(failure(looked.GetError()))
	}
	h.stepUpCode(p, code, false)
	if decided := h.decideDevice(p.bearer, command(), code, true); decided.GetError() != nil {
		h.t.Fatal(failure(decided.GetError()))
	}
}

// TestALostCommitOfPollDeliveryIsUnknown (E1-17): a delivering poll whose COMMIT went unanswered may have enrolled the node, so it is
// INTERNAL/internal with effect UNKNOWN and retry NEVER; here the commit failed, so the authorization is still APPROVED and the next
// poll delivers. A lost commit of a PENDING poll's record is bookkeeping: RESOURCE/overloaded.
func TestALostCommitOfPollDeliveryIsUnknown(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	d, _ := h.start()
	h.faulting("lost", "UPDATE", "fleet.device_authorization", "NEW.state = 1 AND NEW.last_poll_at IS NOT NULL", func() {
		if response := h.poll(d); !undoneCommit(response.GetError()) {
			t.Fatalf("a lost commit of a pending poll's record: %+v", response.GetError())
		}
	})
	h.approveDeviceSignIn(owner, d)
	h.faulting("lost", "UPDATE", "fleet.device_authorization", "NEW.state = 6", func() {
		if response := h.poll(d); !unknownCommit(response.GetError()) {
			t.Fatalf("a lost commit of the delivery: %+v", response.GetError())
		}
	})
	if h.authorizationState(d) != 3 || h.count("SELECT count(*) FROM device.installation WHERE product_id = 'arcforges-node'") != 0 {
		t.Fatal("a failed commit delivered")
	}
	if response := h.poll(d); response.GetError() != nil || response.GetValue().GetCredentials() == nil {
		t.Fatalf("the next poll: %s", failure(response.GetError()))
	}
}

// TestAStoreFailureOfPollDeliveryLeavesItApproved (DEV-04): a store failure inside the delivery rolls everything back: RESOURCE/overloaded
// with AFTER_TIME, the authorization APPROVED, nothing of the enrollment; the identical retry delivers.
func TestAStoreFailureOfPollDeliveryLeavesItApproved(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	d, _ := h.start()
	h.approveDeviceSignIn(owner, d)
	h.faulting("refused", "UPDATE", "fleet.device_authorization", "NEW.state = 6", func() {
		if response := h.poll(d); !undoneCommit(response.GetError()) {
			t.Fatalf("a store failure: %+v", response.GetError())
		}
	})
	if h.authorizationState(d) != 3 || h.count("SELECT count(*) FROM device.installation WHERE product_id = 'arcforges-node'") != 0 {
		t.Fatal("a failed delivery left an effect")
	}
	if response := h.poll(d); response.GetError() != nil || response.GetValue().GetCredentials() == nil {
		t.Fatalf("the identical retry: %s", failure(response.GetError()))
	}
}

// TestAStoreFailureOfALookupGivesTheEntryBack (OQ-8 as decided): a lookup whose review fails in the store gives the reserved units back
// in a transaction of its own; one whose commit went unanswered keeps them.
func TestAStoreFailureOfALookupGivesTheEntryBack(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	d, _ := h.start()
	counted := func() int {
		return h.count("SELECT coalesce(sum(count), 0) FROM platform.rate_limit r WHERE r.bucket_hash = sha256(convert_to('device_entry_account', 'UTF8') || '\\x00'::bytea || convert_to('account:' || $1, 'UTF8'))",
			owner.id.String())
	}
	h.faulting("refused", "UPDATE", "fleet.device_authorization", "NEW.viewed_by IS NOT NULL", func() {
		if response := h.lookup(owner, d.authorization.GetUserCode()); !undoneCommit(response.GetError()) {
			t.Fatalf("a refused review: %+v", response.GetError())
		}
	})
	if counted() != 0 {
		t.Fatalf("a refused review kept %d units", counted())
	}
	h.faulting("lost", "UPDATE", "fleet.device_authorization", "NEW.viewed_by IS NOT NULL", func() {
		if response := h.lookup(owner, d.authorization.GetUserCode()); !undoneCommit(response.GetError()) {
			t.Fatalf("a lost review: %+v", response.GetError())
		}
	})
	if counted() != 1 {
		t.Fatalf("an unanswered review's commit gave its unit back: %d", counted())
	}
}

// TestARefusedAuditUndoesTheDeviceApprovalAndTheReuse (E1-16, audit before effect): with the approval's event refused the approval is
// not made and its evidence is not consumed; with the reuse's event refused the reuse revokes nothing; once the trigger is dropped both
// happen, and the audit chain verifies.
func TestARefusedAuditUndoesTheDeviceApprovalAndTheReuse(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	d, _ := h.start()
	h.db.Exec(`CREATE FUNCTION audit.refuse_device() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.event_type IN ('fleet.device_authorization.approved', 'fleet.device_authorization.code_reused') THEN RAISE EXCEPTION 'refused by the test'; END IF;
    RETURN NEW;
END;
$$`, "CREATE TRIGGER refuse_device BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION audit.refuse_device()")
	code := d.authorization.GetUserCode()
	if looked := h.lookup(owner, code); looked.GetError() != nil {
		t.Fatal(failure(looked.GetError()))
	}
	h.stepUpCode(owner, code, false)
	if response := h.decideDevice(owner.bearer, command(), code, true); response.GetError() == nil {
		t.Fatal("an approval without its audit")
	}
	if h.authorizationState(d) != 1 || h.count("SELECT count(*) FROM identity.step_up_challenge WHERE user_id = $1 AND state = 2", owner.id) != 1 {
		t.Fatal("a refused audit left the approval or consumed the evidence")
	}
	h.db.Exec("DROP TRIGGER refuse_device ON audit.audit_event")
	if response := h.decideDevice(owner.bearer, command(), code, true); response.GetError() != nil {
		t.Fatalf("the approval with its audit: %s", failure(response.GetError()))
	}
	if response := h.poll(d); response.GetValue().GetCredentials() == nil {
		t.Fatal(failure(response.GetError()))
	}
	h.db.Exec("CREATE TRIGGER refuse_device BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION audit.refuse_device()")
	if response := h.poll(d); response.GetError() == nil {
		t.Fatalf("a reuse without its audit: %+v", response.GetValue())
	}
	if h.count("SELECT count(*) FROM identity.session WHERE scope = 3 AND revoked_at IS NULL") != 1 ||
		h.count("SELECT count(*) FROM fleet.device_authorization WHERE reused_at IS NOT NULL") != 0 {
		t.Fatal("a refused audit left the reuse's revocation")
	}
	h.db.Exec("DROP TRIGGER refuse_device ON audit.audit_event")
	if response := h.poll(d); response.GetError() != nil || h.count("SELECT count(*) FROM identity.session WHERE scope = 3 AND revoked_at IS NULL") != 0 {
		t.Fatalf("the reuse with its audit: %s", failure(response.GetError()))
	}
	if _, err := platform.VerifyAudit(context.Background(), h.db.Migration); err != nil {
		t.Fatal(err)
	}
}
