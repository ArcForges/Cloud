// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"bytes"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"

	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// TestRevocationReachesEachCredentialKindOfItsTarget (F10, DC-03, DC-17): RevokeSession revokes an account session whatever its
// credential (bearer, cookie, mobile.limited) and finds no node or push session; RevokeAllSessions revokes every account session
// but the caller's and leaves node and push sessions; DeviceService.Revoke revokes the device, its installations, every session on
// it whatever its scope and each participant's rows in one transaction, after which each of its credentials is refused at the
// transport (auth.credential_revoked) and on refresh.
func TestRevocationReachesEachCredentialKindOfItsTarget(t *testing.T) {
	participant := &participant{}
	h := newHarness(t, settings{policy: writePolicy, participants: []device.Participant{participant}})
	who := h.seedAccount(1, "")
	native := h.signIn(who, newClaim(t), caller{})
	from := bearer(native.GetAccessToken())

	for _, kind := range []struct {
		name       string
		credential issued
		found      bool
	}{
		{"an account bearer", h.issue(who.id, session.ScopeAccount, false), true},
		{"a cookie", h.issue(who.id, session.ScopeAccount, true), true},
		{"a mobile.limited bearer", h.issue(who.id, session.ScopeMobileLimited, false), true},
		{"a node credential", h.issue(who.id, session.ScopeNode, false), false},
		{"a push credential", h.issue(who.id, session.ScopePush, false), false},
	} {
		h.stepUp(who, from, identity.ClassRevokeSession, kind.credential.sessionID)
		refusal := h.revokeSession(from, command(), kind.credential.sessionID).GetError()
		if kind.found {
			if refusal != nil || h.live(kind.credential.sessionID) {
				t.Errorf("RevokeSession of %s: %s", kind.name, failure(refusal))
			}
			continue
		}
		if got, id := resourceOf(refusal); failure(refusal) != "STATE/not_found" || got != "session" || !bytes.Equal(id, kind.credential.sessionID[:]) ||
			!h.live(kind.credential.sessionID) {
			t.Errorf("RevokeSession of %s: %v", kind.name, refusal)
		}
	}

	account, cookie := h.issue(who.id, session.ScopeAccount, false), h.issue(who.id, session.ScopeAccount, true)
	limited, node, push := h.issue(who.id, session.ScopeMobileLimited, false), h.issue(who.id, session.ScopeNode, false), h.issue(who.id, session.ScopePush, false)
	h.stepUp(who, from, identity.ClassRevokeAllSessions, who.id)
	all := rpc(h, revokeAllPath, &publicapiv1.IdentityServiceRevokeAllSessionsRequest{Meta: command()}, from, &publicapiv1.IdentityServiceRevokeAllSessionsResponse{})
	if all.GetError() != nil || all.GetValue().GetReceipt().GetResultRevision() != nil {
		t.Fatalf("RevokeAllSessions: %v", all)
	}
	for name, credential := range map[string]issued{"account": account, "cookie": cookie, "mobile.limited": limited} {
		if h.live(credential.sessionID) {
			t.Errorf("RevokeAllSessions left the %s session", name)
		}
	}
	if !h.live(sessionIDOf(native)) || !h.live(node.sessionID) || !h.live(push.sessionID) {
		t.Fatal("RevokeAllSessions revoked the caller's own, a node or a push session")
	}

	// One device carrying an account, a mobile.limited, a node and a push session.
	other := h.signIn(who, newClaim(t), caller{})
	target := h.deviceOf(sessionIDOf(other))
	onDevice := []issued{h.issueOn(who.id, target, session.ScopeMobileLimited), h.issueOn(who.id, target, session.ScopeNode),
		h.issueOn(who.id, target, session.ScopePush)}
	nodeOnDevice := onDevice[1]
	// Before: the node credential is authenticated but not admitted to an account method.
	if refusal := domainError(t, h.post(profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, bearer(nodeOnDevice.access))); failure(refusal) != "AUTHORIZATION/permission_denied" {
		t.Fatalf("a node credential before the revocation: %v", refusal)
	}
	revoke := func(meta *foundationv1.RequestMeta, deviceID platform.ID) *publicapiv1.DeviceServiceRevokeResponse {
		return rpc(h, revokeDevicePath, &publicapiv1.DeviceServiceRevokeRequest{Meta: meta, DeviceId: idOf(deviceID)}, from, &publicapiv1.DeviceServiceRevokeResponse{})
	}
	expect(t, "a device revocation without evidence", revoke(command(), target).GetError(), "AUTHENTICATION/step_up_required")
	h.stepUp(who, from, identity.ClassRevokeDevice, target)
	// A participant that fails rolls the whole revocation back and keeps no receipt; the same command then succeeds.
	participant.failing(true)
	once, receipts := command(), h.receipts()
	expect(t, "a revocation whose participant failed", revoke(once, target).GetError(), "INTERNAL/internal")
	if h.count("SELECT count(*) FROM device.device WHERE device_id = $1 AND revoked_at IS NULL", target) != 1 || h.receipts() != receipts ||
		!h.live(nodeOnDevice.sessionID) {
		t.Fatal("a failed participant left a partial revocation")
	}
	participant.failing(false)
	revoked := revoke(once, target)
	if revoked.GetError() != nil || revoked.GetValue().GetReceipt().GetResultRevision().GetValue() < 2 {
		t.Fatalf("the device revocation: %v", revoked)
	}
	if called := participant.called(); len(called) != 1 || called[0] != target {
		t.Fatalf("the participant saw %v", called)
	}
	if h.count("SELECT count(*) FROM device.installation WHERE device_id = $1 AND revoked_at IS NULL", target) != 0 ||
		h.count("SELECT count(*) FROM identity.session WHERE device_id = $1 AND revoked_at IS NULL", target) != 0 || h.audits("device.revoked") != 1 {
		t.Fatal("the device revocation left an installation or a session, or was not audited")
	}
	if answer := h.post(profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, bearer(nodeOnDevice.access)); answer.status != "16" ||
		answer.message != "auth.credential_revoked" {
		t.Fatalf("the node credential after the revocation: %+v", answer)
	}
	for _, credential := range onDevice {
		expect(t, "a refresh on the revoked device", h.refreshOf(credential), "AUTHENTICATION/credential_revoked")
	}
	if answer := h.post(profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, bearer(other.GetAccessToken())); answer.status != "16" {
		t.Fatalf("the account session on the revoked device: %+v", answer)
	}
	// A revoked device is not found again; the replay of the same command answers its receipt.
	h.stepUp(who, from, identity.ClassRevokeDevice, target)
	if got, id := resourceOf(revoke(command(), target).GetError()); got != "device" || !bytes.Equal(id, target[:]) {
		t.Fatal("a revoked device is found again")
	}
	if replay := revoke(once, target); replay.GetError() != nil || replay.GetValue().GetReceipt().GetResultRevision().GetValue() !=
		revoked.GetValue().GetReceipt().GetResultRevision().GetValue() || h.audits("device.revoked") != 1 {
		t.Fatalf("the replay: %v", replay)
	}

	// The caller's own device needs no evidence, and its revocation signs the caller out.
	own := h.deviceOf(sessionIDOf(native))
	expect(t, "revoking the caller's own device", revoke(command(), own).GetError(), "")
	if h.live(sessionIDOf(native)) {
		t.Fatal("revoking the caller's own device left its session")
	}
	h.verifyAudit()
}

// TestARefusedAuditRefusesTheWrites (F5): a credential removal and a device revocation whose audit event cannot be written are
// refused with nothing written: the credential and the device stay, the step-up evidence stays unconsumed and no receipt is kept.
// Once the audit works again the same commands succeed without a new step-up, and the chain verifies.
func TestARefusedAuditRefusesTheWrites(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1, "audit@example.org")
	h.remember(who.email)
	from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
	target := h.deviceOf(sessionIDOf(h.signIn(who, newClaim(t), caller{})))
	email := h.credentialIDs(who.id)[1]
	h.stepUp(who, from, identity.ClassRemoveCredential, email)
	h.stepUp(who, from, identity.ClassRevokeDevice, target)
	removal, revocation := command(), command()
	remove := func() *foundationv1.ArcError {
		return rpc(h, removeCredentialPath, &publicapiv1.IdentityServiceRemoveAuthIdentityRequest{Meta: removal, CredentialId: idOf(email)}, from,
			&publicapiv1.IdentityServiceRemoveAuthIdentityResponse{}).GetError()
	}
	revoke := func() *foundationv1.ArcError {
		return rpc(h, revokeDevicePath, &publicapiv1.DeviceServiceRevokeRequest{Meta: revocation, DeviceId: idOf(target)}, from,
			&publicapiv1.DeviceServiceRevokeResponse{}).GetError()
	}
	h.exec("CREATE SCHEMA testfault",
		"CREATE FUNCTION testfault.refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit refused by the test'; END; $$",
		"CREATE TRIGGER test_refuse_audit BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION testfault.refuse()")
	before, receipts := h.writes(), h.receipts()
	expect(t, "a removal without its audit", remove(), "INTERNAL/internal")
	expect(t, "a revocation without its audit", revoke(), "INTERNAL/internal")
	if h.writes() != before || h.receipts() != receipts || len(h.credentialIDs(who.id)) != 2 ||
		h.count("SELECT count(*) FROM identity.step_up_challenge WHERE user_id = $1 AND state = 2", who.id) != 2 {
		t.Fatal("a write without its audit changed something")
	}
	h.exec("DROP TRIGGER test_refuse_audit ON audit.audit_event")
	// The revocation first: the removal moves the authentication epoch, which spends any evidence proved before it.
	expect(t, "the same revocation once the audit works", revoke(), "")
	expect(t, "the same removal once the audit works", remove(), "")
	if len(h.credentialIDs(who.id)) != 1 || h.audits("identity.credential.removed") != 1 || h.audits("device.revoked") != 1 {
		t.Fatal("the writes after the audit works again")
	}
	h.verifyAudit()
}
