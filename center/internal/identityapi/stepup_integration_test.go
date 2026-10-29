// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"bytes"
	"sync"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// TestMobileLimitedNeedsStepUp (T-19) is driven by the operation table: every method whose mobile.limited rule is not Allowed is
// called with a mobile.limited session on a target that is not its own and answers AUTHENTICATION/step_up_required (retry the
// same command) without writing anything or keeping a receipt. A row without a request here fails the test, so a new row cannot
// be left unchecked. The session's own session and device stay open to it (sign-out and removing this phone, A-09), and the
// upgrade class turns it into an account session.
func TestMobileLimitedNeedsStepUp(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1, "")
	limited := h.issue(who.id, session.ScopeMobileLimited, false)
	other := h.issue(who.id, session.ScopeAccount, false)
	credential := h.credentialIDs(who.id)[0]
	requests := map[string]proto.Message{
		updateProfilePath: &publicapiv1.IdentityServiceUpdateProfileRequest{Meta: command(), Patch: &publicapiv1.ProfileUpdate{
			DisplayName: proto.String("Limited")}},
		beginRegisterPath: &publicapiv1.IdentityServiceBeginPasskeyRegistrationRequest{Meta: meta(), DisplayName: proto.String("Phone")},
		completeRegisterPath: &publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest{Meta: command(), FlowId: idOf(platform.NewID()),
			Credential: &publicapiv1.WebAuthnCreation{}},
		renameCredentialPath: &publicapiv1.IdentityServiceRenameAuthIdentityRequest{Meta: command(), CredentialId: idOf(credential),
			Name: proto.String("Renamed")},
		removeCredentialPath: &publicapiv1.IdentityServiceRemoveAuthIdentityRequest{Meta: command(), CredentialId: idOf(credential)},
		revokeSessionPath:    &publicapiv1.IdentityServiceRevokeSessionRequest{Meta: command(), SessionId: idOf(other.sessionID)},
		revokeAllPath:        &publicapiv1.IdentityServiceRevokeAllSessionsRequest{Meta: command()},
		renameDevicePath: &publicapiv1.DeviceServiceRenameRequest{Meta: command(), DeviceId: idOf(h.deviceOf(other.sessionID)),
			Name: proto.String("Renamed")},
		revokeDevicePath: &publicapiv1.DeviceServiceRevokeRequest{Meta: command(), DeviceId: idOf(h.deviceOf(other.sessionID))},
	}
	checked := 0
	for _, operation := range access.Operations() {
		if !operation.Session || operation.MobileLimited == access.Allowed {
			continue
		}
		request, ok := requests[operation.Path]
		if !ok {
			t.Errorf("%s needs a step-up of a mobile.limited session, but this test has no request for it", operation.ID)
			continue
		}
		delete(requests, operation.Path)
		before, receipts := h.writes(), h.receipts()
		refusal := domainError(t, h.post(operation.Path, request, bearer(limited.access)))
		if failure(refusal) != "AUTHENTICATION/step_up_required" || refusal.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND ||
			refusal.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
			t.Errorf("%s from a mobile.limited session: %v", operation.ID, refusal)
		}
		if h.writes() != before || h.receipts() != receipts {
			t.Errorf("%s from a mobile.limited session wrote or kept a receipt", operation.ID)
		}
		checked++
	}
	for path := range requests {
		t.Errorf("%s has a request, but the operation table opens it to mobile.limited", path)
	}
	if checked != 9 {
		t.Fatalf("%d methods need the upgrade, want 9", checked)
	}

	// Its own session and device need neither the upgrade nor evidence.
	expect(t, "a mobile.limited sign-out", h.revokeSession(bearer(limited.access), command(), limited.sessionID).GetError(), "")
	if h.live(limited.sessionID) || h.count("SELECT revoke_reason FROM identity.session WHERE session_id = $1", limited.sessionID) != int(session.RevokedSignedOut) {
		t.Fatal("the sign-out did not end the session as signed out")
	}
	phone := h.issue(who.id, session.ScopeMobileLimited, false)
	removed := rpc(h, revokeDevicePath, &publicapiv1.DeviceServiceRevokeRequest{Meta: command(), DeviceId: idOf(h.deviceOf(phone.sessionID))},
		bearer(phone.access), &publicapiv1.DeviceServiceRevokeResponse{})
	expect(t, "removing its own phone", removed.GetError(), "")
	if h.live(phone.sessionID) {
		t.Fatal("removing the phone left its session live")
	}

	// The upgrade class: only a mobile.limited session may use it, only for itself; proving it makes the session an account session.
	upgrade := func(from issued, target platform.ID) *foundationv1.ArcError {
		return h.beginStepUp(who, bearer(from.access), access.UpgradeClass, target).GetError()
	}
	expect(t, "the upgrade class of an account session", upgrade(other, other.sessionID), "VALIDATION/invalid_argument")
	third := h.issue(who.id, session.ScopeMobileLimited, false)
	refusal := upgrade(third, other.sessionID)
	if failure(refusal) != "VALIDATION/invalid_argument" || refusal.GetDetails().GetState().GetReason() != "target_hash: not_the_session" {
		t.Fatalf("the upgrade of another session: %v", refusal)
	}
	evidence := h.stepUp(who, bearer(third.access), access.UpgradeClass, third.sessionID)
	if evidence.GetOperationClass() != access.UpgradeClass ||
		h.count("SELECT scope FROM identity.session WHERE session_id = $1", third.sessionID) != int(session.ScopeAccount) ||
		h.count("SELECT count(*) FROM identity.step_up_challenge WHERE session_id = $1 AND state = 3", third.sessionID) != 1 {
		t.Fatal("the upgrade did not make the session an account session, or left its evidence unconsumed")
	}
	updated := rpc(h, updateProfilePath, &publicapiv1.IdentityServiceUpdateProfileRequest{Meta: command(), Patch: &publicapiv1.ProfileUpdate{
		DisplayName: proto.String("Upgraded")}}, bearer(third.access), &publicapiv1.IdentityServiceUpdateProfileResponse{})
	if updated.GetError() != nil || updated.GetValue().GetProfile().GetDisplayName() != "Upgraded" {
		t.Fatalf("UpdateProfile after the upgrade: %s", failure(updated.GetError()))
	}
	h.verifyAudit()
}

// TestStepUpEvidenceIsSingleUse (DC-01, SEC-02): evidence is one proved challenge of one session for one class and one target,
// consumed by the call's own transaction within five minutes and in the session's current epochs. Each case below is refused with
// AUTHENTICATION/step_up_required and keeps no receipt; a receipt's replay answers again without new evidence.
func TestStepUpEvidenceIsSingleUse(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1, "single.use@example.org")
	h.remember(who.email)
	native := h.signIn(who, newClaim(t), caller{})
	from := bearer(native.GetAccessToken())
	second := h.signIn(who, newClaim(t), caller{})
	target := func() platform.ID { return h.issue(who.id, session.ScopeAccount, false).sessionID }
	refused := func(what string, meta *foundationv1.RequestMeta, from caller, sessionID platform.ID) {
		t.Helper()
		receipts := h.receipts()
		expect(t, what, h.revokeSession(from, meta, sessionID).GetError(), "AUTHENTICATION/step_up_required")
		if !h.live(sessionID) || h.receipts() != receipts {
			t.Fatalf("%s: the refused call revoked or kept a receipt", what)
		}
	}

	// Once.
	first := target()
	h.stepUp(who, from, identity.ClassRevokeSession, first)
	once := command()
	revoked := h.revokeSession(from, once, first)
	expect(t, "the first use", revoked.GetError(), "")
	if h.live(first) || revoked.GetValue().GetReceipt().GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED ||
		!bytes.Equal(revoked.GetValue().GetReceipt().GetCommandId().GetValue(), once.GetCommandId().GetValue()) {
		t.Fatalf("the first use: %v", revoked.GetValue())
	}
	expect(t, "the second use", h.revokeSession(from, command(), first).GetError(), "AUTHENTICATION/step_up_required")

	// The receipt answers the same command again, without evidence and without a second effect.
	audits := h.audits("identity.session.revoked")
	replayed := h.revokeSession(from, once, first)
	if replayed.GetError() != nil || !proto.Equal(replayed.GetValue(), revoked.GetValue()) || h.audits("identity.session.revoked") != audits {
		t.Fatalf("the replay: %v", replayed)
	}
	expect(t, "the command ID with another request", h.revokeSession(from, once, target()).GetError(), "CONFLICT/command_id_reused")

	// Another target, then the evidence's own target.
	proved, elsewhere := target(), target()
	h.stepUp(who, from, identity.ClassRevokeSession, proved)
	refused("another target", command(), from, elsewhere)
	expect(t, "the evidence's own target after the refusal", h.revokeSession(from, command(), proved).GetError(), "")

	// Another session of the account.
	fourth := target()
	h.stepUp(who, bearer(second.GetAccessToken()), identity.ClassRevokeSession, fourth)
	refused("another session's evidence", command(), from, fourth)

	// Another class, proved by e-mail.
	fifth := target()
	h.stepUpByEmail(who, from, identity.ClassRevokeAllSessions, who.id)
	refused("another class", command(), from, fifth)

	// Older than five minutes.
	sixth := target()
	h.stepUp(who, from, identity.ClassRevokeSession, sixth)
	h.clock.Advance(5*time.Minute + time.Second)
	refused("evidence older than five minutes", command(), from, sixth)

	// Spent by a credential change: removing a credential moves the authentication epoch of the account's live sessions.
	seventh := target()
	h.stepUp(who, from, identity.ClassRevokeSession, seventh)
	email := h.credentialIDs(who.id)[1]
	h.stepUp(who, from, identity.ClassRemoveCredential, email)
	removed := rpc(h, removeCredentialPath, &publicapiv1.IdentityServiceRemoveAuthIdentityRequest{Meta: command(), CredentialId: idOf(email)}, from,
		&publicapiv1.IdentityServiceRemoveAuthIdentityResponse{})
	expect(t, "the removal of the e-mail credential", removed.GetError(), "")
	refused("evidence from before a credential change", command(), from, seventh)

	// Two concurrent uses of one proof: one consumes it, the other is refused.
	eighth := target()
	h.stepUp(who, from, identity.ClassRevokeSession, eighth)
	results := make([]string, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Go(func() { results[index] = failure(h.revokeSession(from, command(), eighth).GetError()) })
	}
	wait.Wait()
	if !(results[0] == "" && results[1] == "AUTHENTICATION/step_up_required" || results[1] == "" && results[0] == "AUTHENTICATION/step_up_required") ||
		h.live(eighth) {
		t.Fatalf("two concurrent uses of one proof: %q", results)
	}
	h.verifyAudit()
}

// TestAStepUpChallengeBindsItsMethodSessionAndProof: a wrong proof is a counted failure; the challenge ends after its attempts; a
// proved challenge cannot be proved again; another session's challenge is not found.
func TestAStepUpChallengeBindsItsMethodSessionAndProof(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1, "binds@example.org")
	h.remember(who.email)
	native := h.signIn(who, newClaim(t), caller{})
	from := bearer(native.GetAccessToken())
	other := h.signIn(who, newClaim(t), caller{})
	target := h.issue(who.id, session.ScopeAccount, false).sessionID
	complete := func(from caller, challenge *publicapiv1.AuthChallenge, code string) *foundationv1.ArcError {
		return rpc(h, completeStepUpPath, &publicapiv1.IdentityServiceCompleteStepUpRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
			Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_EmailCode{EmailCode: code}}}, from,
			&publicapiv1.IdentityServiceCompleteStepUpResponse{}).GetError()
	}
	begun := rpc(h, beginStepUpPath, &publicapiv1.IdentityServiceBeginStepUpRequest{Meta: meta(), OperationClass: proto.String(identity.ClassRevokeSession),
		Method: publicapiv1.AuthMethod_AUTH_METHOD_EMAIL.Enum(), TargetHash: proto.String(identity.TargetHash(identity.ClassRevokeSession, who.id, target))},
		from, &publicapiv1.IdentityServiceBeginStepUpResponse{}).GetValue().GetChallenge()
	code := h.lastCode(who.email)
	refusal := complete(bearer(other.GetAccessToken()), begun, code)
	if kind, id := resourceOf(refusal); failure(refusal) != "STATE/not_found" || kind != "step_up_challenge" ||
		!bytes.Equal(id, begun.GetFlowId().GetValue()) {
		t.Fatalf("another session's challenge: %v", refusal)
	}
	expect(t, "a passkey proof of an e-mail challenge", h.completeStepUp(who, from, begun).GetError(), "VALIDATION/invalid_argument")
	failures := h.audits("identity.step_up.failed")
	expect(t, "a wrong code", complete(from, begun, "BCDF-GHJK"), "AUTHENTICATION/unauthenticated")
	if h.audits("identity.step_up.failed") != failures+1 {
		t.Fatal("a wrong code was not audited")
	}
	expect(t, "the right code", complete(from, begun, code), "")
	expect(t, "the right code again", complete(from, begun, code), "CONFLICT/code_reused")
	h.verifyAudit()
}

// TestARemovalSpendsTheEvidenceProvedBeforeIt (B3): evidence is consumed under the account's row lock, the lock a credential
// removal moves the authentication epoch under, so a removal whose evidence was proved before a concurrent removal reads the moved
// epoch and is refused with AUTHENTICATION/step_up_required, whether the first removal is parked after its epoch move (at its
// audit) or before it (at its credential's row).
func TestARemovalSpendsTheEvidenceProvedBeforeIt(t *testing.T) {
	for _, parked := range []string{"at its audit", "at its credential"} {
		t.Run(parked, func(t *testing.T) {
			h := newHarness(t, settings{policy: writePolicy})
			who := h.seedAccount(1, "b3@example.org")
			h.remember(who.email)
			h.addPasskey(who)
			from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
			ids := h.credentialIDs(who.id)
			if len(ids) != 3 {
				t.Fatalf("%d credentials", len(ids))
			}
			for _, id := range ids[1:] {
				h.stepUp(who, from, identity.ClassRemoveCredential, id)
			}
			remove := func(id platform.ID) string {
				return failure(rpc(h, removeCredentialPath, &publicapiv1.IdentityServiceRemoveAuthIdentityRequest{Meta: command(), CredentialId: idOf(id)},
					from, &publicapiv1.IdentityServiceRemoveAuthIdentityResponse{}).GetError())
			}
			var lock *hold
			if parked == "at its audit" {
				lock = h.holding("SELECT 1 FROM audit.chain_head WHERE singleton FOR UPDATE")
			} else {
				lock = h.holding("SELECT 1 FROM identity.auth_identity WHERE auth_identity_id = $1 FOR UPDATE", ids[1])
			}
			results := make([]string, 2)
			var wait sync.WaitGroup
			wait.Go(func() { results[0] = remove(ids[1]) })
			if !lock.waitFor(1) {
				t.Fatal("the first removal never reached the hold")
			}
			wait.Go(func() { results[1] = remove(ids[2]) })
			if !lock.waitFor(2) {
				t.Fatal("the second removal never waited behind the first")
			}
			lock.release(false)
			wait.Wait()
			if results[0] != "" || results[1] != "AUTHENTICATION/step_up_required" || len(h.credentialIDs(who.id)) != 2 {
				t.Fatalf("two removals of evidence proved before both: %q, %d live credentials", results, len(h.credentialIDs(who.id)))
			}
			h.verifyAudit()
		})
	}
}
