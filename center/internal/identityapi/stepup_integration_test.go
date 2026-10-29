// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
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
// AUTHENTICATION/step_up_required and keeps no receipt; a receipt's replay answers again without new evidence. A challenge begun
// before a credential change and proved after it proves nothing (B10).
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

	// Another class whose target hash names this operation's target: only the class binds it (B14).
	crossedTarget := target()
	crossed := rpc(h, beginStepUpPath, &publicapiv1.IdentityServiceBeginStepUpRequest{Meta: meta(), OperationClass: proto.String(identity.ClassRevokeAllSessions),
		Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(), TargetHash: proto.String(identity.TargetHash(identity.ClassRevokeSession, who.id, crossedTarget))},
		from, &publicapiv1.IdentityServiceBeginStepUpResponse{})
	if crossed.GetError() != nil || h.completeStepUp(who, from, crossed.GetValue().GetChallenge()).GetError() != nil {
		t.Fatalf("a step-up of another class with this target's hash: %s", failure(crossed.GetError()))
	}
	refused("another class with this target's hash", command(), from, crossedTarget)

	// Older than five minutes.
	sixth := target()
	h.stepUp(who, from, identity.ClassRevokeSession, sixth)
	h.clock.Advance(5*time.Minute + time.Second)
	refused("evidence older than five minutes", command(), from, sixth)

	// Spent by a credential change: removing a credential moves the authentication epoch of the account's live sessions. An upgrade
	// begun before the change cannot be proved after it either (B10): the proof checks the epoch, and the upgrade is its only use.
	seventh := target()
	h.stepUp(who, from, identity.ClassRevokeSession, seventh)
	limited := h.issue(who.id, session.ScopeMobileLimited, false)
	upgrade := rpc(h, beginStepUpPath, &publicapiv1.IdentityServiceBeginStepUpRequest{Meta: meta(), OperationClass: proto.String(access.UpgradeClass),
		Method: publicapiv1.AuthMethod_AUTH_METHOD_EMAIL.Enum(), TargetHash: proto.String(identity.TargetHash(access.UpgradeClass, who.id, limited.sessionID))},
		bearer(limited.access), &publicapiv1.IdentityServiceBeginStepUpResponse{})
	if upgrade.GetError() != nil {
		t.Fatalf("begin an e-mail upgrade: %s", failure(upgrade.GetError()))
	}
	code := h.lastCode(who.email)
	email := h.credentialIDs(who.id)[1]
	h.stepUp(who, from, identity.ClassRemoveCredential, email)
	removed := rpc(h, removeCredentialPath, &publicapiv1.IdentityServiceRemoveAuthIdentityRequest{Meta: command(), CredentialId: idOf(email)}, from,
		&publicapiv1.IdentityServiceRemoveAuthIdentityResponse{})
	expect(t, "the removal of the e-mail credential", removed.GetError(), "")
	refused("evidence from before a credential change", command(), from, seventh)
	late := rpc(h, completeStepUpPath, &publicapiv1.IdentityServiceCompleteStepUpRequest{Meta: meta(), FlowId: upgrade.GetValue().GetChallenge().GetFlowId(),
		Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_EmailCode{EmailCode: code}}}, bearer(limited.access),
		&publicapiv1.IdentityServiceCompleteStepUpResponse{})
	expect(t, "an upgrade begun before a credential change, proved after it", late.GetError(), "STATE/expired")
	if h.count("SELECT scope FROM identity.session WHERE session_id = $1", limited.sessionID) != int(session.ScopeMobileLimited) ||
		h.count("SELECT count(*) FROM identity.step_up_challenge WHERE session_id = $1 AND state <> 1", limited.sessionID) != 0 {
		t.Fatal("an upgrade begun before a credential change upgraded the session or was proved")
	}

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

// TestAnotherAccountsPasskeyProvesNoStepUp (B9): a step-up passkey must be the account's own. Another account's passkey is refused
// as a wrong proof (counted in the account's failure bucket, audited, the challenge denied) on the upgrade of a mobile.limited
// session (T-19's bound) and on an account session's class.
func TestAnotherAccountsPasskeyProvesNoStepUp(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	victim, attacker := h.seedAccount(1, ""), h.seedAccount(1, "")
	bucket := sha256.Sum256([]byte("sign_in_failures_account\x00account:" + victim.id.String()))
	failures := func() int {
		return h.count("SELECT coalesce(sum(count), 0)::int FROM platform.rate_limit WHERE bucket_hash = $1", bucket[:])
	}
	phone := h.issue(victim.id, session.ScopeMobileLimited, false)
	begun := h.beginStepUp(victim, bearer(phone.access), access.UpgradeClass, phone.sessionID)
	expect(t, "begin the upgrade", begun.GetError(), "")
	challenge := begun.GetValue().GetChallenge()
	audits, counted := h.audits("identity.step_up.failed"), failures()
	expect(t, "the upgrade with another account's passkey", h.completeStepUp(attacker, bearer(phone.access), challenge).GetError(),
		"AUTHENTICATION/unauthenticated")
	if h.count("SELECT scope FROM identity.session WHERE session_id = $1", phone.sessionID) != int(session.ScopeMobileLimited) ||
		h.audits("identity.step_up.failed") != audits+1 || failures() != counted+1 ||
		h.count("SELECT state FROM identity.step_up_challenge WHERE challenge_id = $1", idFrom(challenge.GetFlowId())) != 5 {
		t.Fatal("another account's passkey upgraded the session, or the failure was not counted, audited and the challenge denied")
	}
	expect(t, "the owner's passkey on the denied challenge", h.completeStepUp(victim, bearer(phone.access), challenge).GetError(), "STATE/expired")
	from := bearer(h.signIn(victim, newClaim(t), caller{}).GetAccessToken())
	target := h.issue(victim.id, session.ScopeAccount, false).sessionID
	other := h.beginStepUp(victim, from, identity.ClassRevokeSession, target).GetValue().GetChallenge()
	expect(t, "an account session's step-up with another account's passkey", h.completeStepUp(attacker, from, other).GetError(),
		"AUTHENTICATION/unauthenticated")
	expect(t, "the revocation without evidence", h.revokeSession(from, command(), target).GetError(), "AUTHENTICATION/step_up_required")
	h.verifyAudit()
}

// stepUpByCode begins an e-mail step-up of RevokeSession of a target and returns its challenge and the code the Fake delivered.
func (h *harness) stepUpByCode(who account, from caller, target platform.ID) (*publicapiv1.AuthChallenge, string) {
	h.t.Helper()
	begun := rpc(h, beginStepUpPath, &publicapiv1.IdentityServiceBeginStepUpRequest{Meta: meta(), OperationClass: proto.String(identity.ClassRevokeSession),
		Method: publicapiv1.AuthMethod_AUTH_METHOD_EMAIL.Enum(), TargetHash: proto.String(identity.TargetHash(identity.ClassRevokeSession, who.id, target))},
		from, &publicapiv1.IdentityServiceBeginStepUpResponse{})
	if begun.GetError() != nil {
		h.t.Fatalf("begin an e-mail step-up: %s", failure(begun.GetError()))
	}
	return begun.GetValue().GetChallenge(), h.lastCode(who.email)
}

// proveByCode completes an e-mail step-up challenge with a code.
func (h *harness) proveByCode(from caller, challenge *publicapiv1.AuthChallenge, code string) *foundationv1.ArcError {
	return rpc(h, completeStepUpPath, &publicapiv1.IdentityServiceCompleteStepUpRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
		Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_EmailCode{EmailCode: code}}}, from, &publicapiv1.IdentityServiceCompleteStepUpResponse{}).GetError()
}

// TestTheStepUpLimitsHold (B12): BeginStepUp counts in the account's step_up_account bucket and a refused begin writes no
// challenge; a wrong proof counts as a failure of the account, so the right code at the limit is refused before it takes an
// attempt; concurrent wrong proofs over many challenges reach the check exactly the limit's number of times (Reserve); concurrent
// wrong proofs on one challenge reach it at most its attempts.
func TestTheStepUpLimitsHold(t *testing.T) {
	t.Run("the begin bucket", func(t *testing.T) {
		h := newHarness(t, settings{policy: `{"stepUpPerAccountLimit": 2, "signInFailuresAccountLimit": 1000, "signInPerPrefixLimit": 1000}`})
		who := h.seedAccount(1, "")
		from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
		target := h.issue(who.id, session.ScopeAccount, false).sessionID
		for range 2 {
			expect(t, "a begin within the limit", h.beginStepUp(who, from, identity.ClassRevokeSession, target).GetError(), "")
		}
		refusal := h.beginStepUp(who, from, identity.ClassRevokeSession, target).GetError()
		if failure(refusal) != "RESOURCE/rate_limited" || refusal.GetDetails().GetLimit().GetLimitName() != "step_up_account" ||
			refusal.GetDetails().GetLimit().GetMaximum().GetValue() != "2" || h.count("SELECT count(*) FROM identity.step_up_challenge") != 2 {
			t.Fatalf("a begin over the limit: %v", refusal)
		}
	})
	limited := `{"stepUpPerAccountLimit": 1000, "signInFailuresAccountLimit": 2, "signInPerPrefixLimit": 1000}`
	t.Run("wrong proofs count", func(t *testing.T) {
		h := newHarness(t, settings{policy: limited})
		who := h.seedAccount(1, "b12.wrong@example.org")
		h.remember(who.email)
		from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
		challenge, code := h.stepUpByCode(who, from, h.issue(who.id, session.ScopeAccount, false).sessionID)
		for range 2 {
			expect(t, "a wrong code", h.proveByCode(from, challenge, "BCDF-GHJK"), "AUTHENTICATION/unauthenticated")
		}
		refusal := h.proveByCode(from, challenge, code)
		if failure(refusal) != "RESOURCE/rate_limited" || refusal.GetDetails().GetLimit().GetLimitName() != "sign_in_failures_account" ||
			h.count("SELECT attempt_count FROM identity.step_up_challenge WHERE challenge_id = $1", idFrom(challenge.GetFlowId())) != 2 {
			t.Fatalf("the right code at the limit: %v", refusal)
		}
	})
	t.Run("concurrent wrong proofs over many challenges", func(t *testing.T) {
		h := newHarness(t, settings{policy: limited})
		who := h.seedAccount(1, "b12.race@example.org")
		h.remember(who.email)
		from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
		target := h.issue(who.id, session.ScopeAccount, false).sessionID
		challenges := make([]*publicapiv1.AuthChallenge, 8)
		for index := range challenges {
			challenges[index], _ = h.stepUpByCode(who, from, target)
		}
		results := make([]string, len(challenges))
		var wait sync.WaitGroup
		for index := range challenges {
			wait.Go(func() { results[index] = failure(h.proveByCode(from, challenges[index], "BCDF-GHJK")) })
		}
		wait.Wait()
		outcomes := map[string]int{}
		for _, result := range results {
			outcomes[result]++
		}
		if outcomes["AUTHENTICATION/unauthenticated"] != 2 || outcomes["RESOURCE/rate_limited"] != 6 ||
			h.count("SELECT coalesce(sum(attempt_count), 0)::int FROM identity.step_up_challenge") != 2 {
			t.Fatalf("outcomes %v", outcomes)
		}
	})
	t.Run("concurrent wrong proofs on one challenge", func(t *testing.T) {
		h := newHarness(t, settings{policy: `{"stepUpPerAccountLimit": 1000, "signInFailuresAccountLimit": 1000, "signInPerPrefixLimit": 1000,
"emailCodeAttempts": 2}`})
		who := h.seedAccount(1, "b12.one@example.org")
		h.remember(who.email)
		from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
		challenge, code := h.stepUpByCode(who, from, h.issue(who.id, session.ScopeAccount, false).sessionID)
		results := make([]string, 8)
		var wait sync.WaitGroup
		for index := range results {
			wait.Go(func() { results[index] = failure(h.proveByCode(from, challenge, "BCDF-GHJK")) })
		}
		wait.Wait()
		outcomes := map[string]int{}
		for _, result := range results {
			outcomes[result]++
		}
		if outcomes["AUTHENTICATION/unauthenticated"] != 2 || outcomes["STATE/expired"] != 6 {
			t.Fatalf("outcomes %v", outcomes)
		}
		expect(t, "the right code after the attempts", h.proveByCode(from, challenge, code), "STATE/expired")
		if h.count("SELECT state FROM identity.step_up_challenge WHERE challenge_id = $1", idFrom(challenge.GetFlowId())) != 5 {
			t.Fatal("the exhausted challenge was not denied")
		}
	})
}

// TestTheStepUpPasskeyCounterAdvances (B13, F14): a proved passkey step-up stores the assertion's counter, and a later equal or
// lower counter is a failed proof (counted, nothing proved, the counter kept), checked again under the credential's row lock when a
// concurrent use advanced it after the library accepted the assertion.
func TestTheStepUpPasskeyCounterAdvances(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	limits := func() int { return h.count("SELECT coalesce(sum(count), 0)::int FROM platform.rate_limit") }
	stored := func(who account) int {
		return h.count("SELECT sign_count FROM identity.auth_identity WHERE user_id = $1 AND provider_id = 'passkey'", who.id)
	}
	prove := func(from caller, challenge *publicapiv1.AuthChallenge, assertion *publicapiv1.WebAuthnAssertion) string {
		return failure(rpc(h, completeStepUpPath, &publicapiv1.IdentityServiceCompleteStepUpRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
			Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertion}}}, from, &publicapiv1.IdentityServiceCompleteStepUpResponse{}).GetError())
	}
	t.Run("in order", func(t *testing.T) {
		who := h.seedAccount(1, "")
		from := bearer(h.signIn(who, newClaim(t), caller{ip: "198.51.100.30"}).GetAccessToken())
		target := h.issue(who.id, session.ScopeAccount, false).sessionID
		challenge := h.beginStepUp(who, from, identity.ClassRevokeSession, target).GetValue().GetChallenge()
		if result := prove(from, challenge, assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge(), 9))); result != "" || stored(who) != 9 {
			t.Fatalf("a step-up with counter 9: %q, stored %d", result, stored(who))
		}
		for _, counter := range []uint32{9, 8} {
			before := limits()
			challenge = h.beginStepUp(who, from, identity.ClassRevokeSession, target).GetValue().GetChallenge()
			result := prove(from, challenge, assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge(), counter)))
			if result != "AUTHENTICATION/unauthenticated" || limits() <= before || stored(who) != 9 {
				t.Fatalf("counter %d: %q, stored %d", counter, result, stored(who))
			}
		}
	})
	for index, item := range []struct {
		name                       string
		stored, assertion, current uint32
	}{
		{"under the row lock, an equal counter", 3, 5, 5},
		{"under the row lock, a lower counter", 3, 4, 6},
		{"under the row lock, zero after a nonzero counter", 0, 0, 5},
	} {
		t.Run(item.name, func(t *testing.T) {
			who := h.seedAccount(1, "")
			from := bearer(h.signIn(who, newClaim(t), caller{ip: fmt.Sprintf("198.51.%d.20", index+1)}).GetAccessToken())
			target := h.issue(who.id, session.ScopeAccount, false).sessionID
			h.exec(fmt.Sprintf("UPDATE identity.auth_identity SET sign_count = %d WHERE user_id = '%s' AND provider_id = 'passkey'", item.stored, who.id))
			challenge := h.beginStepUp(who, from, identity.ClassRevokeSession, target).GetValue().GetChallenge()
			assertion := assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge(), item.assertion))
			before, proved := limits(), h.audits("identity.step_up.proved")
			lock := h.holding("UPDATE identity.auth_identity SET sign_count = $2, rev = rev + 1 WHERE user_id = $1 AND provider_id = 'passkey'",
				who.id, int64(item.current))
			done := make(chan string, 1)
			go func() { done <- prove(from, challenge, assertion) }()
			waited := lock.waitFor(1)
			lock.release(true)
			result := <-done
			if !waited {
				t.Fatalf("the step-up never waited on the credential's row (%s)", result)
			}
			if result != "AUTHENTICATION/unauthenticated" || limits() <= before || h.audits("identity.step_up.proved") != proved ||
				stored(who) != int(item.current) || h.count("SELECT count(*) FROM identity.step_up_challenge WHERE user_id = $1 AND state IN (2, 3)", who.id) != 0 {
				t.Fatalf("result %s, stored %d", result, stored(who))
			}
		})
	}
	h.verifyAudit()
}
