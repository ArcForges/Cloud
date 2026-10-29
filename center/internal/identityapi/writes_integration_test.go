// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// TestAPasskeyRegistersOnceWithItsLabel: BeginPasskeyRegistration needs the account's evidence and a display name of at most 64
// characters (a longer one, which the contract allows up to 256, is refused with rule length); the new passkey is stored once with
// its label even when two completions of its flow race, signs in, and a replay answers from the receipt. A credential ID that is
// registered already is CONFLICT/already_exists, kept by the receipt.
func TestAPasskeyRegistersOnceWithItsLabel(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1, "")
	from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
	begin := func(label *string) *publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse {
		return rpc(h, beginRegisterPath, &publicapiv1.IdentityServiceBeginPasskeyRegistrationRequest{Meta: meta(), DisplayName: label}, from,
			&publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse{})
	}
	complete := func(meta *foundationv1.RequestMeta, flow *foundationv1.Id, creation *publicapiv1.WebAuthnCreation) *publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse {
		return rpc(h, completeRegisterPath, &publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest{Meta: meta, FlowId: flow, Credential: creation}, from,
			&publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse{})
	}
	expect(t, "a registration without evidence", begin(proto.String("Laptop")).GetError(), "AUTHENTICATION/step_up_required")
	for label, reason := range map[string]string{strings.Repeat("a", 65): "display_name: length", " ": "display_name: pattern"} {
		refusal := begin(proto.String(label)).GetError()
		if failure(refusal) != "VALIDATION/invalid_argument" || refusal.GetDetails().GetState().GetReason() != reason {
			t.Fatalf("the display name %q: %v", label, refusal)
		}
	}
	expect(t, "no display name", begin(nil).GetError(), "VALIDATION/invalid_argument")
	h.stepUp(who, from, identity.ClassBeginRegistration, who.id)
	label := strings.Repeat("é", 64)
	challenge := begin(proto.String(label)).GetValue().GetChallenge()
	if challenge == nil || h.count("SELECT count(*) FROM identity.step_up_challenge WHERE user_id = $1 AND state = 3", who.id) != 1 {
		t.Fatal("the registration did not begin, or did not consume its evidence")
	}
	authenticator := virtual.New(rpID, origin)
	creation, key := authenticator.Create(challenge.GetChallenge(), who.handle)
	commands := []*foundationv1.RequestMeta{command(), command()}
	results := make([]*publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Go(func() { results[index] = complete(commands[index], challenge.GetFlowId(), creationOf(creation)) })
	}
	wait.Wait()
	winner := 0
	if results[0].GetError() != nil {
		winner = 1
	}
	if results[winner].GetError() != nil || results[1-winner].GetError() == nil ||
		h.count("SELECT count(*) FROM identity.auth_identity WHERE subject = $1", base64.RawURLEncoding.EncodeToString(creation.CredentialID)) != 1 {
		t.Fatalf("two completions of one flow: %s / %s", failure(results[0].GetError()), failure(results[1].GetError()))
	}
	registered := results[winner].GetValue().GetCredential()
	if registered.GetDisplayName() != label || registered.GetKind() != "passkey" || h.audits("identity.passkey.registered") != 1 {
		t.Fatalf("the registered credential: %v", registered)
	}
	replayed := complete(commands[winner], challenge.GetFlowId(), creationOf(creation))
	if replayed.GetError() != nil || !proto.Equal(replayed.GetValue(), results[winner].GetValue()) || h.audits("identity.passkey.registered") != 1 {
		t.Fatalf("the replay: %v", replayed)
	}
	// The new passkey signs in.
	h.signIn(account{id: who.id, handle: who.handle, authenticator: authenticator, key: key}, newClaim(t), caller{})

	// A credential ID that is registered already (here, to another account) is refused, and the receipt keeps the refusal.
	h.stepUp(who, from, identity.ClassBeginRegistration, who.id)
	again := begin(proto.String("Second")).GetValue().GetChallenge()
	taken, _ := authenticator.Create(again.GetChallenge(), who.handle)
	other := h.seedAccount(1, "")
	if _, err := h.migration.Exec(context.Background(), `INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, public_key,
    user_handle, sign_count, backup_eligible, backup_state, transports, aaguid, attestation_format, created_at, rev)
SELECT $1, user_id, 1, 'passkey', $2, public_key, user_handle, 0, false, false, '{}', aaguid, 'none', now(), 1
FROM identity.auth_identity WHERE user_id = $3 AND method = 1`, platform.NewID(), base64.RawURLEncoding.EncodeToString(taken.CredentialID), other.id); err != nil {
		t.Fatal(err)
	}
	conflict := command()
	refusal := complete(conflict, again.GetFlowId(), creationOf(taken)).GetError()
	if kind, id := resourceOf(refusal); failure(refusal) != "CONFLICT/already_exists" || kind != "credential" || id != nil {
		t.Fatalf("a credential ID registered already: %v", refusal)
	}
	if replay := complete(conflict, again.GetFlowId(), creationOf(taken)).GetError(); failure(replay) != "CONFLICT/already_exists" {
		t.Fatalf("the replay of the refused command: %v", replay)
	}
	h.verifyAudit()
}

// TestProfileCredentialAndDeviceNamesFollowTheirRevisions: UpdateProfile, RenameAuthIdentity and DeviceService.Rename change only
// at the revision the request expects (CONFLICT/revision_conflict with both revisions otherwise), under a command ID they require.
func TestProfileCredentialAndDeviceNamesFollowTheirRevisions(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1, "")
	native := h.signIn(who, newClaim(t), caller{})
	from := bearer(native.GetAccessToken())
	revision := func(table, column string, id platform.ID) int64 {
		return int64(h.count("SELECT rev FROM "+table+" WHERE "+column+" = $1", id))
	}
	at := func(value int64) *foundationv1.RequestMeta {
		meta := command()
		meta.ExpectedRev = &foundationv1.Revision{Value: proto.Int64(value)}
		return meta
	}
	conflict := func(what string, refusal *foundationv1.ArcError, expected, actual int64) {
		t.Helper()
		details := refusal.GetDetails().GetRevision()
		if failure(refusal) != "CONFLICT/revision_conflict" || details.GetExpected().GetValue() != expected || details.GetActual().GetValue() != actual {
			t.Fatalf("%s: %v", what, refusal)
		}
	}
	profile := func(meta *foundationv1.RequestMeta, patch *publicapiv1.ProfileUpdate) *publicapiv1.IdentityServiceUpdateProfileResponse {
		return rpc(h, updateProfilePath, &publicapiv1.IdentityServiceUpdateProfileRequest{Meta: meta, Patch: patch}, from,
			&publicapiv1.IdentityServiceUpdateProfileResponse{})
	}
	refusal := profile(meta(), &publicapiv1.ProfileUpdate{DisplayName: proto.String("Name")}).GetError()
	if failure(refusal) != "VALIDATION/invalid_argument" || refusal.GetDetails().GetState().GetReason() != "meta.command_id: required" {
		t.Fatalf("a write without a command ID: %v", refusal)
	}
	refusal = profile(command(), &publicapiv1.ProfileUpdate{Change: &publicapiv1.ProfileUpdate_ClearAvatar{ClearAvatar: true}}).GetError()
	if refusal.GetDetails().GetState().GetReason() != "patch.avatar: not_offered" {
		t.Fatalf("an avatar change: %v", refusal)
	}
	current := revision("identity.user", "user_id", who.id)
	conflict("a stale profile revision", profile(at(current-1), &publicapiv1.ProfileUpdate{DisplayName: proto.String("Name")}).GetError(), current-1, current)
	updated := profile(at(current), &publicapiv1.ProfileUpdate{DisplayName: proto.String("Grace"), Locale: proto.String("en-GB"),
		Timezone: proto.String("Europe/London")})
	if value := updated.GetValue().GetProfile(); updated.GetError() != nil || value.GetDisplayName() != "Grace" || value.GetLocale() != "en-GB" ||
		value.GetTimezone() != "Europe/London" || value.GetRevision().GetValue() != current+1 || h.audits("identity.profile.updated") != 1 {
		t.Fatalf("the profile update: %v", updated)
	}

	credential := h.credentialIDs(who.id)[0]
	rename := func(meta *foundationv1.RequestMeta, name string) *foundationv1.ArcError {
		return rpc(h, renameCredentialPath, &publicapiv1.IdentityServiceRenameAuthIdentityRequest{Meta: meta, CredentialId: idOf(credential),
			Name: proto.String(name)}, from, &publicapiv1.IdentityServiceRenameAuthIdentityResponse{}).GetError()
	}
	if refusal := rename(command(), strings.Repeat("b", 65)); refusal.GetDetails().GetState().GetReason() != "name: length" {
		t.Fatalf("a long credential name: %v", refusal)
	}
	current = revision("identity.auth_identity", "auth_identity_id", credential)
	conflict("a stale credential revision", rename(at(current+1), "Phone"), current+1, current)
	expect(t, "the credential rename", rename(at(current), "Phone"), "")
	if h.count("SELECT count(*) FROM identity.auth_identity WHERE auth_identity_id = $1 AND label = 'Phone'", credential) != 1 {
		t.Fatal("the credential keeps its old name")
	}

	deviceID := h.deviceOf(sessionIDOf(native))
	renameDevice := func(meta *foundationv1.RequestMeta, name string) *publicapiv1.DeviceServiceRenameResponse {
		return rpc(h, renameDevicePath, &publicapiv1.DeviceServiceRenameRequest{Meta: meta, DeviceId: idOf(deviceID), Name: proto.String(name)}, from,
			&publicapiv1.DeviceServiceRenameResponse{})
	}
	current = revision("device.device", "device_id", deviceID)
	conflict("a stale device revision", renameDevice(at(current-1), "Pixel").GetError(), current-1, current)
	renamed := renameDevice(at(current), "Pixel")
	if renamed.GetError() != nil || renamed.GetValue().GetDevice().GetName() != "Pixel" || renamed.GetValue().GetDevice().GetRevision().GetValue() != current+1 {
		t.Fatalf("the device rename: %v", renamed)
	}
	h.verifyAudit()
}

// TestAnAccountCannotReachAnotherAccountsObjects: every write that names a session, credential or device of another account is
// STATE/not_found with state.resource naming the object the caller sent (F19), and changes nothing of the other account.
func TestAnAccountCannotReachAnotherAccountsObjects(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	alice, bob := h.seedAccount(1, ""), h.seedAccount(1, "")
	aliceSession := sessionIDOf(h.signIn(alice, newClaim(t), caller{}))
	aliceDevice, aliceCredential := h.deviceOf(aliceSession), h.credentialIDs(alice.id)[0]
	from := bearer(h.signIn(bob, newClaim(t), caller{}).GetAccessToken())
	state := func() string {
		var value string
		if err := h.migration.QueryRow(context.Background(), `SELECT concat_ws('|', (SELECT sum(rev) FROM identity.session WHERE user_id = $1),
    (SELECT sum(rev) FROM identity.auth_identity WHERE user_id = $1), (SELECT sum(rev) FROM device.device WHERE user_id = $1))`, alice.id).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	before := state()
	notFound := func(what string, refusal *foundationv1.ArcError, kind string, id platform.ID) {
		t.Helper()
		if got, raw := resourceOf(refusal); failure(refusal) != "STATE/not_found" || got != kind || !bytes.Equal(raw, id[:]) {
			t.Errorf("%s: %v", what, refusal)
		}
	}
	notFound("renaming another account's credential", rpc(h, renameCredentialPath, &publicapiv1.IdentityServiceRenameAuthIdentityRequest{Meta: command(),
		CredentialId: idOf(aliceCredential), Name: proto.String("Mine")}, from, &publicapiv1.IdentityServiceRenameAuthIdentityResponse{}).GetError(),
		"credential", aliceCredential)
	h.stepUp(bob, from, identity.ClassRemoveCredential, aliceCredential)
	notFound("removing another account's credential", rpc(h, removeCredentialPath, &publicapiv1.IdentityServiceRemoveAuthIdentityRequest{Meta: command(),
		CredentialId: idOf(aliceCredential)}, from, &publicapiv1.IdentityServiceRemoveAuthIdentityResponse{}).GetError(), "credential", aliceCredential)
	h.stepUp(bob, from, identity.ClassRevokeSession, aliceSession)
	notFound("revoking another account's session", h.revokeSession(from, command(), aliceSession).GetError(), "session", aliceSession)
	notFound("renaming another account's device", rpc(h, renameDevicePath, &publicapiv1.DeviceServiceRenameRequest{Meta: command(), DeviceId: idOf(aliceDevice),
		Name: proto.String("Mine")}, from, &publicapiv1.DeviceServiceRenameResponse{}).GetError(), "device", aliceDevice)
	h.stepUp(bob, from, identity.ClassRevokeDevice, aliceDevice)
	notFound("revoking another account's device", rpc(h, revokeDevicePath, &publicapiv1.DeviceServiceRevokeRequest{Meta: command(), DeviceId: idOf(aliceDevice)},
		from, &publicapiv1.DeviceServiceRevokeResponse{}).GetError(), "device", aliceDevice)
	unknown := platform.NewID()
	stray, _ := virtual.New(rpID, origin).Create(randomBytes(t, 32), bob.handle)
	completed := rpc(h, completeRegisterPath, &publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest{Meta: command(), FlowId: idOf(unknown),
		Credential: creationOf(stray)}, from,
		&publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse{}).GetError()
	notFound("completing an unknown registration flow", completed, "auth_flow", unknown)
	if state() != before {
		t.Fatal("another account's objects changed")
	}
	h.verifyAudit()
}

// TestTheLastCredentialStays: the last live credential cannot be removed (STATE/invalid_state, reason last_credential; the receipt
// keeps the refusal), and two concurrent removals of an account's two credentials leave one: the account's row lock orders them.
func TestTheLastCredentialStays(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	only := h.seedAccount(1, "")
	from := bearer(h.signIn(only, newClaim(t), caller{}).GetAccessToken())
	remove := func(from caller, meta *foundationv1.RequestMeta, credential platform.ID) *foundationv1.ArcError {
		return rpc(h, removeCredentialPath, &publicapiv1.IdentityServiceRemoveAuthIdentityRequest{Meta: meta, CredentialId: idOf(credential)}, from,
			&publicapiv1.IdentityServiceRemoveAuthIdentityResponse{}).GetError()
	}
	credential := h.credentialIDs(only.id)[0]
	h.stepUp(only, from, identity.ClassRemoveCredential, credential)
	last := command()
	for range 2 {
		refusal := remove(from, last, credential)
		if failure(refusal) != "STATE/invalid_state" || refusal.GetDetails().GetState().GetReason() != "last_credential" ||
			len(h.credentialIDs(only.id)) != 1 {
			t.Fatalf("removing the last credential: %v", refusal)
		}
	}

	both := h.seedAccount(1, "both@example.org")
	h.remember(both.email)
	signedIn := bearer(h.signIn(both, newClaim(t), caller{}).GetAccessToken())
	ids := h.credentialIDs(both.id)
	for _, id := range ids {
		h.stepUp(both, signedIn, identity.ClassRemoveCredential, id)
	}
	results := make([]string, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Go(func() { results[index] = failure(remove(signedIn, command(), ids[index])) })
	}
	wait.Wait()
	succeeded := 0
	for _, result := range results {
		switch result {
		case "":
			succeeded++
		case "STATE/invalid_state", "AUTHENTICATION/step_up_required":
		default:
			t.Fatalf("a concurrent removal: %q", result)
		}
	}
	if succeeded != 1 || len(h.credentialIDs(both.id)) != 1 {
		t.Fatalf("two concurrent removals: %q, %d live credentials", results, len(h.credentialIDs(both.id)))
	}
	h.verifyAudit()
}

// TestHealthStatesTheServedSurfaces: the health document names the surfaces the center serves (AF-CTR-03), which a deployment
// compares with the surfaces its Worker forwards.
func TestHealthStatesTheServedSurfaces(t *testing.T) {
	for surfaces, want := range map[string]string{"": "identity", "none": "none"} {
		h := newHarness(t, settings{surfaces: surfaces})
		response, err := http.Get(h.url + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		var health struct {
			Center struct {
				Surfaces string `json:"surfaces"`
			} `json:"center"`
		}
		err = json.NewDecoder(response.Body).Decode(&health)
		_ = response.Body.Close()
		if err != nil || health.Center.Surfaces != want {
			t.Fatalf("surfaces %q: health states %q (%v)", surfaces, health.Center.Surfaces, err)
		}
	}
}

// TestNoReceiptHoldsAnAddress (C1): an e-mail address is stored in clear only as the subject of an e-mail identity, so no command
// receipt's result holds one. UpdateProfile's first answer states the account's primary address and its replay the account's
// current one, which is none once the e-mail identity is removed. Every receipt-guarded write runs once here, and every stored
// result is scanned for the address.
func TestNoReceiptHoldsAnAddress(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	address := "c1.person@example.org"
	who := h.seedAccount(1, address)
	h.remember(address)
	native := h.signIn(who, newClaim(t), caller{})
	from := bearer(native.GetAccessToken())
	ids := h.credentialIDs(who.id)
	passkey, email := ids[0], ids[1]

	update := command()
	profile := func() *publicapiv1.IdentityServiceUpdateProfileResponse {
		return rpc(h, updateProfilePath, &publicapiv1.IdentityServiceUpdateProfileRequest{Meta: update, Patch: &publicapiv1.ProfileUpdate{
			Locale: proto.String("en-GB")}}, from, &publicapiv1.IdentityServiceUpdateProfileResponse{})
	}
	for _, what := range []string{"the first answer", "the replay"} {
		if answer := profile(); answer.GetError() != nil || answer.GetValue().GetProfile().GetPrimaryEmail() != address {
			t.Fatalf("UpdateProfile, %s: %v", what, answer)
		}
	}
	for credential, name := range map[platform.ID]string{passkey: "Laptop key", email: "Mail"} {
		expect(t, "a credential rename", rpc(h, renameCredentialPath, &publicapiv1.IdentityServiceRenameAuthIdentityRequest{Meta: command(),
			CredentialId: idOf(credential), Name: proto.String(name)}, from, &publicapiv1.IdentityServiceRenameAuthIdentityResponse{}).GetError(), "")
	}
	h.stepUp(who, from, identity.ClassBeginRegistration, who.id)
	challenge := rpc(h, beginRegisterPath, &publicapiv1.IdentityServiceBeginPasskeyRegistrationRequest{Meta: meta(), DisplayName: proto.String("Phone key")},
		from, &publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse{}).GetValue().GetChallenge()
	creation, _ := virtual.New(rpID, origin).Create(challenge.GetChallenge(), who.handle)
	expect(t, "a registration", rpc(h, completeRegisterPath, &publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest{Meta: command(),
		FlowId: challenge.GetFlowId(), Credential: creationOf(creation)}, from, &publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse{}).GetError(), "")
	own := h.deviceOf(sessionIDOf(native))
	expect(t, "a device rename", rpc(h, renameDevicePath, &publicapiv1.DeviceServiceRenameRequest{Meta: command(), DeviceId: idOf(own),
		Name: proto.String("Pixel")}, from, &publicapiv1.DeviceServiceRenameResponse{}).GetError(), "")
	other := h.issue(who.id, session.ScopeAccount, false)
	h.stepUp(who, from, identity.ClassRevokeSession, other.sessionID)
	expect(t, "a session revocation", h.revokeSession(from, command(), other.sessionID).GetError(), "")
	h.stepUp(who, from, identity.ClassRevokeAllSessions, who.id)
	expect(t, "a revocation of all sessions", rpc(h, revokeAllPath, &publicapiv1.IdentityServiceRevokeAllSessionsRequest{Meta: command()}, from,
		&publicapiv1.IdentityServiceRevokeAllSessionsResponse{}).GetError(), "")
	device := h.deviceOf(sessionIDOf(h.signIn(who, newClaim(t), caller{})))
	h.stepUp(who, from, identity.ClassRevokeDevice, device)
	expect(t, "a device revocation", rpc(h, revokeDevicePath, &publicapiv1.DeviceServiceRevokeRequest{Meta: command(), DeviceId: idOf(device)}, from,
		&publicapiv1.DeviceServiceRevokeResponse{}).GetError(), "")
	h.stepUp(who, from, identity.ClassRemoveCredential, email)
	expect(t, "the e-mail identity's removal", rpc(h, removeCredentialPath, &publicapiv1.IdentityServiceRemoveAuthIdentityRequest{Meta: command(),
		CredentialId: idOf(email)}, from, &publicapiv1.IdentityServiceRemoveAuthIdentityResponse{}).GetError(), "")
	if answer := profile(); answer.GetError() != nil || answer.GetValue().GetProfile().PrimaryEmail != nil ||
		answer.GetValue().GetProfile().GetLocale() != "en-GB" {
		t.Fatalf("UpdateProfile's replay after the address was removed: %v", answer)
	}

	rows, err := h.migration.Query(context.Background(), "SELECT operation, result FROM platform.command_receipt")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	operations := map[string]bool{}
	for rows.Next() {
		var operation string
		var result []byte
		if err = rows.Scan(&operation, &result); err != nil {
			t.Fatal(err)
		}
		operations[operation] = true
		if bytes.Contains(bytes.ToLower(result), []byte(address)) {
			t.Errorf("the receipt of %s holds the address", operation)
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{updateProfilePath, renameCredentialPath, completeRegisterPath, renameDevicePath, revokeSessionPath, revokeAllPath,
		revokeDevicePath, removeCredentialPath} {
		if !operations[strings.TrimPrefix(operation, "/")] && !operations[operation] {
			t.Errorf("no receipt of %s was scanned", operation)
		}
	}
	h.verifyAudit()
}

// TestARetryWithItsOwnCorrelationReplaysTheReceipt (B1): a receipt digests the request without RequestMeta.correlation_id, so the
// same command sent again with a new correlation replays its outcome, with that correlation in the reply and no second effect.
// Every other byte is the request: another expected revision or another target under the same command ID is
// CONFLICT/command_id_reused.
func TestARetryWithItsOwnCorrelationReplaysTheReceipt(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1, "")
	from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
	target, other := h.issue(who.id, session.ScopeAccount, false).sessionID, h.issue(who.id, session.ScopeAccount, false).sessionID
	h.stepUp(who, from, identity.ClassRevokeSession, target)
	commandID := platform.NewID()
	attempt := func(correlation platform.ID, revision *int64, sessionID platform.ID) *publicapiv1.IdentityServiceRevokeSessionResponse {
		meta := &foundationv1.RequestMeta{CommandId: idOf(commandID), CorrelationId: idOf(correlation)}
		if revision != nil {
			meta.ExpectedRev = &foundationv1.Revision{Value: proto.Int64(*revision)}
		}
		return h.revokeSession(from, meta, sessionID)
	}
	first := attempt(platform.NewID(), nil, target)
	expect(t, "the first attempt", first.GetError(), "")
	audits, receipts := h.audits("identity.session.revoked"), h.receipts()
	correlation := platform.NewID()
	retry := attempt(correlation, nil, target)
	if retry.GetError() != nil || !proto.Equal(retry.GetValue(), first.GetValue()) || h.audits("identity.session.revoked") != audits ||
		h.receipts() != receipts || !bytes.Equal(retry.GetMeta().GetCorrelationId().GetValue(), correlation[:]) {
		t.Fatalf("the retry with its own correlation: %v", retry)
	}
	revision := int64(1)
	expect(t, "the command with an expected revision", attempt(platform.NewID(), &revision, target).GetError(), "CONFLICT/command_id_reused")
	expect(t, "the command with another target", attempt(platform.NewID(), nil, other).GetError(), "CONFLICT/command_id_reused")
	if !h.live(other) {
		t.Fatal("a reused command ID revoked another session")
	}
}
