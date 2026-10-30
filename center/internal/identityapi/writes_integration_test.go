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
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
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
	// Another account's credential is never named (B6): the details state the kind and the code only.
	if state := refusal.GetDetails().GetState(); failure(refusal) != "CONFLICT/already_exists" || state.GetResource() != nil ||
		state.GetState() != "credential" || state.GetReason() != "already_exists" {
		t.Fatalf("a credential ID registered already: %v", refusal)
	}
	if replay := complete(conflict, again.GetFlowId(), creationOf(taken)).GetError(); failure(replay) != "CONFLICT/already_exists" {
		t.Fatalf("the replay of the refused command: %v", replay)
	}
	// The caller's own live credential is named by its ID, which the caller lists itself.
	h.stepUp(who, from, identity.ClassBeginRegistration, who.id)
	third := begin(proto.String("Third")).GetValue().GetChallenge()
	mine, _ := authenticator.Create(third.GetChallenge(), who.handle)
	existing := platform.NewID()
	if _, err := h.migration.Exec(context.Background(), `INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, public_key,
    user_handle, sign_count, backup_eligible, backup_state, transports, aaguid, attestation_format, created_at, rev)
SELECT $1, user_id, 1, 'passkey', $2, public_key, user_handle, 0, false, false, '{}', aaguid, 'none', now(), 1
FROM identity.auth_identity WHERE user_id = $3 AND method = 1 LIMIT 1`, existing, base64.RawURLEncoding.EncodeToString(mine.CredentialID), who.id); err != nil {
		t.Fatal(err)
	}
	refusal = complete(command(), third.GetFlowId(), creationOf(mine)).GetError()
	if kind, id := resourceOf(refusal); failure(refusal) != "CONFLICT/already_exists" || kind != "credential" || !bytes.Equal(id, existing[:]) {
		t.Fatalf("the caller's own credential ID registered again: %v", refusal)
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
	// A device name follows the credential label rule (UTF-16 units; control characters and blank names are rule pattern).
	for name, reason := range map[string]string{strings.Repeat("\U0001F600", 33): "name: length", "Bell\a": "name: pattern", "   ": "name: pattern"} {
		if refusal := renameDevice(command(), name).GetError(); refusal.GetDetails().GetState().GetReason() != reason {
			t.Fatalf("the device name %q: %v", name, refusal)
		}
	}
	expect(t, "a device name of 64 UTF-16 units", renameDevice(command(), strings.Repeat("\U0001F600", 32)).GetError(), "")
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
	// Each refusal inside a receipt is kept by it (B16); the unknown flow is refused before its receipt.
	if kept := h.refusalsKept("STATE/not_found"); kept != 5 || h.receipts() != kept {
		t.Fatalf("receipts keeping not_found: %d of %d", kept, h.receipts())
	}
	if state() != before {
		t.Fatal("another account's objects changed")
	}
	h.verifyAudit()
}

// TestTheLastCredentialStays: the last live credential cannot be removed (STATE/invalid_state, reason last_credential), and the
// receipt keeps that refusal (B16): its replay answers it even once the account has a second credential. Two concurrent removals of
// an account's two credentials are ordered by the account's row lock, which evidence consumption takes (B3, B15): the first is
// parked at its credential's row while it holds that lock, the second waits behind it and then finds its evidence spent by the
// first's epoch move, so one credential stays; a fresh step-up then meets the last-credential rule.
func TestTheLastCredentialStays(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	only := h.seedAccount(1, "")
	from := bearer(h.signIn(only, newClaim(t), caller{}).GetAccessToken())
	remove := func(from caller, meta *foundationv1.RequestMeta, credential platform.ID) *foundationv1.ArcError {
		return rpc(h, removeCredentialPath, &publicapiv1.IdentityServiceRemoveAuthIdentityRequest{Meta: meta, CredentialId: idOf(credential)}, from,
			&publicapiv1.IdentityServiceRemoveAuthIdentityResponse{}).GetError()
	}
	lastCredential := func(what string, refusal *foundationv1.ArcError) {
		t.Helper()
		if failure(refusal) != "STATE/invalid_state" || refusal.GetDetails().GetState().GetReason() != "last_credential" {
			t.Fatalf("%s: %v", what, refusal)
		}
	}
	credential := h.credentialIDs(only.id)[0]
	h.stepUp(only, from, identity.ClassRemoveCredential, credential)
	last := command()
	lastCredential("removing the last credential", remove(from, last, credential))
	if len(h.credentialIDs(only.id)) != 1 || h.refusalsKept("STATE/invalid_state") != 1 {
		t.Fatal("the refusal removed the credential or was not kept by the receipt")
	}
	if _, err := h.migration.Exec(context.Background(), `INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, public_key,
    user_handle, sign_count, backup_eligible, backup_state, transports, aaguid, attestation_format, created_at, rev)
SELECT $1, user_id, 1, 'passkey', $2, public_key, user_handle, 0, false, false, '{}', aaguid, 'none', now(), 1
FROM identity.auth_identity WHERE user_id = $3 AND method = 1`, platform.NewID(), base64.RawURLEncoding.EncodeToString(randomBytes(t, 32)), only.id); err != nil {
		t.Fatal(err)
	}
	lastCredential("the replay once the account has a second credential", remove(from, last, credential))
	if len(h.credentialIDs(only.id)) != 2 || h.audits("identity.credential.removed") != 0 {
		t.Fatal("the replay removed a credential")
	}

	both := h.seedAccount(1, "both@example.org")
	h.remember(both.email)
	signedIn := bearer(h.signIn(both, newClaim(t), caller{}).GetAccessToken())
	ids := h.credentialIDs(both.id)
	for _, id := range ids {
		h.stepUp(both, signedIn, identity.ClassRemoveCredential, id)
	}
	lock := h.holding("SELECT 1 FROM identity.auth_identity WHERE auth_identity_id = $1 FOR UPDATE", ids[0])
	results := make([]*foundationv1.ArcError, 2)
	var wait sync.WaitGroup
	wait.Go(func() { results[0] = remove(signedIn, command(), ids[0]) })
	if !lock.waitFor(1) {
		t.Fatal("the first removal never reached its credential's row")
	}
	wait.Go(func() { results[1] = remove(signedIn, command(), ids[1]) })
	if !lock.waitFor(2) {
		t.Fatal("the second removal never waited behind the first")
	}
	lock.release(false)
	wait.Wait()
	if results[0] != nil || failure(results[1]) != "AUTHENTICATION/step_up_required" || len(h.credentialIDs(both.id)) != 1 {
		t.Fatalf("two concurrent removals: %v, %v, %d live credentials", results[0], results[1], len(h.credentialIDs(both.id)))
	}
	// The passkey is gone, so the fresh evidence is proved by e-mail.
	h.stepUpByEmail(both, signedIn, identity.ClassRemoveCredential, ids[1])
	lastCredential("the remaining credential with fresh evidence", remove(signedIn, command(), ids[1]))
	h.verifyAudit()
}

// TestARegistrationFlowIsItsBeginningSessions (SEC-07, B2): a registration flow belongs to the session that began it with the
// account's evidence. Another account and another session of the same account completing it get STATE/not_found (auth_flow, the
// flow's ID) and count no attempt; a creation for another challenge is VALIDATION/invalid_argument (credential: not_verified) and
// ends the flow, so the right creation afterwards is STATE/expired. That refusal comes before the command's receipt, so the
// identical replay answers STATE/expired too (B5).
func TestARegistrationFlowIsItsBeginningSessions(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	alice, bob := h.seedAccount(1, ""), h.seedAccount(1, "")
	first := bearer(h.signIn(alice, newClaim(t), caller{}).GetAccessToken())
	second := bearer(h.signIn(alice, newClaim(t), caller{}).GetAccessToken())
	other := bearer(h.signIn(bob, newClaim(t), caller{}).GetAccessToken())
	h.stepUp(alice, first, identity.ClassBeginRegistration, alice.id)
	challenge := rpc(h, beginRegisterPath, &publicapiv1.IdentityServiceBeginPasskeyRegistrationRequest{Meta: meta(), DisplayName: proto.String("Key")}, first,
		&publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse{}).GetValue().GetChallenge()
	flowID := idFrom(challenge.GetFlowId())
	authenticator := virtual.New(rpID, origin)
	complete := func(from caller, meta *foundationv1.RequestMeta, creation passkey.Creation) *foundationv1.ArcError {
		return rpc(h, completeRegisterPath, &publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest{Meta: meta, FlowId: challenge.GetFlowId(),
			Credential: creationOf(creation)}, from, &publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse{}).GetError()
	}
	stored := func(creation passkey.Creation) int {
		return h.count("SELECT count(*) FROM identity.auth_identity WHERE subject = $1", base64.RawURLEncoding.EncodeToString(creation.CredentialID))
	}
	for what, intruder := range map[string]caller{"another account": other, "another session of the account": second} {
		creation, _ := authenticator.Create(challenge.GetChallenge(), alice.handle)
		refusal := complete(intruder, command(), creation)
		if kind, raw := resourceOf(refusal); failure(refusal) != "STATE/not_found" || kind != "auth_flow" || !bytes.Equal(raw, flowID[:]) ||
			stored(creation) != 0 || h.count("SELECT attempts FROM identity.auth_flow WHERE flow_id = $1", flowID) != 0 {
			t.Fatalf("%s completing the flow: %v", what, refusal)
		}
	}
	stray, _ := authenticator.Create(randomBytes(t, 32), alice.handle)
	refused := command()
	refusal := complete(first, refused, stray)
	if failure(refusal) != "VALIDATION/invalid_argument" || refusal.GetDetails().GetState().GetReason() != "credential: not_verified" {
		t.Fatalf("a creation that does not verify: %v", refusal)
	}
	expect(t, "the identical replay of the refused creation", complete(first, refused, stray), "STATE/expired")
	right, _ := authenticator.Create(challenge.GetChallenge(), alice.handle)
	expect(t, "the right creation after a failed one", complete(first, command(), right), "STATE/expired")
	if stored(stray) != 0 || stored(right) != 0 || h.receipts() != 0 {
		t.Fatal("a credential or a receipt was stored")
	}
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
// result is scanned for the address. The writes are checked against the operation table (E7): a row with a receipt that this test
// does not run, or a receipt of a method whose row names none, fails it.
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
		operations["/"+strings.TrimPrefix(operation, "/")] = true
		if bytes.Contains(bytes.ToLower(result), []byte(address)) {
			t.Errorf("the receipt of %s holds the address", operation)
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, operation := range access.Operations() {
		if !operation.Receipt {
			continue
		}
		if !operations[operation.Path] {
			t.Errorf("%s runs under a receipt, but this test has no request for it (no receipt of it was scanned)", operation.ID)
		}
		delete(operations, operation.Path)
	}
	for operation := range operations {
		t.Errorf("a receipt of %s was stored, but its row in the operation table names no receipt", operation)
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

// TestADuplicateOfARunningRegistrationIsBusy (B4): the same CompletePasskeyRegistration command sent again while its first
// execution still runs finds the flow's only attempt taken; it answers RESOURCE/overloaded (AFTER_TIME), never a final refusal,
// and once the first committed the same command replays its success. The first execution is parked in its receipt transaction by
// a held lock on the account's row.
func TestADuplicateOfARunningRegistrationIsBusy(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1, "")
	from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
	h.stepUp(who, from, identity.ClassBeginRegistration, who.id)
	challenge := rpc(h, beginRegisterPath, &publicapiv1.IdentityServiceBeginPasskeyRegistrationRequest{Meta: meta(), DisplayName: proto.String("Key")}, from,
		&publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse{}).GetValue().GetChallenge()
	creation, _ := virtual.New(rpID, origin).Create(challenge.GetChallenge(), who.handle)
	request := &publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest{Meta: command(), FlowId: challenge.GetFlowId(), Credential: creationOf(creation)}
	complete := func() *publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse {
		return rpc(h, completeRegisterPath, request, from, &publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse{})
	}
	lock := h.holding("SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", who.id)
	first := make(chan *publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse, 1)
	go func() { first <- complete() }()
	if !lock.waitFor(1) {
		t.Fatal("the first completion never reached the account's row")
	}
	duplicate := complete().GetError()
	if failure(duplicate) != "RESOURCE/overloaded" || duplicate.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME {
		t.Fatalf("the duplicate while the first runs: %v", duplicate)
	}
	lock.release(false)
	answer := <-first
	if answer.GetError() != nil {
		t.Fatalf("the first completion: %s", failure(answer.GetError()))
	}
	replay := complete()
	if replay.GetError() != nil || !proto.Equal(replay.GetValue(), answer.GetValue()) || h.receipts() != 1 ||
		h.count("SELECT count(*) FROM identity.auth_identity WHERE subject = $1", base64.RawURLEncoding.EncodeToString(creation.CredentialID)) != 1 {
		t.Fatalf("the replay after the first committed: %v", replay)
	}
	h.verifyAudit()
}

// registrationAnswer is a CompletePasskeyRegistration reply.
type registrationAnswer = *publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse

// racedRegistration runs one CompletePasskeyRegistration command twice so that the duplicate's receipt lookup runs before the first
// execution committed and its attempt after it: the first execution parks on the account's row, a table lock queued behind it on a
// second connection parks the duplicate's attempt, and the account's row is then released. committed runs once the first execution
// answered and the table lock is granted, before the duplicate's attempt goes on. It returns both answers, the command (to send it
// again) and the new credential's subject.
func racedRegistration(t *testing.T, h *harness, committed func(ctx context.Context), alter ...func(*publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest)) (first,
	duplicate registrationAnswer, complete func() registrationAnswer, subject string) {
	t.Helper()
	who := h.seedAccount(1, "")
	from := bearer(h.signIn(who, newClaim(t), caller{}).GetAccessToken())
	h.stepUp(who, from, identity.ClassBeginRegistration, who.id)
	challenge := rpc(h, beginRegisterPath, &publicapiv1.IdentityServiceBeginPasskeyRegistrationRequest{Meta: meta(), DisplayName: proto.String("Key")}, from,
		&publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse{}).GetValue().GetChallenge()
	creation, _ := virtual.New(rpID, origin).Create(challenge.GetChallenge(), who.handle)
	request := &publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest{Meta: command(), FlowId: challenge.GetFlowId(), Credential: creationOf(creation)}
	complete = func() registrationAnswer {
		return rpc(h, completeRegisterPath, request, from, &publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse{})
	}
	// alter changes the request the duplicate sends: the same command ID with other bytes.
	sendDuplicate := complete
	if len(alter) > 0 {
		sendDuplicate = func() registrationAnswer {
			changed := proto.Clone(request).(*publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest)
			alter[0](changed)
			return rpc(h, completeRegisterPath, changed, from, &publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse{})
		}
	}
	ctx := context.Background()
	other, err := pgx.ConnectConfig(ctx, h.migration.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.Close(context.Background()) })
	account := h.holding("SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE", who.id)
	firsts := make(chan registrationAnswer, 1)
	go func() { firsts <- complete() }()
	if !account.waitFor(1) {
		t.Fatal("the first completion never reached the account's row")
	}
	table, err := other.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	queued := make(chan error, 1)
	go func() {
		_, err := table.Exec(ctx, "LOCK TABLE identity.auth_flow IN ACCESS EXCLUSIVE MODE")
		queued <- err
	}()
	if !account.waitFor(2) {
		t.Fatal("the table lock never queued behind the first completion")
	}
	duplicates := make(chan registrationAnswer, 1)
	go func() { duplicates <- sendDuplicate() }()
	if !account.waitFor(3) {
		t.Fatal("the duplicate's attempt never queued behind the table lock")
	}
	account.release(false)
	first = <-firsts
	if err = <-queued; err != nil {
		t.Fatal(err)
	}
	if committed != nil {
		committed(ctx)
	}
	if err = table.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	return first, <-duplicates, complete, base64.RawURLEncoding.EncodeToString(creation.CredentialID)
}

// TestADuplicateRefusedAfterItsFirstCommittedAnswersTheReceipt (B4, E1): a duplicate CompletePasskeyRegistration whose receipt
// lookup runs before the first execution committed, and whose attempt runs after it, finds the flow consumed; its second receipt
// lookup answers the first's receipt, never a final code_reused.
func TestADuplicateRefusedAfterItsFirstCommittedAnswersTheReceipt(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	answer, second, _, subject := racedRegistration(t, h, nil)
	if answer.GetError() != nil || second.GetError() != nil || !proto.Equal(second.GetValue(), answer.GetValue()) || h.receipts() != 1 ||
		h.count("SELECT count(*) FROM identity.auth_identity WHERE subject = $1", subject) != 1 {
		t.Fatalf("the first completion %v, the duplicate refused after it committed %v", answer, second)
	}
	h.verifyAudit()
}

// TestADuplicateWhoseSecondLookupFailsIsRetryable (B4, F-1): when that second receipt lookup fails, the duplicate's command may
// have committed, so it answers the lookup's own failure, RESOURCE/overloaded with its retry instant, never the final code_reused
// of the consumed flow; the same command then replays the receipt. A third connection holds the receipt table locked from the
// first execution's commit until the duplicate answered, so its lookup runs into its timeout.
func TestADuplicateWhoseSecondLookupFailsIsRetryable(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	receipts, err := pgx.ConnectConfig(context.Background(), h.migration.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receipts.Close(context.Background()) })
	var locked pgx.Tx
	answer, second, complete, subject := racedRegistration(t, h, func(ctx context.Context) {
		if locked, err = receipts.Begin(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err = locked.Exec(ctx, "LOCK TABLE platform.command_receipt IN ACCESS EXCLUSIVE MODE"); err != nil {
			t.Fatal(err)
		}
	})
	if err = locked.Rollback(context.Background()); err != nil {
		t.Fatal(err)
	}
	refusal := second.GetError()
	if answer.GetError() != nil || failure(refusal) != "RESOURCE/overloaded" || refusal.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME ||
		refusal.GetRetry().GetRetryAt() == nil {
		t.Fatalf("the first completion %v, the duplicate whose second lookup failed %v", answer, second)
	}
	replay := complete()
	if replay.GetError() != nil || !proto.Equal(replay.GetValue(), answer.GetValue()) || h.receipts() != 1 ||
		h.count("SELECT count(*) FROM identity.auth_identity WHERE subject = $1", subject) != 1 {
		t.Fatalf("the same command after the lock: %v", replay)
	}
	h.verifyAudit()
}
