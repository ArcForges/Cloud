// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

const (
	beginPath    = "/arcforges.publicapi.v1.IdentityService/BeginAuthentication"
	completePath = "/arcforges.publicapi.v1.IdentityService/CompleteAuthentication"
	enrollPath   = "/arcforges.publicapi.v1.IdentityService/CompleteEnrollment"
	refreshPath  = "/arcforges.publicapi.v1.IdentityService/RefreshSession"
	profilePath  = "/arcforges.publicapi.v1.IdentityService/GetProfile"
	sessionsPath = "/arcforges.publicapi.v1.IdentityService/ListSessions"
	identities   = "/arcforges.publicapi.v1.IdentityService/ListAuthIdentities"
	providers    = "/arcforges.publicapi.v1.IdentityService/ListAuthProviders"
	devicesPath  = "/arcforges.publicapi.v1.DeviceService/List"
)

// enroll runs the owner bootstrap through the API: BeginAuthentication(PASSKEY, ENROLL), a virtual passkey and CompleteEnrollment
// with the token.
func (h *harness) enroll(token string, claim *publicapiv1.InstallationClaim, from caller) (*publicapiv1.IdentityServiceCompleteEnrollmentResponse, *virtual.Authenticator, *virtual.Key) {
	h.t.Helper()
	begun := rpc(h, beginPath, &publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: meta(), Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(),
		Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_ENROLL.Enum(), Installation: claim}, from, &publicapiv1.IdentityServiceBeginAuthenticationResponse{})
	if begun.GetError() != nil {
		h.t.Fatalf("begin enrollment: %s", failure(begun.GetError()))
	}
	challenge := begun.GetValue().GetChallenge()
	authenticator := virtual.New(rpID, origin)
	creation, key := authenticator.Create(challenge.GetChallenge(), challenge.GetOptions().GetUserHandle())
	response := rpc(h, enrollPath, &publicapiv1.IdentityServiceCompleteEnrollmentRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
		Proof:      &publicapiv1.EnrollmentProof{Proof: &publicapiv1.EnrollmentProof_LocalCode{LocalCode: token}},
		Credential: &publicapiv1.CredentialReplacement{Replacement: &publicapiv1.CredentialReplacement_Passkey{Passkey: creationOf(creation)}},
		Profile:    &publicapiv1.ProfileUpdate{DisplayName: proto.String("Owner"), Locale: proto.String("de-CH"), Timezone: proto.String("Europe/Zurich")},
	}, from, &publicapiv1.IdentityServiceCompleteEnrollmentResponse{})
	if value := response.GetValue().GetSession(); value != nil {
		h.remember(value.GetAccessToken(), value.GetRefreshToken())
	}
	return response, authenticator, key
}

func TestTheOwnerBootstrapCreatesTheFirstAccountOnce(t *testing.T) {
	h := newHarness(t, settings{})
	claim := newClaim(t)
	response, authenticator, key := h.enroll(h.bootstrap, claim, caller{})
	if response.GetError() != nil {
		t.Fatalf("bootstrap: %s", failure(response.GetError()))
	}
	native := response.GetValue().GetSession()
	if native.GetPurpose() != publicapiv1.AuthPurpose_AUTH_PURPOSE_ENROLL || native.GetDevice().GetPlatform() != "android" ||
		native.GetDevice().GetTrust() != publicapiv1.TrustLevel_TRUST_LEVEL_UNTRUSTED || len(native.GetDevice().GetInstalled()) != 1 ||
		native.GetDevice().GetInstalled()[0].GetProduct() != "arcforges-mobile" || native.GetRecoveryGeneration() != 0 {
		t.Fatalf("session %v", native)
	}
	if string(response.GetMeta().GetCorrelationId().GetValue()) == "" {
		t.Fatal("the reply has no correlation id")
	}
	profile := rpc(h, profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{bearer: native.GetAccessToken()},
		&publicapiv1.IdentityServiceGetProfileResponse{}).GetValue().GetProfile()
	if profile.GetDisplayName() != "Owner" || profile.GetLocale() != "de-CH" || profile.GetTimezone() != "Europe/Zurich" || profile.PrimaryEmail != nil ||
		profile.GetRevision().GetValue() != 1 {
		t.Fatalf("profile %v", profile)
	}
	if h.count("SELECT count(*) FROM identity.user") != 1 || h.count("SELECT count(*) FROM identity.bootstrap") != 1 ||
		h.audits("identity.bootstrap.completed") != 1 {
		t.Fatal("the bootstrap rows")
	}
	// The owner signs in with the new passkey.
	signedIn := h.signIn(account{authenticator: authenticator, key: key}, claim, caller{})
	if !bytes.Equal(signedIn.GetDevice().GetDeviceId().GetValue(), native.GetDevice().GetDeviceId().GetValue()) {
		t.Fatal("the same installation is the same device")
	}
	// Used: refused like any other wrong bootstrap, and nothing is written.
	again, _, _ := h.enroll(h.bootstrap, newClaim(t), caller{})
	if failure(again.GetError()) != "AUTHENTICATION/unauthenticated" || h.count("SELECT count(*) FROM identity.user") != 1 {
		t.Fatalf("a second bootstrap: %s", failure(again.GetError()))
	}
	h.verifyAudit()
}

func TestABootstrapIsRefusedAlikeForEveryReason(t *testing.T) {
	h := newHarness(t, settings{policy: `{"bootstrapPerPrefixLimit": 3}`})
	from := caller{ip: "198.51.100.20"}
	flipped := byte('A')
	if h.bootstrap[5] == 'A' {
		flipped = 'B'
	}
	wrong := h.bootstrap[:5] + string(flipped) + h.bootstrap[6:]
	for range 3 {
		response, _, _ := h.enroll(wrong, newClaim(t), from)
		if failure(response.GetError()) != "AUTHENTICATION/unauthenticated" {
			t.Fatalf("a wrong token: %s", failure(response.GetError()))
		}
	}
	response, _, _ := h.enroll("not a token", newClaim(t), from)
	if failure(response.GetError()) != "RESOURCE/rate_limited" || response.GetError().GetDetails().GetLimit().GetLimitName() != "bootstrap_prefix" ||
		response.GetError().GetRetry().GetRetryAt() == nil {
		t.Fatalf("the fourth mismatch of a prefix: %v", response.GetError())
	}
	// The token is compared before any rate-limit decision: the owner is never locked out by someone else's guesses.
	response, _, _ = h.enroll(h.bootstrap, newClaim(t), from)
	if response.GetError() != nil {
		t.Fatalf("the right token from a limited prefix: %s", failure(response.GetError()))
	}
	// The refusals are audited once per bucket window, with the reason only in the audit.
	if h.audits("identity.bootstrap.refused") != 1 || h.count("SELECT count(*) FROM identity.user") != 1 {
		t.Fatal("bootstrap refusals")
	}
	// Once an account exists the right token is refused like a wrong one.
	response, _, _ = h.enroll(h.bootstrap, newClaim(t), caller{ip: "192.0.2.7"})
	if failure(response.GetError()) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("after the bootstrap: %s", failure(response.GetError()))
	}

	unconfigured := newHarness(t, settings{noBootstrap: true})
	response, _, _ = unconfigured.enroll(h.bootstrap, newClaim(t), caller{})
	if failure(response.GetError()) != "AUTHENTICATION/unauthenticated" || unconfigured.count("SELECT count(*) FROM identity.user") != 0 {
		t.Fatalf("no bootstrap configured: %s", failure(response.GetError()))
	}

	expired := newHarness(t, settings{})
	expired.clock.Advance(49 * time.Hour)
	response, _, _ = expired.enroll(expired.bootstrap, newClaim(t), caller{})
	if failure(response.GetError()) != "AUTHENTICATION/unauthenticated" || expired.count("SELECT count(*) FROM identity.user") != 0 {
		t.Fatalf("an expired bootstrap: %s", failure(response.GetError()))
	}

	existing := newHarness(t, settings{})
	existing.seedAccount(1, "")
	response, _, _ = existing.enroll(existing.bootstrap, newClaim(t), caller{})
	if failure(response.GetError()) != "AUTHENTICATION/unauthenticated" || existing.count("SELECT count(*) FROM identity.bootstrap") != 0 {
		t.Fatalf("an account exists: %s", failure(response.GetError()))
	}
	for _, item := range []*harness{h, unconfigured, expired, existing} {
		if item.count("SELECT count(*) FROM identity.session") > 1 {
			t.Fatal("a refused bootstrap issued a session")
		}
		item.verifyAudit()
	}
}

func TestConcurrentBootstrapsCreateOneAccount(t *testing.T) {
	h := newHarness(t, settings{})
	type started struct {
		flow          *foundationv1.Id
		authenticator *virtual.Authenticator
		challenge     *publicapiv1.AuthChallenge
	}
	attempts := make([]started, 6)
	for index := range attempts {
		begun := rpc(h, beginPath, &publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: meta(), Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(),
			Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_ENROLL.Enum(), Installation: newClaim(t)}, caller{}, &publicapiv1.IdentityServiceBeginAuthenticationResponse{})
		attempts[index] = started{flow: begun.GetValue().GetChallenge().GetFlowId(), authenticator: virtual.New(rpID, origin), challenge: begun.GetValue().GetChallenge()}
	}
	var wait sync.WaitGroup
	results := make([]string, len(attempts))
	for index, attempt := range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			creation, _ := attempt.authenticator.Create(attempt.challenge.GetChallenge(), attempt.challenge.GetOptions().GetUserHandle())
			response := rpc(h, enrollPath, &publicapiv1.IdentityServiceCompleteEnrollmentRequest{Meta: meta(), FlowId: attempt.flow,
				Proof:      &publicapiv1.EnrollmentProof{Proof: &publicapiv1.EnrollmentProof_LocalCode{LocalCode: h.bootstrap}},
				Credential: &publicapiv1.CredentialReplacement{Replacement: &publicapiv1.CredentialReplacement_Passkey{Passkey: creationOf(creation)}},
				Profile:    &publicapiv1.ProfileUpdate{DisplayName: proto.String("Owner")},
			}, caller{}, &publicapiv1.IdentityServiceCompleteEnrollmentResponse{})
			results[index] = failure(response.GetError())
		}()
	}
	wait.Wait()
	succeeded := 0
	for _, result := range results {
		switch result {
		case "":
			succeeded++
		case "AUTHENTICATION/unauthenticated":
		default:
			t.Fatalf("a concurrent bootstrap answered %s", result)
		}
	}
	if succeeded != 1 || h.count("SELECT count(*) FROM identity.user") != 1 || h.count("SELECT count(*) FROM identity.auth_identity") != 1 ||
		h.count("SELECT count(*) FROM identity.session") != 1 {
		t.Fatalf("%d bootstraps succeeded: %v", succeeded, results)
	}
	h.verifyAudit()
}

func TestBeginEnrollmentIsUniform(t *testing.T) {
	configured, unconfigured := newHarness(t, settings{}), newHarness(t, settings{noBootstrap: true})
	unconfigured.seedAccount(1, "")
	shape := func(h *harness) *publicapiv1.AuthChallenge {
		begun := rpc(h, beginPath, &publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: meta(), Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(),
			Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_ENROLL.Enum(), Installation: newClaim(t)}, caller{}, &publicapiv1.IdentityServiceBeginAuthenticationResponse{})
		challenge := begun.GetValue().GetChallenge()
		if challenge == nil || len(challenge.GetChallenge()) != 32 || len(challenge.GetOptions().GetUserHandle()) != 32 || challenge.GetRpId() != rpID ||
			challenge.GetOptions().GetUserVerification() != "required" || len(challenge.GetOptions().GetAlgorithms()) != 1 ||
			challenge.GetOptions().GetAlgorithms()[0] != -7 || challenge.GetPurpose() != publicapiv1.AuthPurpose_AUTH_PURPOSE_ENROLL {
			t.Fatalf("challenge %v", challenge)
		}
		return challenge
	}
	a, b := shape(configured), shape(unconfigured)
	a.FlowId, b.FlowId, a.Challenge, b.Challenge, a.ExpiresAt, b.ExpiresAt, a.Options.UserHandle, b.Options.UserHandle = nil, nil, nil, nil, nil, nil, nil, nil
	if !proto.Equal(a, b) {
		t.Fatalf("begin(ENROLL) differs between a pending bootstrap and none:\n%v\n%v", a, b)
	}
}

func TestAPasskeySignsInAndReadsItsAccount(t *testing.T) {
	h := newHarness(t, settings{})
	who := h.seedAccount(1, "ada@example.org")
	claim := newClaim(t)
	native := h.signIn(who, claim, caller{})
	if native.GetPurpose() != publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE || native.GetAccessExpiresAt().GetUnixSeconds()-h.clock.Now().Unix() > 15*60 ||
		native.GetRefreshExpiresAt().GetUnixSeconds()-h.clock.Now().Unix() < 29*24*3600 {
		t.Fatalf("session %v", native)
	}
	bearer := caller{bearer: native.GetAccessToken()}
	profile := rpc(h, profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, bearer, &publicapiv1.IdentityServiceGetProfileResponse{})
	if profile.GetValue().GetProfile().GetPrimaryEmail() != "ada@example.org" || profile.GetValue().GetProfile().GetLocale() != "en-US" {
		t.Fatalf("profile %v", profile)
	}
	credentials := rpc(h, identities, &publicapiv1.IdentityServiceListAuthIdentitiesRequest{Meta: meta(), Page: page(10)}, bearer,
		&publicapiv1.IdentityServiceListAuthIdentitiesResponse{}).GetValue()
	if len(credentials.GetItems()) != 2 || credentials.GetItems()[0].GetKind() != "passkey" || credentials.GetItems()[1].GetKind() != "email_code" ||
		credentials.GetItems()[0].GetLastUsedAt() == nil || credentials.GetPage().GetHasMore() {
		t.Fatalf("credentials %v", credentials)
	}
	sessions := rpc(h, sessionsPath, &publicapiv1.IdentityServiceListSessionsRequest{Meta: meta(), Page: page(10)}, bearer,
		&publicapiv1.IdentityServiceListSessionsResponse{}).GetValue()
	if len(sessions.GetSessions()) != 1 || !sessions.GetSessions()[0].GetCurrent() || sessions.GetSessions()[0].GetProduct() != "arcforges-mobile" {
		t.Fatalf("sessions %v", sessions)
	}
	devices := rpc(h, devicesPath, &publicapiv1.DeviceServiceListRequest{Meta: meta(), Page: page(10)}, bearer, &publicapiv1.DeviceServiceListResponse{}).GetValue()
	if len(devices.GetItems()) != 1 || devices.GetItems()[0].GetName() != "Android phone" || devices.GetItems()[0].GetRevokedAt() != nil {
		t.Fatalf("devices %v", devices)
	}
	// A second sign-in from another phone: two sessions and two devices, paged one at a time.
	h.signIn(who, newClaim(t), caller{})
	first := rpc(h, sessionsPath, &publicapiv1.IdentityServiceListSessionsRequest{Meta: meta(), Page: page(1)}, bearer,
		&publicapiv1.IdentityServiceListSessionsResponse{}).GetValue()
	second := rpc(h, sessionsPath, &publicapiv1.IdentityServiceListSessionsRequest{Meta: meta(), Page: &foundationv1.PageRequest{Limit: proto.Int32(1),
		Cursor: first.GetPage().NextCursor}}, bearer, &publicapiv1.IdentityServiceListSessionsResponse{}).GetValue()
	if len(first.GetSessions()) != 1 || !first.GetPage().GetHasMore() || len(second.GetSessions()) != 1 || second.GetPage().GetHasMore() ||
		bytes.Equal(first.GetSessions()[0].GetSessionId().GetValue(), second.GetSessions()[0].GetSessionId().GetValue()) {
		t.Fatalf("pages %v %v", first, second)
	}
	devicePage := rpc(h, devicesPath, &publicapiv1.DeviceServiceListRequest{Meta: meta(), Page: &foundationv1.PageRequest{Cursor: proto.String("bogus")}},
		bearer, &publicapiv1.DeviceServiceListResponse{})
	if failure(devicePage.GetError()) != "VALIDATION/invalid_cursor" {
		t.Fatalf("a bogus cursor: %s", failure(devicePage.GetError()))
	}
	if h.audits("identity.sign_in.succeeded") != 2 {
		t.Fatal("sign-ins are audited")
	}
	h.verifyAudit()
}

func TestPasskeySignInsOutsideTheRulesAreRefused(t *testing.T) {
	h := newHarness(t, settings{})
	who := h.seedAccount(1, "")
	complete := func(challenge *publicapiv1.AuthChallenge, assertion *publicapiv1.WebAuthnAssertion) string {
		response := rpc(h, completePath, &publicapiv1.IdentityServiceCompleteAuthenticationRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
			Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertion}}}, caller{}, &publicapiv1.IdentityServiceCompleteAuthenticationResponse{})
		return failure(response.GetError())
	}
	// A completed flow presented again is code_reused.
	challenge := h.beginPasskey(newClaim(t), caller{})
	assertion := assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge()))
	if result := complete(challenge, assertion); result != "" {
		t.Fatalf("first completion: %s", result)
	}
	if result := complete(challenge, assertion); result != "CONFLICT/code_reused" {
		t.Fatalf("a completed flow again: %s", result)
	}
	// An unknown credential, a missing user verification and a counter that does not advance are all unauthenticated, and
	// end the flow (its one attempt): a second try is expired.
	stranger := h.seedAccount(1, "")
	unknown := virtual.New(rpID, origin)
	_, unknownKey := unknown.Create(randomBytes(t, 32), stranger.handle)
	challenge = h.beginPasskey(newClaim(t), caller{})
	if result := complete(challenge, assertionOf(unknown.Assert(unknownKey, challenge.GetChallenge()))); result != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("an unknown credential: %s", result)
	}
	if result := complete(challenge, assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge()))); result != "STATE/expired" {
		t.Fatalf("an ended flow: %s", result)
	}
	challenge = h.beginPasskey(newClaim(t), caller{})
	who.authenticator.SkipUV = true
	if result := complete(challenge, assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge()))); result != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("no user verification: %s", result)
	}
	who.authenticator.SkipUV = false
	challenge = h.beginPasskey(newClaim(t), caller{})
	if result := complete(challenge, assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge(), 1))); result != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("a counter that did not advance: %s", result)
	}
	// An expired flow.
	challenge = h.beginPasskey(newClaim(t), caller{})
	h.clock.Advance(6 * time.Minute)
	if result := complete(challenge, assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge()))); result != "STATE/expired" {
		t.Fatalf("an expired flow: %s", result)
	}
	// A suspended account is refused exactly like an unknown credential.
	if _, err := h.migration.Exec(context.Background(), "UPDATE identity.user SET state = 3 WHERE user_id = $1", who.id); err != nil {
		t.Fatal(err)
	}
	challenge = h.beginPasskey(newClaim(t), caller{})
	if result := complete(challenge, assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge()))); result != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("a suspended account: %s", result)
	}
	if _, err := h.migration.Exec(context.Background(), "UPDATE identity.user SET state = 1 WHERE user_id = $1", who.id); err != nil {
		t.Fatal(err)
	}
	// Cross-use: an enrollment flow cannot complete a sign-in, a sign-in flow cannot complete an enrollment.
	enrollment := rpc(h, beginPath, &publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: meta(), Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(),
		Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_ENROLL.Enum(), Installation: newClaim(t)}, caller{}, &publicapiv1.IdentityServiceBeginAuthenticationResponse{}).
		GetValue().GetChallenge()
	if result := complete(enrollment, assertionOf(who.authenticator.Assert(who.key, enrollment.GetChallenge()))); result != "STATE/not_found" {
		t.Fatalf("an enrollment flow as a sign-in: %s", result)
	}
	signInFlow := h.beginPasskey(newClaim(t), caller{})
	creation, _ := virtual.New(rpID, origin).Create(signInFlow.GetChallenge(), randomBytes(t, 32))
	response := rpc(h, enrollPath, &publicapiv1.IdentityServiceCompleteEnrollmentRequest{Meta: meta(), FlowId: signInFlow.GetFlowId(),
		Proof:      &publicapiv1.EnrollmentProof{Proof: &publicapiv1.EnrollmentProof_LocalCode{LocalCode: h.bootstrap}},
		Credential: &publicapiv1.CredentialReplacement{Replacement: &publicapiv1.CredentialReplacement_Passkey{Passkey: creationOf(creation)}},
		Profile:    &publicapiv1.ProfileUpdate{DisplayName: proto.String("Owner")}}, caller{}, &publicapiv1.IdentityServiceCompleteEnrollmentResponse{})
	if result := failure(response.GetError()); result != "AUTHENTICATION/unauthenticated" {
		// An account exists here, so the bootstrap is refused before the flow is read.
		t.Fatalf("a sign-in flow as an enrollment: %s", result)
	}
	// A foreign installation: the claim names another account's installation.
	other := h.seedAccount(1, "")
	shared := newClaim(t)
	h.signIn(other, shared, caller{})
	challenge = h.beginPasskey(shared, caller{})
	if result := complete(challenge, assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge()))); result != "AUTHORIZATION/permission_denied" {
		t.Fatalf("another account's installation: %s", result)
	}
	// Claims outside the native product and platform rules.
	for name, change := range map[string]func(*publicapiv1.InstallationClaim){
		"no claim":         nil,
		"the node product": func(c *publicapiv1.InstallationClaim) { c.Product = proto.String("arcforges-node") },
		"a desktop":        func(c *publicapiv1.InstallationClaim) { c.Platform = proto.String("windows-11") },
		"a bad version":    func(c *publicapiv1.InstallationClaim) { c.AppVersion = proto.String("1.0 beta") },
	} {
		claim := newClaim(t)
		if change == nil {
			claim = nil
		} else {
			change(claim)
		}
		begun := rpc(h, beginPath, &publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: meta(), Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(),
			Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum(), Installation: claim}, caller{}, &publicapiv1.IdentityServiceBeginAuthenticationResponse{})
		if failure(begun.GetError()) != "VALIDATION/invalid_argument" {
			t.Errorf("%s: %s", name, failure(begun.GetError()))
		}
	}
	for name, request := range map[string]*publicapiv1.IdentityServiceBeginAuthenticationRequest{
		"password":         {Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSWORD.Enum(), Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum()},
		"recovery":         {Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(), Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_RECOVER.Enum()},
		"step-up":          {Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(), Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_STEP_UP.Enum()},
		"e-mail enroll":    {Method: publicapiv1.AuthMethod_AUTH_METHOD_EMAIL.Enum(), Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_ENROLL.Enum(), LoginHint: proto.String("a@b.example")},
		"another provider": {Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(), Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum(), ProviderId: proto.String("oidc")},
		"no method":        {Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum()},
	} {
		request.Meta, request.Installation = meta(), newClaim(t)
		begun := rpc(h, beginPath, request, caller{}, &publicapiv1.IdentityServiceBeginAuthenticationResponse{})
		if failure(begun.GetError()) != "VALIDATION/invalid_argument" {
			t.Errorf("%s: %s", name, failure(begun.GetError()))
		}
	}
	h.verifyAudit()
}

func TestRefreshRotatesAndAReusedTokenRevokesTheFamily(t *testing.T) {
	h := newHarness(t, settings{})
	who := h.seedAccount(1, "")
	claim := newClaim(t)
	native := h.signIn(who, claim, caller{})
	refresh := func(token string, installation *foundationv1.Id) *publicapiv1.IdentityServiceRefreshSessionResponse {
		response := rpc(h, refreshPath, &publicapiv1.IdentityServiceRefreshSessionRequest{Meta: meta(), RefreshToken: proto.String(token),
			InstallationId: installation}, caller{}, &publicapiv1.IdentityServiceRefreshSessionResponse{})
		if value := response.GetValue().GetSession(); value != nil {
			h.remember(value.GetAccessToken(), value.GetRefreshToken())
		}
		return response
	}
	if result := failure(refresh(native.GetRefreshToken(), &foundationv1.Id{Value: randomBytes(t, 16)}).GetError()); result != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("another installation: %s", result)
	}
	rotated := refresh(native.GetRefreshToken(), claim.GetInstallationId())
	if rotated.GetError() != nil || rotated.GetValue().GetSession().GetAccessToken() == native.GetAccessToken() ||
		!bytes.Equal(rotated.GetValue().GetSession().GetSessionId().GetValue(), native.GetSessionId().GetValue()) {
		t.Fatalf("rotation %v", rotated)
	}
	next := rotated.GetValue().GetSession()
	// The previous access token is gone; the new one works.
	if answer := h.post(profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{bearer: native.GetAccessToken()}); answer.status != "16" ||
		answer.message != "auth.unauthenticated" {
		t.Fatalf("the rotated access token: %+v", answer)
	}
	if rpc(h, profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{bearer: next.GetAccessToken()},
		&publicapiv1.IdentityServiceGetProfileResponse{}).GetError() != nil {
		t.Fatal("the new access token")
	}
	// The lost-response case (n3): the client presents the spent token again. Strict rotation revokes the family.
	if result := failure(refresh(native.GetRefreshToken(), claim.GetInstallationId()).GetError()); result != "AUTHENTICATION/credential_revoked" {
		t.Fatalf("a reused refresh token: %s", result)
	}
	if h.audits("identity.session.refresh_reused") != 1 || h.count("SELECT count(*) FROM identity.session WHERE revoke_reason = 4") != 1 {
		t.Fatal("the reuse is audited and revokes the family")
	}
	if answer := h.post(profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{bearer: next.GetAccessToken()}); answer.status != "16" ||
		answer.message != "auth.credential_revoked" {
		t.Fatalf("the family's newest access token: %+v", answer)
	}
	if result := failure(refresh(next.GetRefreshToken(), claim.GetInstallationId()).GetError()); result != "AUTHENTICATION/credential_revoked" {
		t.Fatalf("the family's newest refresh token: %s", result)
	}

	// Two concurrent refreshes with one token: one rotates, the other is a reuse and revokes the family.
	fresh := h.signIn(who, newClaim(t), caller{})
	installation := h.migrationInstallation(fresh)
	var wait sync.WaitGroup
	results := make([]string, 2)
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index] = failure(refresh(fresh.GetRefreshToken(), installation).GetError())
		}()
	}
	wait.Wait()
	if !(results[0] == "" && results[1] == "AUTHENTICATION/credential_revoked" || results[1] == "" && results[0] == "AUTHENTICATION/credential_revoked") {
		t.Fatalf("concurrent refreshes: %v", results)
	}

	// The access token expires before the refresh token: token_expired as a transport status, then a refresh works.
	late := h.signIn(who, claim2(t, h), caller{})
	h.clock.Advance(16 * time.Minute)
	if answer := h.post(profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{bearer: late.GetAccessToken()}); answer.status != "16" ||
		answer.message != "auth.token_expired" {
		t.Fatalf("an expired access token: %+v", answer)
	}
	lateInstallation := h.migrationInstallation(late)
	renewed := refresh(late.GetRefreshToken(), lateInstallation)
	if renewed.GetError() != nil {
		t.Fatalf("refresh after the access expiry: %s", failure(renewed.GetError()))
	}
	// Both sides of the refresh idle lifetime.
	h.clock.Advance(30*24*time.Hour - time.Minute)
	stillAlive := refresh(renewed.GetValue().GetSession().GetRefreshToken(), lateInstallation)
	if stillAlive.GetError() != nil {
		t.Fatalf("just inside the idle lifetime: %s", failure(stillAlive.GetError()))
	}
	h.clock.Advance(30*24*time.Hour + time.Minute)
	if result := failure(refresh(stillAlive.GetValue().GetSession().GetRefreshToken(), lateInstallation).GetError()); result != "AUTHENTICATION/token_expired" {
		t.Fatalf("past the idle lifetime: %s", result)
	}
	if result := failure(refresh("afr1.not-a-token", lateInstallation).GetError()); result != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("a malformed token: %s", result)
	}
	h.verifyAudit()
}

// claim2 is a fresh claim (a helper so a test can sign in again without naming the installation).
func claim2(t *testing.T, _ *harness) *publicapiv1.InstallationClaim { return newClaim(t) }

// migrationInstallation is the installation ID of a session, read from the store.
func (h *harness) migrationInstallation(native *publicapiv1.NativeSession) *foundationv1.Id {
	h.t.Helper()
	var sessionID, installation platform.ID
	copy(sessionID[:], native.GetSessionId().GetValue())
	if err := h.migration.QueryRow(context.Background(), "SELECT installation_id FROM identity.session WHERE session_id = $1", sessionID).
		Scan(&installation); err != nil {
		h.t.Fatal(err)
	}
	return &foundationv1.Id{Value: installation[:]}
}
