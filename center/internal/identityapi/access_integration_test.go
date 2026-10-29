// SPDX-License-Identifier: AGPL-3.0-only

package identityapi_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// issued is a session written straight to the store: a native one (any scope, as later tasks will issue them) or a browser one.
type issued struct {
	access, refresh string
	handle, csrf    string
	installation    platform.ID
	sessionID       platform.ID
}

func (h *harness) issue(userID platform.ID, scope session.Scope, browser bool) issued {
	h.t.Helper()
	ctx := context.Background()
	tx, err := h.migration.Begin(ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	now := h.clock.Now()
	policy := config.DefaultIdentityPolicy()
	var result issued
	grant := session.Grant{UserID: userID, Scope: scope, Purpose: session.PurposeAuthenticate, AuthMethod: 1, AuthenticatedAt: now}
	if browser {
		grant.DeviceID, grant.InstallationID, err = device.EnsureBrowser(ctx, tx, userID, platform.NewID(), "1.0.0", now)
		if err != nil {
			h.t.Fatal(err)
		}
		grant.Product = device.ProductWeb
		cookie, err := session.IssueBrowser(ctx, tx, policy, grant, origin, now)
		if err != nil {
			h.t.Fatal(err)
		}
		result = issued{handle: cookie.Handle, csrf: cookie.CSRF, installation: grant.InstallationID, sessionID: cookie.SessionID}
		h.remember(cookie.Handle, cookie.CSRF)
	} else {
		grant.DeviceID, grant.InstallationID, grant.Product = platform.NewID(), platform.NewID(), device.ProductMobile
		platformNumber, platformText := int16(device.PlatformAndroid), "android-15"
		if scope == session.ScopeNode {
			grant.Product, platformNumber, platformText = device.ProductNode, int16(device.PlatformLinux), "linux-x64"
		}
		if _, err = tx.Exec(ctx, `INSERT INTO device.device (device_id, user_id, display_name, platform, trust_level, remote_enabled, first_seen_at, last_seen_at, rev)
VALUES ($1, $2, 'Inserted', $3, 1, false, $4, $4, 1)`, grant.DeviceID, userID, platformNumber, now); err != nil {
			h.t.Fatal(err)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO device.installation (installation_id, device_id, user_id, product_id, app_version, platform, installed_at, last_active_at, rev)
VALUES ($1, $2, $3, $4, '1.0.0', $5, $6, $6, 1)`, grant.InstallationID, grant.DeviceID, userID, grant.Product, platformText, now); err != nil {
			h.t.Fatal(err)
		}
		native, err := session.IssueNative(ctx, tx, policy, grant, now)
		if err != nil {
			h.t.Fatal(err)
		}
		result = issued{access: native.AccessToken, refresh: native.RefreshToken, installation: grant.InstallationID, sessionID: native.SessionID}
		h.remember(native.AccessToken, native.RefreshToken)
	}
	if err = tx.Commit(ctx); err != nil {
		h.t.Fatal(err)
	}
	return result
}

// sessionReads are the session methods A1a serves, with an empty request each.
func sessionReads() map[string]proto.Message {
	return map[string]proto.Message{
		profilePath:  &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()},
		identities:   &publicapiv1.IdentityServiceListAuthIdentitiesRequest{Meta: meta(), Page: page(10)},
		sessionsPath: &publicapiv1.IdentityServiceListSessionsRequest{Meta: meta(), Page: page(10)},
		devicesPath:  &publicapiv1.DeviceServiceListRequest{Meta: meta(), Page: page(10)},
	}
}

var operationIDs = map[string]string{profilePath: "identity.getProfile", identities: "identity.listAuthIdentities", sessionsPath: "identity.listSessions",
	devicesPath: "device.list"}

// domainError is the ArcError of a completed call (field 3 of every reply).
func domainError(t *testing.T, answer reply) *foundationv1.ArcError {
	t.Helper()
	if answer.status != "0" {
		t.Fatalf("grpc-status %q %q", answer.status, answer.message)
	}
	// Every reply carries its ArcError as field 3 of its outcome; the value (field 2) differs per method and is skipped.
	for message := answer.body; len(message) > 0; {
		number, kind, length := protowire.ConsumeTag(message)
		if length < 0 {
			t.Fatal("a malformed reply")
		}
		message = message[length:]
		size := protowire.ConsumeFieldValue(number, kind, message)
		if size < 0 {
			t.Fatal("a malformed reply")
		}
		if number == 3 && kind == protowire.BytesType {
			payload, _ := protowire.ConsumeBytes(message)
			var value foundationv1.ArcError
			if err := proto.Unmarshal(payload, &value); err != nil {
				t.Fatal(err)
			}
			return &value
		}
		message = message[size:]
	}
	return nil
}

// writes is a fingerprint of every identity and device row (revisions and states), to show that a refused call wrote nothing.
func (h *harness) writes() string {
	h.t.Helper()
	var fingerprint string
	err := h.migration.QueryRow(context.Background(), `SELECT concat_ws('|',
    (SELECT coalesce(sum(rev), 0) FROM identity.user), (SELECT coalesce(sum(rev), 0) FROM identity.session), (SELECT count(*) FROM identity.session),
    (SELECT coalesce(sum(rev), 0) FROM identity.auth_identity), (SELECT count(*) FROM identity.auth_flow), (SELECT coalesce(sum(attempts), 0) FROM identity.auth_flow),
    (SELECT coalesce(sum(rev), 0) FROM device.device), (SELECT coalesce(sum(rev), 0) FROM device.installation), (SELECT count(*) FROM identity.spent_refresh),
    (SELECT coalesce(sum(count), 0) FROM platform.rate_limit))`).Scan(&fingerprint)
	if err != nil {
		h.t.Fatal(err)
	}
	return fingerprint
}

// TestOnlyAccountSessionsReachTheSessionMethods is the scope by method matrix of SEC-01: node, push and automation credentials are
// refused with permission_denied before any handler runs, nothing is written, and each refusal is audited; mobile.limited reaches
// every A1a read; a restricted account reaches only its security reads.
func TestOnlyAccountSessionsReachTheSessionMethods(t *testing.T) {
	h := newHarness(t, settings{})
	who := h.seedAccount(1, "")
	for _, scope := range []session.Scope{session.ScopeNode, session.ScopePush, session.ScopeAutomation} {
		credential := h.issue(who.id, scope, false)
		for path, request := range sessionReads() {
			before, audits := h.writes(), h.audits("access.refused")
			refusal := domainError(t, h.post(path, request, caller{bearer: credential.access}))
			if failure(refusal) != "AUTHORIZATION/permission_denied" || refusal.GetDetails().GetState().GetReason() != operationIDs[path] {
				t.Errorf("%s on %s: %v", scope, path, refusal)
			}
			if h.writes() != before || h.audits("access.refused") != audits+1 {
				t.Errorf("%s on %s wrote or was not audited", scope, path)
			}
		}
		refreshed := rpc(h, refreshPath, &publicapiv1.IdentityServiceRefreshSessionRequest{Meta: meta(), RefreshToken: proto.String(credential.refresh),
			InstallationId: &foundationv1.Id{Value: credential.installation[:]}}, caller{}, &publicapiv1.IdentityServiceRefreshSessionResponse{})
		if failure(refreshed.GetError()) != "AUTHORIZATION/permission_denied" {
			t.Errorf("%s refresh: %s", scope, failure(refreshed.GetError()))
		}
	}
	// A revoked node credential is refused as revoked, before its scope is looked at.
	node := h.issue(who.id, session.ScopeNode, false)
	if _, err := h.migration.Exec(context.Background(), "UPDATE identity.session SET revoked_at = now(), revoke_reason = 5 WHERE session_id = $1", node.sessionID); err != nil {
		t.Fatal(err)
	}
	refreshed := rpc(h, refreshPath, &publicapiv1.IdentityServiceRefreshSessionRequest{Meta: meta(), RefreshToken: proto.String(node.refresh),
		InstallationId: &foundationv1.Id{Value: node.installation[:]}}, caller{}, &publicapiv1.IdentityServiceRefreshSessionResponse{})
	if failure(refreshed.GetError()) != "AUTHENTICATION/credential_revoked" {
		t.Fatalf("a revoked node refresh: %s", failure(refreshed.GetError()))
	}
	if answer := h.post(profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{bearer: node.access}); answer.status != "16" ||
		answer.message != "auth.credential_revoked" {
		t.Fatalf("a revoked node bearer: %+v", answer)
	}
	// mobile.limited reaches every A1a read.
	limited := h.issue(who.id, session.ScopeMobileLimited, false)
	for path, request := range sessionReads() {
		if refusal := domainError(t, h.post(path, request, caller{bearer: limited.access})); refusal != nil {
			t.Errorf("mobile.limited on %s: %s", path, failure(refusal))
		}
	}
	// A restricted account reaches its security reads, not its profile.
	restricted := h.seedAccount(2, "")
	credential := h.issue(restricted.id, session.ScopeAccount, false)
	for path, request := range sessionReads() {
		refusal := domainError(t, h.post(path, request, caller{bearer: credential.access}))
		if path == profilePath {
			if failure(refusal) != "AUTHORIZATION/permission_denied" {
				t.Errorf("a restricted account's profile: %s", failure(refusal))
			}
		} else if refusal != nil {
			t.Errorf("a restricted account on %s: %s", path, failure(refusal))
		}
	}
	h.verifyAudit()
}

func TestAccountsSeeOnlyTheirOwnSessionsDevicesAndCredentials(t *testing.T) {
	h := newHarness(t, settings{})
	alice, bob := h.seedAccount(1, "alice@example.org"), h.seedAccount(1, "bob@example.org")
	aliceSession := h.signIn(alice, newClaim(t), caller{})
	bobSession := h.signIn(bob, newClaim(t), caller{})
	h.issue(bob.id, session.ScopeAccount, true)
	ids := func(native *publicapiv1.NativeSession) (sessions, devices, credentials [][]byte) {
		from := caller{bearer: native.GetAccessToken()}
		for _, item := range rpc(h, sessionsPath, &publicapiv1.IdentityServiceListSessionsRequest{Meta: meta(), Page: page(100)}, from,
			&publicapiv1.IdentityServiceListSessionsResponse{}).GetValue().GetSessions() {
			sessions = append(sessions, item.GetSessionId().GetValue())
		}
		for _, item := range rpc(h, devicesPath, &publicapiv1.DeviceServiceListRequest{Meta: meta(), Page: page(100)}, from,
			&publicapiv1.DeviceServiceListResponse{}).GetValue().GetItems() {
			devices = append(devices, item.GetDeviceId().GetValue())
		}
		for _, item := range rpc(h, identities, &publicapiv1.IdentityServiceListAuthIdentitiesRequest{Meta: meta(), Page: page(100)}, from,
			&publicapiv1.IdentityServiceListAuthIdentitiesResponse{}).GetValue().GetItems() {
			credentials = append(credentials, item.GetCredentialId().GetValue())
		}
		return
	}
	aliceSessions, aliceDevices, aliceCredentials := ids(aliceSession)
	bobSessions, bobDevices, bobCredentials := ids(bobSession)
	if len(aliceSessions) != 1 || len(aliceDevices) != 1 || len(aliceCredentials) != 2 || len(bobSessions) != 2 || len(bobDevices) != 2 || len(bobCredentials) != 2 {
		t.Fatalf("counts %d %d %d / %d %d %d", len(aliceSessions), len(aliceDevices), len(aliceCredentials), len(bobSessions), len(bobDevices), len(bobCredentials))
	}
	for _, mine := range [][][]byte{aliceSessions, aliceDevices, aliceCredentials} {
		for _, theirs := range [][][]byte{bobSessions, bobDevices, bobCredentials} {
			for _, a := range mine {
				for _, b := range theirs {
					if bytes.Equal(a, b) {
						t.Fatal("an account sees another account's row")
					}
				}
			}
		}
	}
	profile := rpc(h, profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{bearer: aliceSession.GetAccessToken()},
		&publicapiv1.IdentityServiceGetProfileResponse{}).GetValue().GetProfile()
	if profile.GetPrimaryEmail() != "alice@example.org" {
		t.Fatal("the profile is the caller's")
	}
}

func TestABrowserSessionAuthenticatesByCookieOriginAndCSRF(t *testing.T) {
	h := newHarness(t, settings{})
	who := h.seedAccount(1, "")
	cookie := h.issue(who.id, session.ScopeAccount, true)
	other := h.issue(who.id, session.ScopeAccount, true)
	good := caller{cookie: cookie.handle, csrf: cookie.csrf, origin: origin}
	sessions := rpc(h, sessionsPath, &publicapiv1.IdentityServiceListSessionsRequest{Meta: meta(), Page: page(10)}, good, &publicapiv1.IdentityServiceListSessionsResponse{})
	if sessions.GetError() != nil || len(sessions.GetValue().GetSessions()) != 2 || sessions.GetValue().GetSessions()[0].GetProduct() != "arcforges-web" {
		t.Fatalf("sessions by cookie %v", sessions)
	}
	current := 0
	for _, item := range sessions.GetValue().GetSessions() {
		if item.GetCurrent() {
			current++
			if !bytes.Equal(item.GetSessionId().GetValue(), cookie.sessionID[:]) {
				t.Fatal("the current session is the cookie's")
			}
		}
	}
	if current != 1 {
		t.Fatal("one current session")
	}
	devices := rpc(h, devicesPath, &publicapiv1.DeviceServiceListRequest{Meta: meta(), Page: page(10)}, good, &publicapiv1.DeviceServiceListResponse{}).GetValue()
	if len(devices.GetItems()) != 2 || devices.GetItems()[0].GetPlatform() != "web" || devices.GetItems()[0].GetName() != "Web browser" {
		t.Fatalf("web devices %v", devices)
	}
	refused := map[string]caller{
		"no CSRF token":             {cookie: cookie.handle, origin: origin},
		"another session's CSRF":    {cookie: cookie.handle, csrf: other.csrf, origin: origin},
		"another origin":            {cookie: cookie.handle, csrf: cookie.csrf, origin: "https://evil.example.test"},
		"no origin":                 {cookie: cookie.handle, csrf: cookie.csrf},
		"the handle as CSRF token":  {cookie: cookie.handle, csrf: cookie.handle, origin: origin},
		"a cookie and a bearer":     {cookie: cookie.handle, csrf: cookie.csrf, origin: origin, bearer: "afa1." + cookie.handle},
		"an unknown cookie":         {cookie: session.NewSecret().Text(), csrf: cookie.csrf, origin: origin},
		"a malformed cookie":        {cookie: "x", csrf: cookie.csrf, origin: origin},
		"the CSRF token as cookie":  {cookie: cookie.csrf, csrf: cookie.csrf, origin: origin},
		"the access-token prefix":   {cookie: "afa1." + cookie.handle, csrf: cookie.csrf, origin: origin},
		"a lower-case header value": {cookie: cookie.handle, csrf: strings.ToLower(cookie.csrf), origin: origin},
	}
	for name, from := range refused {
		answer := h.post(profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, from)
		if answer.status != "7" && answer.status != "16" {
			t.Errorf("%s: %+v", name, answer)
		}
	}
	// Idle expiry: 30 minutes without a page load (RPCs never renew).
	h.clock.Advance(29 * time.Minute)
	if rpc(h, profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, good, &publicapiv1.IdentityServiceGetProfileResponse{}).GetError() != nil {
		t.Fatal("inside the idle expiry")
	}
	h.clock.Advance(2 * time.Minute)
	if answer := h.post(profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, good); answer.status != "16" {
		t.Fatalf("past the idle expiry: %+v", answer)
	}
	// A browser device is listed only while it has a live session.
	native := h.signIn(who, newClaim(t), caller{})
	devices = rpc(h, devicesPath, &publicapiv1.DeviceServiceListRequest{Meta: meta(), Page: page(10)}, caller{bearer: native.GetAccessToken()},
		&publicapiv1.DeviceServiceListResponse{}).GetValue()
	if len(devices.GetItems()) != 1 || devices.GetItems()[0].GetPlatform() != "android" {
		t.Fatalf("devices after the browser sessions expired %v", devices)
	}
	// A revoked browser session is refused.
	fresh := h.issue(who.id, session.ScopeAccount, true)
	if _, err := h.migration.Exec(context.Background(), "UPDATE identity.session SET revoked_at = now(), revoke_reason = 1 WHERE session_id = $1", fresh.sessionID); err != nil {
		t.Fatal(err)
	}
	if answer := h.post(profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{cookie: fresh.handle, csrf: fresh.csrf, origin: origin}); answer.status != "16" {
		t.Fatalf("a revoked browser session: %+v", answer)
	}
}

func TestAWorkspaceInTheMetaIsRefused(t *testing.T) {
	h := newHarness(t, settings{})
	who := h.seedAccount(1, "")
	native := h.signIn(who, newClaim(t), caller{})
	scoped := &foundationv1.RequestMeta{WorkspaceId: &foundationv1.Id{Value: randomBytes(t, 16)}}
	refusal := domainError(t, h.post(profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: scoped}, caller{bearer: native.GetAccessToken()}))
	if failure(refusal) != "VALIDATION/invalid_argument" || refusal.GetDetails().GetState().GetReason() != "meta.workspace_id: not_admitted" {
		t.Fatalf("a workspace on a session method: %v", refusal)
	}
	begun := rpc(h, beginPath, &publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: scoped, Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(),
		Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum(), Installation: newClaim(t)}, caller{}, &publicapiv1.IdentityServiceBeginAuthenticationResponse{})
	if failure(begun.GetError()) != "VALIDATION/invalid_argument" || h.count("SELECT count(*) FROM identity.auth_flow") != 1 {
		t.Fatalf("a workspace on an anonymous method: %s", failure(begun.GetError()))
	}
}

// TestADisabledSurfaceAnswersNotActivated: with the identity surface off, every identity method is answered with the domain
// refusal STATE/not_activated (the bytes the Worker sends, plus the correlation id) before any credential, body or store is read.
func TestADisabledSurfaceAnswersNotActivated(t *testing.T) {
	h := newHarness(t, settings{surfaces: "none"})
	for _, method := range routes.IdentityMethods() {
		refusal := domainError(t, h.post(method.Path, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{bearer: "afa1.unknown-token-value-xx"}))
		if failure(refusal) != "STATE/not_activated" || refusal.GetDetails().GetState().GetReason() != "identity" || len(refusal.GetCorrelationId().GetValue()) != 16 {
			t.Errorf("%s: %v", method.Path, refusal)
		}
	}
	if h.count("SELECT count(*) FROM identity.auth_flow") != 0 || h.count("SELECT count(*) FROM platform.rate_limit") != 0 {
		t.Fatal("a disabled surface touched the store")
	}
}

// TestTheServedMethodsAreExactlyTheIdentitySet (F13): of the contract's IdentityService, DeviceService and WorkspaceService methods
// the composed center serves exactly the pinned set of A1a (sign-in, refresh, reads) and A1b (step-up, profile, passkey
// registration, credentials, sign-out and revocation, devices); every other method (AF-ID-02's among them) is UNIMPLEMENTED, and the
// Worker table lists only the set.
func TestTheServedMethodsAreExactlyTheIdentitySet(t *testing.T) {
	h := newHarness(t, settings{})
	pinned := map[string]bool{}
	for _, name := range []string{"IdentityService/BeginAuthentication", "IdentityService/CompleteAuthentication", "IdentityService/RequestEmailCode",
		"IdentityService/RedeemEmailCode", "IdentityService/CompleteEnrollment", "IdentityService/ListAuthProviders", "IdentityService/RefreshSession",
		"IdentityService/GetProfile", "IdentityService/ListAuthIdentities", "IdentityService/ListSessions", "DeviceService/List",
		"IdentityService/BeginStepUp", "IdentityService/CompleteStepUp", "IdentityService/UpdateProfile", "IdentityService/BeginPasskeyRegistration",
		"IdentityService/CompletePasskeyRegistration", "IdentityService/RenameAuthIdentity", "IdentityService/RemoveAuthIdentity",
		"IdentityService/RevokeSession", "IdentityService/RevokeAllSessions", "DeviceService/Rename", "DeviceService/Revoke"} {
		pinned["/arcforges.publicapi.v1."+name] = true
	}
	registered := map[string]bool{}
	for _, method := range routes.IdentityMethods() {
		registered[method.Path] = true
	}
	if len(registered) != len(pinned) {
		t.Fatalf("the registrations are not the pinned set: %v", registered)
	}
	services := publicapiv1.File_arcforges_publicapi_v1_identity_proto.Services()
	total := 0
	for _, service := range []protoreflect.Name{"IdentityService", "DeviceService", "WorkspaceService"} {
		methods := services.ByName(service).Methods()
		for index := range methods.Len() {
			path := "/arcforges.publicapi.v1." + string(service) + "/" + string(methods.Get(index).Name())
			total++
			answer := h.post(path, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{})
			served := !(answer.status == "12" && answer.message == "unimplemented")
			if served != pinned[path] || registered[path] != pinned[path] {
				t.Errorf("%s: served %v, pinned %v (%+v)", path, served, pinned[path], answer)
			}
		}
	}
	if total < 40 {
		t.Fatalf("only %d contract methods", total)
	}
	table, err := routes.Table(mustCenter(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range table.SurfaceRows {
		if !pinned[row.Path] {
			t.Errorf("the Worker table lists %s", row.Path)
		}
	}
}

func mustCenter(t *testing.T) []routes.Module {
	t.Helper()
	modules, err := routes.Center()
	if err != nil {
		t.Fatal(err)
	}
	return modules
}

// TestARefusedAuditRefusesTheSignIn (F5): a sign-in whose audit event cannot be written is refused and writes nothing; once the
// audit works again the same path succeeds and the chain verifies.
func TestARefusedAuditRefusesTheSignIn(t *testing.T) {
	h := newHarness(t, settings{})
	who := h.seedAccount(1, "")
	ctx := context.Background()
	for _, statement := range []string{
		"CREATE SCHEMA testfault",
		"CREATE FUNCTION testfault.refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit refused by the test'; END; $$",
		"CREATE TRIGGER test_refuse_audit BEFORE INSERT ON audit.audit_event FOR EACH ROW EXECUTE FUNCTION testfault.refuse()",
	} {
		if _, err := h.migration.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	challenge := h.beginPasskey(newClaim(t), caller{})
	response := rpc(h, completePath, &publicapiv1.IdentityServiceCompleteAuthenticationRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
		Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertionOf(who.authenticator.Assert(who.key, challenge.GetChallenge()))}}},
		caller{}, &publicapiv1.IdentityServiceCompleteAuthenticationResponse{})
	if failure(response.GetError()) != "INTERNAL/internal" || h.count("SELECT count(*) FROM identity.session") != 0 ||
		h.count("SELECT count(*) FROM device.device") != 0 || h.count("SELECT count(*) FROM audit.audit_event") != 0 {
		t.Fatalf("a sign-in without its audit: %s", failure(response.GetError()))
	}
	if _, err := h.migration.Exec(ctx, "DROP TRIGGER test_refuse_audit ON audit.audit_event"); err != nil {
		t.Fatal(err)
	}
	h.signIn(who, newClaim(t), caller{})
	if h.count("SELECT count(*) FROM identity.session") != 1 || h.audits("identity.sign_in.succeeded") != 1 {
		t.Fatal("the sign-in after the audit works again")
	}
	h.verifyAudit()
}

func TestRateLimitsKeyByPrefixAndAccount(t *testing.T) {
	h := newHarness(t, settings{policy: `{"signInPerPrefixLimit": 3, "signInFailuresAccountLimit": 2}`})
	begin := func(ip string) *foundationv1.ArcError {
		return rpc(h, beginPath, &publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: meta(), Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(),
			Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum(), Installation: newClaim(t)}, caller{ip: ip},
			&publicapiv1.IdentityServiceBeginAuthenticationResponse{}).GetError()
	}
	for _, ip := range []string{"203.0.113.5", "203.0.113.6", "::ffff:203.0.113.7"} {
		if refusal := begin(ip); refusal != nil {
			t.Fatalf("within the limit from %s: %s", ip, failure(refusal))
		}
	}
	refusal := begin("203.0.113.99")
	limit := refusal.GetDetails().GetLimit()
	if failure(refusal) != "RESOURCE/rate_limited" || limit.GetLimitName() != "sign_in_prefix" || limit.GetMaximum().GetValue() != "3" ||
		refusal.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME || refusal.GetRetry().GetRetryAt().GetUnixSeconds() <= h.clock.Now().Unix() {
		t.Fatalf("the fourth request of a /24: %v", refusal)
	}
	if begin("203.0.113.100") == nil || begin("203.0.114.5") != nil {
		t.Fatal("another /24 has its own bucket")
	}
	for _, ip := range []string{"2001:db8:0:1::1", "2001:db8:0:ff::2", "2001:db8::3"} {
		if refusal := begin(ip); refusal != nil {
			t.Fatalf("within the IPv6 limit from %s: %s", ip, failure(refusal))
		}
	}
	if begin("2001:db8:0:10::9") == nil || begin("2001:db8:0:100::1") != nil {
		t.Fatal("IPv6 buckets are /56 networks")
	}
	// Every refusal of a bucket's window is counted; only the first is audited.
	if h.audits("identity.rate_limited") != 2 {
		t.Fatalf("rate-limit audits %d", h.audits("identity.rate_limited"))
	}
	// Per account: failed proofs from two prefixes against one account refuse a third prefix too.
	who := h.seedAccount(1, "")
	wrong := func(ip string) string {
		challenge := h.beginPasskey(newClaim(t), caller{ip: ip})
		bad := who.authenticator.Assert(who.key, randomBytes(t, 32)) // signed over another challenge
		return failure(rpc(h, completePath, &publicapiv1.IdentityServiceCompleteAuthenticationRequest{Meta: meta(), FlowId: challenge.GetFlowId(),
			Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertionOf(bad)}}}, caller{ip: ip},
			&publicapiv1.IdentityServiceCompleteAuthenticationResponse{}).GetError())
	}
	if wrong("192.0.2.1") != "AUTHENTICATION/unauthenticated" || wrong("198.51.100.1") != "AUTHENTICATION/unauthenticated" {
		t.Fatal("failed proofs")
	}
	if result := wrong("100.64.0.1"); result != "RESOURCE/rate_limited" {
		t.Fatalf("a third prefix against the same account: %s", result)
	}
	// The window ends.
	h.clock.Advance(11 * time.Minute)
	if begin("203.0.113.5") != nil {
		t.Fatal("a new window")
	}
	h.signIn(who, newClaim(t), caller{ip: "100.64.0.2"})
	h.verifyAudit()
}

// TestNoSecretReachesTheStoreOrTheLogs (F12): after the flows of A1a ran, no access token, refresh token, cookie handle, CSRF token,
// e-mail code or bootstrap token is in any identity, device, platform or audit row, the statement statistics, the center's log or
// the test server's statement log. E-mail addresses and login hints are only in the e-mail identities' subjects: no flow, bucket,
// audit row, statistic or center log line holds one (the test server logs statement parameters, which hold the address an e-mail
// lookup searches for, so its log is not scanned for addresses). Every table is also scanned for the hex of each value and of each
// credential's raw bytes, as row_to_json renders a bytea column, so a code or token stored in clear in a bytea column is found too.
func TestNoSecretReachesTheStoreOrTheLogs(t *testing.T) {
	h := newHarness(t, settings{policy: `{"emailPerAddressLimit": 100}`})
	ctx := context.Background()
	admin := pgtest.Connect(t, pgtest.WithDatabase(t, pgtest.ServerURL(t), h.database))
	if _, err := admin.Exec(ctx, "CREATE EXTENSION IF NOT EXISTS pg_stat_statements"); err != nil {
		t.Fatal(err)
	}
	response, _, _ := h.enroll(h.bootstrap, newClaim(t), caller{})
	if response.GetError() != nil {
		t.Fatal(failure(response.GetError()))
	}
	address := "secret.person@example.org"
	who := h.seedAccount(1, address)
	addresses := []string{address, "Secret.Person@Example.org", "nobody.here@example.org"}
	native := h.signIn(who, newClaim(t), caller{})
	claim := newClaim(t)
	viaMail := h.beginEmail(addresses[1], caller{}).GetValue().GetChallenge()
	h.requestCode(viaMail.GetFlowId(), address, caller{})
	h.redeem(viaMail.GetFlowId(), h.lastCode(address), caller{})
	unknown := h.beginEmail(addresses[2], caller{}).GetValue().GetChallenge()
	h.requestCode(unknown.GetFlowId(), addresses[2], caller{})
	h.redeem(unknown.GetFlowId(), "BCDF-GHJK", caller{})
	other := h.signIn(who, claim, caller{})
	rpc(h, refreshPath, &publicapiv1.IdentityServiceRefreshSessionRequest{Meta: meta(), RefreshToken: proto.String(other.GetRefreshToken()),
		InstallationId: claim.GetInstallationId()}, caller{}, &publicapiv1.IdentityServiceRefreshSessionResponse{})
	rpc(h, refreshPath, &publicapiv1.IdentityServiceRefreshSessionRequest{Meta: meta(), RefreshToken: proto.String(other.GetRefreshToken()),
		InstallationId: claim.GetInstallationId()}, caller{}, &publicapiv1.IdentityServiceRefreshSessionResponse{})
	cookie := h.issue(who.id, session.ScopeAccount, true)
	rpc(h, profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{cookie: cookie.handle, csrf: cookie.csrf, origin: origin},
		&publicapiv1.IdentityServiceGetProfileResponse{})
	rpc(h, profilePath, &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, caller{bearer: native.GetAccessToken()}, &publicapiv1.IdentityServiceGetProfileResponse{})

	secrets := *h.secrets
	if len(secrets) < 12 {
		t.Fatalf("only %d secrets were collected", len(secrets))
	}
	var lowered []string
	for _, value := range addresses {
		lowered = append(lowered, strings.ToLower(value))
	}
	// row_to_json renders bytea (digests, the code verifier, audit payloads) as lowercase hex (F13): scan for the hex of every value's
	// text and of every credential's 32 raw bytes.
	var hexed []string
	for _, value := range append(append([]string{}, secrets...), addresses...) {
		hexed = append(hexed, hex.EncodeToString([]byte(value)))
		for _, prefix := range []string{session.AccessPrefix, session.RefreshPrefix, session.BootstrapPrefix, ""} {
			if raw, ok := session.ParseToken(prefix, value); ok {
				hexed = append(hexed, hex.EncodeToString(raw[:]))
			}
		}
	}
	for _, value := range lowered {
		hexed = append(hexed, hex.EncodeToString([]byte(value)))
	}
	scan := func(where, text string, values []string) {
		t.Helper()
		for _, value := range values {
			if value != "" && strings.Contains(text, value) {
				t.Errorf("%s holds a secret or an address", where)
			}
		}
	}
	rows, err := admin.Query(ctx, `SELECT table_schema || '.' || table_name FROM information_schema.tables
WHERE table_schema IN ('identity', 'device', 'platform', 'audit') AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	if len(tables) < 12 {
		t.Fatalf("only %d tables", len(tables))
	}
	for _, table := range tables {
		var text string
		if err = admin.QueryRow(ctx, "SELECT coalesce(string_agg(row_to_json(t)::text, ''), '') FROM "+table+" t").Scan(&text); err != nil {
			t.Fatal(err)
		}
		scan(table, text, secrets)
		scan(table+" (bytea)", text, hexed)
		if table != "identity.auth_identity" {
			scan(table, strings.ToLower(text), lowered)
		}
	}
	var statistics string
	if err = admin.QueryRow(ctx, "SELECT coalesce(string_agg(query, ''), '') FROM pg_stat_statements").Scan(&statistics); err != nil {
		t.Fatal(err)
	}
	scan("pg_stat_statements", statistics, secrets)
	scan("pg_stat_statements", strings.ToLower(statistics), lowered)
	scan("the center's log", h.logs.String(), secrets)
	scan("the center's log", strings.ToLower(h.logs.String()), lowered)
	if log, ok := pgtest.ServerLog(t); ok {
		scan("the test server's log", log, secrets)
		if !strings.Contains(log, "identity.session") {
			t.Fatal("the server log does not show the identity statements, so the scan proves nothing")
		}
	}
}
