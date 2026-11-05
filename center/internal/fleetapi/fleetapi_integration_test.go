// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// TestFleetRowsAreTheServedMethods (E1-1, contracts-8): parts E1a, E1b and E2 serve exactly the browser sign-in (BeginNodeSignIn,
// GetNodeSignInFlow, ApproveNodeSignIn, CompleteNodeSignIn), the device-code sign-in (StartDeviceAuthorization,
// PollDeviceAuthorization, LookupDeviceCode, ApproveDeviceCode), RefreshNodeSession, ReportNodeInfo and SignOutNode; every other
// NodeEnrollmentService method is on the not-served list and answers UNIMPLEMENTED with no Worker row; each served method has one
// operation row and no row carries a Feature (never gated, AD-0021 section 13a). With the surface off the eleven methods answer
// STATE/not_activated with state.reason fleet.
func TestFleetRowsAreTheServedMethods(t *testing.T) {
	served := map[string]bool{}
	for _, method := range routes.FleetMethods() {
		served[method.Path] = true
	}
	notServed := []string{"CreatePhonePairing", "ClaimPhonePairing", "GetPhonePairing",
		"ConfirmPhonePairing", "PollPhonePairing", "IssueNodeCertificate", "GetLanHints", "ReportLanEndpoints", "RefreshEntitlementToken",
		"GetEntitlementKeys", "BeginSupportUpload", "CompleteSupportUpload"}
	methods := fleetv1.File_arcforges_fleet_v1_fleet_proto.Services().ByName("NodeEnrollmentService").Methods()
	if methods.Len() != len(served)+len(notServed) || len(served) != 11 {
		t.Fatalf("%d descriptor methods, %d served, %d not served", methods.Len(), len(served), len(notServed))
	}
	for _, name := range notServed {
		if methods.ByName(protoreflect.Name(name)) == nil || served["/arcforges.fleet.v1.NodeEnrollmentService/"+name] {
			t.Fatalf("%s", name)
		}
	}
	rows := 0
	for _, operation := range access.Operations() {
		if !strings.HasPrefix(operation.ID, "fleet.") || operation.Path == routes.NodeChannelPath {
			// The node channel's row is the relay surface's upgrade route (AF-CTR-05 E1a), not a NodeEnrollmentService method.
			continue
		}
		rows++
		if !served[operation.Path] || operation.Feature != "" {
			t.Errorf("row %s: served %v, feature %q", operation.ID, served[operation.Path], operation.Feature)
		}
	}
	if rows != len(served) {
		t.Fatalf("%d fleet rows", rows)
	}
	h := newHarness(t, settings{})
	for _, name := range notServed {
		reply := h.post("/arcforges.fleet.v1.NodeEnrollmentService/"+name, &fleetv1.NodeEnrollmentServiceGetEntitlementKeysRequest{Meta: meta()}, "")
		if reply.Status != "12" {
			t.Errorf("%s answers %q %q", name, reply.Status, reply.Message)
		}
	}
	off := newHarness(t, settings{surfaces: "identity,pages"})
	for path := range served {
		reply := off.post(path, &fleetv1.NodeEnrollmentServiceSignOutNodeRequest{Meta: meta()}, "")
		response := &fleetv1.NodeEnrollmentServiceSignOutNodeResponse{}
		if reply.Body == nil || proto.Unmarshal(reply.Body, response) != nil || failure(response.GetError()) != "STATE/not_activated" ||
			response.GetError().GetDetails().GetState().GetReason() != "fleet" {
			t.Errorf("%s with fleet off: %+v", path, reply)
		}
	}
}

// TestRefreshNodeSession (E1-11, CRD-04, C0 RefreshNodeSessionValue): a node refreshes with its refresh token alone (no installation),
// gets a new pair with the 60-minute access lifetime, the family's absolute end (unchanged by refresh), the published command keys
// with a registered successor, and the node marked seen. Strict rotation: a spent token revokes the family (credential_revoked, audit
// with the node scope); an account token is permission_denied; a revoked device, an expired family and a suspended account refuse;
// a restricted account's node keeps refreshing. Never gated: the gated feature keys are all disabled here.
func TestRefreshNodeSession(t *testing.T) {
	h := newHarness(t, settings{disabled: "center.nodes,center.execute,remote.view,remote.control,center.mcp,push"})
	ctx := context.Background()
	now := time.Now().UTC()
	register := func(kid string, notBefore time.Time) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		tx, err := h.db.Migration.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err = platform.RegisterKey(ctx, tx, platform.SigningKey{KID: kid, Purpose: platform.CommandSigning, Algorithm: "ES256", PublicKey: der,
			SecretBinding: "TEST_ONLY_" + strings.ToUpper(strings.ReplaceAll(kid, "-", "_")), NotBefore: notBefore, NotAfter: notBefore.Add(30 * 24 * time.Hour)}, now); err != nil {
			t.Fatal(err)
		}
		if err = tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	register("current-"+hex.EncodeToString(randomBytes(4)), now)
	register("successor-"+hex.EncodeToString(randomBytes(4)), now.Add(20*24*time.Hour))
	node := h.enroll(1)
	h.db.Exec("UPDATE fleet.node SET last_seen_at = enrolled_at WHERE enrollment_id = '" + node.result.EnrollmentID.String() + "'")
	value, refusal := h.refresh(node.refresh)
	if refusal != nil || value.GetAccessLifetimeMs() != 3_600_000 || len(value.GetCommandKeys()) != 2 || len(value.GetEntitlementKeys()) != 0 ||
		value.GetSessionExpiresAt().GetUnixSeconds() != node.result.Session.ExpiresAt.Unix() || !strings.HasPrefix(value.GetAccessToken(), "afa1.") ||
		value.GetCommandKeys()[1].GetNotBefore().GetUnixSeconds() <= now.Unix() {
		t.Fatalf("refresh %v %v", value, failure(refusal))
	}
	if h.count("SELECT count(*) FROM fleet.node WHERE enrollment_id = $1 AND last_seen_at > enrolled_at", node.result.EnrollmentID) != 1 {
		t.Fatal("the node was not marked seen")
	}
	if h.audits("identity.session.refresh") != 0 {
		t.Fatal("a refresh was audited")
	}
	// The spent token: the family is revoked, once audited with the node scope.
	if _, refusal = h.refresh(node.refresh); failure(refusal) != "AUTHENTICATION/credential_revoked" ||
		h.count("SELECT count(*) FROM identity.session WHERE family_id = $1 AND revoke_reason = 4", node.result.Session.SessionID) != 1 ||
		h.payload("identity.session.refresh_reused")["scope"] != "node" {
		t.Fatalf("reuse %v", failure(refusal))
	}
	if _, refusal = h.refresh(value.GetRefreshToken()); failure(refusal) != "AUTHENTICATION/credential_revoked" {
		t.Fatalf("the family's current token after reuse: %v", failure(refusal))
	}
	// An account token.
	other := h.enroll(1)
	account := h.issue(other.user, session.ScopeAccount)
	if _, refusal = h.refresh(account.RefreshToken); failure(refusal) != "AUTHORIZATION/permission_denied" ||
		refusal.GetDetails().GetState().GetReason() != "fleet.refreshNodeSession" {
		t.Fatalf("an account token: %v", failure(refusal))
	}
	// A restricted account's node keeps refreshing; a suspended one's does not.
	h.db.Exec("UPDATE identity.user SET state = 2 WHERE user_id = '" + other.user.String() + "'")
	if value, refusal = h.refresh(other.refresh); refusal != nil {
		t.Fatalf("a restricted account's node: %v", failure(refusal))
	}
	h.db.Exec("UPDATE identity.user SET state = 3 WHERE user_id = '" + other.user.String() + "'")
	if _, refusal = h.refresh(value.GetRefreshToken()); failure(refusal) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("a suspended account's node: %v", failure(refusal))
	}
	// An expired family; a node row revoked under a live session (defence in depth: credential_revoked, nothing rotated).
	third := h.enroll(1)
	h.db.Exec("UPDATE identity.session SET expires_at = now() - interval '1 second', refresh_expires_at = now() - interval '1 second', access_expires_at = now() - interval '1 second', issued_at = now() - interval '1 hour', authenticated_at = now() - interval '1 hour' WHERE session_id = '" + third.result.Session.SessionID.String() + "'")
	if _, refusal = h.refresh(third.refresh); failure(refusal) != "AUTHENTICATION/token_expired" {
		t.Fatalf("an expired family: %v", failure(refusal))
	}
	fourth := h.enroll(1)
	h.db.Exec("UPDATE fleet.node SET revoked_at = now(), revoke_reason = 1 WHERE enrollment_id = '" + fourth.result.EnrollmentID.String() + "'")
	if _, refusal = h.refresh(fourth.refresh); failure(refusal) != "AUTHENTICATION/credential_revoked" ||
		h.count("SELECT count(*) FROM identity.spent_refresh WHERE session_id = $1", fourth.result.Session.SessionID) != 0 {
		t.Fatalf("a revoked node row: %v", failure(refusal))
	}
	// The device revoked: the next refresh is credential_revoked.
	fifth := h.enroll(1)
	h.revokeDevice(fifth)
	if _, refusal = h.refresh(fifth.refresh); failure(refusal) != "AUTHENTICATION/credential_revoked" {
		t.Fatalf("a revoked device: %v", failure(refusal))
	}
}

func randomBytes(size int) []byte {
	data := make([]byte, size)
	_, _ = rand.Read(data)
	return data
}

// revokeDevice revokes a node's device through DeviceService.Revoke of the composed center, as its account does: a native account
// session of the account with seeded step-up evidence for device.revoke (the device is not the caller's own).
func (h *harness) revokeDevice(node *enrolled) {
	h.t.Helper()
	account := h.issue(node.user, session.ScopeAccount)
	target, err := hex.DecodeString(identity.TargetHash("device.revoke", node.user, node.result.DeviceID))
	if err != nil {
		h.t.Fatal(err)
	}
	h.db.ProveStepUp(dbtest.Session{ID: account.SessionID, User: node.user}, "device.revoke", target, time.Now())
	response := &publicapiv1.DeviceServiceRevokeResponse{}
	reply := h.post("/arcforges.publicapi.v1.DeviceService/Revoke", &publicapiv1.DeviceServiceRevokeRequest{Meta: command(),
		DeviceId: &foundationv1.Id{Value: node.result.DeviceID[:]}}, account.AccessToken)
	if reply.Body == nil || proto.Unmarshal(reply.Body, response) != nil || response.GetError() != nil {
		h.t.Fatalf("DeviceService.Revoke: %+v %v", reply, failure(response.GetError()))
	}
}

// TestRevocationReachesTheNodeCredential (E1-13, CRD-07, DC-03): the composed center registers the node participant, so revoking the
// node's device through DeviceService.Revoke revokes its node row in the same transaction (counted in device.revoked) and its next
// call is the transport refusal auth.credential_revoked; revoking all of an account's sessions leaves node rows and sessions live.
func TestRevocationReachesTheNodeCredential(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll(1)
	keep := h.enrollIn(node.user, node.approver)
	h.revokeDevice(node)
	if h.count("SELECT count(*) FROM fleet.node WHERE enrollment_id = $1 AND revoke_reason = 1", node.result.EnrollmentID) != 1 ||
		h.payload("device.revoked")["participants"] == nil {
		t.Fatalf("the cascade: %v", h.payload("device.revoked"))
	}
	if reply := h.post(signOutPath, &fleetv1.NodeEnrollmentServiceSignOutNodeRequest{Meta: command()}, node.access); reply.Status != "16" ||
		reply.Message != "auth.credential_revoked" {
		t.Fatalf("the revoked node's next call: %+v", reply)
	}
	// RevokeAllSessions (DC-03) leaves node rows and node sessions as they are.
	account := h.issue(node.user, session.ScopeAccount)
	target, _ := hex.DecodeString(identity.TargetHash("identity.revokeAllSessions", node.user, node.user))
	h.db.ProveStepUp(dbtest.Session{ID: account.SessionID, User: node.user}, "identity.revokeAllSessions", target, time.Now())
	response := &publicapiv1.IdentityServiceRevokeAllSessionsResponse{}
	reply := h.post("/arcforges.publicapi.v1.IdentityService/RevokeAllSessions", &publicapiv1.IdentityServiceRevokeAllSessionsRequest{Meta: command()}, account.AccessToken)
	if reply.Body == nil || proto.Unmarshal(reply.Body, response) != nil || response.GetError() != nil {
		t.Fatalf("RevokeAllSessions: %+v %v", reply, failure(response.GetError()))
	}
	if h.count("SELECT count(*) FROM fleet.node WHERE enrollment_id = $1 AND revoked_at IS NULL", keep.result.EnrollmentID) != 1 ||
		h.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND revoked_at IS NULL", keep.result.Session.SessionID) != 1 {
		t.Fatal("RevokeAllSessions reached a node")
	}
}

// TestReportNodeInfoRules (E1-12, CRD-05, Q20, cloud-11, protocol-11, C0 ReportNodeInfo, OQ-5): the node ID must be the credential's,
// the OS cannot change, a hostile name is refused; a rebuild at another commit is no change (canonical versions); a changed name
// renames the device while it bears the reported name and is audited once; a name the account gave wins; the report is receipt
// guarded (a replay answers the stored receipt, another request under the same command ID is command_id_reused) and limited per
// installation; a restricted account's node is permission_denied; a credential whose node row is not live is unauthenticated.
func TestReportNodeInfoRules(t *testing.T) {
	h := newHarness(t, settings{policy: `{"nodeReportInstallationLimit": 8}`})
	node := h.enroll(1)
	info := func(mutate func(*fleetv1.EnrollingNodeInfo)) *fleetv1.EnrollingNodeInfo {
		value := node.node.Info()
		if mutate != nil {
			mutate(value)
		}
		return value
	}
	for want, mutate := range map[string]func(*fleetv1.EnrollingNodeInfo){
		"node.node_id: mismatch": func(i *fleetv1.EnrollingNodeInfo) {
			other := platform.NewID()
			i.NodeId = &foundationv1.Id{Value: other[:]}
		},
		"node.node_id: required": func(i *fleetv1.EnrollingNodeInfo) { i.NodeId = nil },
		"node.os: mismatch":      func(i *fleetv1.EnrollingNodeInfo) { i.Os = i.Os.Enum(); *i.Os = 1 },
		"node.name: pattern":     func(i *fleetv1.EnrollingNodeInfo) { i.Name = proto.String("evil  name") },
		"node.version: pattern":  func(i *fleetv1.EnrollingNodeInfo) { i.Version = proto.String("1.0") },
	} {
		if _, refusal := h.report(node.access, command(), info(mutate)); failure(refusal) != "VALIDATION/invalid_argument" ||
			refusal.GetDetails().GetState().GetReason() != want {
			t.Errorf("%s: %v %v", want, failure(refusal), refusal.GetDetails().GetState().GetReason())
		}
	}
	// Unchanged: another build of the same version.
	if _, refusal := h.report(node.access, command(), info(func(i *fleetv1.EnrollingNodeInfo) { i.Version = proto.String("0.1.0-dev+other") })); refusal != nil ||
		h.audits("fleet.node.info_reported") != 0 {
		t.Fatalf("an unchanged report: %v", failure(refusal))
	}
	renamed := command()
	value, refusal := h.report(node.access, renamed, info(func(i *fleetv1.EnrollingNodeInfo) {
		i.Name = proto.String("buildbox-2")
		i.Version = proto.String("0.2.0")
	}))
	if refusal != nil || value.GetReceipt() == nil || h.audits("fleet.node.info_reported") != 1 ||
		h.count("SELECT count(*) FROM device.device WHERE device_id = $1 AND display_name = 'buildbox-2'", node.result.DeviceID) != 1 ||
		h.count("SELECT count(*) FROM device.installation WHERE installation_id = $1 AND app_version = '0.2.0'", node.result.InstallationID) != 1 {
		t.Fatalf("a renaming report: %v", failure(refusal))
	}
	// The replay answers the stored receipt without a second effect; another body under the command ID is refused.
	if again, refusal := h.report(node.access, renamed, info(func(i *fleetv1.EnrollingNodeInfo) {
		i.Name = proto.String("buildbox-2")
		i.Version = proto.String("0.2.0")
	})); refusal != nil ||
		!proto.Equal(again.GetReceipt(), value.GetReceipt()) || h.audits("fleet.node.info_reported") != 1 {
		t.Fatalf("a replay: %v", failure(refusal))
	}
	if _, refusal := h.report(node.access, renamed, info(nil)); failure(refusal) != "CONFLICT/command_id_reused" {
		t.Fatalf("a reused command ID: %v", failure(refusal))
	}
	// The account renames the device: the node's next name does not override it.
	h.db.Exec("UPDATE device.device SET display_name = 'Work server' WHERE device_id = '" + node.result.DeviceID.String() + "'")
	if _, refusal := h.report(node.access, command(), info(func(i *fleetv1.EnrollingNodeInfo) { i.Name = proto.String("buildbox-3") })); refusal != nil ||
		h.count("SELECT count(*) FROM device.device WHERE device_id = $1 AND display_name = 'Work server'", node.result.DeviceID) != 1 {
		t.Fatalf("the account's name: %v", failure(refusal))
	}
	// The installation's bucket (8 per hour here: the calls above that reached it count).
	limited := false
	for range 8 {
		if _, refusal := h.report(node.access, command(), info(nil)); failure(refusal) == "RESOURCE/rate_limited" {
			limited = refusal.GetDetails().GetLimit().GetLimitName() == "node_report_installation"
			break
		}
	}
	if !limited {
		t.Fatal("the report bucket never refused")
	}
	// A restricted account's node; a node whose row is not live.
	restricted := h.enroll(1)
	h.db.Exec("UPDATE identity.user SET state = 2 WHERE user_id = '" + restricted.user.String() + "'")
	if _, refusal := h.report(restricted.access, command(), restricted.node.Info()); failure(refusal) != "AUTHORIZATION/permission_denied" ||
		refusal.GetDetails().GetState().GetState() != "operation" || refusal.GetDetails().GetState().GetReason() != "fleet.reportNodeInfo" {
		t.Fatalf("a restricted account's node: %v", failure(refusal))
	}
	orphan := h.enroll(1)
	h.db.Exec("UPDATE fleet.node SET revoked_at = now(), revoke_reason = 1 WHERE enrollment_id = '" + orphan.result.EnrollmentID.String() + "'")
	if _, refusal := h.report(orphan.access, command(), orphan.node.Info()); failure(refusal) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("no live node row: %v", failure(refusal))
	}
	if _, refusal := h.signOut(orphan.access, command()); failure(refusal) != "AUTHENTICATION/unauthenticated" {
		t.Fatalf("no live node row on sign-out: %v", failure(refusal))
	}
}

// TestSignOutNode (E1-12, CRD-06, C0 SignOutNode, Q24): the node's credential is revoked as signed out under a receipt, its device,
// installation and node row stay live, and fleet.node.signed_out is audited; a retry after the revocation (also a lost reply's) is
// refused at the ingress as credential_revoked before any receipt is read; the node signs in again in place; a restricted account's
// node may sign out.
func TestSignOutNode(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll(1)
	signOut := command()
	value, refusal := h.signOut(node.access, signOut)
	if refusal != nil || value.GetReceipt().GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED || h.audits("fleet.node.signed_out") != 1 ||
		h.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND revoke_reason = 1", node.result.Session.SessionID) != 1 ||
		h.count("SELECT count(*) FROM fleet.node WHERE enrollment_id = $1 AND revoked_at IS NULL", node.result.EnrollmentID) != 1 ||
		h.count("SELECT count(*) FROM device.device WHERE device_id = $1 AND revoked_at IS NULL", node.result.DeviceID) != 1 {
		t.Fatalf("sign-out: %v", failure(refusal))
	}
	receipts := h.count("SELECT count(*) FROM platform.command_receipt")
	if reply := h.post(signOutPath, &fleetv1.NodeEnrollmentServiceSignOutNodeRequest{Meta: signOut}, node.access); reply.Status != "16" ||
		reply.Message != "auth.credential_revoked" || h.count("SELECT count(*) FROM platform.command_receipt") != receipts {
		t.Fatalf("the retry: %+v", reply)
	}
	again := h.enrollNode(node.user, node.approver, node.node)
	if !again.Reenrolled || again.EnrollmentID != node.result.EnrollmentID {
		t.Fatalf("the sign-in after a sign-out: %+v", again)
	}
	restricted := h.enroll(1)
	h.db.Exec("UPDATE identity.user SET state = 2 WHERE user_id = '" + restricted.user.String() + "'")
	if _, refusal := h.signOut(restricted.access, command()); refusal != nil {
		t.Fatalf("a restricted account's node: %v", failure(refusal))
	}
	if _, refusal := h.signOut(again.Session.AccessToken, meta()); failure(refusal) != "VALIDATION/invalid_argument" {
		t.Fatalf("no command ID: %v", failure(refusal))
	}
}

// TestScopeMatrixOverFleetRows (E1-3, SEC-01, cloud-4): on ReportNodeInfo and SignOutNode only a node credential is admitted; an
// account, mobile.limited, push or automation credential is refused with permission_denied (state operation, the operation ID),
// audited access.refused (reason principal or scope), with nothing written; a node credential reaches no identity session row.
func TestScopeMatrixOverFleetRows(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll(1)
	writes := func() int {
		return h.count("SELECT (SELECT count(*) FROM platform.command_receipt) + (SELECT coalesce(sum(rev), 0) FROM identity.session) + (SELECT coalesce(sum(rev), 0) FROM fleet.node)")
	}
	for _, scope := range []session.Scope{session.ScopeAccount, session.ScopeMobileLimited, session.ScopePush, session.ScopeAutomation} {
		credential := h.issue(node.user, scope)
		for path, request := range map[string]proto.Message{
			reportPath:  &fleetv1.NodeEnrollmentServiceReportNodeInfoRequest{Meta: command(), Node: node.node.Info()},
			signOutPath: &fleetv1.NodeEnrollmentServiceSignOutNodeRequest{Meta: command()},
		} {
			before, refused := writes(), h.audits(access.AuditRefused)
			response := &fleetv1.NodeEnrollmentServiceSignOutNodeResponse{}
			reply := h.post(path, request, credential.AccessToken)
			if reply.Body == nil || proto.Unmarshal(reply.Body, response) != nil || failure(response.GetError()) != "AUTHORIZATION/permission_denied" ||
				response.GetError().GetDetails().GetState().GetState() != "operation" || !strings.HasPrefix(response.GetError().GetDetails().GetState().GetReason(), "fleet.") {
				t.Errorf("%s on %s: %+v", scope, path, reply)
			}
			if writes() != before || h.audits(access.AuditRefused) != refused+1 {
				t.Errorf("%s on %s wrote or was not audited", scope, path)
			}
		}
	}
	reasons := map[string]int{}
	rows, err := h.db.Migration.Query(context.Background(), "SELECT reason FROM audit.audit_event WHERE event_type = $1", access.AuditRefused)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var reason string
		if err = rows.Scan(&reason); err != nil {
			t.Fatal(err)
		}
		reasons[reason]++
	}
	// account and mobile.limited are HUMAN (principal), automation is AGENT but not a node (scope), push acts for no principal (scope).
	if reasons["principal"] != 4 || reasons["scope"] != 4 {
		t.Fatalf("refusal reasons %v", reasons)
	}
	// The node credential on an identity session row.
	response := &publicapiv1.IdentityServiceGetProfileResponse{}
	reply := h.post("/arcforges.publicapi.v1.IdentityService/GetProfile", &publicapiv1.IdentityServiceGetProfileRequest{Meta: meta()}, node.access)
	if reply.Body == nil || proto.Unmarshal(reply.Body, response) != nil || failure(response.GetError()) != "AUTHORIZATION/permission_denied" {
		t.Fatalf("a node on GetProfile: %+v", reply)
	}
	// SEC-6: the refusal of a node credential names the node's installation as its actor, as every fleet event does.
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND actor_ref = $2", access.AuditRefused,
		"node:"+node.result.InstallationID.String()) != 1 {
		t.Fatal("the node's refusal is not audited with the node as its actor")
	}
}

// TestJunkRefreshesDoNotLockOutAPrefix (E1-15, protocol-8): tokens that name nothing fill only their prefix's failure bucket; a valid
// node's refresh from the same prefix still rotates, and a spent token presented while that bucket is full still revokes its
// family. The per-session bucket limits a session's current token; its spent token is never limited.
func TestJunkRefreshesDoNotLockOutAPrefix(t *testing.T) {
	h := newHarness(t, settings{policy: `{"nodeRefreshPrefixLimit": 5, "nodeRefreshSessionLimit": 2}`})
	node := h.enroll(1)
	junk := 0
	for range 12 {
		_, refusal := h.refresh(session.RefreshPrefix + session.NewSecret().Text())
		switch failure(refusal) {
		case "AUTHENTICATION/unauthenticated":
		case "RESOURCE/rate_limited":
			if refusal.GetDetails().GetLimit().GetLimitName() != "node_refresh_prefix" || refusal.GetRetry().GetRetryAt() == nil {
				t.Fatalf("the prefix refusal %v", refusal)
			}
			junk++
		default:
			t.Fatalf("junk: %v", failure(refusal))
		}
	}
	if junk == 0 || h.audits("identity.rate_limited") != 1 {
		t.Fatalf("the prefix bucket refused %d junk calls, audited %d", junk, h.audits("identity.rate_limited"))
	}
	value, refusal := h.refresh(node.refresh)
	if refusal != nil {
		t.Fatalf("a valid refresh behind the junk: %v", failure(refusal))
	}
	value, refusal = h.refresh(value.GetRefreshToken())
	if refusal != nil {
		t.Fatalf("the second refresh: %v", failure(refusal))
	}
	if _, refusal = h.refresh(value.GetRefreshToken()); failure(refusal) != "RESOURCE/rate_limited" ||
		refusal.GetDetails().GetLimit().GetLimitName() != "node_refresh_session" {
		t.Fatalf("the session bucket: %v", failure(refusal))
	}
	// The spent first token: not limited by either bucket, its reuse revokes the family.
	if _, refusal = h.refresh(node.refresh); failure(refusal) != "AUTHENTICATION/credential_revoked" ||
		h.count("SELECT count(*) FROM identity.session WHERE session_id = $1 AND revoke_reason = 4", node.result.Session.SessionID) != 1 {
		t.Fatalf("a spent token behind full buckets: %v", failure(refusal))
	}
}

// TestNoGeneratedSecretIsStoredLoggedOrAudited (E1-18, SEC-10/14; a new test modelled on TestNoSecretReachesTheStoreOrTheLogs): after
// enrollments, refreshes, reports, a reuse and a sign-out, no node access or refresh token appears in any table, in the server log
// or in pg_stat_statements; only their digests are stored.
func TestNoGeneratedSecretIsStoredLoggedOrAudited(t *testing.T) {
	h := newHarness(t, settings{})
	readStatements := h.trackStatements()
	node := h.enroll(1)
	value, _ := h.refresh(node.refresh)
	_, _ = h.refresh(node.refresh)
	other := h.enroll(1)
	_, _ = h.report(other.access, command(), other.node.Info())
	_, _ = h.signOut(other.access, command())
	if value == nil || len(h.secrets) < 6 {
		t.Fatal("no secrets were generated")
	}
	ctx := context.Background()
	var dump string
	if err := h.db.Migration.QueryRow(ctx, `SELECT string_agg(row_text, E'\n') FROM (
    SELECT t::text AS row_text FROM identity.session t UNION ALL SELECT t::text FROM identity.spent_refresh t
    UNION ALL SELECT t::text FROM fleet.node t UNION ALL SELECT t::text FROM device.installation t
    UNION ALL SELECT t::text FROM audit.audit_event t UNION ALL SELECT t::text FROM platform.command_receipt t
    UNION ALL SELECT t::text FROM platform.rate_limit t) rows`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	statements := readStatements()
	for _, secret := range h.secrets {
		body := strings.SplitN(secret, ".", 2)[1]
		for name, text := range map[string]string{"store": dump, "log": h.logs.String(), "statements": statements} {
			if strings.Contains(text, body) {
				t.Errorf("a generated token reached the %s", name)
			}
		}
	}
}

var _ = pgx.ErrNoRows
var _ = store.TxOptions{}

// TestAReportReplayIsAnsweredWithItsReceipt (F2): a node whose reply to a committed report was lost retries with the same command ID
// after its installation's bucket is full, and gets the stored receipt, not rate_limited; the replay does not spend the bucket.
func TestAReportReplayIsAnsweredWithItsReceipt(t *testing.T) {
	h := newHarness(t, settings{policy: `{"nodeReportInstallationLimit": 1}`})
	node := h.enroll(1)
	committed := command()
	first, refusal := h.report(node.access, committed, node.node.Info())
	if refusal != nil {
		t.Fatalf("the first report: %v", failure(refusal))
	}
	if _, refusal = h.report(node.access, command(), node.node.Info()); failure(refusal) != "RESOURCE/rate_limited" {
		t.Fatalf("a new report over the bucket: %v", failure(refusal))
	}
	again, refusal := h.report(node.access, committed, node.node.Info())
	if refusal != nil || !proto.Equal(again.GetReceipt(), first.GetReceipt()) {
		t.Fatalf("the replay: %v", failure(refusal))
	}
}
