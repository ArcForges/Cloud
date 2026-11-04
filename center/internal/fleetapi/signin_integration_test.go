// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// EVIDENCE: REAL PostgreSQL, the real center (server.New: the ingress, the session verifier, the operation table, the identity and
// fleet handlers) behind an httptest listener, binary gRPC-Web over HTTP. MOCKED: the node (center/internal/nodetest, a software
// ES256 key), the account's passkey (identity/passkey/virtual, verified by the real relying party) and the mail sender (the
// harness inbox, for the e-mail step-up). The account rows are SEEDED as an enrolment would leave them; it signs in, steps up,
// reviews and approves through the served API.

const (
	beginPath    = "/arcforges.fleet.v1.NodeEnrollmentService/BeginNodeSignIn"
	reviewPath   = "/arcforges.fleet.v1.NodeEnrollmentService/GetNodeSignInFlow"
	approvePath  = "/arcforges.fleet.v1.NodeEnrollmentService/ApproveNodeSignIn"
	completePath = "/arcforges.fleet.v1.NodeEnrollmentService/CompleteNodeSignIn"
	rpID         = "center.example.test"
	origin       = "https://center.example.test"
)

// person is a seeded account with a virtual passkey and an e-mail address, signed in natively.
type person struct {
	id            platform.ID
	authenticator *virtual.Authenticator
	key           *virtual.Key
	email         string
	emailID       platform.ID
	bearer        string
	sessionID     platform.ID
}

// rpc posts an identity or fleet request and decodes the reply into response.
func rpc[Response proto.Message](h *harness, path string, request proto.Message, bearer string, response Response) Response {
	h.t.Helper()
	decoded, err := nodetest.Decode(h.post(path, request, bearer), response)
	if err != nil {
		h.t.Fatalf("%s: %v", path, err)
	}
	return decoded
}

// person seeds an account in a state with a passkey (made by a virtual authenticator and verified by the relying party) and an
// e-mail identity, and signs it in with the passkey through IdentityService (a native account session).
func (h *harness) person(state int16) *person {
	h.t.Helper()
	rp, err := passkey.New(rpID, origin)
	if err != nil {
		h.t.Fatal(err)
	}
	handle := randomBytes(32)
	p := &person{id: platform.NewID(), authenticator: virtual.New(rpID, origin), email: "owner-" + platform.NewID().String()[:8] + "@example.test", emailID: platform.NewID()}
	challenge := randomBytes(32)
	creation, key := p.authenticator.Create(challenge, handle)
	credential, err := rp.VerifyCreation(challenge, handle, creation, time.Now().Add(time.Minute))
	if err != nil {
		h.t.Fatal(err)
	}
	p.key = key
	ctx := context.Background()
	if _, err = h.db.Migration.Exec(ctx, `INSERT INTO identity.user (user_id, display_name, state, passkey_user_handle, created_at, rev)
VALUES ($1, 'Owner', 1, $2, now() - interval '1 second', 1)`, p.id, handle); err != nil {
		h.t.Fatal(err)
	}
	if _, err = h.db.Migration.Exec(ctx, `INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, public_key, user_handle,
    sign_count, backup_eligible, backup_state, transports, aaguid, attestation_format, created_at, rev)
VALUES ($1, $2, 1, 'passkey', $3, $4, $5, 0, false, false, '{}', $6, 'none', now() - interval '1 second', 1)`, platform.NewID(), p.id,
		base64.RawURLEncoding.EncodeToString(credential.ID), credential.PublicKey, handle, credential.AAGUID); err != nil {
		h.t.Fatal(err)
	}
	if _, err = h.db.Migration.Exec(ctx, `INSERT INTO identity.auth_identity (auth_identity_id, user_id, method, provider_id, subject, created_at, rev)
VALUES ($1, $2, 2, 'email', $3, now(), 1)`, p.emailID, p.id, p.email); err != nil {
		h.t.Fatal(err)
	}
	claim := &publicapiv1.InstallationClaim{InstallationId: &foundationv1.Id{Value: randomBytes(16)}, Product: proto.String("arcforges-mobile"),
		Platform: proto.String("android-15"), AppVersion: proto.String("1.0.0")}
	begun := rpc(h, "/arcforges.publicapi.v1.IdentityService/BeginAuthentication", &publicapiv1.IdentityServiceBeginAuthenticationRequest{Meta: meta(),
		Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(), Purpose: publicapiv1.AuthPurpose_AUTH_PURPOSE_AUTHENTICATE.Enum(), Installation: claim}, "",
		&publicapiv1.IdentityServiceBeginAuthenticationResponse{})
	if begun.GetError() != nil {
		h.t.Fatalf("begin: %s", failure(begun.GetError()))
	}
	signedIn := rpc(h, "/arcforges.publicapi.v1.IdentityService/CompleteAuthentication", &publicapiv1.IdentityServiceCompleteAuthenticationRequest{Meta: meta(),
		FlowId: begun.GetValue().GetChallenge().GetFlowId(), Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertion(
			p.authenticator.Assert(p.key, begun.GetValue().GetChallenge().GetChallenge()))}}}, "", &publicapiv1.IdentityServiceCompleteAuthenticationResponse{})
	if signedIn.GetError() != nil {
		h.t.Fatalf("sign-in: %s", failure(signedIn.GetError()))
	}
	native := signedIn.GetValue().GetSession()
	p.bearer = native.GetAccessToken()
	copy(p.sessionID[:], native.GetSessionId().GetValue())
	h.secrets = append(h.secrets, native.GetAccessToken(), native.GetRefreshToken())
	if state != 1 {
		if _, err = h.db.Migration.Exec(ctx, "UPDATE identity.user SET state = $2, rev = rev + 1 WHERE user_id = $1", p.id, state); err != nil {
			h.t.Fatal(err)
		}
	}
	return p
}

func assertion(value passkey.Assertion) *publicapiv1.WebAuthnAssertion {
	return &publicapiv1.WebAuthnAssertion{CredentialId: value.CredentialID, ClientDataJson: value.ClientDataJSON, AuthenticatorData: value.AuthenticatorData,
		Signature: value.Signature, UserHandle: value.UserHandle}
}

var codePattern = regexp.MustCompile(`code is ([A-Z]{4})-([A-Z]{4})\.`)

// stepUp proves a step-up of the person's session for a class and target, by passkey or by the e-mail code the inbox received.
func (h *harness) stepUp(p *person, class string, target platform.ID, byEmail bool) {
	h.t.Helper()
	method := publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY
	if byEmail {
		method = publicapiv1.AuthMethod_AUTH_METHOD_EMAIL
	}
	begun := rpc(h, "/arcforges.publicapi.v1.IdentityService/BeginStepUp", &publicapiv1.IdentityServiceBeginStepUpRequest{Meta: meta(), OperationClass: proto.String(class),
		Method: method.Enum(), TargetHash: proto.String(identity.TargetHash(class, p.id, target))}, p.bearer, &publicapiv1.IdentityServiceBeginStepUpResponse{})
	if begun.GetError() != nil {
		h.t.Fatalf("begin a step-up of %s: %s", class, failure(begun.GetError()))
	}
	proof := &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: assertion(p.authenticator.Assert(p.key, begun.GetValue().GetChallenge().GetChallenge()))}}
	if byEmail {
		match := codePattern.FindStringSubmatch(h.inbox.last().Text)
		if match == nil {
			h.t.Fatal("no e-mail code reached the inbox")
		}
		proof = &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_EmailCode{EmailCode: match[1] + "-" + match[2]}}
	}
	completed := rpc(h, "/arcforges.publicapi.v1.IdentityService/CompleteStepUp", &publicapiv1.IdentityServiceCompleteStepUpRequest{Meta: meta(),
		FlowId: begun.GetValue().GetChallenge().GetFlowId(), Proof: proof}, p.bearer, &publicapiv1.IdentityServiceCompleteStepUpResponse{})
	if completed.GetError() != nil {
		h.t.Fatalf("complete a step-up of %s: %s", class, failure(completed.GetError()))
	}
}

// signIn is a node's browser sign-in in progress.
type signIn struct {
	node   *nodetest.Node
	pkce   nodetest.SignIn
	flowID platform.ID
	value  *fleetv1.NodeEnrollmentServiceBeginNodeSignInValue
	code   string
}

func flowIDOf(id *foundationv1.Id) platform.ID {
	var flowID platform.ID
	copy(flowID[:], id.GetValue())
	return flowID
}

// begin posts BeginNodeSignIn for a new node.
func (h *harness) begin() (*signIn, *foundationv1.ArcError) {
	h.t.Helper()
	node, err := nodetest.New()
	if err != nil {
		h.t.Fatal(err)
	}
	return h.beginFor(node)
}

func (h *harness) beginFor(node *nodetest.Node) (*signIn, *foundationv1.ArcError) {
	h.t.Helper()
	s := &signIn{node: node, pkce: nodetest.NewSignIn()}
	response := rpc(h, beginPath, node.BeginRequest(s.pkce), "", &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{})
	if response.GetError() != nil {
		return s, response.GetError()
	}
	s.value, s.flowID = response.GetValue(), flowIDOf(response.GetValue().GetFlowId())
	return s, nil
}

func (h *harness) review(p *person, s *signIn) *fleetv1.NodeEnrollmentServiceGetNodeSignInFlowResponse {
	h.t.Helper()
	return rpc(h, reviewPath, &fleetv1.NodeEnrollmentServiceGetNodeSignInFlowRequest{Meta: meta(), FlowId: &foundationv1.Id{Value: s.flowID[:]}}, p.bearer,
		&fleetv1.NodeEnrollmentServiceGetNodeSignInFlowResponse{})
}

func (h *harness) decide(bearer string, s *signIn, approve bool) *fleetv1.NodeEnrollmentServiceApproveNodeSignInResponse {
	h.t.Helper()
	return rpc(h, approvePath, &fleetv1.NodeEnrollmentServiceApproveNodeSignInRequest{Meta: meta(), FlowId: &foundationv1.Id{Value: s.flowID[:]}, Approve: proto.Bool(approve)},
		bearer, &fleetv1.NodeEnrollmentServiceApproveNodeSignInResponse{})
}

// approve reviews, steps up and approves a flow, and keeps the code the loopback receives.
func (h *harness) approve(p *person, s *signIn, byEmail bool) {
	h.t.Helper()
	if review := h.review(p, s); review.GetError() != nil {
		h.t.Fatalf("review: %s", failure(review.GetError()))
	}
	h.stepUp(p, fleet.ClassApproveNodeSignIn, s.flowID, byEmail)
	decided := h.decide(p.bearer, s, true)
	if decided.GetError() != nil {
		h.t.Fatalf("approve: %s", failure(decided.GetError()))
	}
	code, err := s.pkce.LoopbackCode(decided.GetValue().GetRedirectUrl())
	if err != nil {
		h.t.Fatal(err)
	}
	s.code = code
	h.secrets = append(h.secrets, code)
}

func (h *harness) complete(s *signIn) *fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse {
	h.t.Helper()
	return h.completeWith(s.node.CompleteRequest(s.flowID, s.code, s.pkce, s.node.CompleteProof(publicBaseURL, s.flowID, s.code)))
}

func (h *harness) completeWith(request *fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest) *fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse {
	h.t.Helper()
	response := rpc(h, completePath, request, "", &fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse{})
	if credentials := response.GetValue().GetCredentials(); credentials != nil {
		h.secrets = append(h.secrets, credentials.GetAccessToken(), credentials.GetRefreshToken())
	}
	return response
}

// TestBrowserSignInEndToEnd (E1-6): Begin, review, a passkey step-up (and an e-mail-code one) bound to the flow, approval, the
// loopback redirect, Complete with the node key proof. The node receives a node credential of the approving account: tokens of the
// node lifetimes, the family's absolute end, its installation, the account summary (masked e-mail), the published keys; the
// credential refreshes and reports. The authorize URL is the node's derived one byte for byte.
func TestBrowserSignInEndToEnd(t *testing.T) {
	for _, byEmail := range []bool{false, true} {
		h := newHarness(t, settings{})
		owner := h.person(1)
		s, refusal := h.begin()
		if refusal != nil {
			t.Fatalf("begin: %s", failure(refusal))
		}
		if got := s.value.GetAuthorizeUrl(); got != nodetest.DerivedAuthorizeURL(publicBaseURL, s.flowID[:]) || len(got) > 512 ||
			time.Until(instant(s.value.GetExpiresAt())) > 10*time.Minute+time.Second {
			t.Fatalf("authorize URL %q expires %v", got, instant(s.value.GetExpiresAt()))
		}
		review := h.review(owner, s)
		view := review.GetValue().GetFlow()
		if review.GetError() != nil || view.GetState() != fleetv1.NodeSignInState_NODE_SIGN_IN_STATE_PENDING || view.GetNode().GetVersion() != "0.1.0-dev" ||
			view.GetNode().GetName() != "buildbox" || flowIDOf(view.GetFlowId()) != s.flowID {
			t.Fatalf("review: %s %+v", failure(review.GetError()), view)
		}
		h.approve(owner, s, byEmail)
		completed := h.complete(s)
		credentials := completed.GetValue().GetCredentials()
		if completed.GetError() != nil || credentials == nil {
			t.Fatalf("complete: %s", failure(completed.GetError()))
		}
		lifetime := time.Duration(credentials.GetAccessLifetimeMs()) * time.Millisecond
		if lifetime != time.Hour || !strings.HasPrefix(credentials.GetAccessToken(), session.AccessPrefix) || !strings.HasPrefix(credentials.GetRefreshToken(), session.RefreshPrefix) ||
			time.Until(instant(credentials.GetSessionExpiresAt())) < 364*24*time.Hour || len(credentials.GetInstallationId().GetValue()) != 16 ||
			flowIDOf(credentials.GetAccount().GetAccountId()) != owner.id || credentials.GetAccount().GetDisplayName() != "Owner" ||
			credentials.GetAccount().GetEmailMasked() != "o***@example.test" || credentials.GetAccount().Plan != nil || credentials.GetEntitlementToken() != nil {
			t.Fatalf("credentials %+v", credentials)
		}
		method := map[bool]int{false: 1, true: 2}[byEmail]
		if h.count("SELECT count(*) FROM identity.session WHERE scope = 3 AND user_id = $1 AND revoked_at IS NULL AND auth_method = 1", owner.id) != 1 ||
			h.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND state = 3 AND approver_auth_method = 1", s.flowID) != 1 ||
			h.count("SELECT count(*) FROM identity.step_up_challenge WHERE user_id = $1 AND state = 3 AND method = $2", owner.id, method) != 1 {
			t.Fatal("the rows of the sign-in are not as expected")
		}
		if _, refusal := h.report(credentials.GetAccessToken(), command(), s.node.Info()); refusal != nil {
			t.Fatalf("the new credential's report: %s", failure(refusal))
		}
		if value, refusal := h.refresh(credentials.GetRefreshToken()); refusal != nil || value == nil {
			t.Fatalf("the new credential's refresh: %s", failure(refusal))
		}
		if h.audits("fleet.node.enrolled") != 1 || h.audits("fleet.node_sign_in.approved") != 1 {
			t.Fatal("the audit events are missing")
		}
	}
}

// TestTheSignInRowsAdmitOnlyAnAccount (E1-3 for the E1b rows; Q24, T-19): the review and the decision admit an account session;
// a mobile.limited session must upgrade (step_up_required); a node, push or automation credential is refused (principal or scope)
// and a restricted account (restricted, audit only: the wire reason is the operation ID), each without a write; Begin and Complete
// need no credential.
func TestTheSignInRowsAdmitOnlyAnAccount(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	s, _ := h.begin()
	writes := func() int {
		return h.count("SELECT (SELECT coalesce(sum(rev), 0) FROM fleet.node_sign_in) + (SELECT count(*) FROM identity.step_up_challenge WHERE state = 3)")
	}
	node := h.enroll(1)
	for name, bearer := range map[string]string{"node": node.access, "push": h.issue(owner.id, session.ScopePush).AccessToken,
		"automation": h.issue(owner.id, session.ScopeAutomation).AccessToken} {
		before := writes()
		for _, path := range []string{reviewPath, approvePath} {
			response := &fleetv1.NodeEnrollmentServiceApproveNodeSignInResponse{}
			reply := h.post(path, &fleetv1.NodeEnrollmentServiceApproveNodeSignInRequest{Meta: meta(), FlowId: &foundationv1.Id{Value: s.flowID[:]}, Approve: proto.Bool(false)}, bearer)
			if reply.Body == nil || proto.Unmarshal(reply.Body, response) != nil || failure(response.GetError()) != "AUTHORIZATION/permission_denied" {
				t.Errorf("%s on %s: %+v", name, path, reply)
			}
		}
		if writes() != before {
			t.Errorf("%s wrote", name)
		}
	}
	limited := h.issue(owner.id, session.ScopeMobileLimited).AccessToken
	if response := h.decide(limited, s, false); failure(response.GetError()) != "AUTHENTICATION/step_up_required" {
		t.Errorf("mobile.limited: %s", failure(response.GetError()))
	}
	restricted := h.person(2)
	if response := h.review(restricted, s); failure(response.GetError()) != "AUTHORIZATION/permission_denied" ||
		response.GetError().GetDetails().GetState().GetReason() != "fleet.getNodeSignInFlow" {
		t.Errorf("restricted: %s %+v", failure(response.GetError()), response.GetError().GetDetails())
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1 AND reason = 'restricted'", access.AuditRefused) != 1 {
		t.Error("the restricted refusal is not audited with its reason")
	}
	// The account itself is admitted; without evidence the approval is step_up_required, a denial needs none.
	if response := h.review(owner, s); response.GetError() != nil {
		t.Fatalf("the account's review: %s", failure(response.GetError()))
	}
	if response := h.decide(owner.bearer, s, true); failure(response.GetError()) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("an approval without evidence: %s", failure(response.GetError()))
	}
	if response := rpc(h, approvePath, &fleetv1.NodeEnrollmentServiceApproveNodeSignInRequest{Meta: meta(), FlowId: &foundationv1.Id{Value: s.flowID[:]}}, owner.bearer,
		&fleetv1.NodeEnrollmentServiceApproveNodeSignInResponse{}); failure(response.GetError()) != "VALIDATION/invalid_argument" {
		t.Fatalf("a decision without approve: %s", failure(response.GetError()))
	}
	denied := h.decide(owner.bearer, s, false)
	if denied.GetError() != nil || denied.GetValue().GetFlow().GetState() != fleetv1.NodeSignInState_NODE_SIGN_IN_STATE_DENIED ||
		!strings.HasSuffix(denied.GetValue().GetRedirectUrl(), "?error=access_denied&state="+s.pkce.State) {
		t.Fatalf("deny: %s %+v", failure(denied.GetError()), denied.GetValue())
	}
}

// TestCompleteRefusalsOverTheWire (E1-8; the C0 errors of CompleteNodeSignIn): an unknown flow is STATE/not_found naming the presented
// flow; a malformed verifier VALIDATION/invalid_argument; a wrong code AUTHENTICATION/unauthenticated without details; the correct code
// again CONFLICT/code_reused; Begin with a held key CONFLICT/already_exists node_key / already_registered.
func TestCompleteRefusalsOverTheWire(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	s, _ := h.begin()
	h.approve(owner, s, false)
	unknown := platform.NewID()
	request := s.node.CompleteRequest(unknown, s.code, s.pkce, s.node.CompleteProof(publicBaseURL, unknown, s.code))
	if response := h.completeWith(request); failure(response.GetError()) != "STATE/not_found" ||
		!proto.Equal(response.GetError().GetDetails().GetState().GetResource().GetId(), &foundationv1.Id{Value: unknown[:]}) {
		t.Fatalf("an unknown flow: %+v", response.GetError())
	}
	request = s.node.CompleteRequest(s.flowID, s.code, s.pkce, s.node.CompleteProof(publicBaseURL, s.flowID, s.code))
	request.CodeVerifier = proto.String("short")
	if response := h.completeWith(request); failure(response.GetError()) != "VALIDATION/invalid_argument" {
		t.Fatalf("a malformed verifier: %s", failure(response.GetError()))
	}
	request = s.node.CompleteRequest(s.flowID, "wrong", s.pkce, s.node.CompleteProof(publicBaseURL, s.flowID, "wrong"))
	if response := h.completeWith(request); failure(response.GetError()) != "AUTHENTICATION/unauthenticated" || response.GetError().GetDetails().GetState() != nil {
		t.Fatalf("a wrong code: %+v", response.GetError())
	}
	if response := h.complete(s); response.GetError() != nil {
		t.Fatalf("the right code: %s", failure(response.GetError()))
	}
	if response := h.complete(s); failure(response.GetError()) != "CONFLICT/code_reused" {
		t.Fatalf("the code again: %s", failure(response.GetError()))
	}
	_, refusal := h.beginFor(s.node)
	if failure(refusal) != "CONFLICT/already_exists" || refusal.GetDetails().GetState().GetState() != "node_key" ||
		refusal.GetDetails().GetState().GetReason() != "already_registered" || refusal.GetDetails().GetState().GetResource() != nil {
		t.Fatalf("a held key: %+v", refusal)
	}
}

// TestApprovalDoesNotOutliveTheAccountsRemediation (SEC-24, protocol-6 finding A, the binding hook): after the approving session
// itself signs out all other sessions, or removes a credential, the approved flow is DENIED and its code completes nothing; the
// audit events count the cancellation.
func TestApprovalDoesNotOutliveTheAccountsRemediation(t *testing.T) {
	for _, remediation := range []string{"revoke all sessions", "remove a credential"} {
		h := newHarness(t, settings{})
		owner := h.person(1)
		s, _ := h.begin()
		h.approve(owner, s, false)
		eventType := "identity.sessions.revoked_all"
		if remediation == "revoke all sessions" {
			h.stepUp(owner, identity.ClassRevokeAllSessions, owner.id, false)
			if response := rpc(h, "/arcforges.publicapi.v1.IdentityService/RevokeAllSessions", &publicapiv1.IdentityServiceRevokeAllSessionsRequest{Meta: command()},
				owner.bearer, &publicapiv1.IdentityServiceRevokeAllSessionsResponse{}); response.GetError() != nil {
				t.Fatalf("%s: %s", remediation, failure(response.GetError()))
			}
		} else {
			eventType = "identity.credential.removed"
			h.stepUp(owner, identity.ClassRemoveCredential, owner.emailID, false)
			if response := rpc(h, "/arcforges.publicapi.v1.IdentityService/RemoveAuthIdentity", &publicapiv1.IdentityServiceRemoveAuthIdentityRequest{Meta: command(),
				CredentialId: &foundationv1.Id{Value: owner.emailID[:]}}, owner.bearer, &publicapiv1.IdentityServiceRemoveAuthIdentityResponse{}); response.GetError() != nil {
				t.Fatalf("%s: %s", remediation, failure(response.GetError()))
			}
		}
		if response := h.complete(s); failure(response.GetError()) != "AUTHENTICATION/unauthenticated" {
			t.Fatalf("%s: the approval's code afterwards: %s", remediation, failure(response.GetError()))
		}
		if h.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND state = 4", s.flowID) != 1 || h.count("SELECT count(*) FROM fleet.node") != 0 {
			t.Fatalf("%s: the flow is not denied", remediation)
		}
		var participants map[string]int64
		if err := json.Unmarshal(mustJSON(h.payload(eventType)["participants"]), &participants); err != nil || participants["fleet.node_sign_in"] != 1 {
			t.Fatalf("%s: participants %v %v", remediation, participants, err)
		}
	}
}

func mustJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}

// TestTheSignInStoresNoSecret (E1-18 for the browser sign-in): after a sign-in, a reuse and a failed proof, no one-use code, PKCE
// verifier, node key proof or issued token appears in any fleet, identity, audit or rate-limit row, in the server log or in
// pg_stat_statements.
func TestTheSignInStoresNoSecret(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	s, _ := h.begin()
	h.approve(owner, s, false)
	proof := s.node.CompleteProof(publicBaseURL, s.flowID, s.code)
	if response := h.completeWith(s.node.CompleteRequest(s.flowID, s.code, s.pkce, proof)); response.GetError() != nil {
		t.Fatal(failure(response.GetError()))
	}
	_ = h.complete(s)
	failed, _ := h.begin()
	h.approve(owner, failed, false)
	_ = h.completeWith(failed.node.CompleteRequest(failed.flowID, failed.code, nodetest.NewSignIn(), failed.node.CompleteProof(publicBaseURL, failed.flowID, failed.code)))
	secrets := []string{s.code, s.pkce.Verifier, failed.code, failed.pkce.Verifier, base64.RawURLEncoding.EncodeToString(proof), base64.StdEncoding.EncodeToString(proof),
		strings.ToLower(hexText(proof))}
	for _, token := range h.secrets {
		if body, ok := strings.CutPrefix(token, session.AccessPrefix); ok {
			secrets = append(secrets, body)
		}
		if body, ok := strings.CutPrefix(token, session.RefreshPrefix); ok {
			secrets = append(secrets, body)
		}
	}
	ctx := context.Background()
	var dump string
	if err := h.db.Migration.QueryRow(ctx, `SELECT string_agg(row_text, E'\n') FROM (
    SELECT t::text AS row_text FROM fleet.node_sign_in t UNION ALL SELECT t::text FROM identity.session t UNION ALL SELECT t::text FROM fleet.node t
    UNION ALL SELECT t::text FROM device.installation t UNION ALL SELECT t::text FROM audit.audit_event t UNION ALL SELECT t::text FROM platform.rate_limit t
    UNION ALL SELECT t::text FROM identity.step_up_challenge t UNION ALL SELECT t::text FROM platform.command_receipt t) rows`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	var statements string
	_ = h.db.Migration.QueryRow(ctx, "SELECT coalesce(string_agg(query, E'\\n'), '') FROM pg_stat_statements").Scan(&statements)
	for _, secret := range secrets {
		for name, text := range map[string]string{"store": dump, "log": h.logs.String(), "statements": statements} {
			if secret != "" && strings.Contains(text, secret) {
				t.Errorf("a generated secret reached the %s", name)
			}
		}
	}
}

func hexText(data []byte) string {
	const digits = "0123456789abcdef"
	text := make([]byte, 0, 2*len(data))
	for _, b := range data {
		text = append(text, digits[b>>4], digits[b&15])
	}
	return string(text)
}

// instant is a contract Instant as a time.
func instant(value *foundationv1.Instant) time.Time {
	return time.Unix(value.GetUnixSeconds(), int64(value.GetNanos()))
}

// TestTheSignInRowsUpgradeAMobileLimitedSession (T-19, driven by the operation table like identityapi's TestMobileLimitedNeedsStepUp):
// every fleet row whose mobile.limited rule is not Allowed answers a mobile.limited session AUTHENTICATION/step_up_required (retry the
// same command) without writing anything; a fleet row without a request here fails the test.
func TestTheSignInRowsUpgradeAMobileLimitedSession(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	s, _ := h.begin()
	limited := h.issue(owner.id, session.ScopeMobileLimited).AccessToken
	flow := &foundationv1.Id{Value: s.flowID[:]}
	requests := map[string]proto.Message{
		reviewPath:  &fleetv1.NodeEnrollmentServiceGetNodeSignInFlowRequest{Meta: meta(), FlowId: flow},
		approvePath: &fleetv1.NodeEnrollmentServiceApproveNodeSignInRequest{Meta: meta(), FlowId: flow, Approve: proto.Bool(true)},
	}
	writes := func() int { return h.count("SELECT coalesce(sum(rev), 0)::int FROM fleet.node_sign_in") }
	for _, operation := range access.Operations() {
		if !operation.Session || operation.MobileLimited == access.Allowed || !strings.HasPrefix(operation.Path, "/arcforges.fleet.v1.") {
			continue
		}
		request, ok := requests[operation.Path]
		if !ok {
			t.Errorf("%s needs a step-up of a mobile.limited session, but this test has no request for it", operation.ID)
			continue
		}
		delete(requests, operation.Path)
		before := writes()
		response := &fleetv1.NodeEnrollmentServiceApproveNodeSignInResponse{}
		reply := h.post(operation.Path, request, limited)
		if reply.Body == nil || proto.Unmarshal(reply.Body, response) != nil || failure(response.GetError()) != "AUTHENTICATION/step_up_required" ||
			response.GetError().GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND || writes() != before {
			t.Errorf("%s from a mobile.limited session: %+v", operation.ID, response.GetError())
		}
	}
	for path := range requests {
		t.Errorf("%s has a request, but the operation table opens it to mobile.limited", path)
	}
}
