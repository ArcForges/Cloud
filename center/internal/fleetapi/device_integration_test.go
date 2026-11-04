// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi_test

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// EVIDENCE: as signin_integration_test.go: REAL PostgreSQL, the real center behind an httptest listener, binary gRPC-Web; MOCKED node
// (nodetest), passkey (virtual authenticator, verified by the real relying party) and mail sender (the harness inbox). These tests
// drive the device-code sign-in through the served API: Start, the lookup, a step-up bound to the normalized user code, the
// decision under the account's command receipt, and the node's polls.

const (
	startPath         = "/arcforges.fleet.v1.NodeEnrollmentService/StartDeviceAuthorization"
	pollPath          = "/arcforges.fleet.v1.NodeEnrollmentService/PollDeviceAuthorization"
	lookupPath        = "/arcforges.fleet.v1.NodeEnrollmentService/LookupDeviceCode"
	approveDevicePath = "/arcforges.fleet.v1.NodeEnrollmentService/ApproveDeviceCode"
)

// deviceSignIn is a node's device-code sign-in in progress.
type deviceSignIn struct {
	node          *nodetest.Node
	authorization *fleetv1.DeviceAuthorization
}

func (h *harness) start() (*deviceSignIn, *foundationv1.ArcError) {
	h.t.Helper()
	node, err := nodetest.New()
	if err != nil {
		h.t.Fatal(err)
	}
	response := rpc(h, startPath, node.StartRequest(), "", &fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationResponse{})
	if response.GetError() != nil {
		return &deviceSignIn{node: node}, response.GetError()
	}
	authorization := response.GetValue().GetAuthorization()
	h.secrets = append(h.secrets, authorization.GetDeviceCode())
	return &deviceSignIn{node: node, authorization: authorization}, nil
}

func (h *harness) lookup(p *person, code string) *fleetv1.NodeEnrollmentServiceLookupDeviceCodeResponse {
	h.t.Helper()
	return rpc(h, lookupPath, &fleetv1.NodeEnrollmentServiceLookupDeviceCodeRequest{Meta: meta(), UserCode: proto.String(code)}, p.bearer,
		&fleetv1.NodeEnrollmentServiceLookupDeviceCodeResponse{})
}

func (h *harness) decideDevice(bearer string, metaValue *foundationv1.RequestMeta, code string, approve bool) *fleetv1.NodeEnrollmentServiceApproveDeviceCodeResponse {
	h.t.Helper()
	return rpc(h, approveDevicePath, &fleetv1.NodeEnrollmentServiceApproveDeviceCodeRequest{Meta: metaValue, UserCode: proto.String(code), Approve: proto.Bool(approve)},
		bearer, &fleetv1.NodeEnrollmentServiceApproveDeviceCodeResponse{})
}

// stepUpCode proves a step-up of class fleet.approveDeviceCode bound to a normalized user code, as the page computes its target hash.
func (h *harness) stepUpCode(p *person, code string, byEmail bool) {
	h.t.Helper()
	h.stepUpHash(p, fleet.ClassApproveDeviceCode, identity.TextTargetHash(fleet.ClassApproveDeviceCode, p.id, code), byEmail)
}

func (h *harness) poll(d *deviceSignIn) *fleetv1.NodeEnrollmentServicePollDeviceAuthorizationResponse {
	h.t.Helper()
	code := d.authorization.GetDeviceCode()
	response := rpc(h, pollPath, d.node.PollRequest(code, d.node.PollProof(publicBaseURL, code)), "", &fleetv1.NodeEnrollmentServicePollDeviceAuthorizationResponse{})
	if credentials := response.GetValue().GetCredentials(); credentials != nil {
		h.secrets = append(h.secrets, credentials.GetAccessToken(), credentials.GetRefreshToken())
	}
	return response
}

// TestDeviceCodeEndToEnd (E2-2): Start (the derived URIs byte for byte, the 8 letters, 5,000 ms, 600 s), a first poll (PENDING), the
// lookup of the hyphenated lower-case code (the node as it described itself, its canonical version), a step-up by passkey and by e-mail
// code bound to the normalized code, the approval (a Receipt), the poll that delivers the node credential of the approving account,
// which refreshes and reports; a second poll answers COMPLETED without credentials and revokes them.
func TestDeviceCodeEndToEnd(t *testing.T) {
	for _, byEmail := range []bool{false, true} {
		h := newHarness(t, settings{})
		owner := h.person(1)
		d, refusal := h.start()
		if refusal != nil {
			t.Fatalf("start: %s", failure(refusal))
		}
		a := d.authorization
		code := a.GetUserCode()
		if len(code) != 8 || len(a.GetDeviceCode()) != 43 || a.GetVerificationUri() != nodetest.DerivedVerificationURI(publicBaseURL) ||
			a.GetVerificationUriComplete() != nodetest.DerivedVerificationURIComplete(publicBaseURL, code) || len(a.GetVerificationUriComplete()) > 512 ||
			a.GetIntervalMs() != 5000 || time.Until(instant(a.GetExpiresAt())) > 600*time.Second+time.Second {
			t.Fatalf("authorization %+v", a)
		}
		if polled := h.poll(d); polled.GetError() != nil || polled.GetValue().GetState() != fleetv1.DeviceAuthorizationState_DEVICE_AUTHORIZATION_STATE_PENDING {
			t.Fatalf("the first poll: %s %+v", failure(polled.GetError()), polled.GetValue())
		}
		looked := h.lookup(owner, strings.ToLower(code[:4])+"-"+strings.ToLower(code[4:]))
		node := looked.GetValue().GetNode()
		if looked.GetError() != nil || node.GetName() != "buildbox" || node.GetVersion() != "0.1.0-dev" || string(node.GetNodeId().GetValue()) != string(d.node.ID[:]) {
			t.Fatalf("lookup: %s %+v", failure(looked.GetError()), node)
		}
		h.stepUpCode(owner, code, byEmail)
		metaValue := command()
		decided := h.decideDevice(owner.bearer, metaValue, code[:4]+" "+code[4:], true)
		if decided.GetError() != nil || string(decided.GetValue().GetReceipt().GetCommandId().GetValue()) != string(metaValue.GetCommandId().GetValue()) ||
			decided.GetValue().GetReceipt().GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED {
			t.Fatalf("approve: %s %+v", failure(decided.GetError()), decided.GetValue())
		}
		// The harness runs on the real clock: the first poll's time is moved back one interval (SEEDED) instead of waiting 5 seconds.
		if _, err := h.db.Migration.Exec(context.Background(), "UPDATE fleet.device_authorization SET last_poll_at = last_poll_at - interval '5 seconds', rev = rev + 1"); err != nil {
			t.Fatal(err)
		}
		polled := h.poll(d)
		credentials := polled.GetValue().GetCredentials()
		if polled.GetError() != nil || polled.GetValue().GetState() != fleetv1.DeviceAuthorizationState_DEVICE_AUTHORIZATION_STATE_APPROVED || credentials == nil {
			t.Fatalf("the delivering poll: %s %+v", failure(polled.GetError()), polled.GetValue())
		}
		if time.Duration(credentials.GetAccessLifetimeMs())*time.Millisecond != time.Hour || !strings.HasPrefix(credentials.GetAccessToken(), session.AccessPrefix) ||
			string(credentials.GetAccount().GetAccountId().GetValue()) != string(owner.id[:]) || credentials.GetAccount().GetEmailMasked() != "o***@example.test" ||
			credentials.GetEntitlementToken() != nil || time.Until(instant(credentials.GetSessionExpiresAt())) < 364*24*time.Hour {
			t.Fatalf("credentials %+v", credentials)
		}
		method := map[bool]int{false: 1, true: 2}[byEmail]
		if h.count("SELECT count(*) FROM identity.step_up_challenge WHERE user_id = $1 AND state = 3 AND method = $2 AND operation_id = 'fleet.approveDeviceCode'",
			owner.id, method) != 1 || h.count("SELECT count(*) FROM fleet.device_authorization WHERE state = 6 AND approver_auth_method = 1") != 1 {
			t.Fatal("the rows of the sign-in are not as expected")
		}
		if _, refusal := h.report(credentials.GetAccessToken(), command(), d.node.Info()); refusal != nil {
			t.Fatalf("the new credential's report: %s", failure(refusal))
		}
		if value, refusal := h.refresh(credentials.GetRefreshToken()); refusal != nil || value == nil {
			t.Fatalf("the new credential's refresh: %s", failure(refusal))
		}
		again := h.poll(d)
		if again.GetError() != nil || again.GetValue().GetState() != fleetv1.DeviceAuthorizationState_DEVICE_AUTHORIZATION_STATE_COMPLETED || again.GetValue().GetCredentials() != nil {
			t.Fatalf("the second poll: %s %+v", failure(again.GetError()), again.GetValue())
		}
		if h.count("SELECT count(*) FROM identity.session WHERE scope = 3 AND user_id = $1 AND revoked_at IS NULL", owner.id) != 0 ||
			h.audits("fleet.node.enrolled") != 1 || h.audits("fleet.device_authorization.approved") != 1 || h.audits("fleet.device_authorization.code_reused") != 1 {
			t.Fatal("the reuse did not revoke the family, or the events are missing")
		}
	}
}

// TestTheDeviceRowsAdmitOnlyAnAccount (E1-3 for the E2 rows; Q24, T-19): Lookup and the decision admit an account session; a node,
// push or automation credential is refused (permission_denied), a restricted account too (the wire reason the operation ID), each
// with no write and no reservation; malformed user codes, a decision without approve and one without meta.command_id are
// VALIDATION/invalid_argument and cost nothing; Start and Poll need no credential.
func TestTheDeviceRowsAdmitOnlyAnAccount(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	d, _ := h.start()
	writes := func() int {
		return h.count(`SELECT (SELECT coalesce(sum(rev), 0) FROM fleet.device_authorization) + (SELECT coalesce(sum(count), 0) FROM platform.rate_limit)
+ (SELECT count(*) FROM platform.command_receipt)`)
	}
	node := h.enroll(1)
	restricted := h.person(2)
	before := writes()
	for name, bearer := range map[string]string{"node": node.access, "push": h.issue(owner.id, session.ScopePush).AccessToken,
		"automation": h.issue(owner.id, session.ScopeAutomation).AccessToken} {
		if response := h.lookup(&person{bearer: bearer}, d.authorization.GetUserCode()); failure(response.GetError()) != "AUTHORIZATION/permission_denied" {
			t.Errorf("%s on Lookup: %s", name, failure(response.GetError()))
		}
		if response := h.decideDevice(bearer, command(), d.authorization.GetUserCode(), false); failure(response.GetError()) != "AUTHORIZATION/permission_denied" {
			t.Errorf("%s on the decision: %s", name, failure(response.GetError()))
		}
	}
	if response := h.lookup(restricted, d.authorization.GetUserCode()); failure(response.GetError()) != "AUTHORIZATION/permission_denied" ||
		response.GetError().GetDetails().GetState().GetReason() != "fleet.lookupDeviceCode" {
		t.Errorf("restricted: %s %+v", failure(response.GetError()), response.GetError().GetDetails())
	}
	for _, malformed := range []*string{nil, proto.String(""), proto.String("BCDFGHJ"), proto.String("ABCDEFGH"), proto.String("BCDF_GHJK"), proto.String("BCDFGHJK")} {
		response := rpc(h, lookupPath, &fleetv1.NodeEnrollmentServiceLookupDeviceCodeRequest{Meta: meta(), UserCode: malformed}, owner.bearer,
			&fleetv1.NodeEnrollmentServiceLookupDeviceCodeResponse{})
		want := "user_code: pattern"
		if malformed == nil {
			want = "user_code: required"
		}
		if failure(response.GetError()) != "VALIDATION/invalid_argument" || response.GetError().GetDetails().GetState().GetReason() != want {
			t.Errorf("%v: %s %+v", malformed, failure(response.GetError()), response.GetError().GetDetails())
		}
	}
	if response := rpc(h, approveDevicePath, &fleetv1.NodeEnrollmentServiceApproveDeviceCodeRequest{Meta: command(), UserCode: proto.String("BCDFGHJK")}, owner.bearer,
		&fleetv1.NodeEnrollmentServiceApproveDeviceCodeResponse{}); response.GetError().GetDetails().GetState().GetReason() != "approve: required" {
		t.Errorf("a decision without approve: %+v", response.GetError())
	}
	if response := h.decideDevice(owner.bearer, meta(), "BCDFGHJK", false); response.GetError().GetDetails().GetState().GetReason() != "meta.command_id: required" {
		t.Errorf("a decision without a command ID: %+v", response.GetError())
	}
	if writes() != before {
		t.Fatal("a refused credential, a restricted account or a malformed request wrote or reserved")
	}
}

// TestApproveDeviceCodeReceipts (OPS-01): the decision runs under the account's command receipt. A replay of a committed approval is
// answered with its receipt and counts nothing; the same command ID with another request is CONFLICT/command_id_reused; a final
// refusal (not_reviewed) is kept and answered to its replay even after the account reviewed the code; step_up_required is not kept,
// so the same command succeeds after the step-up.
func TestApproveDeviceCodeReceipts(t *testing.T) {
	h := newHarness(t, settings{})
	owner := h.person(1)
	d, _ := h.start()
	code := d.authorization.GetUserCode()
	refused := command()
	if response := h.decideDevice(owner.bearer, refused, code, true); failure(response.GetError()) != "STATE/invalid_state" ||
		response.GetError().GetDetails().GetState().GetReason() != "not_reviewed" {
		t.Fatalf("an unreviewed code: %s", failure(response.GetError()))
	}
	if looked := h.lookup(owner, code); looked.GetError() != nil {
		t.Fatal(failure(looked.GetError()))
	}
	h.stepUpCode(owner, code, false)
	if response := h.decideDevice(owner.bearer, refused, code, true); response.GetError().GetDetails().GetState().GetReason() != "not_reviewed" {
		t.Fatalf("the replay of a kept refusal: %s", failure(response.GetError()))
	}
	approval := command()
	other, _ := h.start()
	if looked := h.lookup(owner, other.authorization.GetUserCode()); looked.GetError() != nil {
		t.Fatal(failure(looked.GetError()))
	}
	if response := h.decideDevice(owner.bearer, approval, other.authorization.GetUserCode(), true); failure(response.GetError()) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("without evidence: %s", failure(response.GetError()))
	}
	h.stepUpCode(owner, other.authorization.GetUserCode(), false)
	first := h.decideDevice(owner.bearer, approval, other.authorization.GetUserCode(), true)
	if first.GetError() != nil {
		t.Fatalf("the same command after the step-up: %s", failure(first.GetError()))
	}
	counted := h.count("SELECT coalesce(sum(count), 0) FROM platform.rate_limit")
	audits := h.count("SELECT count(*) FROM audit.audit_event")
	replay := h.decideDevice(owner.bearer, approval, other.authorization.GetUserCode(), true)
	if replay.GetError() != nil || !proto.Equal(replay.GetValue(), first.GetValue()) || h.count("SELECT coalesce(sum(count), 0) FROM platform.rate_limit") != counted ||
		h.count("SELECT count(*) FROM audit.audit_event") != audits {
		t.Fatalf("the replay: %s %+v", failure(replay.GetError()), replay.GetValue())
	}
	if response := h.decideDevice(owner.bearer, approval, other.authorization.GetUserCode(), false); failure(response.GetError()) != "CONFLICT/command_id_reused" {
		t.Fatalf("the command ID with another request: %s", failure(response.GetError()))
	}
}

// TestTheDeviceSignInStoresNoSecret (E1-18 for E2): the device code, the user code in both forms, the poll proof and the tokens a poll
// delivers reach no row of the store, no server log line and no recorded statement.
func TestTheDeviceSignInStoresNoSecret(t *testing.T) {
	h := newHarness(t, settings{})
	readStatements := h.trackStatements()
	owner := h.person(1)
	d, _ := h.start()
	code := d.authorization.GetUserCode()
	if looked := h.lookup(owner, code); looked.GetError() != nil {
		t.Fatal(failure(looked.GetError()))
	}
	h.stepUpCode(owner, code, false)
	if response := h.decideDevice(owner.bearer, command(), code, true); response.GetError() != nil {
		t.Fatal(failure(response.GetError()))
	}
	proof := d.node.PollProof(publicBaseURL, d.authorization.GetDeviceCode())
	if response := rpc(h, pollPath, d.node.PollRequest(d.authorization.GetDeviceCode(), proof), "", &fleetv1.NodeEnrollmentServicePollDeviceAuthorizationResponse{}); response.GetValue().GetCredentials() == nil {
		t.Fatal(failure(response.GetError()))
	} else {
		h.secrets = append(h.secrets, response.GetValue().GetCredentials().GetAccessToken(), response.GetValue().GetCredentials().GetRefreshToken())
	}
	secrets := []string{d.authorization.GetDeviceCode(), code, fleet.DisplayUserCode(code), base64.RawURLEncoding.EncodeToString(proof), base64.StdEncoding.EncodeToString(proof),
		strings.ToLower(hexText(proof))}
	for _, token := range h.secrets {
		if body, ok := strings.CutPrefix(token, session.AccessPrefix); ok {
			secrets = append(secrets, body)
		}
		if body, ok := strings.CutPrefix(token, session.RefreshPrefix); ok {
			secrets = append(secrets, body)
		}
	}
	var dump string
	if err := h.db.Migration.QueryRow(context.Background(), `SELECT string_agg(row_text, E'\n') FROM (
    SELECT t::text AS row_text FROM fleet.device_authorization t UNION ALL SELECT t::text FROM identity.session t UNION ALL SELECT t::text FROM fleet.node t
    UNION ALL SELECT t::text FROM device.installation t UNION ALL SELECT t::text FROM audit.audit_event t UNION ALL SELECT t::text FROM platform.rate_limit t
    UNION ALL SELECT t::text FROM identity.step_up_challenge t UNION ALL SELECT t::text FROM platform.command_receipt t) rows`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	statements := readStatements()
	for _, secret := range secrets {
		for name, text := range map[string]string{"store": dump, "log": h.logs.String(), "statements": statements} {
			if secret != "" && strings.Contains(text, secret) {
				t.Errorf("a generated secret reached the %s", name)
			}
		}
	}
}

// TestTheDeviceDecisionRowDecidesItsEvidence (Q1, NB-4 of E1b): the ApproveDeviceCode row needs evidence to approve and none to deny.
func TestTheDeviceDecisionRowDecidesItsEvidence(t *testing.T) {
	for _, operation := range access.Operations() {
		if operation.ID != "fleet.approveDeviceCode" {
			continue
		}
		if !operation.NeedsEvidenceToDecide(true) || operation.NeedsEvidenceToDecide(false) || operation.Target != access.TargetUserCode {
			t.Fatalf("the row %+v", operation)
		}
		return
	}
	t.Fatal("no ApproveDeviceCode row")
}
