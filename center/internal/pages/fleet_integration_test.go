// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"crypto/sha256"
	"encoding/hex"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The fleet surface's pages (AF-CTR-04 E3) against a composed center and a real PostgreSQL: a node (nodetest, MOCKED) starts a sign-in
// over the API, an account reviews and decides it on /connect or /activate in a browser session (the virtual authenticator, MOCKED, proves
// the step-up through the pages' routes), and the tests read the rows the decisions wrote.

const (
	beginPath    = "/arcforges.fleet.v1.NodeEnrollmentService/BeginNodeSignIn"
	startPath    = "/arcforges.fleet.v1.NodeEnrollmentService/StartDeviceAuthorization"
	completePath = "/arcforges.fleet.v1.NodeEnrollmentService/CompleteNodeSignIn"
)

func fleetHarness(t *testing.T, hosted bool) *harness {
	t.Helper()
	return newHarness(t, settings{surfaces: "identity,pages,fleet", policy: writePolicy, hosted: hosted})
}

// nodeCall sends a node's request over the API with extra headers (the hosted Worker's origin headers) and decodes the reply.
func nodeCall[Response proto.Message](h *harness, path string, message proto.Message, headers http.Header, response Response) Response {
	h.t.Helper()
	data, err := proto.Marshal(message)
	if err != nil {
		h.t.Fatal(err)
	}
	reply := h.do(request{method: http.MethodPost, path: path, contentType: "application/grpc-web+proto", body: ingress.Frame(data), noOrigin: true,
		ip: "198.51.100.7", headers: headers})
	if reply.status != http.StatusOK || len(reply.body) < 5 || reply.body[0] != 0 {
		h.t.Fatalf("%s: %d", path, reply.status)
	}
	length := int(reply.body[1])<<24 | int(reply.body[2])<<16 | int(reply.body[3])<<8 | int(reply.body[4])
	if err = proto.Unmarshal(reply.body[5:5+length], response); err != nil {
		h.t.Fatal(err)
	}
	return response
}

type begunFlow struct {
	node   *nodetest.Node
	signIn nodetest.SignIn
	flowID platform.ID
}

func (h *harness) beginFlow(headers http.Header) begunFlow {
	h.t.Helper()
	node, err := nodetest.New()
	if err != nil {
		h.t.Fatal(err)
	}
	signIn := nodetest.NewSignIn()
	reply := nodeCall(h, beginPath, node.BeginRequest(signIn), headers, &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{})
	if reply.GetError() != nil {
		h.t.Fatalf("begin: %v", reply.GetError())
	}
	var flowID platform.ID
	copy(flowID[:], reply.GetValue().GetFlowId().GetValue())
	return begunFlow{node: node, signIn: signIn, flowID: flowID}
}

type startedCode struct {
	node *nodetest.Node
	code string
}

func (h *harness) startCode(headers http.Header) startedCode {
	h.t.Helper()
	node, err := nodetest.New()
	if err != nil {
		h.t.Fatal(err)
	}
	reply := nodeCall(h, startPath, node.StartRequest(), headers, &fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationResponse{})
	if reply.GetError() != nil {
		h.t.Fatalf("start: %v", reply.GetError())
	}
	return startedCode{node: node, code: reply.GetValue().GetAuthorization().GetUserCode()}
}

// stepUpText proves a step-up whose target is a text (the device-code approval's normalized user code).
func (b *browser) stepUpText(who account, class, target string) response {
	b.h.t.Helper()
	begun := b.postJSON("/session/v1/web/step-up/begin", map[string]any{"operationClass": class, "method": "passkey",
		"targetHash": identity.TextTargetHash(class, who.id, target)})
	if begun.status != 200 {
		return begun
	}
	var challenge challengeReply
	begun.json(b.h.t, &challenge)
	return b.postJSON("/session/v1/web/step-up/complete", map[string]any{"flowId": challenge.FlowID,
		"proof": map[string]any{"passkey": assertionJSON(who.authenticator.Assert(who.key, unb64(b.h.t, challenge.Challenge)))}})
}

var (
	commandPattern = regexp.MustCompile(`name="command_id" value="([0-9a-f-]{36})"`)
	hrefPattern    = regexp.MustCompile(`id="return-link" href="([^"]+)"`)
)

// field is the first value of a hidden field the page carries.
func field(t *testing.T, reply response, pattern *regexp.Regexp) string {
	t.Helper()
	found := pattern.FindStringSubmatch(reply.text())
	if found == nil {
		t.Fatalf("the page carries no %s: %s", pattern, reply.text())
	}
	return html.UnescapeString(found[1])
}

func (h *harness) flowState(flowID platform.ID) int {
	return h.count("SELECT state FROM fleet.node_sign_in WHERE flow_id = $1", flowID)
}

func (h *harness) codeState(code string) int {
	digest := sha256Hex(code)
	return h.count("SELECT state FROM fleet.device_authorization WHERE encode(user_code_hash, 'hex') = $1", digest)
}

func (h *harness) codeLookups(code string) int {
	return h.count("SELECT lookups FROM fleet.device_authorization WHERE encode(user_code_hash, 'hex') = $1", sha256Hex(code))
}

// TestTheConnectPagesApproveAndDenyABrowserSignIn: the static page, the review (the node, its key's fingerprint, the times, the account,
// the origin), the approval with its step-up, the result page's loopback link, the node's completion with the code from that link,
// and the devices page's node credential expiry; then a denial's link.
func TestTheConnectPagesApproveAndDenyABrowserSignIn(t *testing.T) {
	h := fleetHarness(t, false)
	owner := h.seedAccount(1)
	b := h.newBrowser()
	page := b.get("/connect")
	if page.status != 200 || !strings.Contains(page.text(), `data-page="connect"`) || !strings.Contains(page.text(), `id="connect-review"`) {
		t.Fatalf("GET /connect: %d %s", page.status, page.text())
	}
	b.mustSignIn(owner)
	flow := h.beginFlow(nil)
	review := b.postForm("/connect/review", url.Values{"flow_id": {uuid(flow.flowID)}})
	text := review.text()
	for _, want := range []string{`<bdi id="node-name">buildbox</bdi>`, "The name is reported by the node and is not verified.", fleet.Fingerprint(flow.node.PublicKey),
		"Linux x64", "Origin unknown", `data-step-up-class="fleet.approveNodeSignIn"`, `data-step-up-target="` + hashOf(fleet.ClassApproveNodeSignIn, owner.id, flow.flowID) + `"`,
		`id="deny"`, `id="approve"`} {
		if review.status != 200 || !strings.Contains(text, want) {
			t.Fatalf("the review lacks %q: %d %s", want, review.status, text)
		}
	}
	if strings.Index(text, `id="deny"`) > strings.Index(text, `id="approve"`) {
		t.Fatal("Deny is not first")
	}
	if h.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND viewed_by = $2", flow.flowID, owner.id) != 1 {
		t.Fatal("the review recorded no reviewer")
	}
	b.mustStepUp(owner, fleet.ClassApproveNodeSignIn, flow.flowID)
	done := b.postForm("/connect/decision", url.Values{"flow_id": {uuid(flow.flowID)}, "decision": {"approve"}})
	if done.status != 200 || !strings.Contains(done.text(), `data-page="connect-done"`) || !strings.Contains(done.text(), `rel="noopener noreferrer"`) ||
		done.header.Get("Location") != "" || !strings.Contains(done.text(), "must run on the computer that runs the node") {
		t.Fatalf("the decision: %d %s", done.status, done.text())
	}
	redirect := field(t, done, hrefPattern)
	code, err := flow.signIn.LoopbackCode(redirect)
	if err != nil {
		t.Fatal(err)
	}
	h.remember(code)
	if h.flowState(flow.flowID) != int(fleet.FlowApproved) {
		t.Fatal("the flow is not approved")
	}
	completed := nodeCall(h, completePath, flow.node.CompleteRequest(flow.flowID, code, flow.signIn, flow.node.CompleteProof(publicBaseURL, flow.flowID, code)), nil,
		&fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse{})
	if completed.GetError() != nil {
		t.Fatalf("complete: %v", completed.GetError())
	}
	h.remember(completed.GetValue().GetCredentials().GetAccessToken(), completed.GetValue().GetCredentials().GetRefreshToken())
	devices := b.get("/account/devices")
	if devices.status != 200 || !strings.Contains(devices.text(), "Node sign-in valid until") || !strings.Contains(devices.text(), "<bdi>buildbox</bdi>") {
		t.Fatalf("the devices page: %d %s", devices.status, devices.text())
	}
	// A denial: the result page links the node's loopback with error=access_denied, and the flow is DENIED; no step-up is needed.
	denied := h.beginFlow(nil)
	b.postForm("/connect/review", url.Values{"flow_id": {uuid(denied.flowID)}})
	result := b.postForm("/connect/decision", url.Values{"flow_id": {uuid(denied.flowID)}, "decision": {"deny"}})
	if result.status != 200 || !strings.Contains(field(t, result, hrefPattern), "error=access_denied") || h.flowState(denied.flowID) != int(fleet.FlowDenied) {
		t.Fatalf("the denial: %d %s", result.status, result.text())
	}
	h.verifyAudit()
}

// TestADecisionWithoutEvidenceShowsTheReviewAgain: a /connect approval without a step-up keeps the refusal's status and shows the review
// again (GetNodeSignInFlow counts nothing); the flow stays PENDING.
func TestADecisionWithoutEvidenceShowsTheReviewAgain(t *testing.T) {
	h := fleetHarness(t, false)
	owner := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(owner)
	flow := h.beginFlow(nil)
	b.postForm("/connect/review", url.Values{"flow_id": {uuid(flow.flowID)}})
	again := b.postForm("/connect/decision", url.Values{"flow_id": {uuid(flow.flowID)}, "decision": {"approve"}})
	if again.status != http.StatusForbidden || !strings.Contains(again.text(), `data-page="connect-review"`) || !strings.Contains(again.text(), "passkey check") ||
		!strings.Contains(again.text(), `id="approve"`) {
		t.Fatalf("the decision without evidence: %d %s", again.status, again.text())
	}
	if h.flowState(flow.flowID) != int(fleet.FlowPending) {
		t.Fatal("the flow changed")
	}
}

// TestTheActivatePagesApproveADeviceCode: the static page, a review that withholds the fingerprint's last group and asks for it, the
// approval with the tail and the step-up under the account's receipt, the result page that still offers the denial, and that denial.
func TestTheActivatePagesApproveADeviceCode(t *testing.T) {
	h := fleetHarness(t, false)
	owner := h.seedAccount(1)
	b := h.newBrowser()
	if page := b.get("/activate"); page.status != 200 || !strings.Contains(page.text(), `<label for="user-code">Activation code</label>`) {
		t.Fatalf("GET /activate: %d %s", page.status, page.text())
	}
	b.mustSignIn(owner)
	started := h.startCode(nil)
	h.remember(started.code)
	review := b.postForm("/activate/review", url.Values{"user_code": {strings.ToLower(nodetest.DisplayUserCode(started.code))}})
	full := fleet.Fingerprint(started.node.PublicKey)
	tail := fleet.FingerprintTail(started.node.PublicKey)
	if review.status != 200 || !strings.Contains(review.text(), full[:len(full)-4]+"????") || strings.Contains(review.text(), full) ||
		!strings.Contains(review.text(), `name="fingerprint_tail"`) || !strings.Contains(review.text(), `data-step-up-class="fleet.approveDeviceCode"`) ||
		!strings.Contains(review.text(), `data-step-up-target="`+identity.TextTargetHash(fleet.ClassApproveDeviceCode, owner.id, started.code)+`"`) {
		t.Fatalf("the review: %d %s", review.status, review.text())
	}
	if h.codeLookups(started.code) != 1 {
		t.Fatal("the review counted no lookup")
	}
	command := field(t, review, commandPattern)
	if reply := b.stepUpText(owner, fleet.ClassApproveDeviceCode, started.code); reply.status != 200 {
		t.Fatalf("step-up: %d", reply.status)
	}
	done := b.postForm("/activate/decision", url.Values{"user_code": {started.code}, "command_id": {command}, "decision": {"approve"},
		"fingerprint_tail": {strings.ToLower(tail)}})
	if done.status != 200 || !strings.Contains(done.text(), `data-page="activate-done"`) || !strings.Contains(done.text(), `id="deny"`) {
		t.Fatalf("the decision: %d %s", done.status, done.text())
	}
	if h.codeState(started.code) != int(fleet.AuthorizationApproved) || h.audits("fleet.device_authorization.approved") != 1 {
		t.Fatal("the code is not approved")
	}
	// The approver may still deny it while the credentials are not delivered: the result page's denial (its own command).
	denied := b.postForm("/activate/decision", url.Values{"user_code": {started.code}, "command_id": {field(t, done, commandPattern)}, "decision": {"deny"}})
	if denied.status != 200 || h.codeState(started.code) != int(fleet.AuthorizationDenied) {
		t.Fatalf("the denial: %d %s", denied.status, denied.text())
	}
	if h.codeLookups(started.code) != 1 {
		t.Fatal("a decision looked the code up again")
	}
	h.verifyAudit()
}

// TestTheActivateDecisionNeverLooksTheCodeUpAgain (E2 NB-9, R-1, R-2): a decision without evidence and one with a wrong fingerprint tail
// keep the refusal's status and show the review again without a second lookup; the wrong tail consumes no evidence and keeps the
// entry's reservation; the re-rendered review carries a new command ID, with which the right tail approves; the old command ID with
// another tail is a reused command, not the stored answer of the first tail.
func TestTheActivateDecisionNeverLooksTheCodeUpAgain(t *testing.T) {
	h := fleetHarness(t, false)
	owner := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(owner)
	started := h.startCode(nil)
	h.remember(started.code)
	review := b.postForm("/activate/review", url.Values{"user_code": {started.code}})
	tail := fleet.FingerprintTail(started.node.PublicKey)
	first := field(t, review, commandPattern)
	again := b.postForm("/activate/decision", url.Values{"user_code": {started.code}, "command_id": {first}, "decision": {"approve"}, "fingerprint_tail": {tail}})
	if again.status != http.StatusForbidden || !strings.Contains(again.text(), `data-page="activate-review"`) || h.codeLookups(started.code) != 1 {
		t.Fatalf("without evidence: %d lookups %d %s", again.status, h.codeLookups(started.code), again.text())
	}
	second := field(t, again, commandPattern)
	if second == first {
		t.Fatal("the review shown again keeps the command ID")
	}
	if reply := b.stepUpText(owner, fleet.ClassApproveDeviceCode, started.code); reply.status != 200 {
		t.Fatalf("step-up: %d", reply.status)
	}
	wrong := "0000"
	if tail == wrong {
		wrong = "FFFF"
	}
	mismatch := b.postForm("/activate/decision", url.Values{"user_code": {started.code}, "command_id": {second}, "decision": {"approve"}, "fingerprint_tail": {wrong}})
	if mismatch.status != http.StatusBadRequest || !strings.Contains(mismatch.text(), `data-page="activate-review"`) ||
		!strings.Contains(mismatch.text(), "not the last 4 characters") || h.codeLookups(started.code) != 1 {
		t.Fatalf("a wrong tail: %d lookups %d %s", mismatch.status, h.codeLookups(started.code), mismatch.text())
	}
	if h.count("SELECT count(*) FROM identity.step_up_challenge WHERE user_id = $1 AND state = 2", owner.id) != 1 {
		t.Fatal("the wrong tail consumed the evidence")
	}
	if h.codeState(started.code) != int(fleet.AuthorizationPending) {
		t.Fatal("the wrong tail changed the code")
	}
	// The second command ID answered the wrong tail; the right tail with it is another request: a reused command ID (not the stored
	// answer of the wrong tail, which would show the review again).
	reused := b.postForm("/activate/decision", url.Values{"user_code": {started.code}, "command_id": {second}, "decision": {"approve"}, "fingerprint_tail": {tail}})
	if reused.status != http.StatusBadRequest || h.codeState(started.code) != int(fleet.AuthorizationPending) ||
		strings.Contains(reused.text(), `data-page="activate-review"`) || !strings.Contains(reused.text(), "That form was already used") {
		t.Fatalf("the second command with another tail: %d %s", reused.status, reused.text())
	}
	third := field(t, mismatch, commandPattern)
	approved := b.postForm("/activate/decision", url.Values{"user_code": {started.code}, "command_id": {third}, "decision": {"approve"}, "fingerprint_tail": {tail}})
	if approved.status != 200 || h.codeState(started.code) != int(fleet.AuthorizationApproved) || h.codeLookups(started.code) != 1 {
		t.Fatalf("the right tail: %d %s", approved.status, approved.text())
	}
	// The entries the account spent: the wrong tail only (a right lookup, a refused step-up of a reviewed code and the approval gave
	// theirs back, the reused command reserved none), so a wrong code now leaves 3 of the 5.
	if wrongCode := b.postForm("/activate/review", url.Values{"user_code": {"BCDF-GHJK"}}); !strings.Contains(wrongCode.text(), "You can try 3 more codes now") {
		t.Fatalf("the entries after a wrong tail: %d %s", wrongCode.status, wrongCode.text())
	}
}

// TestOtherDecisionRefusalsShowNoReview (R-2): only a refused step-up and a tail mismatch show the review again; a decision on a code
// this account did not review, and a malformed code, answer the error page and read nothing.
func TestOtherDecisionRefusalsShowNoReview(t *testing.T) {
	h := fleetHarness(t, false)
	owner := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(owner)
	started := h.startCode(nil)
	h.remember(started.code)
	unreviewed := b.postForm("/activate/decision", url.Values{"user_code": {started.code}, "command_id": {uuid(platform.NewID())}, "decision": {"deny"}})
	if unreviewed.status != http.StatusBadRequest || strings.Contains(unreviewed.text(), `data-page="activate-review"`) ||
		!strings.Contains(unreviewed.text(), "needs a fresh review") || strings.Contains(unreviewed.text(), "buildbox") {
		t.Fatalf("a decision of an unreviewed code: %d %s", unreviewed.status, unreviewed.text())
	}
	malformed := b.postForm("/activate/decision", url.Values{"user_code": {"BCDF-GHJA"}, "command_id": {uuid(platform.NewID())}, "decision": {"deny"}})
	if malformed.status != http.StatusBadRequest || strings.Contains(malformed.text(), `data-page="activate-review"`) {
		t.Fatalf("a malformed code: %d %s", malformed.status, malformed.text())
	}
	if h.codeLookups(started.code) != 0 || h.codeState(started.code) != int(fleet.AuthorizationPending) {
		t.Fatal("a refused decision looked the code up or changed it")
	}
	// The decision of the unreviewed code was counted as a wrong entry (E2's F7 resolution: a not_reviewed keeps its unit), so no
	// read before the decision answered it for free; the malformed code cost nothing: a wrong code now leaves 3 of the 5.
	if wrong := b.postForm("/activate/review", url.Values{"user_code": {"BCDF-GHJK"}}); !strings.Contains(wrong.text(), "You can try 3 more codes now") {
		t.Fatalf("the entries after an unreviewed decision: %d %s", wrong.status, wrong.text())
	}
}

// TestTheActivateTextsFollowTheLimit (E2 NB, R-7): a wrong code says how many attempts are left, the last one that none are, a code whose
// five lookups are spent says so, and a malformed code costs nothing.
func TestTheActivateTextsFollowTheLimit(t *testing.T) {
	h := fleetHarness(t, false)
	owner := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(owner)
	if malformed := b.postForm("/activate/review", url.Values{"user_code": {"BCDF-GHJ"}}); malformed.status != http.StatusBadRequest ||
		!strings.Contains(malformed.text(), "Enter the 8 letters") {
		t.Fatalf("malformed: %d %s", malformed.status, malformed.text())
	}
	wrong := b.postForm("/activate/review", url.Values{"user_code": {"BCDF-GHJK"}})
	if wrong.status != http.StatusBadRequest || !strings.Contains(wrong.text(), "You can try 4 more codes now") || !strings.Contains(wrong.text(), `data-page="activate"`) {
		t.Fatalf("a wrong code: %d %s", wrong.status, wrong.text())
	}
	for range 3 {
		b.postForm("/activate/review", url.Values{"user_code": {"BCDF-GHJK"}})
	}
	if last := b.postForm("/activate/review", url.Values{"user_code": {"BCDF-GHJK"}}); !strings.Contains(last.text(), "no attempts are left") {
		t.Fatalf("the last attempt: %d %s", last.status, last.text())
	}
	if limited := b.postForm("/activate/review", url.Values{"user_code": {"BCDF-GHJK"}}); limited.status != http.StatusTooManyRequests {
		t.Fatalf("over the budget: %d %s", limited.status, limited.text())
	}
	// A second account looks one live code up five times; the sixth lookup names the spent lookups.
	other := h.seedAccount(1)
	c := h.newBrowser()
	c.mustSignIn(other)
	started := h.startCode(nil)
	h.remember(started.code)
	for range 5 {
		if reply := c.postForm("/activate/review", url.Values{"user_code": {started.code}}); reply.status != 200 {
			t.Fatalf("a lookup: %d", reply.status)
		}
	}
	if spent := c.postForm("/activate/review", url.Values{"user_code": {started.code}}); !strings.Contains(spent.text(), "looked up too often") {
		t.Fatalf("the sixth lookup: %d %s", spent.status, spent.text())
	}
}

// TestTheFleetPagesKeepTheBrowserProtocol (SEC-06): every fleet POST without its Origin, with a foreign one, without the CSRF token, with
// a query or of another media type is refused before any domain call; a GET with a query is refused; nothing is written.
func TestTheFleetPagesKeepTheBrowserProtocol(t *testing.T) {
	h := fleetHarness(t, false)
	owner := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(owner)
	flow := h.beginFlow(nil)
	form := "application/x-www-form-urlencoded"
	for _, path := range []string{"/connect/review", "/connect/decision", "/activate/review", "/activate/decision"} {
		fields := url.Values{"flow_id": {uuid(flow.flowID)}}
		if strings.HasPrefix(path, "/activate") {
			fields = url.Values{"user_code": {"BCDF-GHJK"}}
		}
		unsigned := fields.Encode()
		fields.Set("csrf", b.csrf)
		body := fields.Encode()
		for name, probe := range map[string]request{
			"no origin":      {method: http.MethodPost, path: path, contentType: form, body: []byte(body), cookie: b.cookie, noOrigin: true},
			"foreign origin": {method: http.MethodPost, path: path, contentType: form, body: []byte(body), cookie: b.cookie, origin: "https://evil.example.test"},
			"no token":       {method: http.MethodPost, path: path, contentType: form, body: []byte(unsigned), cookie: b.cookie},
			"no session":     {method: http.MethodPost, path: path, contentType: form, body: []byte(body)},
		} {
			if reply := h.do(probe); reply.status != http.StatusForbidden {
				t.Errorf("%s %s: %d", name, path, reply.status)
			}
		}
		if reply := h.do(request{method: http.MethodPost, path: path + "?x", contentType: form, body: []byte(body), cookie: b.cookie}); reply.status != http.StatusBadRequest {
			t.Errorf("query %s: %d", path, reply.status)
		}
		if reply := h.do(request{method: http.MethodPost, path: path, contentType: "application/json", body: []byte("{}"), cookie: b.cookie}); reply.status != http.StatusUnsupportedMediaType {
			t.Errorf("media %s: %d", path, reply.status)
		}
	}
	// A flow ID of another shape is refused by its own pattern before any call (upper case, braces, all zero).
	for _, bad := range []string{strings.ToUpper(uuid(flow.flowID)), "{" + uuid(flow.flowID) + "}", "00000000-0000-0000-0000-000000000000"} {
		reply := b.postForm("/connect/review", url.Values{"flow_id": {bad}})
		if reply.status != http.StatusBadRequest || !strings.Contains(reply.text(), "This link is not complete") {
			t.Errorf("flow_id %q: %d", bad, reply.status)
		}
	}
	for _, path := range []string{"/connect", "/activate"} {
		if reply := b.get(path + "?flow=" + uuid(flow.flowID)); reply.status != http.StatusBadRequest {
			t.Errorf("GET %s with a query: %d", path, reply.status)
		}
	}
	if h.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND viewed_by IS NULL AND state = 1", flow.flowID) != 1 {
		t.Fatal("a refused request touched the flow")
	}
}

// TestTheFleetPagesAreAbsentWhileFleetIsOff: with identity and pages but not fleet, every fleet page is 404 before anything is checked.
func TestTheFleetPagesAreAbsentWhileFleetIsOff(t *testing.T) {
	h := newHarness(t, settings{surfaces: "identity,pages", policy: writePolicy})
	b := h.newBrowser()
	for _, probe := range []request{{method: http.MethodGet, path: "/connect"}, {method: http.MethodGet, path: "/activate"},
		{method: http.MethodPost, path: "/connect/review"}, {method: http.MethodPost, path: "/connect/decision"},
		{method: http.MethodPost, path: "/activate/review"}, {method: http.MethodPost, path: "/activate/decision"}} {
		probe.headers = b.headers()
		if reply := h.do(probe); reply.status != http.StatusNotFound || len(reply.body) != 0 {
			t.Errorf("%s %s: %d", probe.method, probe.path, reply.status)
		}
	}
}

// TestNodeTextIsEscapedAndIsolatedOnTheFleetPages (SEC-20, protocol-11): a node name of markup, bidirectional controls and look-alike
// trust wording (seeded by SQL, as Begin's validator refuses most of it) is escaped, sits in its own isolate in quotes, and the page says
// it is not verified.
func TestNodeTextIsEscapedAndIsolatedOnTheFleetPages(t *testing.T) {
	h := fleetHarness(t, false)
	owner := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(owner)
	for _, name := range []string{`<script>alert(1)</script>`, "a\u202Eevil\u202C", "ArcForges Updater (verified)", "x\u2066y\u2069\u200B", `"><img src=x>`} {
		flow := h.beginFlow(nil)
		if _, err := h.migration.Exec(t.Context(), "UPDATE fleet.node_sign_in SET node_name = $2 WHERE flow_id = $1", flow.flowID, name); err != nil {
			t.Fatal(err)
		}
		review := b.postForm("/connect/review", url.Values{"flow_id": {uuid(flow.flowID)}})
		text := review.text()
		if review.status != 200 || strings.Contains(text, "<script>alert") || strings.Contains(text, "<img src=x>") ||
			!strings.Contains(text, `&ldquo;<bdi id="node-name">`) || !strings.Contains(text, "is not verified") {
			t.Fatalf("%q: %d %s", name, review.status, text)
		}
	}
}

// TestTheOriginLineIsTheHostedEdgesOnly (protocol-17, B-1): on the official hosted center the Worker's country and network headers are
// stored at Begin and shown; a self-hosted center stores and shows no origin, even from a trusted proxy that sends both headers.
func TestTheOriginLineIsTheHostedEdgesOnly(t *testing.T) {
	origin := http.Header{http.CanonicalHeaderKey(config.ClientCountryHeader): {"DE"}, http.CanonicalHeaderKey(config.ClientASNHeader): {"3320"}}
	for _, hosted := range []bool{true, false} {
		h := fleetHarness(t, hosted)
		owner := h.seedAccount(1)
		b := h.newBrowser()
		b.mustSignIn(owner)
		flow := h.beginFlow(origin)
		started := h.startCode(origin)
		h.remember(started.code)
		stored := h.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND begin_country = 'DE' AND begin_asn = 3320", flow.flowID) +
			h.count("SELECT count(*) FROM fleet.device_authorization WHERE begin_country = 'DE' AND begin_asn = 3320")
		empty := h.count("SELECT count(*) FROM fleet.node_sign_in WHERE flow_id = $1 AND begin_country IS NULL AND begin_asn IS NULL", flow.flowID) +
			h.count("SELECT count(*) FROM fleet.device_authorization WHERE begin_country IS NULL AND begin_asn IS NULL")
		connect := b.postForm("/connect/review", url.Values{"flow_id": {uuid(flow.flowID)}}).text()
		activate := b.postForm("/activate/review", url.Values{"user_code": {started.code}}).text()
		if hosted {
			if stored != 2 || !strings.Contains(connect, "Request came from DE, network AS3320") || !strings.Contains(activate, "Request came from DE, network AS3320") {
				t.Fatalf("hosted: stored %d", stored)
			}
			continue
		}
		if empty != 2 || !strings.Contains(connect, "Origin unknown") || !strings.Contains(activate, "Origin unknown") {
			t.Fatalf("self-hosted: empty %d", empty)
		}
	}
}

// TestARestrictedAccountIsToldWhy (Q24): the operation table refuses a Restricted account's review; the page names the restriction.
func TestARestrictedAccountIsToldWhy(t *testing.T) {
	h := fleetHarness(t, false)
	owner := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(owner)
	flow := h.beginFlow(nil)
	if _, err := h.migration.Exec(t.Context(), "UPDATE identity.user SET state = 2 WHERE user_id = $1", owner.id); err != nil {
		t.Fatal(err)
	}
	reply := b.postForm("/connect/review", url.Values{"flow_id": {uuid(flow.flowID)}})
	if reply.status != http.StatusForbidden || !strings.Contains(reply.text(), "restricted") {
		t.Fatalf("restricted: %d %s", reply.status, reply.text())
	}
}

func sha256Hex(text string) string {
	digest := sha256.Sum256([]byte(text))
	return hex.EncodeToString(digest[:])
}
