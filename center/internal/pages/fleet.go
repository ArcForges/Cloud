// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The fleet surface's pages (AF-CTR-04 E3): /connect, where an account approves a node's browser sign-in, and /activate, where it
// approves a node's device-code sign-in. They decide nothing node enrollment does not: each review and decision calls the
// NodeEnrollmentService method it stands for in process (fleetapi.Direct), with the cookie session as the caller, so the page and the
// API share the operation table, the step-up evidence, the review window, the rate-limit buckets, the receipts and the audit events.
// The flow ID and the user code reach the pages in the URL's fragment, which only the script reads; the two GET pages are static.
// What the pages add is the browser's protocol (Origin, CSRF, no query), the review page's content (the node as it described itself,
// its key's fingerprint, the times, the account it will join, the request's origin) and, on /activate, the check that the person
// approving types the last group of the fingerprint the node prints (protocol-17), which the review page withholds.

// tailPattern is a fingerprint tail as typed: four hexadecimal characters, either case.
var tailPattern = regexp.MustCompile(`^[0-9A-Fa-f]{4}$`)

// fleetView is everything the fleet templates read besides the page frame.
type fleetView struct {
	// The flow or the code the page is about: the flow ID of a browser sign-in; the normalized user code of a device sign-in and the
	// form in which people read it.
	FlowID   string
	UserCode string
	Display  string
	// The node as it described itself, and its key's fingerprint (on /activate without its last group, which the person types).
	Name        string
	OS          string
	Arch        string
	Version     string
	Fingerprint string
	// The times: when the node asked (and how long ago), and when the request expires.
	RequestedAt   string
	RequestedText string
	Age           string
	ExpiresAt     string
	ExpiresText   string
	// The account the node will join, and where the node's request came from.
	Account string
	Origin  string
	// What the page offers: the decision forms of a PENDING request, or only the denial of an APPROVED one the account approved.
	Decide   bool
	DenyOnly bool
	State    string
	// The step-up target of an approval and the command ID of a device decision (new for every rendered review).
	Target  string
	Command string
	// The result: the redirect to the node's loopback receiver (a browser sign-in), whether the decision approved.
	Redirect string
	Approved bool
}

// osNames and archNames are how the pages name a node's system.
var (
	osNames   = map[int16]string{1: "Windows", 2: "Linux"}
	archNames = map[int16]string{1: "x64", 2: "Arm64"}
)

// stateTexts say what a request that is no longer awaiting a decision is.
var stateTexts = map[int16]string{
	fleet.FlowApproved:  "You approved this request. The node finishes the sign-in on its own.",
	fleet.FlowDenied:    "This request was denied. The node cannot use it.",
	fleet.FlowCompleted: "This node finished signing in with this request.",
	fleet.FlowExpired:   "This request has expired. Start again on the node.",
	fleet.FlowRevoked:   "This request was ended because its one-use code was presented twice. Start again on the node.",
}

// ageText is how long ago an instant was, in words.
func ageText(at, now time.Time) string {
	seconds := int(now.Sub(at).Seconds())
	switch {
	case seconds < 2:
		return "just now"
	case seconds < 120:
		return fmt.Sprintf("%d seconds ago", seconds)
	}
	return fmt.Sprintf("%d minutes ago", seconds/60)
}

// originText is the origin line of a review (protocol-17): the country and network the hosted edge saw, or that it is unknown. It is
// a hint with no judgement: no "same network" or "different network" text.
func originText(origin fleet.Origin) string {
	if origin.Country == nil {
		return "Origin unknown"
	}
	if origin.ASN == nil {
		return "Request came from " + *origin.Country
	}
	return fmt.Sprintf("Request came from %s, network AS%d", *origin.Country, *origin.ASN)
}

// accountText is the account the node will join: its display name and masked e-mail address.
func (e *exchange) accountText(userID platform.ID) string {
	summary, err := e.h.options.Fleet.Account(e.r.Context(), userID)
	switch {
	case err != nil:
		return "this account"
	case summary.EmailMasked != "":
		return summary.DisplayName + " (" + summary.EmailMasked + ")"
	}
	return summary.DisplayName
}

// nodeView fills the node, its key and the times of a review.
func (e *exchange) nodeView(view *fleetView, name string, os, arch int16, version string, key []byte, created, expires time.Time, origin fleet.Origin,
	userID platform.ID, withheld bool) {
	now := e.h.options.Clock()
	view.Name, view.OS, view.Arch, view.Version = name, osNames[os], archNames[arch], version
	view.Fingerprint = fleet.Fingerprint(key)
	if withheld {
		view.Fingerprint = view.Fingerprint[:len(view.Fingerprint)-fleet.TailLength] + "????"
	}
	view.RequestedAt, view.RequestedText, view.Age = attribute(created), timeText(created), ageText(created, now)
	view.ExpiresAt, view.ExpiresText = attribute(expires), timeText(expires)
	view.Origin = originText(origin)
	view.Account = e.accountText(userID)
}

// fleetCall is the admitted call of a fleet method for the exchange, with the request message as the receipt digests it.
func (e *exchange) fleetCall(path string, resolved *session.BrowserSession, request proto.Message) (*ingress.Call, bool) {
	call, err := e.call(path, resolved, message(request))
	if err != nil {
		e.internal(err)
		return nil, false
	}
	return call, true
}

// flowField reads the flow ID of a form: the canonical lower-case 8-4-4-4-12 form, not all zero.
func (e *exchange) flowField(values map[string][]string) (platform.ID, bool) {
	id, ok := parseUUID(first(values, "flow_id"))
	if !ok || id == (platform.ID{}) {
		e.fail(arc.InvalidArgument("flow_id", "pattern"))
		return platform.ID{}, false
	}
	return id, true
}

func first(values map[string][]string, name string) string {
	if list := values[name]; len(list) == 1 {
		return list[0]
	}
	return ""
}

// connectPage is GET /connect: the consent page of a browser sign-in. It is static: the script reads the flow ID from the fragment,
// removes the fragment, asks who is signed in and submits the review.
func (e *exchange) connectPage() { e.serve("connect", pageData{Title: "Connect a node"}) }

// activatePage is GET /activate: the activation page of a device-code sign-in, with the code field the script fills from the fragment.
func (e *exchange) activatePage() { e.serve("activate", pageData{Title: "Activate a node"}) }

// connectReview is POST /connect/review: GetNodeSignInFlow. A PENDING flow is shown with its decision forms (reviewing it records the
// account and time, as the method does); a flow this account approved is shown with the denial only; any other is shown with its state.
func (e *exchange) connectReview() {
	values, resolved, ok := e.formSession("flow_id")
	if !ok {
		return
	}
	flowID, ok := e.flowField(values)
	if !ok {
		return
	}
	e.renderConnectReview(resolved, flowID, nil, 0)
}

// renderConnectReview reviews a flow (GetNodeSignInFlow) and renders the review page, with the error of a refused decision when there
// is one (the page keeps that refusal's status).
func (e *exchange) renderConnectReview(resolved *session.BrowserSession, flowID platform.ID, refused *foundationv1.ArcError, status int) {
	request := &fleetv1.NodeEnrollmentServiceGetNodeSignInFlowRequest{Meta: &foundationv1.RequestMeta{}, FlowId: idOf(flowID)}
	call, ok := e.fleetCall(fleetv1connect.NodeEnrollmentServiceGetNodeSignInFlowProcedure, resolved, request)
	if !ok {
		return
	}
	flow, failure := e.h.options.Fleet.GetNodeSignInFlow(e.r.Context(), call, request)
	if e.arcFailure(failure) {
		return
	}
	view := fleetView{FlowID: uuidText(flowID), State: stateTexts[flow.State]}
	e.nodeView(&view, flow.Name, flow.OS, flow.Arch, flow.Version, flow.PublicKey, flow.CreatedAt, flow.ExpiresAt, flow.Origin, resolved.UserID, false)
	switch flow.State {
	case fleet.FlowPending:
		view.Decide = true
		view.Target = identity.TargetHash(fleet.ClassApproveNodeSignIn, resolved.UserID, flowID)
	case fleet.FlowApproved:
		view.DenyOnly = true
	}
	data := pageData{Title: "Connect this node?", Signed: true, CSRF: resolved.CSRF, Fleet: view}
	if refused != nil {
		data.Error = &errorView{Text: e.fleetText(refused)}
	}
	e.serveStatus("connect-review", data, status)
}

// connectDecision is POST /connect/decision: ApproveNodeSignIn. The approval consumes the step-up evidence the script proved for the
// flow; the reply is a page with the link back to the node's loopback receiver, which the script follows after checking it. A decision
// without evidence shows the review again (GetNodeSignInFlow, which counts nothing).
func (e *exchange) connectDecision() {
	values, resolved, ok := e.formSession("flow_id", "decision")
	if !ok {
		return
	}
	flowID, ok := e.flowField(values)
	if !ok {
		return
	}
	approve, ok := e.decisionField(values)
	if !ok {
		return
	}
	request := &fleetv1.NodeEnrollmentServiceApproveNodeSignInRequest{Meta: &foundationv1.RequestMeta{}, FlowId: idOf(flowID), Approve: proto.Bool(approve)}
	call, ok := e.fleetCall(fleetv1connect.NodeEnrollmentServiceApproveNodeSignInProcedure, resolved, request)
	if !ok {
		return
	}
	decision, failure := e.h.options.Fleet.ApproveNodeSignIn(e.r.Context(), call, request)
	if failure != nil {
		if stepUpRequired(failure) {
			e.renderConnectReview(resolved, flowID, failure, statusOf(failure))
			return
		}
		e.refuseError(failure, 0)
		return
	}
	title := "Return to your terminal"
	e.serve("connect-done", pageData{Title: title, Signed: true, CSRF: resolved.CSRF, Fleet: fleetView{FlowID: uuidText(flowID),
		Redirect: decision.RedirectURL, Approved: approve, Name: decision.Flow.Name}})
}

// decisionField reads a decision: approve or deny.
func (e *exchange) decisionField(values map[string][]string) (bool, bool) {
	switch first(values, "decision") {
	case "approve":
		return true, true
	case "deny":
		return false, true
	}
	e.fail(arc.InvalidArgument("decision", "pattern"))
	return false, false
}

func stepUpRequired(value *foundationv1.ArcError) bool {
	return value.GetCategory() == foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHENTICATION && value.GetCode() == "step_up_required"
}

// tailMismatch is the refusal of a fingerprint tail that is not the node key's (fleet.DecideDevice).
func tailMismatch(value *foundationv1.ArcError) bool {
	return value.GetCategory() == foundationv1.ErrorCategory_ERROR_CATEGORY_VALIDATION && value.GetCode() == "invalid_argument" &&
		value.GetDetails().GetState().GetReason() == "fingerprint_tail: mismatch"
}

// codeField reads a user code: 8 letters of the code alphabet, case-insensitive, separators ignored (C0: malformed input costs nothing,
// so it is refused before any call).
func (e *exchange) codeField(values map[string][]string) (string, bool) {
	code, ok := fleet.NormalizeUserCode(first(values, "user_code"))
	if !ok {
		return "", false
	}
	return code, true
}

// activateReview is POST /activate/review: LookupDeviceCode. It counts one of the code's five lookups and reserves an entry of the
// account's and the network's budgets, as the method does; a refused entry shows the activation page again with its text.
func (e *exchange) activateReview() {
	values, resolved, ok := e.formSession("user_code")
	if !ok {
		return
	}
	code, ok := e.codeField(values)
	if !ok {
		e.activateAgain(resolved, arc.InvalidArgument("user_code", "pattern").Dated(e.h.options.Clock()).ArcError(e.correlation))
		return
	}
	request := &fleetv1.NodeEnrollmentServiceLookupDeviceCodeRequest{Meta: &foundationv1.RequestMeta{}, UserCode: proto.String(code)}
	call, ok := e.fleetCall(fleetv1connect.NodeEnrollmentServiceLookupDeviceCodeProcedure, resolved, request)
	if !ok {
		return
	}
	view, failure := e.h.options.Fleet.LookupDeviceCode(e.r.Context(), call, request)
	if failure != nil {
		e.activateAgain(resolved, failure)
		return
	}
	e.renderActivateReview(resolved, code, view, nil, 0)
}

// activateAgain shows the activation page again with a refusal's text and status (the field is left empty: the page never repeats a
// code the request carried).
func (e *exchange) activateAgain(resolved *session.BrowserSession, value *foundationv1.ArcError) {
	if value.GetCategory() == foundationv1.ErrorCategory_ERROR_CATEGORY_INTERNAL || value.GetCategory() == foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE &&
		value.GetCode() != "rate_limited" {
		e.refuseError(value, 0)
		return
	}
	e.serveStatus("activate", pageData{Title: "Activate a node", Signed: true, CSRF: resolved.CSRF, Error: &errorView{Text: e.fleetText(value)}},
		statusOf(value))
}

// renderActivateReview renders the review of a device code: the node, its key's fingerprint without the last group, the times, the
// account and the origin, the denial and the approval (which asks for the last group). Every rendering mints a new command ID for the
// decision, so a corrected tail is a new command.
func (e *exchange) renderActivateReview(resolved *session.BrowserSession, code string, device fleet.DeviceView, refused *foundationv1.ArcError, status int) {
	view := fleetView{UserCode: code, Display: fleet.DisplayUserCode(code), Decide: true, Command: newCommand(),
		Target: identity.TextTargetHash(fleet.ClassApproveDeviceCode, resolved.UserID, code)}
	e.nodeView(&view, device.Name, device.OS, device.Arch, device.Version, device.PublicKey, device.CreatedAt, device.ExpiresAt, device.Origin, resolved.UserID,
		true)
	data := pageData{Title: "Activate this node?", Signed: true, CSRF: resolved.CSRF, Fleet: view}
	if refused != nil {
		data.Error = &errorView{Text: e.fleetText(refused)}
	}
	e.serveStatus("activate-review", data, status)
}

// activateDecision is POST /activate/decision: ApproveDeviceCode under the account's command receipt, with the fingerprint tail the
// person typed (an approval only). After AUTHENTICATION/step_up_required or a tail mismatch, both of which the decision answers only
// once its review check passed, the review is shown again from a read that counts no lookup (E2 NB-9); every other refusal is the
// error page. An approval's page offers the denial while the credentials are not yet delivered.
func (e *exchange) activateDecision() {
	values, resolved, ok := e.formSession("user_code", "command_id", "decision", "fingerprint_tail")
	if !ok {
		return
	}
	code, ok := e.codeField(values)
	if !ok {
		e.fail(arc.InvalidArgument("user_code", "pattern"))
		return
	}
	commandID, ok := e.formID(values, "command_id")
	if !ok {
		return
	}
	approve, ok := e.decisionField(values)
	if !ok {
		return
	}
	var tail *string
	if approve {
		typed := strings.TrimSpace(first(values, "fingerprint_tail"))
		if !tailPattern.MatchString(typed) {
			e.fail(arc.InvalidArgument("fingerprint_tail", "pattern"))
			return
		}
		tail = &typed
	}
	meta := &foundationv1.RequestMeta{CommandId: idOf(commandID)}
	request := &fleetv1.NodeEnrollmentServiceApproveDeviceCodeRequest{Meta: meta, UserCode: proto.String(code), Approve: proto.Bool(approve)}
	call, ok := e.fleetCall(fleetv1connect.NodeEnrollmentServiceApproveDeviceCodeProcedure, resolved, request)
	if !ok {
		return
	}
	_, failure := e.h.options.Fleet.ApproveDeviceCode(e.r.Context(), call, request, tail)
	if failure != nil {
		if stepUpRequired(failure) || tailMismatch(failure) {
			device, problem := e.h.options.Fleet.ReviewedDevice(e.r.Context(), call, &foundationv1.RequestMeta{}, code)
			if e.arcFailure(problem) {
				return
			}
			e.renderActivateReview(resolved, code, device, failure, statusOf(failure))
			return
		}
		e.refuseError(failure, 0)
		return
	}
	view := fleetView{UserCode: code, Display: fleet.DisplayUserCode(code), Approved: approve, DenyOnly: approve, Command: newCommand()}
	e.serve("activate-done", pageData{Title: "Return to your terminal", Signed: true, CSRF: resolved.CSRF, Fleet: view})
}

// fleetText is a refusal's text on the fleet pages: the fleet's own text of a code where the meaning differs from the account pages',
// else the shared text (messageFor).
func (e *exchange) fleetText(value *foundationv1.ArcError) string {
	return messageForSurface(value, e.h.options.Clock(), true)
}

// serveStatus renders a page template with a status (a page shown again with a refusal keeps that refusal's status).
func (e *exchange) serveStatus(name string, data pageData, status int) {
	if status == 0 {
		e.serve(name, data)
		return
	}
	data.Page = name
	body, err := e.h.views.render(name, data)
	if err != nil {
		e.h.options.Logger.ErrorContext(e.r.Context(), "a page could not be rendered", "route", e.route.ID, "correlationId", e.correlation.CorrelationID)
		e.status(http.StatusServiceUnavailable)
		return
	}
	e.write(status, "text/html; charset=utf-8", body, "", "")
}
