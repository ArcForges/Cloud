// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strconv"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/mobileauth"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The mobile surface (AF-CTR-04 part M): the app's two native JSON routes (begin and token), the authorization page with its review
// and decision forms, and the two apex routes (the asset links statement and the fixed callback page). The pages decide nothing the
// mobile authorization does not: the review and the decision call package mobileauth in process with the cookie session as the
// account, performing the center-defined operation identity.authorizeMobile (its evidence rule: an approval consumes the step-up
// the script proved for the flow, a denial none). What the pages add is the browser's protocol (Origin, CSRF, no query) and the
// review page's content: the claim as the app reports it (escaped, labelled), the client (the release app or a debug build), the
// times, the account it signs in and the begin request's origin.

// mobileView is everything the mobile templates read besides the page frame.
type mobileView struct {
	FlowID string
	// The claim as the app reports it, and the client.
	Platform   string
	AppVersion string
	Debug      bool
	// The times: when the app asked (and how long ago), and when the request expires.
	RequestedAt   string
	RequestedText string
	Age           string
	ExpiresAt     string
	ExpiresText   string
	// The account the app signs in to, and where the begin request came from.
	Account string
	Origin  string
	// What the page offers: the decision forms of a PENDING request, only the denial of an APPROVED one or of one whose installation
	// cannot be this account's, and the state text of any other.
	Decide   bool
	DenyOnly bool
	State    string
	// Standing is the text of an installation that cannot be this account's (Q-7), shown before any step-up.
	Standing string
	// Target is the step-up target of an approval.
	Target string
	// The result: the link that hands the callback to the app (built by package mobileauth from the stored, admitted redirect only,
	// so it is passed to the template as a URL: a debug build's private-use scheme would otherwise be filtered out), and whether the
	// decision approved.
	Redirect template.URL
	Approved bool
}

// mobileStateTexts say what a request that is no longer awaiting a decision is.
var mobileStateTexts = map[int16]string{
	mobileauth.FlowApproved:  "You approved this request. Open the ArcForges app to finish signing in.",
	mobileauth.FlowDenied:    "This request was denied. The app cannot use it.",
	mobileauth.FlowCompleted: "The app finished signing in with this request.",
	mobileauth.FlowExpired:   "This request has expired. Start again in the app.",
	mobileauth.FlowRevoked:   "This request was ended because its one-use code was used twice or with the wrong app. Start again in the app.",
}

// mobileStandingTexts tell the person, before any step-up, that the claimed installation cannot be this account's (Q-7).
var mobileStandingTexts = map[mobileauth.Standing]string{
	mobileauth.StandingForeign: "This phone is signed in to another account. Sign out in the app first.",
	mobileauth.StandingRevoked: "This app installation was removed from your account. Start again in the app; it signs in as a new installation.",
}

// mobileOriginText is the origin line of a review (protocol-17): begin and the approval normally come from the same phone seconds
// apart, so a country or network that is not this browser's is a useful warning; the page shows the values and no judgement.
func mobileOriginText(origin mobileauth.Origin) string {
	if origin.Country == nil {
		return "Origin unknown"
	}
	if origin.ASN == nil {
		return "Request came from " + *origin.Country
	}
	return "Request came from " + *origin.Country + ", network AS" + strconv.FormatInt(*origin.ASN, 10)
}

// mobileAccount is the account the review and the decision act for: the identity caller of the cookie session (its scope included),
// the session's purpose and how it authenticated. Package mobileauth refuses a session that is not of scope account and purpose
// authenticate (the operation's access rule), as entitlement's operator grant refuses a caller that is not of scope account.
func (e *exchange) mobileAccount(resolved *session.BrowserSession) mobileauth.Account {
	caller := resolved.Credential.Caller
	method := int16(1)
	if caller.AuthMethod == "email_code" {
		method = 2
	}
	return mobileauth.Account{Caller: identity.Caller{Request: e.request(), UserID: resolved.UserID, SessionID: resolved.SessionID, DeviceID: resolved.DeviceID,
		Scope: caller.Scope, Browser: true, AuthEpoch: caller.AuthEpoch, RecoveryGeneration: resolved.RecoveryGeneration}, Purpose: resolved.Purpose,
		AuthMethod: method, AuthenticatedAt: caller.AuthenticatedAt}
}

// mobileRequest is the mobile service's view of the exchange.
func (e *exchange) mobileRequest() mobileauth.Request {
	request := mobileauth.Request{ClientIP: e.clientIP, CorrelationID: e.request().CorrelationID}
	if e.h.options.ClientOrigin != nil {
		origin := e.h.options.ClientOrigin(e.r)
		if origin.Country != "" {
			country := origin.Country
			request.Origin.Country = &country
		}
		if origin.ASN != 0 {
			asn := origin.ASN
			request.Origin.ASN = &asn
		}
	}
	return request
}

// mobileText is a refusal's text on the mobile pages.
func (e *exchange) mobileText(value *foundationv1.ArcError) string {
	return messageForSurface(value, e.h.options.Clock(), routes.SurfaceMobile)
}

// mobilePage is GET /mobile/authorize: the authorization page the app opens in a Custom Tab. It is static: the script reads the flow
// ID from the fragment, removes the fragment, asks who is signed in and submits the review.
func (e *exchange) mobilePage() {
	e.serve("mobile-authorize", pageData{Title: "Sign in to the ArcForges app"})
}

// mobileReview is POST /mobile/authorize/review: the review of a flow (recorded for a PENDING flow, as the decision requires).
func (e *exchange) mobileReview() {
	values, resolved, ok := e.formSession("flow_id")
	if !ok {
		return
	}
	flowID, ok := e.flowField(values)
	if !ok {
		return
	}
	e.renderMobileReview(resolved, flowID, nil, 0)
}

// renderMobileReview reviews a flow and renders the review page, with the error of a refused decision when there is one (the page
// keeps that refusal's status).
func (e *exchange) renderMobileReview(resolved *session.BrowserSession, flowID platform.ID, refused *foundationv1.ArcError, status int) {
	flow, err := e.h.options.Mobile.Review(e.r.Context(), e.mobileRequest(), e.mobileAccount(resolved), flowID)
	if err != nil {
		e.mobileFail(err)
		return
	}
	now := e.h.options.Clock()
	view := mobileView{FlowID: uuidText(flowID), Platform: flow.Platform, AppVersion: flow.AppVersion, Debug: flow.ClientID == mobileauth.ClientDebug,
		RequestedAt: attribute(flow.CreatedAt), RequestedText: timeText(flow.CreatedAt), Age: ageText(flow.CreatedAt, now),
		ExpiresAt: attribute(flow.ExpiresAt), ExpiresText: timeText(flow.ExpiresAt), Origin: mobileOriginText(flow.Origin),
		Account: e.mobileAccountText(resolved.UserID), State: mobileStateTexts[flow.State], Standing: mobileStandingTexts[flow.Standing]}
	switch {
	case flow.State == mobileauth.FlowPending && view.Standing == "":
		view.Decide = true
		view.Target = identity.TargetHash(mobileauth.Class, resolved.UserID, flowID)
	case flow.State == mobileauth.FlowPending, flow.State == mobileauth.FlowApproved:
		view.DenyOnly = true
	}
	data := pageData{Title: "Sign in to the ArcForges app?", Signed: true, CSRF: resolved.CSRF, Mobile: view}
	if refused != nil {
		data.Error = &errorView{Text: e.mobileText(refused)}
	}
	e.serveStatus("mobile-authorize-review", data, status)
}

// mobileAccountText is the account the app signs in to: its display name and masked e-mail address.
func (e *exchange) mobileAccountText(userID platform.ID) string {
	profile, err := e.h.options.Mobile.Account(e.r.Context(), userID)
	switch {
	case err != nil:
		return "this account"
	case profile.EmailMasked != "":
		return profile.DisplayName + " (" + profile.EmailMasked + ")"
	}
	return profile.DisplayName
}

// mobileDecision is POST /mobile/authorize/decision: the decision. An approval consumes the step-up evidence the script proved for the
// flow; the reply is a page with the link that hands the callback to the app, which the person taps (MB-7: the only hand-off); the
// script checks the link and never follows it. A decision without evidence, or refused for the installation, shows the review again.
// The evidence rule is the center-defined operation's: a missing operation row refuses the decision (fail closed), it never decides
// without evidence.
func (e *exchange) mobileDecision() {
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
	operation, known := mobileOperation()
	if !known {
		e.internal(errors.New("pages: the center-defined operation " + mobileauth.Class + " is not in the operation table"))
		return
	}
	decision, err := e.h.options.Mobile.Decide(e.r.Context(), e.mobileRequest(), e.mobileAccount(resolved), flowID, approve,
		operation.NeedsEvidenceToDecide(approve))
	if err != nil {
		var refusal *arc.Refusal
		if errors.As(err, &refusal) {
			value := e.arcError(refusal)
			if stepUpRequired(value) || refusal.Code == "permission_denied" || refusal.Code == "credential_revoked" {
				e.renderMobileReview(resolved, flowID, value, statusOf(value))
				return
			}
		}
		e.mobileFail(err)
		return
	}
	title := "Open the ArcForges app"
	e.serve("mobile-authorize-done", pageData{Title: title, Signed: true, CSRF: resolved.CSRF, Mobile: mobileView{FlowID: uuidText(flowID),
		Redirect: template.URL(decision.RedirectURL), Approved: approve}}) // #nosec G203 -- an admitted redirect with center-built parameters
}

// mobileOperation is the center-defined operation the decision performs (its evidence rule); a variable so that a test can remove it.
var mobileOperation = func() (access.CenterOperation, bool) { return access.CenterOperationOf(mobileauth.Class) }

// mobileFail answers a refusal or a failure of the mobile service as the route's kind answers it.
func (e *exchange) mobileFail(err error) {
	var refusal *arc.Refusal
	if errors.As(err, &refusal) {
		e.refuseError(e.arcError(refusal), 0)
		return
	}
	e.internal(err)
}

// mobileBegin is POST /session/v1/mobile/begin (mobile.begin): native JSON, anonymous.
func (e *exchange) mobileBegin() {
	in, refusal := parseMobileBegin(e.body)
	if refusal != nil {
		e.refuseError(e.arcError(refusal), 0)
		return
	}
	begun, err := e.h.options.Mobile.Begin(e.r.Context(), e.mobileRequest(), in)
	if err != nil {
		e.mobileFail(err)
		return
	}
	e.writeJSON(mobileBeginReply{FlowID: uuidText(begun.FlowID), AuthorizeURL: begun.AuthorizeURL, ExpiresAt: formatInstant(begun.ExpiresAt)}, "")
}

// mobileToken is POST /session/v1/mobile/token (mobile.token): native JSON, bound to the flow by the code and the PKCE verifier.
func (e *exchange) mobileToken() {
	in, refusal := parseMobileToken(e.body)
	if refusal != nil {
		e.refuseError(e.arcError(refusal), 0)
		return
	}
	issued, err := e.h.options.Mobile.Token(e.r.Context(), e.mobileRequest(), in)
	if err != nil {
		e.mobileFail(err)
		return
	}
	e.writeJSON(mobileTokenReplyOf(issued), "")
}

// assetLinks is GET /.well-known/assetlinks.json: the configured statement list, exactly (an empty list where none is configured).
func (e *exchange) assetLinks() {
	e.write(http.StatusOK, routes.TypeJSON, e.h.options.Mobile.AssetLinksStatement(), "", "")
}

// appCallback is GET /app/callback: the fixed page a browser shows when the release App Link did not open the app. It reflects
// nothing: the page's script only removes the fragment from the address bar (history.replaceState, without reading it, Q-4).
func (e *exchange) appCallback() { e.serve("app-callback", pageData{Title: "Open the ArcForges app"}) }

// The MobileNativeAuth replies as strict JSON, in the document's member order: UUIDs in canonical lowercase text, instants as RFC 3339
// UTC, int64 values as decimal strings.

type mobileBeginReply struct {
	FlowID       string `json:"flowId"`
	AuthorizeURL string `json:"authorizeUrl"`
	ExpiresAt    string `json:"expiresAt"`
}

type mobileInstalledReply struct {
	Product     string `json:"product"`
	Version     string `json:"version"`
	InstalledAt string `json:"installedAt,omitempty"`
}

type mobileDeviceReply struct {
	DeviceID      string                 `json:"deviceId"`
	Name          string                 `json:"name"`
	Platform      string                 `json:"platform"`
	Trust         string                 `json:"trust"`
	RemoteEnabled bool                   `json:"remoteEnabled"`
	RevokedAt     string                 `json:"revokedAt,omitempty"`
	Revision      string                 `json:"revision"`
	Installed     []mobileInstalledReply `json:"installed,omitempty"`
}

type mobileTokenReply struct {
	SessionID          string            `json:"sessionId"`
	AccessToken        string            `json:"accessToken"`
	AccessExpiresAt    string            `json:"accessExpiresAt"`
	RefreshToken       string            `json:"refreshToken"`
	RefreshExpiresAt   string            `json:"refreshExpiresAt"`
	Device             mobileDeviceReply `json:"device"`
	RecoveryGeneration string            `json:"recoveryGeneration"`
	Scope              string            `json:"scope"`
	Purpose            string            `json:"purpose"`
}

// trustNames are the contract's names of the stored trust levels.
var trustNames = map[int16]string{device.TrustUntrusted: "untrusted", device.TrustTrusted: "trusted", device.TrustRevoked: "revoked"}

// mobileTokenReplyOf is the MobileTokenResponse of an issued session: the NativeTokenResponse members with scope account and purpose
// authenticate; the device's installed products are its arcforges-mobile installations (the document admits no other product).
func mobileTokenReplyOf(issued mobileauth.Issued) mobileTokenReply {
	view := issued.Device
	reply := mobileDeviceReply{DeviceID: uuidText(view.DeviceID), Name: view.Name, Platform: view.Platform.String(), Trust: trustNames[view.Trust],
		RemoteEnabled: view.RemoteEnabled, Revision: strconv.FormatInt(view.Revision, 10)}
	if view.RevokedAt != nil {
		reply.RevokedAt = formatInstant(*view.RevokedAt)
	}
	for _, item := range view.Installed {
		if item.Product == mobileauth.Product {
			reply.Installed = append(reply.Installed, mobileInstalledReply{Product: item.Product, Version: item.Version, InstalledAt: formatInstant(item.InstalledAt)})
		}
	}
	native := issued.Session
	return mobileTokenReply{SessionID: uuidText(native.SessionID), AccessToken: native.AccessToken, AccessExpiresAt: formatInstant(native.AccessExpiresAt),
		RefreshToken: native.RefreshToken, RefreshExpiresAt: formatInstant(native.RefreshExpiresAt), Device: reply, RecoveryGeneration: "0",
		Scope: "account", Purpose: "authenticate"}
}

// encodeMobile is a reply as the handler writes it (writeJSON), for the tests that check the document's shape.
func encodeMobile(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}
