// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identityapi"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The WebBrowserSession routes (Contracts web-browser.schema.json x-arcforges-routes at 62ccef1): bootstrap, authentication begin
// and complete, enrollment complete, step-up begin and complete, and logout. Recovery and the provider callback are AF-ID-02's.

// fail answers an error of a domain call: a refusal as its ArcError, anything else as the API maps it.
func (e *exchange) fail(err error) {
	var refusal *arc.Refusal
	if errors.As(err, &refusal) {
		e.refuseError(e.arcError(refusal), 0)
		return
	}
	e.internal(err)
}

// guard resolves the cookie session and checks the CSRF token of a POST: the session's own token, or on a pre-session route the
// constant derived from the public origin too. A route that needs a session refuses a request without one. It reports whether the
// exchange may go on; otherwise it has answered.
func (e *exchange) guard(needSession bool, field string) (*session.BrowserSession, bool) {
	resolved, problem := e.session()
	if problem != nil {
		e.refuseError(problem, 0)
		return nil, false
	}
	if needSession && resolved == nil {
		e.refuse(refuse(arc.Unauthenticated(), http.StatusForbidden))
		return nil, false
	}
	if !e.checkCSRF(resolved, !needSession, field) {
		e.refuse(refuse(arc.PermissionDenied(e.route.ID), http.StatusForbidden))
		return nil, false
	}
	return resolved, true
}

// authorized runs the operation table's decision for an API method the exchange calls and returns the call.
func (e *exchange) authorized(path string, resolved *session.BrowserSession, message []byte) (*ingress.Call, bool) {
	call, err := e.call(path, resolved, message)
	if err != nil {
		e.internal(err)
		return nil, false
	}
	if _, err = e.h.options.Access.Authorize(e.r.Context(), call); err != nil {
		e.fail(err)
		return nil, false
	}
	return call, true
}

// bootstrap is GET /session/v1/web/bootstrap: who is signed in and the token the page's POSTs carry. It is the one JSON route that
// renews a session (SEC-12).
func (e *exchange) bootstrap() {
	resolved, problem := e.session()
	if problem != nil {
		e.refuseError(problem, 0)
		return
	}
	reply := bootstrapReply{CSRFToken: session.PreSessionCSRF(e.h.options.Origin)}
	if resolved != nil {
		idle, renewed, err := session.Renew(e.r.Context(), e.h.options.DB, e.h.options.Policy, resolved.Handle, e.h.options.Clock())
		if err != nil {
			e.internal(err)
			return
		}
		if renewed {
			resolved.IdleExpiresAt = idle
			reply.Authenticated, reply.CSRFToken, reply.Session = true, resolved.CSRF, projectionOf(resolved)
			reply.Profile = e.profile(resolved)
		}
	}
	e.writeJSON(reply, "")
}

// profile is the profile projection of a session's account, or nil when the account's profile cannot be read by this session.
func (e *exchange) profile(resolved *session.BrowserSession) *profileProjection {
	request := &publicapiv1.IdentityServiceGetProfileRequest{Meta: &foundationv1.RequestMeta{}}
	call, err := e.call(publicapiv1connect.IdentityServiceGetProfileProcedure, resolved, nil)
	if err != nil {
		return nil
	}
	response, err := e.h.options.Direct.GetProfile(e.r.Context(), call, request)
	if err != nil || response.GetError() != nil {
		return nil
	}
	value := response.GetValue().GetProfile()
	return &profileProjection{DisplayName: value.GetDisplayName(), Locale: value.GetLocale(), Timezone: value.GetTimezone(),
		Revision: strconv.FormatInt(value.GetRevision().GetValue(), 10)}
}

// beginAuthentication is POST /session/v1/web/authentication/begin: a passkey ceremony of the browser, to sign in or (the owner
// bootstrap) to enroll. The e-mail, password and provider methods and the recovery purposes are not offered.
func (e *exchange) beginAuthentication() {
	if _, ok := e.guard(false, ""); !ok {
		return
	}
	body, refusal := parseBegin(e.body)
	if refusal != nil {
		e.fail(refusal)
		return
	}
	if _, ok := e.authorized(publicapiv1connect.IdentityServiceBeginAuthenticationProcedure, nil, e.body); !ok {
		return
	}
	var purpose int32
	switch {
	case body.Method != "passkey":
		e.fail(arc.InvalidArgument("method", "not_offered"))
		return
	case body.Purpose == "authenticate":
		purpose = int32(identity.PurposeAuthenticate)
	case body.Purpose == "enroll":
		purpose = int32(identity.PurposeEnroll)
	default:
		e.fail(arc.InvalidArgument("purpose", "not_offered"))
		return
	}
	challenge, err := e.h.options.Identity.BeginAuthentication(e.r.Context(), e.request(), identity.Begin{Method: identity.MethodValuePasskey, Purpose: purpose,
		LoginHint: body.LoginHint, ProviderID: body.ProviderID, Claim: body.Claim, HasClaim: true, Browser: true})
	if err != nil {
		e.fail(err)
		return
	}
	e.writeJSON(challengeOf(identityapi.ChallengeView(challenge, e.h.options.Identity.RelyingParty().RPID())), "")
}

// signedIn answers a completed sign-in or enrollment: the session as the document projects it and the session's cookie.
func (e *exchange) signedIn(result identity.SignedIn, purpose string) {
	issued := result.Browser
	if issued == nil {
		e.fail(errors.New("a browser sign-in issued no cookie session"))
		return
	}
	view := sessionProjection{
		SessionID: uuidText(issued.SessionID), ExpiresAt: formatInstant(issued.ExpiresAt), IdleExpiresAt: formatInstant(issued.IdleExpiresAt),
		UserID: uuidText(result.UserID), DeviceID: uuidText(result.Device.DeviceID), WorkspaceIDs: []string{}, RecoveryGeneration: "0", Purpose: purpose,
	}
	e.writeJSON(view, e.cookieFor(issued))
}

// completeAuthentication is POST /session/v1/web/authentication/complete: the passkey assertion of a sign-in; it sets the session.
func (e *exchange) completeAuthentication() {
	if _, ok := e.guard(false, ""); !ok {
		return
	}
	body, refusal := parseComplete(e.body)
	if refusal != nil {
		e.fail(refusal)
		return
	}
	if _, ok := e.authorized(publicapiv1connect.IdentityServiceCompleteAuthenticationProcedure, nil, e.body); !ok {
		return
	}
	result, err := e.h.options.Identity.CompleteBrowserPasskey(e.r.Context(), e.request(), body.FlowID, body.Assertion)
	if err != nil {
		e.fail(err)
		return
	}
	e.signedIn(result, "authenticate")
}

// completeEnrollment is POST /session/v1/web/enrollment/complete: the owner bootstrap (the configured one-time token, a passkey and
// a display name); it sets the owner's session.
func (e *exchange) completeEnrollment() {
	if _, ok := e.guard(false, ""); !ok {
		return
	}
	body, refusal := parseEnrollment(e.body)
	if refusal != nil {
		e.fail(refusal)
		return
	}
	if _, ok := e.authorized(publicapiv1connect.IdentityServiceCompleteEnrollmentProcedure, nil, e.body); !ok {
		return
	}
	result, err := e.h.options.Identity.Bootstrap(e.r.Context(), e.request(), identity.Enrollment{FlowID: body.FlowID, LocalCode: body.LocalCode,
		Creation: body.Creation, DisplayName: body.DisplayName, Locale: body.Locale, Timezone: body.Timezone, Browser: true})
	if err != nil {
		e.fail(err)
		return
	}
	e.signedIn(result, "enroll")
}

// arcFailure answers the ArcError of a reply message, if it has one.
func (e *exchange) arcFailure(value *foundationv1.ArcError) bool {
	if value == nil {
		return false
	}
	e.refuseError(value, 0)
	return true
}

// beginStepUp is POST /session/v1/web/step-up/begin: the step-up challenge of the session for an operation class and target. It
// calls IdentityService.BeginStepUp; only a passkey is offered here.
func (e *exchange) beginStepUp() {
	resolved, ok := e.guard(true, "")
	if !ok {
		return
	}
	body, refusal := parseStepUp(e.body)
	if refusal != nil {
		e.fail(refusal)
		return
	}
	if body.Method != "passkey" {
		e.fail(arc.InvalidArgument("method", "not_offered"))
		return
	}
	request := &publicapiv1.IdentityServiceBeginStepUpRequest{Meta: &foundationv1.RequestMeta{}, OperationClass: proto.String(body.Class),
		Method: publicapiv1.AuthMethod_AUTH_METHOD_PASSKEY.Enum(), TargetHash: body.TargetHash}
	call, err := e.call(publicapiv1connect.IdentityServiceBeginStepUpProcedure, resolved, e.body)
	if err != nil {
		e.internal(err)
		return
	}
	response, err := e.h.options.Direct.BeginStepUp(e.r.Context(), call, request)
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(response.GetError()) {
		return
	}
	e.writeJSON(challengeOf(response.GetValue().GetChallenge()), "")
}

// completeStepUp is POST /session/v1/web/step-up/complete: the assertion that proves a step-up challenge; the evidence it returns is
// consumed by the sensitive call that follows (in the same transaction as its change) and expires after the policy's TTL.
func (e *exchange) completeStepUp() {
	resolved, ok := e.guard(true, "")
	if !ok {
		return
	}
	body, refusal := parseComplete(e.body)
	if refusal != nil {
		e.fail(refusal)
		return
	}
	request := &publicapiv1.IdentityServiceCompleteStepUpRequest{Meta: &foundationv1.RequestMeta{}, FlowId: &foundationv1.Id{Value: body.FlowID[:]},
		Proof: &publicapiv1.AuthProof{Proof: &publicapiv1.AuthProof_Passkey{Passkey: &publicapiv1.WebAuthnAssertion{CredentialId: body.Assertion.CredentialID,
			ClientDataJson: body.Assertion.ClientDataJSON, AuthenticatorData: body.Assertion.AuthenticatorData, Signature: body.Assertion.Signature,
			UserHandle: body.Assertion.UserHandle}}}}
	call, err := e.call(publicapiv1connect.IdentityServiceCompleteStepUpProcedure, resolved, e.body)
	if err != nil {
		e.internal(err)
		return
	}
	response, err := e.h.options.Direct.CompleteStepUp(e.r.Context(), call, request)
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(response.GetError()) {
		return
	}
	evidence := response.GetValue().GetEvidence()
	e.writeJSON(evidenceReply{OperationClass: evidence.GetOperationClass(), ExpiresAt: formatInstant(instantOf(evidence.GetExpiresAt()))}, "")
}

// logout is POST /session/v1/web/logout: it ends the caller's own session (IdentityService.RevokeSession's domain function, the
// sign-out the operation table leaves open to every session) and removes the cookie. The receipt it answers is the sign-out's own:
// it has no client command, so its ID is new and its effect is that the session ended.
func (e *exchange) logout() {
	resolved, ok := e.guard(true, "")
	if !ok {
		return
	}
	call, ok := e.authorized(publicapiv1connect.IdentityServiceRevokeSessionProcedure, resolved, nil)
	if !ok {
		return
	}
	revision, err := e.signOut(call, resolved)
	if err != nil {
		e.fail(err)
		return
	}
	e.writeJSON(receiptReply{CommandID: uuidText(platform.NewID()), ResultRevision: strconv.FormatInt(revision, 10), Effect: "happened"}, clearCookie())
}

// signOut ends the session of the cookie in one transaction with its audit event.
func (e *exchange) signOut(call *ingress.Call, resolved *session.BrowserSession) (int64, error) {
	caller := identity.Caller{Request: e.request(), UserID: resolved.UserID, SessionID: resolved.SessionID, DeviceID: resolved.DeviceID,
		Scope: call.Caller.Scope, Browser: true, AuthEpoch: call.Caller.AuthEpoch, RecoveryGeneration: resolved.RecoveryGeneration}
	var revision int64
	err := e.h.options.DB.InTx(e.r.Context(), "sign out", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		revision, err = e.h.options.Identity.RevokeSession(ctx, tx, caller, resolved.SessionID, e.h.options.Clock().UTC().Truncate(time.Microsecond))
		return err
	})
	return revision, err
}

// deviceNameOf is the name of a browser's new device: its family from the User-Agent header (device.BrowserName), never the header.
func deviceNameOf(r *http.Request) string {
	return device.BrowserName(strings.TrimSpace(r.Header.Get("User-Agent")))
}
