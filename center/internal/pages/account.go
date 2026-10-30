// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The account pages and the forms that carry the account's writes. A page is rendered on the server from the same reads the API
// answers (identityapi.Direct, with the cookie session's caller), so what it lists is what the account's methods list and the
// operation table has already decided who may see it. Its script only runs the WebAuthn ceremonies and the step-up before a form
// that needs evidence is submitted.

// pageLimit is the number of items a page lists. It is smaller than the API's largest page (100) so that a full page of rows with
// the longest names that escape to the most bytes still fits the page reply bound the Worker enforces (reviewer-4, pinned by
// TestAFullPageOfTheWorstCaseRowsFitsItsReplyBound); the pages say when there are more.
const pageLimit = 30

func pageRequest() *foundationv1.PageRequest {
	return &foundationv1.PageRequest{Limit: proto.Int32(pageLimit)}
}

// signInLocation is where a request without a session goes: the sign-in page, with the page it asked for as the return path in the
// fragment (a fragment is never sent to a server; the sign-in script validates it, DC-13).
func (e *exchange) signInLocation() string {
	return e.h.options.BasePath + routes.PageAccountPrefix + "/sign-in" + routes.PageRedirectFragment + url.QueryEscape(e.h.options.BasePath+e.r.URL.Path)
}

// protected resolves the session of a page load, renews it (SEC-12: a page load is one of the two things that do) and answers a
// request without a live session with a redirect to the sign-in page; it reports whether the page may be rendered.
func (e *exchange) protected() (*session.BrowserSession, bool) {
	resolved, problem := e.session()
	if problem != nil {
		e.refuseError(problem, 0)
		return nil, false
	}
	if resolved != nil {
		idle, renewed, err := session.Renew(e.r.Context(), e.h.options.DB, e.h.options.Policy, resolved.Handle, e.h.options.Clock())
		if err != nil {
			e.internal(err)
			return nil, false
		}
		if renewed {
			resolved.IdleExpiresAt = idle
			return resolved, true
		}
	}
	e.redirect(e.signInLocation(), "")
	return nil, false
}

// serve renders a page template.
func (e *exchange) serve(name string, data pageData) {
	data.Page = name
	body, err := e.h.views.render(name, data)
	if err != nil {
		e.h.options.Logger.ErrorContext(e.r.Context(), "a page could not be rendered", "route", e.route.ID, "correlationId", e.correlation.CorrelationID)
		e.status(http.StatusServiceUnavailable)
		return
	}
	e.write(http.StatusOK, routes.TypeHTML, body, "", "")
}

// writeErrorPage answers a refusal as an HTML page with the refusal's text.
func (e *exchange) writeErrorPage(status int, value *foundationv1.ArcError) {
	text := messageFor(value, e.h.options.Clock())
	data := pageData{Title: pageHeading(status), Page: "error", Error: &errorView{Text: text}, Heading: pageHeading(status), Detail: text,
		Back: routes.PageAccountPrefix + "/passkeys", BackText: "Back to your account"}
	body, err := e.h.views.render("error", data)
	if err != nil {
		e.status(http.StatusServiceUnavailable)
		return
	}
	e.write(status, routes.TypeHTML, body, "", "")
}

// signInPage, bootstrapPage and signOutPage are the pages whose script does the work.
func (e *exchange) signInPage()    { e.serve("sign-in", pageData{Title: "Sign in"}) }
func (e *exchange) bootstrapPage() { e.serve("bootstrap", pageData{Title: "Create the owner account"}) }

func (e *exchange) signOutPage() {
	if _, ok := e.protected(); !ok {
		return
	}
	e.serve("sign-out", pageData{Title: "Sign out", Signed: true})
}

// script and style are the static files.
func (e *exchange) script() { e.write(http.StatusOK, routes.TypeJS, e.h.views.script, "", "") }
func (e *exchange) style()  { e.write(http.StatusOK, routes.TypeCSS, e.h.views.style, "", "") }

// uuidOfID reads a platform ID from a contract Id.
func uuidOfID(value *foundationv1.Id) string {
	id, _ := parseUUIDBytes(value.GetValue())
	return uuidText(id)
}

// newCommand is a new command ID in text, for the form that carries it.
func newCommand() string { return uuidText(platform.NewID()) }

// passkeysPage lists the account and its passkeys (GetProfile and ListAuthIdentities).
func (e *exchange) passkeysPage() {
	resolved, ok := e.protected()
	if !ok {
		return
	}
	data := pageData{Title: "Account and passkeys", Signed: true, CSRF: resolved.CSRF}
	profileCall, err := e.call(publicapiv1connect.IdentityServiceGetProfileProcedure, resolved, nil)
	if err != nil {
		e.internal(err)
		return
	}
	profile, err := e.h.options.Direct.GetProfile(e.r.Context(), profileCall, &publicapiv1.IdentityServiceGetProfileRequest{Meta: &foundationv1.RequestMeta{}})
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(profile.GetError()) {
		return
	}
	value := profile.GetValue().GetProfile()
	data.Profile = profileView{DisplayName: value.GetDisplayName(), Locale: value.GetLocale(), Timezone: value.GetTimezone()}
	listCall, err := e.call(publicapiv1connect.IdentityServiceListAuthIdentitiesProcedure, resolved, nil)
	if err != nil {
		e.internal(err)
		return
	}
	list, err := e.h.options.Direct.ListAuthIdentities(e.r.Context(), listCall, &publicapiv1.IdentityServiceListAuthIdentitiesRequest{
		Meta: &foundationv1.RequestMeta{}, Page: pageRequest()})
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(list.GetError()) {
		return
	}
	for _, item := range list.GetValue().GetItems() {
		id, _ := parseUUIDBytes(item.GetCredentialId().GetValue())
		row := passkeyRow{ID: uuidText(id), Name: item.GetDisplayName(), CreatedAt: attribute(instantOf(item.GetCreatedAt())), CreatedText: timeText(instantOf(item.GetCreatedAt())),
			RenameCommand: newCommand(), RemoveCommand: newCommand(), RemoveTarget: identity.TargetHash(identity.ClassRemoveCredential, resolved.UserID, id)}
		if at := item.GetLastUsedAt(); at != nil {
			row.LastUsedAt, row.LastUsedText = attribute(instantOf(at)), timeText(instantOf(at))
		}
		if item.GetKind() == "passkey" {
			data.Passkeys = append(data.Passkeys, row)
		}
	}
	data.CanRemove = len(list.GetValue().GetItems()) > 1
	data.HasMore = list.GetValue().GetPage().GetHasMore()
	data.AddTarget = identity.TargetHash(identity.ClassBeginRegistration, resolved.UserID, resolved.UserID)
	e.serve("passkeys", data)
}

// productNames are the names the sessions page gives the products.
var productNames = map[string]string{"arcforges-web": "Web browser", "arcforges-mobile": "Phone app", "arcforges-node": "Node"}

// devicesOf lists the account's devices for a page.
func (e *exchange) devicesOf(resolved *session.BrowserSession) ([]*publicapiv1.DeviceView, bool, bool) {
	call, err := e.call(publicapiv1connect.DeviceServiceListProcedure, resolved, nil)
	if err != nil {
		e.internal(err)
		return nil, false, false
	}
	response, err := e.h.options.Direct.ListDevices(e.r.Context(), call, &publicapiv1.DeviceServiceListRequest{Meta: &foundationv1.RequestMeta{}, Page: pageRequest()})
	if err != nil {
		e.internal(err)
		return nil, false, false
	}
	if e.arcFailure(response.GetError()) {
		return nil, false, false
	}
	return response.GetValue().GetItems(), response.GetValue().GetPage().GetHasMore(), true
}

// sessionsPage lists the account's sessions (ListSessions) with the device each is on (DeviceService.List).
func (e *exchange) sessionsPage() {
	resolved, ok := e.protected()
	if !ok {
		return
	}
	call, err := e.call(publicapiv1connect.IdentityServiceListSessionsProcedure, resolved, nil)
	if err != nil {
		e.internal(err)
		return
	}
	response, err := e.h.options.Direct.ListSessions(e.r.Context(), call, &publicapiv1.IdentityServiceListSessionsRequest{Meta: &foundationv1.RequestMeta{}, Page: pageRequest()})
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(response.GetError()) {
		return
	}
	devices, _, ok := e.devicesOf(resolved)
	if !ok {
		return
	}
	names := map[string]string{}
	for _, item := range devices {
		names[uuidOfID(item.GetDeviceId())] = item.GetName()
	}
	data := pageData{Title: "Sessions", Signed: true, CSRF: resolved.CSRF, HasMore: response.GetValue().GetPage().GetHasMore(),
		RevokeAllTarget: identity.TargetHash(identity.ClassRevokeAllSessions, resolved.UserID, resolved.UserID), RevokeAllCommand: newCommand()}
	for _, item := range response.GetValue().GetSessions() {
		id, _ := parseUUIDBytes(item.GetSessionId().GetValue())
		where := names[uuidOfID(item.GetDeviceId())]
		product := productNames[item.GetProduct()]
		switch {
		case where == "" && product == "":
			where = item.GetProduct()
		case where == "":
			where = product
		case product != "" && !strings.Contains(where, product):
			where += " (" + product + ")"
		}
		data.Sessions = append(data.Sessions, sessionRow{ID: uuidText(id), Where: where, Current: item.GetCurrent(),
			IssuedAt: attribute(instantOf(item.GetCreatedAt())), IssuedText: timeText(instantOf(item.GetCreatedAt())),
			LastUsedAt: attribute(instantOf(item.GetLastUsedAt())), LastUsedText: timeText(instantOf(item.GetLastUsedAt())),
			ExpiresAt: attribute(instantOf(item.GetExpiresAt())), ExpiresText: timeText(instantOf(item.GetExpiresAt())),
			RevokeCommand: newCommand(), RevokeTarget: identity.TargetHash(identity.ClassRevokeSession, resolved.UserID, id)})
	}
	e.serve("sessions", data)
}

// devicesPage lists the account's devices (DeviceService.List).
func (e *exchange) devicesPage() {
	resolved, ok := e.protected()
	if !ok {
		return
	}
	devices, more, ok := e.devicesOf(resolved)
	if !ok {
		return
	}
	data := pageData{Title: "Devices", Signed: true, CSRF: resolved.CSRF, HasMore: more}
	for _, item := range devices {
		id, _ := parseUUIDBytes(item.GetDeviceId().GetValue())
		row := deviceRow{ID: uuidText(id), Name: item.GetName(), Platform: item.GetPlatform(), Current: id == resolved.DeviceID,
			RenameCommand: newCommand(), RevokeCommand: newCommand(),
			RevokeTarget: identity.TargetHash(identity.ClassRevokeDevice, resolved.UserID, id)}
		for _, installed := range item.GetInstalled() {
			row.Installed = append(row.Installed, installed.GetProduct()+" "+installed.GetVersion())
		}
		data.Devices = append(data.Devices, row)
	}
	e.serve("devices", data)
}

// The forms. Each carries the session's CSRF token as the csrf field (or the X-AF-CSRF header), a command ID the page generated (so
// a form submitted twice replays one receipt) and the object it acts on; a fresh step-up is proved by the script before the form is
// submitted, and consumed by the API handler the form calls.

// form parses a POST's urlencoded body: exactly the allowed fields, each at most once.
func (e *exchange) form(allowed ...string) (url.Values, bool) {
	values, err := url.ParseQuery(string(e.body))
	if err != nil {
		e.refuse(refuse(arc.InvalidArgument("body", "malformed"), http.StatusBadRequest))
		return nil, false
	}
	for name, list := range values {
		known := false
		for _, candidate := range allowed {
			known = known || candidate == name
		}
		switch {
		case !known:
			e.refuse(refuse(arc.InvalidArgument(name, "unknown"), http.StatusBadRequest))
			return nil, false
		case len(list) != 1:
			e.refuse(refuse(arc.InvalidArgument(name, "repeated"), http.StatusBadRequest))
			return nil, false
		}
	}
	return values, true
}

// formSession parses a form and checks its session and CSRF token.
func (e *exchange) formSession(allowed ...string) (url.Values, *session.BrowserSession, bool) {
	values, ok := e.form(append([]string{"csrf"}, allowed...)...)
	if !ok {
		return nil, nil, false
	}
	resolved, ok := e.guard(true, values.Get("csrf"))
	if !ok {
		return nil, nil, false
	}
	return values, resolved, true
}

// formID reads a UUID field.
func (e *exchange) formID(values url.Values, name string) (platform.ID, bool) {
	id, ok := parseUUID(values.Get(name))
	if !ok {
		e.refuse(refuse(arc.InvalidArgument(name, "required"), http.StatusBadRequest))
	}
	return id, ok
}

func idOf(value platform.ID) *foundationv1.Id { return &foundationv1.Id{Value: value[:]} }

// message is a request as the receipt digests it: deterministic bytes, so the same form submitted again is the same command.
func message(request proto.Message) []byte {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return nil
	}
	return data
}

// done lands a form that succeeded: back on the page it came from, or, when the action ended the session itself (revoking the
// session or the device of this browser), on the sign-in page with the cookie removed. The cookie is removed only by a route whose
// registered rule removes it (SetCookieClear: the two revoke forms) and only when a second look positively finds that session no
// longer live; a look that fails, and every route whose rule keeps the cookie, land on the page like any other success (a page
// that needs a session sends the browser to the sign-in itself).
func (e *exchange) done(landing string, resolved *session.BrowserSession) {
	if e.route.SetCookie == routes.SetCookieClear {
		after, problem := e.h.options.Verifier.ResolveSession(e.r.Context(), e.cookie)
		if problem == nil && (after == nil || after.SessionID != resolved.SessionID) {
			e.redirect(e.h.options.BasePath+routes.PageAccountPrefix+"/sign-in", clearCookie())
			return
		}
	}
	e.redirect(e.h.options.BasePath+routes.PageAccountPrefix+landing, "")
}

// addPasskey is POST /account/passkeys/add: BeginPasskeyRegistration (the step-up evidence the script proved is consumed), then the
// page that runs the browser's WebAuthn creation.
func (e *exchange) addPasskey() {
	values, resolved, ok := e.formSession("display_name")
	if !ok {
		return
	}
	name := values.Get("display_name")
	request := &publicapiv1.IdentityServiceBeginPasskeyRegistrationRequest{Meta: &foundationv1.RequestMeta{}, DisplayName: &name}
	call, err := e.call(publicapiv1connect.IdentityServiceBeginPasskeyRegistrationProcedure, resolved, message(request))
	if err != nil {
		e.internal(err)
		return
	}
	response, err := e.h.options.Direct.BeginPasskeyRegistration(e.r.Context(), call, request)
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(response.GetError()) {
		return
	}
	challenge := challengeOf(response.GetValue().GetChallenge())
	view := registerView{FlowID: challenge.FlowID, CommandID: newCommand(), Challenge: challenge.Challenge, AccountName: e.accountName(resolved)}
	if challenge.Options != nil {
		view.RPID, view.UserHandle, view.Excluded = challenge.Options.RPID, challenge.Options.UserHandle, joinCredentials(challenge.Options.ExcludedCredentials)
	}
	e.serve("register", pageData{Title: "Create your passkey", Signed: true, CSRF: resolved.CSRF, Register: view})
}

// accountName is the account's display name, the name a passkey is created for; a failed read falls back to a fixed text.
func (e *exchange) accountName(resolved *session.BrowserSession) string {
	if profile := e.profile(resolved); profile != nil && profile.DisplayName != "" {
		return profile.DisplayName
	}
	return "ArcForges account"
}

// completePasskey is POST /account/passkeys/complete: CompletePasskeyRegistration with the creation the browser made.
func (e *exchange) completePasskey() {
	values, resolved, ok := e.formSession("command_id", "flow_id", "credential_id", "client_data_json", "attestation_object", "transports")
	if !ok {
		return
	}
	commandID, ok := e.formID(values, "command_id")
	if !ok {
		return
	}
	flowID, ok := e.formID(values, "flow_id")
	if !ok {
		return
	}
	creation := &publicapiv1.WebAuthnCreation{}
	for name, target := range map[string]*[]byte{"credential_id": &creation.CredentialId, "client_data_json": &creation.ClientDataJson,
		"attestation_object": &creation.AttestationObject} {
		data, err := base64.RawURLEncoding.Strict().DecodeString(values.Get(name))
		if err != nil || len(data) == 0 {
			e.refuse(refuse(arc.InvalidArgument(name, "pattern"), http.StatusBadRequest))
			return
		}
		*target = data
	}
	if transports := values.Get("transports"); transports != "" {
		creation.Transports = strings.Split(transports, ",")
	}
	request := &publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest{Meta: &foundationv1.RequestMeta{CommandId: idOf(commandID)}, FlowId: idOf(flowID),
		Credential: creation}
	call, err := e.call(publicapiv1connect.IdentityServiceCompletePasskeyRegistrationProcedure, resolved, message(request))
	if err != nil {
		e.internal(err)
		return
	}
	response, err := e.h.options.Direct.CompletePasskeyRegistration(e.r.Context(), call, request)
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(response.GetError()) {
		return
	}
	e.done("/passkeys", resolved)
}

// renamePasskey is POST /account/passkeys/rename: RenameAuthIdentity.
func (e *exchange) renamePasskey() {
	values, resolved, ok := e.formSession("command_id", "credential_id", "name")
	if !ok {
		return
	}
	commandID, ok := e.formID(values, "command_id")
	if !ok {
		return
	}
	credentialID, ok := e.formID(values, "credential_id")
	if !ok {
		return
	}
	name := values.Get("name")
	request := &publicapiv1.IdentityServiceRenameAuthIdentityRequest{Meta: &foundationv1.RequestMeta{CommandId: idOf(commandID)}, CredentialId: idOf(credentialID), Name: &name}
	call, err := e.call(publicapiv1connect.IdentityServiceRenameAuthIdentityProcedure, resolved, message(request))
	if err != nil {
		e.internal(err)
		return
	}
	response, err := e.h.options.Direct.RenameAuthIdentity(e.r.Context(), call, request)
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(response.GetError()) {
		return
	}
	e.done("/passkeys", resolved)
}

// removePasskey is POST /account/passkeys/remove: RemoveAuthIdentity (the last passkey stays, step-up evidence is consumed).
func (e *exchange) removePasskey() {
	values, resolved, ok := e.formSession("command_id", "credential_id")
	if !ok {
		return
	}
	commandID, ok := e.formID(values, "command_id")
	if !ok {
		return
	}
	credentialID, ok := e.formID(values, "credential_id")
	if !ok {
		return
	}
	request := &publicapiv1.IdentityServiceRemoveAuthIdentityRequest{Meta: &foundationv1.RequestMeta{CommandId: idOf(commandID)}, CredentialId: idOf(credentialID)}
	call, err := e.call(publicapiv1connect.IdentityServiceRemoveAuthIdentityProcedure, resolved, message(request))
	if err != nil {
		e.internal(err)
		return
	}
	response, err := e.h.options.Direct.RemoveAuthIdentity(e.r.Context(), call, request)
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(response.GetError()) {
		return
	}
	e.done("/passkeys", resolved)
}

// revokeSession is POST /account/sessions/revoke: RevokeSession (another session needs evidence; the caller's own is a sign-out).
func (e *exchange) revokeSession() {
	values, resolved, ok := e.formSession("command_id", "session_id")
	if !ok {
		return
	}
	commandID, ok := e.formID(values, "command_id")
	if !ok {
		return
	}
	sessionID, ok := e.formID(values, "session_id")
	if !ok {
		return
	}
	request := &publicapiv1.IdentityServiceRevokeSessionRequest{Meta: &foundationv1.RequestMeta{CommandId: idOf(commandID)}, SessionId: idOf(sessionID)}
	call, err := e.call(publicapiv1connect.IdentityServiceRevokeSessionProcedure, resolved, message(request))
	if err != nil {
		e.internal(err)
		return
	}
	response, err := e.h.options.Direct.RevokeSession(e.r.Context(), call, request)
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(response.GetError()) {
		return
	}
	e.done("/sessions", resolved)
}

// revokeAllSessions is POST /account/sessions/revoke-all: RevokeAllSessions (the caller's own session stays).
func (e *exchange) revokeAllSessions() {
	values, resolved, ok := e.formSession("command_id")
	if !ok {
		return
	}
	commandID, ok := e.formID(values, "command_id")
	if !ok {
		return
	}
	request := &publicapiv1.IdentityServiceRevokeAllSessionsRequest{Meta: &foundationv1.RequestMeta{CommandId: idOf(commandID)}}
	call, err := e.call(publicapiv1connect.IdentityServiceRevokeAllSessionsProcedure, resolved, message(request))
	if err != nil {
		e.internal(err)
		return
	}
	response, err := e.h.options.Direct.RevokeAllSessions(e.r.Context(), call, request)
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(response.GetError()) {
		return
	}
	e.done("/sessions", resolved)
}

// renameDevice is POST /account/devices/rename: DeviceService.Rename.
func (e *exchange) renameDevice() {
	values, resolved, ok := e.formSession("command_id", "device_id", "name")
	if !ok {
		return
	}
	commandID, ok := e.formID(values, "command_id")
	if !ok {
		return
	}
	deviceID, ok := e.formID(values, "device_id")
	if !ok {
		return
	}
	name := values.Get("name")
	request := &publicapiv1.DeviceServiceRenameRequest{Meta: &foundationv1.RequestMeta{CommandId: idOf(commandID)}, DeviceId: idOf(deviceID), Name: &name}
	call, err := e.call(publicapiv1connect.DeviceServiceRenameProcedure, resolved, message(request))
	if err != nil {
		e.internal(err)
		return
	}
	response, err := e.h.options.Direct.RenameDevice(e.r.Context(), call, request)
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(response.GetError()) {
		return
	}
	e.done("/devices", resolved)
}

// revokeDevice is POST /account/devices/revoke: DeviceService.Revoke (another device needs evidence; revoking this browser's device
// ends its session too).
func (e *exchange) revokeDevice() {
	values, resolved, ok := e.formSession("command_id", "device_id")
	if !ok {
		return
	}
	commandID, ok := e.formID(values, "command_id")
	if !ok {
		return
	}
	deviceID, ok := e.formID(values, "device_id")
	if !ok {
		return
	}
	request := &publicapiv1.DeviceServiceRevokeRequest{Meta: &foundationv1.RequestMeta{CommandId: idOf(commandID)}, DeviceId: idOf(deviceID)}
	call, err := e.call(publicapiv1connect.DeviceServiceRevokeProcedure, resolved, message(request))
	if err != nil {
		e.internal(err)
		return
	}
	response, err := e.h.options.Direct.RevokeDevice(e.r.Context(), call, request)
	if err != nil {
		e.internal(err)
		return
	}
	if e.arcFailure(response.GetError()) {
		return
	}
	e.done("/devices", resolved)
}
