// SPDX-License-Identifier: AGPL-3.0-only

// Package pages is the center's own account pages and the WebBrowserSession routes (AF-CTR-03 A2; ArcForges-Design AD-0021 section 7,
// Contracts public/http/v1/web-browser.schema.json at 62ccef1): the sign-in, bootstrap, account and passkeys, sessions, devices and
// sign-out pages with their one static script and style sheet, the JSON routes under /session/v1/web the script calls (bootstrap,
// authentication, enrollment, step-up and logout) and the forms that carry the account's writes. A self-hosted center needs no Web
// deployment for them, and the hosted Worker forwards the same routes through its page handler (PLT-1).
//
// The pages decide nothing the API does not: every action calls the handler of the API method it stands for, in process, with the
// session of the browser's cookie (identityapi.Direct), so a page and the API share the operation table (access.Authorize), the
// step-up evidence, the command receipts, the rate-limit buckets and the audit events. What the pages add is the browser's own
// protocol: the exact Origin of every POST, the session's derived CSRF token (a public constant derived from the origin before
// there is a session), no query string, a cookie only of the one name, a content type and a size for every request, a security
// header set on every reply, and a session renewed only by a page load or the bootstrap read.
package pages

import (
	"crypto/subtle"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identityapi"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Options compose a page handler.
type Options struct {
	// Origin is the exact Origin a POST must carry and the origin a session is bound to: the public base URL's.
	Origin string
	// BasePath is the path of the public base URL below its origin ("" or "/api"): every link and redirect of a page lies below it.
	BasePath string
	// Enabled reports whether the pages surface is on; a disabled surface answers 404 to every page route.
	Enabled func() bool
	Policy  config.IdentityPolicy
	// Identity and Direct are the account core and the API methods the pages call; Access decides the calls that do not go through
	// Direct; Verifier resolves the browser cookie; DB is the store.
	Identity *identity.Service
	Direct   identityapi.Direct
	Access   *access.Authorizer
	Verifier *session.Verifier
	DB       *store.DB
	// Registry holds the ingress policies the calls the pages make carry.
	Registry *ingress.Registry
	// ClientIP extracts the client's address of a request; RequireClientIP refuses a request whose address is unknown (hosted mode).
	ClientIP        func(*http.Request) (netip.Addr, bool)
	RequireClientIP bool
	Clock           func() time.Time
	Logger          *slog.Logger
}

// Handler serves the pages surface.
type Handler struct {
	options  Options
	routes   map[string]routes.PageRoute
	paths    map[string]bool
	views    *views
	handlers map[string]func(*exchange)
}

// New composes the handler; it refuses an inconsistent registration or option set (fail closed).
func New(options Options) (*Handler, error) {
	rows := routes.PageRoutes()
	if err := routes.CheckPages(rows); err != nil {
		return nil, err
	}
	if options.Origin == "" || options.Identity == nil || options.Access == nil || options.Verifier == nil || options.DB == nil || options.Registry == nil ||
		options.Enabled == nil || options.BasePath != "" && (options.BasePath[0] != '/' || strings.HasSuffix(options.BasePath, "/")) {
		return nil, errors.New("the page handler needs an origin, the identity core, the verifier and a store")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.Logger == nil {
		options.Logger = slog.New(slog.DiscardHandler)
	}
	handler := &Handler{options: options, routes: map[string]routes.PageRoute{}, paths: map[string]bool{}}
	for _, row := range rows {
		handler.routes[row.Method+" "+row.Path] = row
		handler.paths[row.Path] = true
	}
	handler.handlers = map[string]func(*exchange){
		"webBrowser.bootstrap": (*exchange).bootstrap, "webBrowser.beginAuthentication": (*exchange).beginAuthentication,
		"webBrowser.completeAuthentication": (*exchange).completeAuthentication, "webBrowser.completeEnrollment": (*exchange).completeEnrollment,
		"webBrowser.beginStepUp": (*exchange).beginStepUp, "webBrowser.completeStepUp": (*exchange).completeStepUp, "webBrowser.logout": (*exchange).logout,
		"page.signIn": (*exchange).signInPage, "page.bootstrap": (*exchange).bootstrapPage, "page.passkeys": (*exchange).passkeysPage,
		"page.sessions": (*exchange).sessionsPage, "page.devices": (*exchange).devicesPage, "page.signOut": (*exchange).signOutPage,
		"asset.script": (*exchange).script, "asset.style": (*exchange).style,
		"form.addPasskey": (*exchange).addPasskey, "form.completePasskey": (*exchange).completePasskey, "form.renamePasskey": (*exchange).renamePasskey,
		"form.removePasskey": (*exchange).removePasskey, "form.revokeSession": (*exchange).revokeSession,
		"form.revokeAllSessions": (*exchange).revokeAllSessions, "form.renameDevice": (*exchange).renameDevice, "form.revokeDevice": (*exchange).revokeDevice,
	}
	for _, row := range rows {
		if handler.handlers[row.ID] == nil {
			return nil, errors.New("a page route has no handler")
		}
	}
	if len(handler.handlers) != len(rows) {
		return nil, errors.New("a page handler has no route")
	}
	if err := access.CheckPages(rows); err != nil {
		return nil, err
	}
	var err error
	if handler.views, err = loadViews(options.BasePath); err != nil {
		return nil, err
	}
	// Every access operation the pages call has its row and its policy, so a missing one stops the composition rather than a request.
	for _, path := range access.PageCalls() {
		if _, ok := access.Lookup(path); !ok {
			return nil, errors.New("a page calls a method that has no row in the operation table")
		}
		if _, ok := options.Registry.Lookup(path); !ok {
			return nil, errors.New("a page calls a method that has no ingress policy")
		}
	}
	return handler, nil
}

// Paths are the exact paths the handler serves (the ingress lets only these through to it).
func (h *Handler) Paths() []string {
	paths := make([]string, 0, len(h.paths))
	for path := range h.paths {
		paths = append(paths, path)
	}
	return paths
}

// exchange is one request being served.
type exchange struct {
	h           *Handler
	w           http.ResponseWriter
	r           *http.Request
	route       routes.PageRoute
	correlation correlation.Context
	clientIP    netip.Addr
	body        []byte
	cookie      string
	resolved    *session.BrowserSession
	resolvedSet bool
	written     bool
}

// ServeHTTP routes one request by its exact method and path, checks everything the browser protocol asks before any route runs,
// and answers every refusal as the route's kind answers: JSON on a JSON route, an HTML page elsewhere.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e := &exchange{h: h, w: w, r: r, correlation: correlation.ForRequest(r.Header.Values(ingress.TraceparentHeader), "")}
	if !h.options.Enabled() || !h.paths[r.URL.Path] {
		e.notFound()
		return
	}
	route, ok := h.routes[r.Method+" "+r.URL.Path]
	if !ok {
		e.status(http.StatusMethodNotAllowed)
		return
	}
	e.route = route
	if refusal := e.admit(); refusal != nil {
		e.refuse(refusal)
		return
	}
	h.handlers[route.ID](e)
}

// admit applies the checks every route shares, in the order the Worker applies them: no query, no Authorization header, a known
// client address, the exact Origin, the content type and size of the body, and the cookie.
func (e *exchange) admit() *refusalWithStatus {
	r, route := e.r, e.route
	if r.URL.RawQuery != "" || r.URL.ForceQuery || strings.Contains(r.RequestURI, "?") {
		return refuse(arc.InvalidArgument("query", "not_admitted"), http.StatusBadRequest)
	}
	if len(r.Header.Values("Authorization")) > 0 {
		return refuse(arc.InvalidArgument("authorization", "not_admitted"), http.StatusBadRequest)
	}
	if e.h.options.ClientIP != nil {
		address, known := e.h.options.ClientIP(r)
		if !known && e.h.options.RequireClientIP {
			return refuse(arc.InvalidArgument("client", "unknown"), http.StatusBadRequest)
		}
		e.clientIP = address
	}
	origins := r.Header.Values("Origin")
	switch {
	case route.Method == http.MethodPost && (len(origins) != 1 || origins[0] != e.h.options.Origin):
		return refuse(arc.PermissionDenied(route.ID), http.StatusForbidden)
	case route.Method == http.MethodGet && len(origins) > 0 && (len(origins) != 1 || origins[0] != e.h.options.Origin):
		return refuse(arc.PermissionDenied(route.ID), http.StatusForbidden)
	}
	if route.Method == http.MethodGet {
		if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
			return refuse(arc.InvalidArgument("body", "not_admitted"), http.StatusBadRequest)
		}
	} else if denial := e.readBody(); denial != nil {
		return denial
	}
	if route.Cookie {
		if cookie, ok := ingress.SessionCookie(r.Header); ok {
			e.cookie = cookie
		}
	}
	return nil
}

// readBody reads a POST's body within the route's bound and media type. A route without a body type takes none.
func (e *exchange) readBody() *refusalWithStatus {
	r, route := e.r, e.route
	if len(r.Header.Values("Content-Encoding")) > 0 {
		return refuse(arc.InvalidArgument("content_encoding", "not_admitted"), http.StatusUnsupportedMediaType)
	}
	if route.RequestType != "" && !hasMediaType(r.Header, route.RequestType) {
		return refuse(arc.InvalidArgument("content_type", "not_admitted"), http.StatusUnsupportedMediaType)
	}
	if r.ContentLength > int64(route.MaxRequestBytes) {
		return refuse(arc.InvalidArgument("body", "too_large"), http.StatusRequestEntityTooLarge)
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(route.MaxRequestBytes)+1))
	if err != nil {
		return refuse(arc.InvalidArgument("body", "unreadable"), http.StatusBadRequest)
	}
	if len(data) > route.MaxRequestBytes {
		return refuse(arc.InvalidArgument("body", "too_large"), http.StatusRequestEntityTooLarge)
	}
	e.body = data
	return nil
}

// hasMediaType reports whether the request's one Content-Type is the media type, with at most the charset UTF-8.
func hasMediaType(header http.Header, mediaType string) bool {
	values := header.Values("Content-Type")
	if len(values) != 1 {
		return false
	}
	media, parameters, _ := strings.Cut(values[0], ";")
	if strings.ToLower(strings.TrimSpace(media)) != mediaType {
		return false
	}
	parameters = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(parameters), " ", ""))
	return parameters == "" || parameters == "charset=utf-8"
}

// session resolves the cookie, once, without changing anything; nil is no session (no cookie, an unknown, revoked or expired one).
func (e *exchange) session() (*session.BrowserSession, *foundationv1.ArcError) {
	if e.resolvedSet {
		return e.resolved, nil
	}
	e.resolvedSet = true
	if e.cookie == "" {
		return nil, nil
	}
	resolved, err := e.h.options.Verifier.ResolveSession(e.r.Context(), e.cookie)
	if err != nil {
		e.h.options.Logger.WarnContext(e.r.Context(), "a page could not read its session", "route", e.route.ID, "correlationId", e.correlation.CorrelationID)
		return nil, arc.Unavailable().Dated(e.h.options.Clock()).ArcError(e.correlation)
	}
	e.resolved = resolved
	return resolved, nil
}

// checkCSRF accepts the session's own derived token and, on a route that needs no session yet, the constant derived from the public
// origin; the token is the X-AF-CSRF header, or on a form the csrf field (when both are present they agree).
func (e *exchange) checkCSRF(resolved *session.BrowserSession, preSession bool, field string) bool {
	tokens := e.r.Header.Values(ingress.CSRFHeader)
	token, present := "", false
	switch {
	case len(tokens) > 1:
		return false
	case len(tokens) == 1:
		token, present = tokens[0], true
	}
	if field != "" {
		if present && token != field {
			return false
		}
		if !present && field != "" {
			token, present = field, true
		}
	}
	if !present || len(token) != session.EncodedLength {
		return false
	}
	if resolved != nil && session.CheckCSRF(resolved.Handle, token) {
		return true
	}
	return preSession && subtle.ConstantTimeCompare([]byte(session.PreSessionCSRF(e.h.options.Origin)), []byte(token)) == 1
}

// request is the identity core's view of the exchange.
func (e *exchange) request() identity.Request {
	request := identity.Request{ClientIP: e.clientIP, DeviceName: deviceNameOf(e.r)}
	if id, ok := parseUUID(e.correlation.CorrelationID); ok {
		request.CorrelationID = &id
	}
	return request
}

// call is the admitted call of an API method for the exchange: the method's policy, the cookie session's caller, the correlation and
// the client address, and the request message as the receipt digests it.
func (e *exchange) call(path string, resolved *session.BrowserSession, message []byte) (*ingress.Call, error) {
	policy, ok := e.h.options.Registry.Lookup(path)
	if !ok {
		return nil, errors.New("a page calls a method that has no ingress policy")
	}
	call := &ingress.Call{Policy: policy, Correlation: e.correlation, ClientIP: e.clientIP, Message: message}
	if resolved != nil {
		call.Caller = resolved.Credential.Caller
	}
	return call, nil
}

// refusalWithStatus is a refusal of the browser protocol with the HTTP status it takes.
type refusalWithStatus struct {
	refusal *arc.Refusal
	status  int
}

func refuse(refusal *arc.Refusal, status int) *refusalWithStatus {
	return &refusalWithStatus{refusal: refusal, status: status}
}

// arcError renders a refusal of the exchange as its ArcError, dated like the API dates it.
func (e *exchange) arcError(refusal *arc.Refusal) *foundationv1.ArcError {
	return refusal.Dated(e.h.options.Clock()).ArcError(e.correlation)
}

// internal answers a failure that is not a refusal: the store that is down, or anything else, as the API maps it.
func (e *exchange) internal(err error) {
	value := e.h.options.Direct.Failure(e.r.Context(), &ingress.Call{Correlation: e.correlation, Policy: ingress.Policy{FullName: e.route.ID}}, err)
	e.refuseError(value, 0)
}

// Disabled is the handler of the page paths where the pages surface is off (or the center has no store): 404 with the security
// headers and no body, whatever the method.
func Disabled() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		setHeaders(w.Header())
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNotFound)
	})
}
