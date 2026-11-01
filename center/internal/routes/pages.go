// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"fmt"
	"slices"
	"strings"
)

// SurfacePages is the pages surface: the center's own account pages and the WebBrowserSession routes (AF-CTR-03 A2). Its routes are
// served only where the surface is enabled; elsewhere the Worker and the center answer 404.
const SurfacePages = "pages"

// SurfaceOperations is the operations surface: the interim page of the operator grant (AF-CTR-03 B). It is its own surface, never
// enabled with identity by default, served only by the official hosted center and only together with the identity and pages
// surfaces (its page proves a step-up through the pages' routes). AF-OPS-01's OperatorService replaces it.
const SurfaceOperations = "operations"

// The prefixes of the pages' paths, relative to the public base URL (the Worker owns APIPrefix in front of them).
const (
	// PageOperationsPrefix is the path of the operations surface's pages.
	PageOperationsPrefix = "/operations"
	// PageBrowserPrefix is the path of the WebBrowserSession routes (Contracts public/http/v1/web-browser.schema.json).
	PageBrowserPrefix = "/session/v1/web"
	// PageAccountPrefix is the path of the account pages and their assets.
	PageAccountPrefix = "/account"
)

// The content types the pages' replies and requests have.
const (
	TypeHTML = "text/html; charset=utf-8"
	TypeJS   = "text/javascript; charset=utf-8"
	TypeCSS  = "text/css; charset=utf-8"
	TypeJSON = "application/json"
	TypeForm = "application/x-www-form-urlencoded"
)

// The bounds of the pages (PLT-1). A JSON route's request bound is the contract's x-arcforges-max-bytes; the passkey completion's
// form carries a WebAuthn creation in three fields (at most 16 KiB each before base64url, 3 x 21846 characters); every other form
// is a few short fields.
const (
	pageBytesBootstrap   = 16_384
	pageBytesChallenge   = 65_536
	pageBytesStepUp      = 4096
	pageBytesBegin       = 8192
	pageBytesComplete    = 131_072
	pageBytesEnrollment  = 262_144
	pageBytesForm        = 4096
	pageBytesCreation    = 98_304
	pageBytesPageReply   = 131_072
	pageBytesAssetReply  = 131_072
	pageBytesReceiptJSON = 4096
	// pageBytesOperationForm bounds an operations form: a reason and a self-approval of 512 characters each, which percent-encode to at
	// most 9 bytes per character, with the short fields around them.
	pageBytesOperationForm = 12_288
)

// PageDurationMilliseconds caps the Worker's budget for one page call (a PBKDF2-free passkey ceremony and a few short transactions).
const PageDurationMilliseconds = 15_000

// PageUserAgentBytes bounds the User-Agent the Worker forwards to the center (printable ASCII; a longer or other value is left out);
// the center names a browser's device from a closed set of families and systems, never from the header's text.
const PageUserAgentBytes = 256

// PageCookieMaxAgeDigits bounds the digits of the session cookie's Max-Age (whole seconds, never zero for a new session): the longest
// session a policy admits is seven days, 604800 seconds, six digits. The Worker accepts a Set-Cookie of a new session only with a
// Max-Age of at most this many digits.
const PageCookieMaxAgeDigits = 6

// PageReturnPathBytes bounds the percent-encoded return path in the fragment of the sign-in redirect (the page the browser asked for,
// below the hosted /api prefix); the longest page path is far below it. The Worker accepts a Location with a longer fragment never.
const PageReturnPathBytes = 512

// PageKind is the kind of a page route.
type PageKind string

// The kinds.
const (
	PageHTMLKind  PageKind = "html"
	PageAssetKind PageKind = "asset"
	PageJSONKind  PageKind = "json"
)

// PageSetCookie is what a route may set in Set-Cookie.
type PageSetCookie string

// The Set-Cookie rules of a route: none, the session cookie of a new session, or its removal.
const (
	SetCookieNone    PageSetCookie = "none"
	SetCookieSession PageSetCookie = "session"
	SetCookieClear   PageSetCookie = "clear"
)

// PageRoute is one route of the pages surface: an exact method and path with the contract the Worker's page handler enforces on the
// way in and out (PLT-1). The Worker's generated table (pageRoutes) and the center's handler both read these rows.
type PageRoute struct {
	// Method is GET or POST; Path the exact path below the public base URL (no query is ever admitted).
	Method string
	Path   string
	// ID names the route: the contract's route ID of a WebBrowserSession route, else a page name.
	ID string
	// Surface is the switchable surface the route belongs to: the Worker forwards it only while that surface is enabled.
	Surface string
	Kind    PageKind
	// RequestType is the exact media type of a POST's body ("" for no body).
	RequestType string
	// ResponseTypes are the media types the route's replies may have (a refusal is JSON on a JSON route, HTML elsewhere).
	ResponseTypes []string
	// MaxRequestBytes bounds the request body, MaxResponseBytes the reply body.
	MaxRequestBytes  int
	MaxResponseBytes int
	// Cookie is whether the session cookie reaches the center: a route that never needs a session does not receive it.
	Cookie bool
	// SetCookie is what the route may set; Redirects whether it may answer 303.
	SetCookie PageSetCookie
	Redirects bool
}

// PageSecurityHeader is a response header every reply of the page handler carries, with its exact value.
type PageSecurityHeader struct {
	Name  string
	Value string
}

// pageCSP is the content security policy of every page (plan section (i)): nothing external, one same-origin script, no inline
// script or style, the WebAuthn calls and the JSON routes only to the same origin, and Trusted Types refused for every sink.
const pageCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; " +
	"frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types 'none'"

// PageSecurityHeaders are the headers every reply of the page handler carries, whatever its status and content (SEC-16): the
// security policy of the pages, the same-origin referrer policy that makes a browser's form POSTs carry an Origin, the opener
// policy, the permission for WebAuthn on the page's own origin, no caching, no transformation and no sniffing. The Worker's
// generated allow-list is this list.
//
// `no-transform` is there for the edge: Cloudflare's Web Analytics adds its beacon (a third-party script and a data-cf-beacon
// attribute) to the HTML of a zone that has the automatic setup on, unless the reply forbids any transformation of its payload.
// The policy blocks the script, but the browser reports the block as a console error, and an injected third-party script
// contradicts "nothing external". The first hosted run found it; a center on this machine has no edge to show it.
func PageSecurityHeaders() []PageSecurityHeader {
	return []PageSecurityHeader{
		{"Content-Security-Policy", pageCSP},
		{"X-Frame-Options", "DENY"},
		{"Referrer-Policy", "same-origin"},
		{"Cross-Origin-Opener-Policy", "same-origin"},
		{"Permissions-Policy", "publickey-credentials-get=(self), publickey-credentials-create=(self)"},
		{"Cache-Control", "no-store, no-transform"},
		{"X-Content-Type-Options", "nosniff"},
	}
}

// PageStatuses are the statuses the Worker lets a page reply keep; every other status becomes the Worker's own 503.
func PageStatuses() []int { return []int{200, 303, 400, 403, 404, 413, 415, 429} }

// PageCookieName is the session cookie (the ingress's name); it is a __Host- cookie, so it is Secure, has no Domain and Path=/.
const PageCookieName = "__Host-af_session"

// PageRedirectFragment starts the fragment that carries the sign-in page's return path in a redirect's Location: the one fragment a
// Location may have (a redirect's Location is a path below PageAccountPrefix, without a query).
const PageRedirectFragment = "#return="

// PageRoutes are the routes of the pages surface, in registration order.
func PageRoutes() []PageRoute {
	rows := pageSurfaceRoutes()
	for index := range rows {
		rows[index].Surface = SurfacePages
	}
	return rows
}

func pageSurfaceRoutes() []PageRoute {
	account := func(path string) string { return PageAccountPrefix + path }
	browser := func(path string) string { return PageBrowserPrefix + path }
	html := []string{TypeHTML}
	jsonReply := []string{TypeJSON}
	page := func(method, path, id string, cookie, redirects bool) PageRoute {
		return PageRoute{Method: method, Path: path, ID: id, Kind: PageHTMLKind, ResponseTypes: html, MaxResponseBytes: pageBytesPageReply, Cookie: cookie,
			SetCookie: SetCookieNone, Redirects: redirects}
	}
	form := func(path, id string, requestBytes int, setCookie PageSetCookie) PageRoute {
		return PageRoute{Method: "POST", Path: path, ID: id, Kind: PageHTMLKind, RequestType: TypeForm, ResponseTypes: html, MaxRequestBytes: requestBytes,
			MaxResponseBytes: pageBytesPageReply, Cookie: true, SetCookie: setCookie, Redirects: true}
	}
	post := func(path, id string, requestBytes, responseBytes int, cookie bool, setCookie PageSetCookie) PageRoute {
		return PageRoute{Method: "POST", Path: path, ID: id, Kind: PageJSONKind, RequestType: TypeJSON, ResponseTypes: jsonReply, MaxRequestBytes: requestBytes,
			MaxResponseBytes: responseBytes, Cookie: cookie, SetCookie: setCookie}
	}
	asset := func(path, id, contentType string) PageRoute {
		return PageRoute{Method: "GET", Path: path, ID: id, Kind: PageAssetKind, ResponseTypes: []string{contentType}, MaxResponseBytes: pageBytesAssetReply,
			SetCookie: SetCookieNone}
	}
	return []PageRoute{
		// The WebBrowserSession routes (Contracts web-browser.schema.json x-arcforges-routes) this center serves; its recovery
		// routes and the provider callback belong to AF-ID-02 and stay unserved.
		{Method: "GET", Path: browser("/bootstrap"), ID: "webBrowser.bootstrap", Kind: PageJSONKind, ResponseTypes: jsonReply,
			MaxResponseBytes: pageBytesBootstrap, Cookie: true, SetCookie: SetCookieNone},
		post(browser("/authentication/begin"), "webBrowser.beginAuthentication", pageBytesBegin, pageBytesChallenge, true, SetCookieNone),
		post(browser("/authentication/complete"), "webBrowser.completeAuthentication", pageBytesComplete, pageBytesBootstrap, true, SetCookieSession),
		post(browser("/enrollment/complete"), "webBrowser.completeEnrollment", pageBytesEnrollment, pageBytesBootstrap, true, SetCookieSession),
		post(browser("/step-up/begin"), "webBrowser.beginStepUp", pageBytesStepUp, pageBytesChallenge, true, SetCookieNone),
		post(browser("/step-up/complete"), "webBrowser.completeStepUp", pageBytesComplete, pageBytesStepUp, true, SetCookieNone),
		{Method: "POST", Path: browser("/logout"), ID: "webBrowser.logout", Kind: PageJSONKind, ResponseTypes: jsonReply,
			MaxResponseBytes: pageBytesReceiptJSON, Cookie: true, SetCookie: SetCookieClear},
		// The pages and their assets.
		page("GET", account("/sign-in"), "page.signIn", false, false),
		page("GET", account("/bootstrap"), "page.bootstrap", false, false),
		page("GET", account("/passkeys"), "page.passkeys", true, true),
		page("GET", account("/sessions"), "page.sessions", true, true),
		page("GET", account("/devices"), "page.devices", true, true),
		page("GET", account("/sign-out"), "page.signOut", true, true),
		asset(account("/account.js"), "asset.script", TypeJS),
		asset(account("/account.css"), "asset.style", TypeCSS),
		// The forms of the pages: each calls the same handler as the API method it names, with the session of the cookie.
		form(account("/passkeys/add"), "form.addPasskey", pageBytesForm, SetCookieNone),
		form(account("/passkeys/complete"), "form.completePasskey", pageBytesCreation, SetCookieNone),
		form(account("/passkeys/rename"), "form.renamePasskey", pageBytesForm, SetCookieNone),
		form(account("/passkeys/remove"), "form.removePasskey", pageBytesForm, SetCookieNone),
		form(account("/sessions/revoke"), "form.revokeSession", pageBytesForm, SetCookieClear),
		form(account("/sessions/revoke-all"), "form.revokeAllSessions", pageBytesForm, SetCookieNone),
		form(account("/devices/rename"), "form.renameDevice", pageBytesForm, SetCookieNone),
		form(account("/devices/revoke"), "form.revokeDevice", pageBytesForm, SetCookieClear),
	}
}

// AllPageRoutes are the page routes of every surface, the pages surface's first.
func AllPageRoutes() []PageRoute { return append(PageRoutes(), OperationsPageRoutes()...) }

// OperationsPageRoutes are the routes of the operations surface, in registration order: the page of the operator grant, its review (the
// request normalized, and the step-up target the script proves) and its confirmation (the grant itself, which consumes the
// step-up). The pages' script and style sheet are the pages surface's assets, which this surface needs enabled.
func OperationsPageRoutes() []PageRoute {
	operations := func(path string) string { return PageOperationsPrefix + path }
	html := []string{TypeHTML}
	form := func(path, id string) PageRoute {
		return PageRoute{Method: "POST", Path: path, ID: id, Surface: SurfaceOperations, Kind: PageHTMLKind, RequestType: TypeForm, ResponseTypes: html,
			MaxRequestBytes: pageBytesOperationForm, MaxResponseBytes: pageBytesPageReply, Cookie: true, SetCookie: SetCookieNone, Redirects: true}
	}
	return []PageRoute{
		{Method: "GET", Path: operations("/grant"), ID: "operations.grant", Surface: SurfaceOperations, Kind: PageHTMLKind, ResponseTypes: html,
			MaxResponseBytes: pageBytesPageReply, Cookie: true, SetCookie: SetCookieNone, Redirects: true},
		form(operations("/grant/review"), "operations.review"),
		form(operations("/grant/confirm"), "operations.confirm"),
	}
}

// ErrPageRegistration is the error of an inconsistent page registration.
var ErrPageRegistration = fmt.Errorf("%w: inconsistent page registration", ErrRegistration)

// CheckPages refuses a page registration that the Worker's handler or the center's could not serve safely: a path that is not
// canonical (no trailing slash, query, percent-encoding or dot segment), a method other than GET and POST, a duplicate row, a body or
// content type that does not fit the method, a bound out of range, an unknown cookie rule, a redirect on a route that is not an HTML
// route, or a route that is neither under the account prefix nor the WebBrowserSession prefix.
func CheckPages(rows []PageRoute) error {
	seen := map[string]bool{}
	ids := map[string]bool{}
	for _, row := range rows {
		key := row.Method + " " + row.Path
		switch {
		case row.Method != "GET" && row.Method != "POST":
			return fmt.Errorf("%w: %s has the method %q", ErrPageRegistration, row.ID, row.Method)
		case row.Surface != SurfacePages && row.Surface != SurfaceOperations:
			return fmt.Errorf("%w: %s belongs to the surface %q", ErrPageRegistration, row.ID, row.Surface)
		case row.Surface == SurfacePages && !strings.HasPrefix(row.Path, PageAccountPrefix+"/") && !strings.HasPrefix(row.Path, PageBrowserPrefix+"/"):
			return fmt.Errorf("%w: %s is outside the page prefixes", ErrPageRegistration, row.Path)
		case row.Surface == SurfaceOperations && !strings.HasPrefix(row.Path, PageOperationsPrefix+"/"):
			return fmt.Errorf("%w: %s is outside the operations prefix", ErrPageRegistration, row.Path)
		case strings.ContainsAny(row.Path, "?#%\\ ") || strings.Contains(row.Path, "//") || strings.Contains(row.Path, "..") || strings.HasSuffix(row.Path, "/"):
			return fmt.Errorf("%w: %s is not canonical", ErrPageRegistration, row.Path)
		case seen[key] || ids[row.ID] || row.ID == "":
			return fmt.Errorf("%w: %s is registered twice or unnamed", ErrPageRegistration, key)
		case row.Kind != PageHTMLKind && row.Kind != PageAssetKind && row.Kind != PageJSONKind:
			return fmt.Errorf("%w: %s has the kind %q", ErrPageRegistration, row.ID, row.Kind)
		case row.SetCookie != SetCookieNone && row.SetCookie != SetCookieSession && row.SetCookie != SetCookieClear:
			return fmt.Errorf("%w: %s has the Set-Cookie rule %q", ErrPageRegistration, row.ID, row.SetCookie)
		case (row.Method == "GET") != (row.RequestType == "" && row.MaxRequestBytes == 0) && row.ID != "webBrowser.logout":
			return fmt.Errorf("%w: %s: a GET has no body and a POST declares one", ErrPageRegistration, row.ID)
		case row.RequestType != "" && row.RequestType != TypeJSON && row.RequestType != TypeForm:
			return fmt.Errorf("%w: %s has the request type %q", ErrPageRegistration, row.ID, row.RequestType)
		case row.RequestType != "" && (row.MaxRequestBytes < 1 || row.MaxRequestBytes > 262_144) || row.RequestType == "" && row.MaxRequestBytes != 0:
			return fmt.Errorf("%w: %s has the request bound %d", ErrPageRegistration, row.ID, row.MaxRequestBytes)
		case len(row.ResponseTypes) == 0 || row.MaxResponseBytes < 1 || row.MaxResponseBytes > 262_144:
			return fmt.Errorf("%w: %s has no response type or a bound out of range", ErrPageRegistration, row.ID)
		case row.Redirects && row.Kind != PageHTMLKind:
			return fmt.Errorf("%w: %s redirects but is not an HTML route", ErrPageRegistration, row.ID)
		case row.SetCookie != SetCookieNone && !row.Cookie:
			return fmt.Errorf("%w: %s sets a cookie but never receives one", ErrPageRegistration, row.ID)
		}
		for _, contentType := range row.ResponseTypes {
			if !slices.Contains([]string{TypeHTML, TypeJS, TypeCSS, TypeJSON}, contentType) {
				return fmt.Errorf("%w: %s has the response type %q", ErrPageRegistration, row.ID, contentType)
			}
		}
		seen[key], ids[row.ID] = true, true
	}
	return nil
}

// Pages is the pages surface's module.
func Pages() (Module, error) {
	rows := PageRoutes()
	if err := CheckPages(rows); err != nil {
		return Module{}, err
	}
	return Module{Name: "pages", Surface: SurfacePages, Pages: rows, Budgets: map[string]Budget{}}, nil
}

// Operations is the operations surface's module.
func Operations() (Module, error) {
	rows := OperationsPageRoutes()
	if err := CheckPages(rows); err != nil {
		return Module{}, err
	}
	return Module{Name: "operations", Surface: SurfaceOperations, Pages: rows, Budgets: map[string]Budget{}}, nil
}
