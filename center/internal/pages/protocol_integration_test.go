// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The browser protocol of the page routes (PLT-1, SEC-03, SEC-16): the exact Origin of every POST, the session's derived CSRF token
// (a constant of the origin before there is a session), no query, no Authorization header, one media type and one size bound per
// route, one security header set on every reply. Each check is proved for every route of the registration, so a route added later
// is held to it too.

// securityHeaders are the headers every reply of the page handler carries, byte for byte (the Worker's generated allow-list is
// held to the same values by tests/worker/pages.test.ts).
var securityHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; " +
		"frame-ancestors 'none'; base-uri 'none'; require-trusted-types-for 'script'; trusted-types 'none'",
	"X-Frame-Options":            "DENY",
	"Referrer-Policy":            "same-origin",
	"Cross-Origin-Opener-Policy": "same-origin",
	"Permissions-Policy":         "publickey-credentials-get=(self), publickey-credentials-create=(self)",
	"Cache-Control":              "no-store",
	"X-Content-Type-Options":     "nosniff",
}

func requireSecurityHeaders(t *testing.T, what string, reply response) {
	t.Helper()
	for name, want := range securityHeaders {
		if values := reply.header.Values(name); len(values) != 1 || values[0] != want {
			t.Errorf("%s (%d): %s is %q", what, reply.status, name, values)
		}
	}
	if len(reply.header.Values("Content-Security-Policy")) == 1 && strings.Contains(reply.header.Get("Content-Type"), "text/html") &&
		!strings.Contains(reply.header.Get("Content-Security-Policy"), "trusted-types 'none'") {
		t.Errorf("%s: an HTML reply without the policy", what)
	}
}

// pagePath reports whether a path is one of the registered page paths.
func pagePath(path string) bool {
	path, _, _ = strings.Cut(path, "?")
	for _, route := range routes.PageRoutes() {
		if route.Path == path {
			return true
		}
	}
	return false
}

// validBody is a body of a route's media type that its handler reads (empty fields: only the checks before it are exercised).
func validBody(route routes.PageRoute) []byte {
	switch route.RequestType {
	case routes.TypeJSON:
		return []byte("{}")
	case routes.TypeForm:
		return []byte("csrf=x")
	}
	return nil
}

// TestEveryRouteRefusesAQueryAnAuthorizationHeaderAndABody: any query string is 400 (an empty one too), as is an Authorization
// header and a body on a GET; a method the route does not have is 405; and every reply carries the whole security header set.
func TestEveryRouteRefusesAQueryAnAuthorizationHeaderAndABody(t *testing.T) {
	h := newHarness(t, settings{})
	for _, route := range routes.PageRoutes() {
		send := func(r request) response {
			r.method, r.path = route.Method, route.Path+r.path
			r.contentType, r.body = route.RequestType, validBody(route)
			return h.do(r)
		}
		for _, query := range []string{"?x=1", "?", "?a=b&a=c", "?%00"} {
			if reply := send(request{path: query}); reply.status != 400 {
				t.Errorf("%s with %q: %d", route.ID, query, reply.status)
			}
		}
		if reply := send(request{headers: http.Header{"Authorization": {"Bearer afa1." + strings.Repeat("A", 43)}}}); reply.status != 400 {
			t.Errorf("%s with Authorization: %d", route.ID, reply.status)
		}
		other := http.MethodPost
		if route.Method == http.MethodPost {
			other = http.MethodGet
		}
		if reply := h.do(request{method: other, path: route.Path, noOrigin: true}); reply.status != 405 {
			t.Errorf("%s by %s: %d", route.ID, other, reply.status)
		}
		if route.Method == http.MethodGet {
			reply := h.do(request{method: http.MethodGet, path: route.Path, body: []byte("x"), contentType: "text/plain"})
			if reply.status != 400 {
				t.Errorf("%s with a body: %d", route.ID, reply.status)
			}
		}
	}
	// A path the pages do not serve is the pipeline's 404.
	for _, path := range []string{"/account", "/account/", "/account/nothing", "/account//sign-in", "/account/sign-in/", "/session/v1/web", "/session/v1/web/recovery/begin",
		"/session/v1/web/providers/x/callback", "/account/%61ccount.js", "/account/../account/sign-in"} {
		if reply := h.do(request{method: http.MethodGet, path: path}); reply.status != 404 {
			t.Errorf("%s: %d", path, reply.status)
		}
	}
}

// TestEveryPostRouteHoldsTheExactOrigin (SEC-03): a POST needs exactly one Origin, equal to the configured origin byte for byte;
// anything else is 403 before any session or body is read. A GET may carry no Origin (a browser sends none for a same-origin
// read) but one it carries must be right.
//
// Every refused POST carries the credentials its route accepts (the signed-in browser's cookie and CSRF token, or on a sign-in
// step the constant of the origin), and the same request with the right Origin is not refused: the Origin is the only thing that
// can have made the 403.
func TestEveryPostRouteHoldsTheExactOrigin(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	constant := session.PreSessionCSRF(origin)
	for _, route := range routes.PageRoutes() {
		if route.Method != http.MethodPost {
			for _, wrong := range []string{"https://evil.example", "null", origin + "/", "http://center.example.test"} {
				reply := h.do(request{method: http.MethodGet, path: route.Path, headers: http.Header{"Origin": {wrong}}})
				if reply.status != 403 {
					t.Errorf("%s with the Origin %q: %d", route.ID, wrong, reply.status)
				}
			}
			if reply := h.do(request{method: http.MethodGet, path: route.Path, headers: http.Header{"Origin": {origin, origin}}}); reply.status != 403 {
				t.Errorf("%s with two Origins: %d", route.ID, reply.status)
			}
			continue
		}
		row, _ := access.PageOperationOf(route.ID)
		// A fresh browser per route, signed in when the route reads a session (the sign-out ends it).
		b := h.newBrowser()
		if row.Credential == access.PageSession {
			b.mustSignIn(who)
		}
		post := func(headers http.Header, noOrigin bool, wrongOrigin string) response {
			t.Helper()
			r := request{method: http.MethodPost, path: route.Path, contentType: route.RequestType, noOrigin: noOrigin, origin: wrongOrigin, headers: headers}
			token := constant
			if row.Credential == access.PageSession {
				r.cookie, token = b.cookie, b.csrf
			}
			switch {
			case route.RequestType == routes.TypeForm:
				r.body = []byte("csrf=" + url.QueryEscape(token))
			case route.RequestType == routes.TypeJSON:
				r.body, r.csrf = validBody(route), token
			default:
				r.csrf = token
			}
			return h.do(r)
		}
		if reply := post(nil, true, ""); reply.status != 403 {
			t.Errorf("%s without an Origin: %d", route.ID, reply.status)
		}
		for _, wrong := range []string{"https://evil.example", "null", origin + "/", "http://center.example.test", "https://CENTER.example.test", "https://center.example.test:443",
			strings.ToUpper(origin), "https://center.example.test.evil.example", "https://center.example.test\\"} {
			if reply := post(nil, false, wrong); reply.status != 403 {
				t.Errorf("%s with the Origin %q: %d", route.ID, wrong, reply.status)
			}
		}
		if reply := post(http.Header{"Origin": {origin, origin}}, true, ""); reply.status != 403 {
			t.Errorf("%s with two Origins: %d", route.ID, reply.status)
		}
		if reply := post(http.Header{"Origin": {"https://evil.example", origin}}, true, ""); reply.status != 403 {
			t.Errorf("%s with a right and a wrong Origin: %d", route.ID, reply.status)
		}
		// The control: the same credentials and the right Origin get past the Origin check (the empty body then fails on its own).
		if reply := post(nil, false, ""); reply.status == 403 {
			t.Errorf("%s with the right Origin and its credentials is still 403: %.160s", route.ID, reply.body)
		}
	}
}

// TestEveryPostRouteHoldsItsMediaTypeAndSize: one Content-Type of the route's type (with at most the UTF-8 charset), no content
// encoding and a body within the route's bound, declared or streamed (413); a route without a body type takes no body.
func TestEveryPostRouteHoldsItsMediaTypeAndSize(t *testing.T) {
	h := newHarness(t, settings{})
	for _, route := range routes.PageRoutes() {
		if route.Method != http.MethodPost {
			continue
		}
		send := func(contentType string, body io.Reader, length int64, headers http.Header) response {
			t.Helper()
			httpRequest, err := http.NewRequest(http.MethodPost, h.url+route.Path, body)
			if err != nil {
				t.Fatal(err)
			}
			httpRequest.ContentLength = length
			if contentType != "" {
				httpRequest.Header.Set("Content-Type", contentType)
			}
			httpRequest.Header.Set("Origin", origin)
			httpRequest.Header.Set("X-Arcforges-Client-Ip", "203.0.113.10")
			for name, values := range headers {
				httpRequest.Header[name] = values
			}
			reply, err := http.DefaultClient.Do(httpRequest)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reply.Body.Close() }()
			data, _ := io.ReadAll(reply.Body)
			result := response{status: reply.StatusCode, header: reply.Header, body: data}
			requireSecurityHeaders(t, route.ID, result)
			return result
		}
		big := bytes.Repeat([]byte("a"), route.MaxRequestBytes+1)
		if route.RequestType == "" {
			// The sign-out takes no body at all.
			if reply := send("application/json", bytes.NewReader([]byte("{}")), 2, nil); reply.status != 413 {
				t.Errorf("%s with a body: %d", route.ID, reply.status)
			}
			continue
		}
		wrong := []string{"", "text/plain", "application/octet-stream", "application/json; charset=latin1", "multipart/form-data; boundary=x", route.RequestType + "; boundary=x"}
		if route.RequestType == routes.TypeJSON {
			wrong = append(wrong, routes.TypeForm)
		} else {
			wrong = append(wrong, routes.TypeJSON)
		}
		for _, contentType := range wrong {
			if reply := send(contentType, bytes.NewReader(validBody(route)), int64(len(validBody(route))), nil); reply.status != 415 {
				t.Errorf("%s with the media type %q: %d", route.ID, contentType, reply.status)
			}
		}
		if reply := send(route.RequestType, bytes.NewReader(validBody(route)), int64(len(validBody(route))), http.Header{"Content-Encoding": {"gzip"}}); reply.status != 415 {
			t.Errorf("%s with a content encoding: %d", route.ID, reply.status)
		}
		if reply := send(route.RequestType+"; charset=utf-8", bytes.NewReader(validBody(route)), int64(len(validBody(route))), nil); reply.status == 415 {
			t.Errorf("%s refuses the UTF-8 charset", route.ID)
		}
		if reply := send(route.RequestType, bytes.NewReader(big), int64(len(big)), nil); reply.status != 413 {
			t.Errorf("%s with a declared body over %d bytes: %d", route.ID, route.MaxRequestBytes, reply.status)
		}
		// Streamed without a declared length (chunked): the bound still holds.
		if reply := send(route.RequestType, io.MultiReader(bytes.NewReader(big)), -1, nil); reply.status != 413 {
			t.Errorf("%s with a streamed body over %d bytes: %d", route.ID, route.MaxRequestBytes, reply.status)
		}
	}
}

// TestCSRFOfTheSessionRoutes (SEC-03): a route that needs a session needs that session's derived token, as the X-AF-CSRF header or,
// on a form, the csrf field; the constant of the origin, another session's token, a token of the wrong length and a repeated header
// are all refused with 403 and change nothing.
func TestCSRFOfTheSessionRoutes(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	a, other := h.newBrowser(), h.newBrowser()
	a.mustSignIn(who)
	other.mustSignIn(who)
	otherToken := other.csrf
	constant := session.PreSessionCSRF(origin)
	for _, route := range routes.PageRoutes() {
		row, _ := access.PageOperationOf(route.ID)
		if route.Method != http.MethodPost || row.Credential != access.PageSession {
			continue
		}
		send := func(cookie, csrf string, extra http.Header) response {
			t.Helper()
			r := request{method: http.MethodPost, path: route.Path, contentType: route.RequestType, cookie: cookie, headers: extra}
			if route.RequestType == routes.TypeForm {
				r.body = []byte("csrf=" + url.QueryEscape(csrf))
			} else {
				r.body, r.csrf = validBody(route), csrf
			}
			return h.do(r)
		}
		for name, probe := range map[string]struct {
			cookie, csrf string
			extra        http.Header
			want         int
		}{
			"no cookie, the constant":     {"", constant, nil, 403},
			"no cookie, no token":         {"", "", nil, 403},
			"a cookie, no token":          {a.cookie, "", nil, 403},
			"a cookie, a wrong token":     {a.cookie, strings.Repeat("A", 43), nil, 403},
			"a cookie, another session's": {a.cookie, otherToken, nil, 403},
			"a cookie, the constant":      {a.cookie, constant, nil, 403},
			"a cookie, a short token":     {a.cookie, a.csrf[:42], nil, 403},
			"a cookie, a padded token":    {a.cookie, a.csrf + "=", nil, 403},
			"an unknown cookie":           {strings.Repeat("A", 43), a.csrf, nil, 403},
		} {
			if reply := send(probe.cookie, probe.csrf, probe.extra); reply.status != probe.want {
				t.Errorf("%s, %s: %d %.120s", route.ID, name, reply.status, reply.body)
			}
		}
		if route.RequestType == routes.TypeJSON {
			if reply := send(a.cookie, a.csrf, http.Header{ingressCSRF: {a.csrf, a.csrf}}); reply.status != 403 {
				t.Errorf("%s with the token twice: %d", route.ID, reply.status)
			}
		}
	}
	if h.audits("identity.step_up.proved") != 0 || len(h.sessionRows(who.id)) != 2 || !h.live(idOf(t, a.bootstrapState().Session.SessionID)) {
		t.Fatal("a refused request changed something")
	}
}

const ingressCSRF = "X-Af-Csrf"

// TestCSRFOfTheSignInRoutes: the sign-in steps need no session, so they take the constant derived from the public origin (or the
// token of the session that happens to be there), and nothing else.
func TestCSRFOfTheSignInRoutes(t *testing.T) {
	h := newHarness(t, settings{policy: writePolicy})
	who := h.seedAccount(1)
	a := h.newBrowser()
	a.mustSignIn(who)
	constant := session.PreSessionCSRF(origin)
	if constant != session.PreSessionCSRF(origin) || constant == session.PreSessionCSRF("https://other.example") || len(constant) != 43 {
		t.Fatal("the pre-session constant is not a function of the origin")
	}
	for name, probe := range map[string]struct {
		cookie, csrf string
		want         int
	}{
		"the constant":                           {"", constant, 200},
		"the constant with a session":            {a.cookie, constant, 200},
		"the session's own token":                {a.cookie, a.csrf, 200},
		"no token":                               {"", "", 403},
		"a wrong token":                          {"", strings.Repeat("B", 43), 403},
		"the session's token without its cookie": {"", a.csrf, 403},
		"another origin's constant":              {"", session.PreSessionCSRF("https://other.example"), 403},
	} {
		data, err := json.Marshal(map[string]any{"method": "passkey", "purpose": "authenticate", "installation": a.claim()})
		if err != nil {
			t.Fatal(err)
		}
		reply := h.do(request{method: http.MethodPost, path: "/session/v1/web/authentication/begin", contentType: "application/json", body: data, cookie: probe.cookie, csrf: probe.csrf})
		if reply.status != probe.want {
			t.Errorf("begin with %s: %d %.120s", name, reply.status, reply.body)
		}
	}
}

// TestADisabledSurfaceAnswers404 (PLT-1, PLT-12): where the pages surface is off every page route is 404 with the security headers
// and no body, whatever the method and credential; the identity surface is unaffected. A center cannot enable the pages without the
// identity surface they call.
func TestADisabledSurfaceAnswers404(t *testing.T) {
	h := newHarness(t, settings{surfaces: "identity"})
	for _, route := range routes.PageRoutes() {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
			reply := h.do(request{method: method, path: route.Path, contentType: route.RequestType, body: validBody(route), cookie: strings.Repeat("A", 43)})
			if reply.status != 404 || len(reply.body) != 0 {
				t.Errorf("%s %s: %d %q", method, route.Path, reply.status, reply.body)
			}
		}
	}
	if reply := h.do(request{method: http.MethodGet, path: "/healthz"}); reply.status != 200 {
		t.Fatalf("health: %d", reply.status)
	}
}
