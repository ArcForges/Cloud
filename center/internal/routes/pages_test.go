// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"errors"
	"strings"
	"testing"
)

// TestThePageRegistrationIsTheContractsRoutesAndThePages: the WebBrowserSession routes the center serves (Contracts
// web-browser.schema.json at 62ccef1; its recovery and provider callback routes stay unserved), the pages and the forms, with the
// bounds the contract states for the JSON bodies.
func TestThePageRegistrationIsTheContractsRoutesAndThePages(t *testing.T) {
	var got []string
	for _, row := range PageRoutes() {
		got = append(got, row.Method+" "+row.Path)
	}
	want := []string{
		"GET /session/v1/web/bootstrap", "POST /session/v1/web/authentication/begin", "POST /session/v1/web/authentication/complete",
		"POST /session/v1/web/enrollment/complete", "POST /session/v1/web/step-up/begin", "POST /session/v1/web/step-up/complete", "POST /session/v1/web/logout",
		"GET /account/sign-in", "GET /account/bootstrap", "GET /account/passkeys", "GET /account/sessions", "GET /account/devices", "GET /account/sign-out",
		"GET /account/account.js", "GET /account/account.css",
		"POST /account/passkeys/add", "POST /account/passkeys/complete", "POST /account/passkeys/rename", "POST /account/passkeys/remove",
		"POST /account/sessions/revoke", "POST /account/sessions/revoke-all", "POST /account/devices/rename", "POST /account/devices/revoke",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the page routes:\n%s", strings.Join(got, "\n"))
	}
	// The contract's x-arcforges-max-bytes of the request documents, and its cookie rules (Contracts 62ccef1).
	contract := map[string]struct {
		request, response int
		cookie            PageSetCookie
	}{
		"/session/v1/web/bootstrap":               {0, 16384, SetCookieNone},
		"/session/v1/web/authentication/begin":    {8192, 65536, SetCookieNone},
		"/session/v1/web/authentication/complete": {131072, 16384, SetCookieSession},
		"/session/v1/web/enrollment/complete":     {262144, 16384, SetCookieSession},
		"/session/v1/web/step-up/begin":           {4096, 65536, SetCookieNone},
		"/session/v1/web/step-up/complete":        {131072, 4096, SetCookieNone},
		"/session/v1/web/logout":                  {0, 4096, SetCookieClear},
	}
	for _, row := range PageRoutes() {
		if want, ok := contract[row.Path]; ok && (row.MaxRequestBytes != want.request || row.SetCookie != want.cookie || row.MaxResponseBytes < want.response || row.Kind != PageJSONKind) {
			t.Errorf("%s: %+v against %+v", row.Path, row, want)
		}
	}
	headers := PageSecurityHeaders()
	if len(headers) != 7 || headers[0].Name != "Content-Security-Policy" || !strings.HasSuffix(headers[0].Value, "require-trusted-types-for 'script'; trusted-types 'none'") {
		t.Fatalf("security headers %v", headers)
	}
	// H-2: the Cloudflare edge injects its Web Analytics beacon into HTML that nothing forbids it to transform.
	cache := ""
	for _, header := range headers {
		if header.Name == "Cache-Control" {
			cache = header.Value
		}
	}
	if cache != "no-store, no-transform" {
		t.Fatalf("Cache-Control is %q, not \"no-store, no-transform\"", cache)
	}
	if got := PageStatuses(); len(got) != 8 || got[0] != 200 || got[1] != 303 || got[7] != 429 {
		t.Fatalf("statuses %v", got)
	}
	// The Worker's bounds come from here: a page call's budget and the longest User-Agent it forwards.
	if PageDurationMilliseconds != 15_000 || PageUserAgentBytes != 256 || PageCookieMaxAgeDigits != 6 || PageReturnPathBytes != 512 {
		t.Fatalf("budgets %d, %d, %d, %d", PageDurationMilliseconds, PageUserAgentBytes, PageCookieMaxAgeDigits, PageReturnPathBytes)
	}
}

func TestInconsistentPageRegistrationsAreRefused(t *testing.T) {
	mutations := map[string]func([]PageRoute) []PageRoute{
		"a path outside the prefixes":   func(rows []PageRoute) []PageRoute { rows[0].Path = "/other/bootstrap"; return rows },
		"a trailing slash":              func(rows []PageRoute) []PageRoute { rows[0].Path = "/session/v1/web/bootstrap/"; return rows },
		"a query in the path":           func(rows []PageRoute) []PageRoute { rows[0].Path += "?x"; return rows },
		"a percent-encoded path":        func(rows []PageRoute) []PageRoute { rows[0].Path = "/session/v1/web/boot%73trap"; return rows },
		"a dot segment":                 func(rows []PageRoute) []PageRoute { rows[0].Path = "/session/v1/web/../bootstrap"; return rows },
		"an unknown method":             func(rows []PageRoute) []PageRoute { rows[0].Method = "DELETE"; return rows },
		"a duplicate route":             func(rows []PageRoute) []PageRoute { return append(rows, rows[0]) },
		"a duplicate ID":                func(rows []PageRoute) []PageRoute { rows[1].ID = rows[0].ID; return rows },
		"an unnamed route":              func(rows []PageRoute) []PageRoute { rows[0].ID = ""; return rows },
		"an unknown kind":               func(rows []PageRoute) []PageRoute { rows[0].Kind = "xml"; return rows },
		"a cookie rule that is no rule": func(rows []PageRoute) []PageRoute { rows[1].SetCookie = "refresh"; return rows },
		"a GET with a body type": func(rows []PageRoute) []PageRoute {
			rows[0].RequestType = TypeJSON
			rows[0].MaxRequestBytes = 10
			return rows
		},
		"a POST without a body type":   func(rows []PageRoute) []PageRoute { rows[1].RequestType = ""; return rows },
		"an unknown request type":      func(rows []PageRoute) []PageRoute { rows[1].RequestType = "text/xml"; return rows },
		"a request bound out of range": func(rows []PageRoute) []PageRoute { rows[1].MaxRequestBytes = 1 << 20; return rows },
		"no response type":             func(rows []PageRoute) []PageRoute { rows[0].ResponseTypes = nil; return rows },
		"an unknown response type":     func(rows []PageRoute) []PageRoute { rows[0].ResponseTypes = []string{"image/png"}; return rows },
		"no response bound":            func(rows []PageRoute) []PageRoute { rows[0].MaxResponseBytes = 0; return rows },
		"a JSON route that redirects":  func(rows []PageRoute) []PageRoute { rows[1].Redirects = true; return rows },
		"a cookie set but never read":  func(rows []PageRoute) []PageRoute { rows[2].Cookie = false; return rows },
	}
	for name, mutate := range mutations {
		rows := PageRoutes()
		if err := CheckPages(mutate(rows)); !errors.Is(err, ErrPageRegistration) {
			t.Errorf("%s was admitted: %v", name, err)
		}
	}
	if err := CheckPages(PageRoutes()); err != nil {
		t.Fatal(err)
	}
	// A module outside the pages surface cannot carry pages.
	modules, err := Center()
	if err != nil {
		t.Fatal(err)
	}
	modules[0].Pages = PageRoutes()[:1]
	if _, err = Table(modules); err == nil {
		t.Fatal("a module of another surface carries pages")
	}
}

func TestThePageRoutesAreThePipelinesPlainPathsAndNotTheWorkersOwnRows(t *testing.T) {
	modules, err := Center()
	if err != nil {
		t.Fatal(err)
	}
	table, err := Table(modules)
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Pages) != len(AllPageRoutes()) {
		t.Fatalf("the Worker table holds %d page routes", len(table.Pages))
	}
	ingress, err := Ingress(modules)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range AllPageRoutes() {
		if !ingress.IsPlain(row.Path) {
			t.Errorf("the pipeline does not let %s through", row.Path)
		}
	}
	if ingress.IsPlain("/account") || ingress.IsPlain("/account/") || ingress.IsPlain("/session/v1/web") {
		t.Fatal("a path outside the registration is plain")
	}
	// The pages add no RPC row: the surface rows are the identity methods only.
	for _, row := range table.SurfaceRows {
		if row.Surface != SurfaceIdentity {
			t.Errorf("an RPC row of the surface %s", row.Surface)
		}
	}
}

// TestTheOperationsRoutesAreTheirOwnSurface: the interim operator page has three routes under /operations, every one of the
// operations surface, none of the pages surface; a route is registered in the module of its own surface, and a path outside the
// prefix of its surface is refused.
func TestTheOperationsRoutesAreTheirOwnSurface(t *testing.T) {
	var got []string
	for _, row := range OperationsPageRoutes() {
		got = append(got, row.Method+" "+row.Path+" "+row.Surface)
		if !row.Cookie || !row.Redirects || row.Kind != PageHTMLKind || row.SetCookie != SetCookieNone {
			t.Errorf("%s: %+v", row.ID, row)
		}
	}
	want := []string{"GET /operations/grant operations", "POST /operations/grant/review operations", "POST /operations/grant/confirm operations"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the operations routes:\n%s", strings.Join(got, "\n"))
	}
	for _, row := range PageRoutes() {
		if row.Surface != SurfacePages {
			t.Errorf("%s belongs to %q", row.ID, row.Surface)
		}
	}
	if SurfaceOperations != "operations" || PageOperationsPrefix != "/operations" {
		t.Fatal(SurfaceOperations, PageOperationsPrefix)
	}
	// A POST of the operations carries the reason and the self-approval of 512 characters each; at nine bytes per character
	// (percent-encoded UTF-8) they fit with the short fields.
	for _, row := range OperationsPageRoutes() {
		if row.Method == "POST" && row.MaxRequestBytes < 2*512*9+1024 {
			t.Errorf("%s: a form bound of %d bytes", row.ID, row.MaxRequestBytes)
		}
	}
	for name, mutate := range map[string]func([]PageRoute) []PageRoute{
		"an operations route without a surface":    func(rows []PageRoute) []PageRoute { rows[0].Surface = ""; return rows },
		"an operations route of the pages surface": func(rows []PageRoute) []PageRoute { rows[0].Surface = SurfacePages; return rows },
		"an operations route outside its prefix":   func(rows []PageRoute) []PageRoute { rows[0].Path = "/account/grant"; return rows },
		"an unknown surface":                       func(rows []PageRoute) []PageRoute { rows[0].Surface = "billing"; return rows },
	} {
		if err := CheckPages(mutate(OperationsPageRoutes())); !errors.Is(err, ErrPageRegistration) {
			t.Errorf("%s was admitted: %v", name, err)
		}
	}
	pages := PageRoutes()
	pages[0].Surface = SurfaceOperations
	if err := CheckPages(pages); !errors.Is(err, ErrPageRegistration) {
		t.Errorf("a pages route of the operations surface was admitted: %v", err)
	}
	modules, err := Center()
	if err != nil {
		t.Fatal(err)
	}
	if surfaces := Surfaces(modules); strings.Join(surfaces, ",") != "identity,pages,operations" {
		t.Fatalf("the surfaces %v", surfaces)
	}
	crossed := append([]Module(nil), modules...)
	crossed[3].Pages = append([]PageRoute(nil), crossed[3].Pages...)
	crossed[3].Pages[0].Surface = SurfacePages
	if _, err = Table(crossed); err == nil {
		t.Fatal("a route of another surface in the operations module was admitted")
	}
}
