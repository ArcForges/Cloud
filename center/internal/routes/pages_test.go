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
	if got := PageStatuses(); len(got) != 8 || got[0] != 200 || got[1] != 303 || got[7] != 429 {
		t.Fatalf("statuses %v", got)
	}
	// The Worker's bounds come from here: a page call's budget and the longest User-Agent it forwards.
	if PageDurationMilliseconds != 15_000 || PageUserAgentBytes != 256 || PageCookieMaxAgeDigits != 7 || PageReturnPathBytes != 512 {
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
	if len(table.Pages) != len(PageRoutes()) {
		t.Fatalf("the Worker table holds %d page routes", len(table.Pages))
	}
	ingress, err := Ingress(modules)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range PageRoutes() {
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
