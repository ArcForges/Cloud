// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"errors"
	"strings"
	"testing"
)

// TestTheMobileRoutesAreTheirOwnSurface (AF-CTR-04 part M, MB-3, M-15, cloud-13): the mobile module declares exactly its seven routes:
// the authorization page and its two forms (form POSTs with the cookie), the two native JSON routes (POST, exactly application/json, no
// cookie in or out, no redirect) and the two exact apex paths (GET, no cookie, no redirect). Every misshaped row is refused, no other
// surface declares a native or apex route, the Worker's table carries the native and apex rows apart from the page rows, and the
// production table and the plain paths are unchanged (Hello and /healthz only).
func TestTheMobileRoutesAreTheirOwnSurface(t *testing.T) {
	var got []string
	for _, row := range MobilePageRoutes() {
		got = append(got, row.Method+" "+row.Path+" "+row.ID+" "+string(row.Kind)+" "+row.Surface)
	}
	want := []string{"GET /mobile/authorize mobile.page html mobile", "POST /mobile/authorize/review mobile.review html mobile",
		"POST /mobile/authorize/decision mobile.decision html mobile", "POST /session/v1/mobile/begin mobile.begin native mobile",
		"POST /session/v1/mobile/token mobile.token native mobile", "GET /.well-known/assetlinks.json apex.assetLinks apex mobile",
		"GET /app/callback apex.appCallback apex mobile"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("the mobile routes:\n%s", strings.Join(got, "\n"))
	}
	if err := CheckPages(MobilePageRoutes()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]PageRoute) []PageRoute{
		"a native route that reads the cookie": func(rows []PageRoute) []PageRoute { rows[3].Cookie = true; return rows },
		"a native route that sets a cookie": func(rows []PageRoute) []PageRoute {
			rows[3].Cookie, rows[3].SetCookie = true, SetCookieSession
			return rows
		},
		"a native route of the form media type": func(rows []PageRoute) []PageRoute { rows[4].RequestType = TypeForm; return rows },
		"a native route at another path":        func(rows []PageRoute) []PageRoute { rows[3].Path = "/session/v1/mobile/other"; return rows },
		"a native GET": func(rows []PageRoute) []PageRoute {
			rows[3].Method, rows[3].RequestType, rows[3].MaxRequestBytes = "GET", "", 0
			return rows
		},
		"a native route that redirects":          func(rows []PageRoute) []PageRoute { rows[3].Redirects = true; return rows },
		"an apex route at another path":          func(rows []PageRoute) []PageRoute { rows[6].Path = "/app/node"; return rows },
		"an apex route of HTML assetlinks":       func(rows []PageRoute) []PageRoute { rows[5].ResponseTypes = []string{TypeHTML}; return rows },
		"an apex route that reads the cookie":    func(rows []PageRoute) []PageRoute { rows[6].Cookie = true; return rows },
		"an apex POST":                           func(rows []PageRoute) []PageRoute { rows[5].Method = "POST"; return rows },
		"a mobile page outside its prefix":       func(rows []PageRoute) []PageRoute { rows[1].Path = "/connect/review"; return rows },
		"a prefix that only starts like /mobile": func(rows []PageRoute) []PageRoute { rows[1].Path = "/mobile/authorized"; return rows },
		"a native route of the fleet surface":    func(rows []PageRoute) []PageRoute { rows[3].Surface = SurfaceFleet; return rows },
		"an apex route of the pages surface":     func(rows []PageRoute) []PageRoute { rows[5].Surface = SurfacePages; return rows },
		"a mobile JSON route under the web prefix": func(rows []PageRoute) []PageRoute {
			rows[3].Kind, rows[3].Path = PageJSONKind, "/session/v1/web/x"
			return rows
		},
	} {
		if err := CheckPages(mutate(MobilePageRoutes())); !errors.Is(err, ErrPageRegistration) {
			t.Errorf("%s was admitted: %v", name, err)
		}
	}
	fleet := FleetPageRoutes()
	fleet[0].Kind = PageNativeKind
	if err := CheckPages(fleet); !errors.Is(err, ErrPageRegistration) {
		t.Error("a native fleet route was admitted")
	}
	modules, err := Center()
	if err != nil {
		t.Fatal(err)
	}
	table, err := Table(modules)
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Native) != 2 || table.Native[0].Path != NativeMobileBegin || table.Native[1].Path != NativeMobileToken || len(table.Apex) != 2 ||
		table.Apex[0].Path != ApexAssetLinks || table.Apex[1].Path != ApexAppCallback {
		t.Fatalf("the native %v and apex %v rows", table.Native, table.Apex)
	}
	for _, row := range table.Pages {
		if row.Surface == SurfaceMobile && row.Kind != PageHTMLKind {
			t.Errorf("a native or apex row in the page rows: %s", row.ID)
		}
	}
	if len(table.Production) != 1 || table.Production[0].Path != HelloMethod || table.HealthPath != APIPrefix+HealthPath {
		t.Fatalf("the production table changed: %+v", table.Production)
	}
	for _, module := range modules {
		if module.Surface == SurfaceMobile && (len(module.Policies) != 0 || len(module.PlainPaths) != 0) {
			t.Fatal("the mobile module declares a method or a plain path")
		}
	}
	ingress, err := Ingress(modules)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range MobilePageRoutes() {
		if !ingress.IsPlain(row.Path) {
			t.Errorf("%s is not passed to the page handler", row.Path)
		}
	}
	for _, path := range []string{"/app", "/app/node/1", "/app/callback/x", "/.well-known/other", "/mobile"} {
		if ingress.IsPlain(path) {
			t.Errorf("%s is served", path)
		}
	}
}
