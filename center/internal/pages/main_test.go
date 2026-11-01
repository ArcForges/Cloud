// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// TestMain fails a full run (every test, against a real PostgreSQL) in which a page route of the registration, a POST above all, was
// never answered with success by any test: a route added without a success test is a failing run (F2).
func TestMain(m *testing.M) {
	code := m.Run()
	filter := flag.Lookup("test.run")
	if code == 0 && os.Getenv(pgtest.EnvServer) != "" && (filter == nil || filter.Value.String() == "") && !testing.Short() {
		provedMu.Lock()
		defer provedMu.Unlock()
		for _, route := range routes.AllPageRoutes() {
			if !proved[route.Method+" "+route.Path] {
				fmt.Fprintf(os.Stderr, "no test proved a success of %s %s (%s)\n", route.Method, route.Path, route.ID)
				code = 1
			}
		}
	}
	os.Exit(code)
}

// TestARouteIsProvedOnlyByASuccess (rec-7): a page counts when it is served (200), a JSON route on a 2xx, a form on a redirect that
// is not to the sign-in page; a refusal, a redirect of a page to the sign-in and a form that the sign-in page took back prove nothing.
func TestARouteIsProvedOnlyByASuccess(t *testing.T) {
	signIn := basePath + "/account/sign-in"
	for _, probe := range []struct {
		method   string
		status   int
		location string
		want     bool
	}{
		{http.MethodGet, 200, "", true},
		{http.MethodGet, 303, signIn + "#return=x", false},
		{http.MethodGet, 304, "", false},
		{http.MethodGet, 404, "", false},
		{http.MethodPost, 200, "", true},
		{http.MethodPost, 204, "", true},
		{http.MethodPost, 303, basePath + "/account/sessions", true},
		{http.MethodPost, 303, signIn, false},
		{http.MethodPost, 400, "", false},
		{http.MethodPost, 403, "", false},
		{http.MethodPost, 503, "", false},
	} {
		path := fmt.Sprintf("/probe/%s/%d/%s", probe.method, probe.status, probe.location)
		recordProved(probe.method, path, probe.status, probe.location)
		provedMu.Lock()
		got := proved[probe.method+" "+path]
		delete(proved, probe.method+" "+path)
		provedMu.Unlock()
		if got != probe.want {
			t.Errorf("%s %d %q proves a route: %v, want %v", probe.method, probe.status, probe.location, got, probe.want)
		}
	}
}
