// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"flag"
	"fmt"
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
		for _, route := range routes.PageRoutes() {
			if !proved[route.Method+" "+route.Path] {
				fmt.Fprintf(os.Stderr, "no test proved a success of %s %s (%s)\n", route.Method, route.Path, route.ID)
				code = 1
			}
		}
	}
	os.Exit(code)
}
