// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/routes"
)

// TestEveryPageRouteHasItsRowAndEveryRowItsRoute (SEC-01, F13): the page table is closed over the registered page routes, in both
// directions, and each row's credential agrees with its route's cookie rule.
func TestEveryPageRouteHasItsRowAndEveryRowItsRoute(t *testing.T) {
	served := routes.PageRoutes()
	if err := CheckPages(served); err != nil {
		t.Fatal(err)
	}
	if len(PageOperations()) != len(served) {
		t.Fatalf("%d rows for %d routes", len(PageOperations()), len(served))
	}
	for name, mutate := range map[string]func([]routes.PageRoute) []routes.PageRoute{
		"a route without a row":          func(rows []routes.PageRoute) []routes.PageRoute { rows[0].ID = "webBrowser.other"; return rows },
		"a row without a route":          func(rows []routes.PageRoute) []routes.PageRoute { return rows[1:] },
		"a cookie the row does not read": func(rows []routes.PageRoute) []routes.PageRoute { rows[7].Cookie = true; return rows },
		"a session the row cannot set": func(rows []routes.PageRoute) []routes.PageRoute {
			rows[4].SetCookie = routes.SetCookieSession
			return rows
		},
		"a row that reads no cookie": func(rows []routes.PageRoute) []routes.PageRoute { rows[0].Cookie = false; return rows },
	} {
		if err := CheckPages(mutate(routes.PageRoutes())); err == nil {
			t.Errorf("%s was admitted", name)
		}
	}
}

// TestEveryMethodAPageCallsHasAnOperationRow: a page has no authority of its own, only the API methods it calls in process, each
// of which has a row (and so a scope rule, a restricted rule, step-up evidence and a receipt as the API has).
func TestEveryMethodAPageCallsHasAnOperationRow(t *testing.T) {
	calls := PageCalls()
	if len(calls) != 17 {
		t.Fatalf("the pages call %d methods: %v", len(calls), calls)
	}
	for _, path := range calls {
		operation, ok := Lookup(path)
		if !ok {
			t.Errorf("%s has no operation row", path)
			continue
		}
		if !operation.Session && !strings.Contains(path, "Authentication") && !strings.Contains(path, "Enrollment") {
			t.Errorf("%s is anonymous but not a sign-in step", path)
		}
	}
	// The writes of the forms keep their rows' rules: the same receipts and the same evidence as the API.
	for id, want := range map[string]struct {
		receipt bool
		stepUp  StepUp
	}{
		"form.completePasskey": {true, NoEvidence}, "form.renamePasskey": {true, NoEvidence}, "form.removePasskey": {true, Evidence},
		"form.revokeSession": {true, EvidenceUnlessOwn}, "form.revokeAllSessions": {true, Evidence}, "form.renameDevice": {true, NoEvidence},
		"form.revokeDevice": {true, EvidenceUnlessOwn}, "form.addPasskey": {false, Evidence},
	} {
		row, ok := PageOperationOf(id)
		if !ok || len(row.Calls) != 1 {
			t.Fatalf("%s: %+v", id, row)
		}
		operation, _ := Lookup(row.Calls[0])
		if operation.Receipt != want.receipt || operation.StepUp != want.stepUp {
			t.Errorf("%s calls %s with %+v", id, operation.ID, operation)
		}
	}
	if _, ok := PageOperationOf("page.unknown"); ok {
		t.Fatal("an unknown page has a row")
	}
}
