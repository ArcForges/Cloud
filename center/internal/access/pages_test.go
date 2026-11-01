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
	served := routes.AllPageRoutes()
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
		if err := CheckPages(mutate(routes.AllPageRoutes())); err == nil {
			t.Errorf("%s was admitted", name)
		}
	}
}

// TestEveryMethodAPageCallsHasAnOperationRow: a page has no authority of its own, only the API methods it calls in process, each
// of which has a row (and so a scope rule, a restricted rule, step-up evidence and a receipt as the API has).
func TestEveryMethodAPageCallsHasAnOperationRow(t *testing.T) {
	calls := PageCalls()
	if len(calls) != 17 { // the operations surface's routes call no method of the table
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

// TestTheOperationsPagesPerformACenterDefinedOperation: the operator grant is no row of the contract's operation table; the page
// table names it as the center-defined operation the review checks and the confirmation performs, and its step-up class is offered.
func TestTheOperationsPagesPerformACenterDefinedOperation(t *testing.T) {
	for id, want := range map[string]string{"operations.grant": "", "operations.review": OperatorGrantClass, "operations.confirm": OperatorGrantClass} {
		row, ok := PageOperationOf(id)
		if !ok || row.Center != want || len(row.Calls) != 0 || row.Credential != PageSession {
			t.Errorf("%s: %+v", id, row)
		}
	}
	operations := CenterOperations()
	if len(operations) != 1 || operations[0].ID != "center.operatorGrant" || operations[0].Risk != "R4" || operations[0].StepUp != Evidence ||
		operations[0].Target != TargetRequest || !operations[0].Receipt || operations[0].Audit != AuditInTransaction {
		t.Fatalf("%+v", operations)
	}
	if target, ok := StepUpClass(OperatorGrantClass); !ok || target != TargetRequest {
		t.Fatalf("%q %v", target, ok)
	}
	// A form that calls no method and performs no center-defined operation is refused, as is a row that names an unknown operation.
	served := routes.AllPageRoutes()
	if err := CheckPages(served); err != nil {
		t.Fatal(err)
	}
	for _, row := range PageOperations() {
		if row.Center != "" && row.Center != OperatorGrantClass {
			t.Errorf("%s performs %q", row.ID, row.Center)
		}
	}
}
