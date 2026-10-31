// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"fmt"

	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"

	"github.com/ArcForges/Cloud/center/internal/routes"
)

// PageCredential is the credential a page route reads.
type PageCredential int

// The credentials of the page routes.
const (
	// PageNoCredential: the route reads no session (a static asset, the sign-in and bootstrap pages, whose script asks the bootstrap
	// route who is signed in).
	PageNoCredential PageCredential = iota + 1
	// PageOptionalSession: the route tells a session from none and answers either (the bootstrap read).
	PageOptionalSession
	// PagePreSession: an anonymous sign-in step of the browser: the exact Origin, and the CSRF token of the session if one resolves,
	// else the constant derived from the public origin (decision 4.2). No flow cookie exists (decision 4.3).
	PagePreSession
	// PageSession: a live cookie session of this origin, and that session's own CSRF token on a POST. A GET page without one
	// redirects to the sign-in page.
	PageSession
)

// PageOperation is one row of the page table (SEC-01): a page route, the credential it reads and the API methods it calls in
// process. A page route has no authority of its own: what a route changes it changes through those methods, whose rows in
// Operations decide what the session may do (scope, restricted accounts, step-up evidence, receipts).
type PageOperation struct {
	// ID is the route's ID (routes.PageRoute.ID).
	ID         string
	Credential PageCredential
	// Calls are the paths of the API methods the route calls; each has a row in Operations.
	Calls []string
	// Center is the center-defined operation the route performs or reviews (CenterOperations), or empty. A form that changes something
	// calls a method of the operation table or performs a center-defined operation; the latter's authority is its own rule.
	Center string
}

// PageOperations is the closed table of the page routes. The composition refuses to start when a page route has no row, a row has
// no route, a row's credential contradicts its route's cookie rule, or a method it calls has no operation row.
func PageOperations() []PageOperation {
	profile := publicapiv1connect.IdentityServiceGetProfileProcedure
	return []PageOperation{
		{"webBrowser.bootstrap", PageOptionalSession, []string{profile}, ""},
		{"webBrowser.beginAuthentication", PagePreSession, []string{publicapiv1connect.IdentityServiceBeginAuthenticationProcedure}, ""},
		{"webBrowser.completeAuthentication", PagePreSession, []string{publicapiv1connect.IdentityServiceCompleteAuthenticationProcedure}, ""},
		{"webBrowser.completeEnrollment", PagePreSession, []string{publicapiv1connect.IdentityServiceCompleteEnrollmentProcedure}, ""},
		{"webBrowser.beginStepUp", PageSession, []string{publicapiv1connect.IdentityServiceBeginStepUpProcedure}, ""},
		{"webBrowser.completeStepUp", PageSession, []string{publicapiv1connect.IdentityServiceCompleteStepUpProcedure}, ""},
		{"webBrowser.logout", PageSession, []string{publicapiv1connect.IdentityServiceRevokeSessionProcedure}, ""},
		{"page.signIn", PageNoCredential, nil, ""},
		{"page.bootstrap", PageNoCredential, nil, ""},
		{"page.passkeys", PageSession, []string{profile, publicapiv1connect.IdentityServiceListAuthIdentitiesProcedure}, ""},
		{"page.sessions", PageSession, []string{publicapiv1connect.IdentityServiceListSessionsProcedure}, ""},
		{"page.devices", PageSession, []string{publicapiv1connect.DeviceServiceListProcedure}, ""},
		{"page.signOut", PageSession, nil, ""},
		{"asset.script", PageNoCredential, nil, ""},
		{"asset.style", PageNoCredential, nil, ""},
		{"form.addPasskey", PageSession, []string{publicapiv1connect.IdentityServiceBeginPasskeyRegistrationProcedure}, ""},
		{"form.completePasskey", PageSession, []string{publicapiv1connect.IdentityServiceCompletePasskeyRegistrationProcedure}, ""},
		{"form.renamePasskey", PageSession, []string{publicapiv1connect.IdentityServiceRenameAuthIdentityProcedure}, ""},
		{"form.removePasskey", PageSession, []string{publicapiv1connect.IdentityServiceRemoveAuthIdentityProcedure}, ""},
		{"form.revokeSession", PageSession, []string{publicapiv1connect.IdentityServiceRevokeSessionProcedure}, ""},
		{"form.revokeAllSessions", PageSession, []string{publicapiv1connect.IdentityServiceRevokeAllSessionsProcedure}, ""},
		{"form.renameDevice", PageSession, []string{publicapiv1connect.DeviceServiceRenameProcedure}, ""},
		{"form.revokeDevice", PageSession, []string{publicapiv1connect.DeviceServiceRevokeProcedure}, ""},
		// The operations surface: the operator grant is a center-defined operation, performed by the confirmation and reviewed (checked
		// without effect) by the review. The pages' own sign-in and step-up routes carry the session the operator proves it with.
		{"operations.grant", PageSession, nil, ""},
		{"operations.review", PageSession, nil, OperatorGrantClass},
		{"operations.confirm", PageSession, nil, OperatorGrantClass},
	}
}

// PageCalls is every API method the page routes call, once, in table order.
func PageCalls() []string {
	var calls []string
	seen := map[string]bool{}
	for _, row := range PageOperations() {
		for _, path := range row.Calls {
			if !seen[path] {
				seen[path] = true
				calls = append(calls, path)
			}
		}
	}
	return calls
}

// PageOperationOf is the row of a page route by its ID.
func PageOperationOf(id string) (PageOperation, bool) {
	for _, row := range PageOperations() {
		if row.ID == id {
			return row, true
		}
	}
	return PageOperation{}, false
}

// CheckPages compares the page table with the registered page routes (SEC-01, F13): every route has exactly one row and every row
// a route; a route that reads a cookie has a credential that reads one and the other way round; a route that sets a cookie is a
// sign-in step or the sign-out; a route that calls API methods only calls methods of the operation table; a session route
// calls at least one (or is the sign-out page and the assets); and a form changes nothing without a method of the table.
func CheckPages(served []routes.PageRoute) error {
	rows := map[string]PageOperation{}
	centers := map[string]bool{}
	for _, operation := range CenterOperations() {
		centers[operation.ID] = true
	}
	for _, row := range PageOperations() {
		if _, repeated := rows[row.ID]; repeated {
			return fmt.Errorf("the page table names %s twice", row.ID)
		}
		if row.Center != "" && !centers[row.Center] {
			return fmt.Errorf("the page table row %s performs %s, which is no center-defined operation", row.ID, row.Center)
		}
		rows[row.ID] = row
		for _, call := range row.Calls {
			if _, ok := Lookup(call); !ok {
				return fmt.Errorf("the page table row %s calls %s, which has no operation row", row.ID, call)
			}
		}
	}
	seen := map[string]bool{}
	for _, route := range served {
		row, ok := rows[route.ID]
		if !ok {
			return fmt.Errorf("the page route %s has no row in the page table", route.ID)
		}
		reads := row.Credential != PageNoCredential
		if reads != route.Cookie {
			return fmt.Errorf("the page table and the route %s disagree about the cookie", route.ID)
		}
		if route.SetCookie == routes.SetCookieSession && row.Credential != PagePreSession {
			return fmt.Errorf("the route %s sets a session cookie but is not a sign-in step", route.ID)
		}
		if route.Kind == routes.PageHTMLKind && route.Method == "POST" && len(row.Calls) == 0 && row.Center == "" {
			return fmt.Errorf("the form %s calls no method of the operation table and performs no center-defined operation", route.ID)
		}
		seen[route.ID] = true
	}
	for id := range rows {
		if !seen[id] {
			return fmt.Errorf("the page table names %s, which is not served", id)
		}
	}
	return nil
}
