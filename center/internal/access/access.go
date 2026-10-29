// SPDX-License-Identifier: AGPL-3.0-only

// Package access is the center's authorization of the identity surface (AF-CTR-03, SEC-01): one closed operation table keyed by
// the exact method path, naming each served method's contract operation (fixtures/public/con-07-identity.json), its risk, whether
// it needs a session, and which callers it admits. The composition refuses to start when a served method has no row or a row has
// no served method, so nothing is admitted by omission. A session method admits only the account-session scopes (account and
// mobile.limited): a node, push or automation credential is refused with AUTHORIZATION/permission_denied before any handler runs or
// anything is written, and each such refusal is audited as access.refused. A restricted account reaches only its security
// operations. A1a serves reads only; step-up, sign-out, revocation and the credential and device changes arrive with A1b, which
// extends this table.
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// MobileLimited is what a mobile.limited session may do with an operation.
type MobileLimited int

// The mobile.limited rules (AD-0011 section 5; T-19).
const (
	// Allowed: the operation is open to a mobile.limited session.
	Allowed MobileLimited = iota
	// Upgrade: the session must first be upgraded to account by a step-up (A1b).
	Upgrade
)

// Operation is one row of the operation table.
type Operation struct {
	Path string
	// ID is the contract operation ID (con-07), the permission_denied reason and the step-up operation class.
	ID string
	// Risk is the contract risk class (R1 to R4).
	Risk string
	// Session is true for a method that needs an account session; false for an anonymous sign-in method.
	Session bool
	// Restricted is true for a security operation a restricted account may still call.
	Restricted bool
	// MobileLimited is the rule of a mobile.limited session.
	MobileLimited MobileLimited
}

// Operations is the closed table of the served identity and device methods.
func Operations() []Operation {
	return []Operation{
		{Path: publicapiv1connect.IdentityServiceBeginAuthenticationProcedure, ID: "identity.beginAuthentication", Risk: "R1"},
		{Path: publicapiv1connect.IdentityServiceCompleteAuthenticationProcedure, ID: "identity.completeAuthentication", Risk: "R1"},
		{Path: publicapiv1connect.IdentityServiceRequestEmailCodeProcedure, ID: "identity.requestEmailCode", Risk: "R1"},
		{Path: publicapiv1connect.IdentityServiceRedeemEmailCodeProcedure, ID: "identity.redeemEmailCode", Risk: "R1"},
		{Path: publicapiv1connect.IdentityServiceCompleteEnrollmentProcedure, ID: "identity.completeEnrollment", Risk: "R1"},
		{Path: publicapiv1connect.IdentityServiceListAuthProvidersProcedure, ID: "identity.listAuthProviders", Risk: "R1"},
		{Path: publicapiv1connect.IdentityServiceRefreshSessionProcedure, ID: "identity.refreshSession", Risk: "R1"},
		{Path: publicapiv1connect.IdentityServiceGetProfileProcedure, ID: "identity.getProfile", Risk: "R1", Session: true},
		{Path: publicapiv1connect.IdentityServiceListAuthIdentitiesProcedure, ID: "identity.listAuthIdentities", Risk: "R1", Session: true, Restricted: true},
		{Path: publicapiv1connect.IdentityServiceListSessionsProcedure, ID: "identity.listSessions", Risk: "R1", Session: true, Restricted: true},
		{Path: publicapiv1connect.DeviceServiceListProcedure, ID: "device.list", Risk: "R1", Session: true, Restricted: true},
	}
}

// Lookup is the row of a method path.
func Lookup(path string) (Operation, bool) {
	for _, operation := range Operations() {
		if operation.Path == path {
			return operation, true
		}
	}
	return Operation{}, false
}

// Check compares the table with the served methods of the identity surface: every served method has exactly one row whose
// session requirement matches its policy, and every row is served.
func Check(served []ingress.Policy) error {
	rows := map[string]Operation{}
	for _, operation := range Operations() {
		if _, repeated := rows[operation.Path]; repeated {
			return fmt.Errorf("the operation table names %s twice", operation.Path)
		}
		rows[operation.Path] = operation
	}
	seen := map[string]bool{}
	for _, policy := range served {
		operation, ok := rows[policy.FullName]
		if !ok {
			return fmt.Errorf("the served method %s has no row in the operation table", policy.FullName)
		}
		if operation.Session != (policy.Authentication == ingress.Session) {
			return fmt.Errorf("the operation table and the policy of %s disagree about its session", policy.FullName)
		}
		seen[policy.FullName] = true
	}
	for path := range rows {
		if !seen[path] {
			return fmt.Errorf("the operation table names %s, which is not served", path)
		}
	}
	return nil
}

// accountScopes are the scopes a session method admits (DC-03).
var accountScopes = []string{"account", "mobile.limited"}

// restrictedState is identity.user_state restricted.
const restrictedState = 2

// Authorizer decides a session call and audits its refusals.
type Authorizer struct {
	db    *store.DB
	clock func() time.Time
}

// NewAuthorizer is the authorizer of a store.
func NewAuthorizer(db *store.DB, clock func() time.Time) *Authorizer {
	if clock == nil {
		clock = time.Now
	}
	return &Authorizer{db: db, clock: clock}
}

// Authorize decides an admitted call of the identity surface before its handler does anything: an unknown method is refused
// (fail closed); an anonymous method needs nothing more; a session method needs an account-session scope, an account whose state
// admits the operation and, for mobile.limited, an operation open to it. A refusal is returned as *arc.Refusal after its audit
// event committed; any other error is a store failure.
func (a *Authorizer) Authorize(ctx context.Context, call *ingress.Call) (Operation, error) {
	operation, ok := Lookup(call.Policy.FullName)
	if !ok {
		return Operation{}, arc.PermissionDenied("unknown")
	}
	if !operation.Session {
		return operation, nil
	}
	caller := call.Caller
	switch {
	case !caller.IsAuthenticated():
		return operation, arc.Unauthenticated()
	case !slices.Contains(accountScopes, caller.Scope):
		return operation, a.refuse(ctx, call, operation, "scope")
	case caller.AccountState == restrictedState && !operation.Restricted:
		return operation, a.refuse(ctx, call, operation, "restricted")
	case caller.Scope == "mobile.limited" && operation.MobileLimited == Upgrade:
		return operation, arc.StepUpRequired()
	}
	return operation, nil
}

func (a *Authorizer) refuse(ctx context.Context, call *ingress.Call, operation Operation, reason string) error {
	payload, err := json.Marshal(map[string]any{"operation": operation.ID, "scope": call.Caller.Scope, "reason": reason})
	if err != nil {
		return err
	}
	var correlationID *platform.ID
	if raw := correlation.IDBytes(call.Correlation.CorrelationID); len(raw) == 16 {
		var id platform.ID
		copy(id[:], raw)
		correlationID = &id
	}
	// The audit is no effect of the refused call, so its transaction is auxiliary (D10).
	err = a.db.InTx(ctx, "audit an access refusal", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: a.clock(), ActorRef: "account:" + call.Caller.UserID,
			EventType: "access.refused", Reason: reason, CorrelationID: correlationID, TargetKind: "operation", TargetID: operation.ID, Payload: payload})
		return err
	})
	if err != nil {
		return err
	}
	return arc.PermissionDenied(operation.ID)
}
