// SPDX-License-Identifier: AGPL-3.0-only

// Package access is the center's authorization of the identity surface (AF-CTR-03, SEC-01): one closed operation table keyed by
// the exact method path, naming each served method's contract operation (fixtures/public/con-07-identity.json), its risk, whether
// it needs a session, which callers it admits, whether it needs step-up evidence and whether it runs under a command receipt. The
// composition refuses to start when a served method has no row or a row has no served method, so nothing is admitted by
// omission. A session method admits only the account-session scopes (account and mobile.limited): a node, push or automation
// credential is refused with AUTHORIZATION/permission_denied before any handler runs or anything is written, and each such
// refusal is audited as access.refused. A restricted account reaches only its security operations. A mobile.limited session
// (a QR-paired phone before its first step-up; AD-0011 section 3, T-19) reaches the reads, the step-up and its own sign-out and
// device removal; everything else answers AUTHENTICATION/step_up_required until a step-up upgrades the session to account.
//
// Authorize decides in a fixed order (AF-CTR-03 part B, plan section (g)); an earlier stage that refuses ends the decision, so a
// later stage is never reached by a call an earlier one refused:
//
//  1. authentication: the call has a validated credential;
//  2. ownership: the object the call addresses belongs to the caller's account, else STATE/not_found (rows that name an Object);
//  3. scope and risk: a credential scope the center knows, an account whose state admits the operation, the session upgrade;
//  4. AGENT/HUMAN separation: the credential's principal is the one the operation serves (account sessions are HUMAN, node and
//     automation credentials are AGENT);
//  5. resource controls: the hook for the controls a composition registers (WithControls; none is composed yet, and the quotas,
//     budgets and per-account limits of the gated operations arrive with AF-CTR-04, DC-07);
//  6. audit: an operation whose Audit is AuditBeforeCall appends access.authorized, and a failed append refuses the call;
//  7. the gate: an operation with a Feature key is refused with ENTITLEMENT/feature_not_entitled unless the feature is available to
//     the caller's account, and the refusal is audited as access.gated.
//
// Essential operations (sign-in, account, billing, security and recovery) carry no Feature and are never gated.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
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
	// Upgrade: the session must first be upgraded to account by a step-up.
	Upgrade
	// UpgradeUnlessOwn: open to a mobile.limited session for the caller's own session or device (sign-out, removing this phone;
	// android.md A-09), an upgrade for any other target. The handler decides once it knows the target.
	UpgradeUnlessOwn
)

// StepUp is when an operation needs step-up evidence (DC-01): one proved, unconsumed challenge of the caller's session for the
// operation's class and target, at most five minutes old, consumed by the operation's own transaction.
type StepUp int

// The evidence rules.
const (
	// NoEvidence: the operation needs none.
	NoEvidence StepUp = iota
	// Evidence: every call needs evidence.
	Evidence
	// EvidenceUnlessOwn: a call on the caller's own session or device needs none (sign-out and removing this phone only remove
	// the caller's own access; decision 4.1b), any other target needs evidence.
	EvidenceUnlessOwn
)

// Audit is who appends the audit event of an operation whose effect or disclosure matters (R3 and above, and every gated one).
type Audit int

// The audit rules.
const (
	// NoAudit: the operation is audited only by the events its own work produces (reads and low-risk writes).
	NoAudit Audit = iota
	// AuditInTransaction: the operation's handler appends its event in the transaction of the effect, so a failed append undoes the
	// effect (the high-risk identity rows).
	AuditInTransaction
	// AuditBeforeCall: Authorize appends access.authorized before the handler runs and before the gate, and a failed append refuses
	// the call (every gated operation).
	AuditBeforeCall
)

// The targets of the step-up classes: the object the target hash names (TargetHash).
const (
	TargetAccount    = "account"
	TargetSession    = "session"
	TargetCredential = "credential"
	TargetDevice     = "device"
)

// UpgradeClass is the center's own step-up class for a mobile.limited session that verifies only to unlock everything (android.md
// A-09, "Verify to unlock all"). Its target is the session; the upgrade consumes the evidence at once.
const UpgradeClass = "identity.upgradeSession"

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
	// StepUp is when the operation needs step-up evidence; Target names its target object.
	StepUp StepUp
	Target string
	// Receipt is true for a write that runs under a command receipt (RequestMeta.command_id; con-07 idempotency IW, DE or CC).
	Receipt bool
	// Feature is the gated feature key of the operation (AD-0021 section 13a), or empty for an essential operation, which is never
	// gated. A gated operation is a session operation audited before the call (AuditBeforeCall).
	Feature feature.Key
	// Agent is true for an operation served to AGENT credentials (node and automation scopes) instead of HUMAN account sessions
	// (account and mobile.limited). No identity row is an agent operation.
	Agent bool
	// Object is the kind of the object the call addresses (device, task, ...), or empty. Authorize then needs the object's owner (a
	// Subject) and answers STATE/not_found for an object of another account before it decides anything else.
	Object string
	// Audit says who appends the operation's audit event; every R3 or higher row and every gated row has one.
	Audit Audit
}

// Operations is the closed table of the served identity and device methods. Risks and evidence follow con-07, with the stricter
// rule where AD-0011 section 3 adds one (DC-18): DeviceService.Rename is device management, so a mobile.limited session needs the
// upgrade, and revoking a session other than the caller's needs evidence (W-22).
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
		{Path: publicapiv1connect.IdentityServiceBeginStepUpProcedure, ID: "identity.beginStepUp", Risk: "R1", Session: true, Restricted: true},
		{Path: publicapiv1connect.IdentityServiceCompleteStepUpProcedure, ID: "identity.completeStepUp", Risk: "R1", Session: true, Restricted: true},
		{Path: publicapiv1connect.IdentityServiceUpdateProfileProcedure, ID: "identity.updateProfile", Risk: "R2", Session: true, MobileLimited: Upgrade,
			Receipt: true},
		{Path: publicapiv1connect.IdentityServiceBeginPasskeyRegistrationProcedure, ID: "identity.beginPasskeyRegistration", Risk: "R2", Session: true,
			MobileLimited: Upgrade, StepUp: Evidence, Target: TargetAccount},
		{Path: publicapiv1connect.IdentityServiceCompletePasskeyRegistrationProcedure, ID: "identity.completePasskeyRegistration", Risk: "R2",
			Session: true, MobileLimited: Upgrade, Receipt: true},
		{Path: publicapiv1connect.IdentityServiceRenameAuthIdentityProcedure, ID: "identity.renameAuthIdentity", Risk: "R2", Session: true,
			Restricted: true, MobileLimited: Upgrade, Receipt: true},
		{Path: publicapiv1connect.IdentityServiceRemoveAuthIdentityProcedure, ID: "identity.removeAuthIdentity", Risk: "R3", Audit: AuditInTransaction, Session: true,
			Restricted: true, MobileLimited: Upgrade, StepUp: Evidence, Target: TargetCredential, Receipt: true},
		{Path: publicapiv1connect.IdentityServiceRevokeSessionProcedure, ID: "identity.revokeSession", Risk: "R2", Session: true, Restricted: true,
			MobileLimited: UpgradeUnlessOwn, StepUp: EvidenceUnlessOwn, Target: TargetSession, Receipt: true},
		{Path: publicapiv1connect.IdentityServiceRevokeAllSessionsProcedure, ID: "identity.revokeAllSessions", Risk: "R3", Audit: AuditInTransaction, Session: true,
			Restricted: true, MobileLimited: Upgrade, StepUp: Evidence, Target: TargetAccount, Receipt: true},
		{Path: publicapiv1connect.DeviceServiceRenameProcedure, ID: "device.rename", Risk: "R1", Session: true, Restricted: true, MobileLimited: Upgrade,
			Receipt: true},
		{Path: publicapiv1connect.DeviceServiceRevokeProcedure, ID: "device.revoke", Risk: "R3", Audit: AuditInTransaction, Session: true, Restricted: true,
			MobileLimited: UpgradeUnlessOwn, StepUp: EvidenceUnlessOwn, Target: TargetDevice, Receipt: true},
	}
}

// OperatorGrantClass is the operation ID and step-up class of the operator grant, a center-defined operation (the contract has no row
// for it): its target is the request itself, named by the SHA-256 of its canonical text (SEC-10). Package entitlement owns the
// operation.
const OperatorGrantClass = entitlement.OperatorGrantClass

// TargetRequest is the target of a center-defined operation: the canonical request.
const TargetRequest = "request"

// CenterOperation is an operation the center defines itself, outside the contract's operation table: the page of the operations
// surface performs it, and its authority is the operator role and the step-up evidence it consumes, not a session method's row.
type CenterOperation struct {
	// ID is the operation ID, the command receipt's operation and the step-up class.
	ID string
	// Risk is the risk class; StepUp and Target are its evidence rule, Receipt whether it runs under a command receipt.
	Risk    string
	StepUp  StepUp
	Target  string
	Receipt bool
	// Audit says who appends its audit event.
	Audit Audit
}

// CenterOperations is the closed list of the center-defined operations.
func CenterOperations() []CenterOperation {
	return []CenterOperation{{ID: OperatorGrantClass, Risk: "R4", StepUp: Evidence, Target: TargetRequest, Receipt: true, Audit: AuditInTransaction}}
}

// StepUpClass is a step-up class BeginStepUp admits and the target its hash names: the operation ID of a row that needs
// evidence, the upgrade class, or a center-defined operation that needs evidence.
func StepUpClass(class string) (target string, ok bool) {
	if class == UpgradeClass {
		return TargetSession, true
	}
	for _, operation := range CenterOperations() {
		if operation.ID == class && operation.StepUp != NoEvidence {
			return operation.Target, true
		}
	}
	for _, operation := range Operations() {
		if operation.ID == class && operation.StepUp != NoEvidence {
			return operation.Target, true
		}
	}
	return "", false
}

// NeedsUpgrade reports whether a caller must first upgrade its session for a call on a target that is (or is not) its own.
func (o Operation) NeedsUpgrade(caller ingress.Caller, own bool) bool {
	if caller.Scope != "mobile.limited" {
		return false
	}
	return o.MobileLimited == Upgrade || o.MobileLimited == UpgradeUnlessOwn && !own
}

// NeedsEvidence reports whether a call on a target that is (or is not) the caller's own needs step-up evidence.
func (o Operation) NeedsEvidence(own bool) bool {
	return o.StepUp == Evidence || o.StepUp == EvidenceUnlessOwn && !own
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
func Check(served []ingress.Policy) error { return checkTable(Operations(), served) }

// checkTable is Check over a given table.
func checkTable(table []Operation, served []ingress.Policy) error {
	rows := map[string]Operation{}
	for _, operation := range table {
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
		if err := CheckRow(operation); err != nil {
			return err
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

// CheckRow refuses a row that contradicts itself: evidence and its target go together; an anonymous row carries nothing that needs
// a caller; a Feature is a gated key, is audited before the call and belongs to a session operation; an R3 or higher row is audited;
// an agent operation is no mobile.limited, restricted or step-up row, because those rules are about a person's session.
func CheckRow(operation Operation) error {
	inconsistent := func(why string) error {
		return fmt.Errorf("the operation row of %s is inconsistent: %s", operation.Path, why)
	}
	switch {
	case (operation.StepUp != NoEvidence) != (operation.Target != ""):
		return inconsistent("evidence and its target go together")
	case !operation.Session && (operation.StepUp != NoEvidence || operation.Receipt || operation.MobileLimited != Allowed || operation.Restricted ||
		operation.Agent || operation.Object != "" || operation.Audit != NoAudit):
		// A gated row is audited before the call, so it is caught here as well.
		return inconsistent("an anonymous row needs no caller")
	case operation.Feature != "" && !feature.IsGated(operation.Feature):
		return inconsistent("the feature is not a gated key")
	case operation.Feature != "" && operation.Restricted:
		return inconsistent("a gated operation is no security operation a restricted account may reach")
	case operation.Feature != "" && operation.Audit != AuditBeforeCall:
		return inconsistent("a gated row is audited before the call")
	case operation.Audit == AuditBeforeCall && operation.Feature == "" && operation.Risk != "R3" && operation.Risk != "R4":
		return inconsistent("only a gated or high-risk row is audited before the call")
	case (operation.Risk == "R3" || operation.Risk == "R4") && operation.Audit == NoAudit:
		return inconsistent("a high-risk row is audited")
	case operation.Agent && (operation.MobileLimited != Allowed || operation.Restricted || operation.StepUp != NoEvidence):
		return inconsistent("an agent row follows no person's session rule")
	}
	return nil
}

// A Principal is who a credential acts for: an account session acts for a person (HUMAN), a node or automation credential for a
// machine (AGENT). A credential of another scope (push) is neither and is admitted to no session operation.
type Principal int

// The principals.
const (
	Human Principal = iota + 1
	Agent
)

// PrincipalOf is the principal of a credential scope, and false for a scope that acts for none.
func PrincipalOf(scope string) (Principal, bool) {
	switch scope {
	case "account", "mobile.limited":
		return Human, true
	case "node", "automation":
		return Agent, true
	}
	return 0, false
}

func (o Operation) principal() Principal {
	if o.Agent {
		return Agent
	}
	return Human
}

// restrictedState is identity.user_state restricted.
const restrictedState = 2

// Subject is the object a call addresses, as the handler that has read the request knows it. Authorize asks for its owner when the
// operation names an Object, so another account's object is STATE/not_found whatever the later stages would say.
type Subject struct {
	// Kind is the kind of the object; it must be the operation's Object.
	Kind string
	// ID is the object's identifier as the not_found refusal names it.
	ID []byte
	// Owner reads the account that owns the object (as the text of its identifier); found is false when there is no such object.
	Owner func(ctx context.Context) (account string, found bool, err error)
}

// Control is a resource control (DC-07): it returns nil to admit the call, or the refusal (an *arc.Refusal, for example a rate
// limit) or the store failure that stops it. It runs after the call's scope and principal are decided and before the audit and the
// gate, so a call that exhausted a resource is refused before it reaches either.
type Control func(ctx context.Context, call *ingress.Call, operation Operation) error

// Authorizer decides a session call and audits its refusals.
type Authorizer struct {
	db       *store.DB
	clock    func() time.Time
	gate     feature.Gate
	controls []Control
	lookup   func(path string) (Operation, bool)
}

// Option configures an Authorizer.
type Option func(*Authorizer)

// WithGate sets the feature gate that decides the operations with a Feature. Without one a gated operation is refused as if its
// feature were unavailable (fail closed).
func WithGate(gate feature.Gate) Option { return func(a *Authorizer) { a.gate = gate } }

// Gate is the feature gate the authorizer asks, or nil.
func (a *Authorizer) Gate() feature.Gate { return a.gate }

// WithControls sets the resource controls Authorize runs, in order, before the audit and the gate.
func WithControls(controls ...Control) Option {
	return func(a *Authorizer) { a.controls = append([]Control(nil), controls...) }
}

// NewAuthorizer is the authorizer of a store.
func NewAuthorizer(db *store.DB, clock func() time.Time, options ...Option) *Authorizer {
	if clock == nil {
		clock = time.Now
	}
	authorizer := &Authorizer{db: db, clock: clock, lookup: Lookup}
	for _, option := range options {
		option(authorizer)
	}
	return authorizer
}

// Authorize decides an admitted call of the identity surface before its handler does anything, for an operation that addresses no
// object (AuthorizeSubject with none). An unknown method is refused (fail closed); an anonymous method needs nothing more; a session
// method goes through the stages listed in the package comment. A refusal is returned as *arc.Refusal after its audit event
// committed; any other error is a store failure.
func (a *Authorizer) Authorize(ctx context.Context, call *ingress.Call) (Operation, error) {
	return a.AuthorizeSubject(ctx, call, nil)
}

// AuthorizeSubject is Authorize for a call that addresses an object: a row that names an Object needs the matching Subject, and a
// call without one is refused (fail closed).
func (a *Authorizer) AuthorizeSubject(ctx context.Context, call *ingress.Call, subject *Subject) (Operation, error) {
	operation, ok := a.lookup(call.Policy.FullName)
	if !ok {
		return Operation{}, arc.PermissionDenied("unknown")
	}
	if !operation.Session {
		return operation, nil
	}
	caller := call.Caller
	// 1. Authentication.
	if !caller.IsAuthenticated() {
		return operation, arc.Unauthenticated()
	}
	// 2. Ownership of the addressed object. A subject for a row that names no Object is a handler that decided ownership by itself:
	// refused, because nothing here would check it.
	if operation.Object != "" || subject != nil {
		if err := a.owned(ctx, call, operation, subject); err != nil {
			return operation, err
		}
	}
	// 3. Scope and risk.
	principal, known := PrincipalOf(caller.Scope)
	switch {
	case !known:
		return operation, a.refuse(ctx, call, operation, "scope")
	case caller.AccountState == restrictedState && !operation.Restricted:
		return operation, a.refuse(ctx, call, operation, "restricted")
	case operation.MobileLimited == Upgrade && operation.NeedsUpgrade(caller, false):
		return operation, arc.StepUpRequired()
	}
	// 4. AGENT/HUMAN separation.
	if principal != operation.principal() {
		return operation, a.refuse(ctx, call, operation, "principal")
	}
	// 5. Resource controls.
	for _, control := range a.controls {
		if err := control(ctx, call, operation); err != nil {
			return operation, err
		}
	}
	// 6. The audit that comes before the call; a failed append refuses it.
	if operation.Audit == AuditBeforeCall {
		if err := a.audit(ctx, call, operation, AuditAuthorized, "", map[string]any{"operation": operation.ID, "risk": operation.Risk, "feature": string(operation.Feature),
			"scope": caller.Scope}); err != nil {
			return operation, err
		}
	}
	// 7. The gate.
	if operation.Feature != "" {
		if err := a.gated(ctx, call, operation); err != nil {
			return operation, err
		}
	}
	return operation, nil
}

// The audit events Authorize appends.
const (
	// AuditRefused is a refusal of scope, principal or account state.
	AuditRefused = "access.refused"
	// AuditAuthorized is the audit that comes before a gated or high-risk call.
	AuditAuthorized = "access.authorized"
	// AuditGated is a gated call the gate refused; its reason is the gate's.
	AuditGated = "access.gated"
)

// owned is stage 2: the addressed object exists and belongs to the caller's account, else STATE/not_found. A row that names an
// Object and a call without the matching Subject is a defect of the handler and is refused, never admitted.
func (a *Authorizer) owned(ctx context.Context, call *ingress.Call, operation Operation, subject *Subject) error {
	if subject == nil || operation.Object == "" || subject.Kind != operation.Object || subject.Owner == nil {
		return a.refuse(ctx, call, operation, "subject")
	}
	owner, found, err := subject.Owner(ctx)
	switch {
	case err != nil:
		return err
	case !found || owner != call.Caller.UserID:
		return arc.NotFound(subject.Kind, subject.ID)
	}
	return nil
}

// gated is stage 7: ENTITLEMENT/feature_not_entitled unless the gate says the feature is available to the caller's account. A gate
// that could not read the entitlement is a failure of the store and is returned as one, not as a missing entitlement.
func (a *Authorizer) gated(ctx context.Context, call *ingress.Call, operation Operation) error {
	decision := feature.Decision{Reason: feature.ReasonModeInvalid}
	if a.gate != nil {
		decision = a.gate.Availability(feature.WithAccount(ctx, call.Caller.UserID), operation.Feature)
	}
	switch {
	case decision.Available:
		return nil
	case decision.Err != nil:
		return gateFailure(decision.Err)
	}
	if err := a.audit(ctx, call, operation, AuditGated, string(decision.Reason), map[string]any{"operation": operation.ID, "feature": string(operation.Feature),
		"reason": string(decision.Reason)}); err != nil {
		return err
	}
	return arc.FeatureNotEntitled(string(operation.Feature))
}

func (a *Authorizer) refuse(ctx context.Context, call *ingress.Call, operation Operation, reason string) error {
	if err := a.audit(ctx, call, operation, AuditRefused, reason, map[string]any{"operation": operation.ID, "scope": call.Caller.Scope, "reason": reason}); err != nil {
		return err
	}
	return arc.PermissionDenied(operation.ID)
}

// audit appends one event about the call in a transaction of its own: it is no effect of the call it is about (D10). An error is
// the store failure, which refuses the call.
func (a *Authorizer) audit(ctx context.Context, call *ingress.Call, operation Operation, eventType, reason string, details map[string]any) error {
	payload, err := json.Marshal(details)
	if err != nil {
		return err
	}
	var correlationID *platform.ID
	if raw := correlation.IDBytes(call.Correlation.CorrelationID); len(raw) == 16 {
		var id platform.ID
		copy(id[:], raw)
		correlationID = &id
	}
	return a.db.InTx(ctx, "audit an access decision", store.TxOptions{Timeout: 5 * time.Second, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: a.clock(), ActorRef: "account:" + call.Caller.UserID,
			EventType: eventType, Reason: reason, CorrelationID: correlationID, TargetKind: "operation", TargetID: operation.ID, Payload: payload})
		return err
	})
}

// gateFailure is the answer to a gate that could not decide. The gate runs before the handler, so a failure of the snapshot's own
// refresh did not touch the call's effect: a commit whose outcome is unknown, a refresh that lost its race on every attempt and a
// center without an entitlement store are an unavailable store (RESOURCE/overloaded, the call did not happen, retry later). A store
// failure keeps its own classification (the transport maps it) and anything else, a defect of the history or of the code, stays what
// it is and is answered INTERNAL/internal.
func gateFailure(err error) error {
	var refusal *entitlement.Refusal
	switch {
	case errors.Is(err, store.ErrCommitUnknown), errors.Is(err, feature.ErrNoEntitlementStore),
		errors.As(err, &refusal) && (refusal.Kind == entitlement.RefusedOutcomeUnknown || refusal.Kind == entitlement.RefusedConcurrentUpdate):
		return arc.Unavailable()
	}
	return err
}
