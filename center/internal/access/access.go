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
//  1. authentication: the call has a validated credential, and a node credential on a row that admits it as a relayed caller
//     (RelayedScopes, AF-CTR-05 E2a) a relay assertion the authorizer itself verified for that credential's installation;
//  2. ownership: the object the call addresses belongs to the caller's account, else STATE/not_found (rows that name an Object);
//  3. scope and risk: a credential scope the center knows, an account whose state admits the operation, the session upgrade;
//  4. AGENT/HUMAN separation: the credential's principal is the one the operation serves (account sessions are HUMAN, node and
//     automation credentials are AGENT), and an AGENT operation admits exactly the credential scopes its row names (a node row
//     admits a node credential, never an automation one): another scope is refused with the audit reason scope; a person's row with
//     RelayedScopes admits the verified relay of stage 1 as its one AGENT caller, and refuses a person's session that names a relay;
//  5. resource controls: the per-account controls a composition registers (WithControls, DC-07; AF-CTR-05 E0): each control stands in
//     front of the rows it covers, every gated row has at least one (CheckControls; the composition refuses to start otherwise), and
//     a control runs before the audit and the gate, so a call an exhausted control refuses writes no access.authorized row;
//  6. audit: an operation whose Audit is AuditBeforeCall appends access.authorized, and a failed append refuses the call;
//  7. the gate: an operation with a Feature key is refused with ENTITLEMENT/feature_not_entitled unless the feature is available to
//     the caller's account, and the refusal is audited as access.gated.
//
// Essential operations (sign-in, account, billing, security and recovery) carry no Feature and are never gated. The node enrollment
// rows of the fleet surface (AF-CTR-04) are essential too (AD-0021 section 13a): node sign-in, refresh, report and sign-out.
//
// A gate that cannot decide (a commit whose outcome is unknown, a refresh that lost its race on every attempt, a center without an
// entitlement store, a replica whose definitions version is not the deploy's current one) answers RESOURCE/overloaded through a
// *GateFailure that wraps its cause, audited as access.gate_failure with a closed reason and no request text; the failure paths of the
// surfaces log it with the correlation ID (LogGateFailure).
//
// The audit reasons of access.refused are scope (a credential scope the center does not know, or one the AGENT row does not admit),
// restricted (a restricted account on a row it may not reach), principal (an AGENT credential on a HUMAN row or the reverse) and
// subject; the reply is always AUTHORIZATION/permission_denied with state operation and the operation ID as its reason.
package access

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
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
	// EvidenceOnApprove: a call that approves needs evidence, a call that denies needs none (the node sign-in approvals, AF-CTR-04 Q1:
	// a denial only refuses access). The handler asks the row (NeedsEvidenceToDecide) and passes the answer to the domain.
	EvidenceOnApprove
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
	// TargetFlow is a node sign-in flow, named by its flow ID (AF-CTR-04: the approval's evidence is bound to the flow it decides).
	TargetFlow = "flow"
	// TargetUserCode is a device authorization, named by its normalized user code, 8 upper-case letters (AF-CTR-04 E2: the approval's
	// evidence is bound to the code it decides; identity.TextTargetHash).
	TargetUserCode = "user_code"
	// TargetNode is an enrolled node, named by its node ID (AF-CTR-05 E2a, D0 verdict): RevokeNode's evidence of class fleet.revokeNode
	// is bound to the node it revokes (and E2b's routed Submit and Cancel to the node they run on).
	TargetNode = "node"
)

// UpgradeClass is the center's own step-up class for a mobile.limited session that verifies only to unlock everything (android.md
// A-09, "Verify to unlock all"). Its target is the session; the upgrade consumes the evidence at once.
const UpgradeClass = "identity.upgradeSession"

// Operation is one row of the operation table.
type Operation struct {
	Path string
	// ID is the contract operation ID (con-07), the permission_denied reason and the step-up operation class. con-07 names no fleet
	// operation, so the fleet rows carry center-defined IDs fleet.<method in lower camel case> (AF-CTR-04).
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
	// Group is the group of the routed task control table (feature.OperationKeys) a gated row belongs to: its Feature must be the key
	// the table names for the group (CheckRow), and only a gated row names one.
	Group feature.Group
	// Scopes are the credential scopes of an operation served to AGENT credentials instead of HUMAN account sessions: empty for a HUMAN
	// row (account and mobile.limited), otherwise a subset of the AGENT scopes node and automation, and only those are admitted (a
	// node row refuses an automation credential). No identity row is an agent operation; the fleet node rows admit node only.
	Scopes []string
	// RelayedScopes are the AGENT scopes a person's row also admits as a node-relayed caller (AF-CTR-05 E2a; Plan CTR5-SUR-03, PB-2,
	// D0-B1, C-N6): only node, only on the rows of RelayedOperations, and only with a relay assertion the hub verified for the bearer
	// credential (Authorize checks it before anything else). The row stays a HUMAN row: its MobileLimited and StepUp rules are its
	// account-session half's, and a relayed caller carries none of them (Design 11 section 1, "The relayed half of a row").
	RelayedScopes []string
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
		// The fleet surface (AF-CTR-04 E1a): the node refreshes anonymously with its refresh token (never under a receipt: it presents
		// a one-use secret); it reports its info and signs itself out with its node credential under a receipt of principal
		// node:<installation>. A restricted account's node may sign out (it only removes access) but not report. Never gated.
		// The browser node sign-in (E1b): Begin and Complete are anonymous (Complete's flow-bound proof is the one-use code, the PKCE
		// verifier and the node key proof; its effect is audited by the domain, fleet.node.enrolled); an account reviews the flow and
		// decides it, approval with step-up evidence of class fleet.approveNodeSignIn bound to the flow ID, denial without (Q1). A
		// restricted account cannot enroll a node (Q24) and a mobile.limited session upgrades first. None runs under a receipt.
		{Path: fleetv1connect.NodeEnrollmentServiceBeginNodeSignInProcedure, ID: "fleet.beginNodeSignIn", Risk: "R1"},
		{Path: fleetv1connect.NodeEnrollmentServiceGetNodeSignInFlowProcedure, ID: "fleet.getNodeSignInFlow", Risk: "R2", Session: true, MobileLimited: Upgrade},
		{Path: fleetv1connect.NodeEnrollmentServiceApproveNodeSignInProcedure, ID: "fleet.approveNodeSignIn", Risk: "R3", Audit: AuditInTransaction, Session: true,
			MobileLimited: Upgrade, StepUp: EvidenceOnApprove, Target: TargetFlow},
		{Path: fleetv1connect.NodeEnrollmentServiceCompleteNodeSignInProcedure, ID: "fleet.completeNodeSignIn", Risk: "R1"},
		// The device-code sign-in (E2): Start and Poll are anonymous (Poll's proof is the device code and the node key proof; its effect is
		// audited by the domain, fleet.node.enrolled); an account looks a user code up (a review, never under a receipt) and decides it
		// under a command receipt of the account, approval with step-up evidence of class fleet.approveDeviceCode bound to the normalized
		// user code, denial without (Q1). A restricted account cannot enroll a node (Q24) and a mobile.limited session upgrades first.
		{Path: fleetv1connect.NodeEnrollmentServiceStartDeviceAuthorizationProcedure, ID: "fleet.startDeviceAuthorization", Risk: "R1"},
		{Path: fleetv1connect.NodeEnrollmentServicePollDeviceAuthorizationProcedure, ID: "fleet.pollDeviceAuthorization", Risk: "R1"},
		{Path: fleetv1connect.NodeEnrollmentServiceLookupDeviceCodeProcedure, ID: "fleet.lookupDeviceCode", Risk: "R2", Session: true, MobileLimited: Upgrade},
		{Path: fleetv1connect.NodeEnrollmentServiceApproveDeviceCodeProcedure, ID: "fleet.approveDeviceCode", Risk: "R3", Audit: AuditInTransaction, Session: true,
			MobileLimited: Upgrade, StepUp: EvidenceOnApprove, Target: TargetUserCode, Receipt: true},
		{Path: fleetv1connect.NodeEnrollmentServiceRefreshNodeSessionProcedure, ID: "fleet.refreshNodeSession", Risk: "R1"},
		{Path: fleetv1connect.NodeEnrollmentServiceReportNodeInfoProcedure, ID: "fleet.reportNodeInfo", Risk: "R1", Session: true, Scopes: []string{"node"},
			Receipt: true},
		{Path: fleetv1connect.NodeEnrollmentServiceSignOutNodeProcedure, ID: "fleet.signOutNode", Risk: "R2", Session: true, Scopes: []string{"node"},
			Restricted: true, Receipt: true, Audit: AuditInTransaction},
		// The node channel (AF-CTR-05 E1a; Plan CTR5-SUR-02, CTR5-HUB-02): the upgrade route GET /fleet/v1/node, the first gated row. A
		// node credential only; the per-account and per-node upgrade-rate buckets stand in front of it (quota.ChannelUpgrades, Q21: no
		// connected-node cap), access.authorized is appended before the gate, and the gate asks center.nodes (the node connection group).
		// It is not served as a Connect method: the relay surface's upgrade handler authorizes it with this row before it upgrades.
		{Path: routes.NodeChannelPath, ID: routes.NodeChannelID, Risk: "R2", Session: true, Scopes: []string{"node"}, Feature: feature.CenterNodes,
			Group: feature.GroupNodeConnection, Audit: AuditBeforeCall},
		// The node registry of FleetService (AF-CTR-05 E2a; Plan CTR5-API-02..04, Q20: never gated, so a lapsed account still lists, renames
		// and revokes its nodes). ListNodes and GetNode admit an account session, and a node credential only as the verified relay of its
		// own node (C-N6: a bearer token alone reads nothing). RenameNode and RevokeNode are a person's device management (as
		// DeviceService.Rename and Revoke: a mobile.limited session upgrades first, a restricted account may still use them); RevokeNode
		// needs step-up evidence of its own class bound to the node it revokes, consumed in its receipt's transaction.
		{Path: fleetv1connect.FleetServiceListNodesProcedure, ID: "fleet.listNodes", Risk: "R1", Session: true, RelayedScopes: []string{"node"}},
		{Path: fleetv1connect.FleetServiceGetNodeProcedure, ID: "fleet.getNode", Risk: "R1", Session: true, RelayedScopes: []string{"node"}, Object: ObjectNode},
		{Path: fleetv1connect.FleetServiceRenameNodeProcedure, ID: "fleet.renameNode", Risk: "R2", Session: true, Restricted: true, MobileLimited: Upgrade,
			Receipt: true, Audit: AuditInTransaction, Object: ObjectNode},
		{Path: fleetv1connect.FleetServiceRevokeNodeProcedure, ID: "fleet.revokeNode", Risk: "R3", Session: true, Restricted: true, MobileLimited: Upgrade,
			StepUp: Evidence, Target: TargetNode, Receipt: true, Audit: AuditInTransaction, Object: ObjectNode},
	}
}

// ObjectNode is the Object of a row that addresses one enrolled node by its node ID: its owner is the account of the node's live
// enrollment, so an unknown, revoked or foreign node is STATE/not_found alike (Plan CTR5-RTE-04, CTR5-SEC-17).
const ObjectNode = "node"

// RelayedOperations are the operation IDs a row may name with RelayedScopes (AF-CTR-05; Design 11 section 1, "The relayed half of a
// row"): the node registry's two reads and the six routed task methods (served from part E2b). No other row admits a node-relayed
// caller, so a node credential never reaches account, device, billing or security methods (Plan CTR5-CALL-02).
func RelayedOperations() []string {
	return []string{"fleet.listNodes", "fleet.getNode", "fleet.submitNodeTask", "fleet.getNodeTask", "fleet.listNodeTasks", "fleet.waitNodeTask",
		"fleet.readNodeTaskOutput", "fleet.cancelNodeTask"}
}

// OperatorGrantClass is the operation ID and step-up class of the operator grant, a center-defined operation (the contract has no row
// for it): its target is the request itself, named by the SHA-256 of its canonical text (SEC-10). Package entitlement owns the
// operation.
const OperatorGrantClass = entitlement.OperatorGrantClass

// TargetRequest is the target of a center-defined operation: the canonical request.
const TargetRequest = "request"

// MobileAuthorizationClass is the operation ID and step-up class of an account's approval of the mobile app's native authorization
// (AF-CTR-04 part M, M-17; Contracts MobileNativeAuth names the class): a center-defined operation whose target is the flow, named by
// its flow ID (identity.TargetHash). Package mobileauth owns the operation; the /mobile/authorize pages perform it.
const MobileAuthorizationClass = "identity.authorizeMobile"

// CenterOperation is an operation the center defines itself, outside the contract's operation table: a page performs it, and its
// authority is its own rule (the operator role for the operator grant, the reviewing account for a mobile authorization) and the
// step-up evidence it consumes, not a session method's row.
type CenterOperation struct {
	// ID is the operation ID, the command receipt's operation and the step-up class.
	ID string
	// Risk is the risk class; StepUp and Target are its evidence rule, Receipt whether it runs under a command receipt.
	Risk    string
	StepUp  StepUp
	Target  string
	Receipt bool
	// Restricted is true for an operation a restricted account may still perform (a mobile authorization is a sign-in, Q-8). On a
	// CenterOperation it is a statement, not a check Authorize makes (no session method's row names it): the page's cookie session
	// admits an active or restricted account only (session.ResolveSession, MaySignIn), and the operation's own rule decides the rest
	// (the operator role; mobileauth's scope and purpose rule).
	Restricted bool
	// Audit says who appends its audit event.
	Audit Audit
}

// CenterOperations is the closed list of the center-defined operations: the operator grant (AF-CTR-03 B) and the mobile
// authorization (AF-CTR-04 part M; evidence on an approval only, never on a denial, as fleet.approveNodeSignIn; audited in the
// decision's transaction; a restricted account may approve, because the approval signs the account in on its phone).
func CenterOperations() []CenterOperation {
	return []CenterOperation{
		{ID: OperatorGrantClass, Risk: "R4", StepUp: Evidence, Target: TargetRequest, Receipt: true, Audit: AuditInTransaction},
		{ID: MobileAuthorizationClass, Risk: "R3", StepUp: EvidenceOnApprove, Target: TargetFlow, Restricted: true, Audit: AuditInTransaction},
	}
}

// CenterOperationOf is the center-defined operation of an ID.
func CenterOperationOf(id string) (CenterOperation, bool) {
	for _, operation := range CenterOperations() {
		if operation.ID == id {
			return operation, true
		}
	}
	return CenterOperation{}, false
}

// NeedsEvidenceToDecide reports whether a decision of a center-defined operation (an approval, or a denial) needs step-up evidence:
// every decision of an Evidence operation, only an approval of an EvidenceOnApprove operation.
func (o CenterOperation) NeedsEvidenceToDecide(approve bool) bool {
	return o.StepUp == Evidence || o.StepUp == EvidenceOnApprove && approve
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

// NeedsEvidenceToDecide reports whether a decision (an approval, or a denial) needs step-up evidence: every decision of an Evidence
// row, only an approval of an EvidenceOnApprove row.
func (o Operation) NeedsEvidenceToDecide(approve bool) bool {
	return o.StepUp == Evidence || o.StepUp == EvidenceOnApprove && approve
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

// Check compares the table with the served methods of the identity and fleet surfaces: every served method has exactly one row whose
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
// a caller; a Feature is a gated key, is the key of the row's group in the routed task control table (feature.OperationKeys; a row
// without a Feature names no group), is audited before the call and belongs to a session operation; an R3 or higher row is audited;
// an agent operation names only the agent scopes and is no mobile.limited or step-up row, because those rules are about a person's
// session (a restricted account's node may still reach an agent row marked Restricted, such as its own sign-out).
func CheckRow(operation Operation) error {
	inconsistent := func(why string) error {
		return fmt.Errorf("the operation row of %s is inconsistent: %s", operation.Path, why)
	}
	switch {
	case (operation.StepUp != NoEvidence) != (operation.Target != ""):
		return inconsistent("evidence and its target go together")
	case !operation.Session && (operation.StepUp != NoEvidence || operation.Receipt || operation.MobileLimited != Allowed || operation.Restricted ||
		len(operation.Scopes) > 0 || operation.Object != "" || operation.Audit != NoAudit):
		// A gated row is audited before the call, so it is caught here as well.
		return inconsistent("an anonymous row needs no caller")
	case operation.Feature != "" && !feature.IsGated(operation.Feature):
		return inconsistent("the feature is not a gated key")
	case operation.Feature == "" && operation.Group != "":
		return inconsistent("only a gated row names a group of the routed task control table")
	case operation.Feature != "" && !keyOfGroup(operation.Group, operation.Feature):
		return inconsistent("a gated row carries the key of its group in the routed task control table (feature.OperationKeys)")
	case operation.Feature != "" && operation.Restricted:
		return inconsistent("a gated operation is no security operation a restricted account may reach")
	case operation.Feature != "" && operation.Audit != AuditBeforeCall:
		return inconsistent("a gated row is audited before the call")
	case operation.Audit == AuditBeforeCall && operation.Feature == "" && operation.Risk != "R3" && operation.Risk != "R4":
		return inconsistent("only a gated or high-risk row is audited before the call")
	case (operation.Risk == "R3" || operation.Risk == "R4") && operation.Audit == NoAudit:
		return inconsistent("a high-risk row is audited")
	case len(operation.Scopes) > 0 && (operation.MobileLimited != Allowed || operation.StepUp != NoEvidence):
		return inconsistent("an agent row follows no person's session rule")
	}
	if len(operation.RelayedScopes) > 0 {
		if err := checkRelayed(operation, inconsistent); err != nil {
			return err
		}
	}
	seen := map[string]bool{}
	for _, scope := range operation.Scopes {
		if principal, known := PrincipalOf(scope); !known || principal != Agent || seen[scope] {
			return inconsistent("an agent row names each agent scope it admits once (node, automation)")
		}
		seen[scope] = true
	}
	return nil
}

// checkRelayed is CheckRow's rule of a row that admits a node-relayed caller (AF-CTR-05 E2a; Plan CTR5-SUR-03, PB-1 item 2): it is a
// person's session row (no Scopes of its own), one of RelayedOperations, never a security operation a restricted account may reach,
// gated or R1 (so a relayed caller reaches nothing above R1 that the gate does not stand in front of), addressing a node or nothing,
// and its RelayedScopes name node, once. Its MobileLimited and StepUp rules are its account-session half's (Authorize applies them to
// a person's session only).
func checkRelayed(operation Operation, inconsistent func(string) error) error {
	switch {
	case len(operation.Scopes) > 0 || !operation.Session:
		return inconsistent("a relayed row is a person's session row")
	case !slices.Contains(RelayedOperations(), operation.ID):
		return inconsistent("only the node registry's reads and the routed task methods admit a node-relayed caller")
	case operation.Restricted:
		return inconsistent("a relayed row is no security operation a restricted account may reach")
	case operation.Feature == "" && operation.Risk != "R1":
		return inconsistent("a relayed row is gated or R1")
	case operation.Object != "" && operation.Object != ObjectNode:
		return inconsistent("a relayed row addresses a node or nothing")
	case len(operation.RelayedScopes) != 1 || operation.RelayedScopes[0] != "node":
		return inconsistent("a relayed row admits the node scope once, and nothing else")
	}
	return nil
}

// keyOfGroup reports whether a key is the key the routed task control table names for a group (AF-CTR-05 E0, CTR5-GATE-06): the
// link between the operation table and feature.OperationKeys.
func keyOfGroup(group feature.Group, key feature.Key) bool {
	want, named := feature.KeyOfGroup(group)
	return named && want == key
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
	if len(o.Scopes) > 0 {
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

// Control is a resource control (DC-07; AF-CTR-05 E0, CTR5-GATE-05): a per-account bound that stands in front of the rows it
// covers. Authorize runs the controls that cover a row after the call's scope and principal are decided and before the audit and the
// gate, so a call that exhausted a resource is refused before it reaches either, and writes no access.authorized row.
type Control interface {
	// Name is the control's policy key: a closed value (a metric label and the limit name of its refusal), never request text.
	Name() string
	// Covers reports whether the control stands in front of an operation row.
	Covers(operation Operation) bool
	// Admit decides one call of a covered row: nil admits it, a refusal (an *arc.Refusal, for example a rate limit) or a store
	// failure stops it. A control that holds a resource for the call's duration releases it with call.AfterCall.
	Admit(ctx context.Context, call *ingress.Call, operation Operation) error
}

// ControlFunc is a Control made of its parts (tests and small compositions).
type ControlFunc struct {
	Key   string
	Rows  func(Operation) bool
	Check func(ctx context.Context, call *ingress.Call, operation Operation) error
}

// Name is the control's policy key.
func (c ControlFunc) Name() string { return c.Key }

// Covers asks Rows; a ControlFunc without Rows covers every row.
func (c ControlFunc) Covers(operation Operation) bool { return c.Rows == nil || c.Rows(operation) }

// Admit asks Check; a ControlFunc without Check admits.
func (c ControlFunc) Admit(ctx context.Context, call *ingress.Call, operation Operation) error {
	if c.Check == nil {
		return nil
	}
	return c.Check(ctx, call, operation)
}

// CheckControls is the composition rule of the resource controls (CTR5-GATE-05): every gated row of the table has at least one
// registered control in front of it, and every control has a name. A gated row without a control fails the composition, so no
// gated call is ever served unbounded.
func CheckControls(table []Operation, controls []Control) error {
	for _, control := range controls {
		if control == nil || control.Name() == "" {
			return errors.New("a resource control has no name")
		}
	}
	for _, operation := range table {
		if operation.Feature == "" {
			continue
		}
		covered := false
		for _, control := range controls {
			covered = covered || control.Covers(operation)
		}
		if !covered {
			return fmt.Errorf("the gated row %s has no resource control in front of it", operation.Path)
		}
	}
	return nil
}

// Authorizer decides a session call and audits its refusals.
type Authorizer struct {
	db       *store.DB
	clock    func() time.Time
	gate     feature.Gate
	controls []Control
	relays   RelayVerifier
	lookup   func(path string) (Operation, bool)
}

// Option configures an Authorizer.
type Option func(*Authorizer)

// WithGate sets the feature gate that decides the operations with a Feature. Without one a gated operation is refused as if its
// feature were unavailable (fail closed).
func WithGate(gate feature.Gate) Option { return func(a *Authorizer) { a.gate = gate } }

// Gate is the feature gate the authorizer asks, or nil.
func (a *Authorizer) Gate() feature.Gate { return a.gate }

// WithControls sets the resource controls Authorize runs, in order, before the audit and the gate: each one for the rows it covers.
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

// CheckComposition is CheckControls over the served operation table and the authorizer's controls: the composition of a center
// refuses to start when a gated row has no control in front of it.
func (a *Authorizer) CheckComposition() error { return CheckControls(Operations(), a.controls) }

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
	operation, _, err := a.AuthorizeRelayed(ctx, call, subject, nil)
	return operation, err
}

// RelayClaim is what a routed request states about its node relay, for the relay assertion's verification (AF-CTR-05; Plan addendum
// D0-B1, C-N1, C-N6): the relay_assertion bytes as received, the routed method, the request digest (Contracts relay.proto
// RelayAssertion request_sha256), the target node (nil for ListNodes), the command (nil for a read), and the relaying node and local
// origin its caller field names.
type RelayClaim struct {
	Assertion            []byte
	Method               relayv1.RoutedMethod
	RequestSHA256        []byte
	TargetNodeID         *platform.ID
	CommandID            *platform.ID
	CallerRelayingNodeID platform.ID
	CallerLocalOrigin    nodev1.Origin
}

// Relay is a verified relay as the verifier returns it (hub.VerifiedRelay, by value): Authorize checks that it is verified and that it
// was verified for the bearer credential's installation, and hands it back to the handler, which routes with it (part E2b).
type Relay interface {
	// Verified reports whether the relay assertion was verified.
	Verified() bool
	// RelayingInstallationID is the relaying node's installation the assertion was verified for.
	RelayingInstallationID() platform.ID
}

// RelayVerifier verifies the relay assertion of a node-relayed call for its bearer credential (hub.Hub.RelayVerifier); its error is
// the refusal (an *arc.Refusal) or a store failure.
type RelayVerifier func(ctx context.Context, credential ingress.Caller, claim RelayClaim) (Relay, error)

// WithRelayVerifier sets the verifier of node-relayed calls. Without one a node credential reaches no relayed row (fail closed).
func WithRelayVerifier(verifier RelayVerifier) Option {
	return func(a *Authorizer) { a.relays = verifier }
}

// AuthorizeRelayed is AuthorizeSubject for a call that may be node-relayed: claim is what the request states about its relay (its
// routed caller and relay assertion), or nil when it states none. A node credential reaches a row that lists its scope in RelayedScopes
// only through the authorizer's own verification of the claim (stage 1b, decisions B-4): the verifier must answer a relay that is
// verified, for the bearer credential's installation; otherwise the call is refused AUTHENTICATION/unauthenticated with the
// relay_assertion reason (missing when the request states none), before anything is read or written, so a bearer token alone reaches
// nothing (C-N6). A person's session whose request states a relay is refused as the wrong principal (audited; Plan CTR5-SUR-03). The
// verified relay is returned for a relayed call, nil otherwise.
func (a *Authorizer) AuthorizeRelayed(ctx context.Context, call *ingress.Call, subject *Subject, claim *RelayClaim) (Operation, Relay, error) {
	operation, ok := a.lookup(call.Policy.FullName)
	if !ok {
		return Operation{}, nil, arc.PermissionDenied("unknown")
	}
	if !operation.Session {
		return operation, nil, nil
	}
	caller := call.Caller
	// 1. Authentication.
	if !caller.IsAuthenticated() {
		return operation, nil, arc.Unauthenticated()
	}
	// 1b. A node-relayed caller is authenticated by its relay assertion as well, verified here (C-N6): a bearer token alone reaches
	// nothing, and nothing is read or written for a refused assertion but the credential's own node and key.
	var relay Relay
	relayed := slices.Contains(operation.RelayedScopes, caller.Scope)
	if relayed {
		var err error
		if relay, err = a.verifyRelay(ctx, caller, claim); err != nil {
			return operation, nil, err
		}
	}
	// 2. Ownership of the addressed object. A subject for a row that names no Object is a handler that decided ownership by itself:
	// refused, because nothing here would check it.
	if operation.Object != "" || subject != nil {
		if err := a.owned(ctx, call, operation, subject); err != nil {
			return operation, nil, err
		}
	}
	// 3. Scope and risk.
	principal, known := PrincipalOf(caller.Scope)
	switch {
	case !known:
		return operation, nil, a.refuse(ctx, call, operation, "scope")
	case caller.AccountState == restrictedState && !operation.Restricted:
		return operation, nil, a.refuse(ctx, call, operation, "restricted")
	case operation.MobileLimited == Upgrade && operation.NeedsUpgrade(caller, false):
		return operation, nil, arc.StepUpRequired()
	}
	// 4. AGENT/HUMAN separation, and the exact scopes of an AGENT row. A verified node relay of a relayed row is the one AGENT caller
	// a person's row admits; a person's session that names a relay is the wrong principal.
	if principal != operation.principal() && !relayed || principal == Human && claim != nil {
		return operation, nil, a.refuse(ctx, call, operation, "principal")
	}
	if principal == Agent && !relayed && !slices.Contains(operation.Scopes, caller.Scope) {
		return operation, nil, a.refuse(ctx, call, operation, "scope")
	}
	// 5. Resource controls: every control that covers the row, before the audit and the gate.
	for _, control := range a.controls {
		if !control.Covers(operation) {
			continue
		}
		if err := control.Admit(ctx, call, operation); err != nil {
			return operation, nil, err
		}
	}
	// 6. The audit that comes before the call; a failed append refuses it.
	if operation.Audit == AuditBeforeCall {
		if err := a.audit(ctx, call, operation, AuditAuthorized, "", map[string]any{"operation": operation.ID, "risk": operation.Risk, "feature": string(operation.Feature),
			"scope": caller.Scope}); err != nil {
			return operation, nil, err
		}
	}
	// 7. The gate.
	if operation.Feature != "" {
		if err := a.gated(ctx, call, operation); err != nil {
			return operation, nil, err
		}
	}
	return operation, relay, nil
}

// verifyRelay is stage 1b (decisions B-4: the authorizer verifies, no handler hands it a verdict): the composed verifier checks the
// claim's relay assertion for the bearer credential (a request that states no claim is checked as one without an assertion, so it is
// refused missing), and the relay it answers must be verified and verified for the credential's own installation. Without a verifier
// every relayed call is refused (fail closed).
func (a *Authorizer) verifyRelay(ctx context.Context, caller ingress.Caller, claim *RelayClaim) (Relay, error) {
	if a.relays == nil {
		return nil, arc.RelayAssertionRefused(arc.RelayMissing)
	}
	stated := RelayClaim{}
	if claim != nil {
		stated = *claim
	}
	relay, err := a.relays(ctx, caller, stated)
	switch {
	case err != nil:
		return nil, err
	case relay == nil || !relay.Verified():
		return nil, arc.RelayAssertionRefused(arc.RelaySignatureInvalid)
	}
	installation := relay.RelayingInstallationID()
	if raw := correlation.IDBytes(caller.InstallationID); len(raw) != len(installation) || string(raw) != string(installation[:]) {
		return nil, arc.RelayAssertionRefused(arc.RelayCredentialMismatch)
	}
	return relay, nil
}

// The audit events Authorize appends.
const (
	// AuditRefused is a refusal of scope, principal or account state.
	AuditRefused = "access.refused"
	// AuditAuthorized is the audit that comes before a gated or high-risk call.
	AuditAuthorized = "access.authorized"
	// AuditGated is a gated call the gate refused; its reason is the gate's.
	AuditGated = "access.gated"
	// AuditGateFailure is a gated call the gate could not decide (RESOURCE/overloaded); its reason is one of the closed gate failure
	// reasons, and it carries no request text. The plan names it access.gateFailure; the audit store admits lower-case event types only
	// (audit_event_event_type), so it is written access.gate_failure.
	AuditGateFailure = "access.gate_failure"
)

// The closed reasons of access.gate_failure (AF-CTR-05 E0, CTR5-GATE-03).
const (
	// GateFailureCommitUnknown: the snapshot's refresh committed without an answer.
	GateFailureCommitUnknown = "commit_unknown"
	// GateFailureRefreshContended: the snapshot's refresh lost the race for the account's revision on every attempt.
	GateFailureRefreshContended = "refresh_contended"
	// GateFailureNoEntitlementStore: a hosted center with a valid catalogue has no entitlement store.
	GateFailureNoEntitlementStore = "no_entitlement_store"
	// GateFailureDefinitionsSuperseded: the replica's definitions version is not the deploy's current one and the snapshot needs a
	// recompute the replica may not do (store-1, entitlement.ErrDefinitionsSuperseded).
	GateFailureDefinitionsSuperseded = "definitions_superseded"
)

// GateFailureReasons is every reason of access.gate_failure.
func GateFailureReasons() []string {
	return []string{GateFailureCommitUnknown, GateFailureRefreshContended, GateFailureNoEntitlementStore, GateFailureDefinitionsSuperseded}
}

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
		failure := gateFailure(decision.Err)
		var undecided *GateFailure
		if !errors.As(failure, &undecided) {
			return failure
		}
		// The failure is audited with its closed reason and no request text; the answer stays RESOURCE/overloaded even when the
		// audit cannot be appended (its error joins the cause, which the failure path logs).
		if err := a.audit(ctx, call, operation, AuditGateFailure, undecided.Reason, map[string]any{"operation": operation.ID,
			"feature": string(operation.Feature), "reason": undecided.Reason}); err != nil {
			undecided.cause = errors.Join(undecided.cause, err)
		}
		return undecided
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
	// The actor is the credential's: a node credential acts as its installation (node:<installation>, as every fleet event names it),
	// any other as its account (SEC-6).
	actor := "account:" + call.Caller.UserID
	if call.Caller.Scope == "node" && call.Caller.InstallationID != "" {
		actor = "node:" + call.Caller.InstallationID
	}
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
		_, err := platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: a.clock(), ActorRef: actor,
			EventType: eventType, Reason: reason, CorrelationID: correlationID, TargetKind: "operation", TargetID: operation.ID, Payload: payload})
		return err
	})
}

// GateFailure is the answer to a gate that could not decide (AF-CTR-05 E0, CTR5-GATE-03): RESOURCE/overloaded wrapped around its cause,
// as fmt.Errorf("%w: %w", arc.Unavailable(), cause) would, with the closed reason of its access.gate_failure row. errors.As finds the
// refusal (the reply), errors.Is the cause (the log line).
type GateFailure struct {
	// Reason is one of GateFailureReasons.
	Reason  string
	refusal *arc.Refusal
	cause   error
}

func (f *GateFailure) Error() string { return f.refusal.Error() + ": " + f.cause.Error() }

// Unwrap is the refusal and the cause.
func (f *GateFailure) Unwrap() []error { return []error{f.refusal, f.cause} }

// Cause is the error the gate could not decide on.
func (f *GateFailure) Cause() error { return f.cause }

// gateFailureReason is the closed reason of a cause a gate could not decide on, and false for any other error.
func gateFailureReason(err error) (string, bool) {
	var refusal *entitlement.Refusal
	switch {
	case errors.Is(err, entitlement.ErrDefinitionsSuperseded):
		return GateFailureDefinitionsSuperseded, true
	case errors.Is(err, feature.ErrNoEntitlementStore):
		return GateFailureNoEntitlementStore, true
	case errors.Is(err, store.ErrCommitUnknown), errors.As(err, &refusal) && refusal.Kind == entitlement.RefusedOutcomeUnknown:
		return GateFailureCommitUnknown, true
	case errors.As(err, &refusal) && refusal.Kind == entitlement.RefusedConcurrentUpdate:
		return GateFailureRefreshContended, true
	}
	return "", false
}

// gateFailure is the answer to a gate that could not decide. The gate runs before the handler, so a failure of the snapshot's own
// refresh did not touch the call's effect: a commit whose outcome is unknown, a refresh that lost its race on every attempt, a center
// without an entitlement store and a replica whose definitions are superseded are an unavailable store (a *GateFailure:
// RESOURCE/overloaded, the call did not happen, retry later). A store failure keeps its own classification (the transport maps it)
// and anything else, a defect of the history or of the code, stays what it is and is answered INTERNAL/internal.
func gateFailure(err error) error {
	if reason, ok := gateFailureReason(err); ok {
		return &GateFailure{Reason: reason, refusal: arc.Unavailable(), cause: err}
	}
	return err
}

// NewGateFailure is the gate failure of a cause the gate could not decide on, and false for any other error (a store failure keeps its
// own classification): the answer a gate that cannot decide gives, for the failure paths' tests and for a handler that asks the gate
// itself.
func NewGateFailure(cause error) (*GateFailure, bool) {
	failure, ok := gateFailure(cause).(*GateFailure)
	return failure, ok
}

// Controls are the resource controls the authorizer runs, in order.
func (a *Authorizer) Controls() []Control { return append([]Control(nil), a.controls...) }

// LogGateFailure writes the log line of a gate failure, with the method and the correlation ID, and reports whether err was one. The
// failure paths of the surfaces (identityapi, fleetapi, the pages) call it, so an operator can tell a gate that could not decide from
// load. The line names the closed reason and the cause, which is a store or entitlement error that carries no request text.
func LogGateFailure(ctx context.Context, logger *slog.Logger, method, correlationID string, err error) bool {
	var failure *GateFailure
	if logger == nil || !errors.As(err, &failure) {
		return false
	}
	logger.WarnContext(ctx, "the feature gate could not decide", "method", method, "correlationId", correlationID, "reason", failure.Reason,
		"error", failure.cause.Error())
	return true
}
