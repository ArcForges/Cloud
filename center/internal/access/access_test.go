// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"

	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// identityPolicies are the served methods the operation table covers: the identity surface's, the fleet surface's (AF-CTR-04) and
// the nodes surface's (AF-CTR-05 E2a).
func identityPolicies(t *testing.T) []ingress.Policy {
	t.Helper()
	module, err := routes.Identity()
	if err != nil {
		t.Fatal(err)
	}
	fleet, err := routes.Fleet()
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := routes.Nodes()
	if err != nil {
		t.Fatal(err)
	}
	// The relay surface's upgrade route (AF-CTR-05 E1a) is authorized with its row by the upgrade handler: it counts as served.
	var upgrades []ingress.Policy
	for _, row := range routes.RelayUpgradeRoutes() {
		upgrades = append(upgrades, ingress.Policy{FullName: row.Path, Kind: ingress.Unary, Authentication: ingress.Session, Surface: row.Surface})
	}
	return append(append(append(module.Policies, fleet.Policies...), nodes.Policies...), upgrades...)
}

func TestTheOperationTableIsExactlyTheServedMethods(t *testing.T) {
	policies := identityPolicies(t)
	if err := Check(policies); err != nil {
		t.Fatal(err)
	}
	if err := Check(policies[1:]); err == nil {
		t.Fatal("a row without a served method was admitted")
	}
	extra, err := ingress.NewUnary("/arcforges.publicapi.v1.IdentityService/BeginRecovery", ingress.Anonymous, ingress.NoScope, 4096, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = Check(append(policies, extra)); err == nil {
		t.Fatal("a served method without a row was admitted")
	}
	// An operation ID names one row (review A N-2): a second row on another path that reuses fleet.listNodes is refused.
	reused := append(Operations(), Operation{Path: "/arcforges.fleet.v1.FleetService/IssueRelayToken", ID: "fleet.listNodes", Risk: "R1", Session: true,
		RelayedScopes: []string{"node"}})
	reusedPolicy, err := ingress.NewUnary("/arcforges.fleet.v1.FleetService/IssueRelayToken", ingress.Session, ingress.NoScope, 4096, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = checkTable(reused, append(policies, reusedPolicy)); err == nil {
		t.Fatal("a repeated operation ID was admitted")
	}
	flipped := append([]ingress.Policy(nil), policies...)
	for index, policy := range flipped {
		if policy.Authentication == ingress.Session {
			anonymous, err := ingress.NewUnary(policy.FullName, ingress.Anonymous, ingress.NoScope, policy.MaxRequestBytes, true)
			if err != nil {
				t.Fatal(err)
			}
			flipped[index] = anonymous
			break
		}
	}
	if err = Check(flipped); err == nil {
		t.Fatal("a session method served anonymously was admitted")
	}
	if _, ok := Lookup("/arcforges.publicapi.v1.IdentityService/BeginRecovery"); ok {
		t.Fatal("an unserved method has a row")
	}
}

// TestTheOperationTableIsThePlansSectionThree pins every row to plan v2 section 3 (SEC-02, SEC-04, DC-18): its risk, its
// mobile.limited rule, its evidence class and target, whether it runs under a receipt and whether a restricted account reaches it.
// Anonymous methods are R1, open and receipt-free; a write is under a receipt exactly when con-07 names it idempotent (IW or DE).
func TestTheOperationTableIsThePlansSectionThree(t *testing.T) {
	want := map[string]string{
		"identity.beginAuthentication":         "R1 anonymous",
		"identity.completeAuthentication":      "R1 anonymous",
		"identity.requestEmailCode":            "R1 anonymous",
		"identity.redeemEmailCode":             "R1 anonymous",
		"identity.completeEnrollment":          "R1 anonymous",
		"identity.listAuthProviders":           "R1 anonymous",
		"identity.refreshSession":              "R1 anonymous",
		"identity.getProfile":                  "R1 allowed none - no-receipt active",
		"identity.listAuthIdentities":          "R1 allowed none - no-receipt restricted",
		"identity.listSessions":                "R1 allowed none - no-receipt restricted",
		"device.list":                          "R1 allowed none - no-receipt restricted",
		"identity.beginStepUp":                 "R1 allowed none - no-receipt restricted",
		"identity.completeStepUp":              "R1 allowed none - no-receipt restricted",
		"identity.updateProfile":               "R2 upgrade none - receipt active",
		"identity.beginPasskeyRegistration":    "R2 upgrade evidence account no-receipt active",
		"identity.completePasskeyRegistration": "R2 upgrade none - receipt active",
		"identity.renameAuthIdentity":          "R2 upgrade none - receipt restricted",
		"identity.removeAuthIdentity":          "R3 upgrade evidence credential receipt restricted",
		"identity.revokeSession":               "R2 upgrade-unless-own evidence-unless-own session receipt restricted",
		"identity.revokeAllSessions":           "R3 upgrade evidence account receipt restricted",
		"device.rename":                        "R1 upgrade none - receipt restricted",
		"device.revoke":                        "R3 upgrade-unless-own evidence-unless-own device receipt restricted",
		// AF-CTR-04 E1a (CTR4-DES-02 as amended by cloud-4 and Q24): the node rows.
		"fleet.refreshNodeSession": "R1 anonymous",
		"fleet.reportNodeInfo":     "R1 allowed none - receipt active node",
		"fleet.signOutNode":        "R2 allowed none - receipt restricted node",
		// AF-CTR-04 E1b (CTR4-DES-02 as amended by Q1 and Q24): the browser sign-in rows.
		"fleet.beginNodeSignIn":    "R1 anonymous",
		"fleet.getNodeSignInFlow":  "R2 upgrade none - no-receipt active",
		"fleet.approveNodeSignIn":  "R3 upgrade evidence-on-approve flow no-receipt active",
		"fleet.completeNodeSignIn": "R1 anonymous",
		// AF-CTR-04 E2 (CTR4-DES-02 as amended by Q1, Q24 and OPS-01): the device-code sign-in rows; only the decision runs under a
		// receipt (of the account).
		"fleet.startDeviceAuthorization": "R1 anonymous",
		"fleet.pollDeviceAuthorization":  "R1 anonymous",
		"fleet.lookupDeviceCode":         "R2 upgrade none - no-receipt active",
		"fleet.approveDeviceCode":        "R3 upgrade evidence-on-approve user_code receipt active",
		// AF-CTR-05 E1a (CTR5-SUR-02): the node channel, the first gated row (TestOperationRowsAreCheckedForConsistency).
		"fleet.nodeChannel": "R2 allowed none - no-receipt active node",
		// AF-CTR-05 E2a (CTR5-SUR-02 as amended by PB-1, C-N6 and Q20): the node registry; the reads also admit a node-relayed caller,
		// RenameNode and RevokeNode are a person's device management, RevokeNode with evidence bound to the node.
		"fleet.listNodes":  "R1 allowed none - no-receipt active relayed:node",
		"fleet.getNode":    "R1 allowed none - no-receipt active relayed:node",
		"fleet.renameNode": "R2 upgrade none - receipt restricted",
		"fleet.revokeNode": "R3 upgrade evidence node receipt restricted",
		// AF-CTR-05 E2b (CTR5-SUR-02 as amended by PB-1, PB-2, D0-B1, C-N6; decisions section 5): the routed task methods, each also
		// for a node-relayed caller; Submit (high) and Cancel (medium) a person's step-up rows bound to the node, the reads low.
		"fleet.submitNodeTask":     "R3 upgrade evidence node no-receipt active relayed:node",
		"fleet.getNodeTask":        "R1 allowed none - no-receipt active relayed:node",
		"fleet.listNodeTasks":      "R1 allowed none - no-receipt active relayed:node",
		"fleet.waitNodeTask":       "R1 allowed none - no-receipt active relayed:node",
		"fleet.readNodeTaskOutput": "R1 allowed none - no-receipt active relayed:node",
		"fleet.cancelNodeTask":     "R2 upgrade evidence node no-receipt active relayed:node",
		// AF-CTR-06: six mutations use routed receipts; five require method/target step-up; planning and queries are low risk.
		"fleet.readNodeFile":            "R1 allowed none - no-receipt active relayed:node",
		"fleet.writeNodeFile":           "R3 upgrade evidence node no-receipt active relayed:node",
		"fleet.editNodeFile":            "R3 upgrade evidence node no-receipt active relayed:node",
		"fleet.searchNodeFiles":         "R1 allowed none - no-receipt active relayed:node",
		"fleet.listNodeDirectory":       "R1 allowed none - no-receipt active relayed:node",
		"fleet.planNodeRemoval":         "R1 allowed none - no-receipt active relayed:node",
		"fleet.executeNodeRemoval":      "R3 upgrade evidence node no-receipt active relayed:node",
		"fleet.getNodeFileOperation":    "R1 allowed none - no-receipt active relayed:node",
		"fleet.registerNodeWorkspace":   "R3 upgrade evidence node no-receipt active relayed:node",
		"fleet.unregisterNodeWorkspace": "R3 upgrade evidence node no-receipt active relayed:node",
		"fleet.listNodeWorkspaces":      "R1 allowed none - no-receipt active relayed:node",
		"fleet.getNodeWorkspace":        "R1 allowed none - no-receipt active relayed:node",
	}
	mobile := map[MobileLimited]string{Allowed: "allowed", Upgrade: "upgrade", UpgradeUnlessOwn: "upgrade-unless-own"}
	evidence := map[StepUp]string{NoEvidence: "none", Evidence: "evidence", EvidenceUnlessOwn: "evidence-unless-own", EvidenceOnApprove: "evidence-on-approve"}
	seen := map[string]bool{}
	for _, operation := range Operations() {
		got := operation.Risk + " anonymous"
		if operation.Session {
			target, receipt, restricted := operation.Target, "no-receipt", "active"
			if target == "" {
				target = "-"
			}
			if operation.Receipt {
				receipt = "receipt"
			}
			if operation.Restricted {
				restricted = "restricted"
			}
			got = fmt.Sprintf("%s %s %s %s %s %s", operation.Risk, mobile[operation.MobileLimited], evidence[operation.StepUp], target, receipt, restricted)
			if len(operation.Scopes) > 0 {
				got += " " + strings.Join(operation.Scopes, ",")
			}
			if len(operation.RelayedScopes) > 0 {
				got += " relayed:" + strings.Join(operation.RelayedScopes, ",")
			}
		}
		if want[operation.ID] != got {
			t.Errorf("%s: %q, want %q", operation.ID, got, want[operation.ID])
		}
		seen[operation.ID] = true
	}
	if len(seen) != len(want) {
		t.Fatalf("the table has %d rows, the plan %d", len(seen), len(want))
	}
}

// TestTheStepUpClassesAreTheEvidenceRows: BeginStepUp admits exactly the classes of the rows that need evidence, each with its
// target, the center's upgrade class, whose target is the session, and the center-defined operator grant, whose target is the
// request.
func TestTheStepUpClassesAreTheEvidenceRows(t *testing.T) {
	want := map[string]string{"identity.beginPasskeyRegistration": TargetAccount, "identity.removeAuthIdentity": TargetCredential,
		"identity.revokeSession": TargetSession, "identity.revokeAllSessions": TargetAccount, "device.revoke": TargetDevice, UpgradeClass: TargetSession,
		"fleet.approveNodeSignIn": TargetFlow, "fleet.approveDeviceCode": TargetUserCode, "fleet.revokeNode": TargetNode,
		"fleet.submitNodeTask": TargetNode, "fleet.cancelNodeTask": TargetNode, "fleet.writeNodeFile": TargetNode, "fleet.editNodeFile": TargetNode, "fleet.executeNodeRemoval": TargetNode, "fleet.registerNodeWorkspace": TargetNode, "fleet.unregisterNodeWorkspace": TargetNode}
	if target, ok := StepUpClass("center.operatorGrant"); !ok || target != TargetRequest {
		t.Fatalf("the operator grant class: %q %v", target, ok)
	}
	for _, operation := range Operations() {
		target, ok := StepUpClass(operation.ID)
		if wanted, listed := want[operation.ID]; ok != listed || target != wanted {
			t.Errorf("%s: %q %v", operation.ID, target, ok)
		}
	}
	if target, ok := StepUpClass(UpgradeClass); !ok || target != TargetSession {
		t.Fatal("the upgrade class")
	}
	for _, class := range []string{"", "identity.updateProfile", "identity.getProfile", "center.operatorgrant", "center.execute", "identity.upgradesession"} {
		if _, ok := StepUpClass(class); ok {
			t.Errorf("%q is a step-up class", class)
		}
	}
}

// TestTheMobileLimitedRules (T-19): a mobile.limited caller needs the upgrade for every Upgrade row and, for an UpgradeUnlessOwn row,
// only on another target; an account caller never does. Evidence is needed on every Evidence row and, for an EvidenceUnlessOwn row,
// only on another target, whatever the scope.
func TestTheMobileLimitedRules(t *testing.T) {
	limited, account := ingress.Caller{Scope: "mobile.limited"}, ingress.Caller{Scope: "account"}
	for _, operation := range Operations() {
		for _, own := range []bool{false, true} {
			wantUpgrade := operation.MobileLimited == Upgrade || operation.MobileLimited == UpgradeUnlessOwn && !own
			if operation.NeedsUpgrade(limited, own) != wantUpgrade || operation.NeedsUpgrade(account, own) {
				t.Errorf("%s own=%v: upgrade", operation.ID, own)
			}
			wantEvidence := operation.StepUp == Evidence || operation.StepUp == EvidenceUnlessOwn && !own
			if operation.NeedsEvidence(own) != wantEvidence {
				t.Errorf("%s own=%v: evidence", operation.ID, own)
			}
		}
	}
}

// TestFleetRowsCarryNoFeature (E1-2, CTR4-DES-03): node enrollment is an account and device operation and is never gated (AD-0021
// section 13a), so no fleet row of the table carries a Feature or is audited before the call; the node rows admit the node scope
// only, and the sign-in's account rows (the review and the decision) are HUMAN rows. A gated fleet row would first need the
// prerequisites AF-CTR-05 part E0 delivered (docs/center-entitlement.md, "What waits for later tasks"): a control and its group.
func TestFleetRowsCarryNoFeature(t *testing.T) {
	rows := 0
	for _, operation := range Operations() {
		if !strings.HasPrefix(operation.ID, "fleet.") || operation.ID == "fleet.nodeChannel" || routedOperation(operation.ID) {
			// The node channel is the first gated row (AF-CTR-05 E1a): TestOperationRowsAreCheckedForConsistency pins it; the routed
			// task rows (E2b) are gated by their groups' keys, pinned by TestTheRoutedRowsAreGatedByTheirGroups.
			continue
		}
		rows++
		account := operation.ID == "fleet.getNodeSignInFlow" || operation.ID == "fleet.approveNodeSignIn" || operation.ID == "fleet.lookupDeviceCode" ||
			operation.ID == "fleet.approveDeviceCode" || strings.HasPrefix(operation.Path, "/arcforges.fleet.v1.FleetService/")
		if operation.Feature != "" || operation.Audit == AuditBeforeCall || operation.Session && !account && strings.Join(operation.Scopes, ",") != "node" ||
			account && len(operation.Scopes) != 0 {
			t.Errorf("%s: feature %q, audit %d, scopes %v", operation.ID, operation.Feature, operation.Audit, operation.Scopes)
		}
	}
	if rows == 0 {
		t.Fatal("no fleet row: the test is vacuous")
	}
}

// TestTheApprovalRowDecidesTheEvidenceOfADecision (Q1; NB-4): the ApproveNodeSignIn row needs evidence to approve and none to deny,
// and the handler asks the row: the same decision on an Evidence row needs evidence either way, on a row without evidence never.
func TestTheApprovalRowDecidesTheEvidenceOfADecision(t *testing.T) {
	row, ok := Lookup(fleetv1connect.NodeEnrollmentServiceApproveNodeSignInProcedure)
	if !ok || row.StepUp != EvidenceOnApprove || !row.NeedsEvidenceToDecide(true) || row.NeedsEvidenceToDecide(false) {
		t.Fatalf("the approval row: %+v", row)
	}
	strict, none := row, row
	strict.StepUp, none.StepUp, none.Target = Evidence, NoEvidence, ""
	if !strict.NeedsEvidenceToDecide(false) || none.NeedsEvidenceToDecide(true) {
		t.Fatal("NeedsEvidenceToDecide does not follow the row")
	}
}

// TestTheRelayedRowsFollowTheirRules (AF-CTR-05 E2a; Plan CTR5-SUR-03, PB-1 item 2; decisions N-1): the rows that admit a node-relayed
// caller are exactly the registry's reads, each a person's R1 session row with the node scope relayed; CheckRow refuses a relayed row
// that is an agent row, an anonymous row, outside RelayedOperations, a restricted account's security row, ungated above R1, addressing
// another object or admitting another or a repeated scope; it keeps a relayed row's person rules (an Upgrade and an Evidence on the
// session half are admitted), and a person's row without relayed scopes is unchanged.
func TestTheRelayedRowsFollowTheirRules(t *testing.T) {
	var relayed []string
	for _, operation := range Operations() {
		if len(operation.RelayedScopes) > 0 {
			relayed = append(relayed, operation.ID)
		}
	}
	if strings.Join(relayed, ",") != strings.Join(RelayedOperations(), ",") {
		t.Fatalf("the relayed rows: %v", relayed)
	}
	row, ok := Lookup(fleetv1connect.FleetServiceGetNodeProcedure)
	if !ok || CheckRow(row) != nil {
		t.Fatalf("the GetNode row: %+v %v", row, CheckRow(row))
	}
	gated := Operation{Path: "/arcforges.fleet.v1.FleetService/SubmitNodeTask", ID: "fleet.submitNodeTask", Risk: "R3", Session: true, RelayedScopes: []string{"node"},
		MobileLimited: Upgrade, StepUp: Evidence, Target: TargetNode, Object: ObjectNode, Feature: feature.CenterExecute, Group: feature.GroupSubmission, Audit: AuditBeforeCall}
	if err := CheckRow(gated); err != nil {
		t.Fatalf("a gated relayed row with its session half's person rules: %v", err)
	}
	for name, change := range map[string]func(*Operation){
		"an agent row":         func(o *Operation) { o.Scopes = []string{"node"} },
		"an anonymous row":     func(o *Operation) { o.Session, o.Object = false, "" },
		"another operation":    func(o *Operation) { o.ID = "fleet.renameNode" },
		"a restricted row":     func(o *Operation) { o.Restricted = true },
		"an ungated R2 row":    func(o *Operation) { o.Risk = "R2" },
		"another object":       func(o *Operation) { o.Object = "device" },
		"the automation scope": func(o *Operation) { o.RelayedScopes = []string{"automation"} },
		"the node scope twice": func(o *Operation) { o.RelayedScopes = []string{"node", "node"} },
		"two scopes":           func(o *Operation) { o.RelayedScopes = []string{"node", "automation"} },
		"a person's scope":     func(o *Operation) { o.RelayedScopes = []string{"account"} },
	} {
		changed := row
		change(&changed)
		if CheckRow(changed) == nil {
			t.Errorf("%s was admitted", name)
		}
	}
}

// routedOperation reports only the explicitly declared routed task/file/workspace rows.
func routedOperation(id string) bool {
	return slices.Contains([]string{"fleet.submitNodeTask", "fleet.getNodeTask", "fleet.listNodeTasks", "fleet.waitNodeTask", "fleet.readNodeTaskOutput",
		"fleet.cancelNodeTask", "fleet.readNodeFile", "fleet.writeNodeFile", "fleet.editNodeFile", "fleet.searchNodeFiles", "fleet.listNodeDirectory", "fleet.planNodeRemoval", "fleet.executeNodeRemoval", "fleet.getNodeFileOperation", "fleet.registerNodeWorkspace", "fleet.unregisterNodeWorkspace", "fleet.listNodeWorkspaces", "fleet.getNodeWorkspace"}, id)
}

// TestTheRoutedRowsAreGatedByTheirGroups (AF-CTR-05 E2b, E2-3; CTR5-GATE-06): each routed task row carries its group's key of the routed
// task control table (submission center.execute, status and output remote.view, control remote.control), is audited before the call,
// addresses a node and admits the node-relayed caller; the routed controls cover it.
func TestTheRoutedRowsAreGatedByTheirGroups(t *testing.T) {
	want := map[string]feature.Group{"fleet.submitNodeTask": feature.GroupSubmission, "fleet.getNodeTask": feature.GroupStatusAndOutput,
		"fleet.listNodeTasks": feature.GroupStatusAndOutput, "fleet.waitNodeTask": feature.GroupStatusAndOutput, "fleet.readNodeTaskOutput": feature.GroupStatusAndOutput,
		"fleet.cancelNodeTask": feature.GroupControl, "fleet.readNodeFile": feature.GroupSubmission, "fleet.writeNodeFile": feature.GroupSubmission, "fleet.editNodeFile": feature.GroupSubmission, "fleet.searchNodeFiles": feature.GroupSubmission, "fleet.listNodeDirectory": feature.GroupSubmission, "fleet.planNodeRemoval": feature.GroupSubmission, "fleet.executeNodeRemoval": feature.GroupSubmission, "fleet.getNodeFileOperation": feature.GroupSubmission, "fleet.registerNodeWorkspace": feature.GroupSubmission, "fleet.unregisterNodeWorkspace": feature.GroupSubmission, "fleet.listNodeWorkspaces": feature.GroupSubmission, "fleet.getNodeWorkspace": feature.GroupSubmission}
	seen := 0
	for _, operation := range Operations() {
		group, ok := want[operation.ID]
		if !ok {
			continue
		}
		seen++
		key, _ := feature.KeyOfGroup(group)
		if operation.Group != group || operation.Feature != key || operation.Audit != AuditBeforeCall || operation.Object != ObjectNode ||
			strings.Join(operation.RelayedScopes, ",") != "node" || CheckRow(operation) != nil {
			t.Errorf("%s: %+v", operation.ID, operation)
		}
	}
	if seen != len(want) {
		t.Fatalf("%d routed rows", seen)
	}
}
