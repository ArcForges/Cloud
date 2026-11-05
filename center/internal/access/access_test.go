// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"

	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// identityPolicies are the served methods the operation table covers: the identity surface's and the fleet surface's (AF-CTR-04).
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
	// The relay surface's upgrade route (AF-CTR-05 E1a) is authorized with its row by the upgrade handler: it counts as served.
	var upgrades []ingress.Policy
	for _, row := range routes.RelayUpgradeRoutes() {
		upgrades = append(upgrades, ingress.Policy{FullName: row.Path, Kind: ingress.Unary, Authentication: ingress.Session, Surface: row.Surface})
	}
	return append(append(module.Policies, fleet.Policies...), upgrades...)
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
		"fleet.approveNodeSignIn": TargetFlow, "fleet.approveDeviceCode": TargetUserCode}
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
		if !strings.HasPrefix(operation.ID, "fleet.") || operation.ID == "fleet.nodeChannel" {
			// The node channel is the first gated row (AF-CTR-05 E1a): TestOperationRowsAreCheckedForConsistency pins it.
			continue
		}
		rows++
		account := operation.ID == "fleet.getNodeSignInFlow" || operation.ID == "fleet.approveNodeSignIn" || operation.ID == "fleet.lookupDeviceCode" ||
			operation.ID == "fleet.approveDeviceCode"
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
