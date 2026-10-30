// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"fmt"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

func identityPolicies(t *testing.T) []ingress.Policy {
	t.Helper()
	module, err := routes.Identity()
	if err != nil {
		t.Fatal(err)
	}
	return module.Policies
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
	}
	mobile := map[MobileLimited]string{Allowed: "allowed", Upgrade: "upgrade", UpgradeUnlessOwn: "upgrade-unless-own"}
	evidence := map[StepUp]string{NoEvidence: "none", Evidence: "evidence", EvidenceUnlessOwn: "evidence-unless-own"}
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
		"identity.revokeSession": TargetSession, "identity.revokeAllSessions": TargetAccount, "device.revoke": TargetDevice, UpgradeClass: TargetSession}
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
