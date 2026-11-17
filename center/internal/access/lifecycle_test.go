// SPDX-License-Identifier: AGPL-3.0-only

package access

import (
	"testing"

	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"
)

func TestPendingDeletionHasAnExactRPCAllowlist(t *testing.T) {
	want := map[string]bool{
		publicapiv1connect.IdentityServiceGetAccountDeletionProcedure: true,
		publicapiv1connect.IdentityServiceBeginStepUpProcedure:        true,
		publicapiv1connect.IdentityServiceCompleteStepUpProcedure:     true,
		publicapiv1connect.IdentityServiceRevokeSessionProcedure:      true,
	}
	for _, row := range Operations() {
		if pendingDeletionOperation(row.Path) != want[row.Path] {
			t.Errorf("pending deletion operation %s", row.Path)
		}
	}
	for class, target := range map[string]string{"identity.confirmAccountDeletion": TargetFlow, "identity.cancelAccountDeletion": TargetFlow, "identity.exportAccount": TargetAccount} {
		if got, ok := StepUpClass(class); !ok || got != target {
			t.Errorf("%s: %q %v", class, got, ok)
		}
	}
	for _, path := range []string{publicapiv1connect.IdentityServiceRequestAccountDeletionProcedure, publicapiv1connect.IdentityServiceCancelAccountDeletionProcedure} {
		if _, ok := Lookup(path); ok {
			t.Errorf("legacy mutation has a row: %s", path)
		}
	}
}

func TestPendingDeletionHasAnExactPageAllowlist(t *testing.T) {
	want := map[string]bool{"page.lifecycle": true, "page.signOut": true, "webBrowser.bootstrap": true,
		"webBrowser.beginStepUp": true, "webBrowser.completeStepUp": true, "webBrowser.logout": true,
		"account.deletion.cancel": true, "account.deletion.confirm": true}
	for _, row := range PageOperations() {
		if PendingDeletionPage(row.ID) != want[row.ID] {
			t.Errorf("pending page authority %s", row.ID)
		}
	}
}
