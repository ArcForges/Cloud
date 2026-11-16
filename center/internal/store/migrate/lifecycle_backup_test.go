// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"strings"
	"testing"
)

func TestLifecycleFunctionACLRequiresTheCompleteClosedSignature(t *testing.T) {
	const signature = "finish_account_deletion(p_operation_id uuid, p_now timestamp with time zone)"
	objects := map[string]int{"FUNCTION identity " + signature: 1, "FUNCTION identity guard_lifecycle_operation()": 1}
	// Object values become zero after their TOC entry is consumed. Membership,
	// not its traversal order, determines whether an ACL is in the closure.
	objects["FUNCTION identity guard_lifecycle_operation()"] = 0
	for _, item := range []string{
		"identity FUNCTION " + signature,
		"identity FUNCTION guard_lifecycle_operation()",
	} {
		if !ctr06SupportedACL(strings.Fields(item), objects) {
			t.Fatal("the known native function ACL was refused")
		}
	}
	for _, item := range []string{
		"identity FUNCTION finish_account_deletion()",
		"identity FUNCTION finish_account_deletion(p_operation_id text, p_now timestamp with time zone)",
		"identity FUNCTION " + signature + " extra",
		"other FUNCTION " + signature,
		"identity PROCEDURE " + signature,
	} {
		if ctr06SupportedACL(strings.Fields(item), objects) {
			t.Fatal("an unreviewed function signature or object type entered the backup closure")
		}
	}
}
