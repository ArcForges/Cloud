// SPDX-License-Identifier: AGPL-3.0-only

package migrate

import (
	"strings"
	"testing"
)

func TestLifecycleNativeFunctionTOCPreservesClosedIdentity(t *testing.T) {
	// Native H-22 PostgreSQL18.7 ca7c836f labels; only the ephemeral owner
	// name is replaced. This runs the complete TOC admission, not just its
	// ACL helper, with the actual unnamed-object/named-ACL distinction.
	const raw = "\n;     Format: CUSTOM\n;     Dumped by pg_dump version: 18.7\n" +
		"306; 1255 17991 FUNCTION identity finish_account_deletion(uuid, timestamp with time zone) fixture_owner\n" +
		"4464; 0 0 ACL identity FUNCTION finish_account_deletion(p_operation_id uuid, p_now timestamp with time zone) fixture_owner\n"
	const inventory = "FUNCTION identity finish_account_deletion(uuid, timestamp with time zone)\n"
	if err := ctr06ArchiveInventoryFor([]byte(raw), inventory, nil); err != nil {
		t.Fatalf("native parameterized function TOC was refused: %v", err)
	}
	for _, bad := range []string{
		strings.Replace(raw, "p_operation_id uuid", "p_operation_id text", 1),
		strings.Replace(raw, "p_operation_id uuid", "account_id uuid", 1),
		strings.Replace(raw, "FUNCTION identity finish_account_deletion(uuid,", "FUNCTION identity finish_account_deletion(text,", 1),
	} {
		if ctr06ArchiveInventoryFor([]byte(bad), inventory, nil) == nil {
			t.Fatal("a changed native function or ACL identity entered the closed archive")
		}
	}
}

func TestLifecycleFunctionACLRequiresTheCompleteClosedSignature(t *testing.T) {
	const signature = "finish_account_deletion(uuid, timestamp with time zone)"
	const namedACL = "finish_account_deletion(p_operation_id uuid, p_now timestamp with time zone)"
	// The actual PostgreSQL18.7 H-22 TOC of ca7c836f used an unnamed
	// FUNCTION signature and this named ACL label for the same function.
	objects := map[string]int{"FUNCTION identity " + signature: 1, "FUNCTION identity guard_lifecycle_operation()": 1}
	// Object values become zero after their TOC entry is consumed. Membership,
	// not its traversal order, determines whether an ACL is in the closure.
	objects["FUNCTION identity guard_lifecycle_operation()"] = 0
	for _, item := range []string{
		"identity FUNCTION " + signature,
		"identity FUNCTION " + namedACL,
		"identity FUNCTION guard_lifecycle_operation()",
	} {
		if !ctr06SupportedACL(strings.Fields(item), objects) {
			t.Fatal("the known native function ACL was refused")
		}
	}
	for _, item := range []string{
		"identity FUNCTION finish_account_deletion()",
		"identity FUNCTION finish_account_deletion(p_operation_id text, p_now timestamp with time zone)",
		"identity FUNCTION finish_account_deletion(account_id uuid, p_now timestamp with time zone)",
		"identity FUNCTION " + signature + " extra",
		"other FUNCTION " + signature,
		"identity PROCEDURE " + signature,
	} {
		if ctr06SupportedACL(strings.Fields(item), objects) {
			t.Fatal("an unreviewed function signature or object type entered the backup closure")
		}
	}
	delete(objects, "FUNCTION identity "+signature)
	if ctr06SupportedACL(strings.Fields("identity FUNCTION "+namedACL), objects) {
		t.Fatal("the named ACL label supplied an authority absent from the closed object inventory")
	}
}
