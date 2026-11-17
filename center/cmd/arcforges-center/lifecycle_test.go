// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"testing"
)

func TestLifecycleCLIRefusesInvalidFlagsBeforeConfiguration(t *testing.T) {
	for _, args := range [][]string{
		{"migrate", "lifecycle"},
		{"migrate", "lifecycle", "--force"},
		{"migrate", "lifecycle", "--archive", "relative", "--metadata", "relative"},
		{"admin", "finish-account-deletion"},
		{"admin", "finish-account-deletion", "--account", "00000000-0000-4000-8000-000000000001"},
		{"admin", "finish-account-deletion", "--operation", "not-a-uuid"},
		{"admin", "finish-account-deletion", "--operation", "00000000-0000-4000-8000-000000000001", "--force"},
	} {
		var stdout, stderr bytes.Buffer
		lookup := func(string) (string, bool) {
			t.Fatal("invalid maintenance flags reached configuration")
			return "", false
		}
		if code := run(args, lookup, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 {
			t.Fatalf("invalid maintenance boundary: exit=%d", code)
		}
	}
}
