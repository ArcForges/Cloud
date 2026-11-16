// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"testing"
)

func TestManagementFlagsRefuseBeforeReadingDatabaseConfiguration(t *testing.T) {
	for _, args := range [][]string{nil, {"--force"}, {"--archive", "relative", "--metadata", "relative"}, {"--archive", "one", "--archive", "two"}} {
		var stdout, stderr bytes.Buffer
		lookup := func(string) (string, bool) { t.Fatal("invalid flags reached configuration"); return "", false }
		arguments := append([]string{"migrate", "management"}, args...)
		if code := run(arguments, lookup, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("invalid flag boundary: code=%d", code)
		}
	}
}
