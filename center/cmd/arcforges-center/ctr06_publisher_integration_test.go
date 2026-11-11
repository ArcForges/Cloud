// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"testing"
)

func TestCTR06HistoricalProtectedPublisherFixture(t *testing.T) {
	if os.Getenv("CTR06_TEST_BRIDGE_BIN") == "" || os.Getenv("CTR06_TEST_BRIDGE_ARCHIVE") == "" || os.Getenv("CTR06_TEST_OUTPUT_DIR") == "" {
		t.Skip("historical fixture requires the independently verified bridge and isolated output")
	}
	runCTR06HistoricalFixture(t, "^TestCTR06ProtectedPublisherIntegration$")
}
