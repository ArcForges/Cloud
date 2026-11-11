// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"testing"
)

func TestCTR06HistoricalSelfHostedBridgeFixture(t *testing.T) {
	if os.Getenv("ARCFORGES_TEST_CTR06_BRIDGE_BINARY") == "" {
		t.Skip("historical fixture requires the independently verified 615.1 bridge executable")
	}
	runCTR06HistoricalFixture(t, "^TestCTR06SelfHosted(NativeBridgeUpgradeAndRollback|RejectsAdditionalTemporaryConnection|ObserveNativeBridgeBackend|RealCLIAndFailure|HardInterruptedCallFailsClosed)$")
}
