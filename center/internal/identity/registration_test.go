// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"testing"

	"github.com/ArcForges/Cloud/center/internal/store"
)

// TestTheRunningGraceCoversTheSuccessTransactionAndNoMore (A-1): a registration completion that took its attempt before the flow's
// expiry commits at most store.DefaultTimeout (the bound of its success transaction) later, so a duplicate is told the store is busy
// for at least that long; an attempt that is never settled turns STATE/expired after at most twice that, so the busy answer does not
// outlast a retry loop.
func TestTheRunningGraceCoversTheSuccessTransactionAndNoMore(t *testing.T) {
	if RunningGrace <= store.DefaultTimeout || RunningGrace > 2*store.DefaultTimeout {
		t.Fatalf("RunningGrace %s against the success transaction's bound %s", RunningGrace, store.DefaultTimeout)
	}
}
