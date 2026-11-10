// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"errors"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/arc"
)

func TestCTR06ReplayConfiguredWindowsAreExclusive(t *testing.T) {
	created := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, window := range []time.Duration{23 * time.Hour, 23*time.Hour + 52*time.Minute} {
		record := &routedRow{created: created, delivered: true, digest: []byte("same")}
		accept := RoutedAccept{Digest: []byte("same"), Window: window, Now: created.Add(window - time.Nanosecond)}
		if err := refuseResend(record, accept, false); err != nil {
			t.Fatalf("%v before cutoff: %v", window, err)
		}
		accept.Now = created.Add(window)
		var refusal *arc.Refusal
		if err := refuseResend(record, accept, false); !errors.As(err, &refusal) || refusal.Code != "invalid_state" || refusal.Reason != "replay_window_passed" {
			t.Fatalf("%v at cutoff: %v", window, err)
		}
	}
}
