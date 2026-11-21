// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"context"
	"errors"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

func TestTheAdmissionsNotFoundFollowsTheRecord(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	fence, _ := h.center.Hub.Routable()
	command := platform.NewID()
	accept := func(command platform.ID) error {
		_, err := fleet.AcceptRouted(context.Background(), h.db.Runtime, fleet.RoutedAccept{AccountID: user, NodeID: node.node.ID, CommandID: command, Method: 1,
			Caller: fleet.RoutedCaller{Kind: fleet.RoutedCallerSession, SessionID: platform.NewID(), Actor: identity.Actor(user)}, Digest: make([]byte, 32),
			RequestSHA256: make([]byte, 32), Size: 10, Fence: fence, Window: time.Hour, InFlight: func() bool { return false }, Online: func() bool { return true },
			Now: time.Now()})
		return err
	}
	if err := accept(command); err != nil {
		t.Fatal(err)
	}
	h.db.Exec("UPDATE fleet.node SET revoked_at = now(), revoke_reason = 1, rev = rev + 1 WHERE node_id = '" + node.node.ID.String() + "'")
	var refusal *arc.Refusal
	if err := accept(command); !errors.As(err, &refusal) || refusal.Code != "node_unreachable" || refusal.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
		refusal.Retry != foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND {
		t.Fatalf("a resend to the revoked node: %v", err)
	}
	if err := accept(platform.NewID()); !errors.As(err, &refusal) || refusal.Code != "not_found" {
		t.Fatalf("a new command to the revoked node: %v", err)
	}
	if got := h.record(user, command); got.Attempts != 1 || h.count("SELECT count(*) FROM fleet.routed_call") != 1 {
		t.Fatalf("a refused admission wrote: %+v", got)
	}
}
