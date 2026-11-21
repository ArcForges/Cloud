// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

func TestASupersededAttemptsAnswerChangesNothing(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	fence, _ := h.center.Hub.Routable()
	command := platform.NewID()
	accept := fleet.RoutedAccept{AccountID: user, NodeID: node.node.ID, CommandID: command, Method: 1,
		Caller: fleet.RoutedCaller{Kind: fleet.RoutedCallerSession, SessionID: platform.NewID(), Actor: identity.Actor(user)}, Digest: make([]byte, 32),
		RequestSHA256: make([]byte, 32), Size: 10, Fence: fence, Window: time.Hour, InFlight: func() bool { return false }, Online: func() bool { return true }, Now: time.Now()}
	for attempt := 1; attempt <= 2; attempt++ {
		if decision, err := fleet.AcceptRouted(context.Background(), h.db.Runtime, accept); err != nil || decision.Attempt != attempt {
			t.Fatalf("attempt %d: %+v %v", attempt, decision, err)
		}
	}
	digest := sha256.Sum256([]byte("response"))
	if _, err := fleet.SettleRouted(context.Background(), h.db.Runtime, fleet.RoutedSettle{AccountID: user, CommandID: command, Method: 1, NodeID: node.node.ID, Attempt: 1,
		Actor: identity.Actor(user), Answer: fleet.RoutedAnswer{Verified: true, Outcome: 1, ResponseSHA256: digest[:], OutcomeSHA256: digest[:], ResponseSize: 8,
			ExecutedAt: time.Now()}, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if got := h.record(user, command); got.State != fleet.RoutedAccepted || got.Attempts != 2 || got.Final {
		t.Fatalf("a superseded answer changed the record: %+v", got)
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.routed.result' AND reason = 'superseded'") != 1 {
		t.Fatal("the superseded answer is not audited")
	}
}
