// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// switchedGate answers center.nodes as a test sets it: available, lapsed, or undecidable (the entitlement store did not answer).
type switchedGate struct{ state atomic.Int32 }

const (
	gateAvailable int32 = iota
	gateLapsed
	gateUndecided
)

func (g *switchedGate) Availability(context.Context, feature.Key) feature.Decision {
	switch g.state.Load() {
	case gateLapsed:
		return feature.Decision{Reason: feature.ReasonOperatorLimit}
	case gateUndecided:
		return feature.Decision{Reason: feature.ReasonEntitlementUnavailable, Err: store.ErrUnavailable}
	}
	return feature.Decision{Available: true, Reason: feature.ReasonEntitled}
}

// TestALapsedAccountsChannelClosesAtTheNextRefresh is E1-12 (CTR5-HUB-09, Q23; mutation "lapse not closing"): the hub asks the gate
// for center.nodes at every lapse interval and at every TokenRefresh. An undecidable gate keeps the open channel until the next check;
// a lapsed entitlement closes it 4403 feature_not_entitled at the next check, audited access.gated once for the close; a TokenRefresh
// triggers the check at once ("no later than the node's next credential refresh", AD-0021 section 13a).
func TestALapsedAccountsChannelClosesAtTheNextRefresh(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) { s.LapseRecheck = 300 * time.Millisecond }})
	gate := &switchedGate{}
	h.center.Hub.SetGate(gate)
	periodic := h.enroll()
	periodicClosed := answer(h.connect(periodic))
	gate.state.Store(gateUndecided)
	if !stillOpen(periodicClosed, time.Second) {
		t.Fatal("an undecidable gate closed an open channel")
	}
	gated := h.audits("access.gated")
	gate.state.Store(gateLapsed)
	if closed := closedWithin(t, periodicClosed, 3*time.Second); closed.Code != hub.CloseRefused || closed.Reason != "feature_not_entitled" {
		t.Fatalf("the periodic check: %+v", closed)
	}
	if n := h.audits("access.gated") - gated; n != 1 {
		t.Fatalf("access.gated %d times for one close", n)
	}
	// The refresh path, with the periodic check out of the way.
	h.center.Hub.SetGate(&switchedGate{})
	slow := newHarness(t, settings{})
	slowGate := &switchedGate{}
	slow.center.Hub.SetGate(slowGate)
	refreshed := slow.enroll()
	channel := slow.connect(refreshed)
	refreshedClosed := answer(channel)
	slowGate.state.Store(gateLapsed)
	if !stillOpen(refreshedClosed, 500*time.Millisecond) {
		t.Fatal("the channel closed before a check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := channel.TokenRefresh(ctx, refreshed.access); err != nil {
		t.Fatal(err)
	}
	if closed := closedWithin(t, refreshedClosed, 3*time.Second); closed.Code != hub.CloseRefused || closed.Reason != "feature_not_entitled" {
		t.Fatalf("the refresh's check: %+v", closed)
	}
}

// TestConnectReplaceRevokeAndCloseConcurrently is E1-25 (-race): fifty rounds of connections that connect, replace each other, are
// revoked and close at once end with no connection held, no deadlock and no goroutine left behind.
func TestConnectReplaceRevokeAndCloseConcurrently(t *testing.T) {
	h := newHarness(t, settings{})
	nodes := []*enrolled{h.enroll(), h.enroll(), h.enroll(), h.enroll(), h.enroll()}
	before := runtime.NumGoroutine()
	var wg sync.WaitGroup
	for round := range 50 {
		node := nodes[round%len(nodes)]
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			channel, err := h.dial(node.access, nil)
			if err != nil {
				return
			}
			defer func() { _ = channel.WS.CloseNow() }()
			if channel.Hello(ctx, node.node, node.result.InstallationID, publicBaseURL) != nil {
				return
			}
			switch round % 3 {
			case 0:
				// A revocation notice for the node's session (re-checked: the session is live, so it stays unless replaced).
				session.Announce(ctx, session.Revocation{Sessions: nil})
				_ = channel.WS.CloseNow()
			case 1:
				_, _ = channel.Accept(ctx)
				time.Sleep(20 * time.Millisecond)
				_ = channel.WS.CloseNow()
			default:
				_, _ = channel.Accept(ctx)
			}
		}()
	}
	wg.Wait()
	stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	h.center.Hub.Stop(stop)
	if h.center.Hub.Count() != 0 {
		t.Fatalf("%d connections left", h.center.Hub.Count())
	}
	if !eventually(t, 10*time.Second, func() bool { return runtime.NumGoroutine() <= before+5 }) {
		t.Fatalf("goroutines: %d before, %d after", before, runtime.NumGoroutine())
	}
}

// TestTheExchangeOfAChannel is the shape of the center's side of a channel (E1-26, the conformance source of N1's FakeCenter): the
// challenge first, ChannelAccepted after the proved hello with the limits in their contract ranges and the connection ID of the
// challenge, heartbeats with their seq, and a RelayClose before the WebSocket close carrying the same code.
func TestTheExchangeOfAChannel(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) {
		s.Heartbeat, s.HeartbeatDeadline, s.MaxFrameBytes = 5*time.Second, 12*time.Second, 1<<20
	}})
	node := h.enroll()
	channel, err := h.dial(node.access, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	challenge := channel.Challenge
	if err := channel.Hello(ctx, node.node, node.result.InstallationID, publicBaseURL); err != nil {
		t.Fatal(err)
	}
	accepted, err := channel.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	limits := accepted.GetLimits()
	if string(accepted.GetConnectionId().GetValue()) != string(challenge.GetConnectionId().GetValue()) || limits.GetMaxFrameBytes() != 1<<20 ||
		limits.GetMaxInFlightCalls() != 8 || limits.GetHeartbeatIntervalMs() != 5000 || limits.GetHeartbeatDeadlineMs() != 12000 || limits.GetMaxRelayNonces() != 8 {
		t.Fatalf("ChannelAccepted: %v", accepted)
	}
	frame, err := channel.Next(ctx)
	if err != nil || frame.GetHeartbeat() == nil || frame.GetHeartbeat().GetSeq() != frame.GetFrameSeq() || frame.GetFrameVersion() != 1 {
		t.Fatalf("the heartbeat: %v %v", frame, err)
	}
	if err := channel.Heartbeat(ctx, frame.GetHeartbeat().GetSeq()); err != nil {
		t.Fatal(err)
	}
	stop, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	go h.center.Hub.Stop(stop)
	closed := channel.AwaitClose(ctx, true)
	if closed.Code != hub.CloseShuttingDown || uint32(closed.Status) != closed.Code {
		t.Fatalf("the close: %+v", closed)
	}
}
