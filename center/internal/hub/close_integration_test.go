// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"slices"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"github.com/coder/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The close of a channel while a write is in flight (AF-CTR-05 E2a; EVIDENCE: REAL composed center and WebSocket server, MOCKED node).
// coder/websocket closes the whole connection when a write's context ends while the write is still in progress; the hub used to derive
// every write's context from the reader's, which ends as soon as the reader stops, so a close decided by the reader (the node's own
// RelayClose, a malformed frame) could tear the connection down before its RelayClose and the close handshake were sent. Under load that
// happened even after a write had flushed its bytes (the Linux leg's TestChannelExchangeCapture and
// TestAMalformedHelloIsRefusedBeforeAnySigningInput variants: no RelayClose, close status -1).

// TestACloseWaitsForTheWriteInFlightAndSendsItsCloseFrame: the node stops reading while the center has many large calls to write, so
// the center's writer is blocked in a write; the node then asks for a relay nonce (its answer is queued behind the calls) and sends its
// RelayClose, which the center reads at once and answers with a close. When the node reads again, it receives, in this order, the call
// frames that were written (at least the one in flight; the calls the close abandoned are skipped, so not all 64), the RelayNonce queued
// before the close, then the center's RelayClose 1000 node_closed as the last frame, then the WebSocket close 1000: the end of the
// reader neither cancels the write in flight nor loses the close frame, and nothing queued before the close comes after it.
func TestACloseWaitsForTheWriteInFlightAndSendsItsCloseFrame(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) {
		s.Heartbeat, s.HeartbeatDeadline = time.Minute, 3*time.Minute
		s.MaxInFlightCalls, s.SendQueueFrames, s.SendQueueBytes, s.WriteTimeout = 64, 128, 64<<20, 20*time.Second
	}})
	node := h.enroll()
	channel := h.connect(node)
	payload := make([]byte, hub.MaxCallPayload)
	for range 64 {
		call := sessionCall(node, hub.MethodGetNodeTask, payload)
		call.Deadline = 20 * time.Second
		h.callAsync(call)
	}
	// 64 frames of about 254 KB (16 MB) do not fit the connection's socket buffers while the node reads nothing: the writer blocks.
	if !eventually(t, 5*time.Second, func() bool { return h.center.Hub.CallsSent() == 64 }) {
		t.Fatalf("the calls were not queued: %d", h.center.Hub.CallsSent())
	}
	time.Sleep(300 * time.Millisecond)
	ctx, cancel := background()
	defer cancel()
	requestID := platform.NewID()
	if err := channel.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_RelayNonceRequest{RelayNonceRequest: &relayv1.RelayNonceRequest{
		RequestId: &foundationv1.Id{Value: requestID[:]}}}}); err != nil {
		t.Fatal(err)
	}
	if err := channel.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_Close{Close: &relayv1.RelayClose{Code: proto.Uint32(1000),
		Reason: proto.String("node_closed")}}}); err != nil {
		t.Fatal(err)
	}
	// The center reads the close and starts its own while its writer is still blocked.
	time.Sleep(300 * time.Millisecond)
	// The node reads again: every frame up to the end of the connection, in order.
	var order []string
	var closed *relayv1.RelayClose
	calls := 0
	status := websocket.StatusCode(-1)
	for {
		frame, err := channel.Next(ctx)
		if err != nil {
			status = websocket.CloseStatus(err)
			break
		}
		switch {
		case frame.GetCall() != nil:
			calls++
			if len(order) == 0 || order[len(order)-1] != "call" {
				order = append(order, "call")
			}
		case frame.GetRelayNonce() != nil:
			if !proto.Equal(frame.GetRelayNonce().GetRequestId(), &foundationv1.Id{Value: requestID[:]}) {
				t.Fatalf("a relay nonce for another request")
			}
			order = append(order, "nonce")
		case frame.GetClose() != nil:
			closed = frame.GetClose()
			order = append(order, "close")
		default:
			order = append(order, "other")
		}
	}
	if !slices.Equal(order, []string{"call", "nonce", "close"}) {
		t.Fatalf("the frames the node read (runs of calls folded): %v", order)
	}
	if calls < 1 || calls >= 64 {
		t.Fatalf("%d call frames written; want the written ones only (at least the one in flight, not the abandoned)", calls)
	}
	if closed.GetCode() != 1000 || closed.GetReason() != "node_closed" || status != 1000 {
		t.Fatalf("the node's view of the close: RelayClose %d %q, status %d", closed.GetCode(), closed.GetReason(), status)
	}
}

// TestACloseToANodeThatStopsReadingEndsWithinTheFlush: the same blocked writer, but the node never reads again. The close flush ends the
// write in flight (the writes' own context, not the write timeout), so the center ends the connection and records its close within
// seconds; a write bounded only by its 20 s timeout would hold the close, and the node's place, that long.
func TestACloseToANodeThatStopsReadingEndsWithinTheFlush(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) {
		s.Heartbeat, s.HeartbeatDeadline = time.Minute, 3*time.Minute
		s.MaxInFlightCalls, s.SendQueueFrames, s.SendQueueBytes, s.WriteTimeout = 64, 128, 64<<20, 20*time.Second
	}})
	node := h.enroll()
	channel := h.connect(node)
	payload := make([]byte, hub.MaxCallPayload)
	for range 64 {
		call := sessionCall(node, hub.MethodGetNodeTask, payload)
		call.Deadline = 20 * time.Second
		h.callAsync(call)
	}
	if !eventually(t, 5*time.Second, func() bool { return h.center.Hub.CallsSent() == 64 }) {
		t.Fatalf("the calls were not queued: %d", h.center.Hub.CallsSent())
	}
	time.Sleep(300 * time.Millisecond)
	ctx, cancel := background()
	defer cancel()
	if err := channel.Send(ctx, &relayv1.RelayFrame{Frame: &relayv1.RelayFrame_Close{Close: &relayv1.RelayClose{Code: proto.Uint32(1000),
		Reason: proto.String("node_closed")}}}); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if !eventually(t, 8*time.Second, func() bool { return h.audits("fleet.channel.closed") == 1 }) {
		t.Fatalf("the close was not recorded within 8 s of the node's close (%s)", time.Since(started))
	}
}
