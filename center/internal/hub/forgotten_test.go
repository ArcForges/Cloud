// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The forgotten late calls (AF-CTR-05 E2a; E1b review A C-N2; EVIDENCE: REAL code, the vendored signed result vector, no store or
// socket): a delivered call no longer waited for is late until its expires_at plus the node's skew; then it no longer holds a slot of
// the node's bound and its call ID is forgotten, so the node's very late result is verified and dropped, never taken for a violation.

// TestAResultForAForgottenCallIsDroppedWithoutAViolation: the late call of the vector's call ID holds the node's one slot until it can
// no longer run; a call added after that is admitted (the slot is free) and the ID is forgotten; the vector's result, signed by the node
// key, is then dropped (the reader goes on, counted "forgotten"), and only once: the ID leaves the list.
func TestAResultForAForgottenCallIsDroppedWithoutAViolation(t *testing.T) {
	vectors := loadVectors(t)
	decoded, err := RelayCodec{}.Decode(vectors.RoutedResult.Frame)
	if err != nil {
		t.Fatal(err)
	}
	frame := decoded.result
	h := New(Options{Settings: Settings{MaxInFlightCalls: 1, MaxInFlightPerCenter: 8}})
	c := &conn{hub: h, publicKey: vectors.Keys["node"].SPKI, calls: map[platform.ID]*pending{}}
	now := time.Now()
	late := &pending{callID: frame.CallID, method: MethodSubmitNodeTask, expires: now, done: make(chan outcome, 1)}
	late.state.Store(callDelivered)
	if c.addCall(late, now) != registered {
		t.Fatal("the first call")
	}
	c.dropCall(late, true)
	if len(c.late) != 1 || len(c.forgotten) != 0 {
		t.Fatalf("a delivered call past its deadline is late: %d late, %d forgotten", len(c.late), len(c.forgotten))
	}
	if c.addCall(&pending{callID: platform.NewID()}, now.Add(nodeSkew-time.Second)) != registerFull {
		t.Fatal("a late call that may still run at the node holds its slot")
	}
	next := &pending{callID: platform.NewID()}
	if c.addCall(next, now.Add(nodeSkew+time.Second)) != registered {
		t.Fatal("a late call that can no longer run holds no slot")
	}
	if len(c.late) != 0 || len(c.forgotten) != 1 || c.forgotten[0] != frame.CallID {
		t.Fatalf("the pruned call is forgotten: %d late, %v", len(c.late), c.forgotten)
	}
	if !c.result(frame) {
		t.Fatal("a verified result for a forgotten call ended the reader")
	}
	if h.metrics.ChannelCount("call", "forgotten") != 1 {
		t.Fatal("the dropped result is not counted")
	}
	if p, lateCall, forgotten := c.take(frame.CallID); p != nil || lateCall != nil || forgotten {
		t.Fatal("a forgotten call ID answers once")
	}
}

// TestTheForgottenCallsAreBounded: a late call pushed out of the full late list is forgotten too, and the forgotten list keeps the
// lateResults newest IDs, the oldest dropped first.
func TestTheForgottenCallsAreBounded(t *testing.T) {
	h := New(Options{Settings: Settings{MaxInFlightCalls: 1 << 20, MaxInFlightPerCenter: 8}})
	c := &conn{hub: h, calls: map[platform.ID]*pending{}}
	now := time.Now()
	var ids []platform.ID
	for range lateResults + 1 {
		p := &pending{callID: platform.NewID(), expires: now.Add(time.Hour)}
		p.state.Store(callDelivered)
		c.calls[p.callID] = p
		c.dropCall(p, true)
		ids = append(ids, p.callID)
	}
	if len(c.late) != lateResults || len(c.forgotten) != 1 || c.forgotten[0] != ids[0] {
		t.Fatalf("the oldest late call is forgotten when the list is full: %d late, %d forgotten", len(c.late), len(c.forgotten))
	}
	for range lateResults {
		c.forgetLocked(platform.NewID())
	}
	if len(c.forgotten) != lateResults || c.forgotten[0] == ids[0] {
		t.Fatalf("the forgotten list keeps %d IDs, the oldest dropped first: %d", lateResults, len(c.forgotten))
	}
	if _, _, forgotten := c.take(ids[0]); forgotten {
		t.Fatal("an ID dropped from the forgotten list is still forgotten")
	}
}
