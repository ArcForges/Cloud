// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"sync"
	"time"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// SigningInputs is how many signing inputs the hub built (the integration tests check that a malformed message reaches none).
func SigningInputs() int64 { return signingInputs.Load() }

// StallWrites holds the writer of a node's accepted connection after it takes its next frame, until release is called: a call queued
// meanwhile is not written (the B-1 tests of the fix round).
func (h *Hub) StallWrites(nodeID platform.ID) (release func()) {
	h.mu.Lock()
	c := h.nodes[nodeID]
	h.mu.Unlock()
	gate := make(chan struct{})
	c.mu.Lock()
	c.stall = gate
	c.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			c.mu.Lock()
			c.stall = nil
			c.mu.Unlock()
			close(gate)
		})
	}
}

// CallsSent is how many call frames the hub queued (the metric "call sent").
func (h *Hub) CallsSent() uint64 { return h.metrics.ChannelCount("call", "sent") }

// StallWritesWithCallNotification coordinates a test with an actually queued
// frame without polling the host or reading process internals.
func (h *Hub) StallWritesWithCallNotification(nodeID platform.ID) (queued <-chan struct{}, release func()) {
	h.mu.Lock()
	c := h.nodes[nodeID]
	h.mu.Unlock()
	gate, notice := make(chan struct{}), make(chan struct{}, 1)
	c.mu.Lock()
	c.stall, c.queuedCall = gate, notice
	c.mu.Unlock()
	var once sync.Once
	return notice, func() {
		once.Do(func() {
			c.mu.Lock()
			c.stall, c.queuedCall = nil, nil
			c.mu.Unlock()
			close(gate)
		})
	}
}

// StallAfterDelivery coordinates the gap between the delivered transition and
// the socket write; it tests only the center's observable send fence.
func (h *Hub) StallAfterDelivery(nodeID platform.ID) (delivered <-chan time.Time, release func()) {
	h.mu.Lock()
	c := h.nodes[nodeID]
	h.mu.Unlock()
	gate, notice := make(chan struct{}), make(chan time.Time, 1)
	c.mu.Lock()
	c.afterDeliverGate, c.afterDeliverNotice = gate, notice
	c.mu.Unlock()
	var once sync.Once
	return notice, func() {
		once.Do(func() {
			c.mu.Lock()
			c.afterDeliverGate, c.afterDeliverNotice = nil, nil
			c.mu.Unlock()
			close(gate)
		})
	}
}
