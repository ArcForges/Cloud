// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"sync"

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
