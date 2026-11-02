// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"context"
	"errors"
	"sync/atomic"
)

// The bounds of a Guard. They are constants of the center, not configuration.
const (
	// MaxInFlight is how many sends may talk to a provider at once.
	MaxInFlight = 4
	// MaxWaiting is how many further sends may wait for a free slot; the next one is refused at once.
	MaxWaiting = 64
)

// Guard bounds the concurrent sends of a Sender: at most MaxInFlight reach the inner sender at once, and up to MaxWaiting more
// wait for a slot. Send stays synchronous (the caller's goroutine waits), so a delivery never needs a durable queue, an outbox or
// a table; the wait is in memory and a process stop loses it, like an in-flight send.
//
// A send is refused (ErrUnavailable, stage "busy") only when MaxWaiting sends already wait, or when its context ends before a slot
// is free. It is never refused merely because other sends are in flight: whether a message waits or is lost must not depend on
// whether another address has an account (a refusal at a full pool would let a caller read the lookup result of an address from
// the loss of their own mail). Two residual channels remain and are accepted and documented: a send behind a full pool is delayed
// by up to one provider latency, which an attacker with a mailbox could observe, and the provider's own quota is shared. A loss
// needs MaxInFlight+MaxWaiting sends in flight inside one send deadline.
//
// Waiting senders are served in the order the Go runtime queues them on the slot channel. A panic of the inner sender releases the
// slot (deferred) and propagates to the caller.
type Guard struct {
	inner   Sender
	slots   chan struct{}
	waiting atomic.Int64
	maxWait int64
}

// NewGuard wraps inner with the center's bounds.
func NewGuard(inner Sender) *Guard { return newGuard(inner, MaxInFlight, MaxWaiting) }

// newGuard is NewGuard with explicit bounds, for tests that need small ones.
func newGuard(inner Sender, inFlight, waiting int) *Guard {
	return &Guard{inner: inner, slots: make(chan struct{}, inFlight), maxWait: int64(waiting)}
}

// Enabled is the inner sender's.
func (g *Guard) Enabled() bool { return g.inner.Enabled() }

// busy is the refusal of a send that cannot wait any longer.
func busy(ctx context.Context) error {
	return &Error{Class: ErrUnavailable, Provider: "guard", Stage: "busy", Timeout: errors.Is(ctx.Err(), context.DeadlineExceeded)}
}

// acquire takes a slot, waiting for one when the bound on waiters allows it.
func (g *Guard) acquire(ctx context.Context) bool {
	select {
	case g.slots <- struct{}{}:
		return true
	default:
	}
	if g.waiting.Add(1) > g.maxWait {
		g.waiting.Add(-1)
		return false
	}
	defer g.waiting.Add(-1)
	select {
	case g.slots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// Send waits for a slot (see Guard) and then calls the inner sender with the same context. A send whose context has ended never
// reaches the inner sender.
func (g *Guard) Send(ctx context.Context, message Message) error {
	if !g.acquire(ctx) {
		return busy(ctx)
	}
	defer func() { <-g.slots }()
	if ctx.Err() != nil {
		return busy(ctx)
	}
	return g.inner.Send(ctx, message)
}
