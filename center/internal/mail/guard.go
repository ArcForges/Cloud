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
// wait for a slot. Send stays synchronous (the caller's goroutine waits), so a delivery needs no durable queue, outbox or table;
// the wait is in memory and a process stop loses it, like an in-flight send.
//
// A send is refused (ErrUnavailable, stage "busy") when MaxInFlight+MaxWaiting sends are already inside Send, and when its context
// ends before a slot is free. It is not refused merely because some other sends are in flight: whether a message waits or is
// lost must not depend on whether another address has an account (a refusal at a full pool would let a caller read the lookup
// result of an address from the loss of their own mail).
//
// A message is therefore lost in two ways, and the second is cheaper for an attacker than the first looks: when more than
// MaxInFlight+MaxWaiting sends are inside Send, or when the queue cannot drain inside the caller's deadline. With a provider that
// needs L per send about MaxInFlight x floor(deadline / L) sends are delivered inside a deadline, so the 68 of the first way holds
// only while the provider answers in under about 1.76 s with the identity layer's 30 s deadline (about 40 sends at 3 s, about 12
// at 9.5 s); a test measures the rule in drain rounds, without a clock. A send behind a full pool is delayed by up to one provider
// latency, and the one at the back of 64 waiters by about 16 latencies; the delay, and the provider's own quota, are channels an
// attacker with a mailbox could observe, accepted and documented as residual risks.
//
// The count and the slot are released in this order: the slot first, then the count, so that the goroutines inside Send never
// exceed the capacity and a waiter that has been handed the slot is no longer counted as a waiter by the time a newcomer looks (a
// newcomer that arrives in the instructions between the two releases is over-counted by one, for nanoseconds). Waiting senders
// are served in the order the Go runtime queues them on the slot channel. A panic of the inner sender releases both and propagates
// to the caller.
type Guard struct {
	inner    Sender
	slots    chan struct{}
	inflight atomic.Int64 // every send from its admission to the end of its release
	capacity int64        // inFlight + waiting
}

// NewGuard wraps inner with the center's bounds.
func NewGuard(inner Sender) *Guard { return newGuard(inner, MaxInFlight, MaxWaiting) }

// newGuard is NewGuard with explicit bounds, for tests that need small ones.
func newGuard(inner Sender, inFlight, waiting int) *Guard {
	return &Guard{inner: inner, slots: make(chan struct{}, inFlight), capacity: int64(inFlight + waiting)}
}

// Enabled is the inner sender's.
func (g *Guard) Enabled() bool { return g.inner.Enabled() }

// busy is the refusal of a send that cannot wait any longer.
func busy(ctx context.Context) error {
	return &Error{Class: ErrUnavailable, Provider: "guard", Stage: "busy", Timeout: errors.Is(ctx.Err(), context.DeadlineExceeded)}
}

// Send waits for a slot (see Guard) and then calls the inner sender with the same context. A send whose context has ended never
// reaches the inner sender.
func (g *Guard) Send(ctx context.Context, message Message) error {
	for { // admission: exactly capacity sends are inside, the next one is refused
		n := g.inflight.Load()
		if n >= g.capacity {
			return busy(ctx)
		}
		if g.inflight.CompareAndSwap(n, n+1) {
			break
		}
	}
	held := false
	defer func() {
		if held {
			<-g.slots // the slot first ...
		}
		g.inflight.Add(-1) // ... then the count
	}()
	select {
	case g.slots <- struct{}{}:
		held = true
	default:
		select {
		case g.slots <- struct{}{}:
			held = true
		case <-ctx.Done():
			return busy(ctx)
		}
	}
	if ctx.Err() != nil {
		return busy(ctx)
	}
	return g.inner.Send(ctx, message)
}
