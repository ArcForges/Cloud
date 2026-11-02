// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gate is an inner sender that blocks until released and counts how many calls are inside at once (the high-water mark is what the
// guard's bound is measured by). It is MOCKED: no provider is involved.
type gate struct {
	release chan struct{}
	inside  atomic.Int64
	high    atomic.Int64
	started atomic.Int64
	calls   atomic.Int64
	result  error
	panics  bool
}

func newGate() *gate { return &gate{release: make(chan struct{})} }

func (g *gate) Enabled() bool { return true }

func (g *gate) Send(ctx context.Context, _ Message) error {
	g.calls.Add(1)
	now := g.inside.Add(1)
	defer g.inside.Add(-1)
	for {
		high := g.high.Load()
		if now <= high || g.high.CompareAndSwap(high, now) {
			break
		}
	}
	g.started.Add(1)
	if g.panics {
		panic("a panic in the inner sender")
	}
	select {
	case <-g.release:
	case <-ctx.Done():
	}
	return g.result
}

// open lets every blocked and future call through.
func (g *gate) open() { close(g.release) }

// watchdog bounds every wait of a guard test, so that a regression of a bound FAILS by name and fast instead of hanging until the
// test binary's timeout (a send that never returns, a result that never arrives).
const watchdog = 10 * time.Second

// bounded is a context that ends after the watchdog.
func bounded(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), watchdog)
	t.Cleanup(cancel)
	return ctx
}

// recv waits for a value with the watchdog.
func recv[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(watchdog):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}

// eventually waits for a condition that depends on goroutines starting; the bound is a generous upper limit, never a lower one.
func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(watchdog)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// give hands one permit to a call that is waiting for it, and fails after the watchdog if no call takes it (a send that was refused
// or lost would otherwise leave the test blocked).
func give(t *testing.T, permits chan struct{}) {
	t.Helper()
	select {
	case permits <- struct{}{}:
	case <-time.After(watchdog):
		t.Fatal("no call took a permit")
	}
}

// sendAll starts n sends and returns their results through a channel, in completion order.
func sendAll(ctx context.Context, g *Guard, n int) <-chan error {
	results := make(chan error, n)
	for range n {
		go func() { results <- g.Send(ctx, testMessage()) }()
	}
	return results
}

// sendOne is a Send in a goroutine, so that the test can bound the wait for its result.
func sendOne(ctx context.Context, g *Guard) <-chan error { return sendAll(ctx, g, 1) }

func TestGuardBoundsAreTheCentersConstants(t *testing.T) {
	g := NewGuard(Disabled{})
	if MaxInFlight != 4 || MaxWaiting != 64 || cap(g.slots) != 4 || g.capacity != 68 {
		t.Fatalf("bounds %d/%d, slots %d, capacity %d: the center's bound is 4 in flight and 64 waiting", MaxInFlight, MaxWaiting, cap(g.slots), g.capacity)
	}
	if g.Enabled() {
		t.Error("the guard of a disabled sender is enabled")
	}
	if !NewGuard(NewFake()).Enabled() {
		t.Error("the guard of an enabled sender is disabled")
	}
}

// TestGuardNeverLetsMoreThanTheBoundReachTheProvider measures the concurrency bound with the race detector's help: the high-water
// mark of calls inside the inner sender stays at 4 while 40 sends are in flight, and every send is eventually delivered.
func TestGuardNeverLetsMoreThanTheBoundReachTheProvider(t *testing.T) {
	inner := newGate()
	g := NewGuard(inner)
	results := sendAll(bounded(t), g, 40)
	eventually(t, "four calls inside", func() bool { return inner.started.Load() >= MaxInFlight })
	time.Sleep(20 * time.Millisecond) // a fifth call, if the bound leaked, would have started by now
	if started := inner.started.Load(); started != MaxInFlight {
		t.Fatalf("%d calls reached the provider while %d slots exist", started, MaxInFlight)
	}
	inner.open()
	for range 40 {
		if err := recv(t, results, "a delivery"); err != nil {
			t.Fatalf("a send failed: %v", err)
		}
	}
	if high := inner.high.Load(); high > MaxInFlight || inner.calls.Load() != 40 {
		t.Errorf("high-water mark %d, %d calls", high, inner.calls.Load())
	}
	if g.inflight.Load() != 0 || len(g.slots) != 0 {
		t.Errorf("%d sends inside, %d slots in use after every send finished", g.inflight.Load(), len(g.slots))
	}
}

// TestGuardDeliversTheSendBehindAFullPoolInsteadOfDroppingIt is the replacement of the "fifth send is refused at once" rule: whether a
// message waits or is lost must not depend on other sends being in flight.
func TestGuardDeliversTheSendBehindAFullPoolInsteadOfDroppingIt(t *testing.T) {
	inner := newGate()
	g := NewGuard(inner)
	ctx := bounded(t)
	results := sendAll(ctx, g, MaxInFlight)
	eventually(t, "a full pool", func() bool { return inner.started.Load() == MaxInFlight })
	fifth := sendOne(ctx, g)
	eventually(t, "the fifth send to wait", func() bool { return g.inflight.Load() == MaxInFlight+1 })
	select {
	case err := <-fifth:
		t.Fatalf("the fifth send returned while the pool was full: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	inner.open()
	for range MaxInFlight {
		if err := recv(t, results, "a delivery"); err != nil {
			t.Fatal(err)
		}
	}
	if err := recv(t, fifth, "the fifth delivery"); err != nil {
		t.Fatalf("the fifth send was not delivered after the release: %v", err)
	}
	if inner.calls.Load() != MaxInFlight+1 {
		t.Errorf("%d calls reached the provider", inner.calls.Load())
	}
}

// TestGuardRefusesExactlyPastTheCapacity measures the second bound at the edges 4, 5, 68 and 69: with n sends inside a probe send
// waits for n up to 67 and is accepted as the 68th, and the 69th is refused at once as unavailable at stage busy; nothing that was
// accepted is lost.
func TestGuardRefusesExactlyPastTheCapacity(t *testing.T) {
	for _, held := range []int{MaxInFlight, MaxInFlight + 1, MaxInFlight + MaxWaiting - 1} {
		inner := newGate()
		g := NewGuard(inner)
		ctx := bounded(t)
		first := sendAll(ctx, g, held)
		eventually(t, "the sends to be inside", func() bool { return g.inflight.Load() == int64(held) && inner.started.Load() == MaxInFlight })
		probe := sendOne(ctx, g) // the held+1st send: accepted, it waits (or holds a slot at 4 only if one is free: none is)
		eventually(t, "the probe to be accepted", func() bool { return g.inflight.Load() == int64(held)+1 })
		select {
		case err := <-probe:
			t.Fatalf("with %d sends inside the probe returned: %v", held, err)
		case <-time.After(20 * time.Millisecond):
		}
		inner.open()
		for range held {
			if err := recv(t, first, "a delivery"); err != nil {
				t.Fatalf("held %d: %v", held, err)
			}
		}
		if err := recv(t, probe, "the probe delivery"); err != nil {
			t.Fatalf("held %d: the probe was lost: %v", held, err)
		}
	}
	inner := newGate()
	g := NewGuard(inner)
	ctx := bounded(t)
	accepted := sendAll(ctx, g, MaxInFlight+MaxWaiting)
	eventually(t, "4 in flight and 64 waiting", func() bool {
		return inner.started.Load() == MaxInFlight && g.inflight.Load() == MaxInFlight+MaxWaiting
	})
	begun := time.Now()
	refused := sendOne(ctx, g)
	err := recv(t, refused, "the refusal")
	failure := expectFailure(t, err, ErrUnavailable, "busy", 0)
	if failure.Provider != "guard" || failure.Timeout || Outcome(err) != "unavailable" || time.Since(begun) > 2*time.Second {
		t.Errorf("past the capacity: %+v after %v", failure, time.Since(begun))
	}
	if g.inflight.Load() != MaxInFlight+MaxWaiting {
		t.Errorf("a refused send left the count at %d", g.inflight.Load())
	}
	inner.open()
	for range MaxInFlight + MaxWaiting {
		if err := recv(t, accepted, "a delivery"); err != nil {
			t.Fatalf("an accepted send was lost: %v", err)
		}
	}
	if inner.calls.Load() != MaxInFlight+MaxWaiting {
		t.Errorf("%d calls reached the provider", inner.calls.Load())
	}
}

// TestGuardAWokenWaiterIsNoLongerCounted is the deterministic regression of the over-count: when a holder finishes, the waiter it
// hands the slot to is runnable but has not run yet. With one processor the holder goes on and sends again before that waiter runs;
// that newcomer is the second send inside a guard of capacity 2 (one holder, one waiter) and must be accepted, not refused.
func TestGuardAWokenWaiterIsNoLongerCounted(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	permits := make(chan struct{})
	inner := senderFunc(func(ctx context.Context, _ Message) error {
		select {
		case <-permits:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	g := newGuard(inner, 1, 1)
	ctx := bounded(t)
	again := make(chan error, 1)
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- g.Send(ctx, testMessage()) // H1 holds the slot until it gets a permit
		again <- g.Send(ctx, testMessage())      // then, in the same goroutine, sends X
	}()
	eventually(t, "the holder to be inside", func() bool { return g.inflight.Load() == 1 && len(g.slots) == 1 })
	waiter := sendOne(ctx, g) // W1 waits behind it
	eventually(t, "the waiter to be counted", func() bool { return g.inflight.Load() == 2 })
	give(t, permits) // H1 finishes, W1 is handed the slot, H1 sends X before W1 has run
	if err := recv(t, holderDone, "the holder"); err != nil {
		t.Fatal(err)
	}
	give(t, permits)
	give(t, permits)
	if err := recv(t, waiter, "the waiter"); err != nil {
		t.Fatalf("the waiter: %v", err)
	}
	if err := recv(t, again, "the newcomer"); err != nil {
		t.Fatalf("a send was refused although only %d sends were inside a guard of capacity 2: %v", 2, err)
	}
}

// TestGuardNeverRefusesAClosedLoopOfExactlyTheCapacity is the statistical form of the same property: 68 senders that each send
// again as soon as the previous send returned never have more than 68 inside, so none is refused.
func TestGuardNeverRefusesAClosedLoopOfExactlyTheCapacity(t *testing.T) {
	inner := senderFunc(func(context.Context, Message) error { runtime.Gosched(); return nil })
	g := NewGuard(inner)
	ctx := bounded(t)
	var refused atomic.Int64
	var wait sync.WaitGroup
	for range MaxInFlight + MaxWaiting {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for range 40 {
				if err := g.Send(ctx, testMessage()); err != nil {
					refused.Add(1)
				}
			}
		}()
	}
	wait.Wait()
	if refused.Load() != 0 {
		t.Errorf("%d sends were refused with at most %d inside", refused.Load(), MaxInFlight+MaxWaiting)
	}
}

// TestGuardLossUnderASlowProviderIsMeasuredInDrainRounds measures the loss rule without a clock: 68 sends are accepted (none is
// refused at the capacity), the provider finishes four per round, and when the caller's context ends after three rounds exactly
// twelve have been delivered and every other send has failed as unavailable, although the capacity was never exceeded. So the
// loss threshold is the smaller of 68 and 4 x the number of rounds that fit in the deadline.
func TestGuardLossUnderASlowProviderIsMeasuredInDrainRounds(t *testing.T) {
	permits := make(chan struct{})
	var delivered atomic.Int64
	inner := &countingSender{permits: permits, delivered: &delivered}
	g := NewGuard(inner)
	ctx, cancel := context.WithCancel(bounded(t))
	defer cancel()
	results := sendAll(ctx, g, MaxInFlight+MaxWaiting)
	eventually(t, "4 inside and 64 waiting", func() bool { return inner.inside.Load() == MaxInFlight && g.inflight.Load() == MaxInFlight+MaxWaiting })
	const rounds = 3
	for round := int64(1); round <= rounds; round++ {
		for range MaxInFlight {
			give(t, permits)
		}
		eventually(t, "a round to drain", func() bool { return delivered.Load() == round*MaxInFlight && inner.inside.Load() == MaxInFlight })
	}
	cancel() // the caller's deadline: the four inside end with the provider's error, the waiting sixty ones never reach it
	ok, lost := 0, 0
	for range MaxInFlight + MaxWaiting {
		if err := recv(t, results, "a result"); err == nil {
			ok++
		} else if Outcome(err) == "unavailable" {
			lost++
		} else {
			t.Fatalf("unexpected result %v", err)
		}
	}
	if ok != rounds*MaxInFlight || lost != MaxInFlight+MaxWaiting-rounds*MaxInFlight || delivered.Load() != rounds*MaxInFlight {
		t.Errorf("delivered %d and lost %d of %d after %d rounds", ok, lost, MaxInFlight+MaxWaiting, rounds)
	}
}

// countingSender finishes one call per permit and keeps the number of calls inside.
type countingSender struct {
	permits   chan struct{}
	delivered *atomic.Int64
	inside    atomic.Int64
}

func (*countingSender) Enabled() bool { return true }

func (c *countingSender) Send(ctx context.Context, _ Message) error {
	c.inside.Add(1)
	defer c.inside.Add(-1)
	select {
	case <-c.permits:
		c.delivered.Add(1)
		return nil
	case <-ctx.Done():
		return &Error{Class: ErrUnavailable, Provider: "fake", Stage: "send"}
	}
}

// TestGuardDropsAWaiterWhoseContextEndsWithoutCallingTheProvider covers both ends of a waiting send: a deadline (Timeout true) and a
// cancellation (Timeout false), each leaving the count at zero and never reaching the inner sender.
func TestGuardDropsAWaiterWhoseContextEndsWithoutCallingTheProvider(t *testing.T) {
	inner := newGate()
	g := newGuard(inner, 1, 8)
	holder := sendOne(bounded(t), g)
	eventually(t, "the slot held", func() bool { return inner.started.Load() == 1 })

	short, stop := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer stop()
	failure := expectFailure(t, recv(t, sendOne(short, g), "the deadline refusal"), ErrUnavailable, "busy", 0)
	if !failure.Timeout {
		t.Error("a waiter whose deadline passed is not marked as a timeout")
	}
	canceled, cancel := context.WithCancel(bounded(t))
	done := sendOne(canceled, g)
	eventually(t, "the canceled waiter to wait", func() bool { return g.inflight.Load() == 2 })
	cancel()
	failure = expectFailure(t, recv(t, done, "the cancellation refusal"), ErrUnavailable, "busy", 0)
	if failure.Timeout {
		t.Error("a canceled waiter is marked as a timeout")
	}
	if g.inflight.Load() != 1 || inner.calls.Load() != 1 {
		t.Errorf("%d sends inside, inner calls %d", g.inflight.Load(), inner.calls.Load())
	}
	inner.open()
	if err := recv(t, holder, "the holder"); err != nil {
		t.Fatal(err)
	}
}

// TestGuardNeverCallsTheProviderForAnEndedContext covers the race between a free slot and a finished context.
func TestGuardNeverCallsTheProviderForAnEndedContext(t *testing.T) {
	inner := newGate()
	g := NewGuard(inner)
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for range 50 {
		expectFailure(t, g.Send(ended, testMessage()), ErrUnavailable, "busy", 0)
	}
	if inner.calls.Load() != 0 || len(g.slots) != 0 || g.inflight.Load() != 0 {
		t.Errorf("calls %d, slots %d, inside %d", inner.calls.Load(), len(g.slots), g.inflight.Load())
	}
}

// TestGuardReleasesTheSlotWhenTheInnerSenderFailsOrPanics: one failing and one panicking send each give their slot back (a guard of
// one slot makes a leak visible at once).
func TestGuardReleasesTheSlotWhenTheInnerSenderFailsOrPanics(t *testing.T) {
	failing := newGate()
	failing.result = &Error{Class: ErrUnauthorized, Provider: "smtp", Stage: "auth", Code: 535}
	failing.open()
	g := newGuard(failing, 1, 1)
	for range 3 {
		expectFailure(t, recv(t, sendOne(bounded(t), g), "a failure"), ErrUnauthorized, "auth", 535)
	}
	if len(g.slots) != 0 || g.inflight.Load() != 0 {
		t.Fatal("a failing send kept its slot")
	}

	panicking := newGate()
	panicking.panics = true
	g = newGuard(panicking, 1, 1)
	for range 3 {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("the panic of the inner sender was swallowed by the guard")
				}
			}()
			_ = g.Send(bounded(t), testMessage())
		}()
	}
	if len(g.slots) != 0 || g.inflight.Load() != 0 {
		t.Fatalf("a panicking send kept its slot: %d in use, %d inside", len(g.slots), g.inflight.Load())
	}
}

// TestGuardPassesTheInnerResultThrough keeps the guard transparent: the result and the context of the inner call are the caller's.
func TestGuardPassesTheInnerResultThrough(t *testing.T) {
	fake := NewFake()
	g := NewGuard(fake)
	if err := g.Send(context.Background(), testMessage()); err != nil || len(fake.Messages()) != 1 {
		t.Fatalf("%v %d", err, len(fake.Messages()))
	}
	want := errors.New("the inner error")
	fake.SetError(want)
	if err := g.Send(context.Background(), testMessage()); err != want {
		t.Fatalf("got %v", err)
	}
	probe := senderFunc(func(ctx context.Context, _ Message) error {
		if ctx.Value(probeKey{}) != 1 {
			return errors.New("the inner sender got another context")
		}
		return nil
	})
	if err := NewGuard(probe).Send(context.WithValue(context.Background(), probeKey{}, 1), testMessage()); err != nil {
		t.Fatal(err)
	}
}

type probeKey struct{}

type senderFunc func(context.Context, Message) error

func (senderFunc) Enabled() bool { return true }

func (f senderFunc) Send(ctx context.Context, message Message) error { return f(ctx, message) }
