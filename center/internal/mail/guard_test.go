// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"context"
	"errors"
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

// eventually waits for a condition that depends on goroutines starting; the bound is a generous upper limit, never a lower one.
func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// sendAll starts n sends and returns their results through a channel, in completion order.
func sendAll(g *Guard, ctx context.Context, n int) <-chan error {
	results := make(chan error, n)
	for range n {
		go func() { results <- g.Send(ctx, testMessage()) }()
	}
	return results
}

func TestGuardBoundsAreTheCentersConstants(t *testing.T) {
	g := NewGuard(Disabled{})
	if MaxInFlight != 4 || MaxWaiting != 64 || cap(g.slots) != 4 || g.maxWait != 64 {
		t.Fatalf("bounds %d/%d, slots %d, waiters %d: the center's bound is 4 in flight and 64 waiting", MaxInFlight, MaxWaiting, cap(g.slots), g.maxWait)
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
	results := sendAll(g, context.Background(), 40)
	eventually(t, "four calls inside", func() bool { return inner.started.Load() >= MaxInFlight })
	time.Sleep(20 * time.Millisecond) // a fifth call, if the bound leaked, would have started by now
	if started := inner.started.Load(); started != MaxInFlight {
		t.Fatalf("%d calls reached the provider while %d slots exist", started, MaxInFlight)
	}
	inner.open()
	for range 40 {
		if err := <-results; err != nil {
			t.Fatalf("a send failed: %v", err)
		}
	}
	if high := inner.high.Load(); high > MaxInFlight || inner.calls.Load() != 40 {
		t.Errorf("high-water mark %d, %d calls", high, inner.calls.Load())
	}
	if g.waiting.Load() != 0 || len(g.slots) != 0 {
		t.Errorf("waiting %d, slots in use %d after every send finished", g.waiting.Load(), len(g.slots))
	}
}

// TestGuardDeliversTheSendBehindAFullPoolInsteadOfDroppingIt is the replacement of the "fifth send is refused at once" rule: whether a
// message waits or is lost must not depend on other sends being in flight.
func TestGuardDeliversTheSendBehindAFullPoolInsteadOfDroppingIt(t *testing.T) {
	inner := newGate()
	g := NewGuard(inner)
	results := sendAll(g, context.Background(), MaxInFlight)
	eventually(t, "a full pool", func() bool { return inner.started.Load() == MaxInFlight })
	fifth := sendAll(g, context.Background(), 1)
	eventually(t, "the fifth send to wait", func() bool { return g.waiting.Load() == 1 })
	select {
	case err := <-fifth:
		t.Fatalf("the fifth send returned while the pool was full: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	inner.open()
	for range MaxInFlight {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if err := <-fifth; err != nil {
		t.Fatalf("the fifth send was not delivered after the release: %v", err)
	}
	if inner.calls.Load() != MaxInFlight+1 {
		t.Errorf("%d calls reached the provider", inner.calls.Load())
	}
}

// TestGuardRefusesOnlyPastTheWaitingCap measures the second bound: 4 in flight and 64 waiting are accepted, the next send is refused
// at once as unavailable at stage busy, and nothing that was accepted is lost.
func TestGuardRefusesOnlyPastTheWaitingCap(t *testing.T) {
	inner := newGate()
	g := NewGuard(inner)
	accepted := sendAll(g, context.Background(), MaxInFlight+MaxWaiting)
	eventually(t, "4 in flight and 64 waiting", func() bool {
		return inner.started.Load() == MaxInFlight && g.waiting.Load() == MaxWaiting
	})
	begun := time.Now()
	err := g.Send(context.Background(), testMessage())
	failure := expectFailure(t, err, ErrUnavailable, "busy", 0)
	if failure.Provider != "guard" || failure.Timeout || Outcome(err) != "unavailable" || time.Since(begun) > 2*time.Second {
		t.Errorf("past the cap: %+v after %v", failure, time.Since(begun))
	}
	if g.waiting.Load() != MaxWaiting {
		t.Errorf("a refused send left the waiting count at %d", g.waiting.Load())
	}
	inner.open()
	for range MaxInFlight + MaxWaiting {
		if err := <-accepted; err != nil {
			t.Fatalf("an accepted send was lost: %v", err)
		}
	}
	if inner.calls.Load() != MaxInFlight+MaxWaiting {
		t.Errorf("%d calls reached the provider", inner.calls.Load())
	}
}

// TestGuardDropsAWaiterWhoseContextEndsWithoutCallingTheProvider covers both ends of a waiting send: a deadline (Timeout true) and a
// cancellation (Timeout false), each leaving the waiting count at zero and never reaching the inner sender.
func TestGuardDropsAWaiterWhoseContextEndsWithoutCallingTheProvider(t *testing.T) {
	inner := newGate()
	g := newGuard(inner, 1, 8)
	holder := sendAll(g, context.Background(), 1)
	eventually(t, "the slot held", func() bool { return inner.started.Load() == 1 })

	short, stop := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer stop()
	failure := expectFailure(t, g.Send(short, testMessage()), ErrUnavailable, "busy", 0)
	if !failure.Timeout {
		t.Error("a waiter whose deadline passed is not marked as a timeout")
	}
	canceled, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Send(canceled, testMessage()) }()
	eventually(t, "the canceled waiter to wait", func() bool { return g.waiting.Load() == 1 })
	cancel()
	failure = expectFailure(t, <-done, ErrUnavailable, "busy", 0)
	if failure.Timeout {
		t.Error("a canceled waiter is marked as a timeout")
	}
	if g.waiting.Load() != 0 || inner.calls.Load() != 1 {
		t.Errorf("waiting %d, inner calls %d", g.waiting.Load(), inner.calls.Load())
	}
	inner.open()
	if err := <-holder; err != nil {
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
	if inner.calls.Load() != 0 || len(g.slots) != 0 || g.waiting.Load() != 0 {
		t.Errorf("calls %d, slots %d, waiting %d", inner.calls.Load(), len(g.slots), g.waiting.Load())
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
		expectFailure(t, g.Send(context.Background(), testMessage()), ErrUnauthorized, "auth", 535)
	}
	if len(g.slots) != 0 {
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
			_ = g.Send(context.Background(), testMessage())
		}()
	}
	if len(g.slots) != 0 || g.waiting.Load() != 0 {
		t.Fatalf("a panicking send kept its slot: %d in use, %d waiting", len(g.slots), g.waiting.Load())
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
