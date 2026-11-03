// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/mail"
)

// The delivery tests need no PostgreSQL, so they run on both hosts. They are MOCKED: a fake or gated sender, no provider.

type recordedEvents struct {
	mu    sync.Mutex
	items []string
	// hold, when set, runs first in every observation: a test blocks the counting of an outcome with it.
	hold func(event, outcome string)
}

func (r *recordedEvents) ObserveIdentity(event, outcome string) {
	if r.hold != nil {
		r.hold(event, outcome)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, event+" "+outcome)
}

func (r *recordedEvents) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.items...)
}

// syncBuffer is a log destination that goroutines may write.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

const (
	deliveryRecipient = "recipient-word-built-sentinel@example.test"
	deliveryCode      = "word-built-sign-in-code-sentinel"
)

func deliveryMessage() mail.Message {
	return mail.Message{To: deliveryRecipient, Subject: "Your ArcForges sign-in code", Text: "Your code is " + deliveryCode + "\n"}
}

// newDeliverService is a service with no database: deliver touches only the sender, the events, the logger and the tracker.
func newDeliverService(sender mail.Sender, synchronous bool) (*Service, *recordedEvents, *syncBuffer) {
	events, logs := &recordedEvents{}, &syncBuffer{}
	options := Options{Mail: sender, Events: events, Logger: untimed(logs)}
	if synchronous {
		options.Background = func(work func()) { work() }
	}
	return New(options), events, logs
}

// bounded fails a waiting test after a generous bound.
func within(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// untimed logs without the timestamp, whose digits would otherwise collide
// with the status codes the leak check looks for.
func untimed(w io.Writer) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}))
}

func TestDeliverCountsTheClosedOutcomeOfEveryClassAndLogsOnlyTheWord(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want string
	}{
		{"sent", nil, "sent"},
		{"rejected", &mail.Error{Class: mail.ErrRejected, Provider: "postmark", Stage: "response", Code: 300}, "rejected"},
		{"unavailable", &mail.Error{Class: mail.ErrUnavailable, Provider: "smtp", Stage: "data", Code: 451}, "unavailable"},
		{"unauthorized", &mail.Error{Class: mail.ErrUnauthorized, Provider: "smtp", Stage: "auth", Code: 535}, "unauthorized"},
		{"a plain error", errors.New("the fake provider refused " + deliveryRecipient), "failed"},
		{"the disabled error", mail.ErrDisabled, "failed"},
	} {
		fake := mail.NewFake()
		fake.SetError(c.err)
		service, events, logs := newDeliverService(fake, true)
		service.deliver(context.Background(), deliveryMessage(), deliverySignIn)
		if got := events.all(); len(got) != 1 || got[0] != "email_send "+c.want {
			t.Errorf("%s: events %v", c.name, got)
		}
		line := logs.String()
		if c.want == "sent" {
			if line != "" {
				t.Errorf("%s: a successful send logged %q", c.name, line)
			}
			continue
		}
		if !strings.Contains(line, deliverySignIn) || !strings.Contains(line, "outcome="+c.want) || strings.Count(line, "\n") != 1 {
			t.Errorf("%s: log %q", c.name, line)
		}
		for _, leak := range []string{deliveryRecipient, "recipient-word", deliveryCode, "sentinel", "554", "535", "451", "300", "code=", "mail:", "refused", "postmark", "smtp", "response"} {
			if strings.Contains(line, leak) {
				t.Errorf("%s: the log line holds %q: %q", c.name, leak, line)
			}
		}
	}
}

func TestDeliverRecoversAPanicOfTheSenderAndStillFinishesTheDelivery(t *testing.T) {
	panicking := senderOf(func(context.Context, mail.Message) error { panic("a panic that names " + deliveryRecipient) })
	service, events, logs := newDeliverService(panicking, false)
	service.deliver(context.Background(), deliveryMessage(), deliveryStepUp)
	within(t, "the panic to be counted", func() bool { return len(events.all()) == 1 })
	if got := events.all(); got[0] != "email_send failed" {
		t.Errorf("events %v", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := service.Drain(ctx); err != nil {
		t.Errorf("a recovered panic left the delivery unfinished (Done is deferred before the recovery): %v", err)
	}
	line := logs.String()
	if !strings.Contains(line, deliveryStepUp) || !strings.Contains(line, "outcome=failed") || strings.Contains(line, "panic that names") || strings.Contains(line, "recipient-word") {
		t.Errorf("log %q", line)
	}
}

// drainWithin runs Drain with a bound and fails the test by name when it has not returned after 3 s (a Drain that ignores its bound
// would otherwise hold the test until the binary's timeout). It returns Drain's error.
func drainWithin(t *testing.T, service *Service, bound time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	got := make(chan error, 1)
	go func() { got <- service.Drain(ctx) }()
	select {
	case err := <-got:
		return err
	case <-time.After(3 * time.Second):
		t.Fatalf("Drain did not return within 3 s of a %v bound", bound)
		return nil
	}
}

// TestDrainWaitsUntilARecoveredDeliveryHasBeenCounted: Done is deferred before the recovery, so it runs after it. The count of the
// failed outcome is held; Drain must not return while it is held (a delivery whose outcome is still being counted is unfinished),
// and returns once it is released.
func TestDrainWaitsUntilARecoveredDeliveryHasBeenCounted(t *testing.T) {
	panicking := senderOf(func(context.Context, mail.Message) error { panic("a panic of the sender") })
	service, events, _ := newDeliverService(panicking, false)
	reached, release := make(chan struct{}), make(chan struct{})
	events.hold = func(_, outcome string) {
		if outcome == "failed" {
			close(reached)
			<-release
		}
	}
	service.deliver(context.Background(), deliveryMessage(), deliverySignIn)
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the recovered delivery was never counted")
	}
	if err := drainWithin(t, service, 100*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Drain returned %v while the outcome of a recovered delivery was still being counted", err)
	}
	close(release)
	long, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := service.Drain(long); err != nil {
		t.Errorf("Drain after the count: %v", err)
	}
	if got := events.all(); len(got) != 1 || got[0] != "email_send failed" {
		t.Errorf("events %v", got)
	}
}

// TestDeliverSendsWithAContextThatOutlivesTheCallerAndEndsAtTheBound: the request that started a delivery ends before the send does,
// so the send must not inherit its cancellation; it carries its own deadline of deliveryTimeout, below which every adapter's own
// timeout (at most 25 s) ends it first.
func TestDeliverSendsWithAContextThatOutlivesTheCallerAndEndsAtTheBound(t *testing.T) {
	type seen struct {
		err      error
		deadline time.Time
		ok       bool
	}
	got := make(chan seen, 1)
	sender := senderOf(func(ctx context.Context, _ mail.Message) error {
		deadline, ok := ctx.Deadline()
		got <- seen{ctx.Err(), deadline, ok}
		return nil
	})
	service, _, _ := newDeliverService(sender, true)
	caller, cancel := context.WithCancel(context.Background())
	cancel() // the request has ended
	began := time.Now()
	service.deliver(caller, deliveryMessage(), deliverySignIn)
	one := <-got
	if one.err != nil {
		t.Errorf("the send inherited the cancellation of the request: %v", one.err)
	}
	if !one.ok || one.deadline.Sub(began) > deliveryTimeout+time.Second || one.deadline.Sub(began) < deliveryTimeout-time.Second {
		t.Errorf("the send's deadline is %v after the call (has one: %v), want about %v", one.deadline.Sub(began), one.ok, deliveryTimeout)
	}
	if deliveryTimeout != 30*time.Second || deliveryTimeout <= config.MaxMailTimeout {
		t.Errorf("deliveryTimeout %v must be 30 s and above the adapters' largest timeout %v", deliveryTimeout, config.MaxMailTimeout)
	}
}

// TestDeliveriesRaceWithTheDrainOnTheClosedFlag: handlers call deliver while the shutdown calls Drain. Every delivery is either
// accepted and then counted exactly once as sent, or refused after the tracker closed and counted unavailable, never lost and
// never counted twice; the race detector (the Linux leg) sees a closed flag or a count touched without the mutex.
func TestDeliveriesRaceWithTheDrainOnTheClosedFlag(t *testing.T) {
	const rounds, callers = 60, 24
	for round := range rounds {
		fake := mail.NewFake()
		service, events, _ := newDeliverService(fake, false)
		start := make(chan struct{})
		var wait sync.WaitGroup
		for range callers {
			wait.Add(1)
			go func() {
				defer wait.Done()
				<-start
				service.deliver(context.Background(), deliveryMessage(), deliverySignIn)
			}()
		}
		close(start)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		drained := service.Drain(ctx)
		cancel()
		wait.Wait()
		// A delivery that raced the drain may have started after it returned; the second drain waits for those that were accepted.
		again, stop := context.WithTimeout(context.Background(), 5*time.Second)
		if err := service.Drain(again); err != nil {
			t.Fatalf("round %d: the second drain: %v (the first: %v)", round, err, drained)
		}
		stop()
		counted := events.all()
		if len(counted) != callers || countOf(counted, "email_send sent")+countOf(counted, "email_send unavailable") != callers ||
			countOf(counted, "email_send sent") != len(fake.Messages()) {
			t.Fatalf("round %d: %d events %v for %d deliveries, %d sent", round, len(counted), counted, callers, len(fake.Messages()))
		}
	}
}

// TestDrainWithNothingPendingReturnsAtOnceEvenWithAnEndedContext: the shutdown gives the drain what the listeners leave, which can be
// nothing; an idle service, or one whose deliveries all finished, is drained, not abandoned. A pending delivery with an ended context
// is the only case that returns the context's error.
func TestDrainWithNothingPendingReturnsAtOnceEvenWithAnEndedContext(t *testing.T) {
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	for range 200 {
		idle, _, _ := newDeliverService(mail.NewFake(), false)
		if err := idle.Drain(ended); err != nil {
			t.Fatalf("an idle service reported %v", err)
		}
		finished, events, _ := newDeliverService(mail.NewFake(), true)
		finished.deliver(context.Background(), deliveryMessage(), deliverySignIn)
		if len(events.all()) != 1 {
			t.Fatal("the synchronous delivery did not finish")
		}
		if err := finished.Drain(ended); err != nil {
			t.Fatalf("a service whose deliveries finished reported %v", err)
		}
	}
	release := make(chan struct{})
	pending, _, _ := newDeliverService(senderOf(func(ctx context.Context, _ mail.Message) error {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	}), false)
	pending.deliver(context.Background(), deliveryMessage(), deliverySignIn)
	if err := pending.Drain(ended); !errors.Is(err, context.Canceled) {
		t.Errorf("a pending delivery with an ended context reported %v", err)
	}
	close(release)
	later, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := pending.Drain(later); err != nil {
		t.Errorf("the delivery never finished: %v", err)
	}
}

// senderOf is a Sender made of a function.
type senderOf func(context.Context, mail.Message) error

func (senderOf) Enabled() bool { return true }

func (f senderOf) Send(ctx context.Context, message mail.Message) error { return f(ctx, message) }

// TestDeliverNeverMakesTheCallerWaitForTheSend is the unit form of N1: with the production goroutine path the call returns while the
// sender is still blocked, and Drain waits for the send to finish.
func TestDeliverNeverMakesTheCallerWaitForTheSendAndDrainWaitsForIt(t *testing.T) {
	release, started := make(chan struct{}), make(chan struct{})
	var finished atomic.Bool
	blocking := senderOf(func(context.Context, mail.Message) error {
		close(started)
		<-release
		finished.Store(true)
		return nil
	})
	service, events, _ := newDeliverService(blocking, false)
	service.deliver(context.Background(), deliveryMessage(), deliverySignIn)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the send never started")
	}
	if finished.Load() || len(events.all()) != 0 {
		t.Fatal("deliver returned only after the send finished")
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		close(release)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := service.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if !finished.Load() || len(events.all()) != 1 || events.all()[0] != "email_send sent" {
		t.Errorf("Drain returned before the send was counted: finished %v, events %v", finished.Load(), events.all())
	}
}

func TestDrainDoesNotHoldTheStopPastItsBound(t *testing.T) {
	release := make(chan struct{})
	stuck := senderOf(func(ctx context.Context, _ mail.Message) error {
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	})
	service, _, _ := newDeliverService(stuck, false)
	service.deliver(context.Background(), deliveryMessage(), deliverySignIn)
	if err := drainWithin(t, service, 100*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Drain returned %v with a 100 ms bound", err)
	}
	close(release)
	later, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := service.Drain(later); err != nil {
		t.Errorf("the delivery never finished: %v", err)
	}
}

// TestADeliveryIsRegisteredBeforeItsGoroutineExists: the work is captured and not yet run, and Drain already waits for it.
func TestADeliveryIsRegisteredBeforeItsGoroutineExists(t *testing.T) {
	var captured func()
	fake := mail.NewFake()
	service := New(Options{Mail: fake, Events: &recordedEvents{}, Background: func(work func()) { captured = work }})
	service.deliver(context.Background(), deliveryMessage(), deliverySignIn)
	if captured == nil {
		t.Fatal("the delivery was not handed to the background hook")
	}
	if err := drainWithin(t, service, 50*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Drain did not wait for a delivery that was accepted but not started: %v", err)
	}
	captured()
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	if err := service.Drain(ctx); err != nil || len(fake.Messages()) != 1 {
		t.Errorf("after the work ran: %v, %d messages", err, len(fake.Messages()))
	}
}

func TestADeliveryAfterTheDrainIsRefusedAndNeverReachesTheSender(t *testing.T) {
	fake := mail.NewFake()
	var handed atomic.Int64
	events, logs := &recordedEvents{}, &syncBuffer{}
	service := New(Options{Mail: fake, Events: events, Logger: untimed(logs), Background: func(work func()) { handed.Add(1); work() }})
	if err := service.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	service.deliver(context.Background(), deliveryMessage(), deliverySignIn)
	if handed.Load() != 0 || len(fake.Messages()) != 0 {
		t.Errorf("a refused delivery was started: %d handed, %d sent", handed.Load(), len(fake.Messages()))
	}
	if got := events.all(); len(got) != 1 || got[0] != "email_send unavailable" || !strings.Contains(logs.String(), "outcome=unavailable") {
		t.Errorf("events %v, log %q", got, logs.String())
	}
}

// TestDrainAbandonsTheDeliveriesThatWaitInTheGuardAtItsBound states what the bound costs: with the guard full, the deliveries that
// wait for a slot (up to 64) are tracked like the four in flight, so Drain gives up on them at its bound and the process exit ends
// them; the two over the guard's capacity were refused at once and counted unavailable.
func TestDrainAbandonsTheDeliveriesThatWaitInTheGuardAtItsBound(t *testing.T) {
	release := make(chan struct{})
	var inside atomic.Int64
	inner := senderOf(func(ctx context.Context, _ mail.Message) error {
		inside.Add(1)
		defer inside.Add(-1)
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil
	})
	service, events, _ := newDeliverService(mail.NewGuard(inner), false)
	total := mail.MaxInFlight + mail.MaxWaiting + 2
	for range total {
		service.deliver(context.Background(), deliveryMessage(), deliverySignIn)
	}
	within(t, "four sends inside and two refused", func() bool { return inside.Load() == mail.MaxInFlight && len(events.all()) == 2 })
	for _, event := range events.all() {
		if event != "email_send unavailable" {
			t.Errorf("a send over the guard's capacity was counted %q", event)
		}
	}
	if err := drainWithin(t, service, 100*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Drain returned %v although %d deliveries were still waiting", err, mail.MaxInFlight+mail.MaxWaiting)
	}
	close(release)
	within(t, "every delivery to be counted after the release", func() bool { return len(events.all()) == total })
	if sent := countOf(events.all(), "email_send sent"); sent != mail.MaxInFlight+mail.MaxWaiting {
		t.Errorf("%d sends were delivered after the release", sent)
	}
}

func countOf(items []string, want string) int {
	count := 0
	for _, item := range items {
		if item == want {
			count++
		}
	}
	return count
}

// TestEverySendGoesThroughDeliver pins the single send and count site: no other non-test file of the package calls the sender's
// Send or counts an email_send event (the monthly meter and the budget of AF-PLAT-01 hook at deliver).
func TestEverySendGoesThroughDeliver(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("no source files: %v", err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") || name == "deliver.go" {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, form := range []string{".mailer.Send(", `"email_send"`, ".Send(sendContext"} {
			if strings.Contains(string(data), form) {
				t.Errorf("%s uses %s outside deliver.go", name, form)
			}
		}
	}
	data, err := os.ReadFile("deliver.go")
	if err != nil || !strings.Contains(string(data), ".mailer.Send(") || !strings.Contains(string(data), `"email_send"`) {
		t.Errorf("deliver.go lost the send or the count: %v", err)
	}
}

// TestADeliveryLogsNeverAnythingButTheOutcome runs every class through the step-up line too and checks the exact field set.
func TestADeliveryLogsNeverAnythingButTheOutcome(t *testing.T) {
	fake := mail.NewFake()
	fake.SetError(&mail.Error{Class: mail.ErrUnauthorized, Provider: "smtp", Stage: "auth", Code: 535})
	service, _, logs := newDeliverService(fake, true)
	service.deliver(context.Background(), deliveryMessage(), deliveryStepUp)
	line := strings.TrimSpace(logs.String())
	fields := strings.Fields(line)
	if len(fields) < 3 || !strings.HasPrefix(line, "level=WARN") || !strings.Contains(line, `msg="a step-up code could not be delivered"`) ||
		fields[len(fields)-1] != "outcome=unauthorized" {
		t.Errorf("log %q", line)
	}
	if got := fmt.Sprint(strings.Count(line, "=")); got != "3" { // level, msg, outcome (the timestamp is dropped by untimed)
		t.Errorf("the line has %s fields: %q", got, line)
	}
}
