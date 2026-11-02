// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDisabledOffersNoMethodAndRefusesToSend(t *testing.T) {
	var sender Sender = Disabled{}
	if sender.Enabled() {
		t.Error("Disabled offers the e-mail method")
	}
	if err := sender.Send(context.Background(), testMessage()); !errors.Is(err, ErrDisabled) || Outcome(err) != "failed" {
		t.Errorf("Disabled.Send: %v", err)
	}
}

func TestFakeRecordsMessagesAndDrivesEveryFailureClass(t *testing.T) {
	fake := NewFake()
	if !fake.Enabled() {
		t.Fatal("the fake is disabled")
	}
	if err := fake.Send(context.Background(), testMessage()); err != nil {
		t.Fatal(err)
	}
	messages := fake.Messages()
	if len(messages) != 1 || messages[0] != testMessage() {
		t.Fatalf("recorded %+v", messages)
	}
	messages[0].To = "changed@example.test"
	if fake.Messages()[0].To != testTo {
		t.Error("Messages returns the internal slice")
	}

	fake.SetFailing(true)
	err := fake.Send(context.Background(), testMessage())
	expectFailure(t, err, ErrUnavailable, "send", 0)
	if Outcome(err) != "unavailable" || len(fake.Messages()) != 1 {
		t.Errorf("a failing fake: outcome %q, %d messages", Outcome(err), len(fake.Messages()))
	}
	for class, want := range map[error]string{ErrRejected: "rejected", ErrUnavailable: "unavailable", ErrUnauthorized: "unauthorized"} {
		fake.SetError(&Error{Class: class, Provider: "fake", Stage: "send"})
		if got := Outcome(fake.Send(context.Background(), testMessage())); got != want {
			t.Errorf("class %q: outcome %q, want %q", class, got, want)
		}
	}
	fake.SetError(errors.New("a plain error"))
	if got := Outcome(fake.Send(context.Background(), testMessage())); got != "failed" {
		t.Errorf("a plain error: outcome %q", got)
	}
	fake.SetFailing(false)
	if err = fake.Send(context.Background(), testMessage()); err != nil || len(fake.Messages()) != 2 {
		t.Errorf("after recovery: %v, %d messages", err, len(fake.Messages()))
	}
}

func TestFakeWaitReturnsOnArrivalAndAtContextEnd(t *testing.T) {
	fake := NewFake()
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = fake.Send(context.Background(), testMessage())
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if messages, ok := fake.Wait(ctx, 1); !ok || len(messages) != 1 {
		t.Fatalf("Wait: %v %v", messages, ok)
	}
	short, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if messages, ok := fake.Wait(short, 2); ok || len(messages) != 1 {
		t.Fatalf("Wait for a message that never comes: %v %v", messages, ok)
	}
}
