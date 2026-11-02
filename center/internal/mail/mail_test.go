// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
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

// TestMessageNeverPrintsItsContents is the structural redaction of the recipient, the subject and the sign-in code: in every shape
// Go can call the methods through, under every formatting path (MOCKED: nothing is sent).
func TestMessageNeverPrintsItsContents(t *testing.T) {
	code := sentinel("sign-in-code")
	message := Message{To: "recipient-" + code + "@example.test", Subject: "subject-" + code, Text: "Your code is " + code + "\n"}
	type exported struct{ Message Message }
	shapes := map[string]any{
		"value": message, "pointer": &message, "exported field": exported{Message: message}, "slice": []Message{message}, "map": map[string]Message{"k": message},
		"slice of any": []any{message, &message}, "pointer to exported": &exported{Message: message},
	}
	for name, shape := range shapes {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d", "%t"} {
			if text := fmt.Sprintf(verb, shape); strings.Contains(text, code) || strings.Contains(text, hex.EncodeToString([]byte(code))) {
				t.Errorf("%s with %s leaks: %s", name, verb, text)
			}
		}
		for handler, build := range map[string]func(*bytes.Buffer) slog.Handler{
			"slog text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
			"slog json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
		} {
			var out bytes.Buffer
			slog.New(build(&out)).Info("probe", "value", shape, slog.Any("again", shape))
			if strings.Contains(out.String(), code) {
				t.Errorf("%s with %s leaks: %s", name, handler, out.String())
			}
		}
		if data, err := json.Marshal(shape); err != nil || strings.Contains(string(data), code) {
			t.Errorf("%s with encoding/json: %s, %v", name, data, err)
		}
	}
	if message.String() != redactedMessage || message.GoString() != redactedMessage {
		t.Error("String or GoString prints more than the marker")
	}
	if text, err := message.MarshalText(); err != nil || string(text) != redactedMessage {
		t.Errorf("MarshalText printed %q, %v", text, err)
	}
	if got := fmt.Sprint(message); got != redactedMessage {
		t.Errorf("Sprint printed %q", got)
	}
	// The fields stay readable by code: the adapters and the closed-loop tests read them.
	if message.To == "" || message.Subject == "" || !strings.Contains(message.Text, code) {
		t.Error("the redaction hides the fields from code")
	}
}
