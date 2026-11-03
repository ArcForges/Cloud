// SPDX-License-Identifier: AGPL-3.0-only

// Package mail is the center's outbound e-mail of sign-in and verification codes. It holds the Sender interface and the senders
// behind it: Disabled, which every deployment uses today (the e-mail method is then not offered at all); Fake, which tests inject
// to read the codes the center sends (the closed loop); and the two live adapters, Postmark over HTTPS and an SMTP submission
// service over TLS (Amazon SES is the first target), with Guard, which bounds how many sends talk to a provider at once. The
// adapters are tested against local servers only (MOCKED): the tests listen on and dial the loopback interface (one resolves the
// host name localhost from the hosts file), and in the ordinary run no packet leaves the host. Three kinds of test reach a real
// endpoint, and each skips without its own explicit local switch: the probe of the Postmark API with the public test token
// (nothing is delivered), the SES handshake that stops before AUTH (no credential exists in the process), and the owner-run live
// send, which does send one real message (it needs a second, confirming switch as well).
//
// New builds the sender of a validated configuration (config.Mail): Disabled unless a provider is named, otherwise that provider's
// adapter behind a Guard; the server calls it, and the identity service sends only through its deliver function, which counts the
// outcome, logs a failure as one closed word, recovers a panic and is drained at the shutdown. The hosted Worker hands the Container
// the mail variables only while a provider is named, and no deployed environment names one.
//
// What this package does NOT make possible: no real account can be mailed. No production code creates an e-mail identity (the
// only non-test INSERT INTO identity.auth_identity statements enroll passkeys), so the sign-in-code surface opens when a sender is
// Enabled but never reaches Send for a real account, and the browser channel refuses e-mail unconditionally. A mail setup
// therefore proves nothing about delivery to a user, and enabling a provider tests nothing about the provider: the adapter is built and
// its configuration validated, but nothing calls Send until an e-mail identity can exist. The credential is used only by the opt-in live
// send.
//
// Failures are typed (Error, with the classes ErrRejected, ErrUnavailable and ErrUnauthorized) and their text holds closed words
// and numbers only (the HTTP status, the SMTP reply code or the Postmark ErrorCode among them): never an address, a sign-in code,
// a body, a credential, a URL or the provider's reply text. A credential is a config.Secret, revealed only inside the two adapters.
package mail

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// DefaultTimeout bounds one send when an adapter is built without a timeout. It is below the 30 s context a delivery runs under.
const DefaultTimeout = 10 * time.Second

// Message is one e-mail: the recipient, a subject and a plain-text body. It holds a sign-in code, so it is never logged, and it
// prints a fixed marker through fmt, slog and encoding/json wherever Go can call these methods (a value, a pointer, an exported
// field, a slice or a map of them). A Message held in an unexported field of another struct is printed by fmt field by field, as
// every Go type is: the structural redaction is the second line, and the first is the rule that nothing formats a Message (the
// delivery code logs an Outcome or a class, never a Message).
type Message struct {
	To      string
	Subject string
	Text    string
}

// redactedMessage is the only text a Message ever prints.
const redactedMessage = "mail.Message[redacted]"

// String is the marker.
func (Message) String() string { return redactedMessage }

// GoString is the marker.
func (Message) GoString() string { return redactedMessage }

// Format prints the marker for every verb except %p (fmt prints a bad verb's operand without consulting a Formatter, and go vet does not
// report it; a Message is never formatted with %p). A struct of strings would otherwise print its fields for %d.
func (Message) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redactedMessage)) }

// LogValue is the marker.
func (Message) LogValue() slog.Value { return slog.StringValue(redactedMessage) }

// MarshalText is the marker.
func (Message) MarshalText() ([]byte, error) { return []byte(redactedMessage), nil }

// MarshalJSON is the marker.
func (Message) MarshalJSON() ([]byte, error) { return []byte(`"` + redactedMessage + `"`), nil }

// errSerialized is what the binary encoders answer: a Message is never serialized as bytes (encoding/gob would otherwise write its
// exported fields, the recipient, the subject and the sign-in code, in clear text; no code serializes a Message, and a durable queue
// is excluded by design).
var errSerialized = errors.New("mail: a Message is never serialized")

// GobEncode refuses: encoding/gob ignores MarshalText and MarshalJSON and writes the exported fields.
func (Message) GobEncode() ([]byte, error) { return nil, errSerialized }

// MarshalBinary refuses, like GobEncode (the binary encoders of the standard library and of gob-like libraries look for it).
func (Message) MarshalBinary() ([]byte, error) { return nil, errSerialized }

// Sender delivers messages.
type Sender interface {
	// Enabled reports whether the e-mail method is offered at all.
	Enabled() bool
	// Send delivers one message; an error is a delivery failure, counted and never shown to the caller.
	Send(ctx context.Context, message Message) error
}

// ErrDisabled is the error of the disabled sender.
var ErrDisabled = errors.New("e-mail delivery is not configured")

// Disabled offers no e-mail method.
type Disabled struct{}

// Enabled is false.
func (Disabled) Enabled() bool { return false }

// Send refuses.
func (Disabled) Send(context.Context, Message) error { return ErrDisabled }

// Fake records every message in memory (tests only): the closed loop of the e-mail code flow.
type Fake struct {
	mu       sync.Mutex
	messages []Message
	notify   chan struct{}
	failure  error
}

// SetFailing makes Send fail with a typed unavailable error (a provider outage) or succeed again.
func (f *Fake) SetFailing(fail bool) {
	if fail {
		f.SetError(&Error{Class: ErrUnavailable, Provider: "fake", Stage: "send"})
		return
	}
	f.SetError(nil)
}

// SetError makes every Send return err (nil: succeed again), so a test can drive each failure class.
func (f *Fake) SetError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failure = err
}

// NewFake is an empty fake sender.
func NewFake() *Fake { return &Fake{notify: make(chan struct{}, 1)} }

// Enabled is true.
func (f *Fake) Enabled() bool { return true }

// Send records the message.
func (f *Fake) Send(_ context.Context, message Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failure != nil {
		return f.failure
	}
	f.messages = append(f.messages, message)
	select {
	case f.notify <- struct{}{}:
	default:
	}
	return nil
}

// Messages is a copy of every message sent so far.
func (f *Fake) Messages() []Message {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Message(nil), f.messages...)
}

// Wait returns the messages once at least count were sent, or false when ctx ends first.
func (f *Fake) Wait(ctx context.Context, count int) ([]Message, bool) {
	for {
		if messages := f.Messages(); len(messages) >= count {
			return messages, true
		}
		select {
		case <-ctx.Done():
			return f.Messages(), false
		case <-f.notify:
		}
	}
}
