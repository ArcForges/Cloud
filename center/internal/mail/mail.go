// SPDX-License-Identifier: AGPL-3.0-only

// Package mail is the center's outbound e-mail of sign-in codes. Only two senders exist until live delivery is decided (AR-14,
// H-19): Disabled, which every deployment uses (the e-mail method is then not offered at all), and Fake, which tests inject to
// read the codes the center sends (the closed loop). No mail configuration passes through the Worker. The live provider adapters
// (Postmark, Amazon SES) arrive later behind the same interface.
package mail

import (
	"context"
	"errors"
	"sync"
)

// Message is one e-mail: the recipient, a subject and a plain-text body. It holds a sign-in code, so it is never logged.
type Message struct {
	To      string
	Subject string
	Text    string
}

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
	fail     bool
}

// SetFailing makes Send fail (a provider failure) or succeed again.
func (f *Fake) SetFailing(fail bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = fail
}

// NewFake is an empty fake sender.
func NewFake() *Fake { return &Fake{notify: make(chan struct{}, 1)} }

// Enabled is true.
func (f *Fake) Enabled() bool { return true }

// Send records the message.
func (f *Fake) Send(_ context.Context, message Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("the fake provider refused the message")
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
