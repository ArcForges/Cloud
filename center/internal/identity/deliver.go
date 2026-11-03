// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"sync"
	"time"

	"github.com/ArcForges/Cloud/center/internal/mail"
)

// The two messages the center sends, named by the line a failed delivery logs. The line carries the outcome word and nothing else.
const (
	deliverySignIn = "an e-mail code could not be delivered"
	deliveryStepUp = "a step-up code could not be delivered"
)

// deliveryTimeout is the context of one send; the adapters' own timeout (at most 25 s) is below it.
const deliveryTimeout = 30 * time.Second

// deliveries tracks the sends that follow a response, so that the shutdown can wait for them. The count and the closed flag sit under
// one mutex; idle is created by the first drain and closed, once, when the tracker is closed and no delivery is pending.
type deliveries struct {
	mu      sync.Mutex
	closed  bool
	pending int
	idle    chan struct{}
}

// add registers one delivery, synchronously and BEFORE its goroutine exists, and reports false once the tracker is closed: a delivery
// that arrives after the shutdown began is refused, not started.
func (d *deliveries) add() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return false
	}
	d.pending++
	return true
}

// done ends one delivery; the last one after the tracker was closed releases the drain.
func (d *deliveries) done() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pending--
	if d.closed && d.pending == 0 {
		close(d.idle)
	}
}

// drain closes the tracker and waits until every accepted delivery has finished or ctx ends, whichever comes first; it returns
// ctx's error in the second case, and nil at once, even for an ended ctx, when no delivery is pending. The deliveries that are still
// running then are abandoned: that includes the goroutines that wait in the mail guard for a slot (up to 64 of them), which the
// process exit ends.
func (d *deliveries) drain(ctx context.Context) error {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		d.idle = make(chan struct{})
		if d.pending == 0 {
			close(d.idle)
		}
	}
	idle := d.idle
	d.mu.Unlock()
	select {
	case <-idle:
		return nil
	default:
	}
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Drain stops accepting deliveries and waits for those in flight, within ctx. The server calls it after the listeners have stopped
// and before the stores close, with the rest of the shutdown bound; the bound is the caller's parameter.
func (s *Service) Drain(ctx context.Context) error { return s.deliveries.drain(ctx) }

// deliver sends one message after the response (the caller has committed its transaction and built the reply: a send never runs
// inside a transaction and the reply never waits for it). It is the only place that sends a message, counts the result and logs a
// failure, so a later budget or meter (the monthly e-mail dimension belongs to AF-PLAT-01) hooks here. The other send paths that
// AF-ID-02 may add differ in risk (for example an address a user types is not an address the center already holds), so each must
// decide for itself and go through here.
//
// The outcome is the closed word of mail.Outcome (sent, rejected, unavailable, unauthorized, failed), counted as an
// email_send event and, when it is not "sent", logged as one fixed line with that word only: never the recipient, the code, the error
// text or the error's numeric code (a provider-chosen value must not become a label or a log key). A panic of the sender is
// recovered and counted failed, because an unrecovered panic in this goroutine would end the whole process. There is no refund of a
// flow's sends after a failure and no retry: a refund would tell a caller whether an address has an account.
func (s *Service) deliver(ctx context.Context, message mail.Message, failure string) {
	if !s.deliveries.add() {
		s.observeDelivery("unavailable", failure)
		return
	}
	s.background(func() {
		defer s.deliveries.done() // registered first, so that it runs after the recovery below
		defer func() {
			if recover() != nil {
				s.observeDelivery("failed", failure)
			}
		}()
		sendContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), deliveryTimeout)
		defer cancel()
		s.observeDelivery(mail.Outcome(s.mailer.Send(sendContext, message)), failure)
	})
}

// observeDelivery counts the outcome and logs a failure with the outcome word only.
func (s *Service) observeDelivery(outcome, failure string) {
	s.events.ObserveIdentity("email_send", outcome)
	if outcome != "sent" {
		s.logger.Warn(failure, "outcome", outcome)
	}
}
