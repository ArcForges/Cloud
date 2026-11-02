// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"errors"
	"fmt"
)

// The classes of a delivery failure. A caller matches them with errors.Is; the outcome words of Outcome are their metric labels.
var (
	// ErrRejected: the provider refused this message, or the message itself is invalid (the stage says which). Sending it again
	// unchanged will not help. A refusal of the connection or of the greeting is not a refusal of the message: that is
	// ErrUnavailable.
	ErrRejected = errors.New("mail: the provider rejected the message")
	// ErrUnavailable: a network, timeout, capacity or provider fault, or a connection-level refusal before any credential or
	// message was offered; the outcome may be unknown and a fresh send may succeed.
	ErrUnavailable = errors.New("mail: the provider is unavailable")
	// ErrUnauthorized: the provider refused this account, sender, stream, address, credential or the credential's permission to
	// send (a revoked token, a pending account, an unconfirmed sender, an IAM policy without ses:SendRawEmail); an operator must
	// act, and no retry will help until they do. The class does not say which of these it was.
	ErrUnauthorized = errors.New("mail: the provider refused the account or the credential")
)

// Error is a delivery failure. Its text is built from closed words and numbers only: never the provider's reply text (which can
// name the recipient or a resource), a body, an address, a credential, a URL, or the text of a lower-level error (which can name
// hosts). It wraps nothing.
type Error struct {
	// Class is one of the three sentinels.
	Class error
	// Provider is a closed word: "postmark", "smtp", "guard" (the delivery guard's own refusals) or "fake" (tests).
	Provider string
	// Stage is a closed word: message, config, busy, dial, tls, auth, envelope, data, http, response, panic, send.
	Stage string
	// Code is the HTTP status, the SMTP reply code or the Postmark ErrorCode that decided the class; 0 when there is none.
	Code int
	// Timeout reports that the deadline of the send (or the context's) ended the conversation. It is never set together with a
	// Code: a reply that arrived is not a timeout.
	Timeout bool
}

// Error is built from closed words and numbers.
func (e *Error) Error() string {
	return fmt.Sprintf("mail: %s %s failed: %s (code %d, timeout %t)", e.Provider, e.Stage, Outcome(e), e.Code, e.Timeout)
}

// Is matches the class sentinel.
func (e *Error) Is(target error) bool { return target == e.Class }

// Outcome is the closed metric label of a send result: sent, rejected, unavailable, unauthorized, or failed for anything that is
// not one of the typed errors (a plain error of a fake sender included).
func Outcome(err error) string {
	switch {
	case err == nil:
		return "sent"
	case errors.Is(err, ErrRejected):
		return "rejected"
	case errors.Is(err, ErrUnavailable):
		return "unavailable"
	case errors.Is(err, ErrUnauthorized):
		return "unauthorized"
	default:
		return "failed"
	}
}
