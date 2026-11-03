// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestErrorTextIsBuiltFromClosedWordsAndNumbers(t *testing.T) {
	cases := []struct {
		err  *Error
		want string
	}{
		{&Error{Class: ErrRejected, Provider: "postmark", Stage: "http", Code: 400}, "mail: postmark http failed: rejected (code 400, timeout false)"},
		{&Error{Class: ErrUnavailable, Provider: "smtp", Stage: "data", Timeout: true}, "mail: smtp data failed: unavailable (code 0, timeout true)"},
		{&Error{Class: ErrUnauthorized, Provider: "smtp", Stage: "auth", Code: 535}, "mail: smtp auth failed: unauthorized (code 535, timeout false)"},
		{&Error{Provider: "fake", Stage: "send"}, "mail: fake send failed: failed (code 0, timeout false)"},
	}
	for _, c := range cases {
		if got := c.err.Error(); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

func TestOutcomeIsTheClosedLabelOfAResult(t *testing.T) {
	typedBy := func(class error) error { return &Error{Class: class, Provider: "smtp", Stage: "data"} }
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"success", nil, "sent"},
		{"rejected", typedBy(ErrRejected), "rejected"},
		{"unavailable", typedBy(ErrUnavailable), "unavailable"},
		{"unauthorized", typedBy(ErrUnauthorized), "unauthorized"},
		{"wrapped rejected", fmt.Errorf("while delivering: %w", typedBy(ErrRejected)), "rejected"},
		{"the bare sentinel", ErrUnauthorized, "unauthorized"},
		{"an untyped error", errors.New("the fake provider refused the message"), "failed"},
		{"a context error", context.DeadlineExceeded, "failed"},
		{"the disabled error", ErrDisabled, "failed"},
		{"a typed error without a class", &Error{Provider: "smtp", Stage: "data"}, "failed"},
	}
	for _, c := range cases {
		if got := Outcome(c.err); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestAnErrorMatchesItsOwnClassOnly(t *testing.T) {
	classes := []error{ErrRejected, ErrUnavailable, ErrUnauthorized}
	for _, own := range classes {
		err := error(&Error{Class: own, Provider: "postmark", Stage: "http"})
		for _, other := range classes {
			if errors.Is(err, other) != (other == own) {
				t.Errorf("an error of class %q matches %q: %v", own, other, errors.Is(err, other))
			}
		}
		var found *Error
		if !errors.As(fmt.Errorf("wrapped: %w", err), &found) || found.Class != own {
			t.Errorf("errors.As does not find the error of class %q", own)
		}
	}
}
