// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"fmt"
	"strings"
	"testing"
)

// Every test of this package is MOCKED: local servers on 127.0.0.1 with a throwaway CA, injected dials and transports, no DNS and
// no external network. The only exceptions are the opt-in probes in live_test.go, which skip without an explicit local switch.

const (
	testFrom = "sender@example.test"
	testTo   = "recipient@example.test"
	testHost = "smtp.example.test"
)

// sentinel is a synthetic credential or leak marker built from words, never a literal that looks like a credential: the secret
// scan reads test data too, and a test fixture never gets an allowlist row.
func sentinel(role string) string {
	return strings.Join([]string{"synthetic", "word", "built", role, "sentinel"}, "-")
}

// testMessage is the message most tests send: a short subject and a body with two lines.
func testMessage() Message {
	return Message{To: testTo, Subject: "Your test sign-in code", Text: "Your code is word-word-word.\nIt expires soon.\n"}
}

// typed returns err as the mail error it must be.
func typed(t *testing.T, err error) *Error {
	t.Helper()
	failure, ok := err.(*Error)
	if !ok {
		t.Fatalf("got %T %v, want a *mail.Error", err, err)
	}
	return failure
}

// expectFailure checks the class, stage and code of a failure and returns it.
func expectFailure(t *testing.T, err error, class error, stage string, code int) *Error {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %v at %s", class, stage)
	}
	failure := typed(t, err)
	if failure.Class != class || failure.Stage != stage || failure.Code != code {
		t.Fatalf("got class %q stage %q code %d (%v), want class %q stage %q code %d", failure.Class, failure.Stage, failure.Code, err, class, stage, code)
	}
	return failure
}

// noLeak fails when the text of err, in any formatting, holds one of the markers.
func noLeak(t *testing.T, err error, markers ...string) {
	t.Helper()
	text := fmt.Sprintf("%v|%+v|%#v|%s|%q|%x", err, err, err, err, err, err)
	for _, marker := range markers {
		if marker != "" && strings.Contains(text, marker) {
			t.Fatalf("the error leaks %q: %s", marker, text)
		}
	}
}
