// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"fmt"
	"log/slog"
)

// Secret holds a credential (a mail provider token or password). The value sits behind a pointer and every formatting method
// prints a fixed marker, so:
//
//   - where Go can call the methods (a value, an exported field, slog.Any, encoding/json, encoding.TextMarshaler) the marker is
//     printed;
//   - where Go cannot call them (a Secret reached through an unexported field, which fmt prints field by field) the pointer
//     keeps the string out of reach: fmt prints an address, slog's text handler prints an address, encoding/json skips the
//     field.
//
// That is what the tests of packages config, mail and identity pin; a reflection dumper that follows pointers (go-spew,
// testify's diff) would still show the value, and the module has none. Only Reveal returns the value: call it at the point of
// use and never store the result (a pin in package mail allows it in the two adapters only). The zero Secret is empty and every
// method accepts it.
//
// Do not compare Secrets with ==: that compares the pointers. Compare Reveal() results (tests only) or use Empty.
type Secret struct{ p *string }

// NewSecret wraps a credential.
func NewSecret(value string) Secret { return Secret{p: &value} }

// redacted is the only text a Secret ever prints.
const redacted = "[redacted]"

// Reveal returns the credential. The empty string for the zero Secret.
func (s Secret) Reveal() string {
	if s.p == nil {
		return ""
	}
	return *s.p
}

// Empty reports whether no credential is set.
func (s Secret) Empty() bool { return s.p == nil || *s.p == "" }

// String is the marker.
func (Secret) String() string { return redacted }

// GoString is the marker.
func (Secret) GoString() string { return redacted }

// Format prints the marker for every verb except %p (fmt bypasses a Formatter for it; a Secret then prints an address, never the value).
func (Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// LogValue is the marker.
func (Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

// MarshalText is the marker.
func (Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// MarshalJSON is the marker.
func (Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
