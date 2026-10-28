// SPDX-License-Identifier: AGPL-3.0-only

// Package correlation holds the call-scoped correlation identity of one admitted call (Design CR-01, CR-02, CR-03, CR-06,
// HP-06). It is a port of the C# host's CorrelationContext (src/ArcForges.Cloud/Ingress/Correlation.cs): one correlation
// identity per causal chain, the W3C trace and span identifiers that join this hop to the Worker's, and the causation id when
// the hop was started by a message rather than by the public request. It is a diagnostic fact and never an input to
// authorization.
package correlation

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

// Context is the correlation of one call.
type Context struct {
	// CorrelationID is a canonical lowercase hyphenated UUID; the trace id of the traceparent is exactly its 32 hex digits.
	CorrelationID string
	// ParentSpanID is the Worker's span (16 hex digits) when the traceparent that reached the center agrees with the
	// correlation id, and empty otherwise.
	ParentSpanID string
	// SpanID is this hop's own span (16 hex digits), created here.
	SpanID string
	// CausationID is the operation that caused this hop (a wake's originating request or previous event), or empty for a
	// public call.
	CausationID string
}

// TraceID is the correlation id without hyphens: the W3C trace id of the chain.
func (c Context) TraceID() string { return strings.ReplaceAll(c.CorrelationID, "-", "") }

// Traceparent is the traceparent this hop continues with: the same trace as the Worker's, this hop's span, sampled.
func (c Context) Traceparent() string { return "00-" + c.TraceID() + "-" + c.SpanID + "-01" }

// New is the identity of a new chain, created at this edge.
func New() Context { return Context{CorrelationID: NewCorrelationID(), SpanID: NewSpanID()} }

// Continue is a hop of an existing chain started by a message (a wake): the same correlation, a new span, the stated cause.
func Continue(correlationID, causationID string) Context {
	return Context{CorrelationID: correlationID, SpanID: NewSpanID(), CausationID: causationID}
}

// ForRequest is the correlation of a call: the validated envelope value, else the trace id of the Worker's traceparent,
// else a fresh identity. A traceparent that names a different trace than the identity chosen here is not a parent of this
// hop: the join is by identifier.
func ForRequest(traceparent []string, envelopeCorrelation string) Context {
	traceCorrelation, parent, parsed := ParseTraceparent(traceparent)
	correlation := envelopeCorrelation
	if correlation == "" && parsed {
		correlation = traceCorrelation
	}
	if correlation == "" {
		correlation = NewCorrelationID()
	}
	result := Context{CorrelationID: correlation, SpanID: NewSpanID()}
	if parsed && correlation == traceCorrelation {
		result.ParentSpanID = parent
	}
	return result
}

// ParseTraceparent reads a strict W3C traceparent: exactly one header value, version 00, lowercase hex, a nonzero trace id
// and a nonzero parent id. Anything else (a repeated header, another version, uppercase, extra text) is no traceparent; the
// center then creates its own identity.
func ParseTraceparent(values []string) (correlationID, parentSpanID string, ok bool) {
	if len(values) != 1 || len(values[0]) != 55 {
		return "", "", false
	}
	text := values[0]
	if text[:3] != "00-" || text[35] != '-' || text[52] != '-' {
		return "", "", false
	}
	trace, parent, flags := text[3:35], text[36:52], text[53:55]
	if !isLowerHex(trace) || !isLowerHex(parent) || !isLowerHex(flags) || isAllZero(trace) || isAllZero(parent) {
		return "", "", false
	}
	return trace[:8] + "-" + trace[8:12] + "-" + trace[12:16] + "-" + trace[16:20] + "-" + trace[20:], parent, true
}

// IsValidID reports whether text is a canonical lowercase hyphenated UUID that is not the nil UUID: the only accepted spelling
// of a correlation or causation id.
func IsValidID(text string) bool {
	if len(text) != 36 {
		return false
	}
	zero := true
	for index := range len(text) {
		character := text[index]
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !isLowerHexByte(character) {
				return false
			}
			if character != '0' {
				zero = false
			}
		}
	}
	return !zero
}

// FormatID is the canonical lowercase UUID text of 16 bytes in canonical (network) order.
func FormatID(id []byte) string {
	text := hex.EncodeToString(id)
	return text[:8] + "-" + text[8:12] + "-" + text[12:16] + "-" + text[16:20] + "-" + text[20:]
}

// IDBytes is the 16-byte value of a canonical correlation id, the value of an Id message. It returns nil for an invalid id.
func IDBytes(correlationID string) []byte {
	if !IsValidID(correlationID) {
		return nil
	}
	value, err := hex.DecodeString(strings.ReplaceAll(correlationID, "-", ""))
	if err != nil {
		return nil
	}
	return value
}

// NewCorrelationID is a random (version 4) UUID in canonical lowercase form.
func NewCorrelationID() string {
	var value [16]byte
	_, _ = rand.Read(value[:])
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return FormatID(value[:])
}

// NewSpanID is eight random bytes that are never all zero, as 16 lowercase hex digits.
func NewSpanID() string {
	var value [8]byte
	for {
		_, _ = rand.Read(value[:])
		if value != [8]byte{} {
			return hex.EncodeToString(value[:])
		}
	}
}

func isLowerHex(text string) bool {
	for index := range len(text) {
		if !isLowerHexByte(text[index]) {
			return false
		}
	}
	return true
}

func isLowerHexByte(character byte) bool {
	return character >= '0' && character <= '9' || character >= 'a' && character <= 'f'
}

func isAllZero(text string) bool { return strings.Trim(text, "0") == "" }
