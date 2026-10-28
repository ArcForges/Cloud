// SPDX-License-Identifier: AGPL-3.0-only

package correlation

import (
	"regexp"
	"strings"
	"testing"
)

const (
	trace  = "4bf92f3577b34da6a3ce929d0e0e4736"
	parent = "00f067aa0ba902b7"
	worker = "00-" + trace + "-" + parent + "-01"
	traced = "4bf92f35-77b3-4da6-a3ce-929d0e0e4736"
)

var strictTraceparent = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

func TestTheWorkerTraceparentJoinsThisHop(t *testing.T) {
	context := ForRequest([]string{worker}, "")
	if context.CorrelationID != traced || context.ParentSpanID != parent {
		t.Fatalf("join lost: %+v", context)
	}
	if context.SpanID == parent || len(context.SpanID) != 16 || !isLowerHex(context.SpanID) {
		t.Fatalf("this hop needs its own span: %q", context.SpanID)
	}
	if context.Traceparent() != "00-"+trace+"-"+context.SpanID+"-01" {
		t.Fatalf("traceparent of this hop: %q", context.Traceparent())
	}
}

func TestTheEnvelopeCorrelationWinsAndADifferentTraceIsNoParent(t *testing.T) {
	stated := "0a1b2c3d-0000-4000-8000-00000000000f"
	context := ForRequest([]string{worker}, stated)
	if context.CorrelationID != stated || context.ParentSpanID != "" {
		t.Fatalf("a traceparent of another trace became the parent: %+v", context)
	}
	same := ForRequest([]string{worker}, traced)
	if same.ParentSpanID != parent {
		t.Fatalf("an agreeing traceparent must stay the parent: %+v", same)
	}
}

func TestAMissingOrMalformedTraceparentCreatesAnIdentity(t *testing.T) {
	for _, values := range [][]string{
		nil,
		{},
		{worker, worker},
		{strings.ToUpper(worker)},
		{"01-" + trace + "-" + parent + "-01"},
		{"00-" + strings.Repeat("0", 32) + "-" + parent + "-01"},
		{"00-" + trace + "-" + strings.Repeat("0", 16) + "-01"},
		{"00-" + trace + "-" + parent + "-0g"},
		{worker + " "},
		{" " + worker[1:]},
		{"00_" + worker[3:]},
		{worker[:35] + "_" + worker[36:]},
	} {
		if _, _, ok := ParseTraceparent(values); ok {
			t.Fatalf("accepted %q", values)
		}
		context := ForRequest(values, "")
		if !IsValidID(context.CorrelationID) || context.ParentSpanID != "" {
			t.Fatalf("no fresh identity for %q: %+v", values, context)
		}
	}
}

func TestOnlyACanonicalNonNilUUIDIsAnIdentity(t *testing.T) {
	for _, valid := range []string{traced, "00000000-0000-0000-0000-000000000001"} {
		if !IsValidID(valid) {
			t.Fatalf("refused %q", valid)
		}
	}
	for _, invalid := range []string{
		"", "00000000-0000-0000-0000-000000000000", strings.ToUpper(traced), "{" + traced + "}", traced[:35],
		traced + "0", strings.ReplaceAll(traced, "-", ""), strings.Replace(traced, "-", "_", 1), " " + traced[1:],
	} {
		if IsValidID(invalid) {
			t.Fatalf("accepted %q", invalid)
		}
	}
}

func TestNewIdentitiesAreCanonicalAndDistinct(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		id := NewCorrelationID()
		if !IsValidID(id) || id[14] != '4' || !strings.ContainsRune("89ab", rune(id[19])) || seen[id] {
			t.Fatalf("not a fresh version 4 identity: %q", id)
		}
		seen[id] = true
		if FormatID(IDBytes(id)) != id {
			t.Fatalf("identity does not round-trip: %q", id)
		}
	}
	if IDBytes("not-an-id") != nil {
		t.Fatal("an invalid identity has no bytes")
	}
	continued := Continue(traced, "0a1b2c3d-0000-4000-8000-00000000000f")
	if continued.CorrelationID != traced || continued.CausationID == "" || continued.ParentSpanID != "" {
		t.Fatalf("continue: %+v", continued)
	}
	if fresh := New(); !IsValidID(fresh.CorrelationID) || len(fresh.SpanID) != 16 {
		t.Fatalf("new: %+v", fresh)
	}
}

// FuzzParseTraceparent checks the traceparent parser against an independent regular expression and its own round trip.
func FuzzParseTraceparent(f *testing.F) {
	for _, seed := range []string{worker, strings.ToUpper(worker), "", "00-", worker + "-", "00-" + strings.Repeat("0", 32) + "-" + parent + "-01"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		correlationID, parentSpanID, ok := ParseTraceparent([]string{value})
		want := strictTraceparent.MatchString(value) && strings.Trim(value[3:35], "0") != "" && strings.Trim(value[36:52], "0") != ""
		if ok != want {
			t.Fatalf("parser and oracle disagree on %q: %v", value, ok)
		}
		if !ok {
			return
		}
		if !IsValidID(correlationID) || parentSpanID != value[36:52] {
			t.Fatalf("invalid identity from %q", value)
		}
		if "00-"+strings.ReplaceAll(correlationID, "-", "")+"-"+parentSpanID+value[52:] != value {
			t.Fatalf("no round trip for %q", value)
		}
		joined := ForRequest([]string{value}, "")
		if joined.CorrelationID != correlationID || joined.ParentSpanID != parentSpanID {
			t.Fatalf("join differs for %q", value)
		}
	})
}
