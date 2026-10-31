// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

// TestInputRulesAcceptOnlyBoundedOpaqueTokens ports InputRulesAcceptOnlyBoundedOpaqueTokens (a C# row the corpus excludes) and adds
// the boundaries of every predicate.
func TestInputRulesAcceptOnlyBoundedOpaqueTokens(t *testing.T) {
	cases := []struct {
		name string
		got  bool
		want bool
	}{
		{"identifier with every allowed class", IsIdentifier("ws-1.A:b_c"), true},
		{"identifier 64 long", IsIdentifier(strings.Repeat("a", 64)), true},
		{"identifier 65 long", IsIdentifier(strings.Repeat("a", 65)), false},
		{"empty identifier", IsIdentifier(""), false},
		{"identifier with a slash", IsIdentifier("a/b"), false},
		{"identifier with a space", IsIdentifier("a b"), false},
		{"identifier with a non-ASCII letter", IsIdentifier("café"), false},
		{"key in capitals", IsKey("Upper"), false},
		{"dotted key", IsKey("cloud.storage.bytes"), true},
		{"key 128 long", IsKey(strings.Repeat("k", 128)), true},
		{"key 129 long", IsKey(strings.Repeat("k", 129)), false},
		{"opaque reference with capitals", IsOpaqueReference("Ticket:42_A"), true},
		{"opaque reference 129 long", IsOpaqueReference(strings.Repeat("r", 129)), false},
		{"actor with a newline", IsActor("bad\nactor"), false},
		{"actor with a tab", IsActor("bad\tactor"), false},
		{"actor of spaces", IsActor("   "), false},
		{"empty actor", IsActor(""), false},
		{"actor 128 units", IsActor(strings.Repeat("a", 128)), true},
		{"actor 129 units", IsActor(strings.Repeat("a", 129)), false},
		// C# counts UTF-16 units: a character outside the basic plane is two.
		{"actor of 64 astral characters", IsActor(strings.Repeat("\U0001F600", 64)), true},
		{"actor of 65 astral characters", IsActor(strings.Repeat("\U0001F600", 65)), false},
		{"reason of 512 units", IsReason(strings.Repeat("r", 512)), true},
		{"reason of 513 units", IsReason(strings.Repeat("r", 513)), false},
		{"reason of 256 astral characters", IsReason(strings.Repeat("\U0001F600", 256)), true},
		{"reason of 257 astral characters", IsReason(strings.Repeat("\U0001F600", 257)), false},
		{"reason with a C1 control", IsReason("a\u0085b"), false},
		{"reason with a no-break space inside text", IsReason("a b"), true},
		{"reason of no-break spaces", IsReason("  "), false},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
}

// TestMicrosConversionsKeepMicrosecondsAndFloorBeforeTheEpoch ports InstantsKeepMicrosecondPrecisionAndFloorBeforeTheEpoch.
func TestMicrosConversionsKeepMicrosecondsAndFloorBeforeTheEpoch(t *testing.T) {
	epoch := time.Unix(0, 0).UTC()
	cases := []struct {
		at   time.Time
		want Micros
	}{
		{epoch.Add(123_456_700 * time.Nanosecond), 123_456},
		{epoch.Add(-100 * time.Nanosecond), -1},
		{epoch.Add(-1000 * time.Nanosecond), -1},
		{epoch.Add(-1100 * time.Nanosecond), -2},
		{time.Date(1970, 1, 1, 2, 0, 0, 0, time.FixedZone("plus2", 2*3600)), 0},
	}
	for _, c := range cases {
		if got := FromTime(c.at); got != c.want {
			t.Errorf("FromTime(%v) = %d, want %d", c.at, got, c.want)
		}
	}
	if got := Micros(123_456).Time(); !got.Equal(epoch.Add(123_456*time.Microsecond)) || got.Location() != time.UTC {
		t.Errorf("Time() = %v", got)
	}
}

// TestSumOfQuotaLimitsRefusesToOverflow: the checked sum of the C# resolver is an explicit check here (the record bounds keep a real
// history far below it, so the check is exercised directly).
func TestSumOfQuotaLimitsRefusesToOverflow(t *testing.T) {
	grant := func(id string, limit int64) Grant {
		return Grant{GrantID: id, AccountID: "a", Kind: KindQuota, Subject: "q", Value: QuotaValue{Limit: limit}, Source: SourceSubscription, IssuedByActor: "x"}
	}
	grants := []Grant{grant("g1", math.MaxInt64), grant("g2", 1)}
	_, err := resolveQuota(QuotaDefinition{Key: "q", Combination: CombineSum}, grants, map[string]Micros{}, ServiceStateResult{}, StatusFact{}, 0)
	if !errors.Is(err, ErrOverflow) {
		t.Fatalf("an overflowing sum: %v", err)
	}
	result, err := resolveQuota(QuotaDefinition{Key: "q", Combination: CombineSum}, grants[:1], map[string]Micros{}, ServiceStateResult{}, StatusFact{}, 0)
	if err != nil || result.Limit != math.MaxInt64 {
		t.Fatalf("a sum that fits: %+v %v", result, err)
	}
}

// TestTheResolverFilesReadNoAmbientClockRandomnessOrFloatingPoint ports NoResolverSourceReadsAnAmbientClockOrRandomnessOrUsesBinaryFloatingPoint
// for the pure files of the package; the store and service files read time only through their injected clock.
func TestTheResolverFilesReadNoAmbientClockRandomnessOrFloatingPoint(t *testing.T) {
	for _, name := range []string{"records.go", "rules.go", "resolve.go", "content.go", "admission.go"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var code strings.Builder
		for line := range strings.SplitSeq(string(data), "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "//") {
				code.WriteString(line + "\n")
			}
		}
		for _, forbidden := range []string{"time.Now", "time.Since", "time.Until", "rand.", "float32", "float64", "math/rand", "crypto/rand", "os.Getenv", "sync.", "context."} {
			if strings.Contains(code.String(), forbidden) {
				t.Errorf("%s uses %s", name, forbidden)
			}
		}
	}
}

// TestTheResolverNamesNoProviderAndHardCodesNoCommercialFigureOrCapability ports the C# guard of the same name.
func TestTheResolverNamesNoProviderAndHardCodesNoCommercialFigureOrCapability(t *testing.T) {
	for _, name := range []string{"records.go", "rules.go", "resolve.go", "content.go", "admission.go"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"Paddle", "Payoneer", "Stripe", "cloud.sync", "cloud.ai", "cloud.storage", "isPro", "IsPro", "remote.control", "center.mcp"} {
			if strings.Contains(string(data), forbidden) {
				t.Errorf("%s names %s", name, forbidden)
			}
		}
	}
}

// TestRecordOrderNeverChangesTheResult: the resolver iterates sorted data only, so the order of the input records does not change the
// snapshot. The test reverses the grants, the terms and the status facts of one mixed history once (the C#
// FactsRecordedAtTheSameInstant... and EqualPriorities... rows, as a property over that history); it does not try every permutation.
func TestRecordOrderNeverChangesTheResult(t *testing.T) {
	definitions := Definitions{Version: "v1", Capabilities: []CapabilityDefinition{{Key: "a.cap", RequiresPaidTerm: true}, {Key: "b.cap"}},
		Quotas: []QuotaDefinition{{Key: "q.level", Combination: CombinePriorityReplace}, {Key: "q.sum", Combination: CombineSum}}, Allowances: []AllowanceDefinition{{Key: "al"}}}
	ref := func(value string) *string { return &value }
	until := Micros(50)
	records := RecordSet{AccountID: "acc", Grants: []Grant{
		{GrantID: "g1", AccountID: "acc", Kind: KindCapability, Subject: "a.cap", Value: CapabilityValue{}, Source: SourceSubscription, SourceRef: ref("s1"), EffectiveFrom: 0, IssuedByActor: "c", CreatedAt: 0},
		{GrantID: "g2", AccountID: "acc", Kind: KindQuota, Subject: "q.level", Value: QuotaValue{Limit: 1, Priority: 2}, Source: SourceSubscription, SourceRef: ref("s2"), EffectiveFrom: 0, IssuedByActor: "c"},
		{GrantID: "g3", AccountID: "acc", Kind: KindQuota, Subject: "q.level", Value: QuotaValue{Limit: 2, Priority: 2}, Source: SourceSubscription, SourceRef: ref("s3"), EffectiveFrom: 0, IssuedByActor: "c"},
		{GrantID: "g4", AccountID: "acc", Kind: KindQuota, Subject: "q.sum", Value: QuotaValue{Limit: 5}, Source: SourceStorageAddOn, SourceRef: ref("s4"), EffectiveFrom: 1, EffectiveUntil: &until, IssuedByActor: "c"},
		{GrantID: "g5", AccountID: "acc", Kind: KindAllowance, Subject: "al", Value: AllowanceValue{CapacityPlanRef: "plan", Priority: 1}, Source: SourceSubscription, SourceRef: ref("s5"), EffectiveFrom: 0, IssuedByActor: "c"},
	}, Terms: []ServiceTermFact{{TermID: "t1", Kind: TermSubscription, StartsAt: 0, EndsAt: 40, AuthorizedAt: 0}, {TermID: "t2", Kind: TermPass, StartsAt: 30, EndsAt: 80, AuthorizedAt: 30, CreatedAt: 5}},
		StatusFacts: []StatusFact{{RecordedAt: 10, Status: StatusNormal, AutoRenew: true}, {RecordedAt: 10, Status: StatusRestricted, AutoRenew: true}, {RecordedAt: 10, Status: StatusNormal, AutoRenew: false}}}
	baseline, err := Resolve(records, definitions, 60)
	if err != nil {
		t.Fatal(err)
	}
	reversed := records
	reversed.Grants = append([]Grant(nil), records.Grants...)
	reversed.Terms = append([]ServiceTermFact(nil), records.Terms...)
	reversed.StatusFacts = append([]StatusFact(nil), records.StatusFacts...)
	for i, j := 0, len(reversed.Grants)-1; i < j; i, j = i+1, j-1 {
		reversed.Grants[i], reversed.Grants[j] = reversed.Grants[j], reversed.Grants[i]
	}
	for i, j := 0, len(reversed.Terms)-1; i < j; i, j = i+1, j-1 {
		reversed.Terms[i], reversed.Terms[j] = reversed.Terms[j], reversed.Terms[i]
	}
	for i, j := 0, len(reversed.StatusFacts)-1; i < j; i, j = i+1, j-1 {
		reversed.StatusFacts[i], reversed.StatusFacts[j] = reversed.StatusFacts[j], reversed.StatusFacts[i]
	}
	other, err := Resolve(reversed, definitions, 60)
	if err != nil {
		t.Fatal(err)
	}
	if !baseline.SameAs(other) {
		t.Fatalf("the order of the records changed the result:\n%s\n%s", baseline.Content.Canonical(), other.Content.Canonical())
	}
}
