// SPDX-License-Identifier: AGPL-3.0-only

package ratelimit

import (
	"net/netip"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
)

func TestClientAddressesKeyByTheirNetwork(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":            "203.0.113.0/24",
		"203.0.113.250":          "203.0.113.0/24",
		"::ffff:203.0.113.9":     "203.0.113.0/24",
		"2001:db8:aa:bbcc::1":    "2001:db8:aa:bb00::/56",
		"2001:db8:aa:bbff:1::99": "2001:db8:aa:bb00::/56",
	}
	for text, want := range cases {
		if got := Prefix(netip.MustParseAddr(text)); got != want {
			t.Errorf("%s: %s, want %s", text, got, want)
		}
	}
	if Prefix(netip.Addr{}) != "unknown" {
		t.Fatal("an unknown address")
	}
	if Prefix(netip.MustParseAddr("203.0.113.7")) == Prefix(netip.MustParseAddr("203.0.114.7")) {
		t.Fatal("two /24 networks share a bucket")
	}
}

func TestBucketsAreDistinctPerKindAndKey(t *testing.T) {
	policy := config.DefaultIdentityPolicy()
	seen := map[[32]byte]bool{}
	for _, kind := range Kinds() {
		window := Window(policy, kind)
		// The anonymous-flow ceiling is the one opt-in kind (C1): by default its limit is 0, so no global bucket is counted.
		if kind == AnonymousFlows && (window.Limit != 0 || window.Window < time.Minute) ||
			kind != AnonymousFlows && (window.Limit < 1 || window.Window < time.Minute) {
			t.Fatalf("%s has no window", kind)
		}
		for _, key := range []string{"a", "b"} {
			hash := Bucket{Kind: kind, Key: key, Window: window}.Hash()
			if seen[hash] {
				t.Fatalf("%s %s collides", kind, key)
			}
			seen[hash] = true
		}
	}
	decision := Decision{RetryAt: time.Unix(100, 0)}
	refusal := decision.Refusal(Bucket{Kind: SignInPrefix, Key: "k", Window: policy.SignInPerPrefix})
	if refusal.Key() != "RESOURCE/rate_limited" || refusal.Limit.Name != "sign_in_prefix" || refusal.Limit.Maximum != 30 || !refusal.RetryAt.Equal(time.Unix(100, 0)) {
		t.Fatalf("refusal %+v", refusal)
	}
}
