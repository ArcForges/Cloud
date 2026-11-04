// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/config"
)

func request(remote string, values ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/x", nil)
	r.RemoteAddr = remote
	for _, value := range values {
		r.Header.Add(config.ClientIPHeader, value)
	}
	return r
}

func TestTheHostedCenterTakesExactlyOneWorkerAddress(t *testing.T) {
	address := ClientAddress(config.OfficialHosted, config.Identity{ClientIPHeader: config.ClientIPHeader})
	accepted := map[string]string{"203.0.113.7": "203.0.113.7", "2001:db8::1": "2001:db8::1", "::ffff:203.0.113.7": "203.0.113.7"}
	for value, want := range accepted {
		got, ok := address(request("10.0.0.1:443", value))
		if !ok || got != netip.MustParseAddr(want) {
			t.Errorf("%q: %v %v", value, got, ok)
		}
	}
	for _, values := range [][]string{nil, {""}, {"203.0.113.7", "203.0.113.8"}, {"203.0.113.7, 203.0.113.8"}, {" 203.0.113.7"}, {"203.0.113.7:80"},
		{"fe80::1%eth0"}, {"example.org"}, {"203.0.113.07"}} {
		if got, ok := address(request("203.0.113.1:443", values...)); ok {
			t.Errorf("%q was taken as %v", values, got)
		}
	}
	if _, ok := ClientAddress(config.OfficialHosted, config.Identity{})(request("203.0.113.1:443", "203.0.113.7")); ok {
		t.Fatal("a hosted center without the header setting read an address")
	}
}

func TestASelfHostedCenterTrustsOnlyItsProxies(t *testing.T) {
	plain := ClientAddress(config.SelfHosted, config.Identity{})
	if got, ok := plain(request("198.51.100.4:5000", "203.0.113.7")); !ok || got != netip.MustParseAddr("198.51.100.4") {
		t.Fatalf("the peer: %v %v", got, ok)
	}
	proxied := ClientAddress(config.SelfHosted, config.Identity{ClientIPHeader: config.ClientIPHeader,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	if got, ok := proxied(request("10.1.2.3:5000", "203.0.113.7")); !ok || got != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("a trusted proxy's header: %v %v", got, ok)
	}
	if got, ok := proxied(request("10.1.2.3:5000", "203.0.113.7", "203.0.113.8")); !ok || got != netip.MustParseAddr("10.1.2.3") {
		t.Fatalf("a repeated header falls back to the peer: %v %v", got, ok)
	}
	if got, ok := proxied(request("198.51.100.4:5000", "203.0.113.7")); !ok || got != netip.MustParseAddr("198.51.100.4") {
		t.Fatalf("an untrusted peer's header: %v %v", got, ok)
	}
	if got, ok := proxied(request("[::ffff:10.1.2.3]:5000", "203.0.113.7")); !ok || got != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("an IPv4-mapped proxy: %v %v", got, ok)
	}
	if _, ok := plain(request("not an address")); ok {
		t.Fatal("an unparsable peer")
	}
}

func FuzzClientAddressHeader(f *testing.F) {
	for _, seed := range []string{"203.0.113.7", "::1", "::ffff:1.2.3.4", "1.2.3.4, 5.6.7.8", "fe80::1%x", "", "999.1.1.1"} {
		f.Add(seed)
	}
	address := ClientAddress(config.OfficialHosted, config.Identity{ClientIPHeader: config.ClientIPHeader})
	f.Fuzz(func(t *testing.T, value string) {
		r := httptest.NewRequest(http.MethodPost, "/x", nil)
		r.Header[http.CanonicalHeaderKey(config.ClientIPHeader)] = []string{value}
		got, ok := address(r)
		if !ok {
			return
		}
		if !got.IsValid() || got.Zone() != "" || got.Is4In6() {
			t.Fatalf("%q gave %v", value, got)
		}
		parsed, err := netip.ParseAddr(value)
		if err != nil || parsed.Unmap() != got {
			t.Fatalf("%q is not one address", value)
		}
	})
}

// TestTheOriginIsTheHostedEdgesOnly (AF-CTR-04 E3, protocol-17, B-1): an official-hosted center reads exactly one valid value of each
// origin header the Worker sets; a self-hosted center reads none, also from a trusted proxy, so a client cannot name its own origin.
func TestTheOriginIsTheHostedEdgesOnly(t *testing.T) {
	origin := func(mode config.Mode, remote string, headers map[string][]string) (string, int64) {
		r := request(remote, "203.0.113.7")
		for name, values := range headers {
			for _, value := range values {
				r.Header.Add(name, value)
			}
		}
		got := ClientOrigin(mode)(r)
		return got.Country, got.ASN
	}
	both := map[string][]string{config.ClientCountryHeader: {"DE"}, config.ClientASNHeader: {"3320"}}
	if country, asn := origin(config.OfficialHosted, "10.0.0.1:443", both); country != "DE" || asn != 3320 {
		t.Fatalf("hosted: %q %d", country, asn)
	}
	for _, remote := range []string{"127.0.0.1:443", "10.0.0.1:443", "[::1]:443"} {
		if country, asn := origin(config.SelfHosted, remote, both); country != "" || asn != 0 {
			t.Fatalf("self-hosted from %s: %q %d", remote, country, asn)
		}
	}
	for _, bad := range []map[string][]string{
		{config.ClientCountryHeader: {"de"}, config.ClientASNHeader: {"0"}},
		{config.ClientCountryHeader: {"XX"}, config.ClientASNHeader: {"03320"}},
		{config.ClientCountryHeader: {"T1"}, config.ClientASNHeader: {"4294967296"}},
		{config.ClientCountryHeader: {"DEU"}, config.ClientASNHeader: {"-1"}},
		{config.ClientCountryHeader: {"DE", "FR"}, config.ClientASNHeader: {"1", "2"}},
		{config.ClientCountryHeader: {" DE"}, config.ClientASNHeader: {"+3320"}},
		{config.ClientCountryHeader: {""}, config.ClientASNHeader: {"33 20"}},
	} {
		if country, asn := origin(config.OfficialHosted, "10.0.0.1:443", bad); country != "" || asn != 0 {
			t.Errorf("%v: %q %d", bad, country, asn)
		}
	}
	if country, asn := origin(config.OfficialHosted, "10.0.0.1:443", map[string][]string{config.ClientCountryHeader: {"US"},
		config.ClientASNHeader: {"4294967295"}}); country != "US" || asn != 4294967295 {
		t.Fatalf("the bounds: %q %d", country, asn)
	}
}
