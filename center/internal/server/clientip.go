// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/ingress"
)

// ClientAddress is the client's address of a surface call, which keys the rate limits (PLT-2, PLT-16, SEC-17):
//   - official-hosted: exactly one value of the Worker's header (set from cf-connecting-ip, overwriting any client value), which
//     must parse as one IP address; otherwise the address is unknown and the pipeline refuses the call, so a missing header is
//     never counted in a shared bucket;
//   - self-hosted: the TCP peer, or exactly one valid value of the header when the peer is a configured trusted proxy.
//
// An IPv4-mapped IPv6 address is taken as IPv4. The address is never logged.
func ClientAddress(mode config.Mode, identity config.Identity) func(*http.Request) (netip.Addr, bool) {
	return func(request *http.Request) (netip.Addr, bool) {
		if mode == config.OfficialHosted {
			if identity.ClientIPHeader == "" {
				return netip.Addr{}, false
			}
			return headerAddress(request.Header.Values(identity.ClientIPHeader))
		}
		peer, ok := peerAddress(request.RemoteAddr)
		if !ok {
			return netip.Addr{}, false
		}
		if identity.ClientIPHeader != "" {
			for _, proxy := range identity.TrustedProxies {
				if proxy.Contains(peer) {
					if forwarded, ok := headerAddress(request.Header.Values(identity.ClientIPHeader)); ok {
						return forwarded, true
					}
					return peer, true
				}
			}
		}
		return peer, true
	}
}

// headerAddress is the address of exactly one header value that is exactly one IP address (no port, zone, list or space).
func headerAddress(values []string) (netip.Addr, bool) {
	if len(values) != 1 {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(values[0])
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}

func peerAddress(remote string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}, false
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return address.WithZone("").Unmap(), true
}

// ClientOrigin is the coarse origin of a surface call (protocol-17): in official-hosted mode exactly one value of each of the Worker's
// origin headers, a country that is two upper-case letters other than XX (Cloudflare's "unknown"; its T1 for Tor is no country and is
// unknown too) and an autonomous system number of 1 to 4294967295 in canonical decimal; anything else is unknown. A self-hosted
// center knows no origin whatever its trusted proxies (AF-CTR-04 E3, B-1): a proxy configured for the client address header passes
// other client headers through, so the values would be the client's own claim, and the review page's origin line would be forgeable
// by the node that asks to be approved.
func ClientOrigin(mode config.Mode) func(*http.Request) ingress.Origin {
	return func(request *http.Request) ingress.Origin {
		if mode != config.OfficialHosted {
			return ingress.Origin{}
		}
		var origin ingress.Origin
		if values := request.Header.Values(config.ClientCountryHeader); len(values) == 1 && validCountry(values[0]) {
			origin.Country = values[0]
		}
		if values := request.Header.Values(config.ClientASNHeader); len(values) == 1 {
			if asn, err := strconv.ParseUint(values[0], 10, 32); err == nil && asn > 0 && strconv.FormatUint(asn, 10) == values[0] {
				origin.ASN = int64(asn)
			}
		}
		return origin
	}
}

func validCountry(value string) bool {
	return len(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z' && value != "XX"
}
