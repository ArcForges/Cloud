// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net"
	"net/http"
	"net/netip"

	"github.com/ArcForges/Cloud/center/internal/config"
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
