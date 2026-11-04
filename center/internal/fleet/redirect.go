// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import "strings"

// The two loopback redirect forms of the browser node sign-in (CTR4-FLW-02; C0 "http://127.0.0.1:<port>/callback or
// http://[::1]:<port>/callback; <port> 1024..65535, decimal, no leading zero").
const (
	loopbackIPv4   = "http://127.0.0.1:"
	loopbackIPv6   = "http://[::1]:"
	loopbackSuffix = "/callback"
)

// ValidLoopbackRedirect admits a redirect URI only when it is byte for byte one of the two loopback forms with a decimal port from
// 1024 to 65535 without a leading zero or sign. Everything else is refused: another host form (localhost, 0.0.0.0, 127.1, a decimal,
// octal or hexadecimal address, an IPv6 zone or another literal, upper-case hexadecimal), userinfo, another scheme, a port outside
// the range, another path, a trailing slash, a query, a fragment, percent-encoding and any other byte. The center never takes a
// redirect target from an approval: it builds the redirect from the stored value (CodeRedirect, DenyRedirect).
func ValidLoopbackRedirect(uri string) bool {
	var rest string
	switch {
	case strings.HasPrefix(uri, loopbackIPv4):
		rest = uri[len(loopbackIPv4):]
	case strings.HasPrefix(uri, loopbackIPv6):
		rest = uri[len(loopbackIPv6):]
	default:
		return false
	}
	port, found := strings.CutSuffix(rest, loopbackSuffix)
	if !found || len(port) < 4 || len(port) > 5 || port[0] < '1' || port[0] > '9' {
		return false
	}
	value := 0
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
		value = value*10 + int(port[i]-'0')
	}
	return value >= 1024 && value <= 65535
}

// CodeRedirect is the redirect of an approval: the stored loopback URI with the one-use code and the client's state (both are
// unreserved characters, so nothing is encoded).
func CodeRedirect(stored, code, state string) string {
	return stored + "?code=" + code + "&state=" + state
}

// DenyRedirect is the redirect of a denial (the shape of NativeAuthorizeCallbackFailure): the stored loopback URI with
// error=access_denied and the client's state.
func DenyRedirect(stored, state string) string {
	return stored + "?error=access_denied&state=" + state
}
