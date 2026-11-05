// SPDX-License-Identifier: AGPL-3.0-only

package mobileauth

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// The redirects and URLs of the flow (MB-2, MB-6, MB-9, MB-10). The center admits exactly one redirect per client and never takes a
// redirect target from an approval: it builds the callback from the stored redirect only.

// AppCallbackPath is the release app's verified App Link path at the origin of the public base URL (Q-3: there is no other link
// origin).
const AppCallbackPath = "/app/callback"

// AuthorizePath is the authorization page below the public base URL.
const AuthorizePath = "/mobile/authorize"

// releaseForm is the contract's form of the release client's redirect (MobileBeginRequest.redirectUri, the https alternative): an
// https origin whose host has a letter top-level label (so no loopback name or IP literal), an optional port, the exact path.
var releaseForm = regexp.MustCompile(`^https://[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z][a-z0-9-]*(?::[1-9][0-9]{0,4})?/app/callback$`)

// ValidIssuer reports whether a public base URL is an issuer the contract admits (config.ValidMobileIssuer): a center whose public
// base URL is not one cannot serve the mobile surface (the configuration refuses it, or leaves it out of the self-hosted default).
func ValidIssuer(publicBaseURL string) bool { return config.ValidMobileIssuer(publicBaseURL) }

// ReleaseRedirect is the release client's one redirect on a center: <origin of the public base URL>/app/callback, or "" when that is
// not of the contract's release form (an http center, an IP or loopback host): such a center admits no release client.
func ReleaseRedirect(publicBaseURL string) string {
	scheme, rest, ok := strings.Cut(publicBaseURL, "://")
	if !ok {
		return ""
	}
	host, _, _ := strings.Cut(rest, "/")
	redirect := scheme + "://" + host + AppCallbackPath
	if !releaseForm.MatchString(redirect) {
		return ""
	}
	return redirect
}

// AdmitRedirect reports whether a client may register a redirect here: the release client exactly its release redirect, the debug
// client exactly its configured private-use redirect (only while one is configured, on a self-hosted center). Every other pair is
// redirectUri: not_admitted.
func (s *Service) AdmitRedirect(clientID, redirectURI string) bool {
	switch clientID {
	case ClientRelease:
		return s.release != "" && redirectURI == s.release
	case ClientDebug:
		return s.debug != "" && redirectURI == s.debug
	}
	return false
}

// ReleaseRedirect is this center's release redirect ("" when it admits no release client).
func (s *Service) ReleaseRedirect() string { return s.release }

// DebugRedirect is this center's debug redirect ("" when it admits no debug client).
func (s *Service) DebugRedirect() string { return s.debug }

// AuthorizeURL is the authorization page of a flow: <public base URL>/mobile/authorize#flow=<flow ID> with the flow ID in its
// lower-case 8-4-4-4-12 form (the app derives the same string from its configured center and requires a byte-equal reply, MB-2).
func AuthorizeURL(publicBaseURL string, flowID platform.ID) string {
	return publicBaseURL + AuthorizePath + "#flow=" + flowID.String()
}

// SuccessRedirect is the callback of an approval (MobileAuthorizeCallbackSuccess): the stored redirect with the fragment
// code=<code>&state=<state>&iss=<issuer>, application/x-www-form-urlencoded in this order; the code and the state are unreserved
// characters, the issuer is percent-encoded.
func SuccessRedirect(stored, code, state, issuer string) string {
	return stored + "#code=" + code + "&state=" + state + "&iss=" + url.QueryEscape(issuer)
}

// DenyRedirect is the callback of a denial (MobileAuthorizeCallbackFailure): the stored redirect with the fragment
// error=access_denied&state=<state>&iss=<issuer> in this order.
func DenyRedirect(stored, state, issuer string) string {
	return stored + "#error=access_denied&state=" + state + "&iss=" + url.QueryEscape(issuer)
}
