// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"regexp"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/mobileauth"
)

// The strict reading of the MobileNativeAuth request bodies (Contracts public/http/v1/mobile-native.schema.json, MobileBeginRequest
// and MobileTokenRequest): each is one JSON object without a repeated key or an unknown member, whose members meet the document's
// types, lengths and patterns, with the same reader as the WebBrowserSession bodies (jsonin.go). A refusal is
// VALIDATION/invalid_argument naming the member by its JSON path. Shape validity is not flow, code, verifier, redirect, installation or
// issuer authorization: package mobileauth decides those (the exact redirect this center admits, the claim's platform family, the
// code compare, the verifier and the binding).

var (
	// mobileRedirectForm is the contract's form of a client redirect (the release App Link or the debug private-use scheme); the
	// center then admits exactly its own value for the client.
	mobileRedirectForm = regexp.MustCompile(`^(?:https://[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z][a-z0-9-]*(?::[1-9][0-9]{0,4})?/app/callback|[a-z][a-z0-9.+-]*\.[a-z0-9.+-]+:/callback)$`)
	// mobileChallenge is a PKCE S256 challenge: 43 base64url characters.
	mobileChallenge = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	// mobileState is a client state: 16 to 128 unreserved characters.
	mobileState = regexp.MustCompile(`^[A-Za-z0-9._~-]{16,128}$`)
	// mobileVerifier is a PKCE verifier: 43 to 128 unreserved characters (RFC 7636 section 4.1).
	mobileVerifier = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	// mobileCode is a one-use code: the canonical unpadded base64url of 32 bytes (its last character carries 4 bits and two zero
	// bits, so it is one of 16 characters).
	mobileCode = regexp.MustCompile(`^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`)
	// mobilePlatform is the contract's platform of the claim: android, optionally followed by a separator and more claim text, in
	// lower case. It is stricter than device.MobilePlatform, which reads the family case-insensitively (the expected-divergence table
	// of the vector replay pins both).
	mobilePlatform = regexp.MustCompile(`^android(?:[0-9._:/-][A-Za-z0-9._:/-]{0,120})?$`)
)

var mobileClients = []string{mobileauth.ClientRelease, mobileauth.ClientDebug}

// parseMobileBegin reads a MobileBeginRequest.
func parseMobileBegin(data []byte) (mobileauth.BeginRequest, *arc.Refusal) {
	root, refusal := parseObject(data, "", "clientId", "redirectUri", "codeChallenge", "codeChallengeMethod", "state", "installation")
	if refusal != nil {
		return mobileauth.BeginRequest{}, refusal
	}
	var result mobileauth.BeginRequest
	if result.ClientID, refusal = root.requiredText("clientId", textRule{enum: mobileClients}); refusal != nil {
		return mobileauth.BeginRequest{}, refusal
	}
	if result.RedirectURI, refusal = root.requiredText("redirectUri", textRule{min: 13, max: 512, pattern: mobileRedirectForm}); refusal != nil {
		return mobileauth.BeginRequest{}, refusal
	}
	if result.CodeChallenge, refusal = root.requiredText("codeChallenge", textRule{min: 43, max: 43, pattern: mobileChallenge}); refusal != nil {
		return mobileauth.BeginRequest{}, refusal
	}
	if _, refusal = root.requiredText("codeChallengeMethod", textRule{enum: []string{"S256"}}); refusal != nil {
		return mobileauth.BeginRequest{}, refusal
	}
	if result.State, refusal = root.requiredText("state", textRule{min: 16, max: 128, pattern: mobileState}); refusal != nil {
		return mobileauth.BeginRequest{}, refusal
	}
	if result.Claim, refusal = parseMobileClaim(root); refusal != nil {
		return mobileauth.BeginRequest{}, refusal
	}
	if !clientRedirectForm(result.ClientID, result.RedirectURI) {
		return mobileauth.BeginRequest{}, arc.InvalidArgument("redirectUri", "client_mismatch")
	}
	return result, nil
}

// parseMobileClaim reads a MobileInstallationClaim.
func parseMobileClaim(root object) (device.Claim, *arc.Refusal) {
	claim, refusal := root.requiredChild("installation", "installationId", "product", "platform", "appVersion")
	if refusal != nil {
		return device.Claim{}, refusal
	}
	var result device.Claim
	if result.InstallationID, refusal = claim.requiredUUID("installationId"); refusal != nil {
		return device.Claim{}, refusal
	}
	if result.Product, refusal = claim.requiredText("product", textRule{enum: []string{mobileauth.Product}}); refusal != nil {
		return device.Claim{}, refusal
	}
	if result.Platform, refusal = claim.requiredText("platform", textRule{min: 7, max: 128, pattern: mobilePlatform}); refusal != nil {
		return device.Claim{}, refusal
	}
	if result.AppVersion, refusal = claim.requiredText("appVersion", textRule{min: 1, max: 128, pattern: textPattern}); refusal != nil {
		return device.Claim{}, refusal
	}
	return result, nil
}

// parseMobileToken reads a MobileTokenRequest.
func parseMobileToken(data []byte) (mobileauth.TokenRequest, *arc.Refusal) {
	root, refusal := parseObject(data, "", "flowId", "code", "codeVerifier", "clientId", "redirectUri", "installationId")
	if refusal != nil {
		return mobileauth.TokenRequest{}, refusal
	}
	var result mobileauth.TokenRequest
	if result.FlowID, refusal = root.requiredUUID("flowId"); refusal != nil {
		return mobileauth.TokenRequest{}, refusal
	}
	if result.Code, refusal = root.requiredText("code", textRule{min: 43, max: 43, pattern: mobileCode}); refusal != nil {
		return mobileauth.TokenRequest{}, refusal
	}
	if result.Verifier, refusal = root.requiredText("codeVerifier", textRule{min: 43, max: 128, pattern: mobileVerifier}); refusal != nil {
		return mobileauth.TokenRequest{}, refusal
	}
	if result.ClientID, refusal = root.requiredText("clientId", textRule{enum: mobileClients}); refusal != nil {
		return mobileauth.TokenRequest{}, refusal
	}
	if result.RedirectURI, refusal = root.requiredText("redirectUri", textRule{min: 13, max: 512, pattern: mobileRedirectForm}); refusal != nil {
		return mobileauth.TokenRequest{}, refusal
	}
	if result.InstallationID, refusal = root.requiredUUID("installationId"); refusal != nil {
		return mobileauth.TokenRequest{}, refusal
	}
	// The rule mobileClientRedirect: the release client takes the App Link form, the debug client the private-use form.
	if !clientRedirectForm(result.ClientID, result.RedirectURI) {
		return mobileauth.TokenRequest{}, arc.InvalidArgument("redirectUri", "client_mismatch")
	}
	return result, nil
}

// releaseRedirectForm is the release alternative of mobileRedirectForm.
var releaseRedirectForm = regexp.MustCompile(`^https://`)

// clientRedirectForm is the contract's rule mobileClientRedirect: arcforges.android takes the https App Link form,
// arcforges.android.local the private-use scheme form.
func clientRedirectForm(clientID, redirectURI string) bool {
	release := releaseRedirectForm.MatchString(redirectURI)
	return clientID == mobileauth.ClientRelease && release || clientID == mobileauth.ClientDebug && !release
}
