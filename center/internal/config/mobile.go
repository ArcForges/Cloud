// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
)

// The environment of the mobile surface (AF-CTR-04 part M).
const (
	// EnvAndroidApp is the Android app identity the center publishes in /.well-known/assetlinks.json (the statements Android's App Link
	// verifier and Credential Manager read): a JSON array of {"packageName", "sha256CertFingerprints", optional "testOnly": true}.
	// Unset, empty or [] publishes an empty list. Production leaves it unset; proof sets a labelled non-shipping test statement (Q-1).
	EnvAndroidApp = "ARCFORGES_CENTER_ANDROID_APP"
	// EnvMobileDebugRedirect is the private-use URI scheme of the debug app (arcforges.android.local): a lower-case reverse-DNS name
	// with at least one dot (RFC 8252 section 7.1). The center admits exactly <scheme>:/callback for the debug client while it is
	// set, and only on a self-hosted center: an official-hosted center refuses to start when the variable is present (MB-9).
	EnvMobileDebugRedirect = "ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT"
)

// MaxMobilePublicBaseURLLength bounds the public base URL of a center that serves the mobile surface: the contract bounds the
// authorization page's URL at 512 characters and the issuer at 453 (MobileNativeAuth: <base>/mobile/authorize#flow=<flow ID> is the
// base and 59 characters).
const MaxMobilePublicBaseURLLength = 512 - 59

// The bounds of the Android app identity: at most 4 apps (a release and a few test builds), each with 1 to 4 certificate fingerprints
// (the upload key and the Play app-signing key, MB-8), in a document of at most 4096 bytes.
const (
	MaxAndroidApps              = 4
	MaxAndroidFingerprints      = 4
	MaxAndroidAppDocumentBytes  = 4096
	MaxMobileDebugSchemeLength  = 100
	androidFingerprintSeparator = ":"
)

var (
	// androidPackage is an Android application ID: two or more dot-separated segments, each a letter then letters, digits or '_'.
	androidPackage = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$`)
	// androidFingerprint is a SHA-256 certificate fingerprint as Digital Asset Links write it: 32 upper-case hexadecimal pairs
	// separated by colons.
	androidFingerprint = regexp.MustCompile(`^([0-9A-F]{2}:){31}[0-9A-F]{2}$`)
	// debugScheme is the strict reverse-DNS grammar of the debug app's scheme: lower-case labels of letters and digits (a label may
	// contain inner hyphens), at least two labels, the first starting with a letter. It is stricter than the contract's form (which
	// admits '+', empty labels and a trailing dot): the expected-divergence table of center/internal/mobileauth records it.
	debugScheme = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*(?:\.[a-z0-9]+(?:-[a-z0-9]+)*)+$`)
)

// mobileIssuer is the contract's form of an issuer (MobileNativeAuth MobileAuthorizeCallbackSuccess.iss and Failure.iss): https with
// a lower-case host of letters, digits, hyphens and dots, or http for a loopback host, an optional port and optional clean path
// segments. The center's public base URL grammar (ParsePublicBaseURL) admits hosts this form does not (an underscore, an IPv6
// literal other than [::1] over https): a center whose base URL is not an issuer cannot serve the mobile surface.
var mobileIssuer = regexp.MustCompile(`^(?:https://[a-z0-9-]+(?:\.[a-z0-9-]+)*|http://(?:localhost|127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|\[::1\]))(?::[1-9][0-9]{0,4})?(?:/[A-Za-z0-9._~-]+)*$`)

// MobileIssuerPattern is the issuer form's regular expression (the vector replay compares it with the contract's pattern).
func MobileIssuerPattern() string { return mobileIssuer.String() }

// ValidMobileIssuer reports whether a public base URL is an issuer the contract admits: the issuer form, at most
// MaxMobilePublicBaseURLLength (453) characters.
func ValidMobileIssuer(publicBaseURL string) bool {
	return len(publicBaseURL) <= MaxMobilePublicBaseURLLength && mobileIssuer.MatchString(publicBaseURL)
}

// reservedSchemes are the schemes the debug app's scheme can never be (MB-9), even though the grammar's dot already refuses them.
var reservedSchemes = []string{"http", "https", "file", "javascript", "data", "intent", "content", "android-app", "about", "blob", "ws", "wss"}

// AndroidApp is one app identity of the asset links statement.
type AndroidApp struct {
	PackageName  string
	Fingerprints []string
	// TestOnly labels a non-shipping test statement (proof's, Q-1): the center logs it at start; the statement is published as any.
	TestOnly bool
}

// Mobile is the configuration of the mobile surface.
type Mobile struct {
	// AndroidApps is the published app identity (none: an empty statement list).
	AndroidApps []AndroidApp
	// DebugScheme is the debug app's private-use scheme, or empty (the debug client is then not admitted).
	DebugScheme string
}

// DebugRedirect is the one redirect the debug client may register, or empty.
func (m Mobile) DebugRedirect() string {
	if m.DebugScheme == "" {
		return ""
	}
	return m.DebugScheme + ":/callback"
}

// TestOnly reports whether a configured app identity is labelled a non-shipping test statement.
func (m Mobile) TestOnly() bool {
	return slices.ContainsFunc(m.AndroidApps, func(app AndroidApp) bool { return app.TestOnly })
}

// ValidDebugScheme admits a debug app scheme: the strict reverse-DNS grammar, at most 100 characters, never a reserved scheme.
func ValidDebugScheme(scheme string) bool {
	return len(scheme) <= MaxMobileDebugSchemeLength && debugScheme.MatchString(scheme) && !slices.Contains(reservedSchemes, scheme)
}

// loadMobile reads the mobile configuration of a mode.
func loadMobile(lookup func(string) (string, bool), mode Mode) (Mobile, error) {
	var mobile Mobile
	if scheme, present := lookup(EnvMobileDebugRedirect); present {
		if mode != SelfHosted {
			return Mobile{}, invalid("%s applies to a self-hosted center only: an official-hosted center never admits the debug app", EnvMobileDebugRedirect)
		}
		if !ValidDebugScheme(scheme) {
			return Mobile{}, invalid("%s must be a lower-case reverse-DNS scheme with at least one dot (for example com.arcforges.android.debug)",
				EnvMobileDebugRedirect)
		}
		mobile.DebugScheme = scheme
	}
	value, _ := lookup(EnvAndroidApp)
	apps, err := ParseAndroidApps(value)
	if err != nil {
		return Mobile{}, invalid("%s: %v", EnvAndroidApp, err)
	}
	mobile.AndroidApps = apps
	return mobile, nil
}

// ParseAndroidApps reads the Android app identity document: empty or [] is none; otherwise a JSON array of 1 to 4 objects with exactly
// the keys packageName (an Android application ID), sha256CertFingerprints (1 to 4 distinct fingerprints) and optionally testOnly
// (true only: false, null or any other value refuses). Unknown or repeated keys, a repeated package, anything after the array (even a
// lone ] or }) and anything else refuse.
func ParseAndroidApps(document string) ([]AndroidApp, error) {
	if document == "" || document == "[]" {
		return nil, nil
	}
	if len(document) > MaxAndroidAppDocumentBytes {
		return nil, errors.New("longer than 4096 bytes")
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(document)))
	decoder.DisallowUnknownFields()
	var raw []json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, errors.New("not one JSON array")
	}
	// Decoder.More reports false before a ] or }, so the end of the document is required explicitly.
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("not one JSON array")
	}
	if len(raw) > MaxAndroidApps {
		return nil, fmt.Errorf("at most %d apps", MaxAndroidApps)
	}
	var apps []AndroidApp
	for index, item := range raw {
		if err := refuseRepeatedKeys(string(item)); err != nil {
			return nil, fmt.Errorf("app %d: %v", index, err)
		}
		var entry struct {
			PackageName  *string         `json:"packageName"`
			Fingerprints []string        `json:"sha256CertFingerprints"`
			TestOnly     json.RawMessage `json:"testOnly"`
		}
		strict := json.NewDecoder(bytes.NewReader(item))
		strict.DisallowUnknownFields()
		if err := strict.Decode(&entry); err != nil {
			return nil, fmt.Errorf("app %d: not an object of packageName, sha256CertFingerprints and testOnly", index)
		}
		switch {
		case entry.PackageName == nil || !androidPackage.MatchString(*entry.PackageName) || len(*entry.PackageName) > 255:
			return nil, fmt.Errorf("app %d: packageName is not an Android application ID", index)
		case len(entry.Fingerprints) < 1 || len(entry.Fingerprints) > MaxAndroidFingerprints:
			return nil, fmt.Errorf("app %d: sha256CertFingerprints needs 1 to %d fingerprints", index, MaxAndroidFingerprints)
		case entry.TestOnly != nil && string(entry.TestOnly) != "true":
			return nil, fmt.Errorf("app %d: testOnly is true or absent", index)
		}
		for _, fingerprint := range entry.Fingerprints {
			if !androidFingerprint.MatchString(fingerprint) || strings.Count(fingerprint, androidFingerprintSeparator) != 31 {
				return nil, fmt.Errorf("app %d: a fingerprint is not 32 upper-case hexadecimal pairs separated by colons", index)
			}
		}
		sorted := slices.Clone(entry.Fingerprints)
		slices.Sort(sorted)
		if len(slices.Compact(sorted)) != len(entry.Fingerprints) {
			return nil, fmt.Errorf("app %d: a fingerprint is listed twice", index)
		}
		if slices.ContainsFunc(apps, func(app AndroidApp) bool { return app.PackageName == *entry.PackageName }) {
			return nil, fmt.Errorf("app %d: the package is listed twice", index)
		}
		apps = append(apps, AndroidApp{PackageName: *entry.PackageName, Fingerprints: slices.Clone(entry.Fingerprints), TestOnly: string(entry.TestOnly) == "true"})
	}
	if len(apps) == 0 {
		return nil, nil
	}
	return apps, nil
}
