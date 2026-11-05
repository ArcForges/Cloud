// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/mobileauth"
	"github.com/ArcForges/Cloud/center/internal/mobiletest"
	"github.com/ArcForges/Cloud/center/internal/oneuse"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// The Go replay of the Contracts MobileNativeAuth vectors (AF-CTR-04 part M, contracts-15): the document and its 120 shared vectors
// are vendored byte for byte at the published cohort (center/internal/mobileauth/testdata, with their source commit, the cohort
// version and the SHA-256 of the document and of the fixture they came from). Every vector is replayed through what the center or
// the app stand-in does with that shape, and the verdict must be the contract's, except where the expected-divergence table says
// why the center differs; each row of the table is pinned by its own check.

// Cohort is the published Contracts cohort the vendored document and vectors are pinned to (Contracts #127, CI run 430).
const (
	cohort         = "1.0.0-ci.430.1"
	cohortCommit   = "5873dc24d4452adc2306f3e0bc6fb477add911e9"
	vectorsFile    = "../mobileauth/testdata/mobile-native-vectors.json"
	documentFile   = "../mobileauth/testdata/mobile-native.schema.json"
	officialIssuer = "https://arcforges.com/api"
)

type mobileVector struct {
	ID        string `json:"id"`
	Root      string `json:"root"`
	Wire      string `json:"wire"`
	Valid     bool   `json:"valid"`
	Text      string `json:"text"`
	Canonical string `json:"canonical"`
}

type vendored struct {
	Source struct {
		Repository     string `json:"repository"`
		Commit         string `json:"commit"`
		Cohort         string `json:"cohort"`
		DocumentSHA256 string `json:"documentSha256"`
	} `json:"source"`
	Routes []struct {
		ID         string `json:"id"`
		Method     string `json:"method"`
		Path       string `json:"path"`
		Credential string `json:"credential"`
		Origin     string `json:"origin"`
		CSRF       string `json:"csrf"`
		SetCookie  string `json:"setCookie"`
		Cache      string `json:"cache"`
	} `json:"routes"`
	Vectors []mobileVector `json:"httpVectors"`
}

func loadVendored(t *testing.T) (vendored, map[string]any) {
	t.Helper()
	data, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var result vendored
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	document, err := os.ReadFile(documentFile)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(document)
	if result.Source.Cohort != cohort || result.Source.Commit != cohortCommit || result.Source.DocumentSHA256 != hex.EncodeToString(digest[:]) ||
		result.Source.Repository != "https://github.com/ArcForges/Contracts" || len(result.Vectors) != 120 {
		t.Fatalf("the vendored vectors are not the pinned cohort's: %+v, %d vectors", result.Source, len(result.Vectors))
	}
	var schema map[string]any
	if err = json.Unmarshal(document, &schema); err != nil {
		t.Fatal(err)
	}
	return result, schema
}

// property is a property of a definition of the vendored document.
func property(t *testing.T, schema map[string]any, definition, name string) map[string]any {
	t.Helper()
	defs, _ := schema["$defs"].(map[string]any)
	root, _ := defs[definition].(map[string]any)
	properties, _ := root["properties"].(map[string]any)
	value, ok := properties[name].(map[string]any)
	if !ok {
		t.Fatalf("the document has no %s.%s", definition, name)
	}
	return value
}

// TestTheCenterIsPinnedToTheMobileNativeAuthCohort: the vendored document's routes are the center's native rows (the paths, POST, no
// cookie, no Origin or CSRF requirement, no-store), and the patterns the center's parsers use are the document's, character for
// character (so a later cohort that changes a pattern fails here until the center follows).
func TestTheCenterIsPinnedToTheMobileNativeAuthCohort(t *testing.T) {
	data, schema := loadVendored(t)
	var native []routes.PageRoute
	for _, route := range routes.MobilePageRoutes() {
		if route.Kind == routes.PageNativeKind {
			native = append(native, route)
		}
	}
	if len(data.Routes) != 2 || len(native) != 2 {
		t.Fatalf("%d routes, %d native rows", len(data.Routes), len(native))
	}
	for index, route := range data.Routes {
		row := native[index]
		credential := map[string]string{"mobile.begin": "anonymous", "mobile.token": "authorization-code"}[route.ID]
		if route.ID != row.ID || route.Method != row.Method || route.Path != row.Path || route.Credential != credential || route.Origin != "none" ||
			route.CSRF != "none" || route.SetCookie != "none" || route.Cache != "no-store" || row.Cookie || row.SetCookie != routes.SetCookieNone {
			t.Errorf("the route %+v and the row %+v", route, row)
		}
	}
	for _, pin := range []struct {
		definition, name string
		center           *regexp.Regexp
	}{
		{"MobileBeginRequest", "redirectUri", mobileRedirectForm}, {"MobileTokenRequest", "redirectUri", mobileRedirectForm},
		{"MobileBeginRequest", "codeChallenge", mobileChallenge}, {"MobileBeginRequest", "state", mobileState},
		{"MobileTokenRequest", "codeVerifier", mobileVerifier}, {"MobileTokenRequest", "code", mobileCode},
		{"MobileInstallationClaim", "platform", mobilePlatform}, {"MobileInstallationClaim", "appVersion", textPattern},
	} {
		if pattern, _ := property(t, schema, pin.definition, pin.name)["pattern"].(string); pattern != pin.center.String() {
			t.Errorf("%s.%s: the contract's %q, the center's %q", pin.definition, pin.name, pattern, pin.center.String())
		}
	}
	for _, definition := range []string{"MobileAuthorizeCallbackSuccess", "MobileAuthorizeCallbackFailure"} {
		if pattern, _ := property(t, schema, definition, "iss")["pattern"].(string); pattern != config.MobileIssuerPattern() {
			t.Errorf("%s.iss: the contract's %q, the center's %q", definition, pattern, config.MobileIssuerPattern())
		}
	}
	if maximum, _ := property(t, schema, "MobileAuthorizeCallbackSuccess", "iss")["maxLength"].(float64); int(maximum) != config.MaxMobilePublicBaseURLLength {
		t.Errorf("the issuer bound %v", maximum)
	}
}

// divergence is one row of the expected-divergence table: the vector, what the contract and the center do, why the difference is safe.
// Its check pins the row (it fails if the center's behaviour changes either way).
type divergence struct {
	vector   string
	contract string
	center   string
	safe     string
	check    func(t *testing.T)
}

// expectedDivergences is the expected-divergence table of the replay (it is also in docs/center-mobile.md).
func expectedDivergences() []divergence {
	return []divergence{
		{
			vector:   "mobile-begin-platform-uppercase",
			contract: "the claim's platform is lower-case: ^android(...)$ refuses ANDROID-15",
			center: "the begin route applies the contract's pattern (refused, as the contract); the shared device.MobilePlatform (also IdentityService's " +
				"native sign-in and device.EnsureNative) reads the family case-insensitively and would admit it",
			safe: "the platform is display text only, HTML-escaped and labelled as the app reports it, and every spelling maps to the one platform Android; " +
				"the route refuses the upper-case form before mobileauth.ValidateClaim runs",
			check: func(t *testing.T) {
				claim := device.Claim{InstallationID: platform.NewID(), Product: mobileauth.Product, Platform: "ANDROID-15", AppVersion: "1.0.0"}
				if mobileauth.ValidateClaim(claim) != nil {
					t.Error("ValidateClaim no longer reads the family case-insensitively")
				}
				if family, ok := device.MobilePlatform("Android-15"); !ok || family != device.PlatformAndroid {
					t.Error("device.MobilePlatform changed")
				}
				if mobilePlatform.MatchString("ANDROID-15") || mobilePlatform.MatchString("Android-15") || !mobilePlatform.MatchString("android-15") {
					t.Error("the begin route's platform pattern is not the contract's lower-case one")
				}
			},
		},
		{
			vector:   "mobile-token-noncanonical-code",
			contract: "a code is ^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$: the last character carries 4 bits and two zero bits",
			center: "the center's generator (oneuse.NewCode, session.NewSecret) emits the canonical base64url of 32 random bytes, and its compare " +
				"(oneuse.ParseCode, session.ParseHandle) admits exactly a text that re-encodes to itself; the token route refuses the shape first",
			safe: "equal on every 43-character input (neither is stricter: the check walks all 64 last characters); the center emits only canonical codes",
			check: func(t *testing.T) {
				base := strings.Repeat("A", 42)
				for _, last := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
					text := base + string(last)
					_, parsed := oneuse.ParseCode(text)
					if parsed != mobileCode.MatchString(text) {
						t.Errorf("the last character %q: the center %v, the contract %v", last, parsed, mobileCode.MatchString(text))
					}
				}
				for range 2000 {
					code, digest := oneuse.NewCode()
					if !mobileCode.MatchString(code) || !oneuse.Matches(code, digest[:]) {
						t.Fatalf("the generator emitted a non-canonical code %q", code)
					}
				}
			},
		},
		{
			vector:   "mobile-callback-success-any-order",
			contract: "a callback is a form-urlencoded fragment: any member order and an unencoded issuer are valid",
			center: "the center writes exactly code (or error), state, iss in this order with iss percent-encoded (mobileauth.SuccessRedirect, " +
				"DenyRedirect); MobileProbe (the app stand-in) reads any order, as the contract asks of the app",
			safe:  "the center's form is one of the contract's valid forms (the canonical vectors are reproduced byte for byte)",
			check: func(t *testing.T) { checkCallbackForms(t) },
		},
		{
			vector:   "mobile-begin-debug-scheme-plus-and-hyphen",
			contract: "the debug redirect's form is [a-z][a-z0-9.+-]*\\.[a-z0-9.+-]+:/callback (N-6): it admits '+', empty labels and a trailing dot",
			center: "ARCFORGES_CENTER_MOBILE_DEBUG_REDIRECT takes the strict reverse-DNS grammar (MB-9: lower-case labels of letters and digits with inner " +
				"hyphens, at least one dot); the center admits exactly <scheme>:/callback of that value, so a '+' scheme is never admitted",
			safe: "stricter: the center admits only its own configured value, and the configuration refuses every scheme outside the grammar " +
				"(and every reserved scheme) at start; the route's shape check still applies the contract's form",
			check: func(t *testing.T) {
				for scheme, want := range map[string]bool{"com.arcforges.android.debug": true, "com.arc-forges.debug": true, "com.arc+forges.debug": false,
					"a..b": false, "a.": false, "com.Arcforges.debug": false, "arcforges": false, "-com.arcforges": false, "com.arcforges-": false} {
					if config.ValidDebugScheme(scheme) != want {
						t.Errorf("the debug scheme %q: %v", scheme, !want)
					}
				}
				// The contract's form admits the '+' scheme of the vector; the configuration's grammar refuses it.
				if !mobileRedirectForm.MatchString("com.arc+forges.debug:/callback") {
					t.Error("the route's form is no longer the contract's")
				}
			},
		},
		{
			vector:   "mobile-callback-success-loopback-issuer",
			contract: "an issuer is https with a host of [a-z0-9-] labels, or http for localhost, 127.x.y.z or [::1]; at most 453 characters",
			center: "the public base URL grammar (config.ParsePublicBaseURL) admits more (an underscore in the host, an https IP literal of IPv6); " +
				"the configuration refuses the mobile surface for a base URL that is not an issuer when the surface is listed, and leaves it out of the " +
				"self-hosted default otherwise",
			safe: "every iss the center writes is its own public base URL, which the configuration has checked against the contract's issuer form",
			check: func(t *testing.T) {
				for base, want := range map[string]bool{officialIssuer: true, "http://127.0.0.1:8080": true, "http://[::1]:8443/x": true,
					"https://under_score.example/api": false, "https://[2001:db8::1]": false, "https://arcforges.com/" + strings.Repeat("a", 440): false} {
					if config.ValidMobileIssuer(base) != want {
						t.Errorf("the issuer %q: %v", base, !want)
					}
				}
			},
		},
	}
}

// checkCallbackForms is divergence (c): the canonical callback vectors are what the center's builders write, and the other valid forms
// (any order, an unencoded issuer) are read by the app stand-in but never written by the center.
func checkCallbackForms(t *testing.T) {
	t.Helper()
	data, _ := loadVendored(t)
	for _, vector := range data.Vectors {
		if !vector.Valid || !strings.HasPrefix(vector.Root, "MobileAuthorizeCallback") {
			continue
		}
		values := fragmentValues(vector.Text)
		var built string
		if vector.Root == "MobileAuthorizeCallbackSuccess" {
			built = mobileauth.SuccessRedirect("", values["code"], values["state"], values["iss"])
		} else {
			built = mobileauth.DenyRedirect("", values["state"], values["iss"])
		}
		canonical := vector.Canonical == vector.Text
		if canonical != ("#"+vector.Text == built) {
			t.Errorf("%s: the center writes %q", vector.ID, built)
		}
	}
}

// fragmentValues reads a form-urlencoded fragment's members.
func fragmentValues(text string) map[string]string {
	values := map[string]string{}
	for _, part := range strings.Split(text, "&") {
		name, value, _ := strings.Cut(part, "=")
		decoded, err := url.QueryUnescape(value)
		if err == nil {
			values[name] = decoded
		}
	}
	return values
}

// TestTheMobileNativeAuthVectorsReplay replays every vendored vector: a request through the center's route bound and parser, a callback
// through the app stand-in's checks (and, canonical, through the center's builders), a begin reply through the app's derived-URL check
// (and, canonical, through the center's encoder), a token reply through the document's closed shape (and, canonical, through the
// center's encoder). Every verdict is the contract's; the expected divergences are below in their own rows.
func TestTheMobileNativeAuthVectorsReplay(t *testing.T) {
	data, _ := loadVendored(t)
	bounds := map[string]int{}
	for _, route := range routes.MobilePageRoutes() {
		if route.Kind == routes.PageNativeKind {
			bounds[map[string]string{routes.NativeMobileBegin: "MobileBeginRequest", routes.NativeMobileToken: "MobileTokenRequest"}[route.Path]] = route.MaxRequestBytes
		}
	}
	roots := map[string]int{}
	for _, vector := range data.Vectors {
		roots[vector.Root]++
		var got bool
		switch vector.Root {
		case "MobileBeginRequest", "MobileTokenRequest":
			if len(vector.Text) > bounds[vector.Root] {
				got = false // the route's bound (x-arcforges-max-bytes) refuses it before any parse: 413
				break
			}
			var refusal error
			if vector.Root == "MobileBeginRequest" {
				_, problem := parseMobileBegin([]byte(vector.Text))
				if problem != nil {
					refusal = problem
				}
			} else {
				_, problem := parseMobileToken([]byte(vector.Text))
				if problem != nil {
					refusal = problem
				}
			}
			got = refusal == nil
		case "MobileAuthorizeCallbackSuccess", "MobileAuthorizeCallbackFailure":
			values := fragmentValues(vector.Text)
			center := officialIssuer
			if vector.Valid {
				center = values["iss"]
			}
			callback, err := mobiletest.ParseFragment(vector.Text, center, values["state"])
			got = err == nil && callback.Denied == (vector.Root == "MobileAuthorizeCallbackFailure")
		case "MobileBeginResponse":
			center := officialIssuer
			if vector.Valid {
				var reply struct {
					AuthorizeURL string `json:"authorizeUrl"`
				}
				_ = json.Unmarshal([]byte(vector.Text), &reply)
				center, _, _ = strings.Cut(reply.AuthorizeURL, "/mobile/authorize#flow=")
			}
			flowID, authorize, expires, err := mobiletest.CheckBeginReply([]byte(vector.Text), center)
			got = err == nil
			if got && vector.Canonical == vector.Text {
				encoded, _ := encodeMobile(mobileBeginReply{FlowID: flowID, AuthorizeURL: authorize, ExpiresAt: expires})
				if string(encoded) != vector.Text {
					t.Errorf("%s: the center encodes %s", vector.ID, encoded)
				}
			}
		case "MobileTokenResponse":
			got = validTokenReply(t, vector)
		default:
			t.Fatalf("%s: an unknown root %s", vector.ID, vector.Root)
		}
		if got != vector.Valid {
			t.Errorf("%s (%s): the contract says valid=%v, the center %v", vector.ID, vector.Root, vector.Valid, got)
		}
	}
	if len(roots) != 6 {
		t.Fatalf("the vectors name %d roots", len(roots))
	}
}

// validTokenReply decodes a token reply into the center's own reply type, closed (no unknown member at any depth), with the document's
// constants and required members, and re-encodes a canonical one byte for byte.
func validTokenReply(t *testing.T, vector mobileVector) bool {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader([]byte(vector.Text)))
	decoder.DisallowUnknownFields()
	var reply mobileTokenReply
	if decoder.Decode(&reply) != nil || decoder.More() {
		return false
	}
	var raw map[string]any
	_ = json.Unmarshal([]byte(vector.Text), &raw)
	device, _ := raw["device"].(map[string]any)
	for _, name := range []string{"sessionId", "accessToken", "accessExpiresAt", "refreshToken", "refreshExpiresAt", "device", "recoveryGeneration", "scope", "purpose"} {
		if _, ok := raw[name]; !ok {
			return false
		}
	}
	for _, name := range []string{"deviceId", "name", "platform", "trust", "remoteEnabled", "revision"} {
		if _, ok := device[name]; !ok {
			return false
		}
	}
	if reply.Scope != "account" || reply.Purpose != "authenticate" || !slices.Contains([]string{"untrusted", "trusted", "revoked"}, reply.Device.Trust) {
		return false
	}
	for _, item := range reply.Device.Installed {
		if item.Product != mobileauth.Product {
			return false
		}
	}
	if vector.Canonical == vector.Text {
		encoded, _ := encodeMobile(reply)
		if string(encoded) != vector.Text {
			t.Errorf("%s: the center encodes %s", vector.ID, encoded)
		}
	}
	return true
}

// TestTheExpectedMobileDivergences pins every row of the expected-divergence table: its vector exists with the contract's verdict, and
// the center's side of the row still holds.
func TestTheExpectedMobileDivergences(t *testing.T) {
	data, _ := loadVendored(t)
	known := map[string]bool{}
	for _, vector := range data.Vectors {
		known[vector.ID] = true
	}
	rows := expectedDivergences()
	if len(rows) < 4 {
		t.Fatalf("the table has %d rows", len(rows))
	}
	for _, row := range rows {
		t.Run(row.vector, func(t *testing.T) {
			if !known[row.vector] || row.contract == "" || row.center == "" || row.safe == "" {
				t.Fatalf("the row of %s is incomplete or names no vector", row.vector)
			}
			row.check(t)
		})
	}
}
