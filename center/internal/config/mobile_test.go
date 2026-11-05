// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"strings"
	"testing"
)

const testPrint = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89"

// TestTheAndroidAppIdentityHasAStrictGrammar (MB-8): unset, empty and [] publish nothing; an app is exactly packageName,
// sha256CertFingerprints (1 to 4 distinct upper-case colon-separated SHA-256 fingerprints) and optionally testOnly true; anything else
// refuses start.
func TestTheAndroidAppIdentityHasAStrictGrammar(t *testing.T) {
	for _, document := range []string{"", "[]"} {
		if apps, err := ParseAndroidApps(document); err != nil || apps != nil {
			t.Errorf("%q: %v %v", document, apps, err)
		}
	}
	apps, err := ParseAndroidApps(`[{"packageName":"com.arcforges.prooftest","sha256CertFingerprints":["` + testPrint + `"],"testOnly":true}]`)
	if err != nil || len(apps) != 1 || apps[0].PackageName != "com.arcforges.prooftest" || !apps[0].TestOnly || apps[0].Fingerprints[0] != testPrint {
		t.Fatalf("the proof statement: %+v %v", apps, err)
	}
	if !(Mobile{AndroidApps: apps}).TestOnly() {
		t.Error("TestOnly")
	}
	lower := strings.ToLower(testPrint)
	for name, document := range map[string]string{
		"not an array":        `{"packageName":"com.a.b"}`,
		"an unknown key":      `[{"packageName":"com.a.b","sha256CertFingerprints":["` + testPrint + `"],"name":"x"}]`,
		"a repeated key":      `[{"packageName":"com.a.b","packageName":"com.a.c","sha256CertFingerprints":["` + testPrint + `"]}]`,
		"one segment":         `[{"packageName":"arcforges","sha256CertFingerprints":["` + testPrint + `"]}]`,
		"a digit segment":     `[{"packageName":"com.1arcforges","sha256CertFingerprints":["` + testPrint + `"]}]`,
		"no fingerprint":      `[{"packageName":"com.a.b","sha256CertFingerprints":[]}]`,
		"five fingerprints":   `[{"packageName":"com.a.b","sha256CertFingerprints":["` + strings.Repeat(testPrint+`","`, 4) + testPrint + `"]}]`,
		"a lower-case print":  `[{"packageName":"com.a.b","sha256CertFingerprints":["` + lower + `"]}]`,
		"a short print":       `[{"packageName":"com.a.b","sha256CertFingerprints":["AB:CD"]}]`,
		"a repeated print":    `[{"packageName":"com.a.b","sha256CertFingerprints":["` + testPrint + `","` + testPrint + `"]}]`,
		"testOnly false":      `[{"packageName":"com.a.b","sha256CertFingerprints":["` + testPrint + `"],"testOnly":false}]`,
		"a repeated package":  `[{"packageName":"com.a.b","sha256CertFingerprints":["` + testPrint + `"]},{"packageName":"com.a.b","sha256CertFingerprints":["` + testPrint + `"]}]`,
		"five apps":           "[" + strings.Repeat(`{"packageName":"com.a.b","sha256CertFingerprints":["`+testPrint+`"]},`, 4) + `{"packageName":"com.a.z","sha256CertFingerprints":["` + testPrint + `"]}]`,
		"two documents":       `[] []`,
		"too long a document": "[" + strings.Repeat(" ", MaxAndroidAppDocumentBytes) + "]",
	} {
		if _, err := ParseAndroidApps(document); err == nil {
			t.Errorf("%s was admitted", name)
		}
	}
	if _, err := Load(environment(withIdentity(OfficialHosted, map[string]string{EnvAndroidApp: `[{"packageName":"x"}]`}))); !errors.Is(err, ErrInvalid) {
		t.Errorf("a malformed identity started: %v", err)
	}
}

// TestTheDebugRedirectIsSelfHostedAndReverseDNS (MB-9): the debug app's scheme is admitted only by a self-hosted center (its presence,
// even empty, refuses an official-hosted start), only in the strict reverse-DNS grammar, never a reserved scheme.
func TestTheDebugRedirectIsSelfHostedAndReverseDNS(t *testing.T) {
	for _, value := range []string{"com.arcforges.android.debug", ""} {
		if _, err := Load(environment(withIdentity(OfficialHosted, map[string]string{EnvMobileDebugRedirect: value}))); !errors.Is(err, ErrInvalid) {
			t.Errorf("an official-hosted center with the debug scheme %q started: %v", value, err)
		}
	}
	loaded, err := Load(environment(withIdentity(SelfHosted, map[string]string{EnvMobileDebugRedirect: "com.arcforges.android.debug"})))
	if err != nil || loaded.Mobile.DebugRedirect() != "com.arcforges.android.debug:/callback" {
		t.Fatalf("self-hosted: %+v %v", loaded.Mobile, err)
	}
	if (Mobile{}).DebugRedirect() != "" {
		t.Error("no scheme, no redirect")
	}
	for _, scheme := range []string{"", "http", "https", "javascript", "intent", "android-app", "file", "data", "content", "about", "blob", "ws", "wss",
		"arcforges", "Com.arcforges.debug", "com..arcforges", "com.arcforges.", ".com.arcforges", "com.arc+forges", "com.arcforges-.debug", "com.-arcforges",
		"com_arcforges.debug", "1com.arcforges", "com.arcforges:x", strings.Repeat("a.", 50) + "b"} {
		if ValidDebugScheme(scheme) {
			t.Errorf("%q was admitted", scheme)
		}
		if scheme != "" {
			if _, err := Load(environment(withIdentity(SelfHosted, map[string]string{EnvMobileDebugRedirect: scheme}))); !errors.Is(err, ErrInvalid) {
				t.Errorf("a self-hosted center with %q started", scheme)
			}
		}
	}
	for _, scheme := range []string{"com.arcforges.android.debug", "dev.example.app1", "com.arc-forges.debug", "a.b"} {
		if !ValidDebugScheme(scheme) {
			t.Errorf("%q was refused", scheme)
		}
	}
}

// TestTheMobileSurfaceNeedsIdentityPagesAndAnIssuer: listed, the mobile surface needs the identity and pages surfaces and a public
// base URL that is a MobileNativeAuth issuer; the self-hosted default includes it and leaves it out for a base URL that is no issuer.
func TestTheMobileSurfaceNeedsIdentityPagesAndAnIssuer(t *testing.T) {
	hosted := func(surfaces, base string) map[string]string {
		values := withIdentity(OfficialHosted, map[string]string{EnvSurfaces: surfaces, EnvClientIPHeader: ClientIPHeader})
		if base != "" {
			values[EnvPublicBaseURL] = base
		}
		return values
	}
	loaded, err := Load(environment(hosted("identity,pages,mobile", "")))
	if err != nil || !loaded.Identity.Enabled(SurfaceMobile) {
		t.Fatalf("identity,pages,mobile: %v %v", loaded.Identity.Surfaces, err)
	}
	for _, list := range []string{"mobile", "identity,mobile", "pages,mobile"} {
		if _, err = Load(environment(hosted(list, ""))); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q started: %v", list, err)
		}
	}
	for _, base := range []string{"https://under_score.example/api", "https://center.example/" + strings.Repeat("a", 432)} {
		if _, err = Load(environment(hosted("identity,pages,mobile", base))); !errors.Is(err, ErrInvalid) {
			t.Errorf("the base %q started with mobile: %v", base, err)
		}
		values := withIdentity(SelfHosted, map[string]string{EnvPublicBaseURL: base})
		defaulted, err := Load(environment(values))
		if err != nil || defaulted.Identity.Enabled(SurfaceMobile) || !defaulted.Identity.Enabled(SurfaceFleet) {
			t.Errorf("the self-hosted default for %q: %v %v", base, defaulted.Identity.Surfaces, err)
		}
	}
	defaulted, err := Load(environment(withIdentity(SelfHosted, nil)))
	if err != nil || !defaulted.Identity.Enabled(SurfaceMobile) {
		t.Fatalf("the self-hosted default: %v %v", defaulted.Identity.Surfaces, err)
	}
}
