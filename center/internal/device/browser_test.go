// SPDX-License-Identifier: AGPL-3.0-only

package device

import (
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// TestABrowserDeviceIsNamedByItsFamilyNotByItsHeader (DC-02): the name of a browser's new device comes from a closed set of browser
// families and systems; whatever else a User-Agent says never reaches an account's device list.
func TestABrowserDeviceIsNamedByItsFamilyNotByItsHeader(t *testing.T) {
	for agent, want := range map[string]string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0":                  "Edge on Windows",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36":                                "Chrome on Windows",
		"Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0":                                                                         "Firefox on Linux",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15":                          "Safari on macOS",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1":        "Safari on iOS",
		"Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36":                          "Chrome on Android",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0":                  "Opera on Windows",
		"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36":                                 "Chrome on ChromeOS",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0.6723.37 Mobile/15E148 Safari/604.1": "Chrome on iOS",
		"curl/8.5.0":   "Web browser",
		"":             "Web browser",
		"Windows only": "Browser on Windows",
		"<script>alert(1)</script> Firefox/1 Windows": "Firefox on Windows",
		"'; DROP TABLE device.device; -- Safari/537":  "Safari",
	} {
		if got := BrowserName(agent); got != want {
			t.Errorf("%q is %q, not %q", agent, got, want)
		}
	}
	// Whatever the header, the name is one of the closed set and a valid device name.
	families := []string{"Edge", "Opera", "Firefox", "Chrome", "Chromium", "Safari"}
	systems := []string{"Windows", "Android", "iOS", "ChromeOS", "macOS", "Linux"}
	allowed := map[string]bool{"Web browser": true}
	for _, family := range families {
		allowed[family] = true
		for _, system := range systems {
			allowed[family+" on "+system] = true
		}
	}
	for _, system := range systems {
		allowed["Browser on "+system] = true
	}
	for _, agent := range []string{strings.Repeat("Firefox/", 500), "\x00\xff\xfe Chrome/", "Edg/ Windows Linux Android", "\n\r\t"} {
		name := BrowserName(agent)
		if !allowed[name] || !ValidName(name) {
			t.Errorf("%q gave %q", agent, name)
		}
	}
}

func TestTheBrowserClaimIsTheDocumentsAndNotTheNativeOne(t *testing.T) {
	id := platform.NewID()
	good := Claim{InstallationID: id, Product: ProductWeb, Platform: "web", AppVersion: "pages-1"}
	if refusal := ValidateBrowserClaim(good, true); refusal != nil {
		t.Fatal(refusal)
	}
	if refusal := ValidateNativeClaim(good, true); refusal == nil {
		t.Fatal("the native sign-in admits the web product")
	}
	for name, test := range map[string]struct {
		claim   Claim
		present bool
		reason  string
	}{
		"absent":          {good, false, "installation: required"},
		"nil id":          {Claim{Product: ProductWeb, Platform: "web", AppVersion: "1"}, true, "installation.installationId: required"},
		"a text":          {Claim{InstallationID: id, Product: "a b", Platform: "web", AppVersion: "1"}, true, "installation.product: pattern"},
		"another product": {Claim{InstallationID: id, Product: ProductMobile, Platform: "web", AppVersion: "1"}, true, "installation.product: not_admitted"},
		"companion":       {Claim{InstallationID: id, Product: "companion", Platform: "web", AppVersion: "1"}, true, "installation.product: not_admitted"},
		"a platform":      {Claim{InstallationID: id, Product: ProductWeb, Platform: "a b", AppVersion: "1"}, true, "installation.platform: pattern"},
		"a version":       {Claim{InstallationID: id, Product: ProductWeb, Platform: "web", AppVersion: ""}, true, "installation.appVersion: pattern"},
	} {
		refusal := ValidateBrowserClaim(test.claim, test.present)
		if refusal == nil || refusal.Reason != test.reason {
			t.Errorf("%s: %v", name, refusal)
		}
	}
}
