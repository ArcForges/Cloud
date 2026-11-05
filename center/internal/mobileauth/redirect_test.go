// SPDX-License-Identifier: AGPL-3.0-only

package mobileauth

import (
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// TestTheRedirectsAreTheCentersOwn (MB-2, MB-9, MB-10, Q-3): the release client's one redirect is the origin of the public base URL with
// /app/callback (none for a center of an IP, loopback or http host); the debug client's is exactly <scheme>:/callback of the
// configuration; nothing else is admitted, and the callbacks are built from the stored redirect with the fragment in the contract's
// order and the issuer percent-encoded.
func TestTheRedirectsAreTheCentersOwn(t *testing.T) {
	for base, want := range map[string]string{
		"https://arcforges.com/api":            "https://arcforges.com/app/callback",
		"https://proof.arcforges.com/api":      "https://proof.arcforges.com/app/callback",
		"https://center.example.test:8443":     "https://center.example.test:8443/app/callback",
		"http://localhost:8080":                "",
		"http://127.0.0.1:8080/api":            "",
		"https://10.0.0.1/api":                 "",
		"https://localhost/api":                "",
		"https://arcforges.com/deep/base/path": "https://arcforges.com/app/callback",
	} {
		if got := ReleaseRedirect(base); got != want {
			t.Errorf("%s: %q, want %q", base, got, want)
		}
	}
	service := New(Options{PublicBaseURL: "https://arcforges.com/api", Mobile: config.Mobile{DebugScheme: "com.arcforges.android.debug"}})
	for _, item := range []struct {
		client, redirect string
		want             bool
	}{
		{ClientRelease, "https://arcforges.com/app/callback", true},
		{ClientDebug, "com.arcforges.android.debug:/callback", true},
		{ClientRelease, "com.arcforges.android.debug:/callback", false},
		{ClientDebug, "https://arcforges.com/app/callback", false},
		{ClientRelease, "https://evil.example/app/callback", false},
		{ClientRelease, "https://arcforges.com/app/callback/", false},
		{ClientDebug, "com.arcforges.android.other:/callback", false},
		{"companion.android", "https://arcforges.com/app/callback", false},
	} {
		if service.AdmitRedirect(item.client, item.redirect) != item.want {
			t.Errorf("%s %s: %v", item.client, item.redirect, !item.want)
		}
	}
	if New(Options{PublicBaseURL: "https://arcforges.com/api"}).AdmitRedirect(ClientDebug, "com.arcforges.android.debug:/callback") {
		t.Error("the debug client without a configured scheme")
	}
	if got := SuccessRedirect("https://arcforges.com/app/callback", "CODE", "state-of-sixteen", "https://arcforges.com/api"); got !=
		"https://arcforges.com/app/callback#code=CODE&state=state-of-sixteen&iss=https%3A%2F%2Farcforges.com%2Fapi" {
		t.Errorf("the success callback %q", got)
	}
	if got := DenyRedirect("com.x.y:/callback", "state-of-sixteen", "http://[::1]:8443"); got !=
		"com.x.y:/callback#error=access_denied&state=state-of-sixteen&iss=http%3A%2F%2F%5B%3A%3A1%5D%3A8443" {
		t.Errorf("the denial %q", got)
	}
	id := platform.ID{0x9b, 0x2d, 0x6c, 0x1e, 0x3f, 0x4a, 0x4b, 0x5c, 0x8d, 0x6e, 0x7f, 0x80, 0x91, 0xa2, 0xb3, 0xc4}
	if got := AuthorizeURL("https://arcforges.com/api", id); got != "https://arcforges.com/api/mobile/authorize#flow=9b2d6c1e-3f4a-4b5c-8d6e-7f8091a2b3c4" {
		t.Errorf("the authorization URL %q", got)
	}
	if service.Issuer() != "https://arcforges.com/api" {
		t.Error("the issuer is not the public base URL")
	}
}

// TestTheCodeLivesAtMostTwoMinutes (N-1, M-4): the contract's bound and the policy's upper bound are both 2 minutes and the default is
// 2 minutes, so no configuration makes the closed statement false.
func TestTheCodeLivesAtMostTwoMinutes(t *testing.T) {
	if MaxCodeLifetime != 2*time.Minute || config.MaxMobileCodeLifetime != MaxCodeLifetime || config.DefaultIdentityPolicy().MobileCodeLifetime != MaxCodeLifetime {
		t.Fatal("the code lifetime bound")
	}
	for value, ok := range map[string]bool{"30s": true, "2m": true, "2m1s": false, "3m": false, "10m": false, "29s": false} {
		if _, err := config.ParseIdentityPolicy(`{"mobileCodeLifetime": "` + value + `"}`); (err == nil) != ok {
			t.Errorf("mobileCodeLifetime %s: %v", value, err)
		}
	}
}

// TestTheAssetLinksStatementBytes (MB-8, Q-2): no app is [] (production); each app is one statement with both relations, the
// android_app target, its package and its fingerprints in order, without white space.
func TestTheAssetLinksStatementBytes(t *testing.T) {
	if got := string(AssetLinks(nil)); got != "[]" {
		t.Fatalf("no app: %q", got)
	}
	apps := []config.AndroidApp{{PackageName: "com.arcforges.prooftest", Fingerprints: []string{"AA", "BB"}}, {PackageName: "com.arcforges.other", Fingerprints: []string{"CC"}}}
	want := `[{"relation":["delegate_permission/common.handle_all_urls","delegate_permission/common.get_login_creds"],"target":{"namespace":"android_app",` +
		`"package_name":"com.arcforges.prooftest","sha256_cert_fingerprints":["AA","BB"]}},{"relation":["delegate_permission/common.handle_all_urls",` +
		`"delegate_permission/common.get_login_creds"],"target":{"namespace":"android_app","package_name":"com.arcforges.other","sha256_cert_fingerprints":["CC"]}}]`
	if got := string(AssetLinks(apps)); got != want {
		t.Fatalf("the statement:\n%s", got)
	}
}

// TestTheStateNames are the lower-case names a refusal of a decision names.
func TestTheStateNames(t *testing.T) {
	for state, name := range map[int16]string{FlowPending: "pending", FlowApproved: "approved", FlowCompleted: "completed", FlowDenied: "denied",
		FlowExpired: "expired", FlowRevoked: "revoked", 9: "unspecified"} {
		if StateName(state) != name {
			t.Errorf("%d: %s", state, StateName(state))
		}
	}
}
