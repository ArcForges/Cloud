// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func withIdentity(mode Mode, extra map[string]string) map[string]string {
	values := minimal(mode)
	values[EnvDatabaseURL] = runtimeURL
	for name, value := range extra {
		values[name] = value
	}
	return values
}

func TestTheSurfacesDefaultPerModeAndAreExactNames(t *testing.T) {
	hosted, err := Load(environment(withIdentity(OfficialHosted, nil)))
	if err != nil || len(hosted.Identity.Surfaces) != 0 {
		t.Fatalf("official-hosted enables no surface by default: %+v %v", hosted.Identity, err)
	}
	self, err := Load(environment(withIdentity(SelfHosted, nil)))
	if err != nil || !self.Identity.Enabled(SurfaceIdentity) {
		t.Fatalf("self-hosted enables the default surfaces: %+v %v", self.Identity, err)
	}
	enabled, err := Load(environment(withIdentity(OfficialHosted, map[string]string{EnvSurfaces: "identity", EnvClientIPHeader: ClientIPHeader})))
	if err != nil || !enabled.Identity.Enabled(SurfaceIdentity) || enabled.Identity.ClientIPHeader != ClientIPHeader {
		t.Fatalf("listed: %+v %v", enabled.Identity, err)
	}
	none, err := Load(environment(withIdentity(SelfHosted, map[string]string{EnvSurfaces: "none"})))
	if err != nil || len(none.Identity.Surfaces) != 0 {
		t.Fatalf("none: %+v %v", none.Identity, err)
	}
	for _, value := range []string{"Identity", "identity,", ",identity", "identity,identity", " identity", "identity ", "billing", "identity,none"} {
		if _, err = Load(environment(withIdentity(SelfHosted, map[string]string{EnvSurfaces: value}))); !errors.Is(err, ErrInvalid) ||
			!strings.Contains(err.Error(), EnvSurfaces) {
			t.Errorf("%q: %v", value, err)
		}
	}
}

func TestTheHostedCenterNeedsTheWorkersAddressHeader(t *testing.T) {
	if _, err := Load(environment(withIdentity(OfficialHosted, map[string]string{EnvSurfaces: "identity"}))); !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), EnvClientIPHeader) {
		t.Fatalf("a hosted surface without the header: %v", err)
	}
	if _, err := Load(environment(withIdentity(OfficialHosted, map[string]string{EnvSurfaces: "identity", EnvClientIPHeader: "X-Forwarded-For"}))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another header: %v", err)
	}
	// The header without a surface is accepted (the Worker always passes it with runtime go).
	if _, err := Load(environment(withIdentity(OfficialHosted, map[string]string{EnvClientIPHeader: strings.ToLower(ClientIPHeader)}))); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(environment(withIdentity(OfficialHosted, map[string]string{EnvTrustedProxies: "10.0.0.0/8"}))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trusted proxies in hosted mode: %v", err)
	}
}

func TestASelfHostedCenterTrustsOnlyListedProxies(t *testing.T) {
	cfg, err := Load(environment(withIdentity(SelfHosted, map[string]string{EnvClientIPHeader: ClientIPHeader, EnvTrustedProxies: "10.0.0.0/8,2001:db8::/32"})))
	if err != nil || len(cfg.Identity.TrustedProxies) != 2 {
		t.Fatalf("%+v %v", cfg.Identity, err)
	}
	for _, values := range []map[string]string{
		{EnvClientIPHeader: ClientIPHeader},
		{EnvTrustedProxies: "10.0.0.0/8"},
		{EnvClientIPHeader: ClientIPHeader, EnvTrustedProxies: "10.0.0.1/8"},
		{EnvClientIPHeader: ClientIPHeader, EnvTrustedProxies: "10.0.0.0/8, 10.1.0.0/16"},
		{EnvClientIPHeader: ClientIPHeader, EnvTrustedProxies: "proxy.internal"},
	} {
		if _, err = Load(environment(withIdentity(SelfHosted, values))); !errors.Is(err, ErrInvalid) {
			t.Errorf("%v: %v", values, err)
		}
	}
}

func TestAnAddressHostOrAMissingStoreKeepsIdentityOff(t *testing.T) {
	values := withIdentity(SelfHosted, nil)
	values[EnvPublicBaseURL] = "http://127.0.0.1:8080/api"
	cfg, err := Load(environment(values))
	if err != nil || cfg.Identity.Enabled(SurfaceIdentity) || len(cfg.Identity.Surfaces) != 0 || cfg.Identity.Enabled(SurfaceFleet) ||
		!strings.Contains(cfg.Identity.Disabled, "domain name") {
		t.Fatalf("the default with an IP host: %+v %v", cfg.Identity, err)
	}
	// cloud-6: the fallback clears the default's surfaces (the code clears the whole list, so a later default that adds a surface is
	// cleared too; the server's TestASelfHostedCenterOnAnAddressServesNoSurface shows the composed result).
	values[EnvPublicBaseURL] = "https://192.168.1.10:8443"
	if cfg, err = Load(environment(values)); err != nil || len(cfg.Identity.Surfaces) != 0 || cfg.Identity.Enabled(SurfaceFleet) {
		t.Fatalf("the default with a private IP host: %+v %v", cfg.Identity, err)
	}
	values[EnvSurfaces] = "fleet,identity,pages"
	if _, err = Load(environment(values)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an explicit fleet list with an IP host starts: %v", err)
	}
	values[EnvSurfaces] = "identity"
	if _, err = Load(environment(values)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an explicit list with an IP host starts: %v", err)
	}
	noStore := minimal(SelfHosted)
	cfg, err = Load(environment(noStore))
	if err != nil || cfg.Identity.Enabled(SurfaceIdentity) || len(cfg.Identity.Surfaces) != 0 || !strings.Contains(cfg.Identity.Disabled, EnvDatabaseURL) {
		t.Fatalf("the default without a store: %+v %v", cfg.Identity, err)
	}
	noStore[EnvSurfaces] = "identity"
	if _, err = Load(environment(noStore)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an explicit list without a store starts: %v", err)
	}
}

func bootstrapDigest(t *testing.T) string {
	t.Helper()
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(token)
	return hex.EncodeToString(digest[:])
}

func TestTheBootstrapIsADigestAndANearExpiry(t *testing.T) {
	digest := bootstrapDigest(t)
	expires := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	cfg, err := Load(environment(withIdentity(SelfHosted, map[string]string{EnvBootstrapSHA256: digest, EnvBootstrapExpiresAt: expires})))
	if err != nil || cfg.Identity.Bootstrap == nil || hex.EncodeToString(cfg.Identity.Bootstrap.TokenSHA256[:]) != digest ||
		cfg.Identity.Bootstrap.ExpiresAt.Format(time.RFC3339) != expires {
		t.Fatalf("%+v %v", cfg.Identity.Bootstrap, err)
	}
	now := time.Now().UTC()
	refused := []map[string]string{
		{EnvBootstrapSHA256: digest},
		{EnvBootstrapExpiresAt: expires},
		{EnvBootstrapSHA256: strings.ToUpper(digest), EnvBootstrapExpiresAt: expires},
		{EnvBootstrapSHA256: digest[:63], EnvBootstrapExpiresAt: expires},
		{EnvBootstrapSHA256: digest[:63] + "g", EnvBootstrapExpiresAt: expires},
		{EnvBootstrapSHA256: digest, EnvBootstrapExpiresAt: now.Add(MaxBootstrapLead + time.Hour).Format(time.RFC3339)},
		{EnvBootstrapSHA256: digest, EnvBootstrapExpiresAt: now.Add(time.Hour).Format("2006-01-02T15:04:05+00:00")},
		{EnvBootstrapSHA256: digest, EnvBootstrapExpiresAt: "tomorrow"},
	}
	for _, values := range refused {
		_, err = Load(environment(withIdentity(SelfHosted, values)))
		if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), digest) {
			t.Errorf("%v: %v", values, err)
		}
	}
	// A past expiry (the variables left set after the bootstrap) still loads, so a restart starts the center; the bootstrap is
	// refused at use as expired (E2).
	past := now.Add(-30 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339)
	if cfg, err = Load(environment(withIdentity(SelfHosted, map[string]string{EnvBootstrapSHA256: digest, EnvBootstrapExpiresAt: past}))); err != nil ||
		cfg.Identity.Bootstrap == nil || cfg.Identity.Bootstrap.ExpiresAt.After(now) {
		t.Fatalf("a past expiry: %+v %v", cfg.Identity.Bootstrap, err)
	}
	// Both sides of the seven-day bound.
	inside := now.Add(MaxBootstrapLead - time.Minute).Truncate(time.Second).Format(time.RFC3339)
	if _, err = Load(environment(withIdentity(SelfHosted, map[string]string{EnvBootstrapSHA256: digest, EnvBootstrapExpiresAt: inside}))); err != nil {
		t.Fatalf("inside the bound: %v", err)
	}
}

func TestTheIdentityPolicyHasDocumentedDefaultsAndBoundedOverrides(t *testing.T) {
	defaults := DefaultIdentityPolicy()
	if err := defaults.Validate(); err != nil {
		t.Fatal(err)
	}
	// C1: the anonymous-flow ceiling is opt-in (0 sets none) and bounded.
	if defaults.AnonymousFlows != (Window{Limit: 0, Window: time.Hour}) {
		t.Fatalf("the anonymous-flow ceiling is set by default: %+v", defaults.AnonymousFlows)
	}
	if ceiling, err := ParseIdentityPolicy(`{"anonymousFlowsLimit":600,"anonymousFlowsWindow":"1h"}`); err != nil ||
		ceiling.AnonymousFlows != (Window{Limit: 600, Window: time.Hour}) {
		t.Fatalf("the proof ceiling: %+v %v", ceiling.AnonymousFlows, err)
	}
	for _, document := range []string{`{"anonymousFlowsLimit": -1}`, `{"anonymousFlowsLimit": 10001}`, `{"anonymousFlowsWindow": "30s"}`,
		`{"anonymousFlowsWindow": "25h"}`, `{"anonymousFlowsLimit": "600"}`} {
		if _, err := ParseIdentityPolicy(document); err == nil {
			t.Errorf("%s was admitted", document)
		}
	}
	if defaults.BrowserAbsolute != 12*time.Hour || defaults.BrowserIdle != 30*time.Minute || defaults.StepUpEvidenceTTL != 5*time.Minute ||
		defaults.EmailCodeAttempts != 5 || defaults.EmailCodeSends != 3 || defaults.EmailCodeIterations != 20_000 || defaults.AccessTokenLifetime != 15*time.Minute {
		t.Fatalf("defaults %+v", defaults)
	}
	policy, err := ParseIdentityPolicy(`{"signInPerPrefixLimit": 3, "signInPerPrefixWindow": "2m", "emailCodeAttempts": 10, "accessTokenLifetime": "1h"}`)
	if err != nil || policy.SignInPerPrefix.Limit != 3 || policy.SignInPerPrefix.Window != 2*time.Minute || policy.EmailCodeAttempts != 10 ||
		policy.AccessTokenLifetime != time.Hour {
		t.Fatalf("override %+v %v", policy, err)
	}
	refused := []string{
		`{"emailCodeAttempts": 11}`, `{"emailCodeAttempts": 0}`, `{"stepUpEvidenceTtl": "6m"}`, `{"stepUpEvidenceTtl": "59s"}`,
		`{"accessTokenLifetime": "61m"}`, `{"browserIdle": "13h", "browserAbsolute": "12h"}`, `{"unknown": 1}`, `{"emailCodeAttempts": 2, "emailCodeAttempts": 3}`,
		`{"emailCodeAttempts": "5"}`, `{"accessTokenLifetime": 900}`, `[]`, `{}{}`, `{"emailCodeIterations": 9999}`, "{" + strings.Repeat(" ", 4096) + "}",
	}
	for _, document := range refused {
		if _, err = ParseIdentityPolicy(document); err == nil {
			t.Errorf("%s was admitted", document)
		}
	}
	for _, document := range []string{`{"stepUpEvidenceTtl": "5m"}`, `{"stepUpEvidenceTtl": "1m"}`, `{"emailCodeAttempts": 10}`, `{"emailCodeAttempts": 1}`} {
		if _, err = ParseIdentityPolicy(document); err != nil {
			t.Errorf("%s: %v", document, err)
		}
	}
	if _, err = Load(environment(withIdentity(SelfHosted, map[string]string{EnvIdentityPolicy: `{"unknown": 1}`}))); !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), EnvIdentityPolicy) {
		t.Fatalf("an invalid override starts: %v", err)
	}
}

// TestTheFleetSurfaceNeedsIdentityAndPagesAndIsInTheSelfHostedDefault pins the fleet surface (AF-CTR-04, delivery-14): it is a known
// name, it needs identity and pages, and since its pages exist (part E3) the self-hosted default includes it; official-hosted mode
// enables it only where it is listed.
func TestTheFleetSurfaceNeedsIdentityAndPagesAndIsInTheSelfHostedDefault(t *testing.T) {
	if !slices.Contains(KnownSurfaces(), SurfaceFleet) || !slices.Contains(DefaultSelfHostedSurfaces(), SurfaceFleet) {
		t.Fatalf("known %v, default %v", KnownSurfaces(), DefaultSelfHostedSurfaces())
	}
	cfg, err := Load(environment(withIdentity(SelfHosted, nil)))
	if err != nil || !cfg.Identity.Enabled(SurfaceFleet) || !cfg.Identity.Enabled(SurfacePages) || cfg.Identity.Enabled(SurfaceOperations) {
		t.Fatalf("the self-hosted default: %+v %v", cfg.Identity, err)
	}
	for _, list := range []string{"fleet", "identity,fleet", "pages,fleet"} {
		if _, err = Load(environment(withIdentity(SelfHosted, map[string]string{EnvSurfaces: list}))); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s starts: %v", list, err)
		}
	}
	if cfg, err = Load(environment(withIdentity(SelfHosted, map[string]string{EnvSurfaces: "identity,pages,fleet"}))); err != nil || !cfg.Identity.Enabled(SurfaceFleet) {
		t.Fatalf("identity,pages,fleet: %+v %v", cfg.Identity, err)
	}
}

// TestTheNodePolicyHasItsDefaultsBoundsAndRelations pins the node keys of the identity policy (AF-CTR-04: D CR-06, Q4, Q5, cloud-5):
// 60-minute access tokens (15 to 60 minutes), 90 days idle, 365 days absolute, 100 nodes per account (1 to 1000), and the three
// buckets with the convention of the other windows; a document that sets every key fits the override bound.
func TestTheNodePolicyHasItsDefaultsBoundsAndRelations(t *testing.T) {
	defaults := DefaultIdentityPolicy()
	if defaults.NodeAccessLifetime != time.Hour || defaults.NodeRefreshIdleLifetime != 90*24*time.Hour || defaults.NodeRefreshAbsolute != 365*24*time.Hour ||
		defaults.MaxNodesPerAccount != 100 || defaults.NodeRefreshPerPrefix != (Window{Limit: 120, Window: 10 * time.Minute}) ||
		defaults.NodeRefreshPerSession != (Window{Limit: 60, Window: 10 * time.Minute}) || defaults.NodeReportPerInstallation != (Window{Limit: 12, Window: time.Hour}) {
		t.Fatalf("node defaults %+v", defaults)
	}
	if lifetimes := defaults.NodeLifetimes(); lifetimes != (Lifetimes{Access: time.Hour, RefreshIdle: 90 * 24 * time.Hour, RefreshAbsolute: 365 * 24 * time.Hour}) {
		t.Fatalf("node lifetimes %+v", lifetimes)
	}
	if lifetimes := defaults.AccountLifetimes(); lifetimes != (Lifetimes{Access: 15 * time.Minute, RefreshIdle: 30 * 24 * time.Hour, RefreshAbsolute: 90 * 24 * time.Hour}) {
		t.Fatalf("account lifetimes %+v", lifetimes)
	}
	for _, document := range []string{`{"nodeAccessLifetime": "14m"}`, `{"nodeAccessLifetime": "61m"}`, `{"nodeRefreshIdleLifetime": "2161h"}`,
		`{"nodeRefreshAbsolute": "9601h"}`, `{"maxNodesPerAccount": 0}`, `{"maxNodesPerAccount": 1001}`, `{"nodeRefreshPrefixLimit": 0}`,
		`{"nodeRefreshSessionWindow": "30s"}`, `{"nodeReportInstallationWindow": "25h"}`, `{"nodeRefreshAbsolute": "24h", "nodeRefreshIdleLifetime": "25h"}`,
		`{"nodeRefreshIdleLifetime": "30m"}`} {
		if _, err := ParseIdentityPolicy(document); err == nil {
			t.Errorf("%s was admitted", document)
		}
	}
	every := `{"nodeAccessLifetime": "15m", "nodeRefreshIdleLifetime": "1h", "nodeRefreshAbsolute": "9600h", "maxNodesPerAccount": 1000,
"nodeRefreshPrefixLimit": 10000, "nodeRefreshPrefixWindow": "24h", "nodeRefreshSessionLimit": 1, "nodeRefreshSessionWindow": "1m",
"nodeReportInstallationLimit": 3, "nodeReportInstallationWindow": "2h"}`
	policy, err := ParseIdentityPolicy(every)
	if err != nil || policy.NodeAccessLifetime != 15*time.Minute || policy.MaxNodesPerAccount != 1000 || policy.NodeRefreshPerSession != (Window{Limit: 1, Window: time.Minute}) ||
		policy.NodeReportPerInstallation != (Window{Limit: 3, Window: 2 * time.Hour}) {
		t.Fatalf("every node key: %+v %v", policy, err)
	}
}

// TestTheBrowserSignInPolicyHasItsDefaultsAndBounds pins the keys of the browser node sign-in (AF-CTR-04 E1b; cloud-5 item 4): a
// 2-minute one-use code (30 seconds to 10 minutes; the flow's 10 minutes are the contract's and no key), and the four buckets with
// the convention of the other windows; a document that sets every node key at once still fits the override bound.
func TestTheBrowserSignInPolicyHasItsDefaultsAndBounds(t *testing.T) {
	defaults := DefaultIdentityPolicy()
	if defaults.NodeCodeLifetime != 2*time.Minute || defaults.NodeFlowPerPrefix != (Window{Limit: 10, Window: 10 * time.Minute}) ||
		defaults.NodeFlowPerNode != (Window{Limit: 10, Window: 10 * time.Minute}) || defaults.NodeCompletePerPrefix != (Window{Limit: 30, Window: 10 * time.Minute}) ||
		defaults.NodeApprovePerAccount != (Window{Limit: 20, Window: time.Hour}) {
		t.Fatalf("browser sign-in defaults %+v", defaults)
	}
	for _, document := range []string{`{"nodeCodeLifetime": "29s"}`, `{"nodeCodeLifetime": "11m"}`, `{"nodeFlowPrefixLimit": 0}`, `{"nodeFlowNodeWindow": "59s"}`,
		`{"nodeCompletePrefixLimit": 10001}`, `{"nodeApproveAccountWindow": "25h"}`, `{"nodeFlowLifetime": "20m"}`} {
		if _, err := ParseIdentityPolicy(document); err == nil {
			t.Errorf("%s was admitted", document)
		}
	}
	every := `{"nodeAccessLifetime": "15m", "nodeRefreshIdleLifetime": "1h", "nodeRefreshAbsolute": "9600h", "maxNodesPerAccount": 1000,
"nodeRefreshPrefixLimit": 10000, "nodeRefreshPrefixWindow": "24h", "nodeRefreshSessionLimit": 1, "nodeRefreshSessionWindow": "1m",
"nodeReportInstallationLimit": 3, "nodeReportInstallationWindow": "2h", "nodeCodeLifetime": "30s", "nodeFlowPrefixLimit": 10000,
"nodeFlowPrefixWindow": "24h", "nodeFlowNodeLimit": 1, "nodeFlowNodeWindow": "1m", "nodeCompletePrefixLimit": 5, "nodeCompletePrefixWindow": "3m",
"nodeApproveAccountLimit": 2, "nodeApproveAccountWindow": "2h"}`
	if len(every) > MaxIdentityPolicyBytes {
		t.Fatalf("a document with every node key is %d bytes", len(every))
	}
	policy, err := ParseIdentityPolicy(every)
	if err != nil || policy.NodeCodeLifetime != 30*time.Second || policy.NodeFlowPerPrefix != (Window{Limit: 10000, Window: 24 * time.Hour}) ||
		policy.NodeFlowPerNode != (Window{Limit: 1, Window: time.Minute}) || policy.NodeCompletePerPrefix != (Window{Limit: 5, Window: 3 * time.Minute}) ||
		policy.NodeApprovePerAccount != (Window{Limit: 2, Window: 2 * time.Hour}) {
		t.Fatalf("every browser sign-in key: %+v %v", policy, err)
	}
}

// TestTheDeviceSignInPolicyHasItsDefaultsAndBounds pins the keys of the device-code sign-in (AF-CTR-04 E2; cloud-5 item 4): the
// poll failure bucket per network and the two user-code entry budgets, with the convention of the other windows. The poll interval,
// the authorization's lifetime and the 5 lookups of a live code are contract values and no keys, so a document naming them is
// refused. A document that sets every node key at once still fits the override bound.
func TestTheDeviceSignInPolicyHasItsDefaultsAndBounds(t *testing.T) {
	defaults := DefaultIdentityPolicy()
	if defaults.NodePollPerPrefix != (Window{Limit: 120, Window: 10 * time.Minute}) || defaults.DeviceEntryPerAccount != (Window{Limit: 5, Window: 15 * time.Minute}) ||
		defaults.DeviceEntryPerPrefix != (Window{Limit: 20, Window: 15 * time.Minute}) {
		t.Fatalf("device sign-in defaults %+v", defaults)
	}
	for _, document := range []string{`{"nodePollPrefixLimit": 0}`, `{"nodePollPrefixWindow": "59s"}`, `{"deviceEntryAccountLimit": 10001}`,
		`{"deviceEntryAccountWindow": "25h"}`, `{"deviceEntryPrefixLimit": 0}`, `{"devicePollInterval": "5s"}`, `{"deviceAuthorizationLifetime": "10m"}`,
		`{"nodePollAuthorizationLimit": 6}`, `{"deviceCodeLookups": 5}`} {
		if _, err := ParseIdentityPolicy(document); err == nil {
			t.Errorf("%s was admitted", document)
		}
	}
	every := `{"nodeAccessLifetime": "15m", "nodeRefreshIdleLifetime": "1h", "nodeRefreshAbsolute": "9600h", "maxNodesPerAccount": 1000,
"nodeRefreshPrefixLimit": 10000, "nodeRefreshPrefixWindow": "24h", "nodeRefreshSessionLimit": 1, "nodeRefreshSessionWindow": "1m",
"nodeReportInstallationLimit": 3, "nodeReportInstallationWindow": "2h", "nodeCodeLifetime": "30s", "nodeFlowPrefixLimit": 10000,
"nodeFlowPrefixWindow": "24h", "nodeFlowNodeLimit": 1, "nodeFlowNodeWindow": "1m", "nodeCompletePrefixLimit": 5, "nodeCompletePrefixWindow": "3m",
"nodeApproveAccountLimit": 2, "nodeApproveAccountWindow": "2h", "nodePollPrefixLimit": 7, "nodePollPrefixWindow": "4m",
"deviceEntryAccountLimit": 1, "deviceEntryAccountWindow": "24h", "deviceEntryPrefixLimit": 10000, "deviceEntryPrefixWindow": "1m"}`
	if len(every) > MaxIdentityPolicyBytes {
		t.Fatalf("a document with every node key is %d bytes", len(every))
	}
	policy, err := ParseIdentityPolicy(every)
	if err != nil || policy.NodePollPerPrefix != (Window{Limit: 7, Window: 4 * time.Minute}) || policy.DeviceEntryPerAccount != (Window{Limit: 1, Window: 24 * time.Hour}) ||
		policy.DeviceEntryPerPrefix != (Window{Limit: 10000, Window: time.Minute}) {
		t.Fatalf("every device sign-in key: %+v %v", policy, err)
	}
}

// TestTheFleetSurfaceRefusesABaseURLTooLongForItsURLs (OQ-13): with fleet enabled the public base URL is at most 462 characters, so
// every URL the center derives for a node stays within the contract's 512; without fleet the longer URL still starts.
func TestTheFleetSurfaceRefusesABaseURLTooLongForItsURLs(t *testing.T) {
	prefix := "https://center.example.test/"
	for length, starts := range map[int]bool{MaxFleetPublicBaseURLLength: true, MaxFleetPublicBaseURLLength + 1: false} {
		base := prefix + strings.Repeat("a", length-len(prefix))
		_, err := Load(environment(withIdentity(SelfHosted, map[string]string{EnvSurfaces: "identity,pages,fleet", EnvPublicBaseURL: base})))
		if (err == nil) != starts || !starts && !errors.Is(err, ErrInvalid) {
			t.Errorf("a base URL of %d characters: %v", length, err)
		}
		if _, err = Load(environment(withIdentity(SelfHosted, map[string]string{EnvSurfaces: "identity,pages", EnvPublicBaseURL: base}))); err != nil {
			t.Errorf("without fleet, %d characters: %v", length, err)
		}
	}
}
