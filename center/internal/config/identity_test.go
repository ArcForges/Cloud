// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
		t.Fatalf("self-hosted enables every surface by default: %+v %v", self.Identity, err)
	}
	enabled, err := Load(environment(withIdentity(OfficialHosted, map[string]string{EnvSurfaces: "identity", EnvClientIPHeader: ClientIPHeader})))
	if err != nil || !enabled.Identity.Enabled(SurfaceIdentity) || enabled.Identity.ClientIPHeader != ClientIPHeader {
		t.Fatalf("listed: %+v %v", enabled.Identity, err)
	}
	none, err := Load(environment(withIdentity(SelfHosted, map[string]string{EnvSurfaces: "none"})))
	if err != nil || len(none.Identity.Surfaces) != 0 {
		t.Fatalf("none: %+v %v", none.Identity, err)
	}
	for _, value := range []string{"Identity", "identity,", ",identity", "identity,identity", " identity", "identity ", "operations", "identity,none"} {
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
	if err != nil || cfg.Identity.Enabled(SurfaceIdentity) || !strings.Contains(cfg.Identity.Disabled, "domain name") {
		t.Fatalf("the default with an IP host: %+v %v", cfg.Identity, err)
	}
	values[EnvSurfaces] = "identity"
	if _, err = Load(environment(values)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an explicit list with an IP host starts: %v", err)
	}
	noStore := minimal(SelfHosted)
	cfg, err = Load(environment(noStore))
	if err != nil || cfg.Identity.Enabled(SurfaceIdentity) || !strings.Contains(cfg.Identity.Disabled, EnvDatabaseURL) {
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
