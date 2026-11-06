// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

func pkcs8(t *testing.T, curve elliptic.Curve) (string, *ecdsa.PrivateKey) {
	t.Helper()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der), private
}

// TestCommandKeysLoadOnlyAsTheirRuleAllows (CTR5-KEY-01): an ARCFORGES_CENTER_KEY_ variable must be a valid name holding the base64 of
// a PKCS#8 P-256 key; at most eight load; a refusal names the variable, never its value; every name with the prefix is reported for unsetting, a malformed one first included.
func TestCommandKeysLoadOnlyAsTheirRuleAllows(t *testing.T) {
	good, private := pkcs8(t, elliptic.P256())
	other, _ := pkcs8(t, elliptic.P384())
	keys, names, err := LoadCommandKeys([]string{"PATH=/bin", "ARCFORGES_CENTER_KEY_B=" + good, "ARCFORGES_CENTER_KEY_A=" + good})
	if err != nil || len(keys) != 2 || keys[0].Binding != "ARCFORGES_CENTER_KEY_A" || len(names) != 2 {
		t.Fatalf("%v %v %v", keys, names, err)
	}
	public, _ := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if !bytes.Equal(keys[0].PublicKey(), public) || keys[0].Signer() == nil {
		t.Fatal("the loaded key is not the variable's")
	}
	for name, entry := range map[string]string{
		"a lower-case name": "ARCFORGES_CENTER_KEY_a=" + good,
		"an empty suffix":   "ARCFORGES_CENTER_KEY_=" + good,
		"not base64":        "ARCFORGES_CENTER_KEY_X=%%%",
		"not PKCS#8":        "ARCFORGES_CENTER_KEY_X=" + base64.StdEncoding.EncodeToString([]byte("key")),
		"another curve":     "ARCFORGES_CENTER_KEY_X=" + other,
	} {
		_, names, err := LoadCommandKeys([]string{entry})
		if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), good) || strings.Contains(err.Error(), other) || len(names) != 1 {
			t.Errorf("%s: %v %v", name, names, err)
		}
	}
	many := []string{}
	for index := range 9 {
		many = append(many, fmt.Sprintf("ARCFORGES_CENTER_KEY_K%d=%s", index, good))
	}
	if _, _, err := LoadCommandKeys(many); !errors.Is(err, ErrInvalid) {
		t.Errorf("nine keys: %v", err)
	}
	// A malformed entry first: every name with the prefix is still reported, so the caller unsets the ones after it too.
	_, names, err = LoadCommandKeys([]string{"ARCFORGES_CENTER_KEY_X=%%%", "PATH=/bin", "ARCFORGES_CENTER_KEY_Y=" + good, "ARCFORGES_CENTER_KEY_z=" + good})
	if !errors.Is(err, ErrInvalid) || !slices.Equal(names, []string{"ARCFORGES_CENTER_KEY_X", "ARCFORGES_CENTER_KEY_Y", "ARCFORGES_CENTER_KEY_z"}) {
		t.Errorf("a malformed entry first: %v %v", names, err)
	}
}

// TestACommandKeyNeverPrintsItsPrivateHalf (SEC-19): every formatting of a loaded key, a log line and JSON show its binding only.
func TestACommandKeyNeverPrintsItsPrivateHalf(t *testing.T) {
	_, private := pkcs8(t, elliptic.P256())
	key, err := NewCommandKey("ARCFORGES_CENTER_KEY_TEST", private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := private.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	secret := hex.EncodeToString(raw)
	var logged bytes.Buffer
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("loaded", "key", key, "keys", []CommandKey{key})
	data, _ := json.Marshal(struct{ Key CommandKey }{key})
	for _, text := range []string{fmt.Sprint(key), fmt.Sprintf("%v %+v %#v %s %q", key, key, key, key, key), logged.String(), string(data),
		fmt.Sprintf("%+v", Config{CommandKeys: []CommandKey{key}})} {
		if strings.Contains(text, secret) || !strings.Contains(text, "ARCFORGES_CENTER_KEY_TEST") && !strings.Contains(text, redacted) {
			t.Errorf("a formatting shows the private half or nothing: %s", text)
		}
	}
	if _, err := NewCommandKey("OTHER", private); err == nil {
		t.Error("a binding outside the prefix was admitted")
	}
}

// TestTheRelaySurfaceNeedsACommandKey (CTR5-SIG-02): a list that names relay without a key refuses to start; the self-hosted default
// leaves relay out and says why; with a key both keep it.
func TestTheRelaySurfaceNeedsACommandKey(t *testing.T) {
	_, private := pkcs8(t, elliptic.P256())
	key, _ := NewCommandKey("ARCFORGES_CENTER_KEY_TEST", private)
	listed := withIdentity(SelfHosted, map[string]string{EnvSurfaces: "identity,pages,fleet,relay"})
	cfg, err := Load(environment(listed))
	if err != nil {
		t.Fatal(err)
	}
	if err = cfg.ApplyCommandKeys(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("relay listed without a key: %v", err)
	}
	cfg, _ = Load(environment(listed))
	if err = cfg.ApplyCommandKeys([]CommandKey{key}); err != nil || !cfg.Identity.Enabled(SurfaceRelay) {
		t.Fatalf("relay listed with a key: %v", err)
	}
	defaulted := withIdentity(SelfHosted, map[string]string{})
	cfg, err = Load(environment(defaulted))
	if err != nil || !cfg.Identity.DefaultSurfaces || !cfg.Identity.Enabled(SurfaceRelay) {
		t.Fatalf("the default: %v %v", cfg.Identity.Surfaces, err)
	}
	if err = cfg.ApplyCommandKeys(nil); err != nil || cfg.Identity.Enabled(SurfaceRelay) || cfg.Identity.RelayDisabled == "" || !cfg.Identity.Enabled(SurfaceFleet) {
		t.Fatalf("the default without a key: %v %v %q", err, cfg.Identity.Surfaces, cfg.Identity.RelayDisabled)
	}
}

// TestTheNodesSurfaceNeedsTheRelaySurface (AF-CTR-05 E2a; Plan CTR5-SUR-01): a list that names nodes without identity, fleet or relay
// refuses to start; the self-hosted default carries nodes with relay and leaves both out when no command key is configured.
func TestTheNodesSurfaceNeedsTheRelaySurface(t *testing.T) {
	for _, list := range []string{"identity,pages,fleet,nodes", "identity,pages,relay,nodes", "nodes"} {
		if _, err := Load(environment(withIdentity(SelfHosted, map[string]string{EnvSurfaces: list}))); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", list, err)
		}
	}
	cfg, err := Load(environment(withIdentity(SelfHosted, map[string]string{EnvSurfaces: "identity,pages,fleet,relay,nodes"})))
	if err != nil || !cfg.Identity.Enabled(SurfaceNodes) {
		t.Fatalf("nodes with its surfaces: %v %v", cfg.Identity.Surfaces, err)
	}
	cfg, err = Load(environment(withIdentity(SelfHosted, map[string]string{})))
	if err != nil || !cfg.Identity.Enabled(SurfaceNodes) || !cfg.Identity.Enabled(SurfaceRelay) {
		t.Fatalf("the default: %v %v", cfg.Identity.Surfaces, err)
	}
	if err = cfg.ApplyCommandKeys(nil); err != nil || cfg.Identity.Enabled(SurfaceNodes) || cfg.Identity.Enabled(SurfaceRelay) {
		t.Fatalf("the default without a key: %v %v", err, cfg.Identity.Surfaces)
	}
}
