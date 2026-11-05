// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
)

// The command-signing keys of the node channel (AF-CTR-05 E1a, Plan CTR5-KEY-01 and CTR5-SIG-02; ArcForges-Design 11 section 3,
// "Command signing key"). A key's private half lives only in the environment variable its fleet.signing_key row names
// (secret_binding); the center reads every variable of the form ARCFORGES_CENTER_KEY_<NAME> once at start, as the base64 of the PKCS#8
// DER of an ECDSA P-256 key, unsets it from the process environment and never logs or prints it. The start then refuses a center that
// serves the relay surface without a valid command key whose private half it holds, and one whose loaded key does not match the
// public half its row registers (server.CheckCommandKeys). Signing calls is AF-CTR-05 E1b's.

// CommandKeyPrefix is the prefix of a command key's variable; the whole name matches CommandKeyName.
const CommandKeyPrefix = "ARCFORGES_CENTER_KEY_"

// CommandKeyName is the pattern of a command key's variable.
var CommandKeyName = regexp.MustCompile(`^ARCFORGES_CENTER_KEY_[A-Z0-9_]{1,40}$`)

// maxCommandKeys bounds the keys a center loads (a key and its successor, with room for a rotation's overlap).
const maxCommandKeys = 8

// CommandKey is one loaded command key: its binding (the variable's name, a fleet.signing_key secret_binding) and its private half.
// Like Secret, every formatting method prints a fixed marker and the private half sits behind a pointer; only Signer returns it.
type CommandKey struct {
	Binding string
	key     *ecdsa.PrivateKey
}

// PublicKey is the PKIX DER of the key's public half, as fleet.signing_key.public_key stores it.
func (k CommandKey) PublicKey() []byte {
	if k.key == nil {
		return nil
	}
	der, err := x509.MarshalPKIXPublicKey(&k.key.PublicKey)
	if err != nil {
		return nil
	}
	return der
}

// Signer is the private half, for the one signer of routed calls (AF-CTR-05 E1b).
func (k CommandKey) Signer() *ecdsa.PrivateKey { return k.key }

// String is the binding with the marker.
func (k CommandKey) String() string { return k.Binding + "=" + redacted }

// GoString is String.
func (k CommandKey) GoString() string { return k.String() }

// Format prints String for every verb.
func (k CommandKey) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(k.String())) }

// LogValue is the binding only.
func (k CommandKey) LogValue() slog.Value { return slog.StringValue(k.Binding) }

// MarshalText is the binding only.
func (k CommandKey) MarshalText() ([]byte, error) { return []byte(k.Binding), nil }

// NewCommandKey wraps a private key under a binding (tests generate one per test; LoadCommandKeys reads the environment).
func NewCommandKey(binding string, key *ecdsa.PrivateKey) (CommandKey, error) {
	if !CommandKeyName.MatchString(binding) || key == nil || key.Curve != elliptic.P256() {
		return CommandKey{}, errors.New("a command key is an ECDSA P-256 key under an ARCFORGES_CENTER_KEY_ binding")
	}
	return CommandKey{Binding: binding, key: key}, nil
}

// LoadCommandKeys reads the command keys of an environment (os.Environ in production): every variable with CommandKeyPrefix must
// match CommandKeyName and hold the standard base64 of a PKCS#8 ECDSA P-256 key, at most eight of them; anything else refuses the
// start with an error that names the variable, never its value. The names it read are returned too, so the caller unsets them.
func LoadCommandKeys(environ []string) ([]CommandKey, []string, error) {
	var keys []CommandKey
	var names []string
	for _, entry := range environ {
		name, value, _ := strings.Cut(entry, "=")
		if !strings.HasPrefix(name, CommandKeyPrefix) {
			continue
		}
		names = append(names, name)
		if !CommandKeyName.MatchString(name) {
			return nil, names, invalid("%s is not a command key variable name (%s)", name, CommandKeyName.String())
		}
		der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
		if err != nil {
			return nil, names, invalid("%s must be the base64 of a PKCS#8 ECDSA P-256 private key", name)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		private, ok := parsed.(*ecdsa.PrivateKey)
		if err != nil || !ok || private.Curve != elliptic.P256() {
			return nil, names, invalid("%s must be the base64 of a PKCS#8 ECDSA P-256 private key", name)
		}
		keys = append(keys, CommandKey{Binding: name, key: private})
	}
	if len(keys) > maxCommandKeys {
		return nil, names, invalid("at most %d command keys (%s*)", maxCommandKeys, CommandKeyPrefix)
	}
	slices.SortFunc(keys, func(a, b CommandKey) int { return strings.Compare(a.Binding, b.Binding) })
	return keys, names, nil
}

// ApplyCommandKeys gives the configuration the loaded command keys. The relay surface needs at least one: where it came from the
// self-hosted default and no key is loaded it is left out (the start never refuses for the default; RelayDisabled says why), and a
// list that names it without a key refuses to start.
func (c *Config) ApplyCommandKeys(keys []CommandKey) error {
	c.CommandKeys = append([]CommandKey(nil), keys...)
	if len(keys) > 0 || !c.Identity.Enabled(SurfaceRelay) {
		return nil
	}
	if !c.Identity.DefaultSurfaces {
		return invalid("the %s surface needs a command key (%s<NAME>, the binding of a fleet.signing_key row)", SurfaceRelay, CommandKeyPrefix)
	}
	c.Identity.Surfaces = slices.DeleteFunc(c.Identity.Surfaces, func(surface Surface) bool { return surface == SurfaceRelay })
	c.Identity.RelayDisabled = "no command key is configured (" + CommandKeyPrefix + "<NAME>)"
	return nil
}
