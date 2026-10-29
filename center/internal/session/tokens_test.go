// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestTheBootstrapDigestIsTheSHA256OfTheTokenText pins the configured form of the owner bootstrap token (E3): the SHA-256 of the
// exact token text, prefix included, as `printf %s "$TOKEN" | sha256sum` prints it; not the digest of its decoded bytes.
func TestTheBootstrapDigestIsTheSHA256OfTheTokenText(t *testing.T) {
	token := BootstrapPrefix + strings.Repeat("A", EncodedLength)
	secret, ok := ParseToken(BootstrapPrefix, token)
	digest := BootstrapDigest(token)
	if !ok || hex.EncodeToString(digest[:]) != "09e0b22a38f1d38f287867c42c2969cf2063ee0194d43f87cb6f1ec7654df8b8" || digest == secret.Digest() {
		t.Fatalf("the bootstrap digest of %s is %x", token, digest)
	}
}

func TestCredentialsHaveExactFormats(t *testing.T) {
	secret := NewSecret()
	for _, prefix := range []string{AccessPrefix, RefreshPrefix, BootstrapPrefix} {
		token := secret.Token(prefix)
		if len(token) != len(prefix)+EncodedLength {
			t.Fatalf("%s length %d", prefix, len(token))
		}
		parsed, ok := ParseToken(prefix, token)
		if !ok || parsed != secret {
			t.Fatalf("%s does not parse back", prefix)
		}
		for _, other := range []string{AccessPrefix, RefreshPrefix, BootstrapPrefix} {
			if other != prefix {
				if _, ok = ParseToken(other, token); ok {
					t.Fatalf("a %s token parsed as %s", prefix, other)
				}
			}
		}
	}
	text := secret.Text()
	invalid := []string{"", text[:42], text + "A", strings.Replace(text, text[:1], "+", 1), text[:42] + "=", " " + text[1:]}
	// The last character of a 43-character base64url string carries only two bits; another value is a non-canonical spelling.
	last := text[42]
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
		if byte(c) != last {
			if _, ok := ParseHandle(text[:42] + string(c)); ok {
				parsed, _ := ParseHandle(text[:42] + string(c))
				if parsed.Text() != text[:42]+string(c) {
					t.Fatal("a non-canonical spelling parsed")
				}
			}
		}
	}
	for _, value := range invalid {
		if _, ok := ParseHandle(value); ok {
			t.Errorf("%q parsed", value)
		}
	}
	if secret.Digest() != sha256.Sum256(secret[:]) {
		t.Fatal("the digest is SHA-256 of the raw bytes")
	}
	if NewSecret() == secret {
		t.Fatal("two secrets are equal")
	}
}

func TestTheCSRFTokenIsBoundToItsHandle(t *testing.T) {
	handle, other := NewSecret(), NewSecret()
	token := CSRF(handle)
	if len(token) != EncodedLength || !CheckCSRF(handle, token) || CSRF(handle) != token {
		t.Fatal("the CSRF token of a handle")
	}
	if CheckCSRF(other, token) || CheckCSRF(handle, CSRF(other)) || CheckCSRF(handle, "") || CheckCSRF(handle, token+"A") || CheckCSRF(handle, token[:42]) {
		t.Fatal("a CSRF token of another handle or of another length matched")
	}
	if token == handle.Text() {
		t.Fatal("the CSRF token is the handle")
	}
}

// TestThePreSessionCSRFIsAFunctionOfTheOriginAlone (decision 4.2): a public constant derived from the origin, 43 base64url
// characters, different for every origin and for the session's own derived token.
func TestThePreSessionCSRFIsAFunctionOfTheOriginAlone(t *testing.T) {
	const origin = "https://arcforges.com"
	token := PreSessionCSRF(origin)
	// SHA-256 of "af-csrf-pre-v1\n" + origin, unpadded base64url: a fixed answer, so the label can never change by accident.
	if token != "lFQXZwfA0cmNHDo26xwWyrCfqRfgY4SqfivQXhp1Pv0" {
		t.Fatalf("the constant is %q", token)
	}
	if len(token) != EncodedLength || token != PreSessionCSRF(origin) || token == PreSessionCSRF("https://proof.arcforges.com") || token == PreSessionCSRF(origin+"/") {
		t.Fatal("the constant is not a function of the origin")
	}
	secret := NewSecret()
	if token == CSRF(secret) {
		t.Fatal("a session's token is the constant")
	}
	if _, ok := ParseHandle(token); !ok {
		t.Fatal("the constant is not a 43-character base64url token")
	}
}
