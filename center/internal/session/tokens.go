// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

// The credential formats (AD-0021 section 5): a prefix naming the kind and version, and 32 random bytes in unpadded base64url
// (43 characters). Only the SHA-256 of a credential is stored.
const (
	// AccessPrefix marks a native access token (the bearer of every call).
	AccessPrefix = "afa1."
	// RefreshPrefix marks a native refresh token (RefreshSession only).
	RefreshPrefix = "afr1."
	// BootstrapPrefix marks the owner bootstrap token, whose SHA-256 (BootstrapDigest) is deployment configuration.
	BootstrapPrefix = "afb1."
	// EncodedLength is the length of the random part, and of a browser cookie handle (which has no prefix).
	EncodedLength = 43
	// csrfLabel is the HMAC message of a browser session's CSRF token.
	csrfLabel = "af-csrf-v1"
)

// Secret is the random part of a credential.
type Secret [32]byte

// NewSecret draws a credential from the system's cryptographic random source.
func NewSecret() Secret {
	var secret Secret
	if _, err := rand.Read(secret[:]); err != nil {
		panic(err)
	}
	return secret
}

// Text is the unpadded base64url form of the secret (a cookie handle).
func (s Secret) Text() string { return base64.RawURLEncoding.EncodeToString(s[:]) }

// Token is the secret with a prefix.
func (s Secret) Token(prefix string) string { return prefix + s.Text() }

// Digest is the stored form: SHA-256 of the 32 raw bytes.
func (s Secret) Digest() [32]byte { return sha256.Sum256(s[:]) }

// BootstrapDigest is the configured form of the owner bootstrap token (ARCFORGES_CENTER_BOOTSTRAP_SHA256): the SHA-256 of the exact
// token text, its prefix included, as `printf %s "$TOKEN" | sha256sum` prints it in lowercase hexadecimal. It is not the digest of
// the token's decoded bytes, which the other credentials store.
func BootstrapDigest(token string) [32]byte { return sha256.Sum256([]byte(token)) }

// ParseToken reads a prefixed credential: the exact prefix and 43 canonical base64url characters; anything else is no
// credential.
func ParseToken(prefix, text string) (Secret, bool) {
	rest, ok := strings.CutPrefix(text, prefix)
	if !ok {
		return Secret{}, false
	}
	return ParseHandle(rest)
}

// ParseHandle reads 43 canonical base64url characters.
func ParseHandle(text string) (Secret, bool) {
	var secret Secret
	if len(text) != EncodedLength {
		return Secret{}, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(text)
	if err != nil || len(decoded) != len(secret) || base64.RawURLEncoding.EncodeToString(decoded) != text {
		return Secret{}, false
	}
	copy(secret[:], decoded)
	return secret, true
}

// CSRF is the CSRF token of a browser session: base64url(HMAC-SHA-256(key = the raw cookie handle, "af-csrf-v1")). It is derived,
// never stored, so it lives exactly as long as the session's handle.
func CSRF(handle Secret) string {
	mac := hmac.New(sha256.New, handle[:])
	mac.Write([]byte(csrfLabel))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// CheckCSRF compares a presented CSRF token with the session's in constant time; only exactly 43 characters can match.
func CheckCSRF(handle Secret, token string) bool {
	if len(token) != EncodedLength {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(CSRF(handle)), []byte(token)) == 1
}
