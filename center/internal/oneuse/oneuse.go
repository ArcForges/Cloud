// SPDX-License-Identifier: AGPL-3.0-only

// Package oneuse holds the pure functions of one-use codes and PKCE (AF-CTR-04; RFC 7636): a one-use code drawn as 32 random bytes in
// 43 canonical unpadded base64url characters and stored only as the SHA-256 of those bytes (session.Secret), the constant-time compare
// of a presented code with a stored digest, the S256 verification of a PKCE verifier against its challenge, and the character
// classes of the challenge, the verifier and a client state. It opens no transaction and reads no store. The browser node sign-in
// (package fleet) uses it; the device-code sign-in (part E2) will reuse it, and the mobile native authorization (part M) will reuse
// the pure functions with redirect rules of its own: the loopback redirect admission and the query-form delivery are the fleet
// package's (delivery-16).
package oneuse

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"

	"github.com/ArcForges/Cloud/center/internal/session"
)

// CodeLength is the length of a one-use code: 32 random bytes in unpadded base64url.
const CodeLength = 43

// NewCode draws a one-use code from the system's cryptographic random source and returns its text, which is shown once, and its
// stored digest (the SHA-256 of the 32 raw bytes).
func NewCode() (text string, digest [32]byte) {
	secret := session.NewSecret()
	return secret.Text(), secret.Digest()
}

// ParseCode reads a presented code: exactly 43 canonical base64url characters (session.ParseHandle: a string that does not re-encode
// to itself, such as one whose last character differs only in the unused bits, is no code).
func ParseCode(text string) (session.Secret, bool) {
	return session.ParseHandle(text)
}

// dummy is the digest a presented code is compared with when the stored row has none, so that a missing digest and a wrong code take
// the same work and give the same answer.
var dummy = sha256.Sum256([]byte("arcforges oneuse: no code was issued"))

// Matches reports whether a presented code text is the code of a stored digest: the text is parsed (a malformed text matches nothing)
// and its digest is compared in constant time with the stored one, or with a fixed dummy when stored is not a 32-byte digest. The
// compare runs in every case, so the answer and its timing do not tell a missing digest from a wrong code.
func Matches(text string, stored []byte) bool {
	secret, parsed := ParseCode(text)
	presented := secret.Digest()
	return Equal(presented, stored) && parsed
}

// Equal compares a presented digest with a stored one in constant time; a stored value that is not a 32-byte digest is replaced by
// the dummy digest for the compare and never matches.
func Equal(presented [32]byte, stored []byte) bool {
	target, present := dummy, len(stored) == len(dummy)
	if present {
		copy(target[:], stored)
	}
	return subtle.ConstantTimeCompare(presented[:], target[:]) == 1 && present
}

// charset reports whether every byte of text is an RFC 3986 unreserved character ([A-Za-z0-9._~-]); base64url admits only
// [A-Za-z0-9_-].
func charset(text string, base64url bool) bool {
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		case !base64url && (c == '.' || c == '~'):
		default:
			return false
		}
	}
	return true
}

// ValidChallenge admits a PKCE S256 challenge: exactly 43 characters of [A-Za-z0-9_-] (the unpadded base64url of a SHA-256; S256 is
// the only method, there is no plain).
func ValidChallenge(text string) bool {
	return len(text) == CodeLength && charset(text, true)
}

// ValidVerifier admits a PKCE verifier: 43 to 128 characters of [A-Za-z0-9._~-] (RFC 7636 section 4.1).
func ValidVerifier(text string) bool {
	return len(text) >= 43 && len(text) <= 128 && charset(text, false)
}

// ValidState admits a client state: 16 to 128 characters of [A-Za-z0-9._~-] (returned unchanged in a redirect, so it needs no
// encoding).
func ValidState(text string) bool {
	return len(text) >= 16 && len(text) <= 128 && charset(text, false)
}

// VerifyS256 reports whether a verifier is admitted and BASE64URL(SHA-256(verifier)) equals the challenge, compared in constant time.
func VerifyS256(verifier, challenge string) bool {
	digest := sha256.Sum256([]byte(verifier))
	derived := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtle.ConstantTimeCompare([]byte(derived), []byte(challenge)) == 1 && ValidVerifier(verifier) && ValidChallenge(challenge)
}
