// SPDX-License-Identifier: AGPL-3.0-only

package passkey

// WithoutUserVerification is a copy of a relying party that does not require user verification, so the tests can show that the
// W3C vectors (which do not set it) fail on that check alone.
func WithoutUserVerification(rp *RelyingParty) *RelyingParty {
	copied := *rp
	copied.requireUV = false
	return &copied
}

// AttestationIsNone is the format peek that runs before the library parses a registration (G3).
func AttestationIsNone(object []byte) bool { return attestationIsNone(object) }
