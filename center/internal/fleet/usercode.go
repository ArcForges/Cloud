// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"crypto/rand"
	"crypto/sha256"
	"strings"
)

// UserCodeAlphabet is the alphabet of a device user code (C0: "8 characters from BCDFGHJKLMNPQRSTVWXZ"): 20 upper-case consonants
// without vowels, so a code spells no word, and without letters that read like digits.
const UserCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"

// UserCodeLength is the length of a user code: 8 letters of the alphabet, 20^8 = 2.56e10 codes (34.5 bits).
const UserCodeLength = 8

// userCodeBound is the rejection bound of the draw: 240 = 12 x 20, so a byte below it taken modulo 20 is uniform over the alphabet.
const userCodeBound = 240

// NewUserCode draws a user code from the system's cryptographic random source by rejection (a byte below 240 is accepted, its
// letter is the byte modulo 20), so every letter is equally likely.
func NewUserCode() string {
	code := make([]byte, 0, UserCodeLength)
	buffer := make([]byte, 16)
	for len(code) < UserCodeLength {
		if _, err := rand.Read(buffer); err != nil {
			panic(err)
		}
		for _, b := range buffer {
			if b < userCodeBound && len(code) < UserCodeLength {
				code = append(code, UserCodeAlphabet[int(b)%len(UserCodeAlphabet)])
			}
		}
	}
	return string(code)
}

// NormalizeUserCode reads a presented user code (C0 validate: "8 characters from the code alphabet; separators ignored"): '-' and
// spaces (U+0020) are removed, the ASCII letters a to z are upper-cased (no other case mapping), and the result must be exactly 8
// letters of the alphabet. It is the normalized code, the text the step-up of an approval is bound to.
func NormalizeUserCode(raw string) (string, bool) {
	var code strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '-' || c == ' ':
			continue
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		if strings.IndexByte(UserCodeAlphabet, c) < 0 || code.Len() == UserCodeLength {
			return "", false
		}
		code.WriteByte(c)
	}
	if code.Len() != UserCodeLength {
		return "", false
	}
	return code.String(), true
}

// DisplayUserCode is a normalized user code as people read it: XXXX-XXXX.
func DisplayUserCode(code string) string { return code[:4] + "-" + code[4:] }

// userCodeDigest is the stored form of a normalized user code: the SHA-256 of its 8 letters (unsalted: a database reader can reverse
// it within the code's 600 seconds, the accepted residual SEC-22).
func userCodeDigest(code string) []byte {
	digest := sha256.Sum256([]byte(code))
	return digest[:]
}
