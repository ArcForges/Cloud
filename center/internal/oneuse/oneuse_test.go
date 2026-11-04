// SPDX-License-Identifier: AGPL-3.0-only

package oneuse

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// EVIDENCE: REAL (pure functions; the RFC 7636 appendix B vector).

func TestANewCodeIs43CanonicalCharactersStoredAsTheDigestOfItsBytes(t *testing.T) {
	seen := map[string]bool{}
	for range 64 {
		text, digest := NewCode()
		raw, err := base64.RawURLEncoding.DecodeString(text)
		if err != nil || len(text) != CodeLength || len(raw) != 32 || digest != sha256.Sum256(raw) || digest == sha256.Sum256([]byte(text)) {
			t.Fatalf("code %q: length %d, %d bytes, digest %x", text, len(text), len(raw), digest)
		}
		if seen[text] {
			t.Fatalf("code %q drawn twice", text)
		}
		seen[text] = true
		if !Matches(text, digest[:]) {
			t.Fatalf("code %q does not match its digest", text)
		}
	}
}

func TestOnlyTheExactCanonicalCodeMatches(t *testing.T) {
	text, digest := NewCode()
	other, otherDigest := NewCode()
	// The last character carries two unused bits: a variant that differs only there decodes to the same bytes and must not match.
	last := text[len(text)-1]
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	index := strings.IndexByte(alphabet, last)
	variant := text[:len(text)-1] + string(alphabet[index^1])
	for _, candidate := range []string{"", text[:42], text + "A", text + "=", strings.ReplaceAll(strings.ReplaceAll(text, "-", "+"), "_", "/") + "+",
		" " + text[1:], text[:42] + "/", text[:42] + "+", variant, other, strings.ToUpper(text)} {
		if candidate == text {
			continue
		}
		if Matches(candidate, digest[:]) {
			t.Fatalf("%q matched the digest of %q", candidate, text)
		}
	}
	if !Matches(other, otherDigest[:]) {
		t.Fatal("a code does not match its own digest")
	}
	for _, stored := range [][]byte{nil, {}, digest[:31], append(digest[:], 0), dummy[:]} {
		if Matches(text, stored) {
			t.Fatalf("a code matched the stored value %x", stored)
		}
	}
	// The dummy digest never matches, not even the bytes it is.
	if Equal(dummy, nil) || Equal(dummy, dummy[:31]) {
		t.Fatal("the dummy digest matched a missing digest")
	}
	if !Equal(digest, digest[:]) || Equal(digest, otherDigest[:]) {
		t.Fatal("Equal does not compare the digests")
	}
}

func TestS256VerifiesTheRFC7636AppendixBVector(t *testing.T) {
	const verifier, challenge = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	if !ValidVerifier(verifier) || !ValidChallenge(challenge) || !VerifyS256(verifier, challenge) {
		t.Fatal("the RFC 7636 appendix B vector does not verify")
	}
	for _, bad := range []struct{ verifier, challenge string }{
		{verifier[:42], challenge},
		{verifier + "x", challenge},
		{verifier, challenge[:42] + "N"},
		{verifier, challenge + "A"},
		{verifier, verifier},                  // plain is not a method
		{verifier + "+", challenge},           // a character outside the class
		{strings.Repeat("a", 129), challenge}, // too long
		{"", ""},
	} {
		if VerifyS256(bad.verifier, bad.challenge) {
			t.Fatalf("verifier %q verified against %q", bad.verifier, bad.challenge)
		}
	}
	long := strings.Repeat("a~._-Z9", 19)[:128]
	digest := sha256.Sum256([]byte(long))
	if !VerifyS256(long, base64.RawURLEncoding.EncodeToString(digest[:])) {
		t.Fatal("a 128-character verifier of the whole class does not verify")
	}
}

func TestTheCharacterClasses(t *testing.T) {
	for _, vector := range []struct {
		text                       string
		challenge, verifier, state bool
	}{
		{strings.Repeat("A", 43), true, true, true},
		{strings.Repeat("a-_", 14) + "Z", true, true, true},
		{strings.Repeat("A", 42), false, false, true},
		{strings.Repeat("A", 44), false, true, true},
		{strings.Repeat("~", 43), false, true, true},
		{strings.Repeat(".", 43), false, true, true},
		{strings.Repeat("A", 42) + "=", false, false, false},
		{strings.Repeat("A", 42) + "+", false, false, false},
		{strings.Repeat("A", 42) + "/", false, false, false},
		{strings.Repeat("A", 42) + " ", false, false, false},
		{strings.Repeat("A", 42) + "é", false, false, false},
		{strings.Repeat("s", 15), false, false, false},
		{strings.Repeat("s", 16), false, false, true},
		{strings.Repeat("s", 128), false, true, true},
		{strings.Repeat("s", 129), false, false, false},
		{"", false, false, false},
	} {
		if ValidChallenge(vector.text) != vector.challenge || ValidVerifier(vector.text) != vector.verifier || ValidState(vector.text) != vector.state {
			t.Fatalf("%q: challenge %v verifier %v state %v", vector.text, ValidChallenge(vector.text), ValidVerifier(vector.text), ValidState(vector.text))
		}
	}
}
