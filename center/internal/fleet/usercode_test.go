// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"strings"
	"testing"
)

// TestUserCodeAlphabetAndUniformity (E2-1, DEV-01): a drawn code is 8 letters of the 20-letter alphabet; over 200,000 draws (1.6
// million letters) every letter's count passes a chi-square test of uniformity (19 degrees of freedom; 50 is far beyond the 0.1%
// critical value 43.8, so a biased draw such as "byte mod 20" over all 256 bytes, whose first 16 letters come 13/12 as often, fails it
// while a fair draw passes it almost surely); the normalized form and the display form.
func TestUserCodeAlphabetAndUniformity(t *testing.T) {
	if len(UserCodeAlphabet) != 20 || strings.ContainsAny(UserCodeAlphabet, "AEIOUY") {
		t.Fatalf("the alphabet %q", UserCodeAlphabet)
	}
	counts := map[byte]int{}
	const draws = 200_000
	for range draws {
		code := NewUserCode()
		if len(code) != UserCodeLength {
			t.Fatalf("a code of %d letters", len(code))
		}
		for i := range len(code) {
			counts[code[i]]++
		}
	}
	expected := float64(draws*UserCodeLength) / 20
	chi := 0.0
	for i := range len(UserCodeAlphabet) {
		diff := float64(counts[UserCodeAlphabet[i]]) - expected
		chi += diff * diff / expected
	}
	if len(counts) != 20 || chi > 50 {
		t.Fatalf("the letters are not uniform: %d letters, chi-square %.1f", len(counts), chi)
	}
	for raw, want := range map[string]string{
		"BCDFGHJK": "BCDFGHJK", "bcdf-ghjk": "BCDFGHJK", "  bCdF - gHjK  ": "BCDFGHJK", "B-C-D-F-G-H-J-K": "BCDFGHJK", "WXZBCDFG": "WXZBCDFG",
	} {
		if got, ok := NormalizeUserCode(raw); !ok || got != want {
			t.Errorf("%q normalizes to %q %v", raw, got, ok)
		}
	}
	for _, raw := range []string{"", "BCDFGHJ", "BCDFGHJKL", "ABCDFGHJ", "BCDFGHJ1", "BCDF\tGHJK", "BCDF_GHJK", "BCDFGHJK", "BCDFGHJＫ", "BCDFGHJı",
		"BCDFGHJß", "BCDF GHJK", "BCDF‐GHJK"} {
		if got, ok := NormalizeUserCode(raw); ok {
			t.Errorf("%q was admitted as %q", raw, got)
		}
	}
	if DisplayUserCode("BCDFGHJK") != "BCDF-GHJK" {
		t.Fatal("the display form")
	}
}
