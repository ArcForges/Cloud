// SPDX-License-Identifier: AGPL-3.0-only

package identity

import "testing"

// EVIDENCE: REAL (a pure function).

func TestMaskEmailKeepsTheFirstCharacterAndTheDomain(t *testing.T) {
	for address, masked := range map[string]string{
		"alice@example.com": "a***@example.com", "a@example.com": "a***@example.com", "élise@example.fr": "é***@example.fr",
		"first.last+tag@sub.example.org": "f***@sub.example.org", "a@b@example.com": "a***@example.com",
		"": "***", "@example.com": "***", "alice@": "***", "alice": "***", "\xffbad@example.com": "***",
	} {
		if got := MaskEmail(address); got != masked {
			t.Errorf("MaskEmail(%q) = %q, want %q", address, got, masked)
		}
	}
}
