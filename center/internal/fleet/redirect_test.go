// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import "testing"

// EVIDENCE: REAL (a pure function).

// TestRedirectURIAcceptsOnlyTheTwoLoopbackForms (E1-5, SEC-09; CTR4-FLW-02): only http://127.0.0.1:<port>/callback and
// http://[::1]:<port>/callback with a decimal port from 1024 to 65535 without a leading zero are admitted, byte for byte.
func TestRedirectURIAcceptsOnlyTheTwoLoopbackForms(t *testing.T) {
	admitted := []string{
		"http://127.0.0.1:1024/callback", "http://127.0.0.1:8080/callback", "http://127.0.0.1:65535/callback", "http://127.0.0.1:49152/callback",
		"http://[::1]:1024/callback", "http://[::1]:53682/callback", "http://[::1]:65535/callback",
	}
	refused := []string{
		"", "http://127.0.0.1:1023/callback", "http://127.0.0.1:65536/callback", "http://127.0.0.1:99999/callback", "http://127.0.0.1:0/callback",
		"http://127.0.0.1:01024/callback", "http://127.0.0.1:+8080/callback", "http://127.0.0.1:-8080/callback", "http://127.0.0.1:/callback",
		"http://127.0.0.1/callback", "http://127.0.0.1:8080", "http://127.0.0.1:8080/", "http://127.0.0.1:8080/callback/", "http://127.0.0.1:8080/Callback",
		"http://127.0.0.1:8080/callback?x=1", "http://127.0.0.1:8080/callback#x", "http://127.0.0.1:8080/callback?", "http://127.0.0.1:8080/%63allback",
		"http://127.0.0.1:8080/callback/../callback", "https://127.0.0.1:8080/callback", "HTTP://127.0.0.1:8080/callback", "http:/127.0.0.1:8080/callback",
		"http://localhost:8080/callback", "http://LOCALHOST:8080/callback", "http://0.0.0.0:8080/callback", "http://127.1:8080/callback",
		"http://127.0.0.2:8080/callback", "http://2130706433:8080/callback", "http://0x7f000001:8080/callback", "http://0177.0.0.1:8080/callback",
		"http://127.000.000.001:8080/callback", "http://user@127.0.0.1:8080/callback", "http://user:pass@127.0.0.1:8080/callback",
		"http://127.0.0.1@evil.example:8080/callback", "http://[::1%25lo]:8080/callback", "http://[0:0:0:0:0:0:0:1]:8080/callback",
		"http://[::ffff:127.0.0.1]:8080/callback", "http://[::1]/callback", "http://::1:8080/callback", "http://[::2]:8080/callback",
		"http://[::1]:8080/callback ", " http://127.0.0.1:8080/callback", "http://127.0.0.1:8080/callback\n", "http://127.0.0.1:80 80/callback",
		"http://127.0.0.1:8080\\callback", "http://127.0.0.1:8a80/callback", "http://127.0.0.1:８０８０/callback", "javascript:alert(1)",
		"http://evil.example/callback", "http://127.0.0.1.evil.example:8080/callback",
	}
	if len(admitted)+len(refused) < 40 {
		t.Fatalf("only %d vectors", len(admitted)+len(refused))
	}
	for _, uri := range admitted {
		if !ValidLoopbackRedirect(uri) {
			t.Errorf("%q was refused", uri)
		}
	}
	for _, uri := range refused {
		if ValidLoopbackRedirect(uri) {
			t.Errorf("%q was admitted", uri)
		}
	}
}

// TestTheRedirectIsBuiltFromTheStoredURI (SEC-09; CTR4-FLW-05): the approval's redirect is the stored loopback URI with the code and
// the state, the denial's with error=access_denied and the state; nothing else is appended.
func TestTheRedirectIsBuiltFromTheStoredURI(t *testing.T) {
	const stored, state, code = "http://[::1]:53682/callback", "state-0123456789abcdef", "code"
	if got := CodeRedirect(stored, code, state); got != "http://[::1]:53682/callback?code=code&state=state-0123456789abcdef" {
		t.Fatalf("approval redirect %q", got)
	}
	if got := DenyRedirect(stored, state); got != "http://[::1]:53682/callback?error=access_denied&state=state-0123456789abcdef" {
		t.Fatalf("denial redirect %q", got)
	}
}
