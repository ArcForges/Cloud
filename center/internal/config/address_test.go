// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"strings"
	"testing"
)

// addressOfLength builds a valid address of exactly total bytes: a 64-byte local part and a domain of labels of at most 63 bytes.
func addressOfLength(t *testing.T, total int) string {
	t.Helper()
	local := strings.Repeat("a", MaxMailLocalBytes)
	rest := total - len(local) - 1 // the domain
	if rest < 4 {
		t.Fatalf("no address of %d bytes", total)
	}
	var labels []string
	for rest > 0 {
		size := min(rest, 63)
		if rest-size > 0 && rest-size < 3 { // leave room for the dot and a last label
			size = rest - 3
		}
		labels = append(labels, strings.Repeat("b", size))
		rest -= size + 1 // the dot that follows
	}
	address := local + "@" + strings.Join(labels, ".")
	if len(address) != total {
		t.Fatalf("built %d bytes, want %d", len(address), total)
	}
	return address
}

// TestValidMailAddress is the rule table of the center's single address syntax (MOCKED: no provider, no DNS).
func TestValidMailAddress(t *testing.T) {
	valid := []string{
		"ada@example.org", "Ada@Example.ORG", "a.b+c@sub.example.org", "x@a-b.example", "a@b.co", "a@x.9a", "a@1.2.3.4.zz",
		"!#$%&'*+-/?=^_`{|}~@example.org", "a@xn--p1ai.xn--80asehdb", "a@example.c0m", strings.Repeat("a", 64) + "@example.org",
		// The edges of every character range of the rules (a range written with < for <= refuses the last character of it).
		"z@example.org", "Z@example.org", "a@example.org", "A@example.org", "0@example.org", "9@example.org", "a@example.A", "a@example.Z",
		"a@example.z", "a@example.a", "a9@x9.com", "A@A.A0", "zZ09aA@zZ09-aA.zZ", "a@0-9.zz", "a@Z-z.A",
		// "?=" alone is harmless; a hexadecimal last label that is not all hexadecimal digits, or a letter beyond 0x, is a name.
		"?=@example.org", "a?=@example.org", "a@example.0xg", "a@0x7f.0.0.1a", "a@example.x0",
		"a@" + strings.Repeat("b", 63) + ".org",
	}
	for _, text := range valid {
		if !ValidMailAddress(text) {
			t.Errorf("%q should be an address", text)
		}
	}
	invalid := map[string]string{
		"empty":                         "",
		"no at":                         "ada",
		"no domain":                     "ada@",
		"no local part":                 "@example.org",
		"two ats":                       "a@b@example.org",
		"one label":                     "ada@localhost",
		"IPv4 literal":                  "a@127.0.0.1",
		"link local literal":            "a@169.254.169.254",
		"all-numeric TLD":               "a@1.1",
		"numeric last label":            "a@example.1",
		"numeric zero":                  "a@0.0.0.0",
		"bracketed literal":             "a@[127.0.0.1]",
		"space":                         "a da@example.org",
		"tab":                           "a\tb@example.org",
		"leading dot":                   ".ada@example.org",
		"trailing dot":                  "ada.@example.org",
		"double dot":                    "a..da@example.org",
		"domain double dot":             "ada@example..org",
		"domain trailing dot":           "ada@example.org.",
		"leading hyphen":                "ada@-example.org",
		"trailing hyphen":               "ada@example-.org",
		"quote":                         `"ada"@example.org`,
		"backslash":                     `a\b@example.org`,
		"underscore in domain":          "ada@exa_mple.org",
		"comma list":                    "a@example.org,b@example.org",
		"semicolon list":                "a@example.org;b@example.org",
		"angle brackets":                "<a@example.org>",
		"comma in the local part":       "a,b@example.org",
		"semicolon in the local part":   "a;b@example.org",
		"less in the local part":        "a<b@example.org",
		"greater in the local part":     "a>b@example.org",
		"hex digit a in the last label": "a@10.0.0.0xa",
		"hex digit 9 in the last label": "a@10.0.0.0x9",
		"display name":                  "Ada <a@example.org>",
		"comment":                       "a(c)@example.org",
		"colon":                         "a:b@example.org",
		"square brackets":               "a[b]@example.org",
		"CR":                            "a@example.org\r",
		"LF":                            "a@example.org\n",
		"CRLF injection":                "a@example.org\r\nBcc: b@example.org",
		"NUL":                           "a\x00@example.org",
		"DEL":                           "a\x7f@example.org",
		"non-ASCII local":               "adé@example.org",
		"non-ASCII domain":              "ada@éxample.org",
		"Kelvin sign":                   "a@example.Korg",
		"local part 65 bytes":           strings.Repeat("a", 65) + "@example.org",
		"label 64 bytes":                "a@" + strings.Repeat("b", 64) + ".org",
		"domain over 253 bytes":         "a@" + strings.Repeat(strings.Repeat("b", 62)+".", 4) + "org",
		"address 255 bytes":             addressOfLength(t, 255),
		"letter only in a mid":          "a@x9.1",
		"hex IP-like 127.0.0.0x1":       "a@127.0.0.0x1",
		"hex IP-like 1.2.3.0x7f":        "a@1.2.3.0x7f",
		"hex IP-like upper":             "a@1.2.3.0X7F",
		"hex prefix alone":              "a@example.0x",
		"encoded word local part":       "=?utf-8?q?x?=@example.org",
		"encoded word CRLF form":        "=?utf-8?q?a=0D=0ABcc=3A_evil=40x.test?=@example.org",
		"encoded word inside":           "a=?b@example.org",
		"encoded word at the end":       "ab=?@example.org",
		"only hyphens and digs":         "a@example.1-1",
	}
	for name, text := range invalid {
		if ValidMailAddress(text) {
			t.Errorf("%s: %q should not be an address", name, text)
		}
	}
}

// TestValidMailAddressBoundaries pins the byte bounds at the edge, in both directions (the identity normalization shares them).
func TestValidMailAddressBoundaries(t *testing.T) {
	if !ValidMailAddress(addressOfLength(t, MaxMailAddressBytes)) {
		t.Error("an address of the maximum length is refused")
	}
	if ValidMailAddress(addressOfLength(t, MaxMailAddressBytes+1)) {
		t.Error("an address one byte over the maximum is accepted")
	}
	if !ValidMailAddress(strings.Repeat("a", MaxMailLocalBytes) + "@example.org") {
		t.Error("a local part of the maximum length is refused")
	}
	if MaxMailAddressBytes != 254 || MaxMailLocalBytes != 64 || MaxMailDisplayNameBytes != 64 {
		t.Error("the bounds changed: the providers' limits and RFC 5321 give 254, 64 and 64")
	}
}

func TestValidMailDisplayName(t *testing.T) {
	for _, text := range []string{"", "ArcForges", "Arc Forges Sign-in", "A", strings.Repeat("n", MaxMailDisplayNameBytes), "R&D", "~", "~~", "Name~", "!", "Z", "a", "0", "9", "A z 09"} {
		if !ValidMailDisplayName(text) {
			t.Errorf("%q should be a display name", text)
		}
	}
	for name, text := range map[string]string{
		"too long": strings.Repeat("n", MaxMailDisplayNameBytes+1), "quote": `a"b`, "backslash": `a\b`, "less": "a<b", "greater": "a>b",
		"paren open": "a(b", "paren close": "a)b", "bracket open": "a[b", "bracket close": "a]b", "comma": "a,b", "colon": "a:b",
		"semicolon": "a;b", "at": "a@b", "dot": ".", "dot at the end": "ArcForges Inc.", "dot inside": "a.b", "encoded word": "=?utf-8?q?x?=", "encoded word inside": "Mail =?x", "CR": "a\rb", "LF": "a\nb",
		"NUL": "a\x00b", "tab": "a\tb", "DEL": "a\x7fb", "unit separator": "a\x1fb", "non-ASCII": "Adé", "leading space": " a", "trailing space": "a ",
	} {
		if ValidMailDisplayName(text) {
			t.Errorf("%s: %q should not be a display name", name, text)
		}
	}
}

// TestValidMailSender pins the composed From bound that the Postmark API enforces (255 characters, a REAL 422/300 for 258) and
// that both adapters and the configuration share.
func TestValidMailSender(t *testing.T) {
	longAddress := addressOfLength(t, 188)
	name := strings.Repeat("n", MaxMailDisplayNameBytes)
	for _, c := range []struct {
		address, name string
		want          bool
	}{
		{"sender@example.org", "", true},
		{"sender@example.org", "ArcForges", true},
		{addressOfLength(t, MaxMailAddressBytes), "", true}, // a bare 254-byte address is within 255
		{longAddress, name, true},                           // 64 + 3 + 188 = 255
		{addressOfLength(t, 189), name, false},              // 256
		{addressOfLength(t, 254), "n", false},               // 1 + 3 + 254 = 258
		{addressOfLength(t, 251), "n", true},                // 255
		{addressOfLength(t, 252), "n", false},               // 256
		{"sender@example.org", "bad.name", false},           // the name rule applies
		{"sender@127.0.0.1", "", false},                     // the address rule applies
		{"sender@example.org,b@example.org", "", false},
	} {
		if got := ValidMailSender(c.address, c.name); got != c.want {
			t.Errorf("ValidMailSender(%d bytes, %q) = %v, want %v", len(c.address), c.name, got, c.want)
		}
	}
	if MaxMailSenderBytes != 255 {
		t.Error("the composed From bound is the provider's 255")
	}
}
