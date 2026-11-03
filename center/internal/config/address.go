// SPDX-License-Identifier: AGPL-3.0-only

package config

import "strings"

// The bounds of a mail address, from RFC 5321 (a forward path of 256 octets including the angle brackets leaves 254 for the
// mailbox) and the providers' own limits (Postmark: 254 per address).
const (
	// MaxMailAddressBytes is the longest address accepted anywhere in the center.
	MaxMailAddressBytes = 254
	// MaxMailLocalBytes is the longest local part.
	MaxMailLocalBytes = 64
	// MaxMailDisplayNameBytes is the longest display name of the From header.
	MaxMailDisplayNameBytes = 64
	// MaxMailSenderBytes is the longest composed From value, "Name <address>": Postmark refuses a From over 255 characters (a REAL
	// probe answered 422 with ErrorCode 300 for 258).
	MaxMailSenderBytes = 255
)

// ValidMailAddress reports whether text is one plain RFC 5322 dot-atom addr-spec of printable ASCII: exactly one "@", a local
// part of 1 to 64 bytes made of the atext characters and inner single dots, a domain of at most 253 bytes with at least two
// labels of letters, digits and inner hyphens (each at most 63 bytes), and a last label that contains a letter (RFC 1123
// section 2.1 and RFC 3696 section 2: a top-level label is never all-numeric, so an IP literal such as a@127.0.0.1 is no address),
// at most 254 bytes in all. There is no display name, quote, comment, white space, angle bracket, comma or other special, so the
// text is safe in an SMTP command, in a To header and in a comma-separated provider field without quoting. Two further forms are
// refused because a consumer would read them as something else: a hexadecimal IP-like last label (a@127.0.0.0x1 is 127.0.0.1 to
// inet_aton) and the RFC 2047 encoded-word opener "=?" in the local part (a consumer that decodes the line as unstructured text
// would turn =?utf-8?q?...?= into any characters, line breaks included; "?=" alone is harmless and stays legal).
//
// It is the single source of the syntax rule; package mail's ValidAddress and identity's NormalizeEmail (after lower-casing) delegate
// to it. It lives here because config has no
// in-repository dependency, so mail and identity can both import it without a cycle. Letter case is kept: a caller that needs a
// canonical form lower-cases first.
func ValidMailAddress(text string) bool {
	if len(text) == 0 || len(text) > MaxMailAddressBytes || strings.Count(text, "@") != 1 {
		return false
	}
	local, domain, _ := strings.Cut(text, "@")
	if len(local) == 0 || len(local) > MaxMailLocalBytes || len(domain) == 0 || len(domain) > 253 {
		return false
	}
	if local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") || strings.Contains(local, "=?") {
		return false
	}
	for i := range len(local) {
		if !mailAtext(local[i]) && local[i] != '.' {
			return false
		}
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if !mailLabel(label) {
			return false
		}
	}
	last := labels[len(labels)-1]
	if len(last) >= 2 && last[0] == '0' && (last[1] == 'x' || last[1] == 'X') && strings.Trim(last[2:], "0123456789abcdefABCDEF") == "" {
		return false
	}
	return strings.IndexFunc(last, func(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }) >= 0
}

// mailAtext is the RFC 5322 atext set of printable ASCII.
func mailAtext(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-/=?^_`{|}~", c) >= 0
}

// mailLabel is a hostname label: 1 to 63 letters, digits and hyphens, not starting or ending with a hyphen.
func mailLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := range len(label) {
		c := label[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// ValidMailDisplayName reports whether text may be the display name of the From header: empty, or at most 64 bytes of printable
// ASCII (space included) without the RFC 5322 specials (" \ < > ( ) [ ] , : ; @ and the dot, which makes a phrase obsolete
// syntax), without an RFC 2047 encoded-word opener ("=?", which a receiving client would decode) and not starting or ending with
// a space. The name is operator configuration, written into the header as it is, so the rule is strict.
func ValidMailDisplayName(text string) bool {
	if len(text) > MaxMailDisplayNameBytes || strings.Contains(text, "=?") || text != strings.Trim(text, " ") {
		return false
	}
	for i := range len(text) {
		c := text[i]
		if c < ' ' || c > '~' || strings.IndexByte("\"\\<>()[],:;@.", c) >= 0 {
			return false
		}
	}
	return true
}

// ValidMailSender reports whether address and name make a sender the center and its providers accept: a ValidMailAddress, a
// ValidMailDisplayName, and a composed "Name <address>" of at most 255 bytes (the bare address when the name is empty). Both
// adapters and the start-up configuration use this one rule, so the pair cannot drift apart.
func ValidMailSender(address, name string) bool {
	if !ValidMailAddress(address) || !ValidMailDisplayName(name) {
		return false
	}
	return name == "" || len(name)+len(" <>")+len(address) <= MaxMailSenderBytes
}
