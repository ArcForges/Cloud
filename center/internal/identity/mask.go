// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"strings"
	"unicode/utf8"
)

// MaskEmail is the masked form of an account's e-mail address shown to a node and on the consent pages (AF-CTR-04;
// fleet.v1.AccountSummary.email_masked): the first character of the local part, three asterisks, then the at sign and the domain
// unchanged, so "alice@example.com" is "a***@example.com". An address without a local part or a domain is "***".
func MaskEmail(address string) string {
	at := strings.LastIndexByte(address, '@')
	if at <= 0 || at == len(address)-1 {
		return "***"
	}
	first, size := utf8.DecodeRuneInString(address)
	if first == utf8.RuneError && size <= 1 {
		return "***"
	}
	return address[:size] + "***" + address[at:]
}
