// SPDX-License-Identifier: AGPL-3.0-only

// Package identity is the center's account core (AF-CTR-03; ArcForges-Design AD-0011, AD-0021 sections 3 to 7): the rules of the
// C# identity core (src/ArcForges.Cloud.Modules.Identity/Core/Domain/IdentityRules.cs, ported), accounts and credentials on the
// PostgreSQL store, the owner bootstrap, passkey and e-mail sign-in, and the reads of the account surface. Rules read no clock, no
// store and no randomness; the store functions take every instant and identifier from their caller.
package identity

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// The text bounds of the C# core, counted in UTF-16 code units as the C# host counts them.
const (
	DisplayNameMaxUnits = 128
	SubjectMaxUnits     = 512
	LabelMaxUnits       = 64
	EmailMaxLength      = 320
)

// UserState is the stored account state (identity.user_state).
type UserState int16

// The account states.
const (
	StateActive          UserState = 1
	StateRestricted      UserState = 2
	StateSuspended       UserState = 3
	StatePendingDeletion UserState = 4
	StateDeleted         UserState = 5
)

// MaySignIn reports whether an account in the state may sign in, refresh and be verified: active and restricted accounts may
// (a restricted account reaches only its security operations); every other state is refused exactly like an unknown credential.
func (s UserState) MaySignIn() bool { return s == StateActive || s == StateRestricted }

// MayAddCredential reports whether a new credential is admitted: only for an active account.
func (s UserState) MayAddCredential() bool { return s == StateActive }

// MayChangeCredentials reports whether a credential may be changed or removed: for an active or restricted account, so a restricted
// account can still remove a compromised credential.
func (s UserState) MayChangeCredentials() bool { return s == StateActive || s == StateRestricted }

// Method is the stored credential method (identity.auth_method).
type Method int16

// The admitted credential methods; password (3) and OIDC (4) are not admitted on the center.
const (
	MethodPasskey   Method = 1
	MethodEmailCode Method = 2
)

// Provider is the provider of a method's credentials.
func (m Method) Provider() string {
	if m == MethodPasskey {
		return "passkey"
	}
	return "email"
}

// Kind is the contract's CredentialSummary.kind of the method.
func (m Method) Kind() string {
	if m == MethodPasskey {
		return "passkey"
	}
	return "email_code"
}

// UTF16Units is the length of valid UTF-8 text in UTF-16 code units.
func UTF16Units(text string) int {
	units := 0
	for _, r := range text {
		units += utf16.RuneLen(r)
	}
	return units
}

// isPlainText is non-empty valid UTF-8 of at most max UTF-16 units without a control character (C0, DEL, C1) or a surrogate.
func isPlainText(text string, max int) bool {
	if text == "" || !utf8.ValidString(text) || UTF16Units(text) > max {
		return false
	}
	for _, r := range text {
		if unicode.IsControl(r) || (r >= 0xD800 && r <= 0xDFFF) {
			return false
		}
	}
	return true
}

// ValidDisplayName is non-empty plain text of at most 128 UTF-16 units that is not only white space.
func ValidDisplayName(text string) bool {
	return isPlainText(text, DisplayNameMaxUnits) && strings.TrimFunc(text, unicode.IsSpace) != ""
}

// ValidSubject is plain text of at most 512 UTF-16 units.
func ValidSubject(text string) bool { return isPlainText(text, SubjectMaxUnits) }

// ValidLabel is a credential label: absent, or plain text of at most 64 UTF-16 units that is not only white space.
func ValidLabel(text *string) bool {
	return text == nil || isPlainText(*text, LabelMaxUnits) && strings.TrimFunc(*text, unicode.IsSpace) != ""
}

var (
	localePattern   = regexp.MustCompile(`^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8}){0,4}$`)
	timezonePattern = regexp.MustCompile(`^[A-Za-z0-9_/-]{1,64}$`)
	labelPattern    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ValidLocale is a BCP 47 shaped language tag of at most 35 characters.
func ValidLocale(text string) bool { return len(text) <= 35 && localePattern.MatchString(text) }

// ValidTimezone is an IANA time zone name shape (Area/Location, UTC, Etc/GMT-1) of at most 64 characters within the contract's
// timezone pattern (con-07 ProfileUpdate and AccountProfile), which has no '+': the Etc/GMT+N zones cannot be named.
func ValidTimezone(text string) bool {
	return timezonePattern.MatchString(text) && !strings.Contains(text, "//") && !strings.HasPrefix(text, "/") && !strings.HasSuffix(text, "/")
}

// NormalizeEmail returns the canonical form of an e-mail address, or false when it is not one: at most 320 bytes, exactly one "@",
// a local part of 1 to 64 printable ASCII characters without white space, quotes or backslashes, and a domain name of at least two
// labels of letters, digits and inner hyphens, at most 253 characters; the whole address is lower-cased. Every syntactically valid
// address is treated alike whether or not an account has it (SEC-05).
func NormalizeEmail(text string) (string, bool) {
	if len(text) == 0 || len(text) > EmailMaxLength || strings.Count(text, "@") != 1 {
		return "", false
	}
	local, domain, _ := strings.Cut(strings.ToLower(text), "@")
	if len(local) == 0 || len(local) > 64 || len(domain) == 0 || len(domain) > 253 {
		return "", false
	}
	for index := range len(local) {
		c := local[index]
		if c <= ' ' || c >= 0x7f || c == '"' || c == '\\' || c == '(' || c == ')' || c == ',' || c == ':' || c == ';' || c == '<' || c == '>' || c == '[' || c == ']' {
			return "", false
		}
	}
	if strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return "", false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return "", false
	}
	for _, label := range labels {
		if !labelPattern.MatchString(label) {
			return "", false
		}
	}
	return local + "@" + domain, true
}

// CheckRemoval is the last-credential rule (model 01 identity.last_credential): a credential may be removed only when the account may
// change credentials and another unrevoked credential remains; the center has no recovery path yet (AF-ID-02).
func CheckRemoval(state UserState, live []string, target string) error {
	if !state.MayChangeCredentials() {
		return ErrNotPermitted
	}
	found, remaining := false, false
	for _, id := range live {
		if id == target {
			found = true
		} else {
			remaining = true
		}
	}
	switch {
	case !found:
		return ErrNotFound
	case !remaining:
		return ErrLastCredential
	}
	return nil
}
