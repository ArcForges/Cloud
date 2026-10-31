// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"errors"
	"sort"
	"unicode"
	"unicode/utf8"
)

// InputError is a record set or definition set that the resolver refuses to interpret (the C# ResolverInputException). The resolver
// fails closed: it never produces a snapshot from inconsistent history, because a guess would be an entitlement nobody can explain.
// The message is the C# wording; it is for logs and tests, never for a client.
type InputError struct{ Message string }

func (e *InputError) Error() string { return e.Message }

// ErrOverflow is an arithmetic overflow the resolver refuses instead of wrapping (the C# checked arithmetic).
var ErrOverflow = errors.New("entitlement arithmetic overflow")

func inputError(message string) error { return &InputError{Message: message} }

// The bounds every record the resolver reads must satisfy. The same rules guard grant admission.
const (
	// MaxRecords is a hard bound on the history of one account the resolver replays, so that evaluation cost stays bounded.
	MaxRecords = 2000
	// MaxQuotaLimit is the largest quota limit of one grant. With MaxRecords it keeps every checked sum inside a signed 64-bit
	// integer.
	MaxQuotaLimit int64 = 100_000_000_000_000
)

// IsIdentifier is InputRules.IsIdentifier: at most 64 of a-z, A-Z, 0-9 and . _ - :.
func IsIdentifier(value string) bool { return isToken(value, 64, true) }

// IsKey is InputRules.IsKey: at most 128 of a-z, 0-9 and . _ - :.
func IsKey(value string) bool { return isToken(value, 128, false) }

// IsOpaqueReference is InputRules.IsOpaqueReference: at most 128 of a-z, A-Z, 0-9 and . _ - :.
func IsOpaqueReference(value string) bool { return isToken(value, 128, true) }

func isToken(value string, maxLength int, allowUpper bool) bool {
	if value == "" || utf16Length(value) > maxLength {
		return false
	}
	for _, c := range value {
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == ':' || allowUpper && c >= 'A' && c <= 'Z'
		if !ok {
			return false
		}
	}
	return true
}

// utf16Length is the C# string.Length: the number of UTF-16 code units.
func utf16Length(value string) int {
	length := 0
	for _, r := range value {
		if r >= 0x10000 {
			length += 2
		} else {
			length++
		}
	}
	return length
}

func isWhiteSpaceOnly(value string) bool {
	for _, r := range value {
		if !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func hasControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// IsActor is InputRules.IsActor: not blank, at most 128 UTF-16 units, no control character.
func IsActor(value string) bool {
	return !isWhiteSpaceOnly(value) && utf16Length(value) <= 128 && !hasControl(value)
}

// IsReason is InputRules.IsReason: not blank, at most 512 UTF-16 units, no control character.
func IsReason(value string) bool {
	return !isWhiteSpaceOnly(value) && utf16Length(value) <= 512 && !hasControl(value)
}

// WellFormedText reports valid UTF-8 (the Go counterpart of the C# well-formed UTF-16 rule): text that is not valid cannot be stored.
func WellFormedText(value string) bool { return utf8.ValidString(value) }

// Validate is RecordSetValidator.Validate: the shape and consistency rules of a record set under a definition set.
func Validate(records RecordSet, definitions Definitions) error {
	if err := validateDefinitions(definitions); err != nil {
		return err
	}
	if !IsIdentifier(records.AccountID) {
		return inputError("The workspace identifier is malformed.")
	}
	if records.Count() > MaxRecords {
		return inputError("The record history exceeds the replay bound.")
	}

	grants := make(map[string]Grant, len(records.Grants))
	for _, grant := range records.Grants {
		if _, repeated := grants[grant.GrantID]; !IsIdentifier(grant.GrantID) || repeated {
			return inputError("A grant identifier is malformed or repeated.")
		}
		grants[grant.GrantID] = grant
		if grant.AccountID != records.AccountID {
			return inputError("A grant belongs to another workspace: " + grant.GrantID)
		}
		if !grant.Kind.Defined() || !grant.Source.Defined() {
			return inputError("A grant has an unknown kind or source: " + grant.GrantID)
		}
		if !IsKey(grant.Subject) {
			return inputError("A grant subject is malformed: " + grant.GrantID)
		}
		if grant.SourceRef != nil && !IsOpaqueReference(*grant.SourceRef) {
			return inputError("A grant source reference is malformed: " + grant.GrantID)
		}
		if !IsActor(grant.IssuedByActor) {
			return inputError("A grant has no issuing actor: " + grant.GrantID)
		}
		if grant.EffectiveUntil != nil && *grant.EffectiveUntil <= grant.EffectiveFrom {
			return inputError("A grant ends before it starts: " + grant.GrantID)
		}
		if !valueMatchesKind(grant.Kind, grant.Value) {
			return inputError("A grant value does not match its kind: " + grant.GrantID)
		}
	}

	revocations := make(map[string]bool, len(records.Revocations))
	for _, revocation := range records.Revocations {
		if !IsIdentifier(revocation.RevocationID) || revocations[revocation.RevocationID] {
			return inputError("A revocation identifier is malformed or repeated.")
		}
		revocations[revocation.RevocationID] = true
		grant, known := grants[revocation.GrantID]
		if !known {
			return inputError("A revocation names no known grant: " + revocation.RevocationID)
		}
		if !IsKey(revocation.ReasonCode) || !IsActor(revocation.IssuedByActor) {
			return inputError("A revocation lacks a reason code or actor: " + revocation.RevocationID)
		}
		if revocation.CreatedAt < grant.CreatedAt {
			return inputError("A revocation predates its grant: " + revocation.RevocationID)
		}
	}

	terms := make(map[string]ServiceTermFact, len(records.Terms))
	for _, term := range records.Terms {
		if _, repeated := terms[term.TermID]; !IsIdentifier(term.TermID) || repeated {
			return inputError("A service term identifier is malformed or repeated.")
		}
		terms[term.TermID] = term
		if !term.Kind.Defined() {
			return inputError("A service term has an unknown kind: " + term.TermID)
		}
		if term.EndsAt <= term.StartsAt {
			return inputError("A service term ends before it starts: " + term.TermID)
		}
		if term.GraceEndsAt != nil && *term.GraceEndsAt < term.EndsAt {
			return inputError("A service term grace ends before the term: " + term.TermID)
		}
	}

	for _, action := range records.TermActions {
		if !action.Kind.Defined() {
			return inputError("A term action has an unknown kind.")
		}
		term, known := terms[action.TermID]
		if !known {
			return inputError("A term action names no known term: " + action.TermID)
		}
		if action.RecordedAt < term.CreatedAt {
			return inputError("A term action predates its term: " + action.TermID)
		}
	}

	for _, fact := range records.StatusFacts {
		if !fact.Status.Defined() {
			return inputError("A workspace status fact has an unknown status.")
		}
	}

	for _, release := range records.FeatureReleases {
		if !IsKey(release.Feature) {
			return inputError("A feature release names a malformed feature.")
		}
	}

	type activationKey struct {
		version string
		at      Micros
	}
	activations := make(map[activationKey]bool, len(records.Activations))
	for _, activation := range records.Activations {
		key := activationKey{activation.Version, activation.ActivatedAt}
		if !IsOpaqueReference(activation.Version) || activations[key] {
			return inputError("A definitions activation is malformed or repeated.")
		}
		activations[key] = true
	}

	// When activations are recorded, the definitions being applied must be the ones activated last: a snapshot is never derived
	// under definitions whose activation, and therefore whose version change, no record shows.
	if len(records.Activations) > 0 && LastActivation(records).Version != definitions.Version {
		return inputError("The definitions version being applied has no recorded activation.")
	}
	return nil
}

// LastActivation is the activation in force: the latest by instant, then by version, a total order. The record set must have one.
func LastActivation(records RecordSet) DefinitionsActivation {
	ordered := append([]DefinitionsActivation(nil), records.Activations...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].ActivatedAt != ordered[j].ActivatedAt {
			return ordered[i].ActivatedAt < ordered[j].ActivatedAt
		}
		return ordered[i].Version < ordered[j].Version
	})
	return ordered[len(ordered)-1]
}

func valueMatchesKind(kind GrantKind, value GrantValue) bool {
	switch kind {
	case KindCapability:
		_, ok := value.(CapabilityValue)
		return ok
	case KindQuota:
		quota, ok := value.(QuotaValue)
		return ok && quota.Limit >= 0 && quota.Limit <= MaxQuotaLimit && quota.Priority >= 0
	case KindAllowance:
		allowance, ok := value.(AllowanceValue)
		return ok && allowance.Priority >= 0 && IsIdentifier(allowance.CapacityPlanRef)
	}
	return false
}

func validateDefinitions(definitions Definitions) error {
	if !IsOpaqueReference(definitions.Version) {
		return inputError("The definitions version is malformed.")
	}
	keys := map[string]bool{}
	for _, capability := range definitions.Capabilities {
		if !IsKey(capability.Key) || keys["capability:"+capability.Key] {
			return inputError("A capability definition is malformed or repeated.")
		}
		keys["capability:"+capability.Key] = true
		if capability.FeatureGate != nil && !IsKey(*capability.FeatureGate) {
			return inputError("A capability feature gate is malformed.")
		}
	}
	for _, quota := range definitions.Quotas {
		if !IsKey(quota.Key) || !quota.Combination.Defined() || keys["quota:"+quota.Key] {
			return inputError("A quota definition is malformed or repeated.")
		}
		keys["quota:"+quota.Key] = true
	}
	for _, allowance := range definitions.Allowances {
		if !IsKey(allowance.Key) || keys["allowance:"+allowance.Key] {
			return inputError("An allowance definition is malformed or repeated.")
		}
		keys["allowance:"+allowance.Key] = true
	}
	return nil
}
