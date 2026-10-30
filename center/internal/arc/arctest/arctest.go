// SPDX-License-Identifier: AGPL-3.0-only

// Package arctest holds the center's check of an ArcError against the Contracts rules, for the tests of every package that renders
// one (the refusals of package arc, the replies of the identity surface, the Worker's generated replies). It is linked into test
// binaries only.
package arctest

import (
	"regexp"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
)

// pattern is the pattern foundation-baseline.json gives ArcError.message_key, StateFailure.state, AggregateRef.kind and
// LimitFailure.limit_name.
var pattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)

// The Instant bounds of foundation-baseline.json: 0001-01-01T00:00:00Z to 9999-12-31T23:59:59Z, nanos below one second.
const (
	InstantMinSeconds = -62135596800
	InstantMaxSeconds = 253402300799
	InstantMaxNanos   = 999_999_999
)

// Violations checks an ArcError against a subset of the rules Contracts public/proto/constraints/foundation-baseline.json
// and eng/foundation_semantics.py (62ccef1) state for it and the messages the center emits in it (B6, E4, F-7). It is a hand copy,
// so later drift in Contracts is not detected. It checks:
//   - ArcError: code, category (1 to 9), message key (pattern), retry and effect (1 to 3) are required; the correlation id is
//     required (a valid Id: 16 bytes, not all zero), also in the Worker's generated replies (E4-1); the arcError rule's generic
//     clause, effect UNKNOWN never with AFTER_TIME, with one named exemption below;
//   - RetryAdvice: the mode is required (1 to 4); the rule retryAdvice (retry_at if and only if AFTER_TIME, a reconciliation
//     operation, matching the pattern, if and only if RECONCILE);
//   - Instant (retry_at, LimitFailure.recovery_at): unix_seconds and nanos are required and within their bounds;
//   - ErrorDetails holds one detail; StateFailure requires its state (pattern) and reason; an AggregateRef requires its kind
//     (pattern) and an Id of 16 bytes that are not all zero; LimitFailure requires its limit name (pattern); a Revision's value is
//     at least 0.
//
// It leaves out: the arcError rule's code-specific clauses, which name only the node catalogue's dotted codes
// that no center code matches; Decimal's canonicalDecimal rule (LimitFailure.maximum) and the valid-Unicode check of strings; and
// the details the center never emits (UpgradeRequired, StateFailure.native, LimitFailure.available, RevisionConflict.conflict_id).
func Violations(value *foundationv1.ArcError) []string {
	var found []string
	check := func(ok bool, rule string) {
		if !ok {
			found = append(found, rule)
		}
	}
	validID := func(id *foundationv1.Id) bool {
		return id != nil && len(id.GetValue()) == 16 && string(id.GetValue()) != string(make([]byte, 16))
	}
	check(value.Code != nil && value.GetCode() != "", "ArcError.code is required")
	check(value.Category != nil && value.GetCategory() >= 1 && value.GetCategory() <= 9, "ArcError.category is required (1 to 9)")
	check(value.MessageKey != nil && pattern.MatchString(value.GetMessageKey()), "ArcError.message_key is required and matches the pattern")
	check(value.GetRetry() != nil && value.GetRetry().Mode != nil && value.GetRetry().GetMode() >= 1 && value.GetRetry().GetMode() <= 4,
		"ArcError.retry.mode is required (1 to 4)")
	check(value.Effect != nil && value.GetEffect() >= 1 && value.GetEffect() <= 3, "ArcError.effect is required (1 to 3)")
	// The arcError rule's generic clause: effect UNKNOWN never with AFTER_TIME. INTERNAL/internal (arc.Internal) is the one exemption:
	// Design errors.md row 85 prescribes "AFTER_TIME once" with effect "UNKNOWN unless known", against Contracts 62ccef1
	// eng/foundation_semantics.py arcError. That open conflict predates this PR (#118) and is routed to the AF-CTR-03 Design
	// companion (E4-INTERNAL); a second refusal with this pair fails here.
	exempt := value.GetCategory() == foundationv1.ErrorCategory_ERROR_CATEGORY_INTERNAL && value.GetCode() == "internal"
	check(exempt || !(value.GetEffect() == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN &&
		value.GetRetry().GetMode() == foundationv1.RetryMode_RETRY_MODE_AFTER_TIME),
		"ArcError: effect UNKNOWN never with retry AFTER_TIME (rule arcError)")
	instant := func(at *foundationv1.Instant, name string) {
		check(at.UnixSeconds != nil && at.GetUnixSeconds() >= InstantMinSeconds && at.GetUnixSeconds() <= InstantMaxSeconds &&
			at.Nanos != nil && at.GetNanos() <= InstantMaxNanos, name+": unix_seconds and nanos are required and within their bounds")
	}
	retry := value.GetRetry()
	reconciliation := retry != nil && retry.ReconciliationOperation != nil
	check((retry.GetMode() == foundationv1.RetryMode_RETRY_MODE_AFTER_TIME) == (retry.GetRetryAt() != nil) &&
		(retry.GetMode() == foundationv1.RetryMode_RETRY_MODE_RECONCILE) == reconciliation,
		"RetryAdvice: retry_at if and only if AFTER_TIME, reconciliation_operation if and only if RECONCILE (rule retryAdvice)")
	check(!reconciliation || pattern.MatchString(retry.GetReconciliationOperation()),
		"RetryAdvice.reconciliation_operation matches the pattern")
	if at := retry.GetRetryAt(); at != nil {
		instant(at, "RetryAdvice.retry_at")
	}
	check(validID(value.GetCorrelationId()), "ArcError.correlation_id is required")
	details := value.GetDetails()
	if details == nil {
		return found
	}
	check(details.GetDetail() != nil, "ErrorDetails holds one detail")
	if state := details.GetState(); state != nil {
		check(state.State != nil && pattern.MatchString(state.GetState()), "StateFailure.state is required and matches the pattern")
		check(state.Reason != nil && state.GetReason() != "", "StateFailure.reason is required")
		if resource := state.GetResource(); resource != nil {
			check(resource.Kind != nil && pattern.MatchString(resource.GetKind()), "AggregateRef.kind is required and matches the pattern")
			check(validID(resource.GetId()), "AggregateRef.id is required (16 bytes, not all zero)")
		}
	}
	if limit := details.GetLimit(); limit != nil {
		check(limit.LimitName != nil && pattern.MatchString(limit.GetLimitName()), "LimitFailure.limit_name is required and matches the pattern")
		if at := limit.GetRecoveryAt(); at != nil {
			instant(at, "LimitFailure.recovery_at")
		}
	}
	if revision := details.GetRevision(); revision != nil {
		for _, item := range []*foundationv1.Revision{revision.GetExpected(), revision.GetActual()} {
			check(item == nil || item.Value != nil && item.GetValue() >= 0, "Revision.value is required and at least 0")
		}
	}
	return found
}
