// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

// IssueGrantRequest is a request to issue one grant. The grant identifier and creation time are assigned by the service, never by
// the caller.
type IssueGrantRequest struct {
	AccountID      string
	Kind           GrantKind
	Subject        string
	Value          GrantValue
	Source         GrantSource
	SourceRef      *string
	EffectiveFrom  Micros
	EffectiveUntil *Micros
	IssuedByActor  string
	Reason         *string
}

// RevokeGrantRequest is a request to revoke one exact grant. ExpectedSnapshotVersion guards the entitlement version the caller
// decided against.
type RevokeGrantRequest struct {
	AccountID               string
	GrantID                 string
	ReasonCode              string
	EffectiveFrom           *Micros
	IssuedByActor           string
	ExpectedSnapshotVersion int64
}

// ValidateIssue is GrantAdmission.Validate: the rules that make the grant interface the only way in (EO-03). It returns the
// refusal's reason, or "" when the request is admitted. Every refusal is explained; nothing is coerced. A credit balance, trial flag
// or operator edit cannot become a grant of a kind the model does not define (SV-03). The wording is the C# wording.
func ValidateIssue(request IssueGrantRequest) string {
	switch {
	case !IsIdentifier(request.AccountID):
		return "The workspace identifier is malformed."
	case !request.Kind.Defined():
		return "The grant kind is not one of capability, quota or allowance."
	case !request.Source.Defined():
		return "The grant source is not in the closed source vocabulary."
	case !IsKey(request.Subject):
		return "The grant subject is malformed."
	case request.Value == nil || !valueMatchesKind(request.Kind, request.Value):
		return "The grant value does not match its kind or is out of range."
	case !IsActor(request.IssuedByActor):
		return "A grant must name the actor or audited action that issued it."
	case request.EffectiveUntil != nil && *request.EffectiveUntil <= request.EffectiveFrom:
		return "A grant must end after it starts."
	case request.SourceRef != nil && !IsOpaqueReference(*request.SourceRef):
		return "The source reference must be an opaque reference of lower-case, upper-case, digit and . _ - : characters, not a provider payload."
	}

	// Every source names its originating transaction or audited action (GR-02). Administrative, compensation and migration grants
	// also carry a reason and, through the source reference, the ticket or incident (GR-04, GR-05).
	if request.SourceRef == nil {
		return "Every grant names the transaction or audited action that originated it."
	}
	if request.Source.Administrative() && (request.Reason == nil || !IsReason(*request.Reason)) {
		return "An administrative, compensation or migration grant requires a reason."
	}
	if !request.Source.Administrative() && request.Reason != nil && !IsReason(*request.Reason) {
		return "The reason is malformed."
	}
	return ""
}

// IsSameIssuance is true when a stored grant is the same issuance as the request, which is what makes a replayed request
// idempotent.
func IsSameIssuance(existing Grant, request IssueGrantRequest) bool {
	return existing.AccountID == request.AccountID && existing.Kind == request.Kind && existing.Subject == request.Subject &&
		existing.Value == request.Value && existing.Source == request.Source && equalStrings(existing.SourceRef, request.SourceRef) &&
		existing.EffectiveFrom == request.EffectiveFrom && equalMicros(existing.EffectiveUntil, request.EffectiveUntil) &&
		existing.IssuedByActor == request.IssuedByActor
}

func equalStrings(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
