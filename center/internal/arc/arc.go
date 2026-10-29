// SPDX-License-Identifier: AGPL-3.0-only

// Package arc is the center's domain refusal: an error that names one code of ArcForges-Design contracts/errors.md with the
// details that row defines, and its rendering as the contract's ArcError (category, snake_case code, message key
// error.<category>.<code>, retry advice, effect and the call's correlation id). A refusal never carries request text: its reason,
// resource and state are registry values.
package arc

import (
	"strconv"
	"strings"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/correlation"
)

// Refusal is one domain refusal.
type Refusal struct {
	Category foundationv1.ErrorCategory
	Code     string
	// Retry is the advice: NEVER unless set.
	Retry foundationv1.RetryMode
	// RetryAt is the earliest retry of an AFTER_TIME advice.
	RetryAt time.Time
	// Reason is state.reason; State is state.state.
	Reason string
	State  string
	// Limit is the LimitFailure detail of a rate limit or bound.
	Limit *Limit
	// Revision is the RevisionConflict detail of a stale expected revision.
	Revision *Revision
	// Effect is the effect certainty: DID_NOT_HAPPEN unless set.
	Effect foundationv1.EffectCertainty
}

// Revision is a RevisionConflict detail: the revision the request expected and the current one.
type Revision struct {
	Expected int64
	Actual   int64
}

// Limit is a LimitFailure detail.
type Limit struct {
	Name string
	// Maximum is the limit's maximum; zero when the refusing layer does not state it (the edge limiter's configuration is the
	// platform's).
	Maximum    int64
	RecoveryAt time.Time
}

func (r *Refusal) Error() string { return "refused: " + r.Key() }

// Key is CATEGORY/code, as the method annotations name it.
func (r *Refusal) Key() string {
	return strings.TrimPrefix(r.Category.String(), "ERROR_CATEGORY_") + "/" + r.Code
}

// MessageKey is error.<category>.<code>.
func (r *Refusal) MessageKey() string {
	return "error." + strings.ToLower(strings.TrimPrefix(r.Category.String(), "ERROR_CATEGORY_")) + "." + r.Code
}

// ArcError renders the refusal with the call's correlation id; the effect is DID_NOT_HAPPEN unless the refusal states another
// (an internal failure whose commit may have happened is UNKNOWN).
func (r *Refusal) ArcError(call correlation.Context) *foundationv1.ArcError {
	retry := r.Retry
	if retry == foundationv1.RetryMode_RETRY_MODE_UNSPECIFIED {
		retry = foundationv1.RetryMode_RETRY_MODE_NEVER
	}
	effect := r.Effect
	if effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNSPECIFIED {
		effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN
	}
	value := &foundationv1.ArcError{
		Code:       proto.String(r.Code),
		Category:   r.Category.Enum(),
		MessageKey: proto.String(r.MessageKey()),
		Retry:      &foundationv1.RetryAdvice{Mode: retry.Enum()},
		Effect:     effect.Enum(),
	}
	if call.CorrelationID != "" {
		value.CorrelationId = &foundationv1.Id{Value: correlation.IDBytes(call.CorrelationID)}
	}
	if !r.RetryAt.IsZero() {
		value.Retry.RetryAt = Instant(r.RetryAt)
	}
	switch {
	case r.Revision != nil:
		value.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_Revision{Revision: &foundationv1.RevisionConflict{
			Expected: &foundationv1.Revision{Value: proto.Int64(r.Revision.Expected)}, Actual: &foundationv1.Revision{Value: proto.Int64(r.Revision.Actual)}}}}
	case r.Limit != nil:
		limit := &foundationv1.LimitFailure{LimitName: proto.String(r.Limit.Name)}
		if r.Limit.Maximum > 0 {
			limit.Maximum = Decimal(r.Limit.Maximum)
		}
		if !r.Limit.RecoveryAt.IsZero() {
			limit.RecoveryAt = Instant(r.Limit.RecoveryAt)
		}
		value.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_Limit{Limit: limit}}
	case r.Reason != "" || r.State != "":
		state := &foundationv1.StateFailure{}
		if r.State != "" {
			state.State = proto.String(r.State)
		}
		if r.Reason != "" {
			state.Reason = proto.String(r.Reason)
		}
		value.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{State: state}}
	}
	return value
}

// The refusals of the identity surface, each a row of errors.md.

// InvalidArgument is VALIDATION/invalid_argument with state.reason = "<field path>: <rule>".
func InvalidArgument(field, rule string) *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_VALIDATION, Code: "invalid_argument", Reason: field + ": " + rule}
}

// InvalidCursor is VALIDATION/invalid_cursor: a page cursor that is malformed or from another listing.
func InvalidCursor() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_VALIDATION, Code: "invalid_cursor"}
}

// Unauthenticated is AUTHENTICATION/unauthenticated: a missing or invalid credential or proof. A wrong proof, an unknown
// credential and an account that may not sign in all give exactly this refusal.
func Unauthenticated() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHENTICATION, Code: "unauthenticated"}
}

// CredentialRevoked is AUTHENTICATION/credential_revoked: the session, device or refresh family was revoked.
func CredentialRevoked() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHENTICATION, Code: "credential_revoked"}
}

// TokenExpired is AUTHENTICATION/token_expired (refresh, then retry the same command).
func TokenExpired() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHENTICATION, Code: "token_expired",
		Retry: foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND}
}

// StepUpRequired is AUTHENTICATION/step_up_required.
func StepUpRequired() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHENTICATION, Code: "step_up_required",
		Retry: foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND}
}

// PermissionDenied is AUTHORIZATION/permission_denied with state.reason = the denied operation.
func PermissionDenied(operation string) *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION, Code: "permission_denied", Reason: operation}
}

// NotFound is STATE/not_found (the object does not exist or is not visible to the caller).
func NotFound() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, Code: "not_found"}
}

// InvalidState is STATE/invalid_state with its state and reason.
func InvalidState(state, reason string) *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, Code: "invalid_state", State: state, Reason: reason}
}

// Expired is STATE/expired: a flow expired.
func Expired() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, Code: "expired"}
}

// CodeReused is CONFLICT/code_reused: a consumed proof was presented again.
func CodeReused() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT, Code: "code_reused"}
}

// AlreadyExists is CONFLICT/already_exists.
func AlreadyExists() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT, Code: "already_exists"}
}

// RevisionConflict is CONFLICT/revision_conflict: meta.expected_rev differs from the object's current revision (re-read, merge).
func RevisionConflict(expected, actual int64) *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT, Code: "revision_conflict",
		Revision: &Revision{Expected: expected, Actual: actual}}
}

// Final reports a refusal that the same command can never turn into a success (its retry advice is NEVER): a command receipt
// keeps it and answers a replay with it. Any other refusal (step_up_required, token_expired, rate_limited, overloaded, internal)
// rolls the receipt back, so the same command ID can succeed after the step-up, the refresh or the wait its advice names.
func (r *Refusal) Final() bool {
	return r.Retry == foundationv1.RetryMode_RETRY_MODE_UNSPECIFIED || r.Retry == foundationv1.RetryMode_RETRY_MODE_NEVER
}

// CommandIDReused is CONFLICT/command_id_reused.
func CommandIDReused() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT, Code: "command_id_reused"}
}

// NotActivated is STATE/not_activated with state.reason = the surface.
func NotActivated(surface string) *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, Code: "not_activated", Reason: surface}
}

// RateLimited is RESOURCE/rate_limited: retry after retryAt (AFTER_TIME without an instant when it is zero); the limit names the
// bucket kind.
func RateLimited(bucket string, maximum int64, retryAt time.Time) *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE, Code: "rate_limited",
		Retry: foundationv1.RetryMode_RETRY_MODE_AFTER_TIME, RetryAt: retryAt,
		Limit: &Limit{Name: bucket, Maximum: maximum, RecoveryAt: retryAt}}
}

// Unavailable is a store that could not be reached: RESOURCE/overloaded, retry after a short time with jitter.
func Unavailable() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE, Code: "overloaded",
		Retry: foundationv1.RetryMode_RETRY_MODE_AFTER_TIME}
}

// Internal is INTERNAL/internal: an unexpected failure (logged with the correlation id), retried once after a while; its effect
// is unknown because the failure may have followed a commit.
func Internal() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_INTERNAL, Code: "internal",
		Retry: foundationv1.RetryMode_RETRY_MODE_AFTER_TIME, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN}
}

// CommitUnknown is INTERNAL/internal for the write that carries a call's effect when its COMMIT was sent without an answer: it may
// have happened (effect UNKNOWN), and the same call is never retried as it was (retry NEVER), because a refresh token or a flow it
// presented may already be spent; the client signs in again or reads the state it needs. An auxiliary transaction's unanswered
// COMMIT (a rate-limit count, a flow attempt, a refusal's audit) leaves the effect undone and is answered as Unavailable (D10).
func CommitUnknown() *Refusal {
	return &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_INTERNAL, Code: "internal",
		Retry: foundationv1.RetryMode_RETRY_MODE_NEVER, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN}
}

// Instant is a contract instant (UTC seconds and nanoseconds, truncated to microseconds as the store keeps them).
func Instant(at time.Time) *foundationv1.Instant {
	at = at.UTC().Truncate(time.Microsecond)
	return &foundationv1.Instant{UnixSeconds: proto.Int64(at.Unix()), Nanos: proto.Uint32(uint32(at.Nanosecond()))}
}

// Decimal is a contract decimal of an integer.
func Decimal(value int64) *foundationv1.Decimal {
	return &foundationv1.Decimal{Value: proto.String(strconv.FormatInt(value, 10))}
}

// ReplyMessage is the bytes of a reply message whose outcome is the ArcError: every reply of the identity and device services
// carries its ArcError as field 3 of the outcome oneof, so one encoding serves each of them, and it is what the Worker returns for a
// refusal it answers itself (generated per surface, without a correlation id).
func ReplyMessage(value *foundationv1.ArcError) ([]byte, error) {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(value)
	if err != nil {
		return nil, err
	}
	return protowire.AppendBytes(protowire.AppendTag(nil, ReplyErrorField, protowire.BytesType), encoded), nil
}

// ReplyErrorField is the field number of the ArcError in every reply's outcome oneof.
const ReplyErrorField = 3
