// SPDX-License-Identifier: AGPL-3.0-only

package arc

import (
	"regexp"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/correlation"
)

// TestEveryRefusalIsAnErrorsRow pins each constructor to its errors.md row: category, code, message key, retry advice and the
// details that row defines, exactly: a row without details carries none, and not_found and already_exists carry state.resource
// with the kind and only the ID the caller named (F19). Every rendering is also a valid foundation message (B6,
// foundationViolations): its StateFailure states a state and a reason, and a resource always has its Id.
func TestEveryRefusalIsAnErrorsRow(t *testing.T) {
	at := time.Date(2026, 10, 28, 12, 0, 0, 123456789, time.UTC)
	flowID := []byte{0x0b, 0x6e, 0x1c, 0x52, 0x2d, 0x40, 0x4e, 0x0f, 0x8a, 0x5c, 0x41, 0x7f, 0x19, 0x9d, 0x60, 0x21}
	cases := []struct {
		refusal *Refusal
		row     string
		retry   foundationv1.RetryMode
	}{
		{InvalidArgument("method", "not_offered"), "VALIDATION/invalid_argument", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{InvalidCursor(), "VALIDATION/invalid_cursor", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{Unauthenticated(), "AUTHENTICATION/unauthenticated", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{TokenExpired(), "AUTHENTICATION/token_expired", foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND},
		{CredentialRevoked(), "AUTHENTICATION/credential_revoked", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{StepUpRequired(), "AUTHENTICATION/step_up_required", foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND},
		{PermissionDenied("device.list"), "AUTHORIZATION/permission_denied", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{NotFound("auth_flow", flowID), "STATE/not_found", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{NotFound("account", nil), "STATE/not_found", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{InvalidArgument("a field path", "length"), "VALIDATION/invalid_argument", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{InvalidState("credential", "last_credential"), "STATE/invalid_state", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{Expired(), "STATE/expired", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{NotActivated("identity"), "STATE/not_activated", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{CodeReused(), "CONFLICT/code_reused", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{AlreadyExists("credential", nil), "CONFLICT/already_exists", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{AlreadyExists("credential", flowID), "CONFLICT/already_exists", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{CommitUnknown(), "INTERNAL/internal", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{CommandIDReused(), "CONFLICT/command_id_reused", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{RevisionConflict(3, 4), "CONFLICT/revision_conflict", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{RateLimited("sign_in_prefix", 30, at), "RESOURCE/rate_limited", foundationv1.RetryMode_RETRY_MODE_AFTER_TIME},
		{Unavailable(), "RESOURCE/overloaded", foundationv1.RetryMode_RETRY_MODE_AFTER_TIME},
		{Internal(), "INTERNAL/internal", foundationv1.RetryMode_RETRY_MODE_AFTER_TIME},
	}
	call := correlation.New()
	for _, item := range cases {
		value := item.refusal.ArcError(call)
		for _, violation := range foundationViolations(value, true) {
			t.Errorf("%s: %s", item.row, violation)
		}
		if item.refusal.Key() != item.row || value.GetRetry().GetMode() != item.retry || value.GetCode() != item.refusal.Code ||
			value.GetMessageKey() != item.refusal.MessageKey() || string(value.GetCorrelationId().GetValue()) != string(correlation.IDBytes(call.CorrelationID)) {
			t.Errorf("%s: %v", item.row, value)
		}
		want := foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN
		if item.row == "INTERNAL/internal" {
			want = foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN
		}
		if value.GetEffect() != want {
			t.Errorf("%s effect %v", item.row, value.GetEffect())
		}
		// The detail each row defines, and nothing else.
		detail := "none"
		switch item.row {
		case "VALIDATION/invalid_argument", "AUTHORIZATION/permission_denied", "STATE/invalid_state", "STATE/not_activated", "STATE/not_found",
			"CONFLICT/already_exists":
			detail = "state"
		case "RESOURCE/rate_limited":
			detail = "limit"
		case "CONFLICT/revision_conflict":
			detail = "revision"
		}
		details := value.GetDetails()
		if detail == "none" && details != nil || detail == "state" && details.GetState() == nil || detail == "limit" && details.GetLimit() == nil ||
			detail == "revision" && details.GetRevision() == nil {
			t.Errorf("%s details %v", item.row, details)
		}
	}
	// The validator refuses the shape F19 first emitted: a state.resource without a state, a reason and an Id.
	if len(foundationViolations(&foundationv1.ArcError{Details: &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{
		State: &foundationv1.StateFailure{Resource: &foundationv1.AggregateRef{Kind: proto.String("account")}}}}}, false)) < 3 {
		t.Fatal("the foundation check admits a StateFailure without its state, reason and resource Id")
	}
	missing := NotFound("auth_flow", flowID).ArcError(call).GetDetails().GetState()
	if missing.GetState() != "auth_flow" || missing.GetReason() != "not_found" || missing.GetResource().GetKind() != "auth_flow" ||
		string(missing.GetResource().GetId().GetValue()) != string(flowID) {
		t.Fatalf("not_found details %v", missing)
	}
	// B6: a resource only by a valid Id: without one (or with a zero one) the details name the kind and the code only.
	for _, value := range []*foundationv1.StateFailure{NotFound("account", nil).ArcError(call).GetDetails().GetState(),
		AlreadyExists("credential", nil).ArcError(call).GetDetails().GetState(), NotFound("session", make([]byte, 16)).ArcError(call).GetDetails().GetState()} {
		if value.GetResource() != nil || value.State == nil || value.Reason == nil {
			t.Fatalf("a resource without a valid ID %v", value)
		}
	}
	own := AlreadyExists("credential", flowID).ArcError(call).GetDetails().GetState()
	if own.GetState() != "credential" || own.GetReason() != "already_exists" || string(own.GetResource().GetId().GetValue()) != string(flowID) {
		t.Fatalf("already_exists of the caller's own object %v", own)
	}
	if value := InvalidArgument("method", "not_offered").ArcError(call).GetDetails().GetState(); value.GetState() != "method" ||
		value.GetReason() != "method: not_offered" ||
		InvalidArgument("a field path", "length").ArcError(call).GetDetails().GetState().GetState() != "request" ||
		PermissionDenied("device.list").ArcError(call).GetDetails().GetState().GetReason() != "device.list" ||
		PermissionDenied("device.list").ArcError(call).GetDetails().GetState().GetState() != "operation" ||
		NotActivated("identity").ArcError(call).GetDetails().GetState().GetReason() != "identity" ||
		NotActivated("identity").ArcError(call).GetDetails().GetState().GetState() != "surface" ||
		InvalidState("credential", "last_credential").ArcError(call).GetDetails().GetState().GetState() != "credential" ||
		NotActivated("identity").MessageKey() != "error.state.not_activated" {
		t.Fatal("state details")
	}
	limited := RateLimited("sign_in_prefix", 30, at).ArcError(call)
	if limited.GetDetails().GetLimit().GetLimitName() != "sign_in_prefix" || limited.GetDetails().GetLimit().GetMaximum().GetValue() != "30" ||
		limited.GetRetry().GetRetryAt().GetUnixSeconds() != at.Unix() || limited.GetRetry().GetRetryAt().GetNanos() != 123456000 ||
		limited.GetDetails().GetLimit().GetRecoveryAt().GetUnixSeconds() != at.Unix() {
		t.Fatalf("limit details %v", limited)
	}
	stale := RevisionConflict(3, 4).ArcError(call).GetDetails().GetRevision()
	if stale.GetExpected().GetValue() != 3 || stale.GetActual().GetValue() != 4 {
		t.Fatalf("revision details %v", stale)
	}
	// A receipt keeps exactly the refusals whose advice is NEVER: the others turn into a success with the same command.
	for _, refusal := range []*Refusal{NotFound("session", flowID), InvalidState("credential", "last_credential"), RevisionConflict(1, 2), CodeReused(),
		AlreadyExists("credential", nil)} {
		if !refusal.Final() {
			t.Errorf("%s is not final", refusal.Key())
		}
	}
	for _, refusal := range []*Refusal{StepUpRequired(), TokenExpired(), RateLimited("step_up_account", 10, at), Unavailable(), Internal()} {
		if refusal.Final() {
			t.Errorf("%s is final", refusal.Key())
		}
	}
	edge := RateLimited("edge", 0, time.Time{}).ArcError(correlation.Context{})
	if edge.GetDetails().GetLimit().GetMaximum() != nil || edge.GetRetry().GetRetryAt() != nil || edge.GetCorrelationId() != nil {
		t.Fatalf("a zero instant and maximum and an empty correlation are not stated %v", edge)
	}
}

// foundationPattern is the pattern foundation-baseline.json gives ArcError.message_key, StateFailure.state, AggregateRef.kind and
// LimitFailure.limit_name.
var foundationPattern = regexp.MustCompile(`^[A-Za-z0-9._:/-]{1,128}$`)

// foundationViolations checks an ArcError against the rules Contracts public/proto/constraints/foundation-baseline.json (62ccef1)
// states for it and the messages it carries (B6): ArcError's code, category, message key, retry, effect and, when the call has one,
// correlation id are required; ErrorDetails holds one detail; StateFailure requires its state (pattern) and reason; an AggregateRef
// requires its kind (pattern) and an Id of 16 bytes that are not all zero; LimitFailure requires its limit name (pattern); a
// Revision's value is at least 0.
func foundationViolations(value *foundationv1.ArcError, correlated bool) []string {
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
	check(value.MessageKey != nil && foundationPattern.MatchString(value.GetMessageKey()), "ArcError.message_key is required and matches the pattern")
	check(value.GetRetry() != nil && value.GetRetry().Mode != nil && value.GetRetry().GetMode() >= 1 && value.GetRetry().GetMode() <= 4,
		"ArcError.retry.mode is required (1 to 4)")
	check(value.Effect != nil && value.GetEffect() >= 1 && value.GetEffect() <= 3, "ArcError.effect is required (1 to 3)")
	if correlated {
		check(validID(value.GetCorrelationId()), "ArcError.correlation_id is required")
	}
	details := value.GetDetails()
	if details == nil {
		return found
	}
	check(details.GetDetail() != nil, "ErrorDetails holds one detail")
	if state := details.GetState(); state != nil {
		check(state.State != nil && foundationPattern.MatchString(state.GetState()), "StateFailure.state is required and matches the pattern")
		check(state.Reason != nil && state.GetReason() != "", "StateFailure.reason is required")
		if resource := state.GetResource(); resource != nil {
			check(resource.Kind != nil && foundationPattern.MatchString(resource.GetKind()), "AggregateRef.kind is required and matches the pattern")
			check(validID(resource.GetId()), "AggregateRef.id is required (16 bytes, not all zero)")
		}
	}
	if limit := details.GetLimit(); limit != nil {
		check(limit.LimitName != nil && foundationPattern.MatchString(limit.GetLimitName()), "LimitFailure.limit_name is required and matches the pattern")
	}
	if revision := details.GetRevision(); revision != nil {
		for _, item := range []*foundationv1.Revision{revision.GetExpected(), revision.GetActual()} {
			check(item == nil || item.Value != nil && item.GetValue() >= 0, "Revision.value is required and at least 0")
		}
	}
	return found
}

func TestAReplyCarriesTheErrorAsFieldThree(t *testing.T) {
	value := NotActivated("identity").ArcError(correlation.Context{})
	message, err := ReplyMessage(value)
	if err != nil {
		t.Fatal(err)
	}
	number, kind, length := protowire.ConsumeTag(message)
	if number != 3 || kind != protowire.BytesType || length < 0 {
		t.Fatal("not field 3")
	}
	payload, _ := protowire.ConsumeBytes(message[length:])
	var decoded foundationv1.ArcError
	if err = proto.Unmarshal(payload, &decoded); err != nil || !proto.Equal(&decoded, value) {
		t.Fatalf("decoded %v %v", &decoded, err)
	}
}
