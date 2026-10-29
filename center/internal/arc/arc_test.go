// SPDX-License-Identifier: AGPL-3.0-only

package arc

import (
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc/arctest"
	"github.com/ArcForges/Cloud/center/internal/correlation"
)

// TestEveryRefusalIsAnErrorsRow pins each constructor to its errors.md row: category, code, message key, retry advice and the
// details that row defines, exactly: a row without details carries none, and not_found and already_exists carry state.resource
// with the kind and only the ID the caller named (F19). Every rendering, dated as the reply dates it, also passes the subset of
// the Contracts foundation rules that arctest.Violations checks (B6, E4, F-7; it names the rules it leaves out): its
// StateFailure states a state and a reason, a resource always has its Id, an AFTER_TIME advice carries its retry_at, and only
// INTERNAL/internal pairs AFTER_TIME with effect UNKNOWN (the one named exemption).
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
		value := item.refusal.Dated(at).ArcError(call)
		for _, violation := range arctest.Violations(value) {
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
	shapeless := NotFound("auth_flow", flowID).ArcError(call)
	shapeless.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{
		State: &foundationv1.StateFailure{Resource: &foundationv1.AggregateRef{Kind: proto.String("account")}}}}
	if len(arctest.Violations(shapeless)) != 3 {
		t.Fatalf("the foundation check admits a StateFailure without its state, reason and resource Id: %v", arctest.Violations(shapeless))
	}
	// The correlation id is required of every ArcError, the Worker's generated replies included (E4-1).
	uncorrelated := Unavailable().Dated(at).ArcError(correlation.Context{})
	if violations := arctest.Violations(uncorrelated); len(violations) != 1 || violations[0] != "ArcError.correlation_id is required" {
		t.Fatalf("the foundation check admits an ArcError without a correlation id: %v", violations)
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
	// E4: an AFTER_TIME refusal without an instant breaks the rule until it is dated; Dated gives it one to two seconds from the
	// refusal and leaves a stated instant and every other advice as they are.
	if len(arctest.Violations(Unavailable().ArcError(call))) != 1 {
		t.Fatal("the foundation check admits AFTER_TIME without retry_at")
	}
	// F-7: the arcError clause admits AFTER_TIME with effect UNKNOWN for INTERNAL/internal only, and the Instant bounds hold.
	unknown := Unavailable().Dated(at)
	unknown.Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN
	if len(arctest.Violations(unknown.ArcError(call))) != 1 || len(arctest.Violations(Internal().Dated(at).ArcError(call))) != 0 {
		t.Fatal("the arcError clause or its one exemption")
	}
	// A-2: the exemption needs both the category INTERNAL and the code "internal": either alone does not exempt the pair, and the
	// bound of LimitFailure.recovery_at is held like retry_at's.
	for name, mutate := range map[string]func(*foundationv1.ArcError){
		"INTERNAL with another code": func(value *foundationv1.ArcError) { value.Code = proto.String("store_corrupt") },
		"another category with the code": func(value *foundationv1.ArcError) {
			value.Category = foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE.Enum()
		},
	} {
		value := Internal().Dated(at).ArcError(call)
		value.Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN.Enum()
		if len(arctest.Violations(value)) != 0 {
			t.Fatalf("the exempt pair itself is refused: %v", arctest.Violations(value))
		}
		mutate(value)
		if len(arctest.Violations(value)) != 1 {
			t.Errorf("%s is exempt from the arcError clause", name)
		}
	}
	for _, bad := range []*foundationv1.Instant{{UnixSeconds: proto.Int64(arctest.InstantMaxSeconds + 1), Nanos: proto.Uint32(0)},
		{UnixSeconds: proto.Int64(arctest.InstantMinSeconds - 1), Nanos: proto.Uint32(0)}, {UnixSeconds: proto.Int64(0), Nanos: proto.Uint32(arctest.InstantMaxNanos + 1)},
		{Nanos: proto.Uint32(0)}} {
		value := RateLimited("sign_in_prefix", 30, at).ArcError(call)
		value.GetDetails().GetLimit().RecoveryAt = bad
		if len(arctest.Violations(value)) != 1 {
			t.Fatalf("the recovery_at bounds admit %v", bad)
		}
	}
	for _, bad := range []*foundationv1.Instant{{UnixSeconds: proto.Int64(arctest.InstantMaxSeconds + 1), Nanos: proto.Uint32(0)},
		{UnixSeconds: proto.Int64(arctest.InstantMinSeconds - 1), Nanos: proto.Uint32(0)}, {UnixSeconds: proto.Int64(0), Nanos: proto.Uint32(arctest.InstantMaxNanos + 1)},
		{Nanos: proto.Uint32(0)}} {
		value := Unavailable().Dated(at).ArcError(call)
		value.Retry.RetryAt = bad
		if len(arctest.Violations(value)) != 1 {
			t.Fatalf("the Instant bounds admit %v", bad)
		}
	}
	for range 50 {
		for _, refusal := range []*Refusal{Unavailable(), Internal()} {
			dated := refusal.Dated(at)
			if dated.RetryAt.Before(at.Add(time.Second)) || !dated.RetryAt.Before(at.Add(2*time.Second)) || !refusal.RetryAt.IsZero() {
				t.Fatalf("%s dated %v at %v", refusal.Key(), dated.RetryAt, at)
			}
		}
	}
	for _, refusal := range []*Refusal{RateLimited("sign_in_prefix", 30, at.Add(time.Hour)), StepUpRequired(), CommitUnknown(), Expired()} {
		if refusal.Dated(at) != refusal {
			t.Errorf("%s was dated", refusal.Key())
		}
	}
	edge := RateLimited("edge", 0, time.Time{}).ArcError(correlation.Context{})
	if edge.GetDetails().GetLimit().GetMaximum() != nil || edge.GetRetry().GetRetryAt() != nil || edge.GetCorrelationId() != nil {
		t.Fatalf("a zero instant and maximum and an empty correlation are not stated %v", edge)
	}
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
