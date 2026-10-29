// SPDX-License-Identifier: AGPL-3.0-only

package arc

import (
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/correlation"
)

// TestEveryRefusalIsAnErrorsRow pins each constructor to its errors.md row: category, code, message key, retry advice and the
// details that row defines, exactly: a row without details carries none, and not_found and already_exists carry state.resource
// with the kind and only the ID the caller named (F19).
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
		{InvalidState("credential", "last_credential"), "STATE/invalid_state", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{Expired(), "STATE/expired", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{NotActivated("identity"), "STATE/not_activated", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{CodeReused(), "CONFLICT/code_reused", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{AlreadyExists("credential", nil), "CONFLICT/already_exists", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{CommandIDReused(), "CONFLICT/command_id_reused", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{RevisionConflict(3, 4), "CONFLICT/revision_conflict", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{RateLimited("sign_in_prefix", 30, at), "RESOURCE/rate_limited", foundationv1.RetryMode_RETRY_MODE_AFTER_TIME},
		{Unavailable(), "RESOURCE/overloaded", foundationv1.RetryMode_RETRY_MODE_AFTER_TIME},
		{Internal(), "INTERNAL/internal", foundationv1.RetryMode_RETRY_MODE_AFTER_TIME},
	}
	call := correlation.New()
	for _, item := range cases {
		value := item.refusal.ArcError(call)
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
	missing := NotFound("auth_flow", flowID).ArcError(call).GetDetails().GetState()
	if missing.GetResource().GetKind() != "auth_flow" || string(missing.GetResource().GetId().GetValue()) != string(flowID) ||
		missing.State != nil || missing.Reason != nil {
		t.Fatalf("not_found resource %v", missing)
	}
	own := NotFound("account", nil).ArcError(call).GetDetails().GetState().GetResource()
	exists := AlreadyExists("credential", nil).ArcError(call).GetDetails().GetState().GetResource()
	if own.GetKind() != "account" || own.GetId() != nil || exists.GetKind() != "credential" || exists.GetId() != nil {
		t.Fatalf("a resource without a named ID %v %v", own, exists)
	}
	if InvalidArgument("method", "not_offered").ArcError(call).GetDetails().GetState().GetReason() != "method: not_offered" ||
		PermissionDenied("device.list").ArcError(call).GetDetails().GetState().GetReason() != "device.list" ||
		NotActivated("identity").ArcError(call).GetDetails().GetState().GetReason() != "identity" ||
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
