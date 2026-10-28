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
// details that row defines.
func TestEveryRefusalIsAnErrorsRow(t *testing.T) {
	at := time.Date(2026, 10, 28, 12, 0, 0, 123456789, time.UTC)
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
		{NotFound(), "STATE/not_found", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{InvalidState("credential", "last_credential"), "STATE/invalid_state", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{Expired(), "STATE/expired", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{NotActivated("identity"), "STATE/not_activated", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{CodeReused(), "CONFLICT/code_reused", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{AlreadyExists(), "CONFLICT/already_exists", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{CommandIDReused(), "CONFLICT/command_id_reused", foundationv1.RetryMode_RETRY_MODE_NEVER},
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
	edge := RateLimited("edge", 0, time.Time{}).ArcError(correlation.Context{})
	if edge.GetDetails().GetLimit().GetMaximum() != nil || edge.GetRetry().GetRetryAt() != nil || edge.GetCorrelationId() != nil {
		t.Fatalf("the edge refusal states no maximum, instant or correlation %v", edge)
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
