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
// StateFailure states a state and a reason, a resource always has its Id, an AFTER_TIME advice carries its retry_at, and no refusal
// pairs AFTER_TIME with effect UNKNOWN (INTERNAL/internal is NEVER with UNKNOWN; there is no exemption).
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
		{FeatureNotEntitled("remote.view"), "ENTITLEMENT/feature_not_entitled", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{CodeReused(), "CONFLICT/code_reused", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{AlreadyExists("credential", nil), "CONFLICT/already_exists", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{AlreadyExists("credential", flowID), "CONFLICT/already_exists", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{CommandIDReused(), "CONFLICT/command_id_reused", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{RevisionConflict(3, 4), "CONFLICT/revision_conflict", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{RateLimited("sign_in_prefix", 30, at), "RESOURCE/rate_limited", foundationv1.RetryMode_RETRY_MODE_AFTER_TIME},
		{KeyAlreadyRegistered(), "CONFLICT/already_exists", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{QuotaExceeded("max_nodes_per_account", 100), "RESOURCE/quota_exceeded", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{CodeInvalid("device_entry_account", 5, 3), "VALIDATION/code_invalid", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{CodeInvalid("device_code_lookups", 5, 0), "VALIDATION/code_invalid", foundationv1.RetryMode_RETRY_MODE_NEVER},
		{Unavailable(), "RESOURCE/overloaded", foundationv1.RetryMode_RETRY_MODE_AFTER_TIME},
		{Internal(), "INTERNAL/internal", foundationv1.RetryMode_RETRY_MODE_NEVER},
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
		case "VALIDATION/invalid_argument", "AUTHORIZATION/permission_denied", "ENTITLEMENT/feature_not_entitled", "STATE/invalid_state", "STATE/not_activated", "STATE/not_found",
			"CONFLICT/already_exists":
			detail = "state"
		case "RESOURCE/rate_limited", "RESOURCE/quota_exceeded", "VALIDATION/code_invalid":
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
		FeatureNotEntitled("remote.view").ArcError(call).GetDetails().GetState().GetReason() != "remote.view" ||
		FeatureNotEntitled("remote.view").ArcError(call).GetDetails().GetState().GetState() != "feature" ||
		FeatureNotEntitled("remote.view").MessageKey() != "error.entitlement.feature_not_entitled" ||
		NotActivated("identity").MessageKey() != "error.state.not_activated" {
		t.Fatal("state details")
	}
	limited := RateLimited("sign_in_prefix", 30, at).ArcError(call)
	if limited.GetDetails().GetLimit().GetLimitName() != "sign_in_prefix" || limited.GetDetails().GetLimit().GetMaximum().GetValue() != "30" ||
		limited.GetRetry().GetRetryAt().GetUnixSeconds() != at.Unix() || limited.GetRetry().GetRetryAt().GetNanos() != 123456000 ||
		limited.GetDetails().GetLimit().GetRecoveryAt().GetUnixSeconds() != at.Unix() {
		t.Fatalf("limit details %v", limited)
	}
	// AF-CTR-04: the held-key refusal names the node key and no resource; the node cap names its limit and maximum, no retry instant.
	if held := KeyAlreadyRegistered().ArcError(call).GetDetails().GetState(); held.GetState() != "node_key" || held.GetReason() != "already_registered" ||
		held.GetResource() != nil {
		t.Fatalf("held-key details %v", held)
	}
	if capped := QuotaExceeded("max_nodes_per_account", 100).ArcError(call); capped.GetDetails().GetLimit().GetLimitName() != "max_nodes_per_account" ||
		capped.GetDetails().GetLimit().GetMaximum().GetValue() != "100" || capped.GetRetry().GetRetryAt() != nil {
		t.Fatalf("quota details %v", capped)
	}
	// AF-CTR-04 E2: code_invalid names its counter, its maximum and what is left; a stated 0 is the decimal 0, not an absent field
	// (contracts-9); a refusal that states nothing left out has no available.
	for _, item := range []struct {
		name               string
		maximum, available int64
		want               string
	}{{"device_entry_account", 5, 3, "3"}, {"device_code_lookups", 5, 0, "0"}} {
		limit := CodeInvalid(item.name, item.maximum, item.available).ArcError(call).GetDetails().GetLimit()
		if limit.GetLimitName() != item.name || limit.GetMaximum().GetValue() != "5" || limit.GetAvailable() == nil ||
			limit.GetAvailable().GetValue() != item.want || limit.GetRecoveryAt() != nil {
			t.Fatalf("code_invalid details %v", limit)
		}
	}
	if CodeInvalid("device_entry_account", 5, 0).Retry != foundationv1.RetryMode_RETRY_MODE_UNSPECIFIED || !CodeInvalid("device_entry_account", 5, 0).Final() {
		t.Fatal("code_invalid is final (NEVER, known effect)")
	}
	if RateLimited("device_entry_account", 5, at).ArcError(call).GetDetails().GetLimit().GetAvailable() != nil {
		t.Fatal("a rate limit states no available")
	}
	bad := CodeInvalid("device_entry_account", 5, 1).ArcError(call)
	bad.Details.GetLimit().Available = &foundationv1.Decimal{Value: proto.String("01")}
	if len(arctest.Violations(bad)) != 1 {
		t.Fatalf("the foundation check admits a non-canonical available: %v", arctest.Violations(bad))
	}
	stale := RevisionConflict(3, 4).ArcError(call).GetDetails().GetRevision()
	if stale.GetExpected().GetValue() != 3 || stale.GetActual().GetValue() != 4 {
		t.Fatalf("revision details %v", stale)
	}
	// A receipt keeps exactly the refusals whose advice is NEVER and whose effect is known: the others turn into a success with the
	// same command (Internal advises NEVER with UNKNOWN and says nothing about the command).
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
	// F-7: the arcError clause admits effect UNKNOWN with no AFTER_TIME at all, INTERNAL/internal included, and the Instant bounds hold.
	unknown := Unavailable().Dated(at)
	unknown.Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN
	if len(arctest.Violations(unknown.ArcError(call))) != 1 || len(arctest.Violations(Internal().Dated(at).ArcError(call))) != 0 {
		t.Fatal("the arcError clause")
	}
	// E4-INTERNAL: no exemption. The pair INTERNAL/internal had (AFTER_TIME with UNKNOWN) is a violation like any other, whatever the
	// category and code of the reply, and Internal itself is NEVER with UNKNOWN.
	pair := Internal().Dated(at).ArcError(call)
	if pair.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER || pair.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
		pair.GetRetry().GetRetryAt() != nil {
		t.Fatalf("INTERNAL/internal is %v with %v", pair.GetRetry(), pair.GetEffect())
	}
	pair.Retry = &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_AFTER_TIME.Enum(), RetryAt: Instant(at.Add(time.Second))}
	if len(arctest.Violations(pair)) != 1 {
		t.Errorf("INTERNAL/internal is exempt from the arcError clause: %v", arctest.Violations(pair))
	}
	for _, code := range []string{"internal", "store_corrupt"} {
		for _, category := range []foundationv1.ErrorCategory{foundationv1.ErrorCategory_ERROR_CATEGORY_INTERNAL, foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE} {
			value := Internal().Dated(at).ArcError(call)
			value.Code, value.Category = proto.String(code), category.Enum()
			value.Retry = pair.Retry
			if len(arctest.Violations(value)) != 1 {
				t.Errorf("%s/%s is exempt from the arcError clause", category, code)
			}
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
		for _, refusal := range []*Refusal{Unavailable()} {
			dated := refusal.Dated(at)
			if dated.RetryAt.Before(at.Add(time.Second)) || !dated.RetryAt.Before(at.Add(2*time.Second)) || !refusal.RetryAt.IsZero() {
				t.Fatalf("%s dated %v at %v", refusal.Key(), dated.RetryAt, at)
			}
		}
	}
	for _, refusal := range []*Refusal{RateLimited("sign_in_prefix", 30, at.Add(time.Hour)), StepUpRequired(), Internal(), Expired()} {
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

// TestReconciliationOperationIsSetExactlyWithReconcile (E4-INTERNAL): the wire mapping sets RetryAdvice.reconciliation_operation when,
// and only when, the advice is RECONCILE (Contracts rule retryAdvice), and a refusal that breaks that cannot be rendered; the check
// every test applies (arctest.Violations) finds the same break in an ArcError that was not built by this package.
func TestReconciliationOperationIsSetExactlyWithReconcile(t *testing.T) {
	call := correlation.New()
	const operation = "arcforges.publicapi.v1.IdentityService/ListSessions"
	reconcile := &Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_INTERNAL, Code: "internal",
		Retry: foundationv1.RetryMode_RETRY_MODE_RECONCILE, Reconcile: operation, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN}
	value := reconcile.Dated(time.Now()).ArcError(call)
	if value.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_RECONCILE || value.GetRetry().GetReconciliationOperation() != operation ||
		value.GetRetry().GetRetryAt() != nil || len(arctest.Violations(value)) != 0 {
		t.Fatalf("RECONCILE with its operation: %v %v", value.GetRetry(), arctest.Violations(value))
	}
	if reconcile.Final() {
		t.Error("a RECONCILE refusal is final")
	}
	// No other refusal of the package states an operation.
	for _, refusal := range []*Refusal{Internal(), Unavailable(), StepUpRequired(), Expired(), RateLimited("x", 1, time.Now())} {
		if refusal.Reconcile != "" || refusal.Dated(time.Now()).ArcError(call).GetRetry().ReconciliationOperation != nil {
			t.Errorf("%s names a reconciliation operation", refusal.Key())
		}
	}
	panics := func(refusal *Refusal) (broke bool) {
		defer func() { broke = recover() != nil }()
		refusal.ArcError(call)
		return false
	}
	without := *reconcile
	without.Reconcile = ""
	other := *Internal()
	other.Reconcile = operation
	malformed := *reconcile
	malformed.Reconcile = "not a valid operation name"
	for name, refusal := range map[string]*Refusal{"RECONCILE without an operation": &without, "an operation without RECONCILE": &other,
		"an operation that does not match the pattern": &malformed} {
		if !panics(refusal) {
			t.Errorf("%s was rendered", name)
		}
	}
	// The check finds both breaks in an ArcError built elsewhere.
	missing := reconcile.ArcError(call)
	missing.Retry.ReconciliationOperation = nil
	stray := Internal().ArcError(call)
	stray.Retry.ReconciliationOperation = proto.String(operation)
	badName := reconcile.ArcError(call)
	badName.Retry.ReconciliationOperation = proto.String("not a valid operation name")
	for name, broken := range map[string]*foundationv1.ArcError{"missing": missing, "stray": stray, "malformed": badName} {
		if len(arctest.Violations(broken)) != 1 {
			t.Errorf("the check admits a %s reconciliation operation: %v", name, arctest.Violations(broken))
		}
	}
}
