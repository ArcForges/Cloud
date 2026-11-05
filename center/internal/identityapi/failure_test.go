// SPDX-License-Identifier: AGPL-3.0-only

package identityapi

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// TestEveryStoreFailureHasItsEffectAndAdvice pins the reply of each store failure (F6): a write whose COMMIT went unanswered may have
// happened, so it is INTERNAL with effect UNKNOWN and never retried as it was; a store that is down or contended before the commit
// did nothing and may be retried after a while (an auxiliary transaction's unanswered commit too, logged as a warning with the
// correlation id); any other failure is INTERNAL with effect UNKNOWN, retry NEVER (E4-INTERNAL).
func TestEveryStoreFailureHasItsEffectAndAdvice(t *testing.T) {
	var logs bytes.Buffer
	server := New(nil, nil, nil, nil, slog.New(slog.NewJSONHandler(&logs, nil)))
	call := &ingress.Call{Policy: ingress.Policy{FullName: "/arcforges.publicapi.v1.IdentityService/RefreshSession"},
		Correlation: correlation.Context{CorrelationID: "4bf92f35-77b3-4da6-a3ce-929d0e0e4736"}}
	for name, item := range map[string]struct {
		err    error
		key    string
		effect foundationv1.EffectCertainty
		retry  foundationv1.RetryMode
		logged bool
		warned bool
	}{
		"an unanswered commit": {&store.Error{Operation: "refresh a session", Kind: store.ErrCommitUnknown}, "INTERNAL/internal",
			foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN, foundationv1.RetryMode_RETRY_MODE_NEVER, true, false},
		"an unavailable store": {&store.Error{Operation: "refresh a session", Kind: store.ErrUnavailable}, "RESOURCE/overloaded",
			foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN, foundationv1.RetryMode_RETRY_MODE_AFTER_TIME, false, false},
		"an unanswered auxiliary commit": {&store.Error{Operation: "count a rate-limit bucket", Kind: store.ErrUnavailable, Unanswered: true},
			"RESOURCE/overloaded", foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN, foundationv1.RetryMode_RETRY_MODE_AFTER_TIME, false, true},
		"contention": {&store.Error{Operation: "refresh a session", Kind: store.ErrContention}, "RESOURCE/overloaded",
			foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN, foundationv1.RetryMode_RETRY_MODE_AFTER_TIME, false, false},
		"a missing privilege": {&store.Error{Operation: "refresh a session", Kind: store.ErrPermission}, "INTERNAL/internal",
			foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN, foundationv1.RetryMode_RETRY_MODE_NEVER, true, false},
	} {
		logs.Reset()
		reply := server.failure(context.Background(), call, item.err)
		key := strings.TrimPrefix(reply.GetCategory().String(), "ERROR_CATEGORY_") + "/" + reply.GetCode()
		if key != item.key || reply.GetEffect() != item.effect || reply.GetRetry().GetMode() != item.retry ||
			strings.Contains(logs.String(), "identity call failed") != item.logged || reply.GetCorrelationId() == nil ||
			strings.Contains(logs.String(), `"msg":"an auxiliary commit went unanswered"`) != item.warned ||
			item.warned && (!strings.Contains(logs.String(), `"level":"WARN"`) || !strings.Contains(logs.String(), "4bf92f35-77b3-4da6-a3ce-929d0e0e4736")) {
			t.Errorf("%s: %s %s %s logged=%v", name, key, reply.GetEffect(), reply.GetRetry().GetMode(), logs.Len() > 0)
		}
	}
}

// gateFailureCauses are the causes a gate cannot decide on, one per closed reason of access.gate_failure.
var gateFailureCauses = map[string]error{
	access.GateFailureCommitUnknown:         &store.Error{Operation: "store the entitlement snapshot", Kind: store.ErrCommitUnknown},
	access.GateFailureRefreshContended:      &entitlement.Refusal{Kind: entitlement.RefusedConcurrentUpdate, Detail: "concurrent"},
	access.GateFailureNoEntitlementStore:    feature.ErrNoEntitlementStore,
	access.GateFailureDefinitionsSuperseded: entitlement.ErrDefinitionsSuperseded,
}

// TestAGateFailureIsLoggedWithItsCorrelationAndAnsweredOverloaded is E0-3 (gate-3) on the identity surface's failure path: a gate that
// could not decide is answered RESOURCE/overloaded (did not happen, retry after a while), and its cause is logged once with the
// method, the correlation ID and the closed reason; it is never the INTERNAL line of a defect.
func TestAGateFailureIsLoggedWithItsCorrelationAndAnsweredOverloaded(t *testing.T) {
	var logs bytes.Buffer
	server := New(nil, nil, nil, nil, slog.New(slog.NewJSONHandler(&logs, nil)))
	call := &ingress.Call{Policy: ingress.Policy{FullName: "/arcforges.test.v1.GateProbe/RemoteView"},
		Correlation: correlation.Context{CorrelationID: "4bf92f35-77b3-4da6-a3ce-929d0e0e4736"}}
	for reason, cause := range gateFailureCauses {
		logs.Reset()
		failure, ok := access.NewGateFailure(cause)
		if !ok {
			t.Fatalf("%s: no gate failure", reason)
		}
		reply := server.failure(context.Background(), call, failure)
		key := strings.TrimPrefix(reply.GetCategory().String(), "ERROR_CATEGORY_") + "/" + reply.GetCode()
		text := logs.String()
		if key != "RESOURCE/overloaded" || reply.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN ||
			reply.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME || strings.Count(text, "\n") != 1 ||
			!strings.Contains(text, `"msg":"the feature gate could not decide"`) || !strings.Contains(text, `"reason":"`+reason+`"`) ||
			!strings.Contains(text, "4bf92f35-77b3-4da6-a3ce-929d0e0e4736") || !strings.Contains(text, call.Policy.FullName) ||
			!strings.Contains(text, cause.Error()) || strings.Contains(text, "identity call failed") {
			t.Errorf("%s: %s %s, logged %s", reason, key, reply.GetEffect(), text)
		}
	}
}
