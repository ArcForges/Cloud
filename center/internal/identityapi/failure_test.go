// SPDX-License-Identifier: AGPL-3.0-only

package identityapi

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"

	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// TestEveryStoreFailureHasItsEffectAndAdvice pins the reply of each store failure (F6): a write whose COMMIT went unanswered may have
// happened, so it is INTERNAL with effect UNKNOWN and never retried as it was; a store that is down or contended before the commit
// did nothing and may be retried after a while; any other failure is INTERNAL, retried once after a while.
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
	}{
		"an unanswered commit": {&store.Error{Operation: "refresh a session", Kind: store.ErrCommitUnknown}, "INTERNAL/internal",
			foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN, foundationv1.RetryMode_RETRY_MODE_NEVER, true},
		"an unavailable store": {&store.Error{Operation: "refresh a session", Kind: store.ErrUnavailable}, "RESOURCE/overloaded",
			foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN, foundationv1.RetryMode_RETRY_MODE_AFTER_TIME, false},
		"contention": {&store.Error{Operation: "refresh a session", Kind: store.ErrContention}, "RESOURCE/overloaded",
			foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN, foundationv1.RetryMode_RETRY_MODE_AFTER_TIME, false},
		"a missing privilege": {&store.Error{Operation: "refresh a session", Kind: store.ErrPermission}, "INTERNAL/internal",
			foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN, foundationv1.RetryMode_RETRY_MODE_AFTER_TIME, true},
	} {
		logs.Reset()
		reply := server.failure(context.Background(), call, item.err)
		key := strings.TrimPrefix(reply.GetCategory().String(), "ERROR_CATEGORY_") + "/" + reply.GetCode()
		if key != item.key || reply.GetEffect() != item.effect || reply.GetRetry().GetMode() != item.retry ||
			strings.Contains(logs.String(), "identity call failed") != item.logged || reply.GetCorrelationId() == nil {
			t.Errorf("%s: %s %s %s logged=%v", name, key, reply.GetEffect(), reply.GetRetry().GetMode(), logs.Len() > 0)
		}
	}
}
