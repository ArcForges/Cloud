// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// gateFailureCauses are the causes a gate cannot decide on, one per closed reason of access.gate_failure.
var gateFailureCauses = map[string]error{
	access.GateFailureCommitUnknown:         &store.Error{Operation: "store the entitlement snapshot", Kind: store.ErrCommitUnknown},
	access.GateFailureRefreshContended:      &entitlement.Refusal{Kind: entitlement.RefusedConcurrentUpdate, Detail: "concurrent"},
	access.GateFailureNoEntitlementStore:    feature.ErrNoEntitlementStore,
	access.GateFailureDefinitionsSuperseded: entitlement.ErrDefinitionsSuperseded,
}

// TestAGateFailureIsLoggedOnTheFleetFailurePath is E0-3 (gate-3) on the fleet handlers' failure path, which the gated fleet rows of
// AF-CTR-05 answer through: RESOURCE/overloaded, and one line with the method, the correlation ID, the closed reason and the cause.
func TestAGateFailureIsLoggedOnTheFleetFailurePath(t *testing.T) {
	var logs bytes.Buffer
	server := New(nil, nil, nil, nil, slog.New(slog.NewJSONHandler(&logs, nil)))
	call := &ingress.Call{Policy: ingress.Policy{FullName: "/arcforges.test.v1.GateProbe/CenterNodes"},
		Correlation: correlation.Context{CorrelationID: "4bf92f35-77b3-4da6-a3ce-929d0e0e4736"}}
	for reason, cause := range gateFailureCauses {
		logs.Reset()
		failure, ok := access.NewGateFailure(cause)
		if !ok {
			t.Fatalf("%s: no gate failure", reason)
		}
		reply := server.failure(context.Background(), call, failure)
		text := logs.String()
		if reply.GetCode() != "overloaded" || strings.Count(text, "\n") != 1 || !strings.Contains(text, `"msg":"the feature gate could not decide"`) ||
			!strings.Contains(text, `"reason":"`+reason+`"`) || !strings.Contains(text, "4bf92f35-77b3-4da6-a3ce-929d0e0e4736") ||
			!strings.Contains(text, cause.Error()) || strings.Contains(text, "fleet call failed") {
			t.Errorf("%s: %s, logged %s", reason, reply.GetCode(), text)
		}
	}
}
