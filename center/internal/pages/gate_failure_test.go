// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// gateFailureCauses are the causes a gate cannot decide on, one per closed reason of access.gate_failure.
var gateFailureCauses = map[string]error{
	access.GateFailureCommitUnknown:         &store.Error{Operation: "store the entitlement snapshot", Kind: store.ErrCommitUnknown},
	access.GateFailureRefreshContended:      &entitlement.Refusal{Kind: entitlement.RefusedConcurrentUpdate, Detail: "concurrent"},
	access.GateFailureNoEntitlementStore:    feature.ErrNoEntitlementStore,
	access.GateFailureDefinitionsSuperseded: entitlement.ErrDefinitionsSuperseded,
}

// TestAGateFailureIsLoggedOnThePagesFailurePath is E0-3 (gate-3) on the pages' failure path (exchange.fail, which answers an
// Authorize that refused): the page answers the busy service's 503 and the cause is logged once with the route, the exchange's
// correlation ID and the closed reason.
func TestAGateFailureIsLoggedOnThePagesFailurePath(t *testing.T) {
	views, err := loadViews("/api")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	handler := &Handler{options: Options{Clock: time.Now, Logger: slog.New(slog.NewJSONHandler(&logs, nil))}, views: views}
	for reason, cause := range gateFailureCauses {
		logs.Reset()
		failure, ok := access.NewGateFailure(cause)
		if !ok {
			t.Fatalf("%s: no gate failure", reason)
		}
		recorder := httptest.NewRecorder()
		e := &exchange{h: handler, w: recorder, r: httptest.NewRequest(http.MethodPost, "/x", nil), route: routes.PageRoute{Surface: routes.SurfacePages, ID: "pages.probe"},
			correlation: correlation.Context{CorrelationID: "4bf92f35-77b3-4da6-a3ce-929d0e0e4736"}}
		e.fail(failure)
		text := logs.String()
		if recorder.Code != http.StatusServiceUnavailable || strings.Count(text, "\n") != 1 ||
			!strings.Contains(text, `"msg":"the feature gate could not decide"`) || !strings.Contains(text, `"reason":"`+reason+`"`) ||
			!strings.Contains(text, "4bf92f35-77b3-4da6-a3ce-929d0e0e4736") || !strings.Contains(text, "pages.probe") || !strings.Contains(text, cause.Error()) {
			t.Errorf("%s: %d, logged %s", reason, recorder.Code, text)
		}
	}
}
