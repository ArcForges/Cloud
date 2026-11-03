// SPDX-License-Identifier: AGPL-3.0-only

package pages

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// TestAConflictReadsAsAPasskeyOnTheAccountPagesAndAsAGrantOnTheOperationsSurface (page-4): the text of CONFLICT/already_exists is the
// passkey's everywhere but on the operations surface, whose own text replaces it there only (and so does the way back).
func TestAConflictReadsAsAPasskeyOnTheAccountPagesAndAsAGrantOnTheOperationsSurface(t *testing.T) {
	views, err := loadViews("/api")
	if err != nil {
		t.Fatal(err)
	}
	handler := &Handler{options: Options{Clock: time.Now}, views: views}
	value := arc.AlreadyExists("credential", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}).Dated(time.Now()).ArcError(correlation.New())
	cases := []struct {
		surface, want, notWant, back string
	}{
		{routes.SurfacePages, "That passkey is already registered.", "features were already granted", "Back to your account"},
		{routes.SurfaceIdentity, "That passkey is already registered.", "features were already granted", "Back to your account"},
		{routes.SurfaceOperations, "These features were already granted with that source reference.", "passkey is already registered", "Back to the grant form"},
	}
	for _, item := range cases {
		recorder := httptest.NewRecorder()
		e := &exchange{h: handler, w: recorder, r: httptest.NewRequest(http.MethodPost, "/x", nil), route: routes.PageRoute{Surface: item.surface, ID: "test"}}
		e.writeErrorPage(http.StatusConflict, value)
		body := recorder.Body.String()
		if recorder.Code != http.StatusConflict || !strings.Contains(body, item.want) || strings.Contains(body, item.notWant) || !strings.Contains(body, item.back) {
			t.Errorf("%s: %d %s", item.surface, recorder.Code, body)
		}
	}
}

// TestAnInternalFailureNeverPromisesARetry (E4-INTERNAL): INTERNAL/internal advises NEVER with effect UNKNOWN, so the page, its
// heading and the JSON body of the WebBrowserSession routes state exactly that: the JSON carries the advice and the effect, the page
// says the request may or may not have been completed and does not tell the reader to try again later (a busy store does, with its
// own advice), and a store that is down keeps its text.
func TestAnInternalFailureNeverPromisesARetry(t *testing.T) {
	views, err := loadViews("/api")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	handler := &Handler{options: Options{Clock: func() time.Time { return now }}, views: views}
	value := arc.Internal().Dated(now).ArcError(correlation.New())
	reply := errorOf(value).Error
	if reply.Retry.Mode != "never" || reply.Retry.RetryAt != "" || reply.Retry.ReconciliationOperation != "" || reply.Effect != "unknown" {
		t.Errorf("the JSON of an internal failure: %+v effect %q", reply.Retry, reply.Effect)
	}
	recorder := httptest.NewRecorder()
	e := &exchange{h: handler, w: recorder, r: httptest.NewRequest(http.MethodPost, "/x", nil), route: routes.PageRoute{Surface: routes.SurfacePages, ID: "test"}}
	e.writeErrorPage(http.StatusServiceUnavailable, value)
	body := recorder.Body.String()
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(body, "may or may not have been completed") ||
		!strings.Contains(body, "Something went wrong") || strings.Contains(body, "Try again") {
		t.Errorf("the page of an internal failure: %d %s", recorder.Code, body)
	}
	busy := httptest.NewRecorder()
	e = &exchange{h: handler, w: busy, r: httptest.NewRequest(http.MethodPost, "/x", nil), route: routes.PageRoute{Surface: routes.SurfacePages, ID: "test"}}
	e.writeErrorPage(http.StatusServiceUnavailable, arc.Unavailable().Dated(now).ArcError(correlation.New()))
	if !strings.Contains(busy.Body.String(), "Try again shortly") || !strings.Contains(busy.Body.String(), "Try again in a moment") {
		t.Errorf("the page of a busy service: %s", busy.Body.String())
	}
}
