// SPDX-License-Identifier: AGPL-3.0-only

package pages_test

import (
	"context"
	"errors"
	"testing"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/mobiletest"
)

// TestMobileProbesScenariosPassAgainstTheCenter runs MobileProbe's own scenario logic (mobiletest.RunScenario, what
// center/cmd/mobile-probe runs on proof for H3) against the real center and PostgreSQL: approve, deny, reuse and wrong-verifier, each
// with the probe's expectations of every reply. Only the person is a seam: instead of the handshake files and a browser, the
// harness's browser reviews and decides the flow on the center's pages (the step-up proved with the virtual authenticator) and hands
// the done page's link back; the refresh goes through the API's RefreshSession, its refusal in mobiletest.RefusalOf's form, as the
// probe's gRPC-Web call reads it. A probe expectation in another spelling than the center's replies (the H3 reuse defect: a JSON
// refusal compared as CONFLICT/code_reused) fails here.
func TestMobileProbesScenariosPassAgainstTheCenter(t *testing.T) {
	h := mobileHarness(t, nil)
	who := h.seedAccount(1)
	b := h.newBrowser()
	b.mustSignIn(who)
	wantDevices := map[string]int{mobiletest.ScenarioApprove: 1, mobiletest.ScenarioDeny: 0, mobiletest.ScenarioReuse: 1,
		mobiletest.ScenarioWrongVerifier: 0}
	for _, scenario := range mobiletest.Scenarios {
		t.Run(scenario, func(t *testing.T) {
			app := h.app()
			var failed []string
			hooks := mobiletest.Hooks{
				Link: func(_ context.Context, attempt mobiletest.Attempt, decision string) (string, error) {
					link, done := b.decide(who, attempt, decision == "approve")
					if link == "" {
						return "", errors.New("the done page has no link: " + done.text())
					}
					return link, nil
				},
				Refresh: func(_ context.Context, token string) (string, error) {
					reply := h.api("/arcforges.publicapi.v1.IdentityService/RefreshSession", &publicapiv1.IdentityServiceRefreshSessionRequest{
						Meta: &foundationv1.RequestMeta{}, RefreshToken: proto.String(token), InstallationId: &foundationv1.Id{Value: app.InstallationID[:]}}, "")
					if reply.status != "0" || reply.body == nil {
						return "", errors.New("refresh: " + reply.status + " " + reply.message)
					}
					var response publicapiv1.IdentityServiceRefreshSessionResponse
					if err := proto.Unmarshal(reply.body, &response); err != nil {
						return "", err
					}
					if failure := response.GetError(); failure != nil {
						return mobiletest.RefusalOf(failure), nil
					}
					h.remember(response.GetValue().GetSession().GetAccessToken(), response.GetValue().GetSession().GetRefreshToken())
					return "", nil
				},
				Record: func(name string, ok bool, outcome string) bool {
					if !ok {
						failed = append(failed, name+": "+outcome)
					}
					return ok
				},
			}
			passed, devices := app.RunScenario(context.Background(), scenario, hooks)
			if !passed || len(failed) > 0 {
				t.Fatalf("the probe's %s scenario failed: %v", scenario, failed)
			}
			if len(devices) != wantDevices[scenario] {
				t.Fatalf("the %s scenario named %d devices", scenario, len(devices))
			}
		})
	}
	// An unknown scenario fails before any request.
	if passed, _ := h.app().RunScenario(context.Background(), "token", mobiletest.Hooks{Record: func(string, bool, string) bool { return false }}); passed {
		t.Fatal("an unknown scenario passed")
	}
}
