// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/quota"
)

// The composition pins of the first gated operation's prerequisites (AF-CTR-05 part E0; EVIDENCE: REAL composition of the center,
// REAL PostgreSQL, REAL entitlement service, gate and operator; MOCKED: the step-up evidence of the operator grant is stubbed).

// selfHostedCenter composes a self-hosted center over a real database with the identity and pages surfaces and the disabled keys.
func selfHostedCenter(t *testing.T, disabled ...string) (*Center, *dbtest.Database) {
	t.Helper()
	db := dbtest.New(t)
	values := map[string]string{
		config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: "https://center.example.test/api", config.EnvDatabaseURL: db.RuntimeURL,
		config.EnvNeonHello: "enabled", config.EnvSurfaces: "identity,pages", config.EnvClientIPHeader: config.ClientIPHeader, config.EnvTrustedProxies: "127.0.0.0/8,::1/128",
	}
	if len(disabled) > 0 {
		values[config.EnvDisabledFeatures] = strings.Join(disabled, ",")
	}
	cfg, err := config.Load(func(key string) (string, bool) { value, found := values[key]; return value, found })
	if err != nil {
		t.Fatal(err)
	}
	center, err := New(cfg, observe.NewLogger(io.Discard, slog.LevelInfo), Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	return center, db
}

// TestSelfHostedComposedOverADatabaseHonoursDisabledKeys is E0-4 (gate-2, the first pin): a self-hosted center composed over a real
// database has an authorizer, and the disabled-key table runs through that authorizer's gate (not a gate built apart from the
// center's): each disabled key answers operator_limit, push without a sender push_sender_not_configured, every other key the
// self-hosted default; the center's own gate answers the same.
func TestSelfHostedComposedOverADatabaseHonoursDisabledKeys(t *testing.T) {
	for _, disabled := range [][]string{nil, {"center.mcp"}, {"center.nodes", "remote.control"}, {"center.execute", "remote.view", "push"}} {
		t.Run(strings.Join(disabled, ",")+"|", func(t *testing.T) {
			center, db := selfHostedCenter(t, disabled...)
			if center.Authorizer == nil || center.Authorizer.Gate() == nil {
				t.Fatal("the self-hosted center over a database has no authorizer with a gate")
			}
			ctx := feature.WithAccount(t.Context(), db.Account(1).String())
			for _, key := range feature.Gated() {
				want := feature.ReasonSelfHostedDefault
				switch {
				case strings.Contains(","+strings.Join(disabled, ",")+",", ","+string(key)+","):
					want = feature.ReasonOperatorLimit
				case key == feature.Push:
					want = feature.ReasonPushSenderNotConfigured
				}
				for name, gate := range map[string]feature.Gate{"the authorizer's gate": center.Authorizer.Gate(), "the center's gate": center.Features} {
					if decision := gate.Availability(ctx, key); decision.Reason != want || decision.Available != (want == feature.ReasonSelfHostedDefault) || decision.Err != nil {
						t.Errorf("%s, %s: %+v, want %s", name, key, decision, want)
					}
				}
			}
		})
	}
}

// TestTheComposedHostedCenterServesTheOperationsPage is E0-4 (gate-2, the second pin): /operations/grant requested from the composed
// hosted center reaches the pages with the center's operator grant (a GET without a session goes to the sign-in page, which only a
// composed operator does; a nil operator answers 404), and the hosted center without the surface answers 404.
func TestTheComposedHostedCenterServesTheOperationsPage(t *testing.T) {
	status := func(center *Center) (int, string) {
		t.Helper()
		listener := httptest.NewServer(center.Public())
		t.Cleanup(listener.Close)
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, listener.URL+"/operations/grant", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Add(config.ClientIPHeader, "203.0.113.7")
		client := &http.Client{Transport: &http.Transport{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = response.Body.Close() }()
		return response.StatusCode, response.Header.Get("Location")
	}
	with, _ := hostedCenter(t, config.PlanDevelopmentFixtures, withOperations, Options{})
	if code, location := status(with); code != http.StatusSeeOther || !strings.Contains(location, "/account/sign-in") {
		t.Fatalf("the composed hosted center with the operations surface: %d %q", code, location)
	}
	without, _ := hostedCenter(t, config.PlanDevelopmentFixtures, []config.Surface{config.SurfaceIdentity, config.SurfacePages}, Options{})
	if code, _ := status(without); code != http.StatusNotFound {
		t.Fatalf("the composed hosted center without the surface: %d", code)
	}
}

// TestOperatorAndGateShareTheDefinitionsVersion is E0-4 (gate-2, the third pin): the operator the center builds computes under the
// definitions the gate reads, so a grant's snapshot is the one the gate then reads as it is: the gate's read neither re-activates
// the definitions nor raises the snapshot version.
func TestOperatorAndGateShareTheDefinitionsVersion(t *testing.T) {
	center, db := hostedCenter(t, config.PlanDevelopmentFixtures, withOperations, Options{})
	op := center.operator(nil)
	want := center.FeatureConfiguration.Definitions().Version
	if op == nil || op.DefinitionsVersion() != want || center.Entitlements.DefinitionsVersion() != want {
		t.Fatalf("the operator computes under %q, the gate's service under %q, the configuration is %q", op.DefinitionsVersion(), center.Entitlements.DefinitionsVersion(), want)
	}
	operator, account := db.Account(1), db.Account(1)
	db.Exec("INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '" + operator.String() +
		"', now() - interval '1 day', now() + interval '30 days', 'operator:cli', 'test operator')")
	result, err := op.Grant(t.Context(), entitlement.GrantCall{Caller: entitlement.OperatorCaller{UserID: operator, Scope: "account"}, CommandID: platform.NewID(),
		Request: entitlement.OperatorRequest{Account: account.String(), Features: []string{"remote.view"}, Reason: "goodwill", SourceRef: "ticket-1",
			ExpiresAt: entitlement.FromTime(time.Now().Add(10 * 24 * time.Hour))},
		Consume: func(context.Context, pgx.Tx, [32]byte, time.Time) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	stored := func() (int64, string, int) {
		t.Helper()
		var version int64
		var definitions string
		if err := db.Migration.QueryRow(t.Context(), "SELECT entitlement_version, definitions_version FROM entitlement.snapshot WHERE account_id = $1", account).Scan(&version, &definitions); err != nil {
			t.Fatal(err)
		}
		return version, definitions, db.Count("SELECT count(*) FROM entitlement.definitions_activation WHERE account_id = $1", account)
	}
	version, definitions, activations := stored()
	if version != result.Version || definitions != want || activations != 1 {
		t.Fatalf("the grant's snapshot: version %d (result %d), definitions %q, %d activations", version, result.Version, definitions, activations)
	}
	if decision := center.Authorizer.Gate().Availability(feature.WithAccount(t.Context(), account.String()), feature.RemoteView); !decision.Available {
		t.Fatalf("the authorizer's gate after the grant: %+v", decision)
	}
	if after, afterDefinitions, afterActivations := stored(); after != version || afterDefinitions != definitions || afterActivations != activations {
		t.Fatalf("the gate's read changed the operator's snapshot: version %d -> %d, %q -> %q, activations %d -> %d", version, after, definitions,
			afterDefinitions, activations, afterActivations)
	}
}

// TestTheAuthorizerIsComposedWithThePerAccountControls (CTR5-GATE-05): the center's authorizer carries the three controls of package
// quota, and the composition checks the operation table against them (a gated row without a control stops the start).
func TestTheAuthorizerIsComposedWithThePerAccountControls(t *testing.T) {
	center, _ := hostedCenter(t, config.PlanDevelopmentFixtures, withOperations, Options{})
	names := map[string]bool{}
	for _, control := range center.Authorizer.Controls() {
		names[control.Name()] = true
	}
	if len(names) != 3 || !names[quota.RoutedCallsName] || !names[quota.RoutedInFlightName] || !names[quota.ChannelUpgradeName] {
		t.Fatalf("the composed controls: %v", names)
	}
	if err := access.CheckControls(access.Operations(), center.Authorizer.Controls()); err != nil {
		t.Fatal(err)
	}
	calls := callsOf(t, "composeIdentity")
	for _, callee := range []string{"WithControls", "Controls", "CheckComposition"} {
		if !calls[callee] {
			t.Errorf("composeIdentity does not call %s", callee)
		}
	}
}

// TestTheStartRecordsTheDefinitionsVersion (store-1): a center that reads entitlements (official hosted, a valid catalogue, a store)
// records its definitions version once; production (no catalogue) and a self-hosted center record nothing; Run calls the record.
func TestTheStartRecordsTheDefinitionsVersion(t *testing.T) {
	hosted, db := hostedCenter(t, config.PlanDevelopmentFixtures, withOperations, Options{})
	if !hosted.recordsDefinitions() {
		t.Fatal("the hosted center with the development fixtures does not record its definitions")
	}
	for range 2 {
		if err := hosted.recordDefinitions(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var version string
	if err := db.Migration.QueryRow(t.Context(), "SELECT definitions_version FROM entitlement.definitions_current").Scan(&version); err != nil ||
		version != hosted.FeatureConfiguration.Definitions().Version {
		t.Fatalf("the recorded fact: %q %v", version, err)
	}
	production, _ := hostedCenter(t, config.PlanNone, withOperations, Options{})
	self, _ := selfHostedCenter(t)
	if production.recordsDefinitions() || self.recordsDefinitions() {
		t.Error("a center that reads no entitlement records its definitions")
	}
	if !callsOf(t, "Run")["recordDefinitions"] || !callsOf(t, "Run")["recordsDefinitions"] {
		t.Error("Run does not record the definitions version")
	}
}
