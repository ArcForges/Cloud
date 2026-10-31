// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

// The composition of the configuration into the gate, the authorizer and the operator grant (config-4): each wire is removed by a
// mutant and one of these tests fails (EVIDENCE: REAL composition of the center, REAL PostgreSQL, REAL entitlement service and
// gate; MOCKED: the production-classified catalogue is injected by the test, the step-up evidence is stubbed).

// productionCatalogue is a catalogue of the production classification: no fixture marker, no notice, no price (a test document).
const productionCatalogue = `{"version":"2026-q4","fixture":false,"capabilities":["center.nodes","center.execute","remote.view","remote.control","center.mcp","push"],
"plans":[{"id":"plan-test","name":"Plan under test","features":["remote.view","push"]}]}`

// hostedCenter composes the official hosted center over a real database. The official hosted configuration requires a verified TLS
// connection to its database, which the test server does not offer: the configuration is loaded as a self-hosted one and then made
// the hosted center's, so everything the hosted mode changes in the composition is under test.
func hostedCenter(t *testing.T, plan config.PlanConfiguration, surfaces []config.Surface, options Options) (*Center, *dbtest.Database) {
	t.Helper()
	db := dbtest.New(t)
	values := map[string]string{
		config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: "https://center.example.test/api", config.EnvDatabaseURL: db.RuntimeURL,
		config.EnvNeonHello: "enabled", config.EnvSurfaces: "identity,pages", config.EnvClientIPHeader: config.ClientIPHeader, config.EnvTrustedProxies: "127.0.0.0/8,::1/128",
	}
	cfg, err := config.Load(func(key string) (string, bool) { value, found := values[key]; return value, found })
	if err != nil {
		t.Fatal(err)
	}
	cfg.Mode, cfg.Plan, cfg.Identity.Surfaces = config.OfficialHosted, plan, surfaces
	center, err := New(cfg, observe.NewLogger(io.Discard, slog.LevelInfo), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(center.Close)
	return center, db
}

var withOperations = []config.Surface{config.SurfaceIdentity, config.SurfacePages, config.SurfaceOperations}

func TestSelfHostedDisabledFeaturesReachTheGate(t *testing.T) {
	cfg := testConfig(config.SelfHosted)
	cfg.DisabledFeatures = []string{"center.mcp", "remote.control"}
	center, err := New(cfg, observe.NewLogger(io.Discard, slog.LevelInfo), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer center.Close()
	for _, key := range feature.Gated() {
		want := feature.ReasonSelfHostedDefault
		if key == feature.CenterMCP || key == feature.RemoteControl {
			want = feature.ReasonOperatorLimit
		}
		if key == feature.Push {
			want = feature.ReasonPushSenderNotConfigured
		}
		if decision := center.Features.Availability(t.Context(), key); decision.Reason != want || decision.Available != (want == feature.ReasonSelfHostedDefault) {
			t.Errorf("%s: %+v, want %s", key, decision, want)
		}
	}
}

func TestAHostedCenterDecidesFromTheStoredEntitlementThroughTheGateAndTheAuthorizer(t *testing.T) {
	center, db := hostedCenter(t, config.PlanDevelopmentFixtures, withOperations, Options{})
	if center.Authorizer == nil || center.Authorizer.Gate() == nil {
		t.Fatal("the identity surface's authorizer is composed without the feature gate")
	}
	account, operator := db.Account(1), db.Account(1)
	db.Exec("INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '" + operator.String() +
		"', now() - interval '1 day', now() + interval '30 days', 'operator:cli', 'test operator')")
	ctx := feature.WithAccount(t.Context(), account.String())
	for name, gate := range map[string]feature.Gate{"the center's gate": center.Features, "the authorizer's gate": center.Authorizer.Gate()} {
		// An account without a grant is not entitled; the store answered (a gate without an entitlement reader would say the store is unavailable).
		if decision := gate.Availability(ctx, feature.RemoteView); decision.Available || decision.Reason != feature.ReasonNoEntitlement || decision.Err != nil {
			t.Fatalf("%s, no grant: %+v", name, decision)
		}
	}
	op := center.operator(nil)
	if op == nil {
		t.Fatal("the hosted center with the operations surface has no operator grant")
	}
	if _, err := op.Grant(t.Context(), entitlement.GrantCall{Caller: entitlement.OperatorCaller{UserID: operator, Scope: "account"}, CommandID: platform.NewID(),
		Request: entitlement.OperatorRequest{Account: account.String(), Features: []string{"remote.view"}, Reason: "goodwill", SourceRef: "ticket-1",
			ExpiresAt: entitlement.FromTime(time.Now().Add(10 * 24 * time.Hour))},
		Consume: func(context.Context, pgx.Tx, [32]byte, time.Time) error { return nil }}); err != nil {
		t.Fatal(err)
	}
	for name, gate := range map[string]feature.Gate{"the center's gate": center.Features, "the authorizer's gate": center.Authorizer.Gate()} {
		if decision := gate.Availability(ctx, feature.RemoteView); !decision.Available || decision.Reason != feature.ReasonEntitled {
			t.Errorf("%s, granted: %+v", name, decision)
		}
		if decision := gate.Availability(ctx, feature.RemoteControl); decision.Available || decision.Reason != feature.ReasonNoEntitlement {
			t.Errorf("%s, a key that was not granted: %+v", name, decision)
		}
	}
}

// TestTheOperatorGrantIsComposedWithThePolicyOfThePlanConfiguration: the operator the center builds uses the policy of its plan
// configuration. Where there is no valid catalogue it refuses (no_catalogue) and writes no grant, no term and no audit of an issue;
// with a production-classified catalogue (injected) it bounds a grant to 90 days and refuses a catalogue-wide one; with the
// development fixtures it admits both.
func TestTheOperatorGrantIsComposedWithThePolicyOfThePlanConfiguration(t *testing.T) {
	cases := []struct {
		name    string
		plan    config.PlanConfiguration
		options Options
		days    int
		all     bool
		// refused is the refusal's code and reason, or empty when the grant is made.
		code, reason string
	}{
		{"no plan configuration", config.PlanNone, Options{}, 30, false, "invalid_state", "no_catalogue"},
		{"an invalid catalogue", config.PlanNone, Options{catalogue: []byte("{"), catalogueClass: feature.ClassProduction}, 30, false, "invalid_state", "no_catalogue"},
		{"a production-classified catalogue, 91 days", config.PlanNone, Options{catalogue: []byte(productionCatalogue), catalogueClass: feature.ClassProduction}, 91, false, "invalid_argument", "expires_at: too_far"},
		{"a production-classified catalogue, catalogue-wide", config.PlanNone, Options{catalogue: []byte(productionCatalogue), catalogueClass: feature.ClassProduction}, 30, true, "invalid_state", "catalogue_wide"},
		{"a production-classified catalogue, 89 days", config.PlanNone, Options{catalogue: []byte(productionCatalogue), catalogueClass: feature.ClassProduction}, 89, false, "", ""},
		{"the development fixtures, 91 days", config.PlanDevelopmentFixtures, Options{}, 91, false, "", ""},
		{"the development fixtures, catalogue-wide", config.PlanDevelopmentFixtures, Options{}, 30, true, "", ""},
		{"the development fixtures, 401 days", config.PlanDevelopmentFixtures, Options{}, 401, false, "invalid_argument", "expires_at: too_far"},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			center, db := hostedCenter(t, item.plan, withOperations, item.options)
			operator, account := db.Account(1), db.Account(1)
			db.Exec("INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES (gen_random_uuid(), '" + operator.String() +
				"', now() - interval '1 day', now() + interval '30 days', 'operator:cli', 'test operator')")
			request := entitlement.OperatorRequest{Account: account.String(), Features: []string{"remote.view"}, All: item.all, Reason: "goodwill", SourceRef: "ticket-1",
				ExpiresAt: entitlement.FromTime(time.Now().Add(time.Duration(item.days)*24*time.Hour - time.Hour))}
			if item.all {
				request.Features = nil
			}
			_, err := center.operator(nil).Grant(t.Context(), entitlement.GrantCall{Caller: entitlement.OperatorCaller{UserID: operator, Scope: "account"}, CommandID: platform.NewID(),
				Request: request, Consume: func(context.Context, pgx.Tx, [32]byte, time.Time) error { return nil }})
			grants := db.Count("SELECT count(*) FROM entitlement.grant")
			terms := db.Count("SELECT count(*) FROM entitlement.service_term")
			issued := db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", entitlement.AuditOperatorGrantIssued)
			if item.code == "" {
				if err != nil || grants == 0 || terms != 1 || issued != 1 {
					t.Fatalf("a grant that the policy admits: %v, %d grants, %d terms, %d issued", err, grants, terms, issued)
				}
				return
			}
			var refusal *arc.Refusal
			if !errors.As(err, &refusal) || refusal.Code != item.code || refusal.Reason != item.reason {
				t.Fatalf("%v, want %s %s", err, item.code, item.reason)
			}
			if grants != 0 || terms != 0 || issued != 0 {
				t.Errorf("a refused grant left %d grants, %d terms, %d issued events", grants, terms, issued)
			}
			if got := db.Count("SELECT count(*) FROM audit.audit_event WHERE event_type = $1", entitlement.AuditOperatorGrantRefused); got != 1 {
				t.Errorf("%d refusals audited", got)
			}
		})
	}
}

// TestTheOperatorGrantExistsOnlyWhereTheOperationsSurfaceIsOn: the center builds no operator without the surface, and none in
// self-hosted mode (where the surface cannot be on).
func TestTheOperatorGrantExistsOnlyWhereTheOperationsSurfaceIsOn(t *testing.T) {
	without, _ := hostedCenter(t, config.PlanDevelopmentFixtures, []config.Surface{config.SurfaceIdentity, config.SurfacePages}, Options{})
	if without.operator(nil) != nil {
		t.Error("an operator grant without the operations surface")
	}
	with, _ := hostedCenter(t, config.PlanDevelopmentFixtures, withOperations, Options{})
	if with.operator(nil) == nil {
		t.Error("no operator grant with the operations surface")
	}
	self, err := New(testConfig(config.SelfHosted), observe.NewLogger(io.Discard, slog.LevelInfo), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	if self.operator(nil) != nil || self.Authorizer != nil {
		t.Error("a self-hosted center without a database has an operator grant or an authorizer")
	}
}

// TestThePlanConfigurationIsLoggedWithoutTheDocument is config-5: an invalid catalogue is one ERROR line whose problem names a rule
// and holds no byte of the document; a hosted center without a plan configuration says so; a self-hosted center logs nothing; and a
// valid catalogue logs nothing.
func TestThePlanConfigurationIsLoggedWithoutTheDocument(t *testing.T) {
	const secret = "SECRET-DOCUMENT-MARKER"
	logged := func(mode config.Mode, plan config.PlanConfiguration, options Options) []string {
		t.Helper()
		var logs bytes.Buffer
		cfg := testConfig(mode)
		cfg.Plan = plan
		logger := observe.NewLogger(&logs, slog.LevelDebug)
		center, err := New(cfg, logger, options)
		if err != nil {
			t.Fatal(err)
		}
		defer center.Close()
		center.logPlanConfiguration(logger)
		var lines []string
		for line := range strings.SplitSeq(strings.TrimSpace(logs.String()), "\n") {
			if line != "" {
				lines = append(lines, line)
			}
		}
		return lines
	}
	lines := logged(config.OfficialHosted, config.PlanNone, Options{catalogue: []byte(`{"version":"` + secret + `","` + secret + `":1}`), catalogueClass: feature.ClassProduction})
	if len(lines) != 1 || !strings.Contains(lines[0], `"level":"ERROR"`) || !strings.Contains(lines[0], "the plan catalogue is invalid") || !strings.Contains(lines[0], "invalid plan catalogue: ") || strings.Contains(lines[0], secret) {
		t.Errorf("an invalid catalogue: %q", lines)
	}
	if lines = logged(config.OfficialHosted, config.PlanNone, Options{}); len(lines) != 1 || !strings.Contains(lines[0], `"level":"INFO"`) || !strings.Contains(lines[0], "no plan configuration") {
		t.Errorf("no plan configuration: %q", lines)
	}
	if lines = logged(config.SelfHosted, config.PlanNone, Options{}); len(lines) != 0 {
		t.Errorf("a self-hosted center: %q", lines)
	}
	if lines = logged(config.OfficialHosted, config.PlanDevelopmentFixtures, Options{}); len(lines) != 0 {
		t.Errorf("a valid catalogue: %q", lines)
	}
}

// TestTheIdentityCompositionIsCheckedAgainstTheOperationTable: a session method served anonymously, which only the operation table's
// check can see (the names and the count still agree), stops the composition (C19).
func TestTheIdentityCompositionIsCheckedAgainstTheOperationTable(t *testing.T) {
	modules, err := routes.Center()
	if err != nil {
		t.Fatal(err)
	}
	if err = checkIdentityComposition(modules); err != nil {
		t.Fatal(err)
	}
	changed := make([]routes.Module, len(modules))
	copy(changed, modules)
	flipped := false
	for index, module := range changed {
		if module.Surface != routes.SurfaceIdentity || flipped {
			continue
		}
		policies := append([]ingress.Policy(nil), module.Policies...)
		for position, policy := range policies {
			if policy.Authentication != ingress.Session {
				continue
			}
			anonymous, err := ingress.NewUnary(policy.FullName, ingress.Anonymous, ingress.NoScope, policy.MaxRequestBytes, true)
			if err != nil {
				t.Fatal(err)
			}
			policies[position], flipped = anonymous, true
			break
		}
		changed[index].Policies = policies
	}
	if !flipped {
		t.Fatal("no session method to serve anonymously")
	}
	if checkIdentityComposition(changed) == nil {
		t.Fatal("a session method served anonymously was admitted")
	}
}

// callsOf lists the names a function of server.go calls (a function or a method).
func callsOf(t *testing.T, function string) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	found := false
	for _, declaration := range file.Decls {
		if declared, ok := declaration.(*ast.FuncDecl); !ok || declared.Name.Name != function {
			continue
		} else {
			found = true
			ast.Inspect(declared, func(node ast.Node) bool {
				if call, isCall := node.(*ast.CallExpr); isCall {
					switch callee := call.Fun.(type) {
					case *ast.Ident:
						names[callee.Name] = true
					case *ast.SelectorExpr:
						names[callee.Sel.Name] = true
					}
				}
				return true
			})
		}
	}
	if !found {
		t.Fatalf("server.go has no function %s", function)
	}
	return names
}

// TestTheCompositionCallsWhatItMustCall: the start composes the checks and the logging of the plan configuration (the functions are
// tested on their own; this pins that the start calls them).
func TestTheCompositionCallsWhatItMustCall(t *testing.T) {
	for function, callee := range map[string]string{"New": "checkIdentityComposition", "checkIdentityComposition": "Check", "Run": "logPlanConfiguration", "composePages": "operator"} {
		if !callsOf(t, function)[callee] {
			t.Errorf("%s does not call %s", function, callee)
		}
	}
}
