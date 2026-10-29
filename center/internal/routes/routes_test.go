// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/ingress"
)

func TestTheCenterServesHelloTheHealthRouteAndTheIdentitySurface(t *testing.T) {
	modules, err := Center()
	if err != nil {
		t.Fatal(err)
	}
	table, err := Table(modules)
	if err != nil {
		t.Fatal(err)
	}
	if len(table.Production) != 1 {
		t.Fatalf("production: %+v", table.Production)
	}
	hello := table.Production[0]
	if hello != (Row{
		Path: "/arcforges.hello.v1.HelloService/SayHello", Kind: "unary", Auth: "anonymous", MaxRequestBytes: 4096,
		MaxFrameBytes: 8192, MaxUnaryResponseBytes: 8192, MaxDurationMilliseconds: 10_000, Instance: "hello",
	}) {
		t.Fatalf("hello: %+v", hello)
	}
	if table.HelloPath != "/api/arcforges.hello.v1.HelloService/SayHello" || table.HealthPath != "/api/healthz" ||
		table.Health != (Row{Path: "/healthz", Kind: "unary", Auth: "anonymous", MaxUnaryResponseBytes: 8192, MaxDurationMilliseconds: 15_000, Instance: "hello"}) ||
		table.MaxBodyBytes != 4096 || table.ColdStartMilliseconds != 15_000 || table.StreamLifetimeMilliseconds != 310_000 {
		t.Fatalf("table: %+v", table)
	}
	// The identity surface is exactly the methods A1a serves (F13 pins the same set against the service descriptors), each
	// reading a RequestMeta, served by the one center instance and switched by the surface.
	served := []string{
		"/arcforges.publicapi.v1.IdentityService/BeginAuthentication anonymous 4096",
		"/arcforges.publicapi.v1.IdentityService/CompleteAuthentication anonymous 16384",
		"/arcforges.publicapi.v1.IdentityService/RequestEmailCode anonymous 4096",
		"/arcforges.publicapi.v1.IdentityService/RedeemEmailCode anonymous 4096",
		"/arcforges.publicapi.v1.IdentityService/CompleteEnrollment anonymous 16384",
		"/arcforges.publicapi.v1.IdentityService/ListAuthProviders anonymous 4096",
		"/arcforges.publicapi.v1.IdentityService/RefreshSession anonymous 4096",
		"/arcforges.publicapi.v1.IdentityService/GetProfile session 4096",
		"/arcforges.publicapi.v1.IdentityService/ListAuthIdentities session 4096",
		"/arcforges.publicapi.v1.IdentityService/ListSessions session 4096",
		"/arcforges.publicapi.v1.DeviceService/List session 4096",
	}
	if len(table.Surfaces) != 1 || table.Surfaces[0] != SurfaceIdentity || len(table.SurfaceRows) != len(served) {
		t.Fatalf("surfaces: %v, %d rows", table.Surfaces, len(table.SurfaceRows))
	}
	for index, row := range table.SurfaceRows {
		if got := fmt.Sprintf("%s %s %d", row.Path, row.Auth, row.MaxRequestBytes); got != served[index] || row.Surface != SurfaceIdentity ||
			!row.RequestMeta || row.Instance != HealthInstance || row.Kind != "unary" || row.MaxFrameBytes != 65_536 ||
			row.MaxUnaryResponseBytes != 65_536 || row.MaxDurationMilliseconds != 15_000 {
			t.Fatalf("surface row %d: %+v", index, row)
		}
	}
	routes, err := Ingress(modules)
	if err != nil {
		t.Fatal(err)
	}
	if policy, ok := routes.Registry.Lookup(HelloMethod); !ok || policy.Authentication != ingress.Anonymous || policy.ReadsRequestMeta() ||
		policy.Surface != "" {
		t.Fatal("the ingress registry differs from the table")
	}
	for _, row := range table.SurfaceRows {
		policy, ok := routes.Registry.Lookup(row.Path)
		if !ok || policy.Surface != SurfaceIdentity || !policy.ReadsRequestMeta() || policy.MaxRequestBytes != row.MaxRequestBytes {
			t.Fatalf("the ingress registry differs from the surface row %s", row.Path)
		}
	}
	if !routes.IsPlain(HealthPath) || routes.IsPlain("/readyz") {
		t.Fatal("plain routes")
	}
}

func TestInconsistentRegistrationsStopTheGenerator(t *testing.T) {
	session, err := ingress.NewUnary("/arcforges.test.v1.Probe/Ping", ingress.Session, ingress.NoScope, 4096, true)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func([]Module) []Module{
		"a method without a budget": func(modules []Module) []Module {
			modules[0].Policies = append(modules[0].Policies, session)
			return modules
		},
		"a budget without a method": func(modules []Module) []Module {
			modules[0].Budgets["/arcforges.test.v1.Probe/Ping"] = Budget{1, 1, 1, "hello"}
			return modules
		},
		"a second plain path": func(modules []Module) []Module {
			modules[0].PlainPaths = append(modules[0].PlainPaths, "/readyz")
			return modules
		},
		"no health path": func(modules []Module) []Module {
			modules[0].PlainPaths = nil
			return modules
		},
		"no Hello": func(modules []Module) []Module {
			modules[0].Policies = []ingress.Policy{session}
			modules[0].Budgets = map[string]Budget{session.FullName: {1, 1, 1, "hello"}}
			return modules
		},
		"a Hello bound other than the body bound": func(modules []Module) []Module {
			modules[0].Policies[0].MaxRequestBytes = 4095
			return modules
		},
		"a budget out of range": func(modules []Module) []Module {
			modules[0].Budgets[HelloMethod] = Budget{MaxFrameBytes: 0, MaxUnaryResponseBytes: 1, MaxDurationMilliseconds: 1, Instance: "hello"}
			return modules
		},
		"a surface policy outside its module's surface": func(modules []Module) []Module {
			modules[1].Policies[0].Surface = ""
			return modules
		},
		"a surface method on another instance": func(modules []Module) []Module {
			budget := modules[1].Budgets[modules[1].Policies[0].FullName]
			budget.Instance = "other"
			modules[1].Budgets[modules[1].Policies[0].FullName] = budget
			return modules
		},
		"a surface method without a RequestMeta": func(modules []Module) []Module {
			path := modules[1].Policies[0].FullName
			policy, err := ingress.NewUnary(path, ingress.Anonymous, ingress.NoScope, 4096, false)
			if err != nil {
				t.Fatal(err)
			}
			modules[1].Policies[0] = policy.InSurface(SurfaceIdentity)
			return modules
		},
		"a surface name out of pattern": func(modules []Module) []Module {
			modules[1].Surface = "Identity"
			for index := range modules[1].Policies {
				modules[1].Policies[index] = modules[1].Policies[index].InSurface("Identity")
			}
			return modules
		},
		"a surface module with a plain path": func(modules []Module) []Module {
			modules[1].PlainPaths = []string{"/readyz"}
			return modules
		},
		"a duplicate module": func(modules []Module) []Module { return append(modules, modules[0]) },
		"no module":          func([]Module) []Module { return nil },
	}
	for name, mutate := range mutations {
		modules, err := Center()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Table(mutate(modules)); !errors.Is(err, ErrRegistration) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// TestTheCenterSendsEveryReplyItsBudgetsAdmit (F8): the Connect writer's bound is the largest reply budget of the registrations, so
// it admits every method's budget (a full DeviceService.List page among them), not only the largest request.
func TestTheCenterSendsEveryReplyItsBudgetsAdmit(t *testing.T) {
	modules, err := Center()
	if err != nil {
		t.Fatal(err)
	}
	largest := MaxResponseBytes(modules)
	for _, module := range modules {
		for path, budget := range module.Budgets {
			if budget.MaxUnaryResponseBytes > largest || budget.MaxFrameBytes > largest {
				t.Errorf("%s: a budget of %d/%d bytes over the send bound %d", path, budget.MaxUnaryResponseBytes, budget.MaxFrameBytes, largest)
			}
		}
	}
	if largest != 65_536 || largest <= MaxRequestBytes(modules) {
		t.Fatalf("send bound %d, request bound %d", largest, MaxRequestBytes(modules))
	}
}
