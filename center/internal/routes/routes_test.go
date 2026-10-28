// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"errors"
	"testing"

	"github.com/ArcForges/Cloud/center/internal/ingress"
)

func TestTheCenterServesExactlyTheAnonymousHelloAndTheHealthRoute(t *testing.T) {
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
	routes, err := Ingress(modules)
	if err != nil {
		t.Fatal(err)
	}
	if policy, ok := routes.Registry.Lookup(HelloMethod); !ok || policy.Authentication != ingress.Anonymous || policy.ReadsRequestMeta() {
		t.Fatal("the ingress registry differs from the table")
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
