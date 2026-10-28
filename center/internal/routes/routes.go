// SPDX-License-Identifier: AGPL-3.0-only

// Package routes holds the center's registrations: each module's public methods with their ingress policies, its plain routes
// and the transport budgets the Worker applies before it forwards a call. The center's ingress registry and the Worker's
// generated production table (worker/tables/center-tables.generated.ts) are both built from here, so the two cannot drift
// apart: a registered method without a budget, a budget that names no registered method, a missing health route or a body bound
// that differs from the Hello policy stops the generator and the center instead of producing a partial table.
package routes

import (
	"errors"
	"fmt"
	"sort"

	"github.com/ArcForges/Contracts/go/arcforges/hello/v1/hellov1connect"

	"github.com/ArcForges/Cloud/center/internal/ingress"
)

// The transport budgets of the public ingress, unchanged from the C# declarations they replace
// (src/ArcForges.Cloud/Generation/TransportBudgets.cs, which stays for the proof environment until AF-CTR-09).
const (
	// APIPrefix is the path the Worker owns in front of every method and plain route.
	APIPrefix = "/api"
	// HealthPath is the one plain route of the production table.
	HealthPath = "/healthz"
	// MaxBodyBytes bounds a whole request body, frame header included; it equals the Hello policy's bound.
	MaxBodyBytes = 4096
	// ColdStartMilliseconds is how long the Container may take to start before a stream's response headers arrive.
	ColdStartMilliseconds = 15_000
	// StreamLifetimeMilliseconds is a server stream's lifetime when the client states no shorter deadline: the annex 10 server
	// close after five minutes plus slack.
	StreamLifetimeMilliseconds = 310_000
	// HealthMaxUnaryResponseBytes bounds the health reply.
	HealthMaxUnaryResponseBytes = 8192
	// HealthMaxDurationMilliseconds caps the health route's duration.
	HealthMaxDurationMilliseconds = 15_000
	// HealthInstance is the Container instance that answers the health route.
	HealthInstance = "hello"
)

// Budget is one method's transport budget as the Worker applies it. These are declarations for the Worker; the center keeps
// its own enforcement.
type Budget struct {
	MaxFrameBytes           int
	MaxUnaryResponseBytes   int
	MaxDurationMilliseconds int
	Instance                string
}

// Module is one independently registered part of the center.
type Module struct {
	Name       string
	Policies   []ingress.Policy
	PlainPaths []string
	Budgets    map[string]Budget
}

// HelloMethod is the path of the anonymous Hello.
const HelloMethod = hellov1connect.HelloServiceSayHelloProcedure

// Hello is the anonymous Hello module and the health route.
func Hello() (Module, error) {
	policy, err := ingress.NewUnary(HelloMethod, ingress.Anonymous, ingress.NoScope, MaxBodyBytes, false)
	if err != nil {
		return Module{}, err
	}
	return Module{
		Name:       "hello",
		Policies:   []ingress.Policy{policy},
		PlainPaths: []string{HealthPath},
		Budgets: map[string]Budget{
			HelloMethod: {MaxFrameBytes: 8192, MaxUnaryResponseBytes: 8192, MaxDurationMilliseconds: 10_000, Instance: "hello"},
		},
	}, nil
}

// Center is every module the center serves, in registration order.
func Center() ([]Module, error) {
	hello, err := Hello()
	if err != nil {
		return nil, err
	}
	return []Module{hello}, nil
}

// Row is one route of the Worker's table: the fields of the generated ApiRoute.
type Row struct {
	Path                    string
	Kind                    string
	Auth                    string
	MaxRequestBytes         int
	MaxFrameBytes           int
	MaxUnaryResponseBytes   int
	MaxDurationMilliseconds int
	Instance                string
	RequestMeta             bool
}

// WorkerTable is everything the Worker's production table is generated from.
type WorkerTable struct {
	HelloPath                  string
	HealthPath                 string
	Health                     Row
	Production                 []Row
	MaxBodyBytes               int
	ColdStartMilliseconds      int
	StreamLifetimeMilliseconds int
}

// ErrRegistration is the error of every inconsistent registration.
var ErrRegistration = errors.New("inconsistent center registration")

// Ingress is the center's public routes: the policy registry of every module and their plain paths.
func Ingress(modules []Module) (*ingress.Routes, error) {
	var policies []ingress.Policy
	var plain []string
	for _, module := range modules {
		policies = append(policies, module.Policies...)
		plain = append(plain, module.PlainPaths...)
	}
	registry, err := ingress.NewRegistry(policies...)
	if err != nil {
		return nil, err
	}
	return ingress.NewRoutes(registry, plain, nil), nil
}

// Table reads the Worker's production table from the registrations, fail-closed.
func Table(modules []Module) (WorkerTable, error) {
	budgets := map[string]Budget{}
	var rows []Row
	var plain []string
	names := map[string]bool{}
	for _, module := range modules {
		for name, budget := range module.Budgets {
			if _, duplicate := budgets[name]; duplicate {
				return WorkerTable{}, fmt.Errorf("%w: the budget of %s is declared twice", ErrRegistration, name)
			}
			budgets[name] = budget
		}
		plain = append(plain, module.PlainPaths...)
		for _, policy := range module.Policies {
			if names[policy.FullName] {
				return WorkerTable{}, fmt.Errorf("%w: duplicate production policy %s", ErrRegistration, policy.FullName)
			}
			names[policy.FullName] = true
			budget, ok := module.Budgets[policy.FullName]
			if !ok {
				return WorkerTable{}, fmt.Errorf("%w: the production method %s has no transport budget", ErrRegistration, policy.FullName)
			}
			if err := checkBudget(policy.FullName, budget); err != nil {
				return WorkerTable{}, err
			}
			rows = append(rows, Row{
				Path: policy.FullName, Kind: kindName(policy.Kind), Auth: authName(policy.Authentication),
				MaxRequestBytes: policy.MaxRequestBytes, MaxFrameBytes: budget.MaxFrameBytes,
				MaxUnaryResponseBytes: budget.MaxUnaryResponseBytes, MaxDurationMilliseconds: budget.MaxDurationMilliseconds,
				Instance: budget.Instance, RequestMeta: policy.ReadsRequestMeta(),
			})
		}
	}
	unused := []string{}
	for name := range budgets {
		if !names[name] {
			unused = append(unused, name)
		}
	}
	if len(unused) > 0 {
		sort.Strings(unused)
		return WorkerTable{}, fmt.Errorf("%w: the transport budget %s names no registered method", ErrRegistration, unused[0])
	}
	if len(rows) == 0 {
		return WorkerTable{}, fmt.Errorf("%w: the production table is empty", ErrRegistration)
	}
	if len(plain) != 1 || plain[0] != HealthPath {
		return WorkerTable{}, fmt.Errorf("%w: the center must declare exactly one plain health path, %s", ErrRegistration, HealthPath)
	}
	var hello *Row
	for index := range rows {
		if rows[index].Path == HelloMethod {
			hello = &rows[index]
		}
	}
	if hello == nil {
		return WorkerTable{}, fmt.Errorf("%w: the production table must serve the Hello method", ErrRegistration)
	}
	if hello.MaxRequestBytes != MaxBodyBytes {
		return WorkerTable{}, fmt.Errorf("%w: MaxBodyBytes must equal the Hello policy's request bound", ErrRegistration)
	}
	if ColdStartMilliseconds < 1 || ColdStartMilliseconds > StreamLifetimeMilliseconds {
		return WorkerTable{}, fmt.Errorf("%w: the cold start budget is out of range", ErrRegistration)
	}
	return WorkerTable{
		HelloPath:  APIPrefix + HelloMethod,
		HealthPath: APIPrefix + HealthPath,
		Health: Row{
			Path: HealthPath, Kind: "unary", Auth: "anonymous", MaxUnaryResponseBytes: HealthMaxUnaryResponseBytes,
			MaxDurationMilliseconds: HealthMaxDurationMilliseconds, Instance: HealthInstance,
		},
		Production:                 rows,
		MaxBodyBytes:               MaxBodyBytes,
		ColdStartMilliseconds:      ColdStartMilliseconds,
		StreamLifetimeMilliseconds: StreamLifetimeMilliseconds,
	}, nil
}

func checkBudget(name string, budget Budget) error {
	const maxBytes = 1_048_576
	if budget.MaxFrameBytes < 1 || budget.MaxFrameBytes > maxBytes || budget.MaxUnaryResponseBytes < 1 ||
		budget.MaxUnaryResponseBytes > maxBytes || budget.MaxDurationMilliseconds < 1 ||
		budget.MaxDurationMilliseconds > StreamLifetimeMilliseconds || budget.Instance == "" {
		return fmt.Errorf("%w: the transport budget of %s is out of range", ErrRegistration, name)
	}
	return nil
}

func kindName(kind ingress.Kind) string {
	if kind == ingress.ServerStream {
		return "serverStream"
	}
	return "unary"
}

func authName(authentication ingress.Authentication) string {
	if authentication == ingress.Session {
		return "session"
	}
	return "anonymous"
}
