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
	"regexp"
	"slices"
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
	// HelloMaxBodyBytes is the Hello policy's request bound, frame header included.
	HelloMaxBodyBytes = 4096
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
	Name string
	// Surface is the switchable surface of every policy of the module (AF-CTR-03), or empty for the always-on Hello.
	Surface    string
	Policies   []ingress.Policy
	PlainPaths []string
	Budgets    map[string]Budget
}

// HelloMethod is the path of the anonymous Hello.
const HelloMethod = hellov1connect.HelloServiceSayHelloProcedure

// Hello is the anonymous Hello module and the health route.
func Hello() (Module, error) {
	policy, err := ingress.NewUnary(HelloMethod, ingress.Anonymous, ingress.NoScope, HelloMaxBodyBytes, false)
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
	identity, err := Identity()
	if err != nil {
		return nil, err
	}
	return []Module{hello, identity}, nil
}

// Surfaces are the switchable surfaces of the registrations, in registration order.
func Surfaces(modules []Module) []string {
	var surfaces []string
	for _, module := range modules {
		if module.Surface != "" && !slices.Contains(surfaces, module.Surface) {
			surfaces = append(surfaces, module.Surface)
		}
	}
	return surfaces
}

// MaxRequestBytes is the largest request bound of any registered method, frame header included: the bound of the Connect reader
// and of the Worker's disposal of an unread upload.
func MaxRequestBytes(modules []Module) int {
	largest := 0
	for _, module := range modules {
		for _, policy := range module.Policies {
			largest = max(largest, policy.MaxRequestBytes)
		}
	}
	return largest
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
	// Surface is the row's switchable surface, or empty for a production row.
	Surface string
}

// WorkerTable is everything the Worker's production table is generated from.
type WorkerTable struct {
	HelloPath  string
	HealthPath string
	Health     Row
	// Production is the always-on rows (Hello); Surfaces and SurfaceRows are the switchable surfaces and their rows, which the Worker
	// forwards only while the surface is enabled.
	Production  []Row
	Surfaces    []string
	SurfaceRows []Row
	// MaxBodyBytes is the bound of a request body of a method that declares no larger one: the Hello bound, which the C#
	// rollback host generates too. Every row carries its own bound; the center's Connect reader takes MaxRequestBytes.
	MaxBodyBytes               int
	ColdStartMilliseconds      int
	StreamLifetimeMilliseconds int
}

var surfacePattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,31}$`)

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
	var rows, surfaceRows []Row
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
			if policy.Surface != module.Surface {
				return WorkerTable{}, fmt.Errorf("%w: the policy %s is not in its module's surface", ErrRegistration, policy.FullName)
			}
			row := Row{
				Path: policy.FullName, Kind: kindName(policy.Kind), Auth: authName(policy.Authentication),
				MaxRequestBytes: policy.MaxRequestBytes, MaxFrameBytes: budget.MaxFrameBytes,
				MaxUnaryResponseBytes: budget.MaxUnaryResponseBytes, MaxDurationMilliseconds: budget.MaxDurationMilliseconds,
				Instance: budget.Instance, RequestMeta: policy.ReadsRequestMeta(), Surface: policy.Surface,
			}
			if policy.Surface == "" {
				rows = append(rows, row)
				continue
			}
			// Every surface row is served by the one center instance (PLT-6) and is a method whose request starts with a RequestMeta.
			if !surfacePattern.MatchString(policy.Surface) || budget.Instance != HealthInstance || !policy.ReadsRequestMeta() {
				return WorkerTable{}, fmt.Errorf("%w: the surface method %s needs a surface name, the %s instance and a RequestMeta", ErrRegistration, policy.FullName, HealthInstance)
			}
			surfaceRows = append(surfaceRows, row)
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
	if hello.MaxRequestBytes != HelloMaxBodyBytes {
		return WorkerTable{}, fmt.Errorf("%w: the Hello policy's request bound changed", ErrRegistration)
	}
	for _, module := range modules {
		if module.Surface != "" && len(module.PlainPaths) > 0 {
			return WorkerTable{}, fmt.Errorf("%w: a surface module declares a plain path", ErrRegistration)
		}
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
		Surfaces:                   Surfaces(modules),
		SurfaceRows:                surfaceRows,
		MaxBodyBytes:               HelloMaxBodyBytes,
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
