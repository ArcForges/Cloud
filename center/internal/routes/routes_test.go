// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"

	"github.com/ArcForges/Cloud/center/internal/ingress"
)

func TestManagementRoutesCanBeRegisteredWithoutLegacyFleet(t *testing.T) {
	module := Module{Name: "nodes", Surface: SurfaceNodes, Budgets: map[string]Budget{}}
	if err := addManagementRoutes(&module); err != nil {
		t.Fatal(err)
	}
	devices, remote := 0, 0
	for _, policy := range module.Policies {
		switch {
		case strings.HasPrefix(policy.FullName, "/arcforges.management.v2.DeviceService/"):
			devices++
			if policy.CarriesRemoteTarget {
				t.Errorf("%s unexpectedly requires a remote target", policy.FullName)
			}
		case strings.HasPrefix(policy.FullName, "/arcforges.sandbox.v2."):
			remote++
			if !policy.CarriesRemoteTarget {
				t.Errorf("%s is missing its remote target requirement", policy.FullName)
			}
		default:
			t.Errorf("unexpected management method %s", policy.FullName)
		}
	}
	if devices != 3 || remote != 23 {
		t.Fatalf("got %d device methods and %d remote methods", devices, remote)
	}
}

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
	// The identity surface is exactly the methods AF-CTR-03 serves (F13 pins the same set against the service descriptors), each
	// reading a RequestMeta, served by the one center instance and switched by the surface.
	served := []string{
		"/arcforges.publicapi.v1.IdentityService/BeginAuthentication anonymous 4096",
		"/arcforges.publicapi.v1.IdentityService/CompleteAuthentication anonymous 16384",
		"/arcforges.publicapi.v1.IdentityService/RequestEmailCode anonymous 4096",
		"/arcforges.publicapi.v1.IdentityService/RedeemEmailCode anonymous 4096",
		"/arcforges.publicapi.v1.IdentityService/CompleteEnrollment anonymous 16384",
		"/arcforges.publicapi.v1.IdentityService/BeginRecovery anonymous 4096",
		"/arcforges.publicapi.v1.IdentityService/CompleteRecovery anonymous 16384",
		"/arcforges.publicapi.v1.IdentityService/ListAuthProviders anonymous 4096",
		"/arcforges.publicapi.v1.IdentityService/RefreshSession anonymous 4096",
		"/arcforges.publicapi.v1.IdentityService/GetProfile session 4096",
		"/arcforges.publicapi.v1.IdentityService/GetAccountDeletion session 4096",
		"/arcforges.publicapi.v1.IdentityService/ListAuthIdentities session 4096",
		"/arcforges.publicapi.v1.IdentityService/ListSessions session 4096",
		"/arcforges.publicapi.v1.DeviceService/List session 4096",
		"/arcforges.publicapi.v1.IdentityService/BeginStepUp session 4096",
		"/arcforges.publicapi.v1.IdentityService/CompleteStepUp session 16384",
		"/arcforges.publicapi.v1.IdentityService/UpdateProfile session 4096",
		"/arcforges.publicapi.v1.IdentityService/BeginPasskeyRegistration session 4096",
		"/arcforges.publicapi.v1.IdentityService/CompletePasskeyRegistration session 16384",
		"/arcforges.publicapi.v1.IdentityService/RenameAuthIdentity session 4096",
		"/arcforges.publicapi.v1.IdentityService/RemoveAuthIdentity session 4096",
		"/arcforges.publicapi.v1.IdentityService/RevokeSession session 4096",
		"/arcforges.publicapi.v1.IdentityService/RevokeAllSessions session 4096",
		"/arcforges.publicapi.v1.DeviceService/Rename session 4096",
		"/arcforges.publicapi.v1.DeviceService/Revoke session 4096",
		"/arcforges.publicapi.v1.EntitlementService/GetSnapshot session 4096",
		// AF-CTR-04 E1b: the browser sign-in; E2: the device-code sign-in; E1a: the node methods.
		"/arcforges.fleet.v1.NodeEnrollmentService/BeginNodeSignIn anonymous 4096",
		"/arcforges.fleet.v1.NodeEnrollmentService/GetNodeSignInFlow session 4096",
		"/arcforges.fleet.v1.NodeEnrollmentService/ApproveNodeSignIn session 4096",
		"/arcforges.fleet.v1.NodeEnrollmentService/CompleteNodeSignIn anonymous 4096",
		"/arcforges.fleet.v1.NodeEnrollmentService/StartDeviceAuthorization anonymous 4096",
		"/arcforges.fleet.v1.NodeEnrollmentService/PollDeviceAuthorization anonymous 4096",
		"/arcforges.fleet.v1.NodeEnrollmentService/LookupDeviceCode session 4096",
		"/arcforges.fleet.v1.NodeEnrollmentService/ApproveDeviceCode session 4096",
		"/arcforges.fleet.v1.NodeEnrollmentService/RefreshNodeSession anonymous 4096",
		"/arcforges.fleet.v1.NodeEnrollmentService/ReportNodeInfo session 4096",
		"/arcforges.fleet.v1.NodeEnrollmentService/SignOutNode session 4096",
		"/arcforges.management.v2.DeviceService/List session 4096",
		"/arcforges.management.v2.DeviceService/Inspect session 4096",
		"/arcforges.management.v2.DeviceService/Revoke session 4096",
		"/arcforges.sandbox.v2.NodeService/GetOperation session 253952",
		"/arcforges.sandbox.v2.NodeService/ListRemoteGrants session 253952",
		"/arcforges.sandbox.v2.NodeService/RevokeRemoteGrant session 253952",
		"/arcforges.sandbox.v2.SandboxService/Create session 253952",
		"/arcforges.sandbox.v2.SandboxService/Configure session 253952",
		"/arcforges.sandbox.v2.SandboxService/List session 253952",
		"/arcforges.sandbox.v2.SandboxService/Inspect session 253952",
		"/arcforges.sandbox.v2.RunService/Start session 253952",
		"/arcforges.sandbox.v2.RunService/Stop session 253952",
		"/arcforges.sandbox.v2.RunService/List session 253952",
		"/arcforges.sandbox.v2.RunService/Inspect session 253952",
		"/arcforges.sandbox.v2.ResourceService/GetBudget session 253952",
		"/arcforges.sandbox.v2.ResourceService/SetPolicy session 253952",
		"/arcforges.sandbox.v2.DataService/BeginImport session 253952",
		"/arcforges.sandbox.v2.DataService/WriteImport session 2097152",
		"/arcforges.sandbox.v2.DataService/CommitImport session 253952",
		"/arcforges.sandbox.v2.DataService/BeginExport session 253952",
		"/arcforges.sandbox.v2.DataService/ReadExport session 253952",
		"/arcforges.sandbox.v2.DataService/InspectTransfer session 253952",
		"/arcforges.sandbox.v2.DataService/CloseTransfer session 253952",
		"/arcforges.sandbox.v2.RunService/WatchOutput session 4096",
		"/arcforges.sandbox.v2.NodeService/WatchEvents session 4096",
		"/arcforges.sandbox.v2.ResourceService/WatchUsage session 4096",
		"/arcforges.publicapi.v1.CommerceService/GetCatalogue session 4096",
		"/arcforges.publicapi.v1.CommerceService/CreatePurchaseIntent session 4096",
		"/arcforges.publicapi.v1.CommerceService/CreateCheckoutAttempt session 4096",
		"/arcforges.publicapi.v1.CommerceService/GetPurchaseState session 4096",
		"/arcforges.publicapi.v1.CommerceService/GetSubscription session 4096",
		"/arcforges.publicapi.v1.CommerceService/CancelSubscription session 4096",
		"/arcforges.publicapi.v1.CommerceService/ReactivateSubscription session 4096",
		"/arcforges.publicapi.v1.CommerceService/ListBillingHistory session 4096",
	}
	if len(table.Surfaces) != 7 || table.Surfaces[0] != SurfaceIdentity || table.Surfaces[1] != SurfacePages || table.Surfaces[2] != SurfaceOperations ||
		table.Surfaces[3] != SurfaceFleet || table.Surfaces[4] != SurfaceRelay || table.Surfaces[5] != SurfaceNodes ||
		table.Surfaces[6] != SurfaceCommerce || len(table.SurfaceRows) != len(served) {
		t.Fatalf("surfaces: %v, %d rows", table.Surfaces, len(table.SurfaceRows))
	}
	for index, row := range table.SurfaceRows {
		// The fleet rows carry the contract's deadline of each method (F3: 5 s for GetNodeSignInFlow and LookupDeviceCode, 15 s for
		// CompleteNodeSignIn, 10 s for the others); the identity rows the identity surface's 15 s.
		surface, deadline, reply := SurfaceIdentity, 15_000, 65_536
		kind := "unary"
		remoteTarget := false
		switch {
		case strings.HasPrefix(row.Path, "/arcforges.publicapi.v1.CommerceService/"):
			surface = SurfaceCommerce
		case strings.HasPrefix(row.Path, "/arcforges.sandbox.v2."):
			surface, deadline, reply = SurfaceNodes, 10_000, RoutedReplyBytes
			remoteTarget = true
			switch row.Path {
			case sandboxv2connect.RunServiceWatchOutputProcedure, sandboxv2connect.NodeServiceWatchEventsProcedure,
				sandboxv2connect.ResourceServiceWatchUsageProcedure:
				kind = "serverStream"
			case sandboxv2connect.DataServiceBeginImportProcedure, sandboxv2connect.DataServiceWriteImportProcedure,
				sandboxv2connect.DataServiceCommitImportProcedure, sandboxv2connect.DataServiceBeginExportProcedure,
				sandboxv2connect.DataServiceCloseTransferProcedure:
				deadline = 30_000
			case sandboxv2connect.DataServiceReadExportProcedure:
				deadline, reply = 30_000, ingress.DataTransferWireBytes
			}
		case strings.HasPrefix(row.Path, "/arcforges.management.v2.DeviceService/"):
			surface, deadline = SurfaceNodes, 10_000
			if row.Path == "/arcforges.management.v2.DeviceService/List" {
				reply = ListDevicesReplyBytes
			}
		case strings.HasPrefix(row.Path, "/arcforges.fleet.v1."):
			surface, deadline = SurfaceFleet, 10_000
			switch row.Path {
			case "/arcforges.fleet.v1.NodeEnrollmentService/GetNodeSignInFlow", "/arcforges.fleet.v1.NodeEnrollmentService/LookupDeviceCode":
				deadline = 5_000
			case "/arcforges.fleet.v1.NodeEnrollmentService/CompleteNodeSignIn":
				deadline = 15_000
			}
		}
		if got := fmt.Sprintf("%s %s %d", row.Path, row.Auth, row.MaxRequestBytes); got != served[index] || row.Surface != surface ||
			!row.RequestMeta || row.Instance != HealthInstance || row.Kind != kind || row.MaxFrameBytes != reply ||
			row.MaxUnaryResponseBytes != reply || row.MaxDurationMilliseconds != deadline || row.RemoteTarget != remoteTarget {
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
		if !ok || policy.Surface != row.Surface || !policy.ReadsRequestMeta() || policy.MaxRequestBytes != row.MaxRequestBytes {
			t.Fatalf("the ingress registry differs from the surface row %s", row.Path)
		}
	}
	if !routes.IsPlain(HealthPath) || routes.IsPlain("/readyz") {
		t.Fatal("plain routes")
	}
	callback := table.PaddleWebhook
	if callback == nil || callback.Path != "/commerce/v1/paddle/webhook" || callback.Method != "POST" ||
		callback.SignatureHeader != "Paddle-Signature" || callback.MaxSignatureBytes != 512 ||
		callback.MaxRequestBytes != 262144 || callback.MaxDurationMilliseconds != 5000 ||
		!routes.IsPaddleWebhook(callback.Path) || routes.IsPlain(callback.Path) || routes.IsPaddleWebhook(callback.Path+"/other") {
		t.Fatalf("unexpected Paddle callback registration: %+v", callback)
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
// it admits every method's budget (including a full DeviceService.List page),
// not only the largest request.
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
	if largest != ingress.DataTransferWireBytes || MaxRequestBytes(modules) != ingress.DataTransferWireBytes {
		t.Fatalf("send bound %d, request bound %d", largest, MaxRequestBytes(modules))
	}
}
