// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"

	"github.com/ArcForges/Cloud/center/internal/ingress"
)

// SurfaceFleet is the fleet surface: node enrollment (AF-CTR-04). Its methods are served only where the surface is enabled; elsewhere
// the Worker and the center answer STATE/not_activated with state.reason fleet.
const SurfaceFleet = "fleet"

// fleetRequestBytes bounds every fleet request of part E1a: a refresh token or a node's description.
const fleetRequestBytes = 4096

// FleetMethods are the NodeEnrollmentService methods the center serves, in registration order: part E1a's refresh, report and
// sign-out. Every other method of the service stays unregistered (UNIMPLEMENTED, no Worker row) until its part serves it: the
// browser sign-in (E1b), the device-code sign-in (E2), and the phone pairing, certificate, LAN, entitlement-token, entitlement-key
// and support-upload methods of later tasks.
func FleetMethods() []IdentityMethod {
	return []IdentityMethod{
		{fleetv1connect.NodeEnrollmentServiceRefreshNodeSessionProcedure, false, fleetRequestBytes},
		{fleetv1connect.NodeEnrollmentServiceReportNodeInfoProcedure, true, fleetRequestBytes},
		{fleetv1connect.NodeEnrollmentServiceSignOutNodeProcedure, true, fleetRequestBytes},
	}
}

// fleetBudget is the transport budget of every fleet method: small replies (a token pair with the key sets, or a receipt), a few short
// transactions, and the contract's 10 s deadline of the three methods (a refresh that outlived the node's deadline and committed
// would leave the node a spent token).
var fleetBudget = Budget{MaxFrameBytes: 65_536, MaxUnaryResponseBytes: 65_536, MaxDurationMilliseconds: 10_000, Instance: HealthInstance}

// Fleet is the fleet surface's module.
func Fleet() (Module, error) {
	module := Module{Name: "fleet", Surface: SurfaceFleet, Budgets: map[string]Budget{}}
	for _, method := range FleetMethods() {
		authentication := ingress.Anonymous
		if method.Session {
			authentication = ingress.Session
		}
		policy, err := ingress.NewUnary(method.Path, authentication, ingress.NoScope, method.MaxRequestBytes, true)
		if err != nil {
			return Module{}, err
		}
		module.Policies = append(module.Policies, policy.InSurface(SurfaceFleet))
		module.Budgets[method.Path] = fleetBudget
	}
	return module, nil
}
