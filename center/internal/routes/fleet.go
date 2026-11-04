// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"

	"github.com/ArcForges/Cloud/center/internal/ingress"
)

// SurfaceFleet is the fleet surface: node enrollment (AF-CTR-04). Its methods are served only where the surface is enabled; elsewhere
// the Worker and the center answer STATE/not_activated with state.reason fleet.
const SurfaceFleet = "fleet"

// fleetRequestBytes bounds every fleet request: a refresh token, a node's description with its key and PKCE values, or a code with its
// verifier and proof (and the CSR that release 1 ignores).
const fleetRequestBytes = 4096

// FleetMethods are the NodeEnrollmentService methods the center serves, in registration order: part E1b's browser sign-in, part E2's
// device-code sign-in, then part E1a's refresh, report and sign-out. Every other method of the service stays unregistered
// (UNIMPLEMENTED, no Worker row) until its task serves it: the phone pairing, certificate, LAN, entitlement-token, entitlement-key and
// support-upload methods.
func FleetMethods() []IdentityMethod {
	return []IdentityMethod{
		{fleetv1connect.NodeEnrollmentServiceBeginNodeSignInProcedure, false, fleetRequestBytes},
		{fleetv1connect.NodeEnrollmentServiceGetNodeSignInFlowProcedure, true, fleetRequestBytes},
		{fleetv1connect.NodeEnrollmentServiceApproveNodeSignInProcedure, true, fleetRequestBytes},
		{fleetv1connect.NodeEnrollmentServiceCompleteNodeSignInProcedure, false, fleetRequestBytes},
		{fleetv1connect.NodeEnrollmentServiceStartDeviceAuthorizationProcedure, false, fleetRequestBytes},
		{fleetv1connect.NodeEnrollmentServicePollDeviceAuthorizationProcedure, false, fleetRequestBytes},
		{fleetv1connect.NodeEnrollmentServiceLookupDeviceCodeProcedure, true, fleetRequestBytes},
		{fleetv1connect.NodeEnrollmentServiceApproveDeviceCodeProcedure, true, fleetRequestBytes},
		{fleetv1connect.NodeEnrollmentServiceRefreshNodeSessionProcedure, false, fleetRequestBytes},
		{fleetv1connect.NodeEnrollmentServiceReportNodeInfoProcedure, true, fleetRequestBytes},
		{fleetv1connect.NodeEnrollmentServiceSignOutNodeProcedure, true, fleetRequestBytes},
	}
}

// fleetBudget is the transport budget of a fleet method: small replies (a token pair with the key sets, a flow, or a receipt), a few
// short transactions, and the contract's deadline of the method: 5 s for GetNodeSignInFlow and LookupDeviceCode, 15 s for
// CompleteNodeSignIn, 10 s for the others (a refresh or a completion that outlived the node's deadline and committed would leave the node a spent token).
func fleetBudget(path string) Budget {
	deadline := 10_000
	switch path {
	case fleetv1connect.NodeEnrollmentServiceGetNodeSignInFlowProcedure, fleetv1connect.NodeEnrollmentServiceLookupDeviceCodeProcedure:
		deadline = 5_000
	case fleetv1connect.NodeEnrollmentServiceCompleteNodeSignInProcedure:
		deadline = 15_000
	}
	return Budget{MaxFrameBytes: 65_536, MaxUnaryResponseBytes: 65_536, MaxDurationMilliseconds: deadline, Instance: HealthInstance}
}

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
		module.Budgets[method.Path] = fleetBudget(method.Path)
	}
	return module, nil
}
