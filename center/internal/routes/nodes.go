// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"

	"github.com/ArcForges/Cloud/center/internal/ingress"
)

// SurfaceNodes is FleetService on the center (AF-CTR-05 E2a; Plan CTR5-SUR-01, Q10): the node registry (ListNodes, GetNode, RenameNode,
// RevokeNode) and, from part E2b, the routed task methods. Its methods are served only where the surface is enabled; elsewhere the
// Worker and the center answer STATE/not_activated.
const SurfaceNodes = "nodes"

// nodesRequestBytes bounds a registry request: a few IDs, a name of at most 64 characters and a relay assertion of at most 512 bytes.
const nodesRequestBytes = 4096

// NodesMethods are the FleetService methods the center serves, in registration order: the node registry (AF-CTR-05 E2a). Every other
// FleetService method stays unregistered (Plan CTR5-API-01: SendNodeCommand, GetNodeCommand, ListNodeCommands, CancelNodeCommand, the push
// preferences, IssueRelayToken, OpenFleetWatch and WatchFleet): the center answers UNIMPLEMENTED and the Worker table has no row for it.
func NodesMethods() []IdentityMethod {
	return []IdentityMethod{
		{fleetv1connect.FleetServiceListNodesProcedure, true, nodesRequestBytes},
		{fleetv1connect.FleetServiceGetNodeProcedure, true, nodesRequestBytes},
		{fleetv1connect.FleetServiceRenameNodeProcedure, true, nodesRequestBytes},
		{fleetv1connect.FleetServiceRevokeNodeProcedure, true, nodesRequestBytes},
	}
}

// nodesBudget is a registry method's transport budget: the contract's deadline (5 s, RevokeNode 10 s); a ListNodes reply carries one
// FleetNode of a few hundred bytes per live enrollment, at most the enrollment cap's bound of 1,000 (config MaxNodesPerAccount), so it
// gets 256 KiB, the others 64 KiB.
func nodesBudget(path string) Budget {
	deadline, reply := 5_000, 65_536
	switch path {
	case fleetv1connect.FleetServiceRevokeNodeProcedure:
		deadline = 10_000
	case fleetv1connect.FleetServiceListNodesProcedure:
		reply = 262_144
	}
	return Budget{MaxFrameBytes: reply, MaxUnaryResponseBytes: reply, MaxDurationMilliseconds: deadline, Instance: HealthInstance}
}

// Nodes is the nodes surface's module: its FleetService methods.
func Nodes() (Module, error) {
	module := Module{Name: "nodes", Surface: SurfaceNodes, Budgets: map[string]Budget{}}
	for _, method := range NodesMethods() {
		policy, err := ingress.NewUnary(method.Path, ingress.Session, ingress.NoScope, method.MaxRequestBytes, true)
		if err != nil {
			return Module{}, err
		}
		module.Policies = append(module.Policies, policy.InSurface(SurfaceNodes))
		module.Budgets[method.Path] = nodesBudget(method.Path)
	}
	return module, nil
}
