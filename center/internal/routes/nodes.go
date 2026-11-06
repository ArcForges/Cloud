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

// ListNodesReplyBytes is ListNodes' reply bound: one FleetNode per live enrollment, at most config.MaxNodesPerAccountBound (1,000), and a
// FleetNode is at most 612 bytes (two names of 64 UTF-16 units of 3-byte characters, a 128-character version, its IDs and the largest
// instants), so the worst reply frame is 615,031 bytes; 640 KiB holds it with its trailers (fleetapi's
// TestTheListNodesReplyFitsItsBoundAtTheCap builds that reply). It is the largest budget, so it is also the center's Connect send bound
// for every method (routes.MaxResponseBytes); each other method's own reply bound is the Worker's.
const ListNodesReplyBytes = 655_360

// nodesBudget is a registry method's transport budget: the contract's deadline (5 s, RevokeNode 10 s); ListNodes replies up to
// ListNodesReplyBytes, the others 64 KiB.
func nodesBudget(path string) Budget {
	deadline, reply := 5_000, 65_536
	switch path {
	case fleetv1connect.FleetServiceRevokeNodeProcedure:
		deadline = 10_000
	case fleetv1connect.FleetServiceListNodesProcedure:
		reply = ListNodesReplyBytes
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
