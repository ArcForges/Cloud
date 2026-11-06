// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"time"

	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"

	"github.com/ArcForges/Cloud/center/internal/ingress"
)

// SurfaceNodes is FleetService on the center (AF-CTR-05 E2a; Plan CTR5-SUR-01, Q10): the node registry (ListNodes, GetNode, RenameNode,
// RevokeNode) and, from part E2b, the routed task methods. Its methods are served only where the surface is enabled; elsewhere the
// Worker and the center answer STATE/not_activated.
const SurfaceNodes = "nodes"

// nodesRequestBytes bounds a registry request: a few IDs, a name of at most 64 characters and a relay assertion of at most 512 bytes.
const nodesRequestBytes = 4096

// routedSubmitBytes bounds a SubmitNodeTask request: its TaskServiceSubmitTaskRequest of at most 253,952 bytes (hub.MaxCallPayload), a
// relay assertion of at most 512 bytes, the IDs, the routed caller and RequestMeta: 256 KiB. routedReadBytes bounds the other routed
// requests: an inner request of at most 3,072 bytes and the same fields.
const (
	routedSubmitBytes = 262_144
	routedReadBytes   = 8_192
)

// RoutedReplyBytes is a routed method's reply bound, the largest a budget may name (1 MiB): value.response of at most 1,040,384 bytes
// (hub.MaxResultPayload) leaves 8,192 bytes for the node ID, ResponseMeta and the frame. It is the largest budget, so it is the center's Connect send bound for every
// method (routes.MaxResponseBytes); each other method's own reply bound is the Worker's.
const RoutedReplyBytes = 1_048_576

// The routed methods' deadlines (Plan CTR5-RTE-06 as fixed by Contracts K2): 10 s; WaitNodeTask wait_ms + 5 s, at most 55 s;
// ReadNodeTaskOutput 10 s, or wait_ms + 10 s, at most 30 s. A route's budget is the longest its method may take.
const (
	RoutedDeadline           = 10 * time.Second
	RoutedWaitDeadline       = 55 * time.Second
	RoutedReadOutputDeadline = 30 * time.Second
)

// NodesMethods are the FleetService methods the center serves, in registration order: the node registry (AF-CTR-05 E2a) and the routed
// task methods (E2b). Every other
// FleetService method stays unregistered (Plan CTR5-API-01: SendNodeCommand, GetNodeCommand, ListNodeCommands, CancelNodeCommand, the push
// preferences, IssueRelayToken, OpenFleetWatch and WatchFleet): the center answers UNIMPLEMENTED and the Worker table has no row for it.
func NodesMethods() []IdentityMethod {
	return []IdentityMethod{
		{fleetv1connect.FleetServiceListNodesProcedure, true, nodesRequestBytes},
		{fleetv1connect.FleetServiceGetNodeProcedure, true, nodesRequestBytes},
		{fleetv1connect.FleetServiceRenameNodeProcedure, true, nodesRequestBytes},
		{fleetv1connect.FleetServiceRevokeNodeProcedure, true, nodesRequestBytes},
		{fleetv1connect.FleetServiceSubmitNodeTaskProcedure, true, routedSubmitBytes},
		{fleetv1connect.FleetServiceGetNodeTaskProcedure, true, routedReadBytes},
		{fleetv1connect.FleetServiceListNodeTasksProcedure, true, routedReadBytes},
		{fleetv1connect.FleetServiceWaitNodeTaskProcedure, true, routedReadBytes},
		{fleetv1connect.FleetServiceReadNodeTaskOutputProcedure, true, routedReadBytes},
		{fleetv1connect.FleetServiceCancelNodeTaskProcedure, true, routedReadBytes},
	}
}

// ListNodesReplyBytes is ListNodes' reply bound: one FleetNode per live enrollment, at most config.MaxNodesPerAccountBound (1,000), and a
// FleetNode is at most 612 bytes (two names of 64 UTF-16 units of 3-byte characters, a 128-character version, its IDs and the largest
// instants), so the worst reply frame is 615,031 bytes; 640 KiB holds it with its trailers (fleetapi's
// TestTheListNodesReplyFitsItsBoundAtTheCap builds that reply). The routed methods' RoutedReplyBytes is larger, so it is the center's
// Connect send bound (routes.MaxResponseBytes).
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
	case fleetv1connect.FleetServiceSubmitNodeTaskProcedure, fleetv1connect.FleetServiceGetNodeTaskProcedure, fleetv1connect.FleetServiceListNodeTasksProcedure,
		fleetv1connect.FleetServiceCancelNodeTaskProcedure:
		deadline, reply = int(RoutedDeadline.Milliseconds()), RoutedReplyBytes
	case fleetv1connect.FleetServiceWaitNodeTaskProcedure:
		deadline, reply = int(RoutedWaitDeadline.Milliseconds()), RoutedReplyBytes
	case fleetv1connect.FleetServiceReadNodeTaskOutputProcedure:
		deadline, reply = int(RoutedReadOutputDeadline.Milliseconds()), RoutedReplyBytes
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
		budget := nodesBudget(method.Path)
		policy = policy.InSurface(SurfaceNodes)
		if method.Path == fleetv1connect.FleetServiceWaitNodeTaskProcedure || method.Path == fleetv1connect.FleetServiceReadNodeTaskOutputProcedure {
			// The routed long polls outlast the server's timeouts (PN-1): their connection deadlines follow their budget.
			policy = policy.WithDeadline(time.Duration(budget.MaxDurationMilliseconds) * time.Millisecond)
		}
		module.Policies = append(module.Policies, policy)
		module.Budgets[method.Path] = budget
	}
	return module, nil
}
