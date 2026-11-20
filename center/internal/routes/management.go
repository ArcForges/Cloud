// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"strings"

	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"
)

// ManagementMethod is one admitted unary operation of the V2 typed channel.
// Selector values are fixed for the matching Node/Center protocol.
type ManagementMethod struct {
	Selector uint8
	Path     string
	Mutation bool
}

// ReceiptMethod is the migration-owned short identity of a durable method.
func (m ManagementMethod) ReceiptMethod() string {
	return strings.ReplaceAll(strings.TrimPrefix(m.Path, "/arcforges.sandbox.v2."), "/", ".")
}

// ManagementMethods is the closed unary CENTER-03 cohort. Stream, data, local
// terminal and delete-approval operations have no route here.
func ManagementMethods() []ManagementMethod {
	return []ManagementMethod{
		{1, sandboxv2connect.NodeServiceGetOperationProcedure, false},
		{2, sandboxv2connect.NodeServiceListRemoteGrantsProcedure, false},
		{3, sandboxv2connect.NodeServiceRevokeRemoteGrantProcedure, true},
		{4, sandboxv2connect.SandboxServiceCreateProcedure, true},
		{5, sandboxv2connect.SandboxServiceConfigureProcedure, true},
		{6, sandboxv2connect.SandboxServiceListProcedure, false},
		{7, sandboxv2connect.SandboxServiceInspectProcedure, false},
		{8, sandboxv2connect.RunServiceStartProcedure, true},
		{9, sandboxv2connect.RunServiceStopProcedure, true},
		{10, sandboxv2connect.RunServiceListProcedure, false},
		{11, sandboxv2connect.RunServiceInspectProcedure, false},
		{12, sandboxv2connect.ResourceServiceGetBudgetProcedure, false},
		{13, sandboxv2connect.ResourceServiceSetPolicyProcedure, true},
	}
}

// ManagementRequestBytes includes the unary frame header. It also fits the
// private channel body bound with room for its signed context.
const ManagementRequestBytes = 253_952
