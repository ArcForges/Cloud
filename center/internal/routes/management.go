// SPDX-License-Identifier: AGPL-3.0-only

package routes

import (
	"strings"
	"time"

	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"

	"github.com/ArcForges/Cloud/center/internal/ingress"
)

// ManagementMethod is one admitted operation of the V2 typed channel.
// Selector values are fixed for the matching Node/Center protocol.
type ManagementMethod struct {
	Selector uint8
	Path     string
	Mutation bool
}

// ManagementWatchMethods are the three public server streams on the fixed
// V2 channel. The order matches the paired private protocol selectors.
func ManagementWatchMethods() []ManagementMethod {
	return []ManagementMethod{
		{14, sandboxv2connect.RunServiceWatchOutputProcedure, false},
		{15, sandboxv2connect.NodeServiceWatchEventsProcedure, false},
		{16, sandboxv2connect.ResourceServiceWatchUsageProcedure, false},
	}
}

// ManagementDataMethods are the exact unary one-file transfer phases.
func ManagementDataMethods() []ManagementMethod {
	return []ManagementMethod{
		{17, sandboxv2connect.DataServiceBeginImportProcedure, true},
		{18, sandboxv2connect.DataServiceWriteImportProcedure, true},
		{19, sandboxv2connect.DataServiceCommitImportProcedure, true},
		{20, sandboxv2connect.DataServiceBeginExportProcedure, true},
		{21, sandboxv2connect.DataServiceReadExportProcedure, false},
		{22, sandboxv2connect.DataServiceInspectTransferProcedure, false},
		{23, sandboxv2connect.DataServiceCloseTransferProcedure, true},
	}
}

// ManagementDeadline is the published bound of a typed routed operation.
func ManagementDeadline(method ManagementMethod) time.Duration {
	switch method.Path {
	case sandboxv2connect.DataServiceBeginImportProcedure, sandboxv2connect.DataServiceWriteImportProcedure,
		sandboxv2connect.DataServiceCommitImportProcedure, sandboxv2connect.DataServiceBeginExportProcedure,
		sandboxv2connect.DataServiceReadExportProcedure, sandboxv2connect.DataServiceCloseTransferProcedure:
		return ManagementDataDeadline
	default:
		return RoutedDeadline
	}
}

// ManagementDataDeadline bounds each transfer phase that may perform I/O.
const ManagementDataDeadline = 30 * time.Second

func matchesManagementTransport(path string, kind ingress.Kind) bool {
	for _, method := range ManagementWatchMethods() {
		if path == method.Path {
			return kind == ingress.ServerStream
		}
	}
	for _, method := range append(ManagementMethods(), ManagementDataMethods()...) {
		if path == method.Path {
			return kind == ingress.Unary
		}
	}
	return false
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
