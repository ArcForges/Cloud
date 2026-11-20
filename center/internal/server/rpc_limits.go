// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"net/http"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"

	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

type rpcRouteFilter struct {
	*http.ServeMux
	accept func(string) bool
}

func (f rpcRouteFilter) Handle(path string, handler http.Handler) {
	if f.accept(path) {
		f.ServeMux.Handle(path, handler)
	}
}

// mountPublicRPCs keeps the two wide transfer directions on the exact same
// dispatcher and HTTP mux. Framing bytes are enforced by ingress and Worker.
func mountPublicRPCs(mux *http.ServeMux, dispatcher *connect.Server, modules []routes.Module) {
	read := min(routes.MaxRequestBytes(modules), ingress.AbsoluteMaxRequestBytes) - ingress.HeaderLength
	send := min(routes.MaxResponseBytes(modules), routes.RoutedReplyBytes) - ingress.HeaderLength
	transfer := ingress.DataTransferWireBytes - ingress.HeaderLength
	writeImport := sandboxv2connect.DataServiceWriteImportProcedure
	readExport := sandboxv2connect.DataServiceReadExportProcedure
	connecthttp.Mount(rpcRouteFilter{mux, func(path string) bool { return path != writeImport && path != readExport }}, dispatcher,
		connecthttp.WithReadMaxBytes(read), connecthttp.WithSendMaxBytes(send))
	connecthttp.Mount(rpcRouteFilter{mux, func(path string) bool { return path == writeImport }}, dispatcher,
		connecthttp.WithReadMaxBytes(transfer), connecthttp.WithSendMaxBytes(send))
	connecthttp.Mount(rpcRouteFilter{mux, func(path string) bool { return path == readExport }}, dispatcher,
		connecthttp.WithReadMaxBytes(read), connecthttp.WithSendMaxBytes(transfer))
}
