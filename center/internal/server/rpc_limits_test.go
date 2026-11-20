// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/ArcForges/Cloud/center/internal/routes"
)

func TestOnlyTheExactTransferDirectionsHaveWiderConnectLimits(t *testing.T) {
	modules, err := routes.Center()
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := connect.NewServer()
	chunk := make([]byte, 1<<20)
	if _, err := rand.Read(chunk); err != nil {
		t.Fatal(err)
	}
	writeImport := sandboxv2connect.DataServiceWriteImportProcedure
	readExport := sandboxv2connect.DataServiceReadExportProcedure
	other := sandboxv2connect.DataServiceInspectTransferProcedure
	for _, path := range []string{writeImport, readExport, other} {
		dispatcher.Register(connect.Method{
			Spec: connect.Spec{Procedure: path, StreamType: connect.StreamTypeUnary},
			Handler: func(_ context.Context, _ connect.Spec, stream connect.ServerStream) error {
				request := &wrapperspb.BytesValue{}
				if err := stream.Receive(request); err != nil {
					return err
				}
				var result []byte
				if len(request.GetValue()) == 1 {
					result = chunk
				}
				return stream.Send(wrapperspb.Bytes(result))
			},
		})
	}
	mux := http.NewServeMux()
	mountPublicRPCs(mux, dispatcher, modules)
	server := httptest.NewServer(mux)
	defer server.Close()
	client := connect.NewClient(connecthttp.NewTransport(server.Client(), server.URL, connecthttp.WithGRPCWeb()))
	call := func(path string, data []byte) (*wrapperspb.BytesValue, error) {
		result := &wrapperspb.BytesValue{}
		err := client.CallUnary(t.Context(), connect.Spec{Procedure: path, StreamType: connect.StreamTypeUnary}, wrapperspb.Bytes(data), result)
		return result, err
	}
	if _, err := call(writeImport, chunk); err != nil {
		t.Fatalf("the complete input chunk and envelope must fit WriteImport: %v", err)
	}
	if result, err := call(readExport, []byte{1}); err != nil || len(result.GetValue()) != len(chunk) {
		t.Fatalf("the complete output chunk and envelope must fit ReadExport: %v", err)
	}
	for _, denied := range []struct {
		path string
		data []byte
	}{{readExport, chunk}, {writeImport, []byte{1}}, {other, chunk}, {other, []byte{1}}} {
		if _, err := call(denied.path, denied.data); connect.CodeOf(err) != connect.CodeResourceExhausted {
			t.Fatalf("%s received a transport limit outside its declared direction: %v", denied.path, err)
		}
	}
}
