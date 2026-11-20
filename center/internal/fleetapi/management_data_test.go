// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"context"
	"errors"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	v2 "github.com/ArcForges/Contracts/go/arcforges/sandbox/v2"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/store"
)

func TestV2DataExportAcceptanceRetainsNoDefiniteEffect(t *testing.T) {
	identity := management.Identity{
		Command: platform.NewID(), OwnerEpoch: platform.NewID(), Method: "DataService.BeginExport",
	}
	transfer := platform.NewID()
	start := &v2.DataServiceBeginExportResponse{Outcome: &v2.DataServiceBeginExportResponse_Value{
		Value: &v2.DataServiceBeginExportValue{Transfer: &v2.Transfer{
			TransferId: id(transfer), State: v2.TransferState_TRANSFER_STATE_OPEN.Enum(),
		}},
	}}
	accepted, err := directControlObservation(identity, start)
	if err != nil || accepted.State != management.StateAccepted || accepted.Effect != 0 ||
		accepted.ResultID != nil || accepted.ResultSHA256 != ([32]byte{}) {
		t.Fatalf("the pending snapshot must not settle a definite effect: %v", err)
	}

	operation := &v2.Operation{
		OwnerEpoch: id(identity.OwnerEpoch), CommandId: id(identity.Command), AggregateId: id(transfer),
		Method: proto.String(identity.Method), State: v2.OperationState_OPERATION_STATE_SUCCEEDED.Enum(),
		Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED.Enum(),
	}
	readback := &v2.NodeServiceGetOperationResponse{Outcome: &v2.NodeServiceGetOperationResponse_Value{
		Value: &v2.NodeServiceGetOperationValue{Operation: operation},
	}}
	settled, err := operationControlObservation(identity, readback, operation)
	if err != nil || settled.State != management.StateSucceeded || settled.Effect != management.EffectHappened ||
		settled.ResultKind != "transfer" || settled.ResultID == nil || *settled.ResultID != transfer ||
		settled.ResultSHA256 == ([32]byte{}) {
		t.Fatalf("the exact original operation must settle the transfer: %v", err)
	}
	operation.OwnerEpoch = id(platform.NewID())
	if _, err := operationControlObservation(identity, readback, operation); !errors.Is(err, errControlResult) {
		t.Fatal("settlement accepted a different owner epoch")
	}
	operation.OwnerEpoch, operation.AggregateId = id(identity.OwnerEpoch), nil
	if _, err := operationControlObservation(identity, readback, operation); !errors.Is(err, errControlResult) {
		t.Fatal("settlement accepted a missing transfer identity")
	}
}

func TestV2DataReadRecipientUsesTypedSessionRefusal(t *testing.T) {
	callID := platform.NewID()
	for _, tc := range []struct {
		err  error
		code string
	}{
		{pgx.ErrNoRows, "unauthenticated"},
		{store.ErrUnavailable, "overloaded"},
		{store.ErrTimeout, "overloaded"},
	} {
		refusal := dataRecipientSessionFailure(tc.err).Dated(time.Now().UTC())
		errorReply := refusal.ArcError(correlation.Context{CorrelationID: callID.String()})
		read := &v2.DataServiceReadExportResponse{
			Meta:    &foundationv1.ResponseMeta{CorrelationId: id(callID)},
			Outcome: &v2.DataServiceReadExportResponse_Error{Error: errorReply},
		}
		inspect := &v2.DataServiceInspectTransferResponse{
			Meta:    &foundationv1.ResponseMeta{CorrelationId: id(callID)},
			Outcome: &v2.DataServiceInspectTransferResponse_Error{Error: errorReply},
		}
		if errorReply.GetCode() != tc.code || !v2.ValidateDataServiceReadExportResponse(read) ||
			!v2.ValidateDataServiceInspectTransferResponse(inspect) {
			t.Fatalf("the pinned contract must accept a typed %s refusal without transfer content", tc.code)
		}
	}

	router := &managementRouter{}
	reply := &v2.NodeServiceGetOperationResponse{Outcome: &v2.NodeServiceGetOperationResponse_Value{
		Value: &v2.NodeServiceGetOperationValue{Operation: &v2.Operation{AggregateId: id(platform.NewID())}},
	}}
	actual, err := router.discloseDataReadback(context.Background(), management.Identity{Method: "DataService.BeginExport"}, reply)
	refusal, ok := errors.AsType[*arc.Refusal](err)
	if actual != nil || !ok || refusal.Code != "unauthenticated" {
		t.Fatal("Data operation readback disclosed transfer metadata without an authenticated recipient")
	}
	actual, err = router.discloseDataReadback(context.Background(), management.Identity{Method: "RunService.Start"}, reply)
	if err != nil || actual != reply {
		t.Fatal("the Data-only check changed the CENTER-03 readback path")
	}
}

func TestV2DataExactChunkSizeAndRange(t *testing.T) {
	const chunkBytes = 1 << 20
	const offset = 4096
	correlation, transfer := platform.NewID(), platform.NewID()
	data := make([]byte, chunkBytes)
	request := &v2.DataServiceWriteImportRequest{
		Meta: &foundationv1.RequestMeta{
			CorrelationId: id(correlation), CommandId: id(platform.NewID()), ExpectedRev: &foundationv1.Revision{Value: proto.Int64(1)},
		},
		OwnerEpoch: id(platform.NewID()), TransferId: id(transfer), Offset: proto.Uint64(offset), Chunk: data,
	}
	if !v2.ValidateDataServiceWriteImportRequest(request) || proto.Size(request) <= chunkBytes {
		t.Fatal("the pinned published shape must accept a full chunk plus the envelope")
	}
	scope := management.Authority{
		Account: platform.NewID(), Actor: platform.NewID(), Node: platform.NewID(),
		Enrollment: platform.NewID(), Grant: platform.NewID(), GrantRevision: 1,
	}
	method := routes.ManagementDataMethods()[1]
	original, err := controlIntent(scope, method, request)
	if err != nil {
		t.Fatal(err)
	}
	request.Meta.CorrelationId = id(platform.NewID())
	duplicate, err := controlIntent(scope, method, request)
	if err != nil || duplicate != original {
		t.Fatal("changing only the correlation changed the original command intent")
	}
	request.Chunk[0] = 1
	changed, err := controlIntent(scope, method, request)
	if err != nil || changed == original {
		t.Fatal("changing the bytes left the original command intent unchanged")
	}

	read := &v2.DataServiceReadExportRequest{
		Meta: &foundationv1.RequestMeta{CorrelationId: id(correlation)}, TransferId: id(transfer),
		Offset: proto.Uint64(offset), MaxBytes: proto.Uint32(chunkBytes),
	}
	chunk := &v2.DataChunk{Data: data, Offset: proto.Uint64(offset), Eof: proto.Bool(false)}
	reply := &v2.DataServiceReadExportResponse{
		Meta:    &foundationv1.ResponseMeta{CorrelationId: id(correlation)},
		Outcome: &v2.DataServiceReadExportResponse_Value{Value: &v2.DataServiceReadExportValue{Chunk: chunk}},
	}
	body, err := proto.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeControlResponse(body, &v2.DataServiceReadExportResponse{}, id(correlation), v2.ValidateDataServiceReadExportResponse)
	if err != nil || !matchesDataControlResponse(read, decoded) {
		t.Fatalf("the pinned readback must preserve a full-size exact range: %v", err)
	}
	read.MaxBytes = proto.Uint32(chunkBytes - 1)
	if matchesDataControlResponse(read, decoded) {
		t.Fatal("readback accepted a response larger than the requested range")
	}
	read.MaxBytes, read.Offset = proto.Uint32(chunkBytes), proto.Uint64(offset+1)
	if matchesDataControlResponse(read, decoded) {
		t.Fatal("readback accepted a response at a different offset")
	}
}
