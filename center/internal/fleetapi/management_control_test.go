// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/connect/v2/connectproto"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	v2 "github.com/ArcForges/Contracts/go/arcforges/sandbox/v2"
	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The real mounted Connect gRPC-Web encoder must preserve the authenticated
// operation detail even though the original mutation response type differs.
func TestV2ControlReconciledReadbackSurvivesGRPCWeb(t *testing.T) {
	correlationID := platform.NewID()
	original := &v2.NodeServiceGetOperationResponse{Meta: &foundationv1.ResponseMeta{CorrelationId: id(correlationID)},
		Outcome: &v2.NodeServiceGetOperationResponse_Value{Value: &v2.NodeServiceGetOperationValue{Operation: &v2.Operation{
			OwnerEpoch: id(platform.NewID()), CommandId: id(platform.NewID()), AggregateId: id(platform.NewID()),
			Method: proto.String("RunService.Start"), State: v2.OperationState_OPERATION_STATE_SUCCEEDED.Enum(),
			Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED.Enum(), UpdatedAt: arc.Instant(time.Now().UTC()),
			ResponseCompacted: proto.Bool(false),
		}}}}
	if !v2.ValidateNodeServiceGetOperationResponse(original) {
		t.Fatal("the operation fixture is invalid")
	}
	server := connect.NewServer()
	sandboxv2connect.RegisterRunServiceHandler(server, replayReadbackFixture{result: original})
	mux := http.NewServeMux()
	connecthttp.Mount(mux, server)
	host := httptest.NewServer(mux)
	defer host.Close()
	client := sandboxv2connect.NewRunServiceClient(connect.NewClient(connecthttp.NewTransport(host.Client(), host.URL, connecthttp.WithGRPCWeb())))
	_, err := client.Start(t.Context(), &v2.RunServiceStartRequest{})
	failure, ok := errors.AsType[*connect.Error](err)
	if !ok || failure.Code() != connect.CodeFailedPrecondition || failure.Message() != "original_operation_reconciled" || len(failure.Details()) != 1 {
		t.Fatalf("gRPC-Web reconciliation status: %v", err)
	}
	actual, err := connectproto.UnmarshalErrorDetail(failure.Details()[0])
	if err != nil || !proto.Equal(actual, original) {
		t.Fatalf("original operation detail changed in transit: %v", err)
	}

	operation := original.GetValue().GetOperation()
	operation.ResponseCompacted = proto.Bool(true)
	compacted := &v2.RunServiceStartResponse{Meta: original.Meta, Outcome: &v2.RunServiceStartResponse_Error{
		Error: controlCompacted(operation).ArcError(correlation.Context{CorrelationID: correlationID.String()}),
	}}
	if !v2.ValidateRunServiceStartResponse(compacted) || compacted.GetError().GetCode() != "receipt_compacted" ||
		compacted.GetError().GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER ||
		!proto.Equal(compacted.GetError().GetDetails().GetState().GetResource().GetId(), operation.GetAggregateId()) {
		t.Fatal("the compacted result did not keep its verified typed aggregate or safe retry rule")
	}
}

type replayReadbackFixture struct {
	sandboxv2connect.UnimplementedRunServiceHandler
	result *v2.NodeServiceGetOperationResponse
}

func (r replayReadbackFixture) Start(context.Context, *v2.RunServiceStartRequest) (*v2.RunServiceStartResponse, error) {
	return nil, controlReconciled(r.result)
}

func TestV2ControlSettlementRequiresCompatibleFreshEvidence(t *testing.T) {
	if !retryableControlSettlement(store.ErrCommitUnknown) || !retryableControlSettlement(store.ErrUnavailable) ||
		retryableControlSettlement(management.ErrLease) || retryableControlSettlement(management.ErrIdentityConflict) {
		t.Fatal("an authority failure must not be treated as a secondary metadata error")
	}
	aggregate, foreign := platform.NewID(), platform.NewID()
	want := management.Observation{State: management.StateSucceeded, Effect: management.EffectHappened, ResultID: &aggregate}
	if !sameVerifiedEffect(want, want) || sameVerifiedEffect(want, management.Observation{State: management.StateSucceeded,
		Effect: management.EffectHappened, ResultID: &foreign}) || sameVerifiedEffect(want, management.Observation{State: management.StateUnknown}) {
		t.Fatal("a second authorized observation may disclose only the original terminal effect")
	}
}

func TestV2ControlOnlyStopCanSucceedWithoutAnEffect(t *testing.T) {
	correlationID, epochID, commandID, runID := platform.NewID(), platform.NewID(), platform.NewID(), platform.NewID()
	operation := &v2.Operation{OwnerEpoch: id(epochID), CommandId: id(commandID), AggregateId: id(runID),
		Method: proto.String("RunService.Stop"), State: v2.OperationState_OPERATION_STATE_SUCCEEDED.Enum(),
		Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(), UpdatedAt: arc.Instant(time.Now().UTC()),
		ResponseCompacted: proto.Bool(false)}
	observed := &v2.NodeServiceGetOperationResponse{Meta: &foundationv1.ResponseMeta{CorrelationId: id(correlationID)},
		Outcome: &v2.NodeServiceGetOperationResponse_Value{Value: &v2.NodeServiceGetOperationValue{Operation: operation}}}
	decode := func() (*v2.NodeServiceGetOperationResponse, error) {
		body, err := proto.Marshal(observed)
		if err != nil {
			t.Fatal(err)
		}
		return decodeControlResponse(body, &v2.NodeServiceGetOperationResponse{}, id(correlationID), v2.ValidateNodeServiceGetOperationResponse)
	}
	result, err := decode()
	if err != nil || !proto.Equal(result, observed) {
		t.Fatalf("the exact no-effect Stop readback was rewritten or refused: %v", err)
	}
	identity := management.Identity{Command: commandID, OwnerEpoch: epochID, Method: "RunService.Stop"}
	retained, err := operationControlObservation(identity, result, result.GetValue().GetOperation())
	if err != nil || retained.State != management.StateSucceeded || retained.Effect != management.EffectDidNotHappen ||
		retained.ResultID == nil || *retained.ResultID != runID {
		t.Fatalf("the Stop result lost its scope or recorded an incorrect effect: %v", err)
	}
	operation.Method = proto.String("RunService.Start")
	if _, err = decode(); !errors.Is(err, errControlResult) {
		t.Fatalf("a Start cannot report success with no effect: %v", err)
	}
}
