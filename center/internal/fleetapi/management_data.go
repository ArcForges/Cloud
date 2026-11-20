// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"context"
	"errors"

	"connectrpc.com/connect/v2"
	v2 "github.com/ArcForges/Contracts/go/arcforges/sandbox/v2"
	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

func managementDataMethods(r *managementRouter) []connect.Method {
	m := routes.ManagementDataMethods()
	return []connect.Method{
		controlMethod(r, m[0], v2.ValidateDataServiceBeginImportRequest, v2.ValidateDataServiceBeginImportResponse),
		controlMethod(r, m[1], v2.ValidateDataServiceWriteImportRequest, v2.ValidateDataServiceWriteImportResponse),
		controlMethod(r, m[2], v2.ValidateDataServiceCommitImportRequest, v2.ValidateDataServiceCommitImportResponse),
		controlMethod(r, m[3], v2.ValidateDataServiceBeginExportRequest, v2.ValidateDataServiceBeginExportResponse),
		controlMethod(r, m[4], v2.ValidateDataServiceReadExportRequest, v2.ValidateDataServiceReadExportResponse),
		controlMethod(r, m[5], v2.ValidateDataServiceInspectTransferRequest, v2.ValidateDataServiceInspectTransferResponse),
		controlMethod(r, m[6], v2.ValidateDataServiceCloseTransferRequest, v2.ValidateDataServiceCloseTransferResponse),
	}
}

func (r *managementRouter) recheckDataRecipient(ctx context.Context, call *ingress.Call) error {
	if err := r.recheckControlCaller(ctx, call); err != nil {
		return dataRecipientSessionFailure(err)
	}
	return r.access.RecheckFeature(ctx, call, call.Policy.FullName)
}

func dataRecipientSessionFailure(err error) *arc.Refusal {
	if errors.Is(err, pgx.ErrNoRows) {
		return arc.Unauthenticated()
	}
	return arc.Unavailable()
}

// A Data receipt can also be disclosed in GetOperation or as a replay detail.
// Recheck both operations when returning a readback from a mutation call.
func (r *managementRouter) discloseDataReadback(ctx context.Context, identity management.Identity, reply controlResponse) (controlResponse, error) {
	if !dataControlMutation(identity.Method) {
		return reply, nil
	}
	call, ok := ingress.CallFrom(ctx)
	if !ok {
		return nil, arc.Unauthenticated()
	}
	if err := r.recheckDataRecipient(ctx, call); err != nil {
		return nil, err
	}
	if call.Policy.FullName != sandboxv2connect.NodeServiceGetOperationProcedure {
		if err := r.access.RecheckFeature(ctx, call, sandboxv2connect.NodeServiceGetOperationProcedure); err != nil {
			return nil, err
		}
	}
	return reply, nil
}

// The Node checks the actual transfer authority. Bind its typed reply to the
// requested target or range before disclosing it or settling a receipt.
func matchesDataControlResponse(request controlRequest, reply controlResponse) bool {
	if reply.GetError() != nil {
		return true
	}
	switch req := request.(type) {
	case *v2.DataServiceBeginImportRequest:
		transfer := reply.(*v2.DataServiceBeginImportResponse).GetValue().GetTransfer()
		return transfer.GetDirection() == "import" && transfer.GetRelativePath() == req.GetRelativePath() &&
			proto.Equal(transfer.GetSandboxId(), req.GetSandboxId()) && transfer.GetByteLength() == req.GetByteLength() &&
			transfer.GetSha256() == req.GetSha256()
	case *v2.DataServiceWriteImportRequest:
		transfer := reply.(*v2.DataServiceWriteImportResponse).GetValue().GetTransfer()
		verified := transfer.GetVerifiedOffset()
		return transfer.GetDirection() == "import" && proto.Equal(transfer.GetTransferId(), req.GetTransferId()) &&
			verified >= req.GetOffset() && verified-req.GetOffset() >= uint64(len(req.GetChunk()))
	case *v2.DataServiceCommitImportRequest:
		value := reply.(*v2.DataServiceCommitImportResponse).GetValue()
		return value.GetTransfer().GetDirection() == "import" &&
			proto.Equal(value.GetTransfer().GetTransferId(), req.GetTransferId()) &&
			proto.Equal(value.GetOperation().GetAggregateId(), req.GetTransferId())
	case *v2.DataServiceBeginExportRequest:
		transfer := reply.(*v2.DataServiceBeginExportResponse).GetValue().GetTransfer()
		return transfer.GetDirection() == "export" && transfer.GetRelativePath() == req.GetRelativePath() &&
			proto.Equal(transfer.GetSandboxId(), req.GetSandboxId())
	case *v2.DataServiceReadExportRequest:
		chunk := reply.(*v2.DataServiceReadExportResponse).GetValue().GetChunk()
		size := uint64(len(chunk.GetData()))
		return chunk.Offset != nil && chunk.Eof != nil && chunk.GetOffset() == req.GetOffset() &&
			size <= uint64(req.GetMaxBytes()) && (size > 0 || chunk.GetEof())
	case *v2.DataServiceInspectTransferRequest:
		transfer := reply.(*v2.DataServiceInspectTransferResponse).GetValue().GetTransfer()
		return proto.Equal(transfer.GetTransferId(), req.GetTransferId())
	case *v2.DataServiceCloseTransferRequest:
		transfer := reply.(*v2.DataServiceCloseTransferResponse).GetValue().GetTransfer()
		return transfer.GetClosedAt() != nil && proto.Equal(transfer.GetTransferId(), req.GetTransferId())
	default:
		return true
	}
}

func dataControlMutation(method string) bool {
	switch method {
	case "DataService.BeginImport", "DataService.WriteImport", "DataService.CommitImport",
		"DataService.BeginExport", "DataService.CloseTransfer":
		return true
	default:
		return false
	}
}

func dataControlObservation(identity management.Identity, reply controlResponse) (management.Observation, error) {
	switch typed := reply.(type) {
	case *v2.DataServiceBeginImportResponse:
		return successfulControlObservation(reply, "transfer", typed.GetValue().GetTransfer().GetTransferId())
	case *v2.DataServiceWriteImportResponse:
		return successfulControlObservation(reply, "transfer", typed.GetValue().GetTransfer().GetTransferId())
	case *v2.DataServiceCommitImportResponse:
		return operationControlObservation(identity, reply, typed.GetValue().GetOperation())
	case *v2.DataServiceBeginExportResponse:
		transfer := typed.GetValue().GetTransfer()
		switch transfer.GetState() {
		case v2.TransferState_TRANSFER_STATE_OPEN:
			// The snapshot worker has accepted the request. GetOperation reads
			// the eventual effect and InspectTransfer reads snapshot progress.
			if _, ok := parseID(transfer.GetTransferId()); ok {
				return management.Observation{State: management.StateAccepted}, nil
			}
		case v2.TransferState_TRANSFER_STATE_COMPLETE:
			return successfulControlObservation(reply, "transfer", transfer.GetTransferId())
		}
	case *v2.DataServiceCloseTransferResponse:
		return successfulControlObservation(reply, "transfer", typed.GetValue().GetTransfer().GetTransferId())
	}
	return management.Observation{}, errControlResult
}
