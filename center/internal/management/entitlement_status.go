// SPDX-License-Identifier: AGPL-3.0-only

package management

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect/v2"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// EntitlementStatusMethod reports the caller's current Center service access.
// It is an essential account read and uses the same gate as remote admission.
func EntitlementStatusMethod(authorizer *access.Authorizer, clock func() time.Time, logger *slog.Logger) connect.Method {
	return connect.Method{
		Spec: connect.Spec{
			Procedure:  publicapiv1connect.EntitlementServiceGetSnapshotProcedure,
			StreamType: connect.StreamTypeUnary,
			Schema: publicapiv1.File_arcforges_publicapi_v1_commerce_proto.Services().
				ByName("EntitlementService").Methods().ByName("GetSnapshot"),
		},
		Handler: func(ctx context.Context, _ connect.Spec, stream connect.ServerStream) error {
			var request publicapiv1.EntitlementServiceGetSnapshotRequest
			if err := stream.Receive(&request); err != nil {
				return err
			}
			call, ok := ingress.CallFrom(ctx)
			if !ok {
				return connect.NewError(connect.CodeInternal, "the status read was not admitted by ingress")
			}
			ctx, cancel := context.WithTimeout(ctx, store.DefaultTimeout)
			defer cancel()
			reply := &publicapiv1.EntitlementServiceGetSnapshotResponse{Meta: ingress.ResponseMeta(call.Correlation)}
			snapshot, err := readEntitlementStatus(ctx, call, &request, authorizer)
			if err != nil {
				var refusal *arc.Refusal
				if !errors.As(err, &refusal) {
					var database *store.Error
					sqlState := ""
					if errors.As(err, &database) {
						sqlState = database.SQLState
					}
					logger.WarnContext(ctx, "the entitlement status could not be read", "method", call.Policy.FullName,
						"correlationId", call.Correlation.CorrelationID, "reason", feature.ReasonEntitlementUnavailable, "sqlState", sqlState)
					refusal = arc.Unavailable()
				}
				reply.Outcome = &publicapiv1.EntitlementServiceGetSnapshotResponse_Error{
					Error: refusal.Dated(clock()).ArcError(call.Correlation),
				}
			} else {
				reply.Outcome = &publicapiv1.EntitlementServiceGetSnapshotResponse_Value{
					Value: &publicapiv1.EntitlementServiceGetSnapshotValue{Snapshot: snapshot},
				}
			}
			return stream.Send(reply)
		},
	}
}

func readEntitlementStatus(ctx context.Context, call *ingress.Call, request *publicapiv1.EntitlementServiceGetSnapshotRequest,
	authorizer *access.Authorizer) (*publicapiv1.EntitlementSnapshot, error) {
	if _, err := authorizer.Authorize(ctx, call); err != nil {
		return nil, err
	}
	meta := request.GetMeta()
	if meta == nil || len(request.ProtoReflect().GetUnknown()) != 0 || len(meta.ProtoReflect().GetUnknown()) != 0 {
		return nil, arc.InvalidArgument("request", "typed_message_invalid")
	}
	if meta.GetWorkspaceId() != nil {
		return nil, arc.InvalidArgument("meta.workspace_id", "not_admitted")
	}
	if meta.GetCommandId() != nil {
		return nil, arc.InvalidArgument("meta.command_id", "not_admitted")
	}
	status, err := feature.Status(feature.WithAccount(ctx, call.Caller.UserID), authorizer.Gate())
	if err != nil {
		return nil, err
	}
	// The resolver's merged service state has no exact source term identity.
	snapshot := &publicapiv1.EntitlementSnapshot{Version: status.Version}
	for _, entry := range status.Features {
		snapshot.Capabilities = append(snapshot.Capabilities, &publicapiv1.Availability{
			Capability: proto.String(string(entry.Key)),
			Allowed:    proto.Bool(entry.Decision.Available),
			Reasons:    []string{string(entry.Decision.Reason)},
		})
	}
	return snapshot, nil
}
