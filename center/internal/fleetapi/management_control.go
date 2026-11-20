// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectproto"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	v2 "github.com/ArcForges/Contracts/go/arcforges/sandbox/v2"
	"github.com/ArcForges/Contracts/go/arcforges/sandbox/v2/sandboxv2connect"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// V2ControlTransport is the authenticated, exact-epoch Hub channel. The
// callback must commit a durable first-send claim for a mutation.
type V2ControlTransport interface {
	V2ControlAuthority(context.Context, platform.ID, platform.ID, platform.ID, platform.ID) (management.V2ControlAuthority, error)
	CallV2(context.Context, management.V2ControlAuthority, management.V2ControlCall,
		func(context.Context, management.V2ControlAuthority) (bool, error)) ([]byte, error)
}

type managementRouter struct {
	*Server
	transport    V2ControlTransport
	receipts     *management.Store
	replayWindow time.Duration
}

type controlRequest interface {
	proto.Message
	GetMeta() *foundationv1.RequestMeta
}

type controlResponse interface {
	proto.Message
	GetMeta() *foundationv1.ResponseMeta
	GetError() *foundationv1.ArcError
}

// V2ControlMethods handles only the declared CENTER-03 unary cohort. A
// generated request and response type are fixed before any caller data arrives.
func (s *Server) V2ControlMethods(transport V2ControlTransport, replayWindow time.Duration) []connect.Method {
	if replayWindow <= 0 {
		replayWindow = config.DefaultIdentityPolicy().RoutedReplayWindow
	}
	r := &managementRouter{Server: s, transport: transport, receipts: management.New(s.db),
		replayWindow: min(replayWindow, config.MaxRoutedReplayWindow)}
	m := routes.ManagementMethods()
	return []connect.Method{
		controlMethod(r, m[0], v2.ValidateNodeServiceGetOperationRequest, v2.ValidateNodeServiceGetOperationResponse),
		controlMethod(r, m[1], v2.ValidateNodeServiceListRemoteGrantsRequest, v2.ValidateNodeServiceListRemoteGrantsResponse),
		controlMethod(r, m[2], v2.ValidateNodeServiceRevokeRemoteGrantRequest, v2.ValidateNodeServiceRevokeRemoteGrantResponse),
		controlMethod(r, m[3], v2.ValidateSandboxServiceCreateRequest, v2.ValidateSandboxServiceCreateResponse),
		controlMethod(r, m[4], v2.ValidateSandboxServiceConfigureRequest, v2.ValidateSandboxServiceConfigureResponse),
		controlMethod(r, m[5], v2.ValidateSandboxServiceListRequest, v2.ValidateSandboxServiceListResponse),
		controlMethod(r, m[6], v2.ValidateSandboxServiceInspectRequest, v2.ValidateSandboxServiceInspectResponse),
		controlMethod(r, m[7], v2.ValidateRunServiceStartRequest, v2.ValidateRunServiceStartResponse),
		controlMethod(r, m[8], v2.ValidateRunServiceStopRequest, v2.ValidateRunServiceStopResponse),
		controlMethod(r, m[9], v2.ValidateRunServiceListRequest, v2.ValidateRunServiceListResponse),
		controlMethod(r, m[10], v2.ValidateRunServiceInspectRequest, v2.ValidateRunServiceInspectResponse),
		controlMethod(r, m[11], v2.ValidateResourceServiceGetBudgetRequest, v2.ValidateResourceServiceGetBudgetResponse),
		controlMethod(r, m[12], v2.ValidateResourceServiceSetPolicyRequest, v2.ValidateResourceServiceSetPolicyResponse),
	}
}

var errControlResult = errors.New("the node's typed control result was not valid for the selected operation")

func controlMethod[Q, R any, Request interface {
	*Q
	controlRequest
}, Response interface {
	*R
	controlResponse
}](r *managementRouter, selected routes.ManagementMethod, validRequest func(Request) bool, validResponse func(Response) bool) connect.Method {
	service, name, _ := strings.Cut(selected.ReceiptMethod(), ".")
	served := method[Q, Request, Response](name, selected.Path,
		func(ctx context.Context, call *ingress.Call, request Request) (Response, error) {
			var value controlResponse
			var failure error
			switch {
			case !validRequest(request), request.GetMeta() == nil, len(request.ProtoReflect().GetUnknown()) != 0:
				failure = arc.InvalidArgument("request", "typed_message_invalid")
			default:
				value, failure = r.route(ctx, call, selected, request, func(body []byte) (controlResponse, error) {
					return decodeControlResponse(body, Response(new(R)), request.GetMeta().GetCorrelationId(), validResponse)
				})
			}
			if failure == nil {
				return value.(Response), nil
			}
			reply := Response(new(R))
			var readback *connect.Error
			if errors.As(failure, &readback) {
				return reply, readback
			}
			body, err := arc.ReplyMessage(r.failure(ctx, call, failure))
			if err != nil {
				return reply, err
			}
			meta, err := proto.Marshal(ingress.ResponseMeta(call.Correlation))
			if err != nil {
				return reply, err
			}
			body = protowire.AppendBytes(protowire.AppendTag(body, 1, protowire.BytesType), meta)
			return reply, proto.Unmarshal(body, reply)
		})
	served.Spec.Schema = v2.File_arcforges_sandbox_v2_platform_proto.Services().ByName(protoreflect.Name(service)).
		Methods().ByName(protoreflect.Name(name))
	return served
}

func decodeControlResponse[Response controlResponse](body []byte, reply Response, correlation *foundationv1.Id,
	valid func(Response) bool) (Response, error) {
	if err := proto.Unmarshal(body, reply); err != nil || len(reply.ProtoReflect().GetUnknown()) != 0 ||
		!proto.Equal(reply.GetMeta().GetCorrelationId(), correlation) ||
		reply.GetError() != nil && !proto.Equal(reply.GetError().GetCorrelationId(), correlation) ||
		!valid(reply) && !validTerminalStopNoEffect(reply, valid) {
		return reply, errControlResult
	}
	return reply, nil
}

// Core's Stop on an already terminal Run succeeds without another effect.
// Check all other fields with the pinned shape validator and return the
// authenticated DID_NOT_HAPPEN unchanged. Only Stop uses this state pair.
func validTerminalStopNoEffect[Response controlResponse](reply Response, valid func(Response) bool) bool {
	var operation *v2.Operation
	switch typed := any(reply).(type) {
	case *v2.RunServiceStopResponse:
		operation = typed.GetValue().GetOperation()
		run := typed.GetValue().GetRun()
		if (run.GetState() != v2.RunState_RUN_STATE_EXITED && run.GetState() != v2.RunState_RUN_STATE_FAILED) ||
			!proto.Equal(run.GetRunId(), operation.GetAggregateId()) {
			return false
		}
	case *v2.NodeServiceGetOperationResponse:
		operation = typed.GetValue().GetOperation()
	default:
		return false
	}
	if operation.GetMethod() != "RunService.Stop" || operation.GetState() != v2.OperationState_OPERATION_STATE_SUCCEEDED ||
		operation.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN || operation.GetError() != nil {
		return false
	}
	if _, known := parseID(operation.GetAggregateId()); !known {
		return false
	}
	copy := proto.Clone(reply).(Response)
	switch typed := any(copy).(type) {
	case *v2.RunServiceStopResponse:
		operation = typed.GetValue().GetOperation()
	case *v2.NodeServiceGetOperationResponse:
		operation = typed.GetValue().GetOperation()
	}
	operation.Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED.Enum()
	return valid(copy)
}

func (r *managementRouter) route(ctx context.Context, call *ingress.Call, selected routes.ManagementMethod, request controlRequest,
	decodeResponse func([]byte) (controlResponse, error)) (controlResponse, error) {
	if err := checkMeta(request.GetMeta()); err != nil {
		return nil, err
	}
	target := call.RemoteTarget
	if target == nil {
		return nil, arc.InvalidArgument("target", "required")
	}
	node, enrollment, grant := platform.ID(target.Node), platform.ID(target.Enrollment), platform.ID(target.Grant)
	var protocol *platform.ID
	subject := &access.Subject{Kind: access.ObjectNode, ID: node[:], Owner: func(ctx context.Context) (string, bool, error) {
		var owner platform.ID
		err := r.db.InTx(ctx, "read exact V2 control target", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT n.user_id,p.protocol_epoch FROM fleet.node n
 LEFT JOIN management.node_protocol p ON (p.enrollment_id,p.node_id,p.account_id)=(n.enrollment_id,n.node_id,n.user_id)
 AND p.revoked_at IS NULL WHERE n.node_id=$1 AND n.enrollment_id=$2 AND n.revoked_at IS NULL`, node, enrollment).
				Scan(&owner, &protocol)
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return owner.String(), err == nil, err
	}}
	if _, err := r.access.AuthorizeSubject(ctx, call, subject); err != nil {
		return nil, err
	}
	account, err := accountOf(call)
	if err != nil {
		return nil, err
	}
	// The actor is the validated session identity's user, never a header.
	scope := management.Authority{Account: account.Caller.UserID, Actor: account.Caller.UserID, Node: node,
		Enrollment: enrollment, Grant: grant, GrantRevision: target.GrantRevision}
	switch typed := request.(type) {
	case *v2.SandboxServiceCreateRequest:
		if provision, ok := parseID(typed.GetProvisionGrantId()); !ok || provision != grant || typed.GetTemplateRevision().GetValue() < 1 {
			return nil, arc.InvalidArgument("provision_grant_id", "bound_template_required")
		}
	case *v2.SandboxServiceConfigureRequest:
		if typed.GetRepairError() {
			return nil, arc.PermissionDenied("sandbox_repair_local_only")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, routes.RoutedDeadline)
	defer cancel()
	if protocol == nil {
		return nil, r.admissionUnavailable(ctx, scope, selected, request, controlUpgradeRequired())
	}
	if r.transport == nil {
		return nil, r.admissionUnavailable(ctx, scope, selected, request, arc.NodeOffline(node[:], r.clock()))
	}
	channel, err := r.transport.V2ControlAuthority(ctx, scope.Account, node, enrollment, *protocol)
	if err != nil {
		return nil, r.admissionUnavailable(ctx, scope, selected, request, r.transportFailure(err, node))
	}
	if channel.AccountID != scope.Account || channel.NodeID != node || channel.EnrollmentID != enrollment ||
		channel.ProtocolEpoch != *protocol || channel.NodeOwnerEpoch == (platform.ID{}) {
		return nil, r.admissionUnavailable(ctx, scope, selected, request, arc.NodeOffline(node[:], r.clock()))
	}
	deadline, _ := ctx.Deadline()
	routed := management.V2ControlCall{Selector: management.V2ControlSelector(selected.Selector),
		ActorID: scope.Actor, OriginalOwnerEpoch: channel.NodeOwnerEpoch, GrantID: grant,
		GrantRevision: target.GrantRevision, Deadline: deadline}
	// The Center and Node use the same correlation. The intent digest below
	// removes that transport identity before serializing the typed request.
	correlation, ok := textID(call.Correlation.CorrelationID)
	if !ok {
		return nil, arc.InvalidArgument("meta.correlation_id", "malformed")
	}
	request.GetMeta().CorrelationId = id(correlation)
	routed.Body, err = proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return nil, arc.InvalidArgument("request", "typed_message_invalid")
	}
	lease := controlLease(channel)
	if selected.Mutation {
		return r.mutation(ctx, selected, scope, channel, lease, request, routed, decodeResponse)
	}
	if query, ok := request.(*v2.NodeServiceGetOperationRequest); ok {
		return r.reconcile(ctx, scope, channel, lease, query, routed, decodeResponse)
	}
	body, err := r.transport.CallV2(ctx, channel, routed, nil)
	if err != nil {
		return nil, r.transportFailure(err, node)
	}
	reply, err := decodeResponse(body)
	return reply, r.transportFailure(err, node)
}

// Admission refused before sending says nothing about an older attempt. A
// scoped metadata read can prove absence or no delivery, never authorize
// disclosure of a receipt whose original Node grant cannot be checked.
func (r *managementRouter) admissionUnavailable(ctx context.Context, scope management.Authority,
	selected routes.ManagementMethod, request controlRequest, unavailable error) error {
	var command *foundationv1.Id
	if query, ok := request.(*v2.NodeServiceGetOperationRequest); ok {
		command = query.GetCommandId()
	} else if selected.Mutation {
		command = request.GetMeta().GetCommandId()
	}
	commandID, valid := parseID(command)
	if !valid {
		return unavailable
	}
	_, receipt, err := r.receipts.InspectOriginal(ctx, scope, commandID)
	return controlAdmissionRefusal(receipt, err, unavailable)
}

func controlAdmissionRefusal(receipt management.Receipt, readErr, unavailable error) error {
	if errors.Is(readErr, pgx.ErrNoRows) || (readErr == nil && receipt.State == management.StateNotDelivered &&
		!receipt.MayHaveDelivered && receipt.DeliveryCount == 0 && receipt.FinalAt == nil &&
		receipt.Effect != nil && *receipt.Effect == management.EffectDidNotHappen) {
		return unavailable
	}
	return controlReadbackUnavailable()
}

func controlReadbackUnavailable() *connect.Error {
	return connect.NewError(connect.CodeUnavailable, "original_operation_readback_unavailable")
}

func controlLease(channel management.V2ControlAuthority) management.Lease {
	return management.Lease{Holder: channel.HubHolder, ChannelEpoch: channel.ConnectionID,
		ProtocolEpoch: channel.ProtocolEpoch, Fence: channel.HubFence}
}

func controlUpgradeRequired() *arc.Refusal {
	return &arc.Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, Code: "upgrade_required",
		State: "node", Reason: "typed_v2_control_required"}
}

func controlRetiredEpoch() *arc.Refusal {
	return &arc.Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT, Code: "owner_epoch_retired",
		State: "operation", Reason: "owner_epoch_retired"}
}

func (r *managementRouter) transportFailure(err error, node platform.ID) error {
	switch {
	case errors.Is(err, management.ErrV2ControlUpgradeRequired):
		return controlUpgradeRequired()
	case errors.Is(err, management.ErrV2ControlUnavailable), errors.Is(err, management.ErrLease):
		return arc.NodeOffline(node[:], r.clock())
	case errors.Is(err, errControlResult):
		return arc.NodeUnreachable(node[:], arc.UnreachableUnverifiable, false)
	case errors.Is(err, management.ErrV2ControlUncertain):
		return arc.NodeUnreachable(node[:], arc.UnreachableChannelClosed, false)
	default:
		return err
	}
}

func controlIntent(scope management.Authority, selected routes.ManagementMethod, request controlRequest) ([32]byte, error) {
	canonical := proto.Clone(request).(controlRequest)
	canonical.GetMeta().CorrelationId = nil
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(canonical)
	if err != nil {
		return [32]byte{}, err
	}
	digest := sha256.New()
	digest.Write([]byte("ArcForges Center operation intent v2\n"))
	digest.Write([]byte{selected.Selector})
	for _, identity := range [...]platform.ID{scope.Account, scope.Actor, scope.Node, scope.Enrollment, scope.Grant} {
		digest.Write(identity[:])
	}
	var revision [8]byte
	binary.BigEndian.PutUint64(revision[:], uint64(scope.GrantRevision))
	digest.Write(revision[:])
	digest.Write(body)
	return [32]byte(digest.Sum(nil)), nil
}

func (r *managementRouter) mutation(ctx context.Context, selected routes.ManagementMethod, scope management.Authority,
	channel management.V2ControlAuthority, lease management.Lease, request controlRequest, routed management.V2ControlCall,
	decodeResponse func([]byte) (controlResponse, error)) (controlResponse, error) {
	command, valid := parseID(request.GetMeta().GetCommandId())
	epochRequest, hasEpoch := request.(interface{ GetOwnerEpoch() *foundationv1.Id })
	if !valid || !hasEpoch {
		return nil, arc.InvalidArgument("meta.command_id", "required")
	}
	epoch, valid := parseID(epochRequest.GetOwnerEpoch())
	if !valid {
		return nil, arc.InvalidArgument("owner_epoch", "required")
	}
	if epoch != channel.NodeOwnerEpoch {
		return nil, controlRetiredEpoch()
	}
	digest, err := controlIntent(scope, selected, request)
	if err != nil {
		return nil, arc.InvalidArgument("request", "typed_message_invalid")
	}
	routed.CommandID, routed.OriginalOwnerEpoch = command, epoch
	now := r.clock().UTC().Truncate(time.Microsecond)
	identity := management.Identity{Account: scope.Account, Actor: scope.Actor, Node: scope.Node, Enrollment: scope.Enrollment,
		Grant: scope.Grant, GrantRevision: scope.GrantRevision, Command: command, OwnerEpoch: epoch, IntentSHA256: digest,
		Method: selected.ReceiptMethod(), CreatedAt: now, ReplayUntil: now.Add(r.replayWindow)}
	receipt, _, err := r.receipts.Reserve(ctx, identity, lease)
	switch {
	case errors.Is(err, management.ErrIdentityConflict), errors.Is(err, management.ErrLegacyCommand):
		return nil, arc.CommandIDReused()
	case errors.Is(err, management.ErrReplayExpired):
		return nil, r.admissionUnavailable(ctx, scope, selected, request,
			&arc.Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, Code: "expired",
				State: "operation", Reason: "replay_window_expired"})
	case errors.Is(err, store.ErrCommitUnknown):
		return nil, controlUnknown("admission_commit_uncertain")
	case err != nil:
		return nil, r.admissionUnavailable(ctx, scope, selected, request, r.transportFailure(err, scope.Node))
	}
	if receipt.FinalAt != nil || receipt.MayHaveDelivered {
		return nil, r.observeReplay(ctx, scope, channel, lease, routed, request.GetMeta())
	}

	var claimed atomic.Bool
	body, err := r.transport.CallV2(ctx, channel, routed, func(ctx context.Context, current management.V2ControlAuthority) (bool, error) {
		if current != channel {
			return false, management.ErrLease
		}
		_, accepted, err := r.receipts.MarkPossiblyDelivered(ctx, identity, lease, receipt)
		claimed.Store(accepted && err == nil)
		return accepted, err
	})
	if err != nil {
		// A concurrent exact request may own the first claim already. Do
		// not classify that other caller's delivery as not delivered.
		if errors.Is(err, management.ErrV2ControlNotClaimed) {
			return nil, r.observeReplay(ctx, scope, channel, lease, routed, request.GetMeta())
		}
		if claimed.Load() || errors.Is(err, management.ErrV2ControlUncertain) || errors.Is(err, store.ErrCommitUnknown) {
			r.retainUncertain(ctx, identity, lease)
			return nil, controlUnknown("no_verified_response")
		}
		settlement, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		confirmed, settleErr := r.receipts.MarkNotDelivered(settlement, identity, lease, receipt)
		if settleErr != nil || confirmed.State != management.StateNotDelivered || confirmed.MayHaveDelivered {
			r.logger.WarnContext(settlement, "V2 no-delivery settlement unavailable", "method", identity.Method, "operation", identity.Command.String())
			return nil, controlUnknown("no_delivery_not_confirmed")
		}
		return nil, r.transportFailure(err, scope.Node)
	}
	if !claimed.Load() {
		return nil, controlUnknown("unclaimed_result")
	}
	reply, err := decodeResponse(body)
	if err != nil {
		r.retainUncertain(ctx, identity, lease)
		return nil, controlUnknown("result_unverifiable")
	}
	observation, err := directControlObservation(identity, reply)
	if err != nil {
		r.retainUncertain(ctx, identity, lease)
		return nil, controlUnknown("result_identity_mismatch")
	}
	if observation.State == management.StateUnknown {
		r.retainUncertain(ctx, identity, lease)
	}
	if observation.State != management.StateAccepted && observation.State != management.StateUnknown {
		settlement, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if _, err = r.receipts.RecordResult(settlement, identity, lease, observation); err != nil {
			if failure := r.confirmControlDisclosure(ctx, identity, channel, routed, request.GetMeta(), observation, err); failure != nil {
				return nil, failure
			}
		}
	}
	return reply, nil
}

func (r *managementRouter) retainUncertain(ctx context.Context, identity management.Identity, lease management.Lease) {
	settlement, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if _, err := r.receipts.MarkUnknown(settlement, identity, lease); err != nil {
		r.logger.WarnContext(settlement, "V2 uncertain delivery settlement unavailable", "method", identity.Method, "operation", identity.Command.String())
	}
}

func controlUnknown(reason string) *arc.Refusal {
	return &arc.Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_EXECUTION, Code: "outcome_unknown",
		State: "operation", Reason: reason, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN,
		Retry: foundationv1.RetryMode_RETRY_MODE_RECONCILE, Reconcile: "NodeService.GetOperation"}
}

func (r *managementRouter) reconcile(ctx context.Context, scope management.Authority, channel management.V2ControlAuthority,
	lease management.Lease, request *v2.NodeServiceGetOperationRequest, routed management.V2ControlCall,
	decodeResponse func([]byte) (controlResponse, error)) (controlResponse, error) {
	command, validCommand := parseID(request.GetCommandId())
	epoch, validEpoch := parseID(request.GetOwnerEpoch())
	if !validCommand || !validEpoch {
		return nil, arc.InvalidArgument("operation", "identity_required")
	}
	identity, receipt, err := r.receipts.InspectOriginal(ctx, scope, command)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, arc.NotFound("operation", command[:])
	}
	if err != nil {
		return nil, err
	}
	if identity.OwnerEpoch != epoch {
		return nil, controlRetiredEpoch()
	}
	routed.CommandID, routed.OriginalOwnerEpoch = identity.Command, identity.OwnerEpoch
	body, err := r.transport.CallV2(ctx, channel, routed, nil)
	if err != nil {
		return nil, r.transportFailure(err, scope.Node)
	}
	reply, err := decodeResponse(body)
	if err != nil {
		return nil, r.transportFailure(err, scope.Node)
	}
	if reply.GetError() != nil {
		return reply, nil // No Node receipt was proved, including retired epoch.
	}
	typed := reply.(*v2.NodeServiceGetOperationResponse)
	observation, err := operationControlObservation(identity, typed, typed.GetValue().GetOperation())
	if err != nil {
		return nil, r.transportFailure(errControlResult, scope.Node)
	}
	if receipt.FinalAt != nil && (observation.State == management.StateAccepted || observation.State == management.StateUnknown ||
		receipt.Effect == nil || *receipt.Effect != observation.Effect) {
		return nil, controlReadbackUnavailable()
	}
	if receipt.FinalAt == nil && receipt.MayHaveDelivered && observation.State != management.StateAccepted && observation.State != management.StateUnknown {
		settlement, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if _, err = r.receipts.ReconcileResult(settlement, identity, lease, observation); err != nil {
			if failure := r.confirmControlDisclosure(ctx, identity, channel, routed, request.GetMeta(), observation, err); failure != nil {
				return nil, failure
			}
		}
	}
	return reply, nil
}

func (r *managementRouter) observeReplay(ctx context.Context, scope management.Authority, channel management.V2ControlAuthority,
	lease management.Lease, routed management.V2ControlCall, meta *foundationv1.RequestMeta) error {
	call, ok := ingress.CallFrom(ctx)
	if !ok {
		return arc.Unauthenticated()
	}
	if err := r.access.RecheckFeature(ctx, call, sandboxv2connect.NodeServiceGetOperationProcedure); err != nil {
		return controlReadbackUnavailable()
	}
	query, read, err := controlReadbackRequest(routed, meta)
	if err != nil {
		return controlReadbackUnavailable()
	}
	response, err := r.reconcile(ctx, scope, channel, lease, query, read, func(payload []byte) (controlResponse, error) {
		return decodeControlResponse(payload, &v2.NodeServiceGetOperationResponse{}, meta.GetCorrelationId(), v2.ValidateNodeServiceGetOperationResponse)
	})
	if err != nil {
		return controlReadbackUnavailable()
	}
	return controlReplayReadback(response.(*v2.NodeServiceGetOperationResponse))
}

func controlReplayReadback(observed *v2.NodeServiceGetOperationResponse) error {
	operation := observed.GetValue().GetOperation()
	if operation == nil {
		// A refusal to read makes no claim about the prior mutation's effect.
		return controlReadbackUnavailable()
	}
	if operation.GetResponseCompacted() {
		return controlCompacted(operation)
	}
	if operation.GetError() != nil && operation.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN {
		return &storedRefusal{operation.GetError()}
	}
	switch operation.GetState() {
	case v2.OperationState_OPERATION_STATE_SUCCEEDED, v2.OperationState_OPERATION_STATE_FAILED:
		return controlReconciled(observed)
	case v2.OperationState_OPERATION_STATE_ACCEPTED, v2.OperationState_OPERATION_STATE_UNKNOWN:
		return controlUnknown("original_operation_reconciliation_required")
	default:
		return controlReadbackUnavailable()
	}
}

func controlReadbackRequest(routed management.V2ControlCall, meta *foundationv1.RequestMeta) (*v2.NodeServiceGetOperationRequest, management.V2ControlCall, error) {
	query := &v2.NodeServiceGetOperationRequest{Meta: &foundationv1.RequestMeta{CorrelationId: meta.GetCorrelationId()},
		OwnerEpoch: id(routed.OriginalOwnerEpoch), CommandId: id(routed.CommandID)}
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(query)
	routed.Selector, routed.Body = 1, body
	return query, routed, err
}

// The durable send claim already prevents execution again. An interrupted
// metadata settlement can still disclose the verified result if both Center
// authority and the Node's read authorization are freshly confirmed.
func (r *managementRouter) confirmControlDisclosure(ctx context.Context, identity management.Identity,
	channel management.V2ControlAuthority, routed management.V2ControlCall, meta *foundationv1.RequestMeta,
	want management.Observation, settleErr error) error {
	r.logger.WarnContext(ctx, "V2 result metadata settlement unavailable", "method", identity.Method, "operation", identity.Command.String())
	unavailable := controlReadbackUnavailable()
	call, ok := ingress.CallFrom(ctx)
	if !ok || !retryableControlSettlement(settleErr) || ctx.Err() != nil {
		return unavailable
	}
	if err := r.recheckControlCaller(ctx, call); err != nil {
		return unavailable
	}
	if err := r.access.RecheckFeature(ctx, call, call.Policy.FullName); err != nil {
		return unavailable
	}
	if call.Policy.FullName != sandboxv2connect.NodeServiceGetOperationProcedure {
		if err := r.access.RecheckFeature(ctx, call, sandboxv2connect.NodeServiceGetOperationProcedure); err != nil {
			return unavailable
		}
	}
	_, read, err := controlReadbackRequest(routed, meta)
	if err != nil {
		return unavailable
	}
	body, err := r.transport.CallV2(ctx, channel, read, nil)
	if err != nil {
		return unavailable
	}
	observed, err := decodeControlResponse(body, &v2.NodeServiceGetOperationResponse{}, meta.GetCorrelationId(), v2.ValidateNodeServiceGetOperationResponse)
	if err != nil || observed.GetError() != nil {
		return unavailable
	}
	if actual, err := operationControlObservation(identity, observed, observed.GetValue().GetOperation()); err != nil ||
		!sameVerifiedEffect(want, actual) {
		return unavailable
	}
	return nil
}

func sameVerifiedEffect(want, actual management.Observation) bool {
	return want.Effect == actual.Effect && (want.State == actual.State ||
		want.State == management.StateRejected && actual.State == management.StateFailed) &&
		(want.ResultID == nil || actual.ResultID != nil && *want.ResultID == *actual.ResultID)
}

func retryableControlSettlement(err error) bool {
	return errors.Is(err, store.ErrUnavailable) || errors.Is(err, store.ErrTimeout) ||
		errors.Is(err, store.ErrContention) || errors.Is(err, store.ErrCommitUnknown)
}

func (r *managementRouter) recheckControlCaller(ctx context.Context, call *ingress.Call) error {
	account, err := accountOf(call)
	if err != nil {
		return err
	}
	credential := int16(1)
	if account.Caller.Browser {
		credential = 2
	}
	scope := session.ScopeAccount
	if account.Caller.Scope == session.ScopeMobileLimited.String() {
		scope = session.ScopeMobileLimited
	}
	return r.db.InTx(ctx, "recheck the typed control result recipient", store.TxOptions{ReadOnly: true}, func(ctx context.Context, tx pgx.Tx) error {
		var live bool
		return tx.QueryRow(ctx, `SELECT true FROM identity.session s
JOIN identity.user u USING(user_id) JOIN identity.account_security_state a USING(user_id)
JOIN device.device d ON d.device_id=s.device_id JOIN device.installation i ON i.installation_id=s.installation_id
WHERE s.session_id=$1 AND s.user_id=$2 AND s.device_id=$3 AND s.credential_kind=$4 AND s.scope=$5
AND u.state=$6 AND s.auth_epoch=$7 AND s.recovery_generation=$8
AND s.auth_epoch=a.auth_epoch AND s.recovery_generation=a.recovery_generation
AND s.revoked_at IS NULL AND d.revoked_at IS NULL AND i.revoked_at IS NULL
AND s.expires_at>clock_timestamp() AND ((s.credential_kind=1 AND s.access_expires_at>clock_timestamp())
OR (s.credential_kind=2 AND s.idle_expires_at>clock_timestamp()))`, account.Caller.SessionID, account.Caller.UserID,
			account.Caller.DeviceID, credential, scope, call.Caller.AccountState, account.Caller.AuthEpoch, account.Caller.RecoveryGeneration).Scan(&live)
	})
}

func controlCompacted(operation *v2.Operation) *arc.Refusal {
	refusal := &arc.Refusal{Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, Code: "receipt_compacted",
		State:  strings.TrimPrefix(operation.GetState().String(), "OPERATION_STATE_"),
		Reason: "original_response_compacted", Effect: operation.GetEffect(), Retry: foundationv1.RetryMode_RETRY_MODE_NEVER}
	if aggregate, valid := parseID(operation.GetAggregateId()); valid {
		refusal.Resource = &arc.Resource{Kind: controlAggregateKind(operation.GetMethod()), ID: aggregate[:]}
	}
	return refusal
}

func controlReconciled(observed *v2.NodeServiceGetOperationResponse) error {
	detail, err := connectproto.NewErrorDetail(observed)
	if err != nil {
		return err
	}
	return connect.NewError(connect.CodeFailedPrecondition, "original_operation_reconciled").WithDetail(detail)
}

func directControlObservation(identity management.Identity, reply controlResponse) (management.Observation, error) {
	if refusal := reply.GetError(); refusal != nil {
		switch refusal.GetEffect() {
		case foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN:
			return management.Observation{State: management.StateUnknown}, nil
		case foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN:
			return controlObservation(reply, management.StateRejected, management.EffectDidNotHappen, "", nil, refusal.GetCode())
		case foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED:
			return controlObservation(reply, management.StateFailed, management.EffectHappened, "", nil, refusal.GetCode())
		default:
			return management.Observation{}, errControlResult
		}
	}
	switch typed := reply.(type) {
	case *v2.SandboxServiceCreateResponse:
		sandbox := typed.GetValue().GetSandbox()
		if sandbox.GetState() == v2.SandboxState_SANDBOX_STATE_CREATING {
			return management.Observation{State: management.StateAccepted}, nil
		}
		return successfulControlObservation(reply, "sandbox", sandbox.GetSandboxId())
	case *v2.SandboxServiceConfigureResponse:
		return successfulControlObservation(reply, "sandbox", typed.GetValue().GetSandbox().GetSandboxId())
	case *v2.NodeServiceRevokeRemoteGrantResponse:
		return successfulControlObservation(reply, "operation", id(identity.Command))
	case *v2.RunServiceStartResponse:
		return operationControlObservation(identity, reply, typed.GetValue().GetOperation())
	case *v2.RunServiceStopResponse:
		return operationControlObservation(identity, reply, typed.GetValue().GetOperation())
	case *v2.ResourceServiceSetPolicyResponse:
		return operationControlObservation(identity, reply, typed.GetValue().GetOperation())
	default:
		return management.Observation{}, errControlResult
	}
}

func successfulControlObservation(reply controlResponse, kind string, aggregateID *foundationv1.Id) (management.Observation, error) {
	aggregate, valid := parseID(aggregateID)
	if !valid {
		return management.Observation{}, errControlResult
	}
	return controlObservation(reply, management.StateSucceeded, management.EffectHappened, kind, &aggregate, "")
}

func operationControlObservation(identity management.Identity, reply controlResponse, operation *v2.Operation) (management.Observation, error) {
	command, validCommand := parseID(operation.GetCommandId())
	epoch, validEpoch := parseID(operation.GetOwnerEpoch())
	if !validCommand || !validEpoch || command != identity.Command || epoch != identity.OwnerEpoch ||
		operation.GetMethod() != identity.Method {
		return management.Observation{}, errControlResult
	}
	switch operation.GetState() {
	case v2.OperationState_OPERATION_STATE_ACCEPTED:
		return management.Observation{State: management.StateAccepted}, nil
	case v2.OperationState_OPERATION_STATE_UNKNOWN:
		return management.Observation{State: management.StateUnknown}, nil
	case v2.OperationState_OPERATION_STATE_SUCCEEDED, v2.OperationState_OPERATION_STATE_FAILED:
		if operation.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN &&
			operation.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED {
			return management.Observation{}, errControlResult
		}
		state := management.StateSucceeded
		if operation.GetState() == v2.OperationState_OPERATION_STATE_FAILED {
			state = management.StateFailed
		}
		var kind string
		var aggregateID *platform.ID
		if aggregate, valid := parseID(operation.GetAggregateId()); valid {
			aggregateID = &aggregate
			kind = controlAggregateKind(identity.Method)
		}
		return controlObservation(reply, state, int16(operation.GetEffect()), kind, aggregateID, operation.GetError().GetCode())
	default:
		return management.Observation{}, errControlResult
	}
}

func controlAggregateKind(method string) string {
	switch method {
	case "SandboxService.Create", "SandboxService.Configure":
		return "sandbox"
	case "RunService.Start", "RunService.Stop":
		return "run"
	case "ResourceService.SetPolicy":
		return "policy"
	default:
		return "operation"
	}
}

func controlObservation(reply controlResponse, state, effect int16, kind string, aggregate *platform.ID, reason string) (management.Observation, error) {
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(reply)
	if err != nil {
		return management.Observation{}, errControlResult
	}
	return management.Observation{State: state, Effect: effect, ResultSHA256: sha256.Sum256(body), ResultKind: kind, ResultID: aggregate, Reason: reason}, nil
}
