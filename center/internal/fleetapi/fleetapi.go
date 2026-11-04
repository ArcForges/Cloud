// SPDX-License-Identifier: AGPL-3.0-only

// Package fleetapi serves the fleet surface's methods of arcforges.fleet.v1 NodeEnrollmentService over Connect (AF-CTR-04): it
// registers exactly the served methods (every other method of the service stays unregistered, so the ingress answers UNIMPLEMENTED
// and the Worker table has no row for it), authorizes each call with the operation table before anything else, maps the contract
// messages to package fleet and answers every refusal as the reply's ArcError with the call's correlation id. Part E1a serves
// RefreshNodeSession, ReportNodeInfo and SignOutNode, part E1b the browser sign-in (BeginNodeSignIn, GetNodeSignInFlow,
// ApproveNodeSignIn, CompleteNodeSignIn), part E2 the device-code sign-in (StartDeviceAuthorization, PollDeviceAuthorization,
// LookupDeviceCode, ApproveDeviceCode).
package fleetapi

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect/v2"
	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Server serves the fleet surface.
type Server struct {
	fleet  *fleet.Service
	access *access.Authorizer
	db     *store.DB
	clock  func() time.Time
	logger *slog.Logger
}

// New is the server of a fleet service.
func New(service *fleet.Service, authorizer *access.Authorizer, db *store.DB, clock func() time.Time, logger *slog.Logger) *Server {
	if clock == nil {
		clock = time.Now
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Server{fleet: service, access: authorizer, db: db, clock: clock, logger: logger}
}

// method is one served unary method: its contract descriptor and its handler.
func method[Request any, PRequest interface {
	*Request
	proto.Message
}, Response proto.Message](name, procedure string, handle func(context.Context, *ingress.Call, PRequest) (Response, error)) connect.Method {
	return connect.Method{
		Spec: connect.Spec{
			StreamType: connect.StreamTypeUnary, Procedure: procedure,
			Schema: fleetv1.File_arcforges_fleet_v1_fleet_proto.Services().ByName("NodeEnrollmentService").Methods().ByName(protoreflect.Name(name)),
		},
		Handler: func(ctx context.Context, _ connect.Spec, stream connect.ServerStream) error {
			request := PRequest(new(Request))
			if err := stream.Receive(request); err != nil {
				return err
			}
			call, ok := ingress.CallFrom(ctx)
			if !ok {
				return connect.NewError(connect.CodeInternal, "the call was not admitted by the ingress pipeline")
			}
			response, err := handle(ctx, call, request)
			if err != nil {
				return err
			}
			return stream.Send(response)
		},
	}
}

// Methods are exactly the served methods, in the order of routes.FleetMethods.
func (s *Server) Methods() []connect.Method {
	return []connect.Method{
		method("BeginNodeSignIn", fleetv1connect.NodeEnrollmentServiceBeginNodeSignInProcedure, s.beginNodeSignIn),
		method("GetNodeSignInFlow", fleetv1connect.NodeEnrollmentServiceGetNodeSignInFlowProcedure, s.getNodeSignInFlow),
		method("ApproveNodeSignIn", fleetv1connect.NodeEnrollmentServiceApproveNodeSignInProcedure, s.approveNodeSignIn),
		method("CompleteNodeSignIn", fleetv1connect.NodeEnrollmentServiceCompleteNodeSignInProcedure, s.completeNodeSignIn),
		method("StartDeviceAuthorization", fleetv1connect.NodeEnrollmentServiceStartDeviceAuthorizationProcedure, s.startDeviceAuthorization),
		method("PollDeviceAuthorization", fleetv1connect.NodeEnrollmentServicePollDeviceAuthorizationProcedure, s.pollDeviceAuthorization),
		method("LookupDeviceCode", fleetv1connect.NodeEnrollmentServiceLookupDeviceCodeProcedure, s.lookupDeviceCode),
		method("ApproveDeviceCode", fleetv1connect.NodeEnrollmentServiceApproveDeviceCodeProcedure, s.approveDeviceCode),
		method("RefreshNodeSession", fleetv1connect.NodeEnrollmentServiceRefreshNodeSessionProcedure, s.refreshNodeSession),
		method("ReportNodeInfo", fleetv1connect.NodeEnrollmentServiceReportNodeInfoProcedure, s.reportNodeInfo),
		method("SignOutNode", fleetv1connect.NodeEnrollmentServiceSignOutNodeProcedure, s.signOutNode),
	}
}

// storedRefusal is a refusal a command receipt answered: the ArcError of the command's one execution, without a correlation id.
type storedRefusal struct{ value *foundationv1.ArcError }

func (r *storedRefusal) Error() string { return "the command was refused: " + r.value.GetCode() }

// failure is the ArcError of an error, by the rules of the identity surface: a refusal as it is, a stored refusal with this call's
// correlation id, an effect write whose commit outcome is unknown and anything unexpected as INTERNAL/internal (UNKNOWN, NEVER;
// logged with the correlation id), a store that is down or contended as RESOURCE/overloaded.
func (s *Server) failure(ctx context.Context, call *ingress.Call, err error) *foundationv1.ArcError {
	if err == nil {
		return nil
	}
	var refusal *arc.Refusal
	var stored *storedRefusal
	switch {
	case errors.As(err, &stored):
		value := proto.Clone(stored.value).(*foundationv1.ArcError)
		value.CorrelationId = nil
		if call.Correlation.CorrelationID != "" {
			value.CorrelationId = &foundationv1.Id{Value: correlation.IDBytes(call.Correlation.CorrelationID)}
		}
		return value
	case errors.As(err, &refusal):
	case errors.Is(err, store.ErrCommitUnknown):
		s.logger.ErrorContext(ctx, "fleet call failed", "method", call.Policy.FullName, "correlationId", call.Correlation.CorrelationID, "error", err.Error())
		refusal = arc.Internal()
	case errors.Is(err, store.ErrUnavailable), errors.Is(err, store.ErrTimeout), errors.Is(err, store.ErrContention), errors.Is(err, store.ErrCanceled),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		var storeErr *store.Error
		if errors.As(err, &storeErr) && storeErr.Unanswered {
			s.logger.WarnContext(ctx, "an auxiliary commit went unanswered", "method", call.Policy.FullName, "correlationId",
				call.Correlation.CorrelationID, "operation", storeErr.Operation)
		}
		refusal = arc.Unavailable()
	default:
		s.logger.ErrorContext(ctx, "fleet call failed", "method", call.Policy.FullName, "correlationId", call.Correlation.CorrelationID, "error", err.Error())
		refusal = arc.Internal()
	}
	return refusal.Dated(s.clock()).ArcError(call.Correlation)
}

// checkMeta refuses a RequestMeta that names a workspace: node enrollment is account-scoped.
func checkMeta(meta *foundationv1.RequestMeta) error {
	if len(meta.GetWorkspaceId().GetValue()) > 0 {
		return arc.InvalidArgument("meta.workspace_id", "not_admitted")
	}
	return nil
}

func id(value platform.ID) *foundationv1.Id { return &foundationv1.Id{Value: value[:]} }

// parseID reads a contract Id: 16 bytes that are not all zero.
func parseID(value *foundationv1.Id) (platform.ID, bool) {
	var result platform.ID
	if value == nil || len(value.GetValue()) != len(result) {
		return platform.ID{}, false
	}
	copy(result[:], value.GetValue())
	return result, result != platform.ID{}
}

// textID reads the canonical text of an ID (the ingress caller's).
func textID(text string) (platform.ID, bool) {
	var result platform.ID
	raw := correlation.IDBytes(text)
	if len(raw) != len(result) {
		return platform.ID{}, false
	}
	copy(result[:], raw)
	return result, true
}

func request(call *ingress.Call) fleet.Request {
	request := fleet.Request{ClientIP: call.ClientIP}
	if correlationID, ok := textID(call.Correlation.CorrelationID); ok {
		request.CorrelationID = &correlationID
	}
	return request
}

// node authorizes a node-credential call (the operation table: node scope only, a restricted account's node only on its sign-out)
// and returns the node.
func (s *Server) node(ctx context.Context, call *ingress.Call, meta *foundationv1.RequestMeta) (fleet.Node, error) {
	if err := checkMeta(meta); err != nil {
		return fleet.Node{}, err
	}
	if _, err := s.access.Authorize(ctx, call); err != nil {
		return fleet.Node{}, err
	}
	userID, userOK := textID(call.Caller.UserID)
	sessionID, sessionOK := textID(call.Caller.SessionID)
	installationID, installationOK := textID(call.Caller.InstallationID)
	if !userOK || !sessionOK || !installationOK {
		return fleet.Node{}, arc.Unauthenticated()
	}
	return fleet.Node{UserID: userID, SessionID: sessionID, InstallationID: installationID}, nil
}

// command is the receipt command of a node write: the node's principal (its installation), meta.command_id (required), the method
// and the request as transmitted without its correlation.
func command(call *ingress.Call, node fleet.Node, meta *foundationv1.RequestMeta) (platform.Command, error) {
	commandID, ok := parseID(meta.GetCommandId())
	if !ok {
		return platform.Command{}, arc.InvalidArgument("meta.command_id", "required")
	}
	digested, err := platform.RequestDigestInput(call.Message)
	if err != nil {
		return platform.Command{}, err
	}
	return platform.Command{Principal: fleet.NodeActor(node.InstallationID), CommandID: commandID, Operation: call.Policy.FullName, Request: digested}, nil
}

func receipt(command platform.Command) *foundationv1.Receipt {
	return &foundationv1.Receipt{CommandId: id(command.CommandID), Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED.Enum()}
}

// execute runs a receipt-guarded write once per command (platform.Execute): a final refusal is kept and answered to every replay.
func execute[V proto.Message](ctx context.Context, s *Server, command platform.Command, value V, run func(ctx context.Context, tx pgx.Tx, now time.Time) (V, error)) (V, error) {
	outcome, err := platform.Execute(ctx, s.db, command, store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
		result, err := run(ctx, tx, s.clock().UTC().Truncate(time.Microsecond))
		if err != nil {
			var refusal *arc.Refusal
			if errors.As(err, &refusal) && refusal.Final() {
				encoded, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(refusal.ArcError(correlation.Context{}))
				if marshalErr != nil {
					return nil, marshalErr
				}
				return nil, &platform.Refusal{Code: refusal.Key(), Result: encoded}
			}
			return nil, err
		}
		return proto.MarshalOptions{Deterministic: true}.Marshal(result)
	})
	return decode(outcome, err, value)
}

// decode is the answer of a receipt outcome: the stored reply, the stored refusal (as *storedRefusal) or the failure.
func decode[V proto.Message](outcome platform.Outcome, err error, value V) (V, error) {
	var zero V
	switch {
	case errors.Is(err, platform.ErrCommandIDReused):
		return zero, arc.CommandIDReused()
	case errors.Is(err, platform.ErrCommandInProgress):
		return zero, arc.Unavailable()
	case err != nil:
		return zero, err
	case outcome.Succeeded:
		if err = proto.Unmarshal(outcome.Result, value); err != nil {
			return zero, err
		}
		return value, nil
	}
	refusal := &foundationv1.ArcError{}
	if err = proto.Unmarshal(outcome.Result, refusal); err != nil {
		return zero, err
	}
	return zero, &storedRefusal{value: refusal}
}

func publicKeys(keys []platform.SigningKey) []*fleetv1.PublicKey {
	result := make([]*fleetv1.PublicKey, 0, len(keys))
	for _, key := range keys {
		result = append(result, &fleetv1.PublicKey{Kid: proto.String(key.KID), Algorithm: proto.String(key.Algorithm), Key: key.PublicKey,
			NotBefore: arc.Instant(key.NotBefore), NotAfter: arc.Instant(key.NotAfter)})
	}
	return result
}

func (s *Server) refreshNodeSession(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceRefreshNodeSessionRequest) (*fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse, error) {
	refreshed, err := func() (fleet.Refreshed, error) {
		if err := checkMeta(message.GetMeta()); err != nil {
			return fleet.Refreshed{}, err
		}
		if _, err := s.access.Authorize(ctx, call); err != nil {
			return fleet.Refreshed{}, err
		}
		return s.fleet.Refresh(ctx, request(call), message.GetRefreshToken())
	}()
	response := &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse_Error{Error: failure}
		return response, nil
	}
	issued := refreshed.Session
	response.Outcome = &fleetv1.NodeEnrollmentServiceRefreshNodeSessionResponse_Value{Value: &fleetv1.NodeEnrollmentServiceRefreshNodeSessionValue{
		RefreshToken: proto.String(issued.RefreshToken), AccessToken: proto.String(issued.AccessToken), AccessExpiresAt: arc.Instant(issued.AccessExpiresAt),
		CommandKeys: publicKeys(refreshed.CommandKeys), EntitlementKeys: publicKeys(refreshed.EntitlementKeys), SessionExpiresAt: arc.Instant(issued.ExpiresAt),
		AccessLifetimeMs: proto.Uint64(uint64(issued.AccessExpiresAt.Sub(issued.IssuedAt).Milliseconds())),
	}}
	return response, nil
}

func (s *Server) reportNodeInfo(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceReportNodeInfoRequest) (*fleetv1.NodeEnrollmentServiceReportNodeInfoResponse, error) {
	value, err := func() (*fleetv1.NodeEnrollmentServiceReportNodeInfoValue, error) {
		node, err := s.node(ctx, call, message.GetMeta())
		if err != nil {
			return nil, err
		}
		receiptCommand, err := command(call, node, message.GetMeta())
		if err != nil {
			return nil, err
		}
		if message.GetNode() == nil {
			return nil, arc.InvalidArgument("node", "required")
		}
		nodeID, ok := parseID(message.GetNode().GetNodeId())
		if !ok {
			return nil, arc.InvalidArgument("node.node_id", "required")
		}
		info, err := fleet.ParseNodeInfo(message.GetNode())
		if err != nil {
			return nil, err
		}
		// F2: a replay of a committed report is answered with its receipt at once; only a command without one counts in the
		// installation's bucket.
		if outcome, found, err := platform.Lookup(ctx, s.db, receiptCommand); err != nil || found {
			return decode(outcome, err, &fleetv1.NodeEnrollmentServiceReportNodeInfoValue{})
		}
		if err = s.fleet.TakeReport(ctx, request(call), node); err != nil {
			return nil, err
		}
		return execute(ctx, s, receiptCommand, &fleetv1.NodeEnrollmentServiceReportNodeInfoValue{},
			func(ctx context.Context, tx pgx.Tx, now time.Time) (*fleetv1.NodeEnrollmentServiceReportNodeInfoValue, error) {
				if _, err := s.fleet.Report(ctx, tx, request(call), node, nodeID, info, now); err != nil {
					return nil, err
				}
				return &fleetv1.NodeEnrollmentServiceReportNodeInfoValue{Receipt: receipt(receiptCommand)}, nil
			})
	}()
	response := &fleetv1.NodeEnrollmentServiceReportNodeInfoResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.NodeEnrollmentServiceReportNodeInfoResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.NodeEnrollmentServiceReportNodeInfoResponse_Value{Value: value}
	return response, nil
}

func (s *Server) signOutNode(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceSignOutNodeRequest) (*fleetv1.NodeEnrollmentServiceSignOutNodeResponse, error) {
	value, err := func() (*fleetv1.NodeEnrollmentServiceSignOutNodeValue, error) {
		node, err := s.node(ctx, call, message.GetMeta())
		if err != nil {
			return nil, err
		}
		receiptCommand, err := command(call, node, message.GetMeta())
		if err != nil {
			return nil, err
		}
		return execute(ctx, s, receiptCommand, &fleetv1.NodeEnrollmentServiceSignOutNodeValue{},
			func(ctx context.Context, tx pgx.Tx, now time.Time) (*fleetv1.NodeEnrollmentServiceSignOutNodeValue, error) {
				if err := s.fleet.SignOut(ctx, tx, request(call), node, now); err != nil {
					return nil, err
				}
				return &fleetv1.NodeEnrollmentServiceSignOutNodeValue{Receipt: receipt(receiptCommand)}, nil
			})
	}()
	response := &fleetv1.NodeEnrollmentServiceSignOutNodeResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.NodeEnrollmentServiceSignOutNodeResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.NodeEnrollmentServiceSignOutNodeResponse_Value{Value: value}
	return response, nil
}
