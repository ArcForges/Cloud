// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"context"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
)

// The browser node sign-in (part E1b): BeginNodeSignIn and CompleteNodeSignIn are anonymous (the node proves the flow with its
// one-use code, its PKCE verifier and its node key), GetNodeSignInFlow and ApproveNodeSignIn take an account session. None runs under
// a command receipt: Begin's meta.command_id is correlation only (every call starts a new flow), Complete presents a one-use secret,
// the approval's reply holds the one-use code (a result never holds a secret; the flow row is its idempotency state), and the review
// is a mark.

// account authorizes an account-session call and returns its account: the identity caller and how its session authenticated.
func (s *Server) account(ctx context.Context, call *ingress.Call, meta *foundationv1.RequestMeta) (access.Operation, fleet.Account, error) {
	if err := checkMeta(meta); err != nil {
		return access.Operation{}, fleet.Account{}, err
	}
	operation, err := s.access.Authorize(ctx, call)
	if err != nil {
		return access.Operation{}, fleet.Account{}, err
	}
	userID, userOK := textID(call.Caller.UserID)
	sessionID, sessionOK := textID(call.Caller.SessionID)
	deviceID, deviceOK := textID(call.Caller.DeviceID)
	if !userOK || !sessionOK || !deviceOK {
		return access.Operation{}, fleet.Account{}, arc.Unauthenticated()
	}
	method := int16(1)
	if call.Caller.AuthMethod == "email_code" {
		method = 2
	}
	caller := identity.Caller{Request: identity.Request{ClientIP: call.ClientIP, CorrelationID: request(call).CorrelationID}, UserID: userID, SessionID: sessionID,
		DeviceID: deviceID, Scope: call.Caller.Scope, Browser: call.Caller.Credential == ingress.CredentialBrowserSession, AuthEpoch: call.Caller.AuthEpoch,
		RecoveryGeneration: int64(call.Caller.RecoveryGeneration)}
	return operation, fleet.Account{Caller: caller, AuthMethod: method, AuthenticatedAt: call.Caller.AuthenticatedAt}, nil
}

// flowView is the contract view of a flow: the node as it described itself (its canonical version), the state and the times.
func flowView(view fleet.FlowView) *fleetv1.NodeSignInFlowView {
	return &fleetv1.NodeSignInFlowView{FlowId: id(view.FlowID), Node: &fleetv1.EnrollingNodeInfo{NodeId: id(view.NodeID), Name: proto.String(view.Name),
		Os: nodev1.OsFamily(view.OS).Enum(), Arch: nodev1.CpuArchitecture(view.Arch).Enum(), Version: proto.String(view.Version)},
		State: fleetv1.NodeSignInState(view.State).Enum(), CreatedAt: arc.Instant(view.CreatedAt), ExpiresAt: arc.Instant(view.ExpiresAt)}
}

func (s *Server) beginNodeSignIn(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceBeginNodeSignInRequest) (*fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse, error) {
	begun, err := func() (fleet.Begun, error) {
		if err := checkMeta(message.GetMeta()); err != nil {
			return fleet.Begun{}, err
		}
		if _, err := s.access.Authorize(ctx, call); err != nil {
			return fleet.Begun{}, err
		}
		in, err := fleet.ParseBegin(message)
		if err != nil {
			return fleet.Begun{}, err
		}
		return s.fleet.Begin(ctx, request(call), in)
	}()
	response := &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.NodeEnrollmentServiceBeginNodeSignInResponse_Value{Value: &fleetv1.NodeEnrollmentServiceBeginNodeSignInValue{
		FlowId: id(begun.FlowID), AuthorizeUrl: proto.String(begun.AuthorizeURL), ExpiresAt: arc.Instant(begun.ExpiresAt)}}
	return response, nil
}

func (s *Server) getNodeSignInFlow(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceGetNodeSignInFlowRequest) (*fleetv1.NodeEnrollmentServiceGetNodeSignInFlowResponse, error) {
	view, err := func() (fleet.FlowView, error) {
		_, account, err := s.account(ctx, call, message.GetMeta())
		if err != nil {
			return fleet.FlowView{}, err
		}
		flowID, ok := parseID(message.GetFlowId())
		if !ok {
			return fleet.FlowView{}, arc.InvalidArgument("flow_id", "required")
		}
		return s.fleet.Review(ctx, account, flowID)
	}()
	response := &fleetv1.NodeEnrollmentServiceGetNodeSignInFlowResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.NodeEnrollmentServiceGetNodeSignInFlowResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.NodeEnrollmentServiceGetNodeSignInFlowResponse_Value{Value: &fleetv1.NodeEnrollmentServiceGetNodeSignInFlowValue{Flow: flowView(view)}}
	return response, nil
}

func (s *Server) approveNodeSignIn(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceApproveNodeSignInRequest) (*fleetv1.NodeEnrollmentServiceApproveNodeSignInResponse, error) {
	decision, err := func() (fleet.Decision, error) {
		_, account, err := s.account(ctx, call, message.GetMeta())
		if err != nil {
			return fleet.Decision{}, err
		}
		flowID, ok := parseID(message.GetFlowId())
		if !ok {
			return fleet.Decision{}, arc.InvalidArgument("flow_id", "required")
		}
		// A decision names itself: an absent approve is refused rather than read as a denial (a center rule; the contract has no
		// validate rule on the field).
		if message.Approve == nil {
			return fleet.Decision{}, arc.InvalidArgument("approve", "required")
		}
		return s.fleet.Decide(ctx, request(call), account, flowID, message.GetApprove())
	}()
	response := &fleetv1.NodeEnrollmentServiceApproveNodeSignInResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.NodeEnrollmentServiceApproveNodeSignInResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.NodeEnrollmentServiceApproveNodeSignInResponse_Value{Value: &fleetv1.NodeEnrollmentServiceApproveNodeSignInValue{
		RedirectUrl: proto.String(decision.RedirectURL), Flow: flowView(decision.Flow)}}
	return response, nil
}

func (s *Server) completeNodeSignIn(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceCompleteNodeSignInRequest) (*fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse, error) {
	completed, err := func() (fleet.Completed, error) {
		if err := checkMeta(message.GetMeta()); err != nil {
			return fleet.Completed{}, err
		}
		if _, err := s.access.Authorize(ctx, call); err != nil {
			return fleet.Completed{}, err
		}
		in, err := fleet.ParseComplete(message)
		if err != nil {
			return fleet.Completed{}, err
		}
		return s.fleet.Complete(ctx, request(call), in)
	}()
	response := &fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse_Error{Error: failure}
		return response, nil
	}
	issued := completed.Enrolled.Session
	account := &fleetv1.AccountSummary{AccountId: id(completed.Account.ID), DisplayName: proto.String(completed.Account.DisplayName)}
	if completed.Account.EmailMasked != "" {
		account.EmailMasked = proto.String(completed.Account.EmailMasked)
	}
	response.Outcome = &fleetv1.NodeEnrollmentServiceCompleteNodeSignInResponse_Value{Value: &fleetv1.NodeEnrollmentServiceCompleteNodeSignInValue{
		Credentials: &fleetv1.NodeCredentials{RefreshToken: proto.String(issued.RefreshToken), AccessToken: proto.String(issued.AccessToken),
			AccessExpiresAt: arc.Instant(issued.AccessExpiresAt), Account: account, CommandKeys: publicKeys(completed.Enrolled.CommandKeys),
			EntitlementKeys: publicKeys(completed.Enrolled.EntitlementKeys), InstallationId: id(completed.Enrolled.InstallationID),
			SessionExpiresAt: arc.Instant(issued.ExpiresAt), AccessLifetimeMs: proto.Uint64(uint64(issued.AccessExpiresAt.Sub(issued.IssuedAt).Milliseconds()))},
	}}
	return response, nil
}
