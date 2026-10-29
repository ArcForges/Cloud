// SPDX-License-Identifier: AGPL-3.0-only

// Package identityapi serves the identity surface's methods of arcforges.publicapi.v1 IdentityService and DeviceService
// (AF-CTR-03 A1a and A1b) over Connect: it registers exactly the served methods (every other method of the two services stays
// unregistered, so the ingress answers UNIMPLEMENTED and the Worker table has no row for it), authorizes each session call with
// the operation table before anything else, maps the contract messages to the account core and answers every refusal as the
// reply's ArcError with the call's correlation id. Identity and device methods refuse a RequestMeta that names a workspace.
package identityapi

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect/v2"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/page"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Server serves the identity surface.
type Server struct {
	identity *identity.Service
	access   *access.Authorizer
	db       *store.DB
	clock    func() time.Time
	logger   *slog.Logger
}

// New is the server of an account core.
func New(service *identity.Service, authorizer *access.Authorizer, db *store.DB, clock func() time.Time, logger *slog.Logger) *Server {
	if clock == nil {
		clock = time.Now
	}
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Server{identity: service, access: authorizer, db: db, clock: clock, logger: logger}
}

// method is one served unary method: its contract descriptor and its handler.
func method[Request any, PRequest interface {
	*Request
	proto.Message
}, Response proto.Message](service, name, procedure string, handle func(context.Context, *ingress.Call, PRequest) (Response, error)) connect.Method {
	return connect.Method{
		Spec: connect.Spec{
			StreamType: connect.StreamTypeUnary, Procedure: procedure,
			Schema: publicapiv1.File_arcforges_publicapi_v1_identity_proto.Services().ByName(protoreflect.Name(service)).Methods().ByName(protoreflect.Name(name)),
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

// Methods are exactly the served methods, in the order of routes.IdentityMethods.
func (s *Server) Methods() []connect.Method {
	return []connect.Method{
		method("IdentityService", "BeginAuthentication", publicapiv1connect.IdentityServiceBeginAuthenticationProcedure, s.beginAuthentication),
		method("IdentityService", "CompleteAuthentication", publicapiv1connect.IdentityServiceCompleteAuthenticationProcedure, s.completeAuthentication),
		method("IdentityService", "RequestEmailCode", publicapiv1connect.IdentityServiceRequestEmailCodeProcedure, s.requestEmailCode),
		method("IdentityService", "RedeemEmailCode", publicapiv1connect.IdentityServiceRedeemEmailCodeProcedure, s.redeemEmailCode),
		method("IdentityService", "CompleteEnrollment", publicapiv1connect.IdentityServiceCompleteEnrollmentProcedure, s.completeEnrollment),
		method("IdentityService", "ListAuthProviders", publicapiv1connect.IdentityServiceListAuthProvidersProcedure, s.listAuthProviders),
		method("IdentityService", "RefreshSession", publicapiv1connect.IdentityServiceRefreshSessionProcedure, s.refreshSession),
		method("IdentityService", "GetProfile", publicapiv1connect.IdentityServiceGetProfileProcedure, s.getProfile),
		method("IdentityService", "ListAuthIdentities", publicapiv1connect.IdentityServiceListAuthIdentitiesProcedure, s.listAuthIdentities),
		method("IdentityService", "ListSessions", publicapiv1connect.IdentityServiceListSessionsProcedure, s.listSessions),
		method("DeviceService", "List", publicapiv1connect.DeviceServiceListProcedure, s.listDevices),
		method("IdentityService", "BeginStepUp", publicapiv1connect.IdentityServiceBeginStepUpProcedure, s.beginStepUp),
		method("IdentityService", "CompleteStepUp", publicapiv1connect.IdentityServiceCompleteStepUpProcedure, s.completeStepUp),
		method("IdentityService", "UpdateProfile", publicapiv1connect.IdentityServiceUpdateProfileProcedure, s.updateProfile),
		method("IdentityService", "BeginPasskeyRegistration", publicapiv1connect.IdentityServiceBeginPasskeyRegistrationProcedure, s.beginPasskeyRegistration),
		method("IdentityService", "CompletePasskeyRegistration", publicapiv1connect.IdentityServiceCompletePasskeyRegistrationProcedure,
			s.completePasskeyRegistration),
		method("IdentityService", "RenameAuthIdentity", publicapiv1connect.IdentityServiceRenameAuthIdentityProcedure, s.renameAuthIdentity),
		method("IdentityService", "RemoveAuthIdentity", publicapiv1connect.IdentityServiceRemoveAuthIdentityProcedure, s.removeAuthIdentity),
		method("IdentityService", "RevokeSession", publicapiv1connect.IdentityServiceRevokeSessionProcedure, s.revokeSession),
		method("IdentityService", "RevokeAllSessions", publicapiv1connect.IdentityServiceRevokeAllSessionsProcedure, s.revokeAllSessions),
		method("DeviceService", "Rename", publicapiv1connect.DeviceServiceRenameProcedure, s.renameDevice),
		method("DeviceService", "Revoke", publicapiv1connect.DeviceServiceRevokeProcedure, s.revokeDevice),
	}
}

// failure is the ArcError of an error: a refusal as it is, the call's effect write whose commit outcome is unknown as
// INTERNAL/internal with effect UNKNOWN and retry NEVER (F6), a store that is down or contended as RESOURCE/overloaded (an
// auxiliary transaction's unanswered commit included, D10), anything else as INTERNAL/internal (logged with the correlation id;
// store errors never carry row values).
func (s *Server) failure(ctx context.Context, call *ingress.Call, err error) *foundationv1.ArcError {
	if err == nil {
		return nil
	}
	var refusal *arc.Refusal
	var stored *storedRefusal
	switch {
	case errors.As(err, &stored):
		// A refusal a command receipt kept: the same ArcError for every replay, with this call's correlation id.
		value := proto.Clone(stored.value).(*foundationv1.ArcError)
		value.CorrelationId = nil
		if call.Correlation.CorrelationID != "" {
			value.CorrelationId = &foundationv1.Id{Value: correlation.IDBytes(call.Correlation.CorrelationID)}
		}
		return value
	case errors.As(err, &refusal):
	case errors.Is(err, store.ErrCommitUnknown):
		s.logger.ErrorContext(ctx, "identity call failed", "method", call.Policy.FullName, "correlationId", call.Correlation.CorrelationID, "error", err.Error())
		refusal = arc.CommitUnknown()
	case errors.Is(err, store.ErrUnavailable), errors.Is(err, store.ErrTimeout), errors.Is(err, store.ErrContention), errors.Is(err, store.ErrCanceled),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		var storeErr *store.Error
		if errors.As(err, &storeErr) && storeErr.Unanswered {
			// An auxiliary commit went unanswered: the call's effect did not happen, but the count, attempt or audit may have.
			s.logger.WarnContext(ctx, "an auxiliary commit went unanswered", "method", call.Policy.FullName, "correlationId",
				call.Correlation.CorrelationID, "operation", storeErr.Operation)
		}
		refusal = arc.Unavailable()
	default:
		s.logger.ErrorContext(ctx, "identity call failed", "method", call.Policy.FullName, "correlationId", call.Correlation.CorrelationID, "error", err.Error())
		refusal = arc.Internal()
	}
	return refusal.ArcError(call.Correlation)
}

// checkMeta refuses a RequestMeta that names a workspace (DC-19): identity and device methods are account-scoped.
func checkMeta(meta *foundationv1.RequestMeta) error {
	if len(meta.GetWorkspaceId().GetValue()) > 0 {
		return arc.InvalidArgument("meta.workspace_id", "not_admitted")
	}
	return nil
}

func anonymous(call *ingress.Call) identity.Request {
	request := identity.Request{ClientIP: call.ClientIP}
	if correlationID, ok := textID(call.Correlation.CorrelationID); ok {
		request.CorrelationID = &correlationID
	}
	return request
}

// authorize decides a session call and returns its account.
func (s *Server) authorize(ctx context.Context, call *ingress.Call, meta *foundationv1.RequestMeta) (platform.ID, error) {
	if err := checkMeta(meta); err != nil {
		return platform.ID{}, err
	}
	if _, err := s.access.Authorize(ctx, call); err != nil {
		return platform.ID{}, err
	}
	userID, ok := textID(call.Caller.UserID)
	if !ok {
		return platform.ID{}, arc.Unauthenticated()
	}
	return userID, nil
}

func (s *Server) anonymousCall(ctx context.Context, call *ingress.Call, meta *foundationv1.RequestMeta) error {
	if err := checkMeta(meta); err != nil {
		return err
	}
	_, err := s.access.Authorize(ctx, call)
	return err
}

func (s *Server) beginAuthentication(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceBeginAuthenticationRequest) (*publicapiv1.IdentityServiceBeginAuthenticationResponse, error) {
	challenge, err := func() (identity.Challenge, error) {
		if err := s.anonymousCall(ctx, call, request.GetMeta()); err != nil {
			return identity.Challenge{}, err
		}
		if request.Method == nil {
			return identity.Challenge{}, arc.InvalidArgument("method", "required")
		}
		if request.Purpose == nil {
			return identity.Challenge{}, arc.InvalidArgument("purpose", "required")
		}
		installation, present := claim(request.GetInstallation())
		return s.identity.BeginAuthentication(ctx, anonymous(call), identity.Begin{Method: int32(request.GetMethod()), Purpose: int32(request.GetPurpose()),
			LoginHint: request.LoginHint, ProviderID: request.ProviderId, Claim: installation, HasClaim: present})
	}()
	response := &publicapiv1.IdentityServiceBeginAuthenticationResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceBeginAuthenticationResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceBeginAuthenticationResponse_Value{Value: &publicapiv1.IdentityServiceBeginAuthenticationValue{
		Challenge: authChallenge(challenge, s.identity.RelyingParty().RPID())}}
	return response, nil
}

func (s *Server) completeAuthentication(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceCompleteAuthenticationRequest) (*publicapiv1.IdentityServiceCompleteAuthenticationResponse, error) {
	signedIn, err := func() (identity.SignedIn, error) {
		if err := s.anonymousCall(ctx, call, request.GetMeta()); err != nil {
			return identity.SignedIn{}, err
		}
		flowID, ok := parseID(request.GetFlowId())
		if !ok {
			return identity.SignedIn{}, arc.InvalidArgument("flow_id", "required")
		}
		switch proof := request.GetProof().GetProof().(type) {
		case *publicapiv1.AuthProof_Passkey:
			return s.identity.CompletePasskey(ctx, anonymous(call), flowID, assertion(proof.Passkey))
		case *publicapiv1.AuthProof_EmailCode:
			return s.identity.RedeemEmailCode(ctx, anonymous(call), flowID, proof.EmailCode)
		case nil:
			return identity.SignedIn{}, arc.InvalidArgument("proof", "required")
		default:
			return identity.SignedIn{}, arc.InvalidArgument("proof", "not_offered")
		}
	}()
	response := &publicapiv1.IdentityServiceCompleteAuthenticationResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceCompleteAuthenticationResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceCompleteAuthenticationResponse_Value{Value: &publicapiv1.IdentityServiceCompleteAuthenticationValue{
		Session: nativeSession(signedIn)}}
	return response, nil
}

func (s *Server) requestEmailCode(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceRequestEmailCodeRequest) (*publicapiv1.IdentityServiceRequestEmailCodeResponse, error) {
	challenge, err := func() (identity.Challenge, error) {
		if err := s.anonymousCall(ctx, call, request.GetMeta()); err != nil {
			return identity.Challenge{}, err
		}
		if request.Purpose == nil {
			return identity.Challenge{}, arc.InvalidArgument("purpose", "required")
		}
		if request.Email == nil {
			return identity.Challenge{}, arc.InvalidArgument("email", "required")
		}
		flowID, hasFlow := parseID(request.GetFlowId())
		return s.identity.RequestEmailCode(ctx, anonymous(call), flowID, hasFlow, request.GetEmail(), int32(request.GetPurpose()))
	}()
	response := &publicapiv1.IdentityServiceRequestEmailCodeResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceRequestEmailCodeResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceRequestEmailCodeResponse_Value{Value: &publicapiv1.IdentityServiceRequestEmailCodeValue{
		Challenge: authChallenge(challenge, s.identity.RelyingParty().RPID())}}
	return response, nil
}

func (s *Server) redeemEmailCode(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceRedeemEmailCodeRequest) (*publicapiv1.IdentityServiceRedeemEmailCodeResponse, error) {
	signedIn, err := func() (identity.SignedIn, error) {
		if err := s.anonymousCall(ctx, call, request.GetMeta()); err != nil {
			return identity.SignedIn{}, err
		}
		flowID, ok := parseID(request.GetFlowId())
		if !ok {
			return identity.SignedIn{}, arc.InvalidArgument("flow_id", "required")
		}
		return s.identity.RedeemEmailCode(ctx, anonymous(call), flowID, request.GetCode())
	}()
	response := &publicapiv1.IdentityServiceRedeemEmailCodeResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceRedeemEmailCodeResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceRedeemEmailCodeResponse_Value{Value: &publicapiv1.IdentityServiceRedeemEmailCodeValue{
		Session: nativeSession(signedIn)}}
	return response, nil
}

func (s *Server) completeEnrollment(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceCompleteEnrollmentRequest) (*publicapiv1.IdentityServiceCompleteEnrollmentResponse, error) {
	signedIn, err := func() (identity.SignedIn, error) {
		if err := s.anonymousCall(ctx, call, request.GetMeta()); err != nil {
			return identity.SignedIn{}, err
		}
		flowID, ok := parseID(request.GetFlowId())
		if !ok {
			return identity.SignedIn{}, arc.InvalidArgument("flow_id", "required")
		}
		var token string
		switch proof := request.GetProof().GetProof().(type) {
		case *publicapiv1.EnrollmentProof_LocalCode:
			token = proof.LocalCode
		case nil:
			return identity.SignedIn{}, arc.InvalidArgument("proof", "required")
		default:
			return identity.SignedIn{}, arc.InvalidArgument("proof", "not_offered")
		}
		var created *publicapiv1.WebAuthnCreation
		switch replacement := request.GetCredential().GetReplacement().(type) {
		case *publicapiv1.CredentialReplacement_Passkey:
			created = replacement.Passkey
		case nil:
			return identity.SignedIn{}, arc.InvalidArgument("credential", "required")
		default:
			return identity.SignedIn{}, arc.InvalidArgument("credential", "not_offered")
		}
		profile := request.GetProfile()
		if profile == nil {
			return identity.SignedIn{}, arc.InvalidArgument("profile", "required")
		}
		if profile.GetChange() != nil {
			return identity.SignedIn{}, arc.InvalidArgument("profile.avatar", "not_offered")
		}
		return s.identity.Bootstrap(ctx, anonymous(call), identity.Enrollment{FlowID: flowID, LocalCode: token, Creation: creation(created),
			DisplayName: profile.GetDisplayName(), Locale: profile.Locale, Timezone: profile.Timezone})
	}()
	response := &publicapiv1.IdentityServiceCompleteEnrollmentResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceCompleteEnrollmentResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceCompleteEnrollmentResponse_Value{Value: &publicapiv1.IdentityServiceCompleteEnrollmentValue{
		Session: nativeSession(signedIn)}}
	return response, nil
}

func (s *Server) listAuthProviders(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceListAuthProvidersRequest) (*publicapiv1.IdentityServiceListAuthProvidersResponse, error) {
	response := &publicapiv1.IdentityServiceListAuthProvidersResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, s.anonymousCall(ctx, call, request.GetMeta())); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceListAuthProvidersResponse_Error{Error: failure}
		return response, nil
	}
	value := &publicapiv1.IdentityServiceListAuthProvidersValue{}
	for _, provider := range s.identity.Providers() {
		value.Providers = append(value.Providers, providerView(provider))
	}
	response.Outcome = &publicapiv1.IdentityServiceListAuthProvidersResponse_Value{Value: value}
	return response, nil
}

func (s *Server) refreshSession(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceRefreshSessionRequest) (*publicapiv1.IdentityServiceRefreshSessionResponse, error) {
	signedIn, err := func() (identity.SignedIn, error) {
		if err := s.anonymousCall(ctx, call, request.GetMeta()); err != nil {
			return identity.SignedIn{}, err
		}
		installationID, ok := parseID(request.GetInstallationId())
		if !ok {
			return identity.SignedIn{}, arc.InvalidArgument("installation_id", "required")
		}
		return s.identity.Refresh(ctx, anonymous(call), request.GetRefreshToken(), installationID)
	}()
	response := &publicapiv1.IdentityServiceRefreshSessionResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceRefreshSessionResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceRefreshSessionResponse_Value{Value: &publicapiv1.IdentityServiceRefreshSessionValue{
		Session: nativeSession(signedIn)}}
	return response, nil
}

func (s *Server) getProfile(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceGetProfileRequest) (*publicapiv1.IdentityServiceGetProfileResponse, error) {
	profile, err := func() (identity.Profile, error) {
		userID, err := s.authorize(ctx, call, request.GetMeta())
		if err != nil {
			return identity.Profile{}, err
		}
		return s.identity.GetProfile(ctx, userID)
	}()
	response := &publicapiv1.IdentityServiceGetProfileResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceGetProfileResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceGetProfileResponse_Value{Value: &publicapiv1.IdentityServiceGetProfileValue{Profile: accountProfile(profile)}}
	return response, nil
}

func pageRequest(listing page.Listing, request *foundationv1.PageRequest) (page.Request, error) {
	if request == nil {
		return page.Request{}, arc.InvalidArgument("page", "required")
	}
	if len(request.GetCursor()) > 4096 {
		return page.Request{}, arc.InvalidCursor()
	}
	parsed, refusal := page.Parse(listing, request.GetCursor(), request.GetLimit(), request.Limit != nil)
	if refusal != nil {
		return page.Request{}, refusal
	}
	return parsed, nil
}

func (s *Server) listAuthIdentities(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceListAuthIdentitiesRequest) (*publicapiv1.IdentityServiceListAuthIdentitiesResponse, error) {
	var items []identity.Credential
	next := ""
	err := func() error {
		userID, err := s.authorize(ctx, call, request.GetMeta())
		if err != nil {
			return err
		}
		parsed, err := pageRequest(page.Credentials, request.GetPage())
		if err != nil {
			return err
		}
		items, next, err = s.identity.ListCredentials(ctx, userID, parsed)
		return err
	}()
	response := &publicapiv1.IdentityServiceListAuthIdentitiesResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceListAuthIdentitiesResponse_Error{Error: failure}
		return response, nil
	}
	value := &publicapiv1.IdentityServiceListAuthIdentitiesValue{Page: pageState(next)}
	for _, item := range items {
		value.Items = append(value.Items, credentialSummary(item))
	}
	response.Outcome = &publicapiv1.IdentityServiceListAuthIdentitiesResponse_Value{Value: value}
	return response, nil
}

func (s *Server) listSessions(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceListSessionsRequest) (*publicapiv1.IdentityServiceListSessionsResponse, error) {
	var items []session.Summary
	next := ""
	err := func() error {
		userID, err := s.authorize(ctx, call, request.GetMeta())
		if err != nil {
			return err
		}
		parsed, err := pageRequest(page.Sessions, request.GetPage())
		if err != nil {
			return err
		}
		items, next, err = session.List(ctx, s.db, userID, call.Caller.SessionID, parsed, s.clock().UTC())
		return err
	}()
	response := &publicapiv1.IdentityServiceListSessionsResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceListSessionsResponse_Error{Error: failure}
		return response, nil
	}
	value := &publicapiv1.IdentityServiceListSessionsValue{Page: pageState(next)}
	for _, item := range items {
		value.Sessions = append(value.Sessions, sessionSummary(item))
	}
	response.Outcome = &publicapiv1.IdentityServiceListSessionsResponse_Value{Value: value}
	return response, nil
}

func (s *Server) listDevices(ctx context.Context, call *ingress.Call, request *publicapiv1.DeviceServiceListRequest) (*publicapiv1.DeviceServiceListResponse, error) {
	var items []device.View
	next := ""
	err := func() error {
		userID, err := s.authorize(ctx, call, request.GetMeta())
		if err != nil {
			return err
		}
		parsed, err := pageRequest(page.Devices, request.GetPage())
		if err != nil {
			return err
		}
		items, next, err = device.List(ctx, s.db, userID, parsed, s.clock().UTC())
		return err
	}()
	response := &publicapiv1.DeviceServiceListResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.DeviceServiceListResponse_Error{Error: failure}
		return response, nil
	}
	value := &publicapiv1.DeviceServiceListValue{Page: pageState(next)}
	for _, item := range items {
		value.Items = append(value.Items, deviceView(item))
	}
	response.Outcome = &publicapiv1.DeviceServiceListResponse_Value{Value: value}
	return response, nil
}
