// SPDX-License-Identifier: AGPL-3.0-only

package identityapi

import (
	"context"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"

	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
)

// Direct is the served methods called in process, with an admitted call and a typed request: the center's own account pages call the
// handlers the Connect transport calls, so a page's action is the API method's action with the same operation row
// (access.Authorize), the same step-up evidence, the same command receipt, the same rate-limit buckets and the same audit event.
// The call carries what the pipeline decides for a request: the method's policy, the caller of the cookie session, the
// correlation, the client address and the request message as transmitted (the receipt's digest input).
type Direct struct{ s *Server }

// Direct is the in-process view of the server's methods.
func (s *Server) Direct() Direct { return Direct{s} }

// GetProfile is IdentityService.GetProfile.
func (d Direct) GetProfile(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceGetProfileRequest) (*publicapiv1.IdentityServiceGetProfileResponse, error) {
	return d.s.getProfile(ctx, call, request)
}

// ListAuthIdentities is IdentityService.ListAuthIdentities.
func (d Direct) ListAuthIdentities(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceListAuthIdentitiesRequest) (*publicapiv1.IdentityServiceListAuthIdentitiesResponse, error) {
	return d.s.listAuthIdentities(ctx, call, request)
}

// ListSessions is IdentityService.ListSessions.
func (d Direct) ListSessions(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceListSessionsRequest) (*publicapiv1.IdentityServiceListSessionsResponse, error) {
	return d.s.listSessions(ctx, call, request)
}

// ListDevices is DeviceService.List.
func (d Direct) ListDevices(ctx context.Context, call *ingress.Call, request *publicapiv1.DeviceServiceListRequest) (*publicapiv1.DeviceServiceListResponse, error) {
	return d.s.listDevices(ctx, call, request)
}

// BeginStepUp is IdentityService.BeginStepUp.
func (d Direct) BeginStepUp(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceBeginStepUpRequest) (*publicapiv1.IdentityServiceBeginStepUpResponse, error) {
	return d.s.beginStepUp(ctx, call, request)
}

// CompleteStepUp is IdentityService.CompleteStepUp.
func (d Direct) CompleteStepUp(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceCompleteStepUpRequest) (*publicapiv1.IdentityServiceCompleteStepUpResponse, error) {
	return d.s.completeStepUp(ctx, call, request)
}

// BeginPasskeyRegistration is IdentityService.BeginPasskeyRegistration.
func (d Direct) BeginPasskeyRegistration(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceBeginPasskeyRegistrationRequest) (*publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse, error) {
	return d.s.beginPasskeyRegistration(ctx, call, request)
}

// CompletePasskeyRegistration is IdentityService.CompletePasskeyRegistration.
func (d Direct) CompletePasskeyRegistration(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest) (*publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse, error) {
	return d.s.completePasskeyRegistration(ctx, call, request)
}

// RenameAuthIdentity is IdentityService.RenameAuthIdentity.
func (d Direct) RenameAuthIdentity(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceRenameAuthIdentityRequest) (*publicapiv1.IdentityServiceRenameAuthIdentityResponse, error) {
	return d.s.renameAuthIdentity(ctx, call, request)
}

// RemoveAuthIdentity is IdentityService.RemoveAuthIdentity.
func (d Direct) RemoveAuthIdentity(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceRemoveAuthIdentityRequest) (*publicapiv1.IdentityServiceRemoveAuthIdentityResponse, error) {
	return d.s.removeAuthIdentity(ctx, call, request)
}

// RevokeSession is IdentityService.RevokeSession.
func (d Direct) RevokeSession(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceRevokeSessionRequest) (*publicapiv1.IdentityServiceRevokeSessionResponse, error) {
	return d.s.revokeSession(ctx, call, request)
}

// RevokeAllSessions is IdentityService.RevokeAllSessions.
func (d Direct) RevokeAllSessions(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceRevokeAllSessionsRequest) (*publicapiv1.IdentityServiceRevokeAllSessionsResponse, error) {
	return d.s.revokeAllSessions(ctx, call, request)
}

// RenameDevice is DeviceService.Rename.
func (d Direct) RenameDevice(ctx context.Context, call *ingress.Call, request *publicapiv1.DeviceServiceRenameRequest) (*publicapiv1.DeviceServiceRenameResponse, error) {
	return d.s.renameDevice(ctx, call, request)
}

// RevokeDevice is DeviceService.Revoke.
func (d Direct) RevokeDevice(ctx context.Context, call *ingress.Call, request *publicapiv1.DeviceServiceRevokeRequest) (*publicapiv1.DeviceServiceRevokeResponse, error) {
	return d.s.revokeDevice(ctx, call, request)
}

// Failure is the ArcError of an error a Direct method returned (a refusal as it is, any other error as the transport maps it:
// logged with the call's correlation id and answered INTERNAL, or RESOURCE/overloaded for a store that is down), nil for no error.
func (d Direct) Failure(ctx context.Context, call *ingress.Call, err error) *foundationv1.ArcError {
	return d.s.failure(ctx, call, err)
}

// ChallengeView is the contract AuthChallenge of a ceremony the account core started, for the pages that render it as JSON.
func ChallengeView(challenge identity.Challenge, rpID string) *publicapiv1.AuthChallenge {
	return authChallenge(challenge, rpID)
}
