// SPDX-License-Identifier: AGPL-3.0-only

package identityapi

import (
	"context"

	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

func (s *Server) getAccountDeletion(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceGetAccountDeletionRequest) (*publicapiv1.IdentityServiceGetAccountDeletionResponse, error) {
	value, err := func() (*identity.Lifecycle, error) {
		_, caller, err := s.authorizeCaller(ctx, call, request.GetMeta())
		if err != nil {
			return nil, err
		}
		item, err := s.identity.GetDeletion(ctx, caller)
		if err == nil && item == nil {
			return nil, arc.NotFound("account_deletion", caller.UserID[:])
		}
		return item, err
	}()
	response := &publicapiv1.IdentityServiceGetAccountDeletionResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceGetAccountDeletionResponse_Error{Error: failure}
		return response, nil
	}
	result := &publicapiv1.IdentityServiceGetAccountDeletionValue{}
	if value != nil {
		// No grace or purge date is promised before the external retention gates.
		result.Deletion = &publicapiv1.DeletionStatus{DeletionId: id(value.ID), State: proto.String(LifecycleState(value.State))}
	}
	response.Outcome = &publicapiv1.IdentityServiceGetAccountDeletionResponse_Value{Value: result}
	return response, nil
}

// LifecycleState is the public state of retained account lifecycle evidence.
func LifecycleState(state int16) string {
	switch state {
	case identity.LifecycleAwaitingProof:
		return "awaitingProof"
	case identity.LifecycleConfirmed:
		return "confirmed"
	case identity.LifecycleProcessing:
		return "processing"
	case identity.LifecycleCompleted:
		return "completed"
	case identity.LifecycleFailed:
		return "failed"
	case identity.LifecycleExpired:
		return "expired"
	case identity.LifecycleRevoked:
		return "revoked"
	}
	return "unknown"
}

func (s *Server) beginRecovery(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceBeginRecoveryRequest) (*publicapiv1.IdentityServiceBeginRecoveryResponse, error) {
	value, err := func() (identity.Challenge, error) {
		if err := s.anonymousCall(ctx, call, request.GetMeta()); err != nil {
			return identity.Challenge{}, err
		}
		if request.GetMethod() != publicapiv1.RecoveryMethod_RECOVERY_METHOD_EMAIL_CODE {
			return identity.Challenge{}, arc.InvalidArgument("method", "not_offered")
		}
		if request.GetAccountHint() != "" {
			return identity.Challenge{}, arc.InvalidArgument("account_hint", "not_offered")
		}
		installation, present := claim(request.GetInstallation())
		return s.identity.BeginRecovery(ctx, anonymous(call), identity.RecoveryBegin{Email: request.GetEmail(), Claim: installation, HasClaim: present})
	}()
	response := &publicapiv1.IdentityServiceBeginRecoveryResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceBeginRecoveryResponse_Error{Error: failure}
	} else {
		response.Outcome = &publicapiv1.IdentityServiceBeginRecoveryResponse_Value{Value: &publicapiv1.IdentityServiceBeginRecoveryValue{Challenge: authChallenge(value, s.identity.RelyingParty().RPID())}}
	}
	return response, nil
}

func (s *Server) completeRecovery(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceCompleteRecoveryRequest) (*publicapiv1.IdentityServiceCompleteRecoveryResponse, error) {
	var commandID platform.ID
	value, err := func() (identity.Lifecycle, error) {
		if err := s.anonymousCall(ctx, call, request.GetMeta()); err != nil {
			return identity.Lifecycle{}, err
		}
		flowID, err := required("flow_id", request.GetFlowId())
		if err != nil {
			return identity.Lifecycle{}, err
		}
		commandID, err = required("meta.command_id", request.GetMeta().GetCommandId())
		if err != nil {
			return identity.Lifecycle{}, err
		}
		proof, ok := request.GetProof().GetProof().(*publicapiv1.AuthProof_EmailCode)
		if !ok {
			return identity.Lifecycle{}, arc.InvalidArgument("proof", "not_offered")
		}
		replacement, ok := request.GetReplacement().GetReplacement().(*publicapiv1.CredentialReplacement_Passkey)
		if !ok {
			return identity.Lifecycle{}, arc.InvalidArgument("replacement", "not_offered")
		}
		return s.identity.CompleteRecovery(ctx, anonymous(call), identity.RecoveryComplete{FlowID: flowID, EmailCode: proof.EmailCode,
			Creation: creation(replacement.Passkey), CommandID: commandID})
	}()
	response := &publicapiv1.IdentityServiceCompleteRecoveryResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceCompleteRecoveryResponse_Error{Error: failure}
	} else {
		response.Outcome = &publicapiv1.IdentityServiceCompleteRecoveryResponse_Value{Value: &publicapiv1.IdentityServiceCompleteRecoveryValue{
			Receipt: receipt(platform.Command{CommandID: commandID}, &value.Revision)}}
	}
	return response, nil
}

// GetAccountDeletion is the safe status read; confirmation uses the revision-bound page protocol.
func (d Direct) GetAccountDeletion(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceGetAccountDeletionRequest) (*publicapiv1.IdentityServiceGetAccountDeletionResponse, error) {
	return d.s.getAccountDeletion(ctx, call, request)
}
