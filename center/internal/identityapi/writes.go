// SPDX-License-Identifier: AGPL-3.0-only

package identityapi

import (
	"context"
	"errors"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The account's writes (AF-CTR-03 A1b): step-up, passkey registration, profile and credential changes, sign-out and session,
// credential and device revocation. Each authorizes the call with the operation table first; a write whose row names a receipt
// requires meta.command_id and runs at most once per account and command ID (platform.Execute, AD-0021 section 10): the step-up
// evidence it needs is consumed in its own transaction, a final refusal (retry NEVER) is kept by the receipt and answered to every
// replay, and any other refusal (step_up_required, rate_limited, overloaded) or failure rolls the receipt back, so the same command
// can succeed after the step-up or the wait its advice names. The receipt keeps the reply message without tokens and without an
// e-mail address (C1). A refusal decided before the receipt is not kept, and a replay is decided afresh (E6, F-4): the access
// check's (permission_denied, step_up_required), the request's validation (a RequestMeta naming a workspace, a missing
// meta.command_id, a missing patch, patch.avatar: not_offered, a missing credential, a missing flow_id, credential_id, session_id or
// device_id) and CompletePasskeyRegistration's not_found, expired, code_reused and credential: not_verified; of these only
// not_verified ends the flow (B5), so its identical replay answers STATE/expired. A duplicate of a registration whose first
// execution still runs answers RESOURCE/overloaded, and one refused just after that execution committed answers its receipt from a
// second lookup, or that lookup's own failure (B4, F-1).

// storedRefusal is a refusal a command receipt answered: the ArcError of the command's one execution, without a correlation id.
type storedRefusal struct{ value *foundationv1.ArcError }

func (r *storedRefusal) Error() string { return "the command was refused: " + r.value.GetCode() }

// identityCaller is the identity core's view of an authorized session call.
func identityCaller(call *ingress.Call) (identity.Caller, error) {
	userID, userOK := textID(call.Caller.UserID)
	sessionID, sessionOK := textID(call.Caller.SessionID)
	deviceID, deviceOK := textID(call.Caller.DeviceID)
	if !userOK || !sessionOK || !deviceOK {
		return identity.Caller{}, arc.Unauthenticated()
	}
	return identity.Caller{Request: anonymous(call), UserID: userID, SessionID: sessionID, DeviceID: deviceID, Scope: call.Caller.Scope,
		Browser: call.Caller.Credential == ingress.CredentialBrowserSession, AuthEpoch: call.Caller.AuthEpoch,
		RecoveryGeneration: int64(call.Caller.RecoveryGeneration)}, nil
}

// authorizeCaller decides a session call and returns its operation row and its caller.
func (s *Server) authorizeCaller(ctx context.Context, call *ingress.Call, meta *foundationv1.RequestMeta) (access.Operation, identity.Caller, error) {
	if err := checkMeta(meta); err != nil {
		return access.Operation{}, identity.Caller{}, err
	}
	operation, err := s.access.Authorize(ctx, call)
	if err != nil {
		return access.Operation{}, identity.Caller{}, err
	}
	caller, err := identityCaller(call)
	return operation, caller, err
}

// command is the receipt command of a write: the account's principal, meta.command_id (required), the method and the request
// message as transmitted without its correlation (platform.RequestDigestInput).
func command(call *ingress.Call, caller identity.Caller, meta *foundationv1.RequestMeta) (platform.Command, error) {
	commandID, ok := parseID(meta.GetCommandId())
	if !ok {
		return platform.Command{}, arc.InvalidArgument("meta.command_id", "required")
	}
	// B1: a retry with its own correlation is the same command; every other byte of the request decides whether it is.
	digested, err := platform.RequestDigestInput(call.Message)
	if err != nil {
		return platform.Command{}, err
	}
	return platform.Command{Principal: identity.Actor(caller.UserID), CommandID: commandID, Operation: call.Policy.FullName, Request: digested}, nil
}

// expectedRevision is meta.expected_rev, or nil when the request states none.
func expectedRevision(meta *foundationv1.RequestMeta) *int64 {
	if meta.GetExpectedRev() == nil || meta.GetExpectedRev().Value == nil {
		return nil
	}
	value := meta.GetExpectedRev().GetValue()
	return &value
}

// receipt is a write's Receipt value: its command, the revision it produced (when it changed one object) and its effect.
func receipt(command platform.Command, revision *int64) *foundationv1.Receipt {
	value := &foundationv1.Receipt{CommandId: id(command.CommandID), Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED.Enum()}
	if revision != nil {
		value.ResultRevision = &foundationv1.Revision{Value: proto.Int64(*revision)}
	}
	return value
}

// execute runs a receipt-guarded write once per command (platform.Execute) and decodes its outcome into value.
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

// required is an Id field the request must carry.
func required(field string, value *foundationv1.Id) (platform.ID, error) {
	parsed, ok := parseID(value)
	if !ok {
		return platform.ID{}, arc.InvalidArgument(field, "required")
	}
	return parsed, nil
}

func (s *Server) beginStepUp(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceBeginStepUpRequest) (*publicapiv1.IdentityServiceBeginStepUpResponse, error) {
	challenge, err := func() (identity.Challenge, error) {
		_, caller, err := s.authorizeCaller(ctx, call, request.GetMeta())
		if err != nil {
			return identity.Challenge{}, err
		}
		in := identity.StepUpBegin{Class: request.OperationClass, TargetHash: request.TargetHash}
		if request.Method != nil {
			method := int32(request.GetMethod())
			in.Method = &method
		}
		return s.identity.BeginStepUp(ctx, caller, in)
	}()
	response := &publicapiv1.IdentityServiceBeginStepUpResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceBeginStepUpResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceBeginStepUpResponse_Value{Value: &publicapiv1.IdentityServiceBeginStepUpValue{
		Challenge: authChallenge(challenge, s.identity.RelyingParty().RPID())}}
	return response, nil
}

func (s *Server) completeStepUp(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceCompleteStepUpRequest) (*publicapiv1.IdentityServiceCompleteStepUpResponse, error) {
	evidence, err := func() (identity.Evidence, error) {
		_, caller, err := s.authorizeCaller(ctx, call, request.GetMeta())
		if err != nil {
			return identity.Evidence{}, err
		}
		challengeID, err := required("flow_id", request.GetFlowId())
		if err != nil {
			return identity.Evidence{}, err
		}
		var proof identity.StepUpProof
		switch value := request.GetProof().GetProof().(type) {
		case *publicapiv1.AuthProof_Passkey:
			signed := assertion(value.Passkey)
			proof.Passkey = &signed
		case *publicapiv1.AuthProof_EmailCode:
			proof.EmailCode = &value.EmailCode
		case nil:
			return identity.Evidence{}, arc.InvalidArgument("proof", "required")
		default:
			return identity.Evidence{}, arc.InvalidArgument("proof", "not_offered")
		}
		return s.identity.CompleteStepUp(ctx, caller, challengeID, proof)
	}()
	response := &publicapiv1.IdentityServiceCompleteStepUpResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceCompleteStepUpResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceCompleteStepUpResponse_Value{Value: &publicapiv1.IdentityServiceCompleteStepUpValue{
		Evidence: &publicapiv1.StepUpEvidence{OperationClass: proto.String(evidence.Class), ExpiresAt: arc.Instant(evidence.ExpiresAt)}}}
	return response, nil
}

func (s *Server) updateProfile(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceUpdateProfileRequest) (*publicapiv1.IdentityServiceUpdateProfileResponse, error) {
	value, err := func() (*publicapiv1.IdentityServiceUpdateProfileValue, error) {
		_, caller, err := s.authorizeCaller(ctx, call, request.GetMeta())
		if err != nil {
			return nil, err
		}
		receiptCommand, err := command(call, caller, request.GetMeta())
		if err != nil {
			return nil, err
		}
		patch := request.GetPatch()
		switch {
		case patch == nil:
			return nil, arc.InvalidArgument("patch", "required")
		case patch.GetChange() != nil:
			return nil, arc.InvalidArgument("patch.avatar", "not_offered")
		}
		change := identity.ProfileChange{DisplayName: patch.DisplayName, Locale: patch.Locale, Timezone: patch.Timezone}
		expected := expectedRevision(request.GetMeta())
		// C1: the receipt keeps the profile without its primary e-mail address, which is stored in clear only as the subject of an
		// e-mail identity. The first answer is the profile the transaction read; a replay states the account's current address.
		var answer *publicapiv1.IdentityServiceUpdateProfileValue
		stored, err := execute(ctx, s, receiptCommand, &publicapiv1.IdentityServiceUpdateProfileValue{},
			func(ctx context.Context, tx pgx.Tx, _ time.Time) (*publicapiv1.IdentityServiceUpdateProfileValue, error) {
				profile, err := s.identity.UpdateProfile(ctx, tx, caller, change, expected)
				if err != nil {
					return nil, err
				}
				answer = &publicapiv1.IdentityServiceUpdateProfileValue{Profile: accountProfile(profile)}
				return withoutAddress(answer), nil
			})
		if err != nil {
			return nil, err
		}
		if answer != nil && proto.Equal(withoutAddress(answer), stored) {
			return answer, nil
		}
		current, err := s.identity.GetProfile(ctx, caller.UserID)
		if err != nil {
			return nil, err
		}
		stored.GetProfile().PrimaryEmail = current.PrimaryEmail
		return stored, nil
	}()
	response := &publicapiv1.IdentityServiceUpdateProfileResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceUpdateProfileResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceUpdateProfileResponse_Value{Value: value}
	return response, nil
}

// withoutAddress is an UpdateProfile reply as its receipt keeps it: without the primary e-mail address (C1).
func withoutAddress(value *publicapiv1.IdentityServiceUpdateProfileValue) *publicapiv1.IdentityServiceUpdateProfileValue {
	kept := proto.CloneOf(value)
	if kept.GetProfile() != nil {
		kept.Profile.PrimaryEmail = nil
	}
	return kept
}

func (s *Server) beginPasskeyRegistration(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceBeginPasskeyRegistrationRequest) (*publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse, error) {
	challenge, err := func() (identity.Challenge, error) {
		_, caller, err := s.authorizeCaller(ctx, call, request.GetMeta())
		if err != nil {
			return identity.Challenge{}, err
		}
		return s.identity.BeginRegistration(ctx, caller, request.DisplayName)
	}()
	response := &publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceBeginPasskeyRegistrationResponse_Value{Value: &publicapiv1.IdentityServiceBeginPasskeyRegistrationValue{
		Challenge: authChallenge(challenge, s.identity.RelyingParty().RPID())}}
	return response, nil
}

func (s *Server) completePasskeyRegistration(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceCompletePasskeyRegistrationRequest) (*publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse, error) {
	value, err := func() (*publicapiv1.IdentityServiceCompletePasskeyRegistrationValue, error) {
		_, caller, err := s.authorizeCaller(ctx, call, request.GetMeta())
		if err != nil {
			return nil, err
		}
		receiptCommand, err := command(call, caller, request.GetMeta())
		if err != nil {
			return nil, err
		}
		flowID, err := required("flow_id", request.GetFlowId())
		if err != nil {
			return nil, err
		}
		if request.GetCredential() == nil {
			return nil, arc.InvalidArgument("credential", "required")
		}
		// A replay is answered from the receipt before anything else, so it never counts an attempt or verifies again.
		outcome, found, err := platform.Lookup(ctx, s.db, receiptCommand)
		if err != nil || found {
			return decode(outcome, err, &publicapiv1.IdentityServiceCompletePasskeyRegistrationValue{})
		}
		registration, err := s.identity.PrepareRegistration(ctx, caller, flowID, creation(request.GetCredential()))
		if err != nil {
			// B4: a duplicate refused because its first execution held the flow's attempt answers that execution's receipt when it
			// committed meanwhile. The command may have committed, so a lookup that fails answers its own (retryable) failure, never
			// the refusal (F-1).
			if outcome, found, lookupErr := platform.Lookup(ctx, s.db, receiptCommand); lookupErr != nil || found {
				return decode(outcome, lookupErr, &publicapiv1.IdentityServiceCompletePasskeyRegistrationValue{})
			}
			return nil, err
		}
		value, err := execute(ctx, s, receiptCommand, &publicapiv1.IdentityServiceCompletePasskeyRegistrationValue{},
			func(ctx context.Context, tx pgx.Tx, now time.Time) (*publicapiv1.IdentityServiceCompletePasskeyRegistrationValue, error) {
				credential, err := s.identity.FinishRegistration(ctx, tx, caller, registration, now)
				if err != nil {
					return nil, err
				}
				return &publicapiv1.IdentityServiceCompletePasskeyRegistrationValue{Credential: credentialSummary(credential)}, nil
			})
		if err != nil {
			var stored *storedRefusal
			var refusal *arc.Refusal
			s.identity.AbandonRegistration(ctx, registration, errors.As(err, &stored) || errors.As(err, &refusal))
		}
		return value, err
	}()
	response := &publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceCompletePasskeyRegistrationResponse_Value{Value: value}
	return response, nil
}

func (s *Server) renameAuthIdentity(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceRenameAuthIdentityRequest) (*publicapiv1.IdentityServiceRenameAuthIdentityResponse, error) {
	value, err := func() (*publicapiv1.IdentityServiceRenameAuthIdentityValue, error) {
		_, caller, err := s.authorizeCaller(ctx, call, request.GetMeta())
		if err != nil {
			return nil, err
		}
		receiptCommand, err := command(call, caller, request.GetMeta())
		if err != nil {
			return nil, err
		}
		credentialID, err := required("credential_id", request.GetCredentialId())
		if err != nil {
			return nil, err
		}
		expected := expectedRevision(request.GetMeta())
		return execute(ctx, s, receiptCommand, &publicapiv1.IdentityServiceRenameAuthIdentityValue{},
			func(ctx context.Context, tx pgx.Tx, _ time.Time) (*publicapiv1.IdentityServiceRenameAuthIdentityValue, error) {
				credential, err := s.identity.RenameCredential(ctx, tx, caller, credentialID, request.Name, expected)
				if err != nil {
					return nil, err
				}
				return &publicapiv1.IdentityServiceRenameAuthIdentityValue{Credential: credentialSummary(credential)}, nil
			})
	}()
	response := &publicapiv1.IdentityServiceRenameAuthIdentityResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceRenameAuthIdentityResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceRenameAuthIdentityResponse_Value{Value: value}
	return response, nil
}

func (s *Server) removeAuthIdentity(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceRemoveAuthIdentityRequest) (*publicapiv1.IdentityServiceRemoveAuthIdentityResponse, error) {
	value, err := func() (*publicapiv1.IdentityServiceRemoveAuthIdentityValue, error) {
		operation, caller, err := s.authorizeCaller(ctx, call, request.GetMeta())
		if err != nil {
			return nil, err
		}
		receiptCommand, err := command(call, caller, request.GetMeta())
		if err != nil {
			return nil, err
		}
		credentialID, err := required("credential_id", request.GetCredentialId())
		if err != nil {
			return nil, err
		}
		return execute(ctx, s, receiptCommand, &publicapiv1.IdentityServiceRemoveAuthIdentityValue{},
			func(ctx context.Context, tx pgx.Tx, now time.Time) (*publicapiv1.IdentityServiceRemoveAuthIdentityValue, error) {
				if operation.NeedsEvidence(false) {
					if err := identity.ConsumeEvidence(ctx, tx, caller, identity.ClassRemoveCredential, credentialID, now); err != nil {
						return nil, err
					}
				}
				revision, err := s.identity.RemoveCredential(ctx, tx, caller, credentialID, now)
				if err != nil {
					return nil, err
				}
				return &publicapiv1.IdentityServiceRemoveAuthIdentityValue{Receipt: receipt(receiptCommand, &revision)}, nil
			})
	}()
	response := &publicapiv1.IdentityServiceRemoveAuthIdentityResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceRemoveAuthIdentityResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceRemoveAuthIdentityResponse_Value{Value: value}
	return response, nil
}

func (s *Server) revokeSession(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceRevokeSessionRequest) (*publicapiv1.IdentityServiceRevokeSessionResponse, error) {
	value, err := func() (*publicapiv1.IdentityServiceRevokeSessionValue, error) {
		operation, caller, err := s.authorizeCaller(ctx, call, request.GetMeta())
		if err != nil {
			return nil, err
		}
		receiptCommand, err := command(call, caller, request.GetMeta())
		if err != nil {
			return nil, err
		}
		sessionID, err := required("session_id", request.GetSessionId())
		if err != nil {
			return nil, err
		}
		own := sessionID == caller.SessionID
		if operation.NeedsUpgrade(call.Caller, own) {
			return nil, arc.StepUpRequired()
		}
		return execute(ctx, s, receiptCommand, &publicapiv1.IdentityServiceRevokeSessionValue{},
			func(ctx context.Context, tx pgx.Tx, now time.Time) (*publicapiv1.IdentityServiceRevokeSessionValue, error) {
				if operation.NeedsEvidence(own) {
					if err := identity.ConsumeEvidence(ctx, tx, caller, identity.ClassRevokeSession, sessionID, now); err != nil {
						return nil, err
					}
				}
				revision, err := s.identity.RevokeSession(ctx, tx, caller, sessionID, now)
				if err != nil {
					return nil, err
				}
				return &publicapiv1.IdentityServiceRevokeSessionValue{Receipt: receipt(receiptCommand, &revision)}, nil
			})
	}()
	response := &publicapiv1.IdentityServiceRevokeSessionResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceRevokeSessionResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceRevokeSessionResponse_Value{Value: value}
	return response, nil
}

func (s *Server) revokeAllSessions(ctx context.Context, call *ingress.Call, request *publicapiv1.IdentityServiceRevokeAllSessionsRequest) (*publicapiv1.IdentityServiceRevokeAllSessionsResponse, error) {
	value, err := func() (*publicapiv1.IdentityServiceRevokeAllSessionsValue, error) {
		operation, caller, err := s.authorizeCaller(ctx, call, request.GetMeta())
		if err != nil {
			return nil, err
		}
		receiptCommand, err := command(call, caller, request.GetMeta())
		if err != nil {
			return nil, err
		}
		return execute(ctx, s, receiptCommand, &publicapiv1.IdentityServiceRevokeAllSessionsValue{},
			func(ctx context.Context, tx pgx.Tx, now time.Time) (*publicapiv1.IdentityServiceRevokeAllSessionsValue, error) {
				if operation.NeedsEvidence(false) {
					if err := identity.ConsumeEvidence(ctx, tx, caller, identity.ClassRevokeAllSessions, caller.UserID, now); err != nil {
						return nil, err
					}
				}
				if _, err := s.identity.RevokeAllSessions(ctx, tx, caller, now); err != nil {
					return nil, err
				}
				return &publicapiv1.IdentityServiceRevokeAllSessionsValue{Receipt: receipt(receiptCommand, nil)}, nil
			})
	}()
	response := &publicapiv1.IdentityServiceRevokeAllSessionsResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.IdentityServiceRevokeAllSessionsResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.IdentityServiceRevokeAllSessionsResponse_Value{Value: value}
	return response, nil
}

func (s *Server) renameDevice(ctx context.Context, call *ingress.Call, request *publicapiv1.DeviceServiceRenameRequest) (*publicapiv1.DeviceServiceRenameResponse, error) {
	value, err := func() (*publicapiv1.DeviceServiceRenameValue, error) {
		_, caller, err := s.authorizeCaller(ctx, call, request.GetMeta())
		if err != nil {
			return nil, err
		}
		receiptCommand, err := command(call, caller, request.GetMeta())
		if err != nil {
			return nil, err
		}
		deviceID, err := required("device_id", request.GetDeviceId())
		if err != nil {
			return nil, err
		}
		expected := expectedRevision(request.GetMeta())
		return execute(ctx, s, receiptCommand, &publicapiv1.DeviceServiceRenameValue{},
			func(ctx context.Context, tx pgx.Tx, now time.Time) (*publicapiv1.DeviceServiceRenameValue, error) {
				view, err := s.identity.RenameDevice(ctx, tx, caller, deviceID, request.Name, expected, now)
				if err != nil {
					return nil, err
				}
				return &publicapiv1.DeviceServiceRenameValue{Device: deviceView(*view)}, nil
			})
	}()
	response := &publicapiv1.DeviceServiceRenameResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.DeviceServiceRenameResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.DeviceServiceRenameResponse_Value{Value: value}
	return response, nil
}

func (s *Server) revokeDevice(ctx context.Context, call *ingress.Call, request *publicapiv1.DeviceServiceRevokeRequest) (*publicapiv1.DeviceServiceRevokeResponse, error) {
	value, err := func() (*publicapiv1.DeviceServiceRevokeValue, error) {
		operation, caller, err := s.authorizeCaller(ctx, call, request.GetMeta())
		if err != nil {
			return nil, err
		}
		receiptCommand, err := command(call, caller, request.GetMeta())
		if err != nil {
			return nil, err
		}
		deviceID, err := required("device_id", request.GetDeviceId())
		if err != nil {
			return nil, err
		}
		own := deviceID == caller.DeviceID
		if operation.NeedsUpgrade(call.Caller, own) {
			return nil, arc.StepUpRequired()
		}
		return execute(ctx, s, receiptCommand, &publicapiv1.DeviceServiceRevokeValue{},
			func(ctx context.Context, tx pgx.Tx, now time.Time) (*publicapiv1.DeviceServiceRevokeValue, error) {
				if operation.NeedsEvidence(own) {
					if err := identity.ConsumeEvidence(ctx, tx, caller, identity.ClassRevokeDevice, deviceID, now); err != nil {
						return nil, err
					}
				}
				revision, err := s.identity.RevokeDevice(ctx, tx, caller, deviceID, now)
				if err != nil {
					return nil, err
				}
				return &publicapiv1.DeviceServiceRevokeValue{Receipt: receipt(receiptCommand, &revision)}, nil
			})
	}()
	response := &publicapiv1.DeviceServiceRevokeResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &publicapiv1.DeviceServiceRevokeResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &publicapiv1.DeviceServiceRevokeResponse_Value{Value: value}
	return response, nil
}
