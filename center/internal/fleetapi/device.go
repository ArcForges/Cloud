// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"context"
	"errors"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The device-code sign-in (part E2): StartDeviceAuthorization and PollDeviceAuthorization are anonymous (the node proves the
// authorization with its device code and its node key), LookupDeviceCode and ApproveDeviceCode take an account session. Only the
// decision runs under a command receipt (of the account): Start's reply holds the device code (a result never holds a secret; its
// meta.command_id is correlation only), a poll presents a one-use secret, and a lookup is a review.

// userCode reads a request's user code (C0 validate: "8 characters from the code alphabet; separators ignored"): absent is
// user_code: required, anything else that does not normalize is user_code: pattern. Malformed input costs nothing.
func userCode(present bool, raw string) (string, error) {
	if !present {
		return "", arc.InvalidArgument("user_code", "required")
	}
	code, ok := fleet.NormalizeUserCode(raw)
	if !ok {
		return "", arc.InvalidArgument("user_code", "pattern")
	}
	return code, nil
}

func (s *Server) startDeviceAuthorization(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationRequest) (*fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationResponse, error) {
	started, err := func() (fleet.Started, error) {
		if err := checkMeta(message.GetMeta()); err != nil {
			return fleet.Started{}, err
		}
		if _, err := s.access.Authorize(ctx, call); err != nil {
			return fleet.Started{}, err
		}
		in, err := fleet.ParseStart(message)
		if err != nil {
			return fleet.Started{}, err
		}
		return s.fleet.Start(ctx, request(call), in)
	}()
	response := &fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationResponse_Value{Value: &fleetv1.NodeEnrollmentServiceStartDeviceAuthorizationValue{
		Authorization: &fleetv1.DeviceAuthorization{DeviceCode: proto.String(started.DeviceCode), UserCode: proto.String(started.UserCode),
			VerificationUri: proto.String(started.VerificationURI), VerificationUriComplete: proto.String(started.VerificationURIComplete),
			IntervalMs: proto.Uint64(uint64(started.Interval.Milliseconds())), ExpiresAt: arc.Instant(started.ExpiresAt)}}}
	return response, nil
}

func (s *Server) pollDeviceAuthorization(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServicePollDeviceAuthorizationRequest) (*fleetv1.NodeEnrollmentServicePollDeviceAuthorizationResponse, error) {
	polled, err := func() (fleet.Polled, error) {
		if err := checkMeta(message.GetMeta()); err != nil {
			return fleet.Polled{}, err
		}
		if _, err := s.access.Authorize(ctx, call); err != nil {
			return fleet.Polled{}, err
		}
		in, err := fleet.ParsePoll(message)
		if err != nil {
			return fleet.Polled{}, err
		}
		return s.fleet.Poll(ctx, request(call), in)
	}()
	response := &fleetv1.NodeEnrollmentServicePollDeviceAuthorizationResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.NodeEnrollmentServicePollDeviceAuthorizationResponse_Error{Error: failure}
		return response, nil
	}
	value := &fleetv1.NodeEnrollmentServicePollDeviceAuthorizationValue{State: fleetv1.DeviceAuthorizationState(polled.State).Enum(),
		IntervalMs: proto.Uint64(uint64(polled.Interval.Milliseconds()))}
	if polled.Completed != nil {
		value.Credentials = nodeCredentials(*polled.Completed)
	}
	response.Outcome = &fleetv1.NodeEnrollmentServicePollDeviceAuthorizationResponse_Value{Value: value}
	return response, nil
}

// deviceView is the contract view of a looked-up authorization: the node as it described itself at Start (its canonical version).
func deviceView(view fleet.DeviceView) *fleetv1.EnrollingNodeInfo {
	return &fleetv1.EnrollingNodeInfo{NodeId: id(view.NodeID), Name: proto.String(view.Name), Os: nodev1.OsFamily(view.OS).Enum(),
		Arch: nodev1.CpuArchitecture(view.Arch).Enum(), Version: proto.String(view.Version)}
}

func (s *Server) lookupDeviceCode(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceLookupDeviceCodeRequest) (*fleetv1.NodeEnrollmentServiceLookupDeviceCodeResponse, error) {
	view, err := func() (fleet.DeviceView, error) {
		_, account, err := s.account(ctx, call, message.GetMeta())
		if err != nil {
			return fleet.DeviceView{}, err
		}
		code, err := userCode(message.UserCode != nil, message.GetUserCode())
		if err != nil {
			return fleet.DeviceView{}, err
		}
		entry, err := s.fleet.ReserveEntry(ctx, request(call), account, "lookup")
		if err != nil {
			return fleet.DeviceView{}, err
		}
		return s.fleet.Lookup(ctx, request(call), account, entry, code)
	}()
	response := &fleetv1.NodeEnrollmentServiceLookupDeviceCodeResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.NodeEnrollmentServiceLookupDeviceCodeResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.NodeEnrollmentServiceLookupDeviceCodeResponse_Value{Value: &fleetv1.NodeEnrollmentServiceLookupDeviceCodeValue{Node: deviceView(view)}}
	return response, nil
}

// accountCommand is the receipt command of an account's write: the account's principal (account:<id>), meta.command_id (required),
// the method and the request as transmitted without its correlation.
func accountCommand(call *ingress.Call, account fleet.Account, meta *foundationv1.RequestMeta) (platform.Command, error) {
	commandID, ok := parseID(meta.GetCommandId())
	if !ok {
		return platform.Command{}, arc.InvalidArgument("meta.command_id", "required")
	}
	digested, err := platform.RequestDigestInput(call.Message)
	if err != nil {
		return platform.Command{}, err
	}
	return platform.Command{Principal: identity.Actor(account.Caller.UserID), CommandID: commandID, Operation: call.Policy.FullName, Request: digested}, nil
}

// approveDeviceCode decides a user code under the account's command receipt. In this order: the operation table, meta.command_id,
// the user code and the presence of approve (a decision names itself: a center rule) are checked before anything is counted; a
// replay of a committed command is answered with its receipt at once and counts nothing; the decision is counted
// (node_approve_account) and the entry reserved; then the receipt's transaction decides (fleet.DecideDevice), and the entry is
// settled after it. A concurrent duplicate that the receipt answered gives its reservation back (it is no new entry).
func (s *Server) approveDeviceCode(ctx context.Context, call *ingress.Call, message *fleetv1.NodeEnrollmentServiceApproveDeviceCodeRequest) (*fleetv1.NodeEnrollmentServiceApproveDeviceCodeResponse, error) {
	value, err := func() (*fleetv1.NodeEnrollmentServiceApproveDeviceCodeValue, error) {
		operation, account, err := s.account(ctx, call, message.GetMeta())
		if err != nil {
			return nil, err
		}
		receiptCommand, err := accountCommand(call, account, message.GetMeta())
		if err != nil {
			return nil, err
		}
		code, err := userCode(message.UserCode != nil, message.GetUserCode())
		if err != nil {
			return nil, err
		}
		if message.Approve == nil {
			return nil, arc.InvalidArgument("approve", "required")
		}
		approve := message.GetApprove()
		if outcome, found, err := platform.Lookup(ctx, s.db, receiptCommand); err != nil || found {
			return decode(outcome, err, &fleetv1.NodeEnrollmentServiceApproveDeviceCodeValue{})
		}
		if err = s.fleet.TakeDecision(ctx, request(call), account); err != nil {
			return nil, err
		}
		entry, err := s.fleet.ReserveEntry(ctx, request(call), account, "device_decide")
		if err != nil {
			return nil, err
		}
		var decided error
		ran := false
		outcome, err := platform.Execute(ctx, s.db, receiptCommand, store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) ([]byte, error) {
			ran = true
			decided = s.fleet.DecideDevice(ctx, tx, request(call), account, entry, code, approve, operation.NeedsEvidenceToDecide(approve),
				s.clock().UTC().Truncate(time.Microsecond))
			if decided != nil {
				var refusal *arc.Refusal
				if errors.As(decided, &refusal) && refusal.Final() {
					encoded, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(refusal.ArcError(correlation.Context{}))
					if marshalErr != nil {
						return nil, marshalErr
					}
					return nil, &platform.Refusal{Code: refusal.Key(), Result: encoded}
				}
				return nil, decided
			}
			return proto.MarshalOptions{Deterministic: true}.Marshal(&fleetv1.NodeEnrollmentServiceApproveDeviceCodeValue{Receipt: receipt(receiptCommand)})
		})
		switch {
		case err == nil && outcome.Replayed, !ran && err == nil:
			_ = s.fleet.GiveBack(ctx, entry)
		case err != nil:
			s.fleet.Settle(ctx, request(call), entry, err, "device_decide")
		default:
			s.fleet.Settle(ctx, request(call), entry, decided, "device_decide")
		}
		return decode(outcome, err, &fleetv1.NodeEnrollmentServiceApproveDeviceCodeValue{})
	}()
	response := &fleetv1.NodeEnrollmentServiceApproveDeviceCodeResponse{Meta: ingress.ResponseMeta(call.Correlation)}
	if failure := s.failure(ctx, call, err); failure != nil {
		response.Outcome = &fleetv1.NodeEnrollmentServiceApproveDeviceCodeResponse_Error{Error: failure}
		return response, nil
	}
	response.Outcome = &fleetv1.NodeEnrollmentServiceApproveDeviceCodeResponse_Value{Value: value}
	return response, nil
}
