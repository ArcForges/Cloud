// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// Real composed Go Center, PostgreSQL transactions/audit, session authorization,
// WebSocket and ES256 verification. nodetest is a synthetic software-key peer:
// its simulated FULL receipts are not native Node filesystem/ownership evidence.
func qualificationResponse(call *relayv1.ChannelCall, correlation *foundationv1.Id, reason string) *nodev1.FileServicePlanRemovalResponse {
	if correlation == nil {
		correlation = call.GetCallId()
	}
	failure := &foundationv1.ArcError{
		Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE.Enum(), Code: proto.String("invalid_state"),
		MessageKey: proto.String("error.state.invalid_state"), CorrelationId: correlation,
		Retry:   &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()},
		Effect:  foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(),
		Details: &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{State: &foundationv1.StateFailure{State: proto.String("file"), Reason: proto.String(reason)}}},
	}
	return &nodev1.FileServicePlanRemovalResponse{Meta: &foundationv1.ResponseMeta{CorrelationId: correlation},
		Outcome: &nodev1.FileServicePlanRemovalResponse_Error{Error: failure}, Audit: &nodev1.FileAuditMetadata{}}
}

func TestCTR06SignedAttemptQualificationReceiptAndExactReplay(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	foreign := h.accountSession(h.db.Account(1), session.ScopeAccount)
	responses := make(chan func(*relayv1.ChannelCall) []byte, 1)
	produced := make(chan []byte, 1)
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		body := (<-responses)(call)
		produced <- body
		return node.node.Executed(call, body), body, true
	})
	for _, reason := range []string{"attempt_references_unverified", "attempt_tracking_unverified"} {
		for _, explicit := range []bool{true, false} {
			name := reason + "/fallback"
			if explicit {
				name = reason + "/request_correlation"
			}
			t.Run(name, func(t *testing.T) {
				command := platform.NewID()
				meta := &foundationv1.RequestMeta{CommandId: idValue(command)}
				if explicit {
					meta.CorrelationId = idValue(platform.NewID())
				}
				inner := &nodev1.FileServicePlanRemovalRequest{Meta: meta, Target: &nodev1.FileServicePlanRemovalRequest_AttemptId{AttemptId: idValue(platform.NewID())}}
				raw := mustMarshal(t, inner)
				// Preserve a benign unknown field as evidence that hashing binds the
				// exact transmitted request, not a protobuf re-encoding.
				raw = protowire.AppendTag(raw, 199, protowire.VarintType)
				raw = protowire.AppendVarint(raw, 17)
				send := func(body func(*relayv1.ChannelCall) []byte) (*fleetv1.FleetServicePlanNodeRemovalResponse, *relayv1.ChannelCall, []byte) {
					responses <- body
					reply := &fleetv1.FleetServicePlanNodeRemovalResponse{}
					h.rpc(fleetv1connect.FleetServicePlanNodeRemovalProcedure, &fleetv1.FleetServicePlanNodeRemovalRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: raw}, issued.AccessToken, reply)
					return reply, <-calls, <-produced
				}
				reply, firstCall, wire := send(func(call *relayv1.ChannelCall) []byte {
					return mustMarshal(t, qualificationResponse(call, meta.CorrelationId, reason))
				})
				if reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), wire) {
					t.Fatalf("signed refusal not forwarded exactly: %v", reply.GetError())
				}
				var decoded nodev1.FileServicePlanRemovalResponse
				if err := proto.Unmarshal(wire, &decoded); err != nil {
					t.Fatal(err)
				}
				if !explicit && !bytes.Equal(decoded.GetError().GetCorrelationId().GetValue(), firstCall.GetCallId().GetValue()) {
					t.Fatal("fixture failed to use the actual first call ID")
				}
				read := func() *fleet.RoutedRecord {
					record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, int16(relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL))
					if err != nil || record == nil {
						t.Fatalf("receipt: %v", err)
					}
					return record
				}
				if record := read(); record.State != fleet.RoutedFailed || !record.Delivered || record.Final || record.Attempts != 1 {
					t.Fatalf("first refusal receipt: %+v", record)
				}
				if h.count("SELECT count(*) FROM fleet.routed_file_target WHERE account_id=$1 AND node_id=$2", user, node.node.ID) != 0 {
					t.Fatal("refusal manufactured a plan/operation lookup target")
				}
				exact := sha256.Sum256(raw)
				if h.count("SELECT count(*) FROM fleet.routed_file_call WHERE account_id=$1 AND command_id=$2 AND request_sha256=$3", user, command, exact[:]) != 1 {
					t.Fatal("receipt did not bind exact raw request")
				}
				replayed, secondCall, replayWire := send(func(*relayv1.ChannelCall) []byte { return wire })
				if bytes.Equal(firstCall.GetCallId().GetValue(), secondCall.GetCallId().GetValue()) || !bytes.Equal(replayWire, wire) {
					t.Fatal("fixture did not replay original bytes under a new call")
				}
				if !unknownSameCommand(replayed.GetError()) {
					t.Fatalf("later refusal settled earlier possible delivery: %v", replayed.GetError())
				}
				if record := read(); record.State != fleet.RoutedUnknown || record.Final || record.Attempts != 2 {
					t.Fatalf("refusal replay did not preserve conservative Center uncertainty: %+v", record)
				}
				if h.count(`SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1
					AND (convert_from(payload,'UTF8')::jsonb->>'refusal')::int=$2
					AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='true'
					AND CASE WHEN jsonb_typeof(convert_from(payload,'UTF8')::jsonb->'observations')='array'
 THEN jsonb_array_length(convert_from(payload,'UTF8')::jsonb->'observations')=0 ELSE true END`, command, int(fleet.RefusalCode("state/invalid_state"))) != 2 {
					t.Fatal("first refusal and original-byte replay were not both verified in content-free audit")
				}
				// A same-command change to an unknown protobuf field is still a
				// raw-byte mismatch and cannot reach the synthetic peer.
				changed := bytes.Clone(raw)
				changed[len(changed)-1] ^= 1
				bad := &fleetv1.FleetServicePlanNodeRemovalResponse{}
				h.rpc(fleetv1connect.FleetServicePlanNodeRemovalProcedure, &fleetv1.FleetServicePlanNodeRemovalRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: changed}, issued.AccessToken, bad)
				if errorKey(bad.GetError()) != "CONFLICT/command_id_reused" {
					t.Fatalf("raw command reuse: %v", bad.GetError())
				}
				select {
				case <-calls:
					t.Fatal("raw mismatch reached node")
				default:
				}
				// Account-session receipt identity is the account, as recordDigest
				// specifies. A different account cannot disclose or reuse it.
				h.rpc(fleetv1connect.FleetServicePlanNodeRemovalProcedure, &fleetv1.FleetServicePlanNodeRemovalRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: raw}, foreign.AccessToken, bad)
				if errorKey(bad.GetError()) != "STATE/not_found" {
					t.Fatalf("foreign account disclosed or reused receipt: %v", bad.GetError())
				}
				select {
				case <-calls:
					t.Fatal("foreign caller reached node")
				default:
				}
			})
		}
	}
}

func TestCTR06SignedAttemptQualificationRejectsContradictions(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	responses := make(chan func(*relayv1.ChannelCall) []byte, 1)
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		body := (<-responses)(call)
		return node.node.Executed(call, body), body, true
	})
	for _, name := range []string{"workspace_selector", "wrong_state", "wrong_correlation", "wrong_meta", "happened", "same_command", "retry_at", "reconcile", "resource", "native", "native_failure", "identity_changed"} {
		t.Run(name, func(t *testing.T) {
			command := platform.NewID()
			inner := &nodev1.FileServicePlanRemovalRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command), CorrelationId: idValue(platform.NewID())},
				Target: &nodev1.FileServicePlanRemovalRequest_AttemptId{AttemptId: idValue(platform.NewID())}}
			if name == "workspace_selector" {
				inner.Target = &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: &nodev1.FilePath{WorkspaceId: idValue(platform.NewID()), Path: proto.String("fixture")}}
			}
			responses <- func(call *relayv1.ChannelCall) []byte {
				x := qualificationResponse(call, inner.Meta.CorrelationId, "attempt_tracking_unverified")
				e, state := x.GetError(), x.GetError().GetDetails().GetState()
				switch name {
				case "wrong_state":
					state.State = proto.String("task")
				case "wrong_correlation":
					e.CorrelationId = idValue(platform.NewID())
				case "wrong_meta":
					x.Meta.CorrelationId = idValue(platform.NewID())
				case "happened":
					e.Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED.Enum()
				case "same_command":
					e.Retry.Mode = foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND.Enum()
				case "retry_at":
					e.Retry.RetryAt = &foundationv1.Instant{UnixSeconds: proto.Int64(1800000000), Nanos: proto.Uint32(0)}
				case "reconcile":
					e.Retry.ReconciliationOperation = proto.String("arbitrary")
				case "resource", "native":
					s := state.ProtoReflect()
					s.Mutable(s.Descriptor().Fields().ByName(protoreflect.Name(name)))
				case "native_failure":
					e.Code = proto.String("file_access_denied")
					e.MessageKey = proto.String("error.state.file_access_denied")
					state.Reason = proto.String("file_access_denied")
				case "identity_changed":
					e.Category = foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT.Enum()
					e.Code = proto.String("file_changed")
					e.MessageKey = proto.String("error.conflict.file_changed")
					state.Reason = proto.String("planned_tree_changed")
				}
				return mustMarshal(t, x)
			}
			reply := &fleetv1.FleetServicePlanNodeRemovalResponse{}
			h.rpc(fleetv1connect.FleetServicePlanNodeRemovalProcedure, &fleetv1.FleetServicePlanNodeRemovalRequest{Meta: inner.Meta, NodeId: idValue(node.node.ID), Request: mustMarshal(t, inner)}, issued.AccessToken, reply)
			<-calls
			record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, int16(relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL))
			if err != nil || record == nil {
				t.Fatalf("receipt: %v", err)
			}
			if name == "native_failure" || name == "identity_changed" {
				// Synthetic producer classification only: the center cannot observe
				// the native failure/change. It must preserve distinct legal errors.
				if reply.GetError() != nil || record.State != fleet.RoutedFailed {
					t.Fatal("distinct valid native-failure classification rejected")
				}
				var response nodev1.FileServicePlanRemovalResponse
				if err := proto.Unmarshal(reply.GetValue().GetResponse(), &response); err != nil {
					t.Fatal(err)
				}
				expected := "file_access_denied"
				if name == "identity_changed" {
					expected = "file_changed"
				}
				if response.GetError().GetCode() != expected {
					t.Fatal("known failure became qualification unknown")
				}
			} else if !unknownSameCommand(reply.GetError()) || record.State != fleet.RoutedUnknown || record.Final {
				t.Fatalf("malformed signed inner settled: error=%v record=%+v", reply.GetError(), record)
			}
			if h.count("SELECT count(*) FROM fleet.routed_file_target WHERE account_id=$1 AND node_id=$2", user, node.node.ID) != 0 {
				t.Fatal("refusal made plan target")
			}
		})
	}
}

func TestCTR06LaterQualificationCannotSettleLostPlanResult(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	inner := &nodev1.FileServicePlanRemovalRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
		Target: &nodev1.FileServicePlanRemovalRequest_AttemptId{AttemptId: idValue(platform.NewID())}}
	raw := mustMarshal(t, inner)
	lost := serve(t, node, channel, func(*relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		_ = channel.WS.CloseNow()
		return nil, nil, false
	})
	send := func() *fleetv1.FleetServicePlanNodeRemovalResponse {
		reply := &fleetv1.FleetServicePlanNodeRemovalResponse{}
		h.rpc(fleetv1connect.FleetServicePlanNodeRemovalProcedure, &fleetv1.FleetServicePlanNodeRemovalRequest{Meta: inner.Meta, NodeId: idValue(node.node.ID), Request: raw}, issued.AccessToken, reply)
		return reply
	}
	if first := send(); !unknownSameCommand(first.GetError()) {
		t.Fatalf("lost first result: %v", first.GetError())
	}
	<-lost
	eventually(t, 5*time.Second, func() bool { return !h.center.Hub.Connected(node.node.ID) })
	second := h.connectFiles(node)
	calls := serve(t, node, second, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		body := mustMarshal(t, qualificationResponse(call, nil, "attempt_references_unverified"))
		return node.node.Executed(call, body), body, true
	})
	if reply := send(); !unknownSameCommand(reply.GetError()) {
		t.Fatalf("later refusal erased prior uncertainty: %v", reply.GetError())
	}
	<-calls
	record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, int16(relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL))
	if err != nil || record == nil || record.State != fleet.RoutedUnknown || record.Final || record.Attempts != 2 {
		t.Fatalf("prior uncertainty lost: %+v %v", record, err)
	}
	if h.count(`SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1
		AND (convert_from(payload,'UTF8')::jsonb->>'refusal')::int=$2`, command, int(fleet.RefusalCode("state/invalid_state"))) != 1 {
		t.Fatal("later verified refusal missing from audit")
	}
}

func TestCTR06OuterQualificationCannotSettlePGReceipt(t *testing.T) {
	for _, reason := range []string{"attempt_references_unverified", "attempt_tracking_unverified", "capability_unavailable", "replay_window_passed"} {
		t.Run(reason, func(t *testing.T) {
			h := routedHarness(t)
			user := h.db.Account(1)
			node := h.enrollIn(user)
			channel := h.connectFiles(node)
			issued := h.accountSession(user, session.ScopeAccount)
			calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
				failure := qualificationResponse(call, nil, reason).GetError()
				return node.node.Refused(call, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY, failure), nil, true
			})
			command := platform.NewID()
			inner := &nodev1.FileServicePlanRemovalRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
				Target: &nodev1.FileServicePlanRemovalRequest_AttemptId{AttemptId: idValue(platform.NewID())}}
			reply := &fleetv1.FleetServicePlanNodeRemovalResponse{}
			h.rpc(fleetv1connect.FleetServicePlanNodeRemovalProcedure, &fleetv1.FleetServicePlanNodeRemovalRequest{Meta: inner.Meta, NodeId: idValue(node.node.ID), Request: mustMarshal(t, inner)}, issued.AccessToken, reply)
			<-calls
			record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, int16(relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL))
			if err != nil || record == nil {
				t.Fatalf("receipt: %v", err)
			}
			if reason == "attempt_references_unverified" || reason == "attempt_tracking_unverified" {
				if !unknownSameCommand(reply.GetError()) || record.State != fleet.RoutedUnknown || record.Final {
					t.Fatalf("fake outer qualification settled: %v %+v", reply.GetError(), record)
				}
				if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1 AND convert_from(payload,'UTF8')::jsonb->>'verified'='false'", command) != 1 {
					t.Fatal("fake outer outcome credited as verified")
				}
			} else if errorKey(reply.GetError()) != "STATE/invalid_state" || reply.GetError().GetDetails().GetState().GetReason() != reason ||
				reply.GetError().GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN ||
				reply.GetError().GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER {
				t.Fatalf("existing outer refusal changed: %v", reply.GetError())
			}
			if h.count("SELECT count(*) FROM fleet.routed_file_target WHERE account_id=$1 AND node_id=$2", user, node.node.ID) != 0 {
				t.Fatal("outer refusal produced a plan target")
			}
		})
	}
}
