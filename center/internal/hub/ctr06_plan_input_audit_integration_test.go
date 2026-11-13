// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// Real Go Center, authenticated session, PostgreSQL, ES256 channel and audit.
// The signed peer, source bytes and owner actor are isolated fixtures, not a
// native Node filesystem read, genuine owner decision or positive files E2E.
func TestCTR06SignedPlanOwnershipInputAuditAndReceipt(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	answers := make(chan []byte, 1)
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		body := <-answers
		return node.node.Executed(call, body), body, true
	})
	seededBody := []byte("synthetic-plan-input-body-849ac84b")
	digest := sha256.Sum256(seededBody)
	for _, tc := range []struct {
		name, limit, maximum string
		audit, available     string
		valid                bool
	}{
		{"canonical", "removal_ownership_input_bytes", "67108864", "valid", "", true},
		{"opaque", "opaque.actual.bound", "67108864", "valid", "", true},
		{"available_decimal", "removal_ownership_input_bytes", "67108864", "valid", "1.00", true},
		{"available_zero_fraction", "removal_ownership_input_bytes", "67108864", "valid", "0.0", true},
		{"available_negative_nonzero", "opaque.actual.bound", "67108864", "valid", "-1.00", true},
		{"available_leading_zero", "removal_ownership_input_bytes", "67108864", "valid", "01.0", false},
		{"available_negative_zero", "removal_ownership_input_bytes", "67108864", "valid", "-0.0", false},
		{"available_many_fractional", "removal_ownership_input_bytes", "67108864", "valid", "0.0000000001", false},
		{"no_observation", "removal_ownership_input_bytes", "67108864", "none", "", true},
		{"fractional", "removal_ownership_input_bytes", "67108864.00", "valid", "1.00", false},
		{"unequal", "removal_ownership_input_bytes", "67108864", "unequal", "", false},
		{"item_count", "removal_ownership_input_bytes", "67108864", "item_count", "", false},
		{"other_observation", "removal_ownership_input_bytes", "67108864", "other", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := platform.NewID()
			var write nodev1.FileServiceWriteFileResponse
			if err := proto.Unmarshal(signedLimitResponse(tc.limit, tc.maximum), &write); err != nil {
				t.Fatal(err)
			}
			failure := write.GetError()
			if tc.available != "" {
				failure.GetDetails().GetLimit().Available = &foundationv1.Decimal{Value: proto.String(tc.available)}
			}
			response := &nodev1.FileServicePlanRemovalResponse{
				Meta:    &foundationv1.ResponseMeta{CorrelationId: failure.CorrelationId},
				Outcome: &nodev1.FileServicePlanRemovalResponse_Error{Error: failure},
			}
			if tc.audit != "none" {
				observation := &nodev1.FileAuditObservation{
					Kind:      nodev1.FileAuditKind_FILE_AUDIT_KIND_INPUT_BYTES.Enum(),
					SizeBytes: proto.Uint64(uint64(len(seededBody))), DigestInputBytes: proto.Uint64(uint64(len(seededBody))), Sha256: digest[:],
				}
				if tc.audit == "unequal" {
					observation.DigestInputBytes = proto.Uint64(1)
				} else if tc.audit == "item_count" {
					observation.ItemCount = proto.Uint32(0)
				} else if tc.audit == "other" {
					observation.Kind = nodev1.FileAuditKind_FILE_AUDIT_KIND_OPERATION_METADATA.Enum()
				}
				response.Audit = &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{observation}}
			}
			responseBytes := mustMarshal(t, response)
			inner := &nodev1.FileServicePlanRemovalRequest{
				Meta: &foundationv1.RequestMeta{CommandId: idValue(command), CorrelationId: idValue(platform.NewID())},
				Target: &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: &nodev1.FilePath{
					WorkspaceId: idValue(platform.NewID()), Path: proto.String("fixture/tree"),
				}},
			}
			raw := mustMarshal(t, inner)
			send := func() *fleetv1.FleetServicePlanNodeRemovalResponse {
				answers <- responseBytes
				reply := &fleetv1.FleetServicePlanNodeRemovalResponse{}
				h.rpc(fleetv1connect.FleetServicePlanNodeRemovalProcedure, &fleetv1.FleetServicePlanNodeRemovalRequest{
					Meta: inner.Meta, NodeId: idValue(node.node.ID), Request: raw,
				}, issued.AccessToken, reply)
				<-calls
				return reply
			}
			reply := send()
			record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, int16(relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL))
			if err != nil || record == nil {
				t.Fatalf("routed receipt unavailable: %v", err)
			}
			if tc.valid {
				if reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), responseBytes) || record.State != fleet.RoutedFailed {
					t.Fatalf("verified inner refusal not preserved: reply=%v state=%v", reply, record.State)
				}
				if tc.audit == "none" {
					if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1 AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='false'", command) != 1 {
						t.Fatal("absent signed observation was invented")
					}
				} else {
					if h.count(`SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1
						AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='true'
						AND jsonb_array_length(convert_from(payload,'UTF8')::jsonb->'observations')=1
						AND (convert_from(payload,'UTF8')::jsonb->'observations'->0->>'kind')::int=2
						AND (convert_from(payload,'UTF8')::jsonb->'observations'->0->>'sizeBytes')::int=$2
						AND (convert_from(payload,'UTF8')::jsonb->'observations'->0->>'digestInputBytes')::int=$2
						AND convert_from(payload,'UTF8')::jsonb->'observations'->0->>'sha256'=$3
						AND NOT ((convert_from(payload,'UTF8')::jsonb->'observations'->0) ? 'itemCount')`,
						command, len(seededBody), hex.EncodeToString(digest[:])) != 1 {
						t.Fatal("signed node observation not preserved in the durable center audit")
					}
				}
				if tc.name == "canonical" || tc.name == "available_decimal" {
					replay := send()
					if errorKey(replay.GetError()) != "STATE/node_unreachable" ||
						replay.GetError().GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
						replay.GetError().GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND {
						t.Fatalf("resend must retain existing conservative outer uncertainty: %v", replay.GetError())
					}
					if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1 AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='true'", command) != 2 {
						t.Fatal("verified replay observation missing from audit")
					}
				}
			} else {
				if errorKey(reply.GetError()) != "STATE/node_unreachable" ||
					reply.GetError().GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
					record.State != fleet.RoutedUnknown {
					t.Fatalf("invalid signed inner result settled: %v", reply.GetError())
				}
				if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1 AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='false'", command) != 1 {
					t.Fatal("invalid result was credited with a node observation")
				}
			}
			if h.count("SELECT count(*) FROM audit.audit_event WHERE command_id=$1 AND position($2 in convert_from(payload,'UTF8'))>0", command, string(seededBody)) != 0 {
				t.Fatal("synthetic source content leaked into center audit")
			}
		})
	}
}

func TestCTR06PlanMissingSignedResultDoesNotInventInputAudit(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		_ = channel.WS.CloseNow() // close only this test-owned peer before it sends a result
		return nil, nil, false
	})
	command := platform.NewID()
	inner := &nodev1.FileServicePlanRemovalRequest{
		Meta: &foundationv1.RequestMeta{CommandId: idValue(command), CorrelationId: idValue(platform.NewID())},
		Target: &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: &nodev1.FilePath{
			WorkspaceId: idValue(platform.NewID()), Path: proto.String("fixture/no-result"),
		}},
	}
	reply := &fleetv1.FleetServicePlanNodeRemovalResponse{}
	h.rpc(fleetv1connect.FleetServicePlanNodeRemovalProcedure, &fleetv1.FleetServicePlanNodeRemovalRequest{
		Meta: inner.Meta, NodeId: idValue(node.node.ID), Request: mustMarshal(t, inner),
	}, issued.AccessToken, reply)
	<-calls
	if errorKey(reply.GetError()) != "STATE/node_unreachable" ||
		reply.GetError().GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN {
		t.Fatalf("missing result must retain uncertainty: %v", reply.GetError())
	}
	if h.count(`SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1
		AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='false'
		AND CASE WHEN jsonb_typeof(convert_from(payload,'UTF8')::jsonb->'observations')='array'
			THEN jsonb_array_length(convert_from(payload,'UTF8')::jsonb->'observations')=0 ELSE true END`, command) != 1 {
		t.Fatal("missing signed result acquired invented input audit")
	}
}

func TestCTR06SignedPlanInputAuditSuccessBindsTargetAndReplay(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	command, workspace, planID := platform.NewID(), platform.NewID(), platform.NewID()
	path := &nodev1.FilePath{WorkspaceId: idValue(workspace), Path: proto.String("fixture/input")}
	inner := &nodev1.FileServicePlanRemovalRequest{
		Meta:   &foundationv1.RequestMeta{CommandId: idValue(command), CorrelationId: idValue(platform.NewID())},
		Target: &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: path},
	}
	body := []byte("synthetic-signed-plan-source-527a")
	digest := sha256.Sum256(body)
	planDigest := sha256.Sum256([]byte("synthetic-plan-digest"))
	plan := &nodev1.FileRemovalPlan{
		PlanId: idValue(planID), Digest: planDigest[:],
		ExpiresAt: &foundationv1.Instant{UnixSeconds: proto.Int64(1800000000), Nanos: proto.Uint32(0)},
		Items: []*nodev1.FileRemovalItem{{Path: proto.String("fixture/input"), Kind: nodev1.FileEntryKind_FILE_ENTRY_KIND_FILE.Enum(),
			SizeBytes: proto.Uint64(uint64(len(body))), IdentitySha256: make([]byte, 32), OwnerVerified: proto.Bool(true)}},
		TotalBytes: proto.Uint64(uint64(len(body))), RequiresApproval: proto.Bool(true), QuarantineAvailable: proto.Bool(false),
		Risk: nodev1.RiskClass_RISK_CLASS_HIGH.Enum(), Target: &nodev1.FileRemovalPlan_WorkspacePath{WorkspacePath: path},
	}
	response := mustMarshal(t, &nodev1.FileServicePlanRemovalResponse{
		Meta:    &foundationv1.ResponseMeta{CorrelationId: inner.Meta.CorrelationId},
		Outcome: &nodev1.FileServicePlanRemovalResponse_Value{Value: &nodev1.FileServicePlanRemovalValue{Plan: plan}},
		Audit: &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{
			Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_INPUT_BYTES.Enum(), SizeBytes: proto.Uint64(uint64(len(body))),
			DigestInputBytes: proto.Uint64(uint64(len(body))), Sha256: digest[:],
		}}},
	})
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		return node.node.Executed(call, response), response, true
	})
	raw := mustMarshal(t, inner)
	for index := 0; index < 2; index++ {
		reply := &fleetv1.FleetServicePlanNodeRemovalResponse{}
		h.rpc(fleetv1connect.FleetServicePlanNodeRemovalProcedure, &fleetv1.FleetServicePlanNodeRemovalRequest{
			Meta: inner.Meta, NodeId: idValue(node.node.ID), Request: raw,
		}, issued.AccessToken, reply)
		<-calls
		if reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), response) {
			t.Fatalf("verified plan or exact replay not forwarded: %v", reply.GetError())
		}
	}
	record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, int16(relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL))
	if err != nil || record == nil || record.State != fleet.RoutedSucceeded || !record.Final || !record.Delivered || record.Attempts != 2 {
		t.Fatalf("successful plan receipt/replay state: %+v %v", record, err)
	}
	if h.count("SELECT count(*) FROM fleet.routed_file_target WHERE target_kind=1 AND lookup_id=$1 AND account_id=$2 AND node_id=$3 AND workspace_id=$4 AND target_path='fixture/input'", planID, user, node.node.ID, workspace) != 1 {
		t.Fatal("verified plan target was not durably bound")
	}
	if h.count(`SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1
		AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='true'
		AND jsonb_array_length(convert_from(payload,'UTF8')::jsonb->'observations')=1
		AND (convert_from(payload,'UTF8')::jsonb->'observations'->0->>'kind')::int=2
		AND (convert_from(payload,'UTF8')::jsonb->'observations'->0->>'sizeBytes')::int=$2
		AND (convert_from(payload,'UTF8')::jsonb->'observations'->0->>'digestInputBytes')::int=$2
		AND convert_from(payload,'UTF8')::jsonb->'observations'->0->>'sha256'=$3
		AND NOT ((convert_from(payload,'UTF8')::jsonb->'observations'->0) ? 'itemCount')`,
		command, len(body), hex.EncodeToString(digest[:])) != 2 {
		t.Fatal("signed success and replay audit did not preserve the node observation")
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE command_id=$1 AND position($2 in convert_from(payload,'UTF8'))>0", command, string(body)) != 0 {
		t.Fatal("synthetic source content leaked into center audit")
	}
}
