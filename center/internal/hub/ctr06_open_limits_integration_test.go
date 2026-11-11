// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// Captured bytes are the exact synthetic-node payload sent over the actual
// signed channel; they contain no file content, credentials or real identities.
func captureCTR06450(t *testing.T, name string, body []byte) {
	t.Helper()
	if directory := os.Getenv("ARCFORGES_CTR06_450_CAPTURE"); directory != "" {
		if err := os.WriteFile(filepath.Join(directory, name+".bin"), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Real center, account authorization, PostgreSQL receipt/audit and channel
// signatures. The answering node and software key are synthetic, not a native
// file operation or a claim that a real filesystem limit was observed.
func TestCTR06SignedOpenLimitNamesAndFoundationShapes(t *testing.T) {
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
	for _, tc := range []struct {
		name, limit, maximum string
		valid, absent        bool
	}{
		{"write_alias", "existing_file_size_bytes", "4194304", true, false},
		{"write_alias_absent", "existing_file_size_bytes", "4194304", true, true},
		{"write_canonical", "file_existing_bytes", "4194304", true, false},
		{"write_open_spelling", "legacy.existing-file-limit", "4194304", true, false},
		{"write_wrong_max", "existing_file_size_bytes", "3", false, false},
		{"write_small_input", "other_write_bytes", "196608", false, false},
		{"write_canonical_no_fallback", "file_write_bytes", "4194304", false, false},
		{"write_bad_decimal", "file_existing_bytes", "4194304.00", false, false},
		{"write_bad_name", "existing file size", "4194304", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := platform.NewID()
			body := signedLimitResponse(tc.limit, tc.maximum)
			captureCTR06450(t, tc.name, body)
			answers <- body
			inner := &nodev1.FileServiceWriteFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
				Path: &nodev1.FilePath{WorkspaceId: idValue(platform.NewID()), Path: proto.String("open-" + tc.name + ".txt")},
				Data: []byte("x"), Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedSha256{ExpectedSha256: make([]byte, 32)}}
			if tc.absent {
				inner.Precondition = &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}
			}
			h.proveFor(issued, user, "fleet.writeNodeFile", node.node.ID)
			reply := &fleetv1.FleetServiceWriteNodeFileResponse{}
			h.rpc(fleetv1connect.FleetServiceWriteNodeFileProcedure, &fleetv1.FleetServiceWriteNodeFileRequest{
				Meta: inner.Meta, NodeId: idValue(node.node.ID), Request: mustMarshal(t, inner),
			}, issued.AccessToken, reply)
			<-calls
			record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, int16(relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE))
			if err != nil || record == nil || record.Final {
				t.Fatalf("non-final receipt: %+v %v", record, err)
			}
			if tc.valid {
				if reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), body) || record.State != fleet.RoutedFailed {
					t.Fatalf("valid signed refusal not forwarded: reply=%v receipt=%+v", reply, record)
				}
				if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND command_id=$1 AND (convert_from(payload,'UTF8')::jsonb->>'refusal')::int=$2", command, fleet.RefusalCode("resource/too_large")) != 1 {
					t.Fatal("valid refusal missing audit")
				}
			} else {
				if errorKey(reply.GetError()) != "STATE/node_unreachable" || reply.GetError().GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
					reply.GetError().GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND || record.State != fleet.RoutedUnknown {
					t.Fatalf("invalid response settled: reply=%v receipt=%+v", reply, record)
				}
			}
			if h.count("SELECT count(*) FROM audit.audit_event WHERE command_id=$1 AND convert_from(payload,'UTF8') LIKE $2", command, "%"+tc.limit+"%") != 0 {
				t.Fatal("unverified label was persisted to audit")
			}
		})
	}
}

func TestCTR06SignedAmbiguousEditLimit(t *testing.T) {
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
	for _, tc := range []struct {
		name, limit, replacement string
		valid                    bool
	}{
		{"edit_alias_non_growing", "legacy_file_size", "x", true},
		{"edit_canonical_non_growing", "file_edit_result_bytes", "x", false},
		{"edit_canonical_growing", "file_edit_result_bytes", "xx", true},
		{"edit_wrong_canonical_method", "file_write_bytes", "xx", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			command := platform.NewID()
			var write nodev1.FileServiceWriteFileResponse
			if err := proto.Unmarshal(signedLimitResponse(tc.limit, "4194304"), &write); err != nil {
				t.Fatal(err)
			}
			body := mustMarshal(t, &nodev1.FileServiceEditFileResponse{Outcome: &nodev1.FileServiceEditFileResponse_Error{Error: write.GetError()}})
			captureCTR06450(t, tc.name, body)
			answers <- body
			inner := &nodev1.FileServiceEditFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
				Path:    &nodev1.FilePath{WorkspaceId: idValue(platform.NewID()), Path: proto.String("open-" + tc.name + ".txt")},
				OldText: proto.String("x"), NewText: proto.String(tc.replacement), ExpectedOccurrences: proto.Uint32(1), ExpectedSha256: make([]byte, 32)}
			h.proveFor(issued, user, "fleet.editNodeFile", node.node.ID)
			reply := &fleetv1.FleetServiceEditNodeFileResponse{}
			h.rpc(fleetv1connect.FleetServiceEditNodeFileProcedure, &fleetv1.FleetServiceEditNodeFileRequest{
				Meta: inner.Meta, NodeId: idValue(node.node.ID), Request: mustMarshal(t, inner),
			}, issued.AccessToken, reply)
			<-calls
			record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, int16(relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE))
			if err != nil || record == nil || record.Final {
				t.Fatalf("non-final receipt: %+v %v", record, err)
			}
			if tc.valid {
				if reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), body) || record.State != fleet.RoutedFailed {
					t.Fatalf("valid signed edit: reply=%v receipt=%+v", reply, record)
				}
			} else if errorKey(reply.GetError()) != "STATE/node_unreachable" || reply.GetError().GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN || record.State != fleet.RoutedUnknown {
				t.Fatalf("invalid signed edit: reply=%v receipt=%+v", reply, record)
			}
		})
	}
}

// The status is supplied by a software-key fixture; no node journal is
// fabricated or claimed. The center's real original-call receipt and its
// caller/target/raw-request-SHA authorization are exercised in PostgreSQL.
func TestCTR06SignedCompletedLimitStatusBindsOriginalReceipt(t *testing.T) {
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
	command, workspace := platform.NewID(), platform.NewID()
	path := &nodev1.FilePath{WorkspaceId: idValue(workspace), Path: proto.String("status-target.txt")}
	inner := &nodev1.FileServiceWriteFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
		Path: path, Data: []byte("PRIVATE-STATUS-BODY"), Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedSha256{ExpectedSha256: make([]byte, 32)}}
	request := mustMarshal(t, inner)
	raw := sha256.Sum256(request)
	answers <- signedLimitResponse("file_existing_bytes", "4194304")
	h.proveFor(issued, user, "fleet.writeNodeFile", node.node.ID)
	writeReply := &fleetv1.FleetServiceWriteNodeFileResponse{}
	h.rpc(fleetv1connect.FleetServiceWriteNodeFileProcedure, &fleetv1.FleetServiceWriteNodeFileRequest{
		Meta: inner.Meta, NodeId: idValue(node.node.ID), Request: request,
	}, issued.AccessToken, writeReply)
	<-calls
	if writeReply.GetError() != nil {
		t.Fatalf("original signed refusal: %v", writeReply)
	}
	now := time.Now().UTC()
	instant := &foundationv1.Instant{UnixSeconds: proto.Int64(now.Unix()), Nanos: proto.Uint32(uint32(now.Nanosecond()))}
	var errorResponse nodev1.FileServiceWriteFileResponse
	if err := proto.Unmarshal(signedLimitResponse("existing_file_size_bytes", "4194304"), &errorResponse); err != nil {
		t.Fatal(err)
	}
	operation := &nodev1.FileOperation{CommandId: idValue(command), Kind: nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE.Enum(),
		State: nodev1.FileOperationState_FILE_OPERATION_STATE_COMPLETED.Enum(), RequestSha256: raw[:], CreatedAt: instant, UpdatedAt: instant,
		Acknowledged: proto.Bool(false), Held: proto.Bool(false), Target: &nodev1.FileOperation_WorkspacePath{WorkspacePath: path},
		Outcome: &nodev1.FileOperation_Error{Error: errorResponse.GetError()}}
	statusRequest := mustMarshal(t, &nodev1.FileServiceGetFileOperationRequest{OperationCommandId: idValue(command)})
	send := func(op *nodev1.FileOperation, token string, name string) *fleetv1.FleetServiceGetNodeFileOperationResponse {
		t.Helper()
		body := mustMarshal(t, &nodev1.FileServiceGetFileOperationResponse{Outcome: &nodev1.FileServiceGetFileOperationResponse_Value{
			Value: &nodev1.FileServiceGetFileOperationValue{Operation: op}}})
		captureCTR06450(t, name, body)
		answers <- body
		reply := &fleetv1.FleetServiceGetNodeFileOperationResponse{}
		h.rpc(fleetv1connect.FleetServiceGetNodeFileOperationProcedure, &fleetv1.FleetServiceGetNodeFileOperationRequest{
			NodeId: idValue(node.node.ID), Request: statusRequest,
		}, token, reply)
		<-calls
		return reply
	}
	if reply := send(operation, issued.AccessToken, "status_alias"); reply.GetError() != nil {
		t.Fatalf("valid caller-bound status: %v", reply)
	}
	newSession := h.accountSession(user, session.ScopeAccount)
	if reply := send(operation, newSession.AccessToken, "status_same_account"); reply.GetError() != nil {
		t.Fatalf("same account new session: %v", reply)
	}
	for _, tc := range []struct {
		name   string
		change func(*nodev1.FileOperation)
	}{
		{"status_wrong_hash", func(op *nodev1.FileOperation) { op.RequestSha256 = make([]byte, 32) }},
		{"status_wrong_target", func(op *nodev1.FileOperation) {
			op.Target = &nodev1.FileOperation_WorkspacePath{WorkspacePath: &nodev1.FilePath{WorkspaceId: idValue(workspace), Path: proto.String("foreign-target.txt")}}
		}},
		{"status_wrong_kind", func(op *nodev1.FileOperation) { op.Kind = nodev1.FileOperationKind_FILE_OPERATION_KIND_EDIT.Enum() }},
		{"status_wrong_max", func(op *nodev1.FileOperation) {
			op.GetError().GetDetails().GetLimit().Maximum.Value = proto.String("3")
		}},
		{"status_known_path", func(op *nodev1.FileOperation) {
			op.GetError().GetDetails().GetLimit().LimitName = proto.String("path_bytes")
			op.GetError().GetDetails().GetLimit().Maximum.Value = proto.String("4096")
		}},
		{"status_known_path_alias", func(op *nodev1.FileOperation) {
			op.GetError().GetDetails().GetLimit().LimitName = proto.String("legacy_path_bytes")
			op.GetError().GetDetails().GetLimit().Maximum.Value = proto.String("4096")
		}},
		{"status_bad_decimal", func(op *nodev1.FileOperation) {
			op.GetError().GetDetails().GetLimit().Maximum.Value = proto.String("4194304.00")
		}},
		{"status_acknowledged", func(op *nodev1.FileOperation) { op.Acknowledged = proto.Bool(true) }},
		{"status_unknown_wrong_error", func(op *nodev1.FileOperation) {
			op.State = nodev1.FileOperationState_FILE_OPERATION_STATE_UNKNOWN.Enum()
			op.Held = proto.Bool(true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := proto.Clone(operation).(*nodev1.FileOperation)
			tc.change(bad)
			reply := send(bad, issued.AccessToken, tc.name)
			if errorKey(reply.GetError()) != "STATE/node_unreachable" {
				t.Fatalf("unbound or invalid status exposed: %v", reply)
			}
		})
	}
	other := h.db.Account(1)
	stranger := h.accountSession(other, session.ScopeAccount)
	foreign := &fleetv1.FleetServiceGetNodeFileOperationResponse{}
	h.rpc(fleetv1connect.FleetServiceGetNodeFileOperationProcedure, &fleetv1.FleetServiceGetNodeFileOperationRequest{
		NodeId: idValue(node.node.ID), Request: statusRequest,
	}, stranger.AccessToken, foreign)
	if errorKey(foreign.GetError()) != "STATE/not_found" {
		t.Fatalf("foreign caller: %v", foreign)
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE convert_from(payload,'UTF8') LIKE '%PRIVATE-STATUS-BODY%' OR convert_from(payload,'UTF8') LIKE '%foreign-target.txt%'") != 0 {
		t.Fatal("body or foreign target leaked to audit")
	}
}
