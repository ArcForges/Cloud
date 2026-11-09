// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/jackc/pgx/v5"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// REAL composed center, gRPC-Web, PostgreSQL, WebSocket, signatures, ownership,
// authorization and receipt transactions. MOCKED node handlers/software keys and
// seeded step-up ceremony; no actual filesystem or native-node E2E is claimed.
func TestCTR06TwelveFleetMethodsUseTheRealSignedRoutingAndReceipts(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	workspace := platform.NewID()
	path := &nodev1.FilePath{WorkspaceId: idValue(workspace), Path: proto.String("bounded/path")}
	issued := h.accountSession(user, session.ScopeAccount)
	denial := arc.PermissionDenied("file.read").ArcError(correlation.Context{})
	cases := []struct {
		name, procedure, class string
		method                 relayv1.RoutedMethod
		mutation               bool
		inner                  func(*foundationv1.RequestMeta) proto.Message
		response               []byte
		outer                  func(*foundationv1.RequestMeta, []byte) proto.Message
		reply                  func() proto.Message
	}{
		{"ReadNodeFile", fleetv1connect.FleetServiceReadNodeFileProcedure, "", relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_FILE, false,
			func(meta *foundationv1.RequestMeta) proto.Message {
				return &nodev1.FileServiceReadFileRequest{Path: path, Offset: proto.Uint64(0), Length: proto.Uint64(1)}
			},
			mustMarshal(t, &nodev1.FileServiceReadFileResponse{Outcome: &nodev1.FileServiceReadFileResponse_Error{Error: denial}}),
			func(meta *foundationv1.RequestMeta, payload []byte) proto.Message {
				return &fleetv1.FleetServiceReadNodeFileRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: payload}
			},
			func() proto.Message { return &fleetv1.FleetServiceReadNodeFileResponse{} },
		},
		{"WriteNodeFile", fleetv1connect.FleetServiceWriteNodeFileProcedure, "fleet.writeNodeFile", relayv1.RoutedMethod_ROUTED_METHOD_WRITE_NODE_FILE, true,
			func(meta *foundationv1.RequestMeta) proto.Message {
				return &nodev1.FileServiceWriteFileRequest{Meta: meta, Path: path, Data: []byte("PRIVATE-FILE-BODY-MARKER"), Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}}
			},
			mustMarshal(t, &nodev1.FileServiceWriteFileResponse{Outcome: &nodev1.FileServiceWriteFileResponse_Error{Error: denial}}),
			func(meta *foundationv1.RequestMeta, payload []byte) proto.Message {
				return &fleetv1.FleetServiceWriteNodeFileRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: payload}
			},
			func() proto.Message { return &fleetv1.FleetServiceWriteNodeFileResponse{} },
		},
		{"EditNodeFile", fleetv1connect.FleetServiceEditNodeFileProcedure, "fleet.editNodeFile", relayv1.RoutedMethod_ROUTED_METHOD_EDIT_NODE_FILE, true,
			func(meta *foundationv1.RequestMeta) proto.Message {
				return &nodev1.FileServiceEditFileRequest{Meta: meta, Path: path, OldText: proto.String("PRIVATE-OLD-MARKER"), NewText: proto.String("PRIVATE-NEW-MARKER"), ExpectedOccurrences: proto.Uint32(1), ExpectedSha256: make([]byte, 32)}
			},
			mustMarshal(t, &nodev1.FileServiceEditFileResponse{Outcome: &nodev1.FileServiceEditFileResponse_Error{Error: denial}}),
			func(meta *foundationv1.RequestMeta, payload []byte) proto.Message {
				return &fleetv1.FleetServiceEditNodeFileRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: payload}
			},
			func() proto.Message { return &fleetv1.FleetServiceEditNodeFileResponse{} },
		},
		{"SearchNodeFiles", fleetv1connect.FleetServiceSearchNodeFilesProcedure, "", relayv1.RoutedMethod_ROUTED_METHOD_SEARCH_NODE_FILES, false,
			func(meta *foundationv1.RequestMeta) proto.Message {
				return &nodev1.FileServiceSearchFilesRequest{Path: path, Pattern: proto.String("PRIVATE-PATTERN-MARKER"), Mode: nodev1.FileSearchMode(1).Enum()}
			},
			mustMarshal(t, &nodev1.FileServiceSearchFilesResponse{Outcome: &nodev1.FileServiceSearchFilesResponse_Error{Error: denial}}),
			func(meta *foundationv1.RequestMeta, payload []byte) proto.Message {
				return &fleetv1.FleetServiceSearchNodeFilesRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: payload}
			},
			func() proto.Message { return &fleetv1.FleetServiceSearchNodeFilesResponse{} },
		},
		{"ListNodeDirectory", fleetv1connect.FleetServiceListNodeDirectoryProcedure, "", relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_DIRECTORY, false,
			func(meta *foundationv1.RequestMeta) proto.Message {
				return &nodev1.FileServiceListDirectoryRequest{Path: path, PageSize: proto.Uint32(1)}
			},
			mustMarshal(t, &nodev1.FileServiceListDirectoryResponse{Outcome: &nodev1.FileServiceListDirectoryResponse_Error{Error: denial}}),
			func(meta *foundationv1.RequestMeta, payload []byte) proto.Message {
				return &fleetv1.FleetServiceListNodeDirectoryRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: payload}
			},
			func() proto.Message { return &fleetv1.FleetServiceListNodeDirectoryResponse{} },
		},
		{"PlanNodeRemoval", fleetv1connect.FleetServicePlanNodeRemovalProcedure, "", relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL, true,
			func(meta *foundationv1.RequestMeta) proto.Message {
				return &nodev1.FileServicePlanRemovalRequest{Meta: meta, Target: &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: path}}
			},
			mustMarshal(t, &nodev1.FileServicePlanRemovalResponse{Outcome: &nodev1.FileServicePlanRemovalResponse_Error{Error: denial}}),
			func(meta *foundationv1.RequestMeta, payload []byte) proto.Message {
				return &fleetv1.FleetServicePlanNodeRemovalRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: payload}
			},
			func() proto.Message { return &fleetv1.FleetServicePlanNodeRemovalResponse{} },
		},
		{"ExecuteNodeRemoval", fleetv1connect.FleetServiceExecuteNodeRemovalProcedure, "fleet.executeNodeRemoval", relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL, true,
			func(meta *foundationv1.RequestMeta) proto.Message {
				return &nodev1.FileServiceExecuteRemovalRequest{Meta: meta, PlanId: idValue(workspace), PlanDigest: make([]byte, 32)}
			},
			mustMarshal(t, &nodev1.FileServiceExecuteRemovalResponse{Outcome: &nodev1.FileServiceExecuteRemovalResponse_Error{Error: denial}}),
			func(meta *foundationv1.RequestMeta, payload []byte) proto.Message {
				return &fleetv1.FleetServiceExecuteNodeRemovalRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: payload}
			},
			func() proto.Message { return &fleetv1.FleetServiceExecuteNodeRemovalResponse{} },
		},
		{"GetNodeFileOperation", fleetv1connect.FleetServiceGetNodeFileOperationProcedure, "", relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION, false,
			func(meta *foundationv1.RequestMeta) proto.Message {
				return &nodev1.FileServiceGetFileOperationRequest{OperationCommandId: idValue(workspace)}
			},
			mustMarshal(t, &nodev1.FileServiceGetFileOperationResponse{Outcome: &nodev1.FileServiceGetFileOperationResponse_Error{Error: denial}}),
			func(meta *foundationv1.RequestMeta, payload []byte) proto.Message {
				return &fleetv1.FleetServiceGetNodeFileOperationRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: payload}
			},
			func() proto.Message { return &fleetv1.FleetServiceGetNodeFileOperationResponse{} },
		},
		{"RegisterNodeWorkspace", fleetv1connect.FleetServiceRegisterNodeWorkspaceProcedure, "fleet.registerNodeWorkspace", relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE, true,
			func(meta *foundationv1.RequestMeta) proto.Message {
				return &nodev1.WorkspaceServiceRegisterWorkspaceRequest{Meta: meta, Path: proto.String("/srv/owned-test-root")}
			},
			mustMarshal(t, &nodev1.WorkspaceServiceRegisterWorkspaceResponse{Outcome: &nodev1.WorkspaceServiceRegisterWorkspaceResponse_Error{Error: denial}}),
			func(meta *foundationv1.RequestMeta, payload []byte) proto.Message {
				return &fleetv1.FleetServiceRegisterNodeWorkspaceRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: payload}
			},
			func() proto.Message { return &fleetv1.FleetServiceRegisterNodeWorkspaceResponse{} },
		},
		{"UnregisterNodeWorkspace", fleetv1connect.FleetServiceUnregisterNodeWorkspaceProcedure, "fleet.unregisterNodeWorkspace", relayv1.RoutedMethod_ROUTED_METHOD_UNREGISTER_NODE_WORKSPACE, true,
			func(meta *foundationv1.RequestMeta) proto.Message {
				return &nodev1.WorkspaceServiceUnregisterWorkspaceRequest{Meta: meta, WorkspaceId: idValue(workspace)}
			},
			mustMarshal(t, &nodev1.WorkspaceServiceUnregisterWorkspaceResponse{Outcome: &nodev1.WorkspaceServiceUnregisterWorkspaceResponse_Error{Error: denial}}),
			func(meta *foundationv1.RequestMeta, payload []byte) proto.Message {
				return &fleetv1.FleetServiceUnregisterNodeWorkspaceRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: payload}
			},
			func() proto.Message { return &fleetv1.FleetServiceUnregisterNodeWorkspaceResponse{} },
		},
		{"ListNodeWorkspaces", fleetv1connect.FleetServiceListNodeWorkspacesProcedure, "", relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_WORKSPACES, false,
			func(meta *foundationv1.RequestMeta) proto.Message {
				return &nodev1.WorkspaceServiceListWorkspacesRequest{Meta: meta}
			},
			mustMarshal(t, &nodev1.WorkspaceServiceListWorkspacesResponse{Outcome: &nodev1.WorkspaceServiceListWorkspacesResponse_Error{Error: denial}}),
			func(meta *foundationv1.RequestMeta, payload []byte) proto.Message {
				return &fleetv1.FleetServiceListNodeWorkspacesRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: payload}
			},
			func() proto.Message { return &fleetv1.FleetServiceListNodeWorkspacesResponse{} },
		},
		{"GetNodeWorkspace", fleetv1connect.FleetServiceGetNodeWorkspaceProcedure, "", relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_WORKSPACE, false,
			func(meta *foundationv1.RequestMeta) proto.Message {
				return &nodev1.WorkspaceServiceGetWorkspaceRequest{WorkspaceId: idValue(workspace)}
			},
			mustMarshal(t, &nodev1.WorkspaceServiceGetWorkspaceResponse{Outcome: &nodev1.WorkspaceServiceGetWorkspaceResponse_Error{Error: denial}}),
			func(meta *foundationv1.RequestMeta, payload []byte) proto.Message {
				return &fleetv1.FleetServiceGetNodeWorkspaceRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: payload}
			},
			func() proto.Message { return &fleetv1.FleetServiceGetNodeWorkspaceResponse{} },
		},
	}
	responses := map[relayv1.RoutedMethod][]byte{}
	for _, c := range cases {
		responses[c.method] = c.response
	}
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		var header relayv1.CallHeader
		if proto.Unmarshal(call.GetHeader().GetHeader(), &header) != nil {
			return nil, nil, false
		}
		payload := responses[header.GetMethod()]
		return node.node.Executed(call, payload), payload, true
	})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			command := platform.NewID()
			meta := &foundationv1.RequestMeta{}
			if c.mutation {
				meta.CommandId = idValue(command)
			}
			if c.class != "" {
				h.proveFor(issued, user, c.class, node.node.ID)
			}
			payload := mustMarshal(t, c.inner(meta))
			reply := c.reply()
			h.rpc(c.procedure, c.outer(meta, payload), issued.AccessToken, reply)
			reflected := reply.ProtoReflect()
			outcome := reflected.WhichOneof(reflected.Descriptor().Oneofs().ByName("outcome"))
			if outcome == nil || outcome.Number() != 2 {
				t.Fatalf("outer route refused: %v", reply)
			}
			value := reflected.Get(outcome).Message()
			response := value.Get(value.Descriptor().Fields().ByName("response")).Bytes()
			if !bytes.Equal(response, c.response) {
				t.Fatal("signed inner response was changed")
			}
			select {
			case sent := <-calls:
				var header relayv1.CallHeader
				_ = proto.Unmarshal(sent.GetHeader().GetHeader(), &header)
				if header.GetMethod() != c.method || (header.CommandId != nil) != c.mutation || !bytes.Equal(sent.Payload, payload) {
					t.Fatal("method,command or payload binding differs")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("no actual channel call")
			}
			record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, int16(c.method))
			if err != nil {
				t.Fatal(err)
			}
			if c.mutation {
				if record == nil || record.State != fleet.RoutedFailed || !record.Delivered || record.Final {
					t.Fatalf("definite handler refusal receipt: %+v", record)
				}
			} else if record != nil {
				t.Fatal("read created mutation receipt")
			}
		})
	}
	if got := h.count("SELECT count(*) FROM fleet.routed_file_call"); got != 6 {
		t.Fatalf("file mutation receipts=%d", got)
	}
	if got := h.count("SELECT count(*) FROM fleet.routed_call"); got != 0 {
		t.Fatalf("file call entered task receipt table: %d", got)
	}
	if h.audits("fleet.file.read") != 6 {
		t.Fatal("each read needs its actual center audit")
	}
	for _, marker := range []string{"PRIVATE-FILE-BODY-MARKER", "PRIVATE-OLD-MARKER", "PRIVATE-NEW-MARKER", "PRIVATE-PATTERN-MARKER"} {
		if h.count("SELECT count(*) FROM audit.audit_event WHERE convert_from(payload,'UTF8') LIKE $1", "%"+marker+"%") != 0 || strings.Contains(h.logs.String(), marker) {
			t.Fatal("body or pattern leaked into persisted audit/log")
		}
	}
}

func TestCTR06WriteReplaySharesTheOldCommandNamespace(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	issued := h.accountSession(user, session.ScopeAccount)
	command, workspace := platform.NewID(), platform.NewID()
	data := []byte("PRIVATE-WRITE-BODY")
	digest := sha256.Sum256(data)
	response := mustMarshal(t, &nodev1.FileServiceWriteFileResponse{Outcome: &nodev1.FileServiceWriteFileResponse_Value{Value: &nodev1.FileServiceWriteFileValue{
		Result: &nodev1.FileMutationResult{CommandId: idValue(command), SizeBytes: proto.Uint64(uint64(len(data))), Sha256: digest[:]}}},
		Audit: &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_WRITTEN_BYTES.Enum(),
			SizeBytes: proto.Uint64(uint64(len(data))), Sha256: digest[:], DigestInputBytes: proto.Uint64(uint64(len(data)))}}}})
	calls := serve(t, node, channel, deduplicating(node, func(*relayv1.ChannelCall) []byte { return response }))
	payload := mustMarshal(t, &nodev1.FileServiceWriteFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
		Path: &nodev1.FilePath{WorkspaceId: idValue(workspace), Path: proto.String("result.txt")}, Data: data,
		Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}})
	send := func() *fleetv1.FleetServiceWriteNodeFileResponse {
		h.proveFor(issued, user, "fleet.writeNodeFile", node.node.ID)
		reply := &fleetv1.FleetServiceWriteNodeFileResponse{}
		h.rpc(fleetv1connect.FleetServiceWriteNodeFileProcedure, &fleetv1.FleetServiceWriteNodeFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
			NodeId: idValue(node.node.ID), Request: payload}, issued.AccessToken, reply)
		return reply
	}
	for i := 0; i < 2; i++ {
		if reply := send(); reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), response) {
			t.Fatalf("write/replay: %v", reply)
		}
		<-calls
	}
	record, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, 10)
	if err != nil || record == nil || record.State != fleet.RoutedSucceeded || !record.Final || record.Attempts != 2 {
		t.Fatalf("replay record %+v %v", record, err)
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.result' AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='true' AND convert_from(payload,'UTF8') LIKE $1", "%"+hex.EncodeToString(digest[:])+"%") != 2 {
		t.Fatal("actual signed result digest not audited on both deliveries")
	}
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	if failure := h.submit(issued.AccessToken, command, node.node.ID, submitPayload(t, command, "PRIVATE-OLD-TASK")).GetError(); errorKey(failure) != "CONFLICT/command_id_reused" {
		t.Fatalf("same command in old namespace: %v", failure)
	}
	if h.count("SELECT count(*) FROM fleet.routed_call WHERE account_id=$1 AND command_id=$2", user, command) != 0 {
		t.Fatal("conflicting old receipt committed")
	}
	// Caller scope is account-local: another account cannot inspect this record.
	other := h.db.Account(2)
	if got, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, other, command, 10); err != nil || got != nil {
		t.Fatal("cross-account receipt exposed")
	}
}

// A reply whose durable settlement is lost stays potentially delivered across a
// fenced sweep, and an expired resend cannot become a new effect even offline.
func TestCTR06LostFileSettlementIsSweptAndReplayWindowPrecedesPresence(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	issued := h.accountSession(user, session.ScopeAccount)
	command, workspace := platform.NewID(), platform.NewID()
	data := []byte("bounded")
	sum := sha256.Sum256(data)
	response := mustMarshal(t, &nodev1.FileServiceWriteFileResponse{Outcome: &nodev1.FileServiceWriteFileResponse_Value{Value: &nodev1.FileServiceWriteFileValue{
		Result: &nodev1.FileMutationResult{CommandId: idValue(command), SizeBytes: proto.Uint64(uint64(len(data))), Sha256: sum[:]}}},
		Audit: &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_WRITTEN_BYTES.Enum(),
			SizeBytes: proto.Uint64(uint64(len(data))), DigestInputBytes: proto.Uint64(uint64(len(data))), Sha256: sum[:]}}}})
	calls := serve(t, node, channel, deduplicating(node, func(*relayv1.ChannelCall) []byte { return response }))
	payload := mustMarshal(t, &nodev1.FileServiceWriteFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
		Path: &nodev1.FilePath{WorkspaceId: idValue(workspace), Path: proto.String("lost.txt")}, Data: data,
		Precondition: &nodev1.FileServiceWriteFileRequest_ExpectedAbsent{ExpectedAbsent: true}})
	role := pgx.Identifier{h.db.Name + "_runtime"}.Sanitize()
	h.db.Exec("REVOKE UPDATE ON fleet.routed_file_call FROM " + role)
	h.proveFor(issued, user, "fleet.writeNodeFile", node.node.ID)
	reply := &fleetv1.FleetServiceWriteNodeFileResponse{}
	h.rpc(fleetv1connect.FleetServiceWriteNodeFileProcedure, &fleetv1.FleetServiceWriteNodeFileRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
		NodeId: idValue(node.node.ID), Request: payload}, issued.AccessToken, reply)
	if reply.GetError() != nil {
		t.Fatal(reply.GetError())
	}
	<-calls
	got, err := fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, 10)
	if err != nil || got == nil || got.State != fleet.RoutedAccepted || got.Final {
		t.Fatalf("lost settlement %+v %v", got, err)
	}
	h.db.Exec("GRANT UPDATE ON fleet.routed_file_call TO " + role)
	fence, live := h.center.Hub.Routable()
	if !live {
		t.Fatal("test hub has no lease")
	}
	swept, err := fleet.SweepRouted(context.Background(), h.db.Runtime, fence, time.Now())
	if err != nil || swept != 1 {
		t.Fatalf("fenced sweep %d %v", swept, err)
	}
	got, err = fleet.ReadRoutedForMethod(context.Background(), h.db.Runtime, user, command, 10)
	if err != nil || got.State != fleet.RoutedUnknown || !got.Delivered || got.Final {
		t.Fatalf("swept receipt %+v %v", got, err)
	}
	var digest []byte
	var created time.Time
	if err = h.db.Migration.QueryRow(context.Background(), "SELECT request_digest,created_at FROM fleet.routed_file_call WHERE account_id=$1 AND command_id=$2", user, command).Scan(&digest, &created); err != nil {
		t.Fatal(err)
	}
	onlineCalled := false
	_, err = fleet.AcceptRouted(context.Background(), h.db.Runtime, fleet.RoutedAccept{AccountID: user, CommandID: command, NodeID: node.node.ID, Method: 10,
		Digest: digest, Window: time.Hour, Now: created.Add(2 * time.Hour), InFlight: func() bool { return false }, Online: func() bool { onlineCalled = true; return false }})
	var refusal *arc.Refusal
	if !errors.As(err, &refusal) || refusal.Code != "invalid_state" || onlineCalled {
		t.Fatalf("window must precede presence: %v called=%v", err, onlineCalled)
	}
	// The new namespace guard also precedes presence for an old task method.
	_, err = fleet.AcceptRouted(context.Background(), h.db.Runtime, fleet.RoutedAccept{AccountID: user, CommandID: command, NodeID: node.node.ID, Method: 1,
		Digest: digest, Window: time.Hour, Now: created, InFlight: func() bool { return false }, Online: func() bool { onlineCalled = true; return false }})
	if !errors.As(err, &refusal) || refusal.Code != "command_id_reused" || onlineCalled {
		t.Fatalf("namespace must precede presence: %v called=%v", err, onlineCalled)
	}
}

func TestCTR06ReadAuditsOnlyVerifiedDigestAndRejectsCorruptSignedBytes(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	issued := h.accountSession(user, session.ScopeAccount)
	workspace := platform.NewID()
	data := []byte("PRIVATE-READ-CONTENT-MARKER")
	sum := sha256.Sum256(data)
	var count atomic.Int32
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		digest := sum[:]
		if count.Add(1) > 1 {
			digest = make([]byte, 32)
		}
		payload := mustMarshal(t, &nodev1.FileServiceReadFileResponse{Outcome: &nodev1.FileServiceReadFileResponse_Value{Value: &nodev1.FileServiceReadFileValue{
			Data: data, Offset: proto.Uint64(0), NextOffset: proto.Uint64(uint64(len(data))), Eof: proto.Bool(true), Sha256: digest, FileSize: proto.Uint64(uint64(len(data)))}},
			Audit: &nodev1.FileAuditMetadata{Observations: []*nodev1.FileAuditObservation{{Kind: nodev1.FileAuditKind_FILE_AUDIT_KIND_READ_BYTES.Enum(),
				SizeBytes: proto.Uint64(uint64(len(data))), DigestInputBytes: proto.Uint64(uint64(len(data))), Sha256: digest}}}})
		return node.node.Executed(call, payload), payload, true
	})
	payload := mustMarshal(t, &nodev1.FileServiceReadFileRequest{Path: &nodev1.FilePath{WorkspaceId: idValue(workspace), Path: proto.String("read.txt")}, Offset: proto.Uint64(0), Length: proto.Uint64(65536)})
	send := func() *fleetv1.FleetServiceReadNodeFileResponse {
		reply := &fleetv1.FleetServiceReadNodeFileResponse{}
		h.rpc(fleetv1connect.FleetServiceReadNodeFileProcedure, &fleetv1.FleetServiceReadNodeFileRequest{NodeId: idValue(node.node.ID), Request: payload}, issued.AccessToken, reply)
		<-calls
		return reply
	}
	if reply := send(); reply.GetError() != nil {
		t.Fatal(reply.GetError())
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.read' AND convert_from(payload,'UTF8') LIKE $1", "%"+hex.EncodeToString(sum[:])+"%") != 1 {
		t.Fatal("verified content digest missing")
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE convert_from(payload,'UTF8') LIKE $1", "%PRIVATE-READ-CONTENT-MARKER%") != 0 || strings.Contains(h.logs.String(), "PRIVATE-READ-CONTENT-MARKER") {
		t.Fatal("read body persisted")
	}
	if failure := send().GetError(); errorKey(failure) != "STATE/node_unreachable" || failure.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
		t.Fatalf("corrupt signed bytes must not be forwarded as success: %v", failure)
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.read' AND convert_from(payload,'UTF8')::jsonb->>'nodeAuditAvailable'='false'") != 1 {
		t.Fatal("invalid result must explicitly lack trusted observations")
	}
}

func TestCTR06WorkspaceRegistrationRequiresVerifiedOwnNodeHuman(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	var acceptedAssertion []byte
	var acceptedPayload []byte
	for _, origin := range []nodev1.Origin{nodev1.Origin_ORIGIN_SCRIPT, nodev1.Origin_ORIGIN_AGENT, nodev1.Origin_ORIGIN_HUMAN} {
		command := platform.NewID()
		payload := mustMarshal(t, &nodev1.WorkspaceServiceRegisterWorkspaceRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)}, Path: proto.String("/srv/test-root")})
		digest := sha256.Sum256(payload)
		assertion := mustMarshal(t, node.node.Assertion(publicBaseURL, nodetest.Relay{InstallationID: node.result.InstallationID, LocalOrigin: origin, LocalSession: platform.NewID(),
			Method: relayv1.RoutedMethod_ROUTED_METHOD_REGISTER_NODE_WORKSPACE, RequestSHA256: digest[:], Target: &node.node.ID, Command: &command, Nonce: nonceOf(t, channel)}))
		if origin == nodev1.Origin_ORIGIN_HUMAN {
			acceptedAssertion = assertion
			acceptedPayload = payload
			break
		}
		reply := &fleetv1.FleetServiceRegisterNodeWorkspaceResponse{}
		h.rpc(fleetv1connect.FleetServiceRegisterNodeWorkspaceProcedure, &fleetv1.FleetServiceRegisterNodeWorkspaceRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
			NodeId: idValue(node.node.ID), Caller: relayedCaller(node, origin), RelayAssertion: assertion, Request: payload}, node.access, reply)
		if errorKey(reply.GetError()) != "AUTHORIZATION/permission_denied" || h.count("SELECT count(*) FROM fleet.routed_file_call") != 0 {
			t.Fatalf("fixed HUMAN row accepted %v: %v", origin, reply)
		}
	}
	var inner nodev1.WorkspaceServiceRegisterWorkspaceRequest
	if err := proto.Unmarshal(acceptedPayload, &inner); err != nil {
		t.Fatal(err)
	}
	denial := arc.PermissionDenied("workspace.register").ArcError(correlation.Context{})
	response := mustMarshal(t, &nodev1.WorkspaceServiceRegisterWorkspaceResponse{Outcome: &nodev1.WorkspaceServiceRegisterWorkspaceResponse_Error{Error: denial}})
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		return node.node.Executed(call, response), response, true
	})
	reply := &fleetv1.FleetServiceRegisterNodeWorkspaceResponse{}
	h.rpc(fleetv1connect.FleetServiceRegisterNodeWorkspaceProcedure, &fleetv1.FleetServiceRegisterNodeWorkspaceRequest{Meta: inner.Meta, NodeId: idValue(node.node.ID),
		Caller: relayedCaller(node, nodev1.Origin_ORIGIN_HUMAN), RelayAssertion: acceptedAssertion, Request: acceptedPayload}, node.access, reply)
	if reply.GetError() != nil {
		t.Fatalf("verified HUMAN could not reach target policy: %v", reply.GetError())
	}
	sent := <-calls
	if !bytes.Equal(sent.Payload, acceptedPayload) {
		t.Fatal("HUMAN forwarded payload differs")
	}
}
