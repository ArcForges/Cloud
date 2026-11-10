// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"context"
	"crypto/sha256"
	"net/http/httptest"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/observe"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/server"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// This is a real center/PG/signature/restart and content-free audit test; its
// software-key node is a fixture, not native filesystem or cleanup acceptance.
func TestCTR06CallerBoundTargetsSurviveRefusalOfflineAndRestart(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connectFiles(node)
	issued := h.accountSession(user, session.ScopeAccount)
	workspace, planID, planCommand, executeCommand := platform.NewID(), platform.NewID(), platform.NewID(), platform.NewID()
	path := &nodev1.FilePath{WorkspaceId: idValue(workspace), Path: proto.String("private/target.txt")}
	planDigest := sha256.Sum256([]byte("plan transcript"))
	execInner := &nodev1.FileServiceExecuteRemovalRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(executeCommand)}, PlanId: idValue(planID), PlanDigest: planDigest[:]}
	execBytes := mustMarshal(t, execInner)
	opDigest := sha256.Sum256(execBytes)
	instant := func(at time.Time) *foundationv1.Instant {
		return &foundationv1.Instant{UnixSeconds: proto.Int64(at.Unix()), Nanos: proto.Uint32(uint32(at.Nanosecond()))}
	}
	now := time.Now().UTC()
	plan := &nodev1.FileRemovalPlan{PlanId: idValue(planID), Digest: planDigest[:], ExpiresAt: instant(now.Add(time.Hour)),
		Items:      []*nodev1.FileRemovalItem{{Path: proto.String("private/target.txt"), Kind: nodev1.FileEntryKind_FILE_ENTRY_KIND_FILE.Enum(), SizeBytes: proto.Uint64(1), IdentitySha256: make([]byte, 32), OwnerVerified: proto.Bool(true)}},
		TotalBytes: proto.Uint64(1), RequiresApproval: proto.Bool(false), QuarantineAvailable: proto.Bool(true), Risk: nodev1.RiskClass_RISK_CLASS_LOW.Enum(),
		Target: &nodev1.FileRemovalPlan_WorkspacePath{WorkspacePath: path}}
	planResponse := mustMarshal(t, &nodev1.FileServicePlanRemovalResponse{Outcome: &nodev1.FileServicePlanRemovalResponse_Value{Value: &nodev1.FileServicePlanRemovalValue{Plan: plan}}})
	denied := arc.PermissionDenied("file.remove").ArcError(correlation.New())
	execResponse := mustMarshal(t, &nodev1.FileServiceExecuteRemovalResponse{Outcome: &nodev1.FileServiceExecuteRemovalResponse_Error{Error: denied}})
	operation := &nodev1.FileOperation{CommandId: idValue(executeCommand), Kind: nodev1.FileOperationKind_FILE_OPERATION_KIND_REMOVAL.Enum(),
		State: nodev1.FileOperationState_FILE_OPERATION_STATE_PREPARED.Enum(), RequestSha256: opDigest[:], CreatedAt: instant(now), UpdatedAt: instant(now),
		Acknowledged: proto.Bool(false), Held: proto.Bool(false), Target: &nodev1.FileOperation_WorkspacePath{WorkspacePath: path}}
	statusResponse := mustMarshal(t, &nodev1.FileServiceGetFileOperationResponse{Outcome: &nodev1.FileServiceGetFileOperationResponse_Value{Value: &nodev1.FileServiceGetFileOperationValue{Operation: operation}}})
	answer := func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		header := headerOf(t, call)
		var response []byte
		switch header.GetMethod() {
		case relayv1.RoutedMethod_ROUTED_METHOD_PLAN_NODE_REMOVAL:
			response = planResponse
		case relayv1.RoutedMethod_ROUTED_METHOD_EXECUTE_NODE_REMOVAL:
			response = execResponse
		case relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_FILE_OPERATION:
			response = statusResponse
		default:
			t.Errorf("unexpected method %v", header.GetMethod())
			return nil, nil, false
		}
		return node.node.Executed(call, response), response, true
	}
	calls := serve(t, node, channel, answer)
	planInner := &nodev1.FileServicePlanRemovalRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(planCommand)}, Target: &nodev1.FileServicePlanRemovalRequest_WorkspacePath{WorkspacePath: path}}
	planReply := &fleetv1.FleetServicePlanNodeRemovalResponse{}
	h.rpc(fleetv1connect.FleetServicePlanNodeRemovalProcedure, &fleetv1.FleetServicePlanNodeRemovalRequest{Meta: planInner.Meta, NodeId: idValue(node.node.ID), Request: mustMarshal(t, planInner)}, issued.AccessToken, planReply)
	if planReply.GetError() != nil {
		t.Fatalf("signed plan: %v", planReply.GetError())
	}
	<-calls
	if h.count("SELECT count(*) FROM fleet.routed_file_target WHERE target_kind=1 AND lookup_id=$1 AND account_id=$2 AND node_id=$3 AND workspace_id=$4 AND target_path='private/target.txt'", planID, user, node.node.ID, workspace) != 1 {
		t.Fatal("signed plan target was not durably bound")
	}
	if _, err := h.db.Migration.Exec(context.Background(), "UPDATE fleet.routed_file_target SET target_path='rewritten' WHERE lookup_id=$1", planID); err == nil {
		t.Fatal("target association was mutable")
	}

	statusPayload := mustMarshal(t, &nodev1.FileServiceGetFileOperationRequest{OperationCommandId: idValue(executeCommand)})
	status := func(token string, target platform.ID) *fleetv1.FleetServiceGetNodeFileOperationResponse {
		reply := &fleetv1.FleetServiceGetNodeFileOperationResponse{}
		h.rpc(fleetv1connect.FleetServiceGetNodeFileOperationProcedure, &fleetv1.FleetServiceGetNodeFileOperationRequest{NodeId: idValue(target), Request: statusPayload}, token, reply)
		return reply
	}
	// An authentic Node response alone does not prove the caller owns this ID.
	// Before an accepted operation establishes the binding it cannot reveal the
	// path, create an association or make the Node audit trusted evidence.
	if reply := status(issued.AccessToken, node.node.ID); reply.GetError() == nil {
		t.Fatal("signed status disclosed an unbound operation")
	}
	<-calls
	if h.count("SELECT count(*) FROM fleet.routed_file_target WHERE target_kind=2 AND lookup_id=$1", executeCommand) != 0 {
		t.Fatal("unbound signed status created an operation association")
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.read' AND convert_from(payload,'UTF8')::jsonb->>'path'='private/target.txt'") != 0 {
		t.Fatal("unbound signed status disclosed the path in audit")
	}

	execute := func(token string, command platform.ID, request []byte) *fleetv1.FleetServiceExecuteNodeRemovalResponse {
		reply := &fleetv1.FleetServiceExecuteNodeRemovalResponse{}
		h.rpc(fleetv1connect.FleetServiceExecuteNodeRemovalProcedure, &fleetv1.FleetServiceExecuteNodeRemovalRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)}, NodeId: idValue(node.node.ID), Request: request}, token, reply)
		return reply
	}
	if f := execute(issued.AccessToken, executeCommand, execBytes).GetError(); errorKey(f) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("unproved execute: %v", f)
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.refused' AND command_id=$1 AND convert_from(payload,'UTF8')::jsonb->>'workspaceId'=$2 AND convert_from(payload,'UTF8')::jsonb->>'path'='private/target.txt'", executeCommand, workspace.String()) != 1 {
		t.Fatal("refused execute lost target")
	}
	h.proveFor(issued, user, "fleet.executeNodeRemoval", node.node.ID)
	if reply := execute(issued.AccessToken, executeCommand, execBytes); reply.GetError() != nil {
		t.Fatalf("signed execute refusal: %v", reply.GetError())
	}
	<-calls
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type IN ('fleet.routed.accepted','fleet.routed.result') AND command_id=$1 AND convert_from(payload,'UTF8')::jsonb->>'workspaceId'=$2 AND convert_from(payload,'UTF8')::jsonb->>'path'='private/target.txt'", executeCommand, workspace.String()) != 2 {
		t.Fatal("execute accepted/result audit lost target")
	}
	// Even a correctly signed status cannot change the exact bytes admitted by
	// the original caller, or substitute another operation kind.
	goodStatus := statusResponse
	badOperation := proto.Clone(operation).(*nodev1.FileOperation)
	badOperation.RequestSha256 = make([]byte, 32)
	statusResponse = mustMarshal(t, &nodev1.FileServiceGetFileOperationResponse{Outcome: &nodev1.FileServiceGetFileOperationResponse_Value{Value: &nodev1.FileServiceGetFileOperationValue{Operation: badOperation}}})
	if reply := status(issued.AccessToken, node.node.ID); reply.GetError() == nil {
		t.Fatal("signed status with a foreign raw request digest was exposed")
	}
	<-calls
	badOperation = proto.Clone(operation).(*nodev1.FileOperation)
	badOperation.Kind = nodev1.FileOperationKind_FILE_OPERATION_KIND_WRITE.Enum()
	statusResponse = mustMarshal(t, &nodev1.FileServiceGetFileOperationResponse{Outcome: &nodev1.FileServiceGetFileOperationResponse_Value{Value: &nodev1.FileServiceGetFileOperationValue{Operation: badOperation}}})
	if reply := status(issued.AccessToken, node.node.ID); reply.GetError() == nil {
		t.Fatal("signed status with a different mutation kind was exposed")
	}
	<-calls
	statusResponse = goodStatus
	if reply := status(issued.AccessToken, node.node.ID); reply.GetError() != nil {
		t.Fatalf("signed status: %v", reply.GetError())
	}
	<-calls
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.read' AND reason='succeeded' AND convert_from(payload,'UTF8')::jsonb->>'workspaceId'=$1 AND convert_from(payload,'UTF8')::jsonb->>'path'='private/target.txt'", workspace.String()) != 1 {
		t.Fatal("status audit lost target")
	}
	// The account identity is stable across valid sessions.
	anotherSession := h.accountSession(user, session.ScopeAccount)
	if reply := status(anotherSession.AccessToken, node.node.ID); reply.GetError() != nil {
		t.Fatalf("same account's new session lost status: %v", reply.GetError())
	}
	<-calls
	if original, err := fleet.LookupFileOperationReceipt(context.Background(), h.db.Runtime, user, node.node.ID,
		fleet.RoutedCaller{Kind: fleet.RoutedCallerRelay, RelayingNodeID: node.node.ID, LocalOrigin: 1, LocalSessionID: platform.NewID()}, executeCommand); err != nil || original != nil {
		t.Fatalf("foreign relay received an account receipt: %+v %v", original, err)
	}
	other := h.db.Account(1)
	stranger := h.accountSession(other, session.ScopeAccount)
	if reply := status(stranger.AccessToken, node.node.ID); errorKey(reply.GetError()) != "STATE/not_found" {
		t.Fatalf("foreign account status: %v", reply.GetError())
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE actor_ref=$1 AND convert_from(payload,'UTF8')::jsonb->>'path'='private/target.txt'", "account:"+other.String()) != 0 {
		t.Fatal("foreign account learned target in audit")
	}
	foreignNode := h.enrollIn(user)
	if target, err := fleet.LookupFileTarget(context.Background(), h.db.Runtime, user, foreignNode.node.ID, fleet.RoutedCaller{Kind: fleet.RoutedCallerSession, SessionID: issued.SessionID}, fleet.FileTargetPlan, planID); err != nil || target != nil {
		t.Fatalf("cross-node target: %+v %v", target, err)
	}
	if target, err := fleet.LookupFileTarget(context.Background(), h.db.Runtime, user, node.node.ID, fleet.RoutedCaller{Kind: fleet.RoutedCallerRelay, RelayingNodeID: node.node.ID, LocalOrigin: 1, LocalSessionID: platform.NewID()}, fleet.FileTargetPlan, planID); err != nil || target != nil {
		t.Fatalf("cross-caller target: %+v %v", target, err)
	}

	stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	h.center.Hub.Stop(stop)
	cancel()
	offlineCommand := platform.NewID()
	offlineInner := proto.Clone(execInner).(*nodev1.FileServiceExecuteRemovalRequest)
	offlineInner.Meta.CommandId = idValue(offlineCommand)
	if f := execute(issued.AccessToken, offlineCommand, mustMarshal(t, offlineInner)).GetError(); errorKey(f) != "STATE/node_offline" {
		t.Fatalf("offline execute: %v", f)
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.routed.refused' AND command_id=$1 AND convert_from(payload,'UTF8')::jsonb->>'workspaceId'=$2 AND convert_from(payload,'UTF8')::jsonb->>'path'='private/target.txt'", offlineCommand, workspace.String()) != 1 {
		t.Fatal("offline execute lost target")
	}

	// A separate Center instance using the same database proves lookup survives restart.
	values := map[string]string{config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: publicBaseURL, config.EnvDatabaseURL: h.db.RuntimeURL,
		config.EnvSurfaces: "identity,pages,fleet,relay,nodes", config.EnvClientIPHeader: config.ClientIPHeader, config.EnvTrustedProxies: "127.0.0.0/8,::1/128"}
	cfg, err := config.Load(func(key string) (string, bool) { value, ok := values[key]; return value, ok })
	if err != nil {
		t.Fatal(err)
	}
	if err = cfg.ApplyCommandKeys([]config.CommandKey{h.commandKey}); err != nil {
		t.Fatal(err)
	}
	tuned := testSettings()
	tuned.Heartbeat, tuned.HeartbeatDeadline = time.Second, 30*time.Second
	next, err := server.New(cfg, observe.NewLogger(h.logs, 0), server.Options{Hub: &tuned, Background: func(work func()) { work() }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(next.Close)
	if err = next.CheckCommandKeys(context.Background()); err != nil {
		t.Fatal(err)
	}
	next.Hub.Start(context.Background())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		next.Hub.Stop(ctx)
	})
	listener := httptest.NewServer(next.Public())
	t.Cleanup(listener.Close)
	h.center, h.url = next, listener.URL
	newChannel := h.connectFiles(node)
	newCalls := serve(t, node, newChannel, answer)
	if reply := status(issued.AccessToken, node.node.ID); reply.GetError() != nil {
		t.Fatalf("status after restart: %v", reply.GetError())
	}
	<-newCalls
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type='fleet.file.read' AND reason='succeeded' AND convert_from(payload,'UTF8')::jsonb->>'workspaceId'=$1 AND convert_from(payload,'UTF8')::jsonb->>'path'='private/target.txt'", workspace.String()) != 3 {
		t.Fatal("restart status lost target")
	}
}
