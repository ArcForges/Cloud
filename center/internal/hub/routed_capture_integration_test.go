// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The routed method captures (AF-CTR-05 E2b, E2-26; EVIDENCE: REAL PostgreSQL, the REAL composed center behind its ingress and hub;
// MOCKED: the node, nodetest with a software key, whose answers the test fixes): for each of the six routed task methods the cases ok,
// offline, unknown, gated and quota, as binary gRPC-Web posted by an account session, in the format of the FakeCenter captures (schema
// version 2). Part N1 copies the directory verbatim for the ArcForges FakeCenter's conformance test. request.frames is the request
// message, reply.frames the reply message, each normalized and re-encoded, and reply.trailers the grpc-status. Only values the center,
// the node's enrollment or a random source produced are replaced.

const routedExchangesDirectory = "testdata/routed"

var routedCaptureNormalization = []string{
	"a 16-byte ID the center or the node drew: 15 bytes of its kind (0xa1 correlation, 0xa6 node) and n for the n-th distinct one of the kind",
	"every Instant: unix_seconds 0, nanos 0 (a retry_at carries the center's jitter)",
	"the authorization header carries the placeholder of its account session's token",
	"the inner request and response bytes are the test's own fixed messages (task, attempt and command IDs fixed by the test)",
}

// fixedID is an ID the test chooses: 16 bytes of b.
func fixedID(b byte) platform.ID {
	var value platform.ID
	copy(value[:], bytes.Repeat([]byte{b}, 16))
	return value
}

type routedMethodCase struct {
	name      string
	path      string
	method    relayv1.RoutedMethod
	mutation  bool
	class     string
	inner     func(command platform.ID) []byte
	response  []byte
	build     func(meta *foundationv1.RequestMeta, nodeID platform.ID, inner []byte) proto.Message
	newResult func() proto.Message
}

func mustMarshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func routedMethodCases(t *testing.T) []routedMethodCase {
	task, attempt := fixedID(0x51), fixedID(0x52)
	id := func(value platform.ID) *foundationv1.Id {
		return &foundationv1.Id{Value: append([]byte(nil), value[:]...)}
	}
	return []routedMethodCase{
		{"SubmitNodeTask", fleetv1connect.FleetServiceSubmitNodeTaskProcedure, routedSubmitMethod, true, "fleet.submitNodeTask",
			func(command platform.ID) []byte {
				return mustMarshal(t, &nodev1.TaskServiceSubmitTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: id(command)},
					Spec: &nodev1.TaskSpec{Command: &nodev1.CommandSpec{Form: &nodev1.CommandSpec_Argv{Argv: &nodev1.ArgvCommand{Argv: []string{"/bin/true"}}}}}})
			},
			mustMarshal(t, &nodev1.TaskServiceSubmitTaskResponse{Outcome: &nodev1.TaskServiceSubmitTaskResponse_Value{Value: &nodev1.TaskServiceSubmitTaskValue{TaskId: id(task)}}}),
			func(meta *foundationv1.RequestMeta, nodeID platform.ID, inner []byte) proto.Message {
				return &fleetv1.FleetServiceSubmitNodeTaskRequest{Meta: meta, NodeId: id(nodeID), Request: inner}
			}, func() proto.Message { return &fleetv1.FleetServiceSubmitNodeTaskResponse{} }},
		{"GetNodeTask", fleetv1connect.FleetServiceGetNodeTaskProcedure, relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_TASK, false, "",
			func(platform.ID) []byte { return mustMarshal(t, &nodev1.TaskServiceGetTaskRequest{TaskId: id(task)}) },
			mustMarshal(t, &nodev1.TaskServiceGetTaskResponse{Outcome: &nodev1.TaskServiceGetTaskResponse_Value{Value: &nodev1.TaskServiceGetTaskValue{}}}),
			func(meta *foundationv1.RequestMeta, nodeID platform.ID, inner []byte) proto.Message {
				return &fleetv1.FleetServiceGetNodeTaskRequest{Meta: meta, NodeId: id(nodeID), Request: inner}
			}, func() proto.Message { return &fleetv1.FleetServiceGetNodeTaskResponse{} }},
		{"ListNodeTasks", fleetv1connect.FleetServiceListNodeTasksProcedure, relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_TASKS, false, "",
			func(platform.ID) []byte {
				return mustMarshal(t, &nodev1.TaskServiceListTasksRequest{Filter: &nodev1.TaskFilter{}})
			},
			mustMarshal(t, &nodev1.TaskServiceListTasksResponse{Outcome: &nodev1.TaskServiceListTasksResponse_Value{Value: &nodev1.TaskServiceListTasksValue{}}}),
			func(meta *foundationv1.RequestMeta, nodeID platform.ID, inner []byte) proto.Message {
				return &fleetv1.FleetServiceListNodeTasksRequest{Meta: meta, NodeId: id(nodeID), Request: inner}
			}, func() proto.Message { return &fleetv1.FleetServiceListNodeTasksResponse{} }},
		{"WaitNodeTask", fleetv1connect.FleetServiceWaitNodeTaskProcedure, relayv1.RoutedMethod_ROUTED_METHOD_WAIT_NODE_TASK, false, "",
			func(platform.ID) []byte {
				return mustMarshal(t, &nodev1.TaskServiceWaitTaskRequest{TaskId: id(task), WaitMs: proto.Uint64(100)})
			},
			mustMarshal(t, &nodev1.TaskServiceWaitTaskResponse{Outcome: &nodev1.TaskServiceWaitTaskResponse_Value{Value: &nodev1.TaskServiceWaitTaskValue{Reached: proto.Bool(true)}}}),
			func(meta *foundationv1.RequestMeta, nodeID platform.ID, inner []byte) proto.Message {
				return &fleetv1.FleetServiceWaitNodeTaskRequest{Meta: meta, NodeId: id(nodeID), Request: inner}
			}, func() proto.Message { return &fleetv1.FleetServiceWaitNodeTaskResponse{} }},
		{"ReadNodeTaskOutput", fleetv1connect.FleetServiceReadNodeTaskOutputProcedure, relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_TASK_OUTPUT, false, "",
			func(platform.ID) []byte {
				return mustMarshal(t, &nodev1.TaskServiceReadTaskOutputRequest{AttemptId: id(attempt), MaxBytes: proto.Uint32(1024)})
			},
			mustMarshal(t, &nodev1.TaskServiceReadTaskOutputResponse{Outcome: &nodev1.TaskServiceReadTaskOutputResponse_Value{Value: &nodev1.TaskServiceReadTaskOutputValue{
				Data: []byte("hello\n"), Eof: proto.Bool(true)}}}),
			func(meta *foundationv1.RequestMeta, nodeID platform.ID, inner []byte) proto.Message {
				return &fleetv1.FleetServiceReadNodeTaskOutputRequest{Meta: meta, NodeId: id(nodeID), Request: inner}
			}, func() proto.Message { return &fleetv1.FleetServiceReadNodeTaskOutputResponse{} }},
		{"CancelNodeTask", fleetv1connect.FleetServiceCancelNodeTaskProcedure, relayv1.RoutedMethod_ROUTED_METHOD_CANCEL_NODE_TASK, true, "fleet.cancelNodeTask",
			func(command platform.ID) []byte {
				return mustMarshal(t, &nodev1.TaskServiceCancelTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: id(command)}, TaskId: id(task)})
			},
			mustMarshal(t, &nodev1.TaskServiceCancelTaskResponse{Outcome: &nodev1.TaskServiceCancelTaskResponse_Value{Value: &nodev1.TaskServiceCancelTaskValue{}}}),
			func(meta *foundationv1.RequestMeta, nodeID platform.ID, inner []byte) proto.Message {
				return &fleetv1.FleetServiceCancelNodeTaskRequest{Meta: meta, NodeId: id(nodeID), Request: inner}
			}, func() proto.Message { return &fleetv1.FleetServiceCancelNodeTaskResponse{} }},
	}
}

const routedSubmitMethod = relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK

// normalizeRouted replaces, in a message, every ID by its placeholder (the node's as 0xa6, any other as 0xa1) and every Instant by 0.
func normalizeRouted(p *channelPlaceholders, nodeID platform.ID, fixed map[string]bool, message protoreflect.Message) {
	if message.Descriptor().FullName() == "arcforges.foundation.v1.Id" {
		field := message.Descriptor().Fields().ByName("value")
		value := message.Get(field).Bytes()
		switch {
		case bytes.Equal(value, nodeID[:]):
			message.Set(field, protoreflect.ValueOfBytes(p.id(value, 0xa6)))
		case !fixed[hex.EncodeToString(value)]:
			message.Set(field, protoreflect.ValueOfBytes(p.id(value, 0xa1)))
		}
		return
	}
	if message.Descriptor().FullName() == "arcforges.foundation.v1.Instant" {
		message.Set(message.Descriptor().Fields().ByName("unix_seconds"), protoreflect.ValueOfInt64(0))
		message.Set(message.Descriptor().Fields().ByName("nanos"), protoreflect.ValueOfUint32(0))
		return
	}
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Kind() == protoreflect.MessageKind && !field.IsList() && !field.IsMap() {
			normalizeRouted(p, nodeID, fixed, value.Message())
		}
		return true
	})
}

// TestRoutedExchangeCapture captures the routed methods' cases (E2-26). ARCFORGES_UPDATE_EXCHANGES=1 rewrites the directory.
func TestRoutedExchangeCapture(t *testing.T) {
	main := routedHarness(t)
	gated := newHarness(t, settings{surfaces: "identity,pages,fleet,relay,nodes", disabled: "center.execute,remote.view,remote.control",
		tune: func(s *hub.Settings) { s.Heartbeat, s.HeartbeatDeadline = time.Second, 30*time.Second }})
	quota := newHarness(t, settings{surfaces: "identity,pages,fleet,relay,nodes", policy: `{"routedCallsAccountLimit": 1}`,
		tune: func(s *hub.Settings) { s.Heartbeat, s.HeartbeatDeadline = time.Second, 30*time.Second }})
	fixed := map[string]bool{}
	for _, b := range []byte{0x51, 0x52, 0x91, 0x92, 0x93, 0x94, 0x95} {
		value := fixedID(b)
		fixed[hex.EncodeToString(value[:])] = true
	}
	cases := map[string]channelExchange{}
	capture := func(h *harness, m routedMethodCase, name string, node *enrolled, issued session.Native, command platform.ID) {
		t.Helper()
		meta := &foundationv1.RequestMeta{}
		if m.mutation {
			meta.CommandId = &foundationv1.Id{Value: append([]byte(nil), command[:]...)}
			h.proveFor(issued, node.user, m.class, node.node.ID)
		}
		request := m.build(meta, node.node.ID, m.inner(command))
		reply, err := nodetest.Client{URL: h.url, ClientIPHeader: config.ClientIPHeader}.Post(m.path, request, issued.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		response := m.newResult()
		if _, err := nodetest.Decode(reply, response); err != nil {
			t.Fatalf("%s %s: %v", m.name, name, err)
		}
		p := &channelPlaceholders{t: t, start: time.Now(), ids: map[string][]byte{}, values: map[string]string{}, counts: map[string]int{}}
		normalizedRequest := proto.Clone(request)
		normalizeRouted(p, node.node.ID, fixed, normalizedRequest.ProtoReflect())
		normalizeRouted(p, node.node.ID, fixed, response.ProtoReflect())
		outcome := "value"
		if failure := response.ProtoReflect().Get(response.ProtoReflect().Descriptor().Fields().ByName("error")).Message(); failure.IsValid() {
			outcome = errorKey(failure.Interface().(*foundationv1.ArcError))
		}
		requestBytes, replyBytes := mustMarshal(t, normalizedRequest), mustMarshal(t, response)
		value := channelExchange{SchemaVersion: 2, Source: "Cloud center/internal/hub routed_capture_integration_test.go", ContractsCohort: channelCohort,
			Method: m.path, Case: name, Outcome: outcome,
			Headers:    map[string]string{"authorization": "Bearer " + p.token(issued.AccessToken), "content-type": "application/grpc-web+proto"},
			Request:    channelWire{ContentType: "application/grpc-web+proto", Frames: []string{hex.EncodeToString(requestBytes)}},
			Reply:      channelWire{ContentType: "application/grpc-web+proto", HTTPStatus: reply.HTTP, Frames: []string{hex.EncodeToString(replyBytes)}, Trailers: "grpc-status:" + reply.Status},
			Normalized: routedCaptureNormalization}
		sum := sha256Hex(append(append([]byte(nil), requestBytes...), replyBytes...))
		value.SHA256 = sum
		cases[m.name+"-"+name] = value
	}
	for _, m := range routedMethodCases(t) {
		// ok, offline and unknown on the main center, each with its own account and node.
		user := main.db.Account(1)
		node := main.enrollIn(user)
		issued := main.accountSession(user, session.ScopeAccount)
		capture(main, m, "offline", node, issued, fixedID(0x91))
		channel := main.connect(node)
		calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
			return node.node.Executed(call, m.response), m.response, true
		})
		capture(main, m, "ok", node, issued, fixedID(0x92))
		<-calls
		other := main.enrollIn(user)
		otherChannel := main.connect(other)
		dropped := serve(t, other, otherChannel, func(*relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
			_ = otherChannel.WS.CloseNow()
			return nil, nil, false
		})
		capture(main, m, "unknown", other, issued, fixedID(0x93))
		<-dropped
		// gated: the features are disabled.
		gatedUser := gated.db.Account(1)
		gatedNode := gated.enrollIn(gatedUser)
		capture(gated, m, "gated", gatedNode, gated.accountSession(gatedUser, session.ScopeAccount), fixedID(0x94))
		// quota: one routed call per account and window; the first (to an offline node) takes it.
		quotaUser := quota.db.Account(1)
		quotaNode := quota.enrollIn(quotaUser)
		quotaSession := quota.accountSession(quotaUser, session.ScopeAccount)
		capture(quota, m, "offline-first", quotaNode, quotaSession, fixedID(0x95))
		delete(cases, m.name+"-offline-first")
		capture(quota, m, "quota", quotaNode, quotaSession, fixedID(0x94))
	}
	for name, value := range cases {
		want := map[string]string{"ok": "value", "offline": "STATE/node_offline", "unknown": "STATE/node_unreachable", "gated": "ENTITLEMENT/feature_not_entitled",
			"quota": "RESOURCE/rate_limited"}[value.Case]
		if value.Outcome != want {
			t.Errorf("%s: %s, want %s", name, value.Outcome, want)
		}
	}
	if os.Getenv("ARCFORGES_UPDATE_EXCHANGES") == "1" {
		writeRoutedExchanges(t, cases)
		return
	}
	committed, err := filepath.Glob(filepath.Join(routedExchangesDirectory, "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(committed) != len(cases) {
		t.Errorf("%d committed routed exchanges, %d captured: run ARCFORGES_UPDATE_EXCHANGES=1 go test -run TestRoutedExchangeCapture", len(committed), len(cases))
	}
	for _, file := range committed {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var stored channelExchange
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&stored); err != nil {
			t.Errorf("%s: %v", file, err)
			continue
		}
		captured, ok := cases[strings.TrimSuffix(filepath.Base(file), ".json")]
		stored.CenterCommit, captured.CenterCommit = "", ""
		left, _ := json.Marshal(stored)
		right, _ := json.Marshal(captured)
		if !ok || !bytes.Equal(left, right) {
			t.Errorf("%s differs from a fresh capture: run ARCFORGES_UPDATE_EXCHANGES=1 go test -run TestRoutedExchangeCapture", file)
		}
	}
}

func writeRoutedExchanges(t *testing.T, cases map[string]channelExchange) {
	t.Helper()
	if err := os.MkdirAll(routedExchangesDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(cases))
	for name := range cases {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		value := cases[name]
		value.CenterCommit = os.Getenv("ARCFORGES_CENTER_COMMIT")
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(routedExchangesDirectory, name+".json"), append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
