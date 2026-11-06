// SPDX-License-Identifier: AGPL-3.0-only

package fleetapi

import (
	"bytes"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

func marshal(t *testing.T, message proto.Message) []byte {
	t.Helper()
	data, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func pid(value platform.ID) *foundationv1.Id {
	return &foundationv1.Id{Value: append([]byte(nil), value[:]...)}
}

// TestTheOutcomeDigestLeavesOutOnlyTheVolatileFields (decisions Q-5, a requirement for N2): two renderings of one outcome that differ
// only in ResponseMeta, the ArcError's correlation_id and its retry_at have one digest; a change of any other field (the code, the
// effect, the retry mode, the value) changes it.
func TestTheOutcomeDigestLeavesOutOnlyTheVolatileFields(t *testing.T) {
	refusal := func(correlation platform.ID, at int64, code string, mode foundationv1.RetryMode) []byte {
		return marshal(t, &nodev1.TaskServiceCancelTaskResponse{Meta: &foundationv1.ResponseMeta{CorrelationId: pid(platform.NewID())},
			Outcome: &nodev1.TaskServiceCancelTaskResponse_Error{Error: &foundationv1.ArcError{Code: proto.String(code),
				Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE.Enum(), CorrelationId: pid(correlation),
				Retry:  &foundationv1.RetryAdvice{Mode: mode.Enum(), RetryAt: &foundationv1.Instant{UnixSeconds: proto.Int64(at)}},
				Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum()}}})
	}
	digest := func(data []byte) []byte {
		value, err := OutcomeDigest(data)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	after := foundationv1.RetryMode_RETRY_MODE_AFTER_TIME
	base := digest(refusal(platform.NewID(), 100, "invalid_state", after))
	if !bytes.Equal(base, digest(refusal(platform.NewID(), 200, "invalid_state", after))) {
		t.Fatal("the meta, the correlation ID and retry_at are left out")
	}
	if bytes.Equal(base, digest(refusal(platform.NewID(), 100, "not_found", after))) ||
		bytes.Equal(base, digest(refusal(platform.NewID(), 100, "invalid_state", foundationv1.RetryMode_RETRY_MODE_NEVER))) {
		t.Fatal("the code and the retry mode are digested")
	}
	value := func(task platform.ID) []byte {
		return marshal(t, &nodev1.TaskServiceSubmitTaskResponse{Meta: &foundationv1.ResponseMeta{CorrelationId: pid(platform.NewID())},
			Outcome: &nodev1.TaskServiceSubmitTaskResponse_Value{Value: &nodev1.TaskServiceSubmitTaskValue{TaskId: pid(task)}}})
	}
	task := platform.NewID()
	if !bytes.Equal(digest(value(task)), digest(value(task))) || bytes.Equal(digest(value(task)), digest(value(platform.NewID()))) {
		t.Fatal("a value's digest follows the value only")
	}
	if _, err := OutcomeDigest([]byte{0x1a, 0x05, 0x01}); err == nil {
		t.Fatal("a malformed response has no digest")
	}
}

// TestTheInnerRequestIsCheckedAndBounded (CTR5-RTE-01, -02, -06): the inner request's shape, the command ID tie and the routed bounds,
// and the method's deadline (Wait: wait_ms + 5 s, at most 55 s; ReadOutput: wait_ms + 10 s, at most 30 s; 10 s otherwise).
func TestTheInnerRequestIsCheckedAndBounded(t *testing.T) {
	command, task := platform.NewID(), platform.NewID()
	submit := func(meta platform.ID, spec bool) []byte {
		request := &nodev1.TaskServiceSubmitTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: pid(meta)}}
		if spec {
			request.Spec = &nodev1.TaskSpec{}
		}
		return marshal(t, request)
	}
	cases := []struct {
		name     string
		method   relayv1.RoutedMethod
		payload  []byte
		outer    *platform.ID
		field    string
		deadline time.Duration
		long     bool
	}{
		{"submit", relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK, submit(command, true), &command, "", 10 * time.Second, false},
		{"submit without a spec", relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK, submit(command, false), &command, "request.spec", 0, false},
		{"another inner command", relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK, submit(platform.NewID(), true), &command, "request.meta.command_id", 0, false},
		{"an empty request", relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_TASK, nil, nil, "request", 0, false},
		{"a read over 3,072 bytes", relayv1.RoutedMethod_ROUTED_METHOD_LIST_NODE_TASKS, make([]byte, 3073), nil, "request", 0, false},
		{"get without a task", relayv1.RoutedMethod_ROUTED_METHOD_GET_NODE_TASK, marshal(t, &nodev1.TaskServiceGetTaskRequest{Detail: nodev1.TaskDetail(1).Enum()}), nil,
			"request.task_id", 0, false},
		{"wait 50 s", relayv1.RoutedMethod_ROUTED_METHOD_WAIT_NODE_TASK, marshal(t, &nodev1.TaskServiceWaitTaskRequest{TaskId: pid(task), WaitMs: proto.Uint64(50_000)}),
			nil, "", 55 * time.Second, true},
		{"wait over 50 s", relayv1.RoutedMethod_ROUTED_METHOD_WAIT_NODE_TASK, marshal(t, &nodev1.TaskServiceWaitTaskRequest{TaskId: pid(task), WaitMs: proto.Uint64(50_001)}),
			nil, "request.wait_ms", 0, false},
		{"wait without waiting", relayv1.RoutedMethod_ROUTED_METHOD_WAIT_NODE_TASK, marshal(t, &nodev1.TaskServiceWaitTaskRequest{TaskId: pid(task)}), nil, "", 5 * time.Second, false},
		{"output 20 s", relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_TASK_OUTPUT, marshal(t, &nodev1.TaskServiceReadTaskOutputRequest{AttemptId: pid(task),
			WaitMs: proto.Uint32(20_000), MaxBytes: proto.Uint32(262_144)}), nil, "", 30 * time.Second, true},
		{"output over 256 KiB", relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_TASK_OUTPUT, marshal(t, &nodev1.TaskServiceReadTaskOutputRequest{AttemptId: pid(task),
			MaxBytes: proto.Uint32(262_145)}), nil, "request.max_bytes", 0, false},
		{"output over 20 s", relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_TASK_OUTPUT, marshal(t, &nodev1.TaskServiceReadTaskOutputRequest{AttemptId: pid(task),
			WaitMs: proto.Uint32(20_001)}), nil, "request.wait_ms", 0, false},
		{"output without waiting", relayv1.RoutedMethod_ROUTED_METHOD_READ_NODE_TASK_OUTPUT, marshal(t, &nodev1.TaskServiceReadTaskOutputRequest{AttemptId: pid(task)}), nil,
			"", 10 * time.Second, false},
		{"cancel", relayv1.RoutedMethod_ROUTED_METHOD_CANCEL_NODE_TASK, marshal(t, &nodev1.TaskServiceCancelTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: pid(command)},
			TaskId: pid(task)}), &command, "", 10 * time.Second, false},
	}
	for _, c := range cases {
		checked, err := checkInner(c.method, c.payload, c.outer)
		if c.field != "" {
			refusal, ok := err.(*arc.Refusal)
			if !ok || refusal.Code != "invalid_argument" || refusal.State != c.field {
				t.Fatalf("%s: %v", c.name, err)
			}
			continue
		}
		if err != nil || checked.deadline != c.deadline || checked.longPoll != c.long {
			t.Fatalf("%s: %+v, %v", c.name, checked, err)
		}
	}
	if hubDeadline(10*time.Second) != 9*time.Second || hubDeadline(55*time.Second) != 54*time.Second {
		t.Fatal("the hub waits the method's deadline less a second (Q-7)")
	}
}

// TestTheRecordDigestBindsTheCallerClassNotTheCorrelation (Q-4; decisions B-3): the digest follows the method, the node, the caller
// class and the request without its correlation ID; a resend from another session of the same account, or with a new correlation,
// converges, and another caller class or another request does not.
func TestTheRecordDigestBindsTheCallerClassNotTheCorrelation(t *testing.T) {
	user, node, command := platform.NewID(), platform.NewID(), platform.NewID()
	request := func(correlation platform.ID, marker string) []byte {
		return marshal(t, &nodev1.TaskServiceSubmitTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: pid(command), CorrelationId: pid(correlation)},
			Spec: &nodev1.TaskSpec{Title: proto.String(marker)}})
	}
	session := fleet.RoutedCaller{Kind: fleet.RoutedCallerSession, SessionID: platform.NewID()}
	relay := fleet.RoutedCaller{Kind: fleet.RoutedCallerRelay, RelayingNodeID: node, LocalOrigin: 1, LocalSessionID: platform.NewID()}
	digest := func(caller fleet.RoutedCaller, payload []byte) []byte {
		value, err := recordDigest(relayv1.RoutedMethod_ROUTED_METHOD_SUBMIT_NODE_TASK, node, caller, user, payload)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	first := digest(session, request(platform.NewID(), "a"))
	other := session
	other.SessionID = platform.NewID()
	if !bytes.Equal(first, digest(other, request(platform.NewID(), "a"))) {
		t.Fatal("another session or correlation of the same request converges")
	}
	script := relay
	script.LocalOrigin = 2
	if bytes.Equal(first, digest(relay, request(platform.NewID(), "a"))) || bytes.Equal(digest(relay, request(platform.NewID(), "a")), digest(script, request(platform.NewID(), "a"))) ||
		bytes.Equal(first, digest(session, request(platform.NewID(), "b"))) {
		t.Fatal("the caller class and the request are digested")
	}
}
