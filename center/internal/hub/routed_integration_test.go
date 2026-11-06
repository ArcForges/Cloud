// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
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
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The routed task methods of FleetService (AF-CTR-05 part E2b; Plan CTR5-RTE-01..07, CTR5-CALL-01..03, PB-1, PB-2, D0-B1, C-N1, PN-1,
// PN-6; decisions B-1..B-3, Q-5, Q-8, Q-15 and section 4; EVIDENCE: REAL PostgreSQL, the composed center with its real ingress, session
// verifier, authorizer, relay verification, controls and gate, the real WebSocket server and hub; MOCKED: the nodes, nodetest with
// software keys, whose answers the tests write, and the step-up ceremony, whose proved challenge is seeded as identityapi's tests do).

// routedHarness is a center with the nodes surface; its channels answer heartbeats while a test waits for calls.
func routedHarness(t *testing.T) *harness {
	t.Helper()
	return newHarness(t, settings{surfaces: "identity,pages,fleet,relay,nodes",
		tune: func(s *hub.Settings) { s.Heartbeat, s.HeartbeatDeadline = time.Second, 30*time.Second }})
}

// submitPayload is a TaskServiceSubmitTaskRequest of a command with planted markers in its argv, working directory and environment.
func submitPayload(t *testing.T, command platform.ID, marker string) []byte {
	t.Helper()
	data, err := proto.Marshal(&nodev1.TaskServiceSubmitTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command), CorrelationId: idValue(platform.NewID())},
		Spec: &nodev1.TaskSpec{Command: &nodev1.CommandSpec{Form: &nodev1.CommandSpec_Argv{Argv: &nodev1.ArgvCommand{Argv: []string{"/bin/echo", marker + "-ARGV"}}}},
			WorkingDirectory: proto.String("/srv/" + marker + "-CWD"), Environment: &nodev1.EnvironmentSpec{Set: map[string]string{"SECRET": marker + "-ENV"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// submitResponse is a node's TaskServiceSubmitTaskResponse with a task ID and a warning that carries a marker.
func submitResponse(t *testing.T, task platform.ID, marker string) []byte {
	t.Helper()
	data, err := proto.Marshal(&nodev1.TaskServiceSubmitTaskResponse{Meta: &foundationv1.ResponseMeta{CorrelationId: idValue(platform.NewID())},
		Outcome: &nodev1.TaskServiceSubmitTaskResponse_Value{Value: &nodev1.TaskServiceSubmitTaskValue{TaskId: idValue(task), Warnings: []string{marker + "-WARNING"}}}})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// respond answers one routed call: the result header and its payload, or answer false to leave the call unanswered.
type respond func(call *relayv1.ChannelCall) (header *relayv1.ResultHeader, payload []byte, answer bool)

// serve answers a node's routed calls until its channel closes and hands each call to the test.
func serve(t *testing.T, node *enrolled, channel *nodetest.Channel, answer respond) <-chan *relayv1.ChannelCall {
	t.Helper()
	calls := make(chan *relayv1.ChannelCall, 128)
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			call, err := channel.NextCall(ctx)
			if err != nil {
				cancel()
				close(calls)
				return
			}
			calls <- call
			if header, payload, ok := answer(call); ok {
				_ = channel.Answer(ctx, node.node, call.GetCallId(), header, payload)
			}
			cancel()
		}
	}()
	return calls
}

// deduplicating is a MOCKED node's command deduplication: the first call of a command ID executes (its response is the one given),
// every later call of the same command replays that response.
func deduplicating(node *enrolled, response func(*relayv1.ChannelCall) []byte) respond {
	var mu sync.Mutex
	seen := map[string][]byte{}
	return func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		mu.Lock()
		defer mu.Unlock()
		var header relayv1.CallHeader
		_ = proto.Unmarshal(call.GetHeader().GetHeader(), &header)
		key := string(header.GetCommandId().GetValue())
		if recorded, ok := seen[key]; ok && key != "" {
			return node.node.Executed(call, recorded), recorded, true
		}
		value := response(call)
		seen[key] = value
		return node.node.Executed(call, value), value, true
	}
}

func (h *harness) submit(bearer string, commandID, nodeID platform.ID, payload []byte) *fleetv1.FleetServiceSubmitNodeTaskResponse {
	h.t.Helper()
	response := &fleetv1.FleetServiceSubmitNodeTaskResponse{}
	h.rpc(fleetv1connect.FleetServiceSubmitNodeTaskProcedure, &fleetv1.FleetServiceSubmitNodeTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(commandID)},
		NodeId: idValue(nodeID), Request: payload}, bearer, response)
	return response
}

// proveFor seeds one proved step-up challenge of a class bound to a node for an account session.
func (h *harness) proveFor(issued session.Native, user platform.ID, class string, nodeID platform.ID) {
	h.t.Helper()
	target, err := hex.DecodeString(identity.TargetHash(class, user, nodeID))
	if err != nil {
		h.t.Fatal(err)
	}
	h.db.ProveStepUp(dbtest.Session{ID: issued.SessionID, User: user}, class, target, time.Now())
}

func (h *harness) record(user, command platform.ID) *fleet.RoutedRecord {
	h.t.Helper()
	value, err := fleet.ReadRouted(context.Background(), h.db.Runtime, user, command)
	if err != nil {
		h.t.Fatal(err)
	}
	return value
}

// TestASubmitIsRoutedRecordedAndReplayedByTheNode (E2-4, E2-7, E2-9; decisions B-3, N-3): an account session's Submit, with step-up
// evidence bound to the node, routes the exact inner bytes; the record is SUCCEEDED with the task ID and holds no byte of the request
// or response; a resend needs fresh evidence (without it: step_up_required and nothing routed), is then routed again with its own bytes,
// and the node's deduplication replays the outcome, which the center answers; a resend with other bytes is command_id_reused.
func TestASubmitIsRoutedRecordedAndReplayedByTheNode(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	task := platform.NewID()
	recorded := submitResponse(t, task, "PLANTED")
	calls := serve(t, node, channel, deduplicating(node, func(*relayv1.ChannelCall) []byte { return recorded }))
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	payload := submitPayload(t, command, "PLANTED")
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	first := h.submit(issued.AccessToken, command, node.node.ID, payload)
	if first.GetError() != nil {
		t.Fatalf("the submit: %v", first.GetError())
	}
	sent := <-calls
	if !bytes.Equal(sent.GetPayload(), payload) {
		t.Fatal("the node did not receive the caller's exact bytes")
	}
	if !proto.Equal(first.GetValue().GetNodeId(), idValue(node.node.ID)) || !bytes.Equal(first.GetValue().GetResponse(), recorded) {
		t.Fatalf("the reply: %v", first.GetValue())
	}
	record := h.record(user, command)
	if record == nil || record.State != fleet.RoutedSucceeded || !record.Final || !record.Delivered || record.Attempts != 1 || record.TaskID == nil || *record.TaskID != task {
		t.Fatalf("the record: %+v", record)
	}
	// A resend without fresh evidence: step_up_required, nothing routed, the record unchanged.
	if failure := h.submit(issued.AccessToken, command, node.node.ID, payload).GetError(); errorKey(failure) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("a resend without evidence: %v", failure)
	}
	if got := h.record(user, command); got.Attempts != 1 {
		t.Fatalf("a refused resend changed the record: %+v", got)
	}
	// With fresh evidence: routed again (the resend's own bytes, a new correlation inside), and the node replays.
	resent := submitPayload(t, command, "PLANTED")
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	second := h.submit(issued.AccessToken, command, node.node.ID, resent)
	if second.GetError() != nil || !bytes.Equal(second.GetValue().GetResponse(), first.GetValue().GetResponse()) {
		t.Fatalf("the resend: %v", second)
	}
	if again := <-calls; !bytes.Equal(again.GetPayload(), resent) {
		t.Fatal("the resend is not routed with its own bytes")
	}
	if got := h.record(user, command); got.State != fleet.RoutedSucceeded || got.Attempts != 2 {
		t.Fatalf("after the resend: %+v", got)
	}
	// Other bytes under the same command ID.
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	other := submitPayload(t, command, "OTHER")
	if failure := h.submit(issued.AccessToken, command, node.node.ID, other).GetError(); errorKey(failure) != "CONFLICT/command_id_reused" {
		t.Fatalf("other bytes under the command: %v", failure)
	}
	if h.audits("fleet.routed.accepted") != 2 || h.audits("fleet.routed.result") != 2 {
		t.Fatalf("the audit: %d accepted, %d results", h.audits("fleet.routed.accepted"), h.audits("fleet.routed.result"))
	}
}

// TestAnOfflineNodeIsRefusedBeforeItsRecord (E2-5; decisions Q-8): a Submit for a live node without a channel here is STATE/node_offline
// (DID_NOT_HAPPEN, AFTER_TIME): no routing record, no evidence consumed, one fleet.routed.refused row (reason node_offline, digests and
// sizes only); a read for it is node_offline with no fleet.routed row at all.
func TestAnOfflineNodeIsRefusedBeforeItsRecord(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	failure := h.submit(issued.AccessToken, command, node.node.ID, submitPayload(t, command, "OFFLINE")).GetError()
	if errorKey(failure) != "STATE/node_offline" || failure.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN ||
		failure.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME {
		t.Fatalf("the submit: %v", failure)
	}
	if h.record(user, command) != nil || h.audits("fleet.routed.refused") != 1 || h.audits("fleet.routed.accepted") != 0 {
		t.Fatalf("an offline submit wrote: record %v, %d refused", h.record(user, command), h.audits("fleet.routed.refused"))
	}
	if consumed := h.count("SELECT count(*) FROM identity.step_up_challenge WHERE consumed_at IS NOT NULL"); consumed != 0 {
		t.Fatalf("an offline submit consumed %d challenges", consumed)
	}
	payload := h.count(`SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.routed.refused' AND payload::text NOT LIKE '%OFFLINE%' AND reason = 'node_offline'`)
	if payload != 1 {
		t.Fatal("the refused row names its reason and no request text")
	}
	read, err := proto.Marshal(&nodev1.TaskServiceGetTaskRequest{TaskId: idValue(platform.NewID())})
	if err != nil {
		t.Fatal(err)
	}
	response := &fleetv1.FleetServiceGetNodeTaskResponse{}
	h.rpc(fleetv1connect.FleetServiceGetNodeTaskProcedure, &fleetv1.FleetServiceGetNodeTaskRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(node.node.ID),
		Request: read}, issued.AccessToken, response)
	if errorKey(response.GetError()) != "STATE/node_offline" || h.audits("fleet.routed.refused") != 1 {
		t.Fatalf("an offline read: %v", response.GetError())
	}
}

// TestARecordIsDeliveredExactlyWhenTheReplyIsUnknown (the E1b "delivered" definition, a command's first attempt; decisions B-1): a call whose frame the writer never
// took (the writes stalled until the deadline) is answered DID_NOT_HAPPEN and recorded NOT_DELIVERED, not delivered, and the node never
// receives it; a call the node received whose channel then closed is answered UNKNOWN and recorded UNKNOWN, delivered.
func TestARecordIsDeliveredExactlyWhenTheReplyIsUnknown(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	issued := h.accountSession(user, session.ScopeAccount)
	release := h.center.Hub.StallWrites(node.node.ID)
	command := platform.NewID()
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	failure := h.submit(issued.AccessToken, command, node.node.ID, submitPayload(t, command, "STALLED")).GetError()
	release()
	if errorKey(failure) != "STATE/node_unreachable" || failure.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
		t.Fatalf("a stalled submit: %v", failure)
	}
	if got := h.record(user, command); !eventually(t, 5*time.Second, func() bool {
		got := h.record(user, command)
		return got != nil && got.State == fleet.RoutedNotDelivered && !got.Delivered
	}) {
		t.Fatalf("a stalled submit's record: %+v", got)
	}
	// The node reads the next call and its channel closes before it answers.
	calls := serve(t, node, channel, func(*relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) { return nil, nil, false })
	second := platform.NewID()
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	done := make(chan *foundationv1.ArcError, 1)
	go func() {
		done <- h.submit(issued.AccessToken, second, node.node.ID, submitPayload(t, second, "CLOSED")).GetError()
	}()
	select {
	case <-calls:
	case <-time.After(10 * time.Second):
		t.Fatal("the node did not receive the call")
	}
	_ = channel.WS.CloseNow()
	failure = <-done
	if errorKey(failure) != "STATE/node_unreachable" || failure.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
		failure.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND {
		t.Fatalf("a delivered submit whose channel closed: %v", failure)
	}
	if !eventually(t, 5*time.Second, func() bool {
		got := h.record(user, second)
		return got != nil && got.State == fleet.RoutedUnknown && got.Delivered && !got.Final
	}) {
		t.Fatalf("the delivered submit's record: %+v", h.record(user, second))
	}
}

// TestALostSettlementCountsAsDeliveredAndTheWindowComesFirst (decisions B-1): a settlement that cannot be written leaves the record
// ACCEPTED; with no attempt in flight, a resend counts it as one that may have reached the node, so past the replay window it is
// STATE/invalid_state replay_window_passed whether the node is online or offline, and is never routed.
func TestALostSettlementCountsAsDeliveredAndTheWindowComesFirst(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	task := platform.NewID()
	calls := serve(t, node, channel, deduplicating(node, func(*relayv1.ChannelCall) []byte { return submitResponse(t, task, "LOST") }))
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	payload := submitPayload(t, command, "LOST")
	// The runtime role may insert records but no longer update them: the settlement fails on every try.
	role := `"` + h.db.Name + `_runtime"`
	h.db.Exec("REVOKE UPDATE ON fleet.routed_call FROM " + role)
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	if reply := h.submit(issued.AccessToken, command, node.node.ID, payload); reply.GetError() != nil {
		t.Fatalf("the submit is answered as the node answered it: %v", reply.GetError())
	}
	<-calls
	time.Sleep(time.Second) // the settlement's retries
	if got := h.record(user, command); got == nil || got.State != fleet.RoutedAccepted || got.Delivered {
		t.Fatalf("a lost settlement's record: %+v", got)
	}
	h.db.Exec("GRANT UPDATE ON fleet.routed_call TO " + role)
	// Past the window by a minute (the record was created 23 h 1 min ago): refused online, and offline, never routed.
	// (The record's trigger keeps created_at; the test moves it with the migration role, the trigger set aside for the one statement.)
	h.db.Exec("ALTER TABLE fleet.routed_call DISABLE TRIGGER routed_call_guarded", "UPDATE fleet.routed_call SET created_at = created_at - interval '23 hours 1 minute' WHERE command_id = '"+
		command.String()+"'", "ALTER TABLE fleet.routed_call ENABLE TRIGGER routed_call_guarded")
	for _, online := range []bool{true, false} {
		if !online {
			_ = channel.WS.CloseNow()
			eventually(t, 5*time.Second, func() bool { return !h.center.Hub.Connected(node.node.ID) })
		}
		h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
		failure := h.submit(issued.AccessToken, command, node.node.ID, payload).GetError()
		if errorKey(failure) != "STATE/invalid_state" || failure.GetDetails().GetState().GetReason() != "replay_window_passed" ||
			failure.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN || failure.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER {
			t.Fatalf("a resend past the window (online %v): %v", online, failure)
		}
	}
	select {
	case call, open := <-calls:
		if open {
			t.Fatalf("a resend past the window was routed: %v", call.GetCallId())
		}
	default:
	}
	if got := h.record(user, command); got.Attempts != 1 {
		t.Fatalf("a refused resend changed the record: %+v", got)
	}
}

// TestALeaseTakeOverSweepsTheRecordsBeforeRouting (decisions B-1): a record left ACCEPTED (its settlement lost) becomes UNKNOWN and
// delivered when the hub takes the lease again, by the fenced boot sweep, before the hub routes anything; an admission under a fence that
// is no longer live commits nothing.
func TestALeaseTakeOverSweepsTheRecordsBeforeRouting(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	enrollment := node.result.EnrollmentID
	command := platform.NewID()
	h.db.Exec(`INSERT INTO fleet.routed_call (account_id, command_id, node_enrollment_id, node_id, method, caller_kind, session_id, request_digest, request_size,
    state, delivered, attempts, created_at, updated_at) VALUES ('` + user.String() + `', '` + command.String() + `', '` + enrollment.String() + `', '` +
		node.node.ID.String() + `', 1, 1, gen_random_uuid(), decode(repeat('ab', 32), 'hex'), 10, 1, false, 1, now(), now())`)
	fence, routable := h.center.Hub.Routable()
	if !routable {
		t.Fatal("the hub does not route after its start")
	}
	// Another process takes the lease over (it expired), then this hub takes it back under a higher fence.
	h.db.Exec("UPDATE fleet.hub_lease SET fence = fence + 1, holder = gen_random_uuid(), expires_at = now()")
	if !eventually(t, 10*time.Second, func() bool {
		next, ok := h.center.Hub.Routable()
		return ok && next > fence
	}) {
		t.Fatal("the hub did not take the lease back")
	}
	got := h.record(user, command)
	if got == nil || got.State != fleet.RoutedUnknown || !got.Delivered {
		t.Fatalf("the swept record: %+v", got)
	}
	// An admission under the old fence: node_offline, nothing written.
	_, err := fleet.AcceptRouted(context.Background(), h.db.Runtime, fleet.RoutedAccept{AccountID: user, NodeID: node.node.ID, CommandID: platform.NewID(), Method: 1,
		Caller: fleet.RoutedCaller{Kind: fleet.RoutedCallerSession, SessionID: platform.NewID(), Actor: identity.Actor(user)}, Digest: make([]byte, 32),
		RequestSHA256: make([]byte, 32), Size: 10, Fence: fence, Window: time.Hour, InFlight: func() bool { return false }, Online: func() bool { return true },
		Now: time.Now()})
	if !strings.Contains(errorText(err), "node_offline") || h.count("SELECT count(*) FROM fleet.routed_call") != 1 {
		t.Fatalf("an admission under a stale fence: %v", err)
	}
	// A resend of the swept record under the stale fence (review A CN-1): node_unreachable with UNKNOWN, and nothing is written.
	_, err = fleet.AcceptRouted(context.Background(), h.db.Runtime, fleet.RoutedAccept{AccountID: user, NodeID: node.node.ID, CommandID: command, Method: 1,
		Caller: fleet.RoutedCaller{Kind: fleet.RoutedCallerSession, SessionID: platform.NewID(), Actor: identity.Actor(user)}, Digest: bytes.Repeat([]byte{0xab}, 32),
		RequestSHA256: make([]byte, 32), Size: 10, Fence: fence, Window: time.Hour, InFlight: func() bool { return false }, Online: func() bool { return true },
		Now: time.Now()})
	var refusal *arc.Refusal
	if !errors.As(err, &refusal) || refusal.Code != "node_unreachable" || refusal.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
		refusal.Retry != foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND {
		t.Fatalf("a resend under a stale fence: %v", err)
	}
	if got := h.record(user, command); got.Attempts != 1 {
		t.Fatalf("a fenced resend wrote: %+v", got)
	}
	// A sweep that cannot commit (the runtime role may not update the records): the hub holds the new lease but routes nothing, a read
	// to the node's open channel included, until a later wake of the lease loop sweeps.
	role := `"` + h.db.Name + `_runtime"`
	h.db.Exec("REVOKE UPDATE ON fleet.routed_call FROM " + role)
	held, _ := h.center.Hub.Lease().Fence()
	h.db.Exec("UPDATE fleet.hub_lease SET fence = fence + 1, holder = gen_random_uuid(), expires_at = now()")
	if !eventually(t, 10*time.Second, func() bool {
		next, ok := h.center.Hub.Lease().Fence()
		return ok && next > held+1
	}) {
		t.Fatal("the hub did not take the lease back")
	}
	if _, routable := h.center.Hub.Routable(); routable {
		t.Fatal("the hub routes before its sweep committed")
	}
	channel := h.connect(node)
	serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		return node.node.Executed(call, []byte{0x12, 0x00}), []byte{0x12, 0x00}, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	read := func() *foundationv1.ArcError {
		response := &fleetv1.FleetServiceGetNodeTaskResponse{}
		h.rpc(fleetv1connect.FleetServiceGetNodeTaskProcedure, &fleetv1.FleetServiceGetNodeTaskRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(node.node.ID),
			Request: marshalInner(t, &nodev1.TaskServiceGetTaskRequest{TaskId: idValue(platform.NewID())})}, issued.AccessToken, response)
		return response.GetError()
	}
	if failure := read(); errorKey(failure) != "STATE/node_offline" {
		t.Fatalf("a read before the sweep committed: %v", failure)
	}
	h.db.Exec("GRANT UPDATE ON fleet.routed_call TO " + role)
	if !eventually(t, 10*time.Second, func() bool { _, ok := h.center.Hub.Routable(); return ok }) {
		t.Fatal("the hub did not sweep again")
	}
	if failure := read(); failure != nil {
		t.Fatalf("a read after the sweep: %v", failure)
	}
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestConcurrentDuplicatesJoinOneRoutedCall (E2-23; decisions Q-15): duplicates of a Submit in flight join it: one routed call, one
// execution, every caller the same answer, each with its own evidence consumed.
func TestConcurrentDuplicatesJoinOneRoutedCall(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	task := platform.NewID()
	gate := make(chan struct{})
	response := submitResponse(t, task, "JOINED")
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		<-gate
		return node.node.Executed(call, response), response, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	payload := submitPayload(t, command, "JOINED")
	const callers = 8
	for range callers {
		h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	}
	replies := make(chan *fleetv1.FleetServiceSubmitNodeTaskResponse, callers)
	for range callers {
		go func() { replies <- h.submit(issued.AccessToken, command, node.node.ID, payload) }()
	}
	<-calls
	if !eventually(t, 5*time.Second, func() bool { return h.audits("fleet.routed.accepted") == callers }) {
		t.Fatalf("%d of %d callers admitted", h.audits("fleet.routed.accepted"), callers)
	}
	close(gate)
	for range callers {
		reply := <-replies
		if reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), response) {
			t.Fatalf("a joined caller's reply: %v", reply)
		}
	}
	select {
	case <-calls:
		t.Fatal("a duplicate was routed a second time")
	case <-time.After(300 * time.Millisecond):
	}
	if got := h.record(user, command); got.Attempts != 1 || got.State != fleet.RoutedSucceeded {
		t.Fatalf("the joined record: %+v", got)
	}
	if joined := h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.routed.accepted' AND reason = 'joined'"); joined != callers-1 {
		t.Fatalf("%d joined", joined)
	}
	if consumed := h.count("SELECT count(*) FROM identity.step_up_challenge WHERE consumed_at IS NOT NULL"); consumed != callers {
		t.Fatalf("%d evidence consumed", consumed)
	}
}

// TestANodeRefusalThatDidNotHappenIsNotFinal (decisions section 4): a node's signed refusal that says the call did not happen leaves the
// record REJECTED_BY_NODE and not final, so a resend is routed again; a node answer whose effect is unknown (a duplicate answered while
// the first still executes) is UNKNOWN, never final.
func TestANodeRefusalThatDidNotHappenIsNotFinal(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	task := platform.NewID()
	var mu sync.Mutex
	answers := 0
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		mu.Lock()
		defer mu.Unlock()
		answers++
		switch answers {
		case 1:
			refusal := policyRefusal()
			refusal.Effect = foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum()
			return node.node.Refused(call, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY, refusal), nil, true
		case 2:
			// The node's handler answers a duplicate while the first is still executing: its effect is unknown.
			response, err := proto.Marshal(&nodev1.TaskServiceSubmitTaskResponse{Outcome: &nodev1.TaskServiceSubmitTaskResponse_Error{Error: &foundationv1.ArcError{
				Category: foundationv1.ErrorCategory_ERROR_CATEGORY_CONFLICT.Enum(), Code: proto.String("command_id_reused"),
				Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND.Enum()}, Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN.Enum()}}})
			if err != nil {
				t.Error(err)
			}
			return node.node.Executed(call, response), response, true
		}
		response := submitResponse(t, task, "AGAIN")
		return node.node.Executed(call, response), response, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	payload := submitPayload(t, command, "AGAIN")
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	if failure := h.submit(issued.AccessToken, command, node.node.ID, payload).GetError(); errorKey(failure) != "AUTHORIZATION/permission_denied" {
		t.Fatalf("the node's refusal: %v", failure)
	}
	<-calls
	if got := h.record(user, command); got.State != fleet.RoutedRejected || got.Final || got.Refusal == nil || *got.Refusal != fleet.RefusalCode("authorization/permission_denied") {
		t.Fatalf("a refusal that did not happen: %+v", got)
	}
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	_ = h.submit(issued.AccessToken, command, node.node.ID, payload)
	<-calls
	if got := h.record(user, command); got.State != fleet.RoutedUnknown || got.Final || !got.Delivered {
		t.Fatalf("an answer whose effect is unknown: %+v", got)
	}
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	if reply := h.submit(issued.AccessToken, command, node.node.ID, payload); reply.GetError() != nil {
		t.Fatalf("the third attempt: %v", reply.GetError())
	}
	<-calls
	if got := h.record(user, command); got.State != fleet.RoutedSucceeded || got.Attempts != 3 {
		t.Fatalf("after the execution: %+v", got)
	}
}

// TestAReplayedOutcomeWithAnotherDigestIsUnknownAndAudited (E2-10; Q-5, N-2): a final record's resend whose replayed outcome differs
// outside ResponseMeta, the correlation ID and retry_at is node_unreachable replay_digest_differs (UNKNOWN, NEVER) and audited; one that
// differs only in those fields is the node's answer.
func TestAReplayedOutcomeWithAnotherDigestIsUnknownAndAudited(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	task := platform.NewID()
	var mu sync.Mutex
	answers := 0
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		mu.Lock()
		defer mu.Unlock()
		answers++
		marker := "SAME"
		if answers == 3 {
			marker = "DIFFERENT"
		}
		// Every answer carries a new ResponseMeta (submitResponse), which the comparison leaves out.
		response := submitResponse(t, task, marker)
		return node.node.Executed(call, response), response, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	payload := submitPayload(t, command, "REPLAY")
	for attempt := 1; attempt <= 3; attempt++ {
		h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
		failure := h.submit(issued.AccessToken, command, node.node.ID, payload).GetError()
		<-calls
		switch {
		case attempt < 3 && failure != nil:
			t.Fatalf("attempt %d: %v", attempt, failure)
		case attempt == 3 && (errorKey(failure) != "STATE/node_unreachable" || failure.GetDetails().GetState().GetReason() != "replay_digest_differs" ||
			failure.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN || failure.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER):
			t.Fatalf("a differing replay: %v", failure)
		}
	}
	if !eventually(t, 5*time.Second, func() bool { return h.audits("fleet.routed.replay_differs") == 1 }) {
		t.Fatal("the differing replay is not audited")
	}
	if got := h.record(user, command); got.State != fleet.RoutedSucceeded || got.Attempts != 3 {
		t.Fatalf("a final record keeps its outcome: %+v", got)
	}
}

// TestTheStepUpRulesStandBeforeTheRecord (PB-1): a mobile.limited session never reaches Submit (Cancel's identical rules are pinned by
// the operation table's tests) (step_up_required at the
// authorizer, nothing written beyond nothing), and an account session without evidence for the node routes nothing and records nothing.
func TestTheStepUpRulesStandBeforeTheRecord(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	calls := serve(t, node, channel, func(*relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) { return nil, nil, false })
	limited := h.accountSession(user, session.ScopeMobileLimited)
	before := h.writes()
	command := platform.NewID()
	if failure := h.submit(limited.AccessToken, command, node.node.ID, submitPayload(t, command, "LIMITED")).GetError(); errorKey(failure) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("mobile.limited: %v", failure)
	}
	if h.writes() != before {
		t.Fatal("a mobile.limited submit wrote")
	}
	issued := h.accountSession(user, session.ScopeAccount)
	h.proveFor(issued, user, "fleet.submitNodeTask", platform.NewID())
	if failure := h.submit(issued.AccessToken, command, node.node.ID, submitPayload(t, command, "NOEVIDENCE")).GetError(); errorKey(failure) != "AUTHENTICATION/step_up_required" {
		t.Fatalf("evidence for another node: %v", failure)
	}
	if h.record(user, command) != nil || h.audits("fleet.routed.accepted") != 0 {
		t.Fatal("a submit without evidence recorded")
	}
	select {
	case <-calls:
		t.Fatal("a submit without evidence was routed")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestARelayedSubmitCarriesOnlyTheVerifiedCaller (D0-B1, C-N1, C-N6): a node credential relays a Submit for its own node with a relay
// assertion over the inner bytes; the call header's caller is the assertion's (NODE_RELAY, its local origin and session), the record's
// caller a relay; the same request without an assertion is AUTHENTICATION/unauthenticated (relay_assertion missing) and writes nothing.
func TestARelayedSubmitCarriesOnlyTheVerifiedCaller(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	task := platform.NewID()
	command := platform.NewID()
	payload := submitPayload(t, command, "RELAY")
	request := &fleetv1.FleetServiceSubmitNodeTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)}, NodeId: idValue(node.node.ID),
		Caller: relayedCaller(node, nodev1.Origin_ORIGIN_SCRIPT), Request: payload}
	before := h.writes()
	// A token alone: with a routed caller and no assertion, and with neither.
	for _, bare := range []*fleetv1.FleetServiceSubmitNodeTaskRequest{request,
		{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)}, NodeId: idValue(node.node.ID), Request: payload}} {
		response := &fleetv1.FleetServiceSubmitNodeTaskResponse{}
		h.rpc(fleetv1connect.FleetServiceSubmitNodeTaskProcedure, bare, node.access, response)
		if failure := response.GetError(); errorKey(failure) != "AUTHENTICATION/unauthenticated" || failure.GetDetails().GetState().GetReason() != "missing" ||
			h.writes() != before || h.count("SELECT count(*) FROM fleet.routed_call") != 0 {
			t.Fatalf("a token alone: %v", failure)
		}
	}
	var response *fleetv1.FleetServiceSubmitNodeTaskResponse
	digest := sha256.Sum256(payload)
	local := platform.NewID()
	assertion := node.node.Assertion(publicBaseURL, nodetest.Relay{InstallationID: node.result.InstallationID, LocalOrigin: nodev1.Origin_ORIGIN_SCRIPT,
		LocalSession: local, Method: hub.MethodSubmitNodeTask, RequestSHA256: digest[:], Target: &node.node.ID, Command: &command, Nonce: nonceOf(t, channel)})
	encoded, err := proto.Marshal(assertion)
	if err != nil {
		t.Fatal(err)
	}
	request.RelayAssertion = encoded
	// The node answers calls from here on (the relay nonce was read from its channel above).
	calls := serve(t, node, channel, deduplicating(node, func(*relayv1.ChannelCall) []byte { return submitResponse(t, task, "RELAY") }))
	response = &fleetv1.FleetServiceSubmitNodeTaskResponse{}
	h.rpc(fleetv1connect.FleetServiceSubmitNodeTaskProcedure, request, node.access, response)
	if response.GetError() != nil {
		t.Fatalf("a relayed submit: %v", response.GetError())
	}
	header := headerOf(t, <-calls)
	caller := header.GetCaller()
	if caller.GetKind() != nodev1.CenterCallerKind_CENTER_CALLER_KIND_NODE_RELAY || caller.GetLocalOrigin() != nodev1.Origin_ORIGIN_SCRIPT ||
		!bytes.Equal(caller.GetLocalSessionId().GetValue(), local[:]) || !bytes.Equal(caller.GetRelayingNodeId().GetValue(), node.node.ID[:]) {
		t.Fatalf("the routed caller: %v", caller)
	}
	if kind := h.count("SELECT caller_kind FROM fleet.routed_call WHERE command_id = $1", command); kind != int(fleet.RoutedCallerRelay) {
		t.Fatalf("the record's caller kind %d", kind)
	}
}

func marshalInner(t *testing.T, message proto.Message) []byte {
	t.Helper()
	data, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestTheRoutedReadsAreForwardedWithoutARecord (E2-4, Q-10): Get, List, Wait and ReadOutput route their exact bytes and answer the
// node's response bytes unchanged; no routing record and no fleet.routed row is written for a read, only access.authorized.
func TestTheRoutedReadsAreForwardedWithoutARecord(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		response := append([]byte("\x12\x00"), call.GetPayload()[:1]...) // the node's bytes, whatever they are
		return node.node.Executed(call, response), response, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	task := idValue(platform.NewID())
	meta := &foundationv1.RequestMeta{}
	reads := []struct {
		path     string
		request  proto.Message
		response proto.Message
		inner    []byte
	}{
		{fleetv1connect.FleetServiceGetNodeTaskProcedure, nil, &fleetv1.FleetServiceGetNodeTaskResponse{}, marshalInner(t, &nodev1.TaskServiceGetTaskRequest{TaskId: task})},
		{fleetv1connect.FleetServiceListNodeTasksProcedure, nil, &fleetv1.FleetServiceListNodeTasksResponse{}, marshalInner(t, &nodev1.TaskServiceListTasksRequest{Filter: &nodev1.TaskFilter{}})},
		{fleetv1connect.FleetServiceWaitNodeTaskProcedure, nil, &fleetv1.FleetServiceWaitNodeTaskResponse{}, marshalInner(t, &nodev1.TaskServiceWaitTaskRequest{TaskId: task, WaitMs: proto.Uint64(10)})},
		{fleetv1connect.FleetServiceReadNodeTaskOutputProcedure, nil, &fleetv1.FleetServiceReadNodeTaskOutputResponse{}, marshalInner(t, &nodev1.TaskServiceReadTaskOutputRequest{AttemptId: task})},
	}
	reads[0].request = &fleetv1.FleetServiceGetNodeTaskRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: reads[0].inner}
	reads[1].request = &fleetv1.FleetServiceListNodeTasksRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: reads[1].inner}
	reads[2].request = &fleetv1.FleetServiceWaitNodeTaskRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: reads[2].inner}
	reads[3].request = &fleetv1.FleetServiceReadNodeTaskOutputRequest{Meta: meta, NodeId: idValue(node.node.ID), Request: reads[3].inner}
	authorized := h.audits("access.authorized")
	for _, read := range reads {
		h.rpc(read.path, read.request, issued.AccessToken, read.response)
		sent := <-calls
		if !bytes.Equal(sent.GetPayload(), read.inner) {
			t.Fatalf("%s: the node did not receive the exact bytes", read.path)
		}
		value := read.response.ProtoReflect().Get(read.response.ProtoReflect().Descriptor().Fields().ByName("value")).Message()
		got := value.Get(value.Descriptor().Fields().ByName("response")).Bytes()
		if !bytes.Equal(got, append([]byte("\x12\x00"), read.inner[:1]...)) {
			t.Fatalf("%s: the reply is not the node's bytes: %x", read.path, got)
		}
	}
	if h.count("SELECT count(*) FROM fleet.routed_call") != 0 || h.count("SELECT count(*) FROM audit.audit_event WHERE event_type LIKE 'fleet.routed.%'") != 0 ||
		h.audits("access.authorized") != authorized+4 {
		t.Fatalf("a read wrote a record or a routed row: %d authorized", h.audits("access.authorized"))
	}
}

// TestTheLongPollsHoldAtMostHalfTheConnections (PN-1): the routed long polls of all accounts wait in at most half of the request
// connections (ARCFORGES_CENTER_MAX_CONNECTIONS 8: four); a fifth is RESOURCE/overloaded before it is routed, and a slot frees when a
// wait ends. A per-account in-flight bound over half of the connections refuses to start the center.
func TestTheLongPollsHoldAtMostHalfTheConnections(t *testing.T) {
	h := newHarness(t, settings{surfaces: "identity,pages,fleet,relay,nodes", maxConnections: "8", policy: `{"routedInFlightPerAccount": 4}`,
		tune: func(s *hub.Settings) { s.Heartbeat, s.HeartbeatDeadline = time.Second, 30*time.Second }})
	release := make(chan struct{})
	waiting := make(chan struct{}, 16)
	wait := func(node *enrolled) {
		channel := h.connect(node)
		serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
			waiting <- struct{}{}
			// The node holds each wait until the test releases it, answering later on its own goroutine.
			go func() {
				<-release
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = channel.Answer(ctx, node.node, call.GetCallId(), node.node.Executed(call, []byte{0x12, 0x00}), []byte{0x12, 0x00})
			}()
			return nil, nil, false
		})
	}
	type poller struct {
		bearer string
		node   *enrolled
	}
	pollers := []poller{}
	for account := 1; account <= 3; account++ {
		user := h.db.Account(1)
		node := h.enrollIn(user)
		wait(node)
		pollers = append(pollers, poller{h.accountSession(user, session.ScopeAccount).AccessToken, node})
	}
	poll := func(p poller) *foundationv1.ArcError {
		response := &fleetv1.FleetServiceWaitNodeTaskResponse{}
		h.rpc(fleetv1connect.FleetServiceWaitNodeTaskProcedure, &fleetv1.FleetServiceWaitNodeTaskRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(p.node.node.ID),
			Request: marshalInner(t, &nodev1.TaskServiceWaitTaskRequest{TaskId: idValue(platform.NewID()), WaitMs: proto.Uint64(20_000)})}, p.bearer, response)
		return response.GetError()
	}
	results := make(chan *foundationv1.ArcError, 8)
	for _, p := range []poller{pollers[0], pollers[0], pollers[1], pollers[1]} {
		go func() { results <- poll(p) }()
	}
	for range 4 {
		select {
		case <-waiting:
		case <-time.After(10 * time.Second):
			t.Fatal("the long polls did not reach the nodes")
		}
	}
	if failure := poll(pollers[2]); errorKey(failure) != "RESOURCE/overloaded" || h.center.Metrics.Summary()["channel routed long_polls"] != 1 {
		t.Fatalf("a fifth long poll: %v, %d counted", failure, h.center.Metrics.Summary()["channel routed long_polls"])
	}
	close(release)
	for range 4 {
		if failure := <-results; failure != nil {
			t.Fatalf("a long poll: %v", failure)
		}
	}
	if failure := poll(pollers[2]); failure != nil {
		t.Fatalf("a long poll after the others ended: %v", failure)
	}
	values := map[string]string{config.EnvMode: string(config.SelfHosted), config.EnvPublicBaseURL: publicBaseURL, config.EnvMaxConnections: "8",
		config.EnvDatabaseURL: h.db.RuntimeURL, config.EnvSurfaces: "identity,pages,fleet,relay,nodes", config.EnvIdentityPolicy: `{"routedInFlightPerAccount": 5}`}
	if _, err := config.Load(func(key string) (string, bool) { value, ok := values[key]; return value, ok }); err == nil ||
		!strings.Contains(err.Error(), "routedInFlightPerAccount") {
		t.Fatalf("an in-flight bound over half of the connections: %v", err)
	}
}

// TestARoutedLongPollOutlastsTheServerTimeouts (E2-11, PN-1): on a server whose read and write timeouts are 2 s, a WaitNodeTask whose
// node answers after 3 s is answered: the route's own transport deadline (its budget plus a margin) replaces the server's for it.
func TestARoutedLongPollOutlastsTheServerTimeouts(t *testing.T) {
	h := routedHarness(t)
	server := httptest.NewUnstartedServer(h.center.Public())
	server.Config.ReadTimeout, server.Config.WriteTimeout = 2*time.Second, 2*time.Second
	server.Start()
	t.Cleanup(server.Close)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		time.Sleep(3 * time.Second)
		return node.node.Executed(call, []byte{0x12, 0x00}), []byte{0x12, 0x00}, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	reply, err := nodetest.Client{URL: server.URL, ClientIPHeader: config.ClientIPHeader}.Post(fleetv1connect.FleetServiceWaitNodeTaskProcedure,
		&fleetv1.FleetServiceWaitNodeTaskRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(node.node.ID),
			Request: marshalInner(t, &nodev1.TaskServiceWaitTaskRequest{TaskId: idValue(platform.NewID()), WaitMs: proto.Uint64(5_000)})}, issued.AccessToken)
	if err != nil {
		t.Fatalf("the long poll was cut: %v", err)
	}
	response, err := nodetest.Decode(reply, &fleetv1.FleetServiceWaitNodeTaskResponse{})
	if err != nil || response.GetError() != nil || !bytes.Equal(response.GetValue().GetResponse(), []byte{0x12, 0x00}) {
		t.Fatalf("the long poll's reply: %v, %v", response, err)
	}
}

// TestTheRefusalCodeTableIsTheMigrations (decisions B-2): migration 0010's fleet.refusal_code rows are fleet.RefusalCodes and other (0),
// and the table refuses every change.
func TestTheRefusalCodeTableIsTheMigrations(t *testing.T) {
	h := routedHarness(t)
	rows, err := h.db.Migration.Query(context.Background(), "SELECT value, category || '/' || code FROM fleet.refusal_code")
	if err != nil {
		t.Fatal(err)
	}
	stored := map[string]int16{}
	for rows.Next() {
		var value int16
		var key string
		if err := rows.Scan(&value, &key); err != nil {
			t.Fatal(err)
		}
		stored[key] = value
	}
	rows.Close()
	want := fleet.RefusalCodes()
	want["other/other"] = fleet.RefusalOther
	if len(stored) != len(want) {
		t.Fatalf("%d rows, %d codes", len(stored), len(want))
	}
	for key, value := range want {
		if stored[key] != value {
			t.Fatalf("%s: %d in the migration, %d in the table", key, stored[key], value)
		}
	}
	for _, statement := range []string{"UPDATE fleet.refusal_code SET code = 'renamed' WHERE value = 1", "DELETE FROM fleet.refusal_code WHERE value = 1"} {
		if _, err := h.db.Migration.Exec(context.Background(), statement); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// TestTheStoreHoldsNoRoutedPayload is the inspection (E2-14, E2-15; PN-6; decisions B-3): after a submission whose argv, working
// directory and environment carry planted markers, a node response whose warning carries one, a resend, a refused submission, a Cancel
// whose reason and a ReadOutput whose output carry one, no column of any table holds a marker, the logs and the metric keys hold none,
// and the routing record has no text column and no byte column but its three digests.
func TestTheStoreHoldsNoRoutedPayload(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	task := platform.NewID()
	serve(t, node, channel, deduplicating(node, func(call *relayv1.ChannelCall) []byte {
		var header relayv1.CallHeader
		_ = proto.Unmarshal(call.GetHeader().GetHeader(), &header)
		if header.GetMethod() == hub.MethodReadNodeTaskOutput {
			return marshalInner(t, &nodev1.TaskServiceReadTaskOutputResponse{Outcome: &nodev1.TaskServiceReadTaskOutputResponse_Value{
				Value: &nodev1.TaskServiceReadTaskOutputValue{Data: []byte("INSPECTMARK-OUTPUT"), Eof: proto.Bool(true)}}})
		}
		return submitResponse(t, task, "INSPECTMARK")
	}))
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	payload := submitPayload(t, command, "INSPECTMARK")
	for range 2 {
		h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
		if failure := h.submit(issued.AccessToken, command, node.node.ID, payload).GetError(); failure != nil {
			t.Fatal(failure)
		}
	}
	refused := platform.NewID()
	_ = h.submit(issued.AccessToken, refused, node.node.ID, submitPayload(t, refused, "INSPECTMARK"))
	// A Cancel whose reason carries a marker, and a ReadOutput whose output does (review A N-9).
	cancel := platform.NewID()
	h.proveFor(issued, user, "fleet.cancelNodeTask", node.node.ID)
	cancelResponse := &fleetv1.FleetServiceCancelNodeTaskResponse{}
	h.rpc(fleetv1connect.FleetServiceCancelNodeTaskProcedure, &fleetv1.FleetServiceCancelNodeTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(cancel)},
		NodeId: idValue(node.node.ID), Request: marshalInner(t, &nodev1.TaskServiceCancelTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(cancel)},
			TaskId: idValue(task), Reason: proto.String("INSPECTMARK-REASON")})}, issued.AccessToken, cancelResponse)
	if cancelResponse.GetError() != nil {
		t.Fatal(cancelResponse.GetError())
	}
	outputResponse := &fleetv1.FleetServiceReadNodeTaskOutputResponse{}
	h.rpc(fleetv1connect.FleetServiceReadNodeTaskOutputProcedure, &fleetv1.FleetServiceReadNodeTaskOutputRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(node.node.ID),
		Request: marshalInner(t, &nodev1.TaskServiceReadTaskOutputRequest{AttemptId: idValue(task)})}, issued.AccessToken, outputResponse)
	if outputResponse.GetError() != nil {
		t.Fatal(outputResponse.GetError())
	}
	for key := range h.center.Metrics.Summary() {
		if strings.Contains(key, "INSPECTMARK") {
			t.Errorf("a metric key holds a planted marker: %s", key)
		}
	}
	columns, err := h.db.Migration.Query(context.Background(), `SELECT table_schema, table_name, column_name, data_type FROM information_schema.columns
WHERE table_schema NOT IN ('pg_catalog', 'information_schema') AND data_type IN ('text', 'character varying', 'bytea', 'jsonb', 'json')`)
	if err != nil {
		t.Fatal(err)
	}
	type column struct{ schema, table, name, kind string }
	var all []column
	for columns.Next() {
		var c column
		if err := columns.Scan(&c.schema, &c.table, &c.name, &c.kind); err != nil {
			t.Fatal(err)
		}
		all = append(all, c)
	}
	columns.Close()
	routedBytes := []string{}
	for _, c := range all {
		condition := `"` + c.name + `"::text LIKE '%INSPECTMARK%'`
		if c.kind == "bytea" {
			condition = `position(convert_to('INSPECTMARK', 'UTF8') in "` + c.name + `") > 0`
		}
		found := h.count(`SELECT count(*) FROM "` + c.schema + `"."` + c.table + `" WHERE ` + condition)
		if found != 0 {
			t.Errorf("%s.%s.%s holds a planted marker", c.schema, c.table, c.name)
		}
		if c.schema == "fleet" && c.table == "routed_call" {
			if c.kind != "bytea" {
				t.Errorf("the routing record has a %s column %s", c.kind, c.name)
			}
			routedBytes = append(routedBytes, c.name)
		}
	}
	slices.Sort(routedBytes)
	if !slices.Equal(routedBytes, []string{"outcome_sha256", "request_digest", "response_sha256"}) {
		t.Errorf("the routing record's byte columns: %v", routedBytes)
	}
	if strings.Contains(h.logs.String(), "INSPECTMARK") {
		t.Error("a log line holds a planted marker")
	}
}

// TestRoutingNeverReachesAnotherAccountsNode (E2-6; CTR5-SEC-17): a Submit or a read naming another account's node, an unknown node or a
// revoked one is STATE/not_found at the ownership stage: nothing is written (no rate count, no access.authorized, no evidence consumed,
// no record) and nothing is routed.
func TestRoutingNeverReachesAnotherAccountsNode(t *testing.T) {
	h := routedHarness(t)
	owner, stranger := h.db.Account(1), h.db.Account(2)
	node := h.enrollIn(owner)
	channel := h.connect(node)
	calls := serve(t, node, channel, func(*relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) { return nil, nil, false })
	issued := h.accountSession(stranger, session.ScopeAccount)
	h.proveFor(issued, stranger, "fleet.submitNodeTask", node.node.ID)
	before := h.writes()
	for _, target := range []platform.ID{node.node.ID, platform.NewID()} {
		command := platform.NewID()
		if failure := h.submit(issued.AccessToken, command, target, submitPayload(t, command, "FOREIGN")).GetError(); errorKey(failure) != "STATE/not_found" {
			t.Fatalf("a submit for a node that is not the caller's: %v", failure)
		}
		response := &fleetv1.FleetServiceGetNodeTaskResponse{}
		h.rpc(fleetv1connect.FleetServiceGetNodeTaskProcedure, &fleetv1.FleetServiceGetNodeTaskRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(target),
			Request: marshalInner(t, &nodev1.TaskServiceGetTaskRequest{TaskId: idValue(platform.NewID())})}, issued.AccessToken, response)
		if errorKey(response.GetError()) != "STATE/not_found" {
			t.Fatalf("a read for a node that is not the caller's: %v", response.GetError())
		}
	}
	if h.writes() != before || h.count("SELECT count(*) FROM fleet.routed_call") != 0 {
		t.Fatalf("a call for another account's node wrote: %d", h.writes()-before)
	}
	select {
	case <-calls:
		t.Fatal("a call for another account's node was routed")
	case <-time.After(200 * time.Millisecond):
	}
}

// postAndLeave posts a request and goes away after a while without reading the reply (a caller whose client gave up).
func (h *harness) postAndLeave(path string, request proto.Message, bearer string, after time.Duration) {
	h.t.Helper()
	data := marshalInner(h.t, request)
	frame := make([]byte, 5+len(data))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(data)))
	copy(frame[5:], data)
	ctx, cancel := context.WithTimeout(context.Background(), after)
	defer cancel()
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url+path, bytes.NewReader(frame))
	if err != nil {
		h.t.Fatal(err)
	}
	httpRequest.Header.Set("Content-Type", "application/grpc-web+proto")
	httpRequest.Header.Set(config.ClientIPHeader, "198.51.100.7")
	httpRequest.Header.Set("Authorization", "Bearer "+bearer)
	if response, err := http.DefaultClient.Do(httpRequest); err == nil {
		_ = response.Body.Close()
	}
}

// TestALeaderThatGoesAwayDoesNotEndTheJoinedCall (decisions Q-15): the first caller of a Submit goes away while its call is in flight;
// a duplicate that joined it still receives the node's answer within its own deadline, and the record is SUCCEEDED: the attempt runs
// on a context of its own, never the leader's request's.
func TestALeaderThatGoesAwayDoesNotEndTheJoinedCall(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	task := platform.NewID()
	response := submitResponse(t, task, "LEADER")
	gate := make(chan struct{})
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		<-gate
		return node.node.Executed(call, response), response, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	payload := submitPayload(t, command, "LEADER")
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	left := make(chan struct{})
	go func() {
		defer close(left)
		h.postAndLeave(fleetv1connect.FleetServiceSubmitNodeTaskProcedure, &fleetv1.FleetServiceSubmitNodeTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
			NodeId: idValue(node.node.ID), Request: payload}, issued.AccessToken, 1500*time.Millisecond)
	}()
	<-calls
	joined := make(chan *fleetv1.FleetServiceSubmitNodeTaskResponse, 1)
	go func() { joined <- h.submit(issued.AccessToken, command, node.node.ID, payload) }()
	if !eventually(t, 5*time.Second, func() bool {
		return h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.routed.accepted' AND reason = 'joined'") == 1
	}) {
		t.Fatal("the duplicate did not join")
	}
	<-left
	close(gate)
	if reply := <-joined; reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), response) {
		t.Fatalf("the joined caller after the leader left: %v", reply)
	}
	if !eventually(t, 5*time.Second, func() bool {
		got := h.record(user, command)
		return got != nil && got.State == fleet.RoutedSucceeded && got.Attempts == 1
	}) {
		t.Fatalf("the record: %+v", h.record(user, command))
	}
}
