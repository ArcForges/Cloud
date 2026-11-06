// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The routed API's review fix round 1 (AF-CTR-05 part E2b; decisions B-1, Q-4, Q-15, section 4, PB-2; EVIDENCE as in
// routed_integration_test.go: REAL PostgreSQL, the composed center and hub; MOCKED: the nodes and the step-up ceremony).

func unknownSameCommand(failure *foundationv1.ArcError) bool {
	return errorKey(failure) == "STATE/node_unreachable" && failure.GetEffect() == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN &&
		failure.GetRetry().GetMode() == foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND
}

// TestAResendThatMayHaveReachedTheNodeIsNeverDidNotHappen (decisions B-1, review fix 1): once a command may have reached the node, a
// resend's refusals about delivery are node_unreachable with UNKNOWN and SAME_COMMAND, never DID_NOT_HAPPEN: the node offline at the
// admission (still audited fleet.routed.refused), and the hub's own bound refusing the resend's attempt, which leaves the record UNKNOWN
// (the earlier attempt may have reached the node) without a lost settlement.
func TestAResendThatMayHaveReachedTheNodeIsNeverDidNotHappen(t *testing.T) {
	h := newHarness(t, settings{surfaces: "identity,pages,fleet,relay,nodes",
		tune: func(s *hub.Settings) {
			s.Heartbeat, s.HeartbeatDeadline, s.MaxInFlightCalls = time.Second, 30*time.Second, 1
		}})
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	calls := serve(t, node, channel, func(*relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		_ = channel.WS.CloseNow()
		return nil, nil, false
	})
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	payload := submitPayload(t, command, "RESEND")
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	if failure := h.submit(issued.AccessToken, command, node.node.ID, payload).GetError(); !unknownSameCommand(failure) {
		t.Fatalf("the first attempt: %v", failure)
	}
	<-calls
	eventually(t, 5*time.Second, func() bool { return !h.center.Hub.Connected(node.node.ID) })
	// Offline at the admission.
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	if failure := h.submit(issued.AccessToken, command, node.node.ID, payload).GetError(); !unknownSameCommand(failure) {
		t.Fatalf("a resend to the offline node: %v", failure)
	}
	if h.audits("fleet.routed.refused") != 1 {
		t.Fatalf("%d refused rows", h.audits("fleet.routed.refused"))
	}
	// The hub's bound: another command's call holds the node's one slot.
	again := h.connect(node)
	held := make(chan struct{})
	serve(t, node, again, func(*relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		close(held)
		return nil, nil, false
	})
	other := platform.NewID()
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	go func() { _ = h.submit(issued.AccessToken, other, node.node.ID, submitPayload(t, other, "HOLDER")) }()
	<-held
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	if failure := h.submit(issued.AccessToken, command, node.node.ID, payload).GetError(); !unknownSameCommand(failure) {
		t.Fatalf("a resend refused by the hub's bound: %v", failure)
	}
	if !eventually(t, 5*time.Second, func() bool {
		got := h.record(user, command)
		return got != nil && got.State == fleet.RoutedUnknown && got.Delivered && got.Attempts == 2
	}) {
		t.Fatalf("the record: %+v", h.record(user, command))
	}
	if lost := h.center.Metrics.Summary()["channel routed settle_lost"]; lost != 0 {
		t.Fatalf("%d settlements lost", lost)
	}
}

// TestALeaseMoveDuringAnInFlightCallIsUnknownAndReplayedLater (decisions Q-15, review B B-2): the lease moves while a Submit is in flight
// at the node; the first reply is UNKNOWN, a duplicate during the move is not joined across it and is answered UNKNOWN (the record may
// have reached the node), the record is UNKNOWN and delivered; once this hub takes the lease back and sweeps, a resend is routed as the
// next attempt and only the node's deduplication prevents a second effect.
func TestALeaseMoveDuringAnInFlightCallIsUnknownAndReplayedLater(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	task := platform.NewID()
	gate := make(chan struct{})
	var executed sync.WaitGroup
	executed.Add(1)
	dedup := deduplicating(node, func(*relayv1.ChannelCall) []byte { executed.Done(); return submitResponse(t, task, "MOVED") })
	held := make(chan struct{}, 4)
	answer := func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		held <- struct{}{}
		<-gate
		return dedup(call)
	}
	serve(t, node, channel, answer)
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	payload := submitPayload(t, command, "MOVED")
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	first := make(chan *foundationv1.ArcError, 1)
	go func() { first <- h.submit(issued.AccessToken, command, node.node.ID, payload).GetError() }()
	<-held
	fence, _ := h.center.Hub.Routable()
	h.db.Exec("UPDATE fleet.hub_lease SET fence = fence + 1, holder = gen_random_uuid(), expires_at = now() + interval '3 seconds'")
	if failure := <-first; !unknownSameCommand(failure) {
		t.Fatalf("the first reply: %v", failure)
	}
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	if failure := h.submit(issued.AccessToken, command, node.node.ID, payload).GetError(); !unknownSameCommand(failure) {
		t.Fatalf("a duplicate during the move: %v", failure)
	}
	if got := h.record(user, command); got == nil || got.State != fleet.RoutedUnknown || !got.Delivered || got.Attempts != 1 {
		t.Fatalf("the record after the move: %+v", got)
	}
	// The node executed the first call meanwhile (its answer cannot reach the closed channel).
	close(gate)
	executed.Wait()
	if !eventually(t, 15*time.Second, func() bool { next, ok := h.center.Hub.Routable(); return ok && next > fence+1 }) {
		t.Fatal("the hub did not take the lease back")
	}
	again := h.connect(node)
	serve(t, node, again, answer)
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	reply := h.submit(issued.AccessToken, command, node.node.ID, payload)
	if reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), submitResponse(t, task, "MOVED")) && len(reply.GetValue().GetResponse()) == 0 {
		t.Fatalf("the resend after the take-back: %v", reply)
	}
	if got := h.record(user, command); got.State != fleet.RoutedSucceeded || got.Attempts != 2 {
		t.Fatalf("the record after the resend: %+v", got)
	}
}

// TestEachAttemptAuditsItsOwnCaller (decisions Q-4, review A B-1): every fleet.routed.accepted row names the caller of its own attempt:
// two resends from two sessions of the account carry their sessions; two relays from two local processes carry their local sessions,
// with the relaying node and the local origin.
func TestEachAttemptAuditsItsOwnCaller(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	task := platform.NewID()
	command := platform.NewID()
	payload := submitPayload(t, command, "CALLER")
	sessions := []session.Native{h.accountSession(user, session.ScopeAccount), h.accountSession(user, session.ScopeAccount)}
	// The relays first: their nonces are read from the channel before it serves calls.
	relayed := platform.NewID()
	relayPayload := submitPayload(t, relayed, "CALLER")
	digest := sha256.Sum256(relayPayload)
	locals := []platform.ID{platform.NewID(), platform.NewID()}
	var requests []*fleetv1.FleetServiceSubmitNodeTaskRequest
	for _, local := range locals {
		assertion, err := proto.Marshal(node.node.Assertion(publicBaseURL, nodetest.Relay{InstallationID: node.result.InstallationID, LocalOrigin: nodev1.Origin_ORIGIN_AGENT,
			LocalSession: local, Method: hub.MethodSubmitNodeTask, RequestSHA256: digest[:], Target: &node.node.ID, Command: &relayed, Nonce: nonceOf(t, channel)}))
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, &fleetv1.FleetServiceSubmitNodeTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(relayed)}, NodeId: idValue(node.node.ID),
			Caller: relayedCaller(node, nodev1.Origin_ORIGIN_AGENT), Request: relayPayload, RelayAssertion: assertion})
	}
	serve(t, node, channel, deduplicating(node, func(*relayv1.ChannelCall) []byte { return submitResponse(t, task, "CALLER") }))
	for _, issued := range sessions {
		h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
		if failure := h.submit(issued.AccessToken, command, node.node.ID, payload).GetError(); failure != nil {
			t.Fatal(failure)
		}
	}
	for _, request := range requests {
		response := &fleetv1.FleetServiceSubmitNodeTaskResponse{}
		h.rpc(fleetv1connect.FleetServiceSubmitNodeTaskProcedure, request, node.access, response)
		if response.GetError() != nil {
			t.Fatal(response.GetError())
		}
	}
	for index, issued := range sessions {
		if n := h.count(`SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.routed.accepted' AND convert_from(payload, 'UTF8')::jsonb->>'sessionId' = $1 AND (convert_from(payload, 'UTF8')::jsonb->>'attempt')::int = $2`,
			issued.SessionID.String(), index+1); n != 1 {
			t.Fatalf("the attempt of session %d: %d rows", index, n)
		}
	}
	for index, local := range locals {
		if n := h.count(`SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.routed.accepted' AND convert_from(payload, 'UTF8')::jsonb->>'localSessionId' = $1 AND
    convert_from(payload, 'UTF8')::jsonb->>'relayingNodeId' = $2 AND (convert_from(payload, 'UTF8')::jsonb->>'localOrigin')::int = 3 AND (convert_from(payload, 'UTF8')::jsonb->>'attempt')::int = $3`, local.String(), node.node.ID.String(), index+1); n != 1 {
			t.Fatalf("the attempt of local session %d: %d rows", index, n)
		}
	}
}

// TestASupersededAttemptsAnswerChangesNothing (review A N-3, B N-3): a settlement of attempt 1 that lands after attempt 2 was admitted
// changes nothing and is audited with reason superseded.
func TestASupersededAttemptsAnswerChangesNothing(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	fence, _ := h.center.Hub.Routable()
	command := platform.NewID()
	accept := fleet.RoutedAccept{AccountID: user, NodeID: node.node.ID, CommandID: command, Method: 1,
		Caller: fleet.RoutedCaller{Kind: fleet.RoutedCallerSession, SessionID: platform.NewID(), Actor: identity.Actor(user)}, Digest: make([]byte, 32),
		RequestSHA256: make([]byte, 32), Size: 10, Fence: fence, Window: time.Hour, InFlight: func() bool { return false }, Online: func() bool { return true }, Now: time.Now()}
	for attempt := 1; attempt <= 2; attempt++ {
		if decision, err := fleet.AcceptRouted(context.Background(), h.db.Runtime, accept); err != nil || decision.Attempt != attempt {
			t.Fatalf("attempt %d: %+v %v", attempt, decision, err)
		}
	}
	digest := sha256.Sum256([]byte("response"))
	if _, err := fleet.SettleRouted(context.Background(), h.db.Runtime, fleet.RoutedSettle{AccountID: user, CommandID: command, Method: 1, NodeID: node.node.ID, Attempt: 1,
		Actor: identity.Actor(user), Answer: fleet.RoutedAnswer{Verified: true, Outcome: 1, ResponseSHA256: digest[:], OutcomeSHA256: digest[:], ResponseSize: 8,
			ExecutedAt: time.Now()}, Now: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if got := h.record(user, command); got.State != fleet.RoutedAccepted || got.Attempts != 2 || got.Final {
		t.Fatalf("a superseded answer changed the record: %+v", got)
	}
	if h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.routed.result' AND reason = 'superseded'") != 1 {
		t.Fatal("the superseded answer is not audited")
	}
}

// TestASettlementIsRetried (review B N-3): a settlement whose first try cannot write (the record's row is locked past the try's 5 s) is
// tried again and lands; the caller receives the node's answer.
func TestASettlementIsRetried(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	task := platform.NewID()
	command := platform.NewID()
	ctx := context.Background()
	locker, err := pgx.Connect(ctx, h.db.RuntimeURL)
	if err != nil {
		t.Fatal(err)
	}
	committed := make(chan struct{})
	// The locking transaction's goroutine ends before the connection is closed.
	t.Cleanup(func() {
		<-committed
		_ = locker.Close(ctx)
	})
	response := submitResponse(t, task, "RETRY")
	serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		// Before the node answers, another transaction holds the record's row for 6 s.
		tx, err := locker.Begin(ctx)
		if err != nil {
			t.Error(err)
			close(committed)
			return nil, nil, false
		}
		if _, err := tx.Exec(ctx, "SELECT 1 FROM fleet.routed_call WHERE command_id = $1 FOR UPDATE", command); err != nil {
			t.Error(err)
		}
		go func() {
			defer close(committed)
			time.Sleep(6 * time.Second)
			_ = tx.Commit(ctx)
		}()
		return node.node.Executed(call, response), response, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	h.submit(issued.AccessToken, command, node.node.ID, submitPayload(t, command, "RETRY"))
	if !eventually(t, 15*time.Second, func() bool { got := h.record(user, command); return got != nil && got.State == fleet.RoutedSucceeded }) {
		t.Fatalf("the settlement did not land: %+v", h.record(user, command))
	}
	if !strings.Contains(h.logs.String(), "could not be recorded; retrying") {
		t.Fatal("the first try did not fail")
	}
}

// TestTheFinalityOfANodeRefusalFollowsItsEffect (decisions section 4, review A B-2): a node refusal that says HAPPENED is final, one
// that says DID_NOT_HAPPEN is not; the same for an EXPIRED outcome.
func TestTheFinalityOfANodeRefusalFollowsItsEffect(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	type outcome struct {
		result relayv1.RoutedOutcome
		code   string
		effect foundationv1.EffectCertainty
	}
	var mu sync.Mutex
	planned := map[string]outcome{}
	serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		var header relayv1.CallHeader
		_ = proto.Unmarshal(call.GetHeader().GetHeader(), &header)
		mu.Lock()
		plan := planned[string(header.GetCommandId().GetValue())]
		mu.Unlock()
		category, prefix := foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION, "authorization"
		if plan.result == relayv1.RoutedOutcome_ROUTED_OUTCOME_EXPIRED {
			category, prefix = foundationv1.ErrorCategory_ERROR_CATEGORY_STATE, "state"
		}
		refusal := &foundationv1.ArcError{Code: proto.String(plan.code), Category: category.Enum(), MessageKey: proto.String("error." + prefix + "." + plan.code),
			Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()}, Effect: plan.effect.Enum(), CorrelationId: idValue(platform.NewID())}
		return node.node.Refused(call, plan.result, refusal), nil, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	happened, didNotHappen := foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED, foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN
	cases := []struct {
		plan  outcome
		state fleet.RoutedState
		final bool
	}{
		{outcome{relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY, "permission_denied", happened}, fleet.RoutedRejected, true},
		{outcome{relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY, "permission_denied", didNotHappen}, fleet.RoutedRejected, false},
		{outcome{relayv1.RoutedOutcome_ROUTED_OUTCOME_EXPIRED, "expired", didNotHappen}, fleet.RoutedExpired, false},
		{outcome{relayv1.RoutedOutcome_ROUTED_OUTCOME_EXPIRED, "expired", happened}, fleet.RoutedExpired, true},
	}
	for index, c := range cases {
		command := platform.NewID()
		mu.Lock()
		planned[string(command[:])] = c.plan
		mu.Unlock()
		h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
		failure := h.submit(issued.AccessToken, command, node.node.ID, submitPayload(t, command, "FINALITY")).GetError()
		if !strings.HasSuffix(errorKey(failure), "/"+c.plan.code) {
			t.Fatalf("case %d: %v", index, failure)
		}
		if got := h.record(user, command); got == nil || got.State != c.state || got.Final != c.final {
			t.Fatalf("case %d: the record %+v", index, got)
		}
	}
}

// TestTheNodePolicyRefusalIsForwardedAndAudited (E2-12, N-8): a node's policy refusal is the method's error rebuilt from its closed
// fields (category, code, state and reason, retry, effect), with the caller's own correlation ID, never the node's; it is audited
// fleet.routed.result with its refusal code; an EXPIRED outcome of a read is STATE/expired, with no record.
func TestTheNodePolicyRefusalIsForwardedAndAudited(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	node2Correlation := policyRefusal().GetCorrelationId()
	serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		var header relayv1.CallHeader
		_ = proto.Unmarshal(call.GetHeader().GetHeader(), &header)
		if header.GetMethod() == hub.MethodGetNodeTask {
			expired := &foundationv1.ArcError{Code: proto.String("expired"), Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE.Enum(),
				MessageKey: proto.String("error.state.expired"), Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()},
				Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(), CorrelationId: idValue(platform.NewID())}
			return node.node.Refused(call, relayv1.RoutedOutcome_ROUTED_OUTCOME_EXPIRED, expired), nil, true
		}
		refusal := policyRefusal()
		refusal.CorrelationId = node2Correlation
		return node.node.Refused(call, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY, refusal), nil, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	reply := h.submit(issued.AccessToken, command, node.node.ID, submitPayload(t, command, "POLICY"))
	failure := reply.GetError()
	if errorKey(failure) != "AUTHORIZATION/permission_denied" || failure.GetDetails().GetState().GetState() != "task.submit" ||
		failure.GetDetails().GetState().GetReason() != "relay_own_node_only" || failure.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER ||
		failure.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
		t.Fatalf("the forwarded refusal: %v", failure)
	}
	if proto.Equal(failure.GetCorrelationId(), node2Correlation) || !proto.Equal(failure.GetCorrelationId(), reply.GetMeta().GetCorrelationId()) {
		t.Fatal("the refusal carries the caller's correlation, never the node's")
	}
	if n := h.count(`SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.routed.result' AND (convert_from(payload, 'UTF8')::jsonb->>'refusal')::int = $1 AND
    convert_from(payload, 'UTF8')::jsonb->>'state' = 'rejected_by_node' AND (convert_from(payload, 'UTF8')::jsonb->>'outcome')::int = 2`, int(fleet.RefusalCode("authorization/permission_denied"))); n != 1 {
		t.Fatalf("%d audited results", n)
	}
	response := &fleetv1.FleetServiceGetNodeTaskResponse{}
	h.rpc(fleetv1connect.FleetServiceGetNodeTaskProcedure, &fleetv1.FleetServiceGetNodeTaskRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(node.node.ID),
		Request: marshalInner(t, &nodev1.TaskServiceGetTaskRequest{TaskId: idValue(platform.NewID())})}, issued.AccessToken, response)
	if errorKey(response.GetError()) != "STATE/expired" || h.count("SELECT count(*) FROM fleet.routed_call") != 1 {
		t.Fatalf("an EXPIRED read: %v", response.GetError())
	}
}

// TestACrossNodeRelayIsRoutedWithTheVerifiedRelayingNode (PB-2): node A relays a Submit to node B of the same account; the call header
// names A as the relaying node, from the verified assertion; B's own-node policy refusal comes back rebuilt, and the record is
// REJECTED_BY_NODE and not final; a caller field that names B as the relaying node is request_mismatch.
func TestACrossNodeRelayIsRoutedWithTheVerifiedRelayingNode(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	relaying, target := h.enrollIn(user), h.enrollIn(user)
	relayChannel, targetChannel := h.connect(relaying), h.connect(target)
	calls := serve(t, target, targetChannel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		return target.node.Refused(call, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY, policyRefusal()), nil, true
	})
	command := platform.NewID()
	payload := submitPayload(t, command, "CROSS")
	digest := sha256.Sum256(payload)
	request := func(caller *fleetv1.RoutedCaller) *fleetv1.FleetServiceSubmitNodeTaskResponse {
		assertion, err := proto.Marshal(relaying.node.Assertion(publicBaseURL, nodetest.Relay{InstallationID: relaying.result.InstallationID,
			LocalOrigin: nodev1.Origin_ORIGIN_HUMAN, LocalSession: platform.NewID(), Method: hub.MethodSubmitNodeTask, RequestSHA256: digest[:], Target: &target.node.ID,
			Command: &command, Nonce: nonceOf(t, relayChannel)}))
		if err != nil {
			t.Fatal(err)
		}
		response := &fleetv1.FleetServiceSubmitNodeTaskResponse{}
		h.rpc(fleetv1connect.FleetServiceSubmitNodeTaskProcedure, &fleetv1.FleetServiceSubmitNodeTaskRequest{Meta: &foundationv1.RequestMeta{CommandId: idValue(command)},
			NodeId: idValue(target.node.ID), Caller: caller, Request: payload, RelayAssertion: assertion}, relaying.access, response)
		return response
	}
	lying := relayedCaller(target, nodev1.Origin_ORIGIN_HUMAN)
	if failure := request(lying).GetError(); errorKey(failure) != "AUTHENTICATION/unauthenticated" || failure.GetDetails().GetState().GetReason() != "request_mismatch" {
		t.Fatalf("a caller naming the target as the relaying node: %v", failure)
	}
	failure := request(relayedCaller(relaying, nodev1.Origin_ORIGIN_HUMAN)).GetError()
	if errorKey(failure) != "AUTHORIZATION/permission_denied" || failure.GetDetails().GetState().GetReason() != "relay_own_node_only" {
		t.Fatalf("the target's own-node refusal: %v", failure)
	}
	header := headerOf(t, <-calls)
	if !bytes.Equal(header.GetCaller().GetRelayingNodeId().GetValue(), relaying.node.ID[:]) || !bytes.Equal(header.GetTargetNodeId().GetValue(), target.node.ID[:]) {
		t.Fatalf("the routed header: caller %v, target %x", header.GetCaller(), header.GetTargetNodeId().GetValue())
	}
	if got := h.record(user, command); got == nil || got.State != fleet.RoutedRejected || got.Final {
		t.Fatalf("the record: %+v", got)
	}
}

// TestARelayedReadIsRoutedOnlyWithItsAssertion (C-N6, review A N-8): a node credential's routed read without an assertion is
// AUTHENTICATION/unauthenticated (missing) and writes nothing; with one it is routed with the verified relaying node as its caller.
func TestARelayedReadIsRoutedOnlyWithItsAssertion(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	inner := marshalInner(t, &nodev1.TaskServiceGetTaskRequest{TaskId: idValue(platform.NewID())})
	before := h.writes()
	response := &fleetv1.FleetServiceGetNodeTaskResponse{}
	h.rpc(fleetv1connect.FleetServiceGetNodeTaskProcedure, &fleetv1.FleetServiceGetNodeTaskRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(node.node.ID), Request: inner},
		node.access, response)
	if failure := response.GetError(); errorKey(failure) != "AUTHENTICATION/unauthenticated" || failure.GetDetails().GetState().GetReason() != "missing" || h.writes() != before {
		t.Fatalf("a token alone: %v", failure)
	}
	digest := sha256.Sum256(inner)
	assertion, err := proto.Marshal(node.node.Assertion(publicBaseURL, nodetest.Relay{InstallationID: node.result.InstallationID, LocalOrigin: nodev1.Origin_ORIGIN_SCRIPT,
		LocalSession: platform.NewID(), Method: hub.MethodGetNodeTask, RequestSHA256: digest[:], Target: &node.node.ID, Nonce: nonceOf(t, channel)}))
	if err != nil {
		t.Fatal(err)
	}
	calls := serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		return node.node.Executed(call, []byte{0x12, 0x00}), []byte{0x12, 0x00}, true
	})
	response = &fleetv1.FleetServiceGetNodeTaskResponse{}
	h.rpc(fleetv1connect.FleetServiceGetNodeTaskProcedure, &fleetv1.FleetServiceGetNodeTaskRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(node.node.ID),
		Caller: relayedCaller(node, nodev1.Origin_ORIGIN_SCRIPT), Request: inner, RelayAssertion: assertion}, node.access, response)
	if response.GetError() != nil || !bytes.Equal(response.GetValue().GetResponse(), []byte{0x12, 0x00}) {
		t.Fatalf("a relayed read: %v", response)
	}
	if caller := headerOf(t, <-calls).GetCaller(); caller.GetKind() != nodev1.CenterCallerKind_CENTER_CALLER_KIND_NODE_RELAY ||
		!bytes.Equal(caller.GetRelayingNodeId().GetValue(), node.node.ID[:]) {
		t.Fatalf("the read's caller: %v", caller)
	}
}
