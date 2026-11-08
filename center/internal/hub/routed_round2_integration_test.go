// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"errors"
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
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
)

// The coordinator's rule for a resend (AF-CTR-05 E2b fix round 2; R1..R5; EVIDENCE as in routed_integration_test.go).

// expiredRefusal is a node's STATE/expired refusal that did not happen.
func expiredRefusal() *foundationv1.ArcError {
	return &foundationv1.ArcError{Code: proto.String("expired"), Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE.Enum(),
		MessageKey: proto.String("error.state.expired"), Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()},
		Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(), CorrelationId: idValue(platform.NewID())}
}

// TestANodeRefusalOfAResendIsUnknown (R1, review A CB-1): a node-signed DID_NOT_HAPPEN refusal of a resend (a policy refusal, an
// expiry) is answered node_unreachable with UNKNOWN and SAME_COMMAND, on a record that is UNKNOWN (which stays UNKNOWN, with the node's
// code) and on one that is SUCCEEDED (which stays SUCCEEDED); the node's code is in the audit row.
func TestANodeRefusalOfAResendIsUnknown(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	task := platform.NewID()
	executed := submitResponse(t, task, "REFUSED")
	var mu sync.Mutex
	plan := []string{}
	serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		mu.Lock()
		next := plan[0]
		plan = plan[1:]
		mu.Unlock()
		switch next {
		case "close":
			_ = channel.WS.CloseNow()
			return nil, nil, false
		case "policy":
			return node.node.Refused(call, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY, policyRefusal()), nil, true
		case "expired":
			return node.node.Refused(call, relayv1.RoutedOutcome_ROUTED_OUTCOME_EXPIRED, expiredRefusal()), nil, true
		}
		return node.node.Executed(call, executed), executed, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	submit := func(command platform.ID, answer string) *foundationv1.ArcError {
		mu.Lock()
		plan = append(plan, answer)
		mu.Unlock()
		h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
		return h.submit(issued.AccessToken, command, node.node.ID, submitPayload(t, command, "REFUSED")).GetError()
	}
	// An UNKNOWN record: its first attempt reached the node, whose channel then closed.
	unknown := platform.NewID()
	if failure := submit(unknown, "close"); !unknownSameCommand(failure) {
		t.Fatalf("the first attempt: %v", failure)
	}
	eventually(t, 5*time.Second, func() bool { return !h.center.Hub.Connected(node.node.ID) })
	// A new channel of its own: the first channel's serving goroutine still reads its variable (the race the Linux leg found).
	second := h.connect(node)
	serve(t, node, second, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		mu.Lock()
		next := plan[0]
		plan = plan[1:]
		mu.Unlock()
		switch next {
		case "policy":
			return node.node.Refused(call, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY, policyRefusal()), nil, true
		case "expired":
			return node.node.Refused(call, relayv1.RoutedOutcome_ROUTED_OUTCOME_EXPIRED, expiredRefusal()), nil, true
		}
		return node.node.Executed(call, executed), executed, true
	})
	for _, answer := range []string{"policy", "expired"} {
		if failure := submit(unknown, answer); !unknownSameCommand(failure) {
			t.Fatalf("a %s refusal of a resend of an UNKNOWN record: %v", answer, failure)
		}
		if got := h.record(user, unknown); got.State != fleet.RoutedUnknown || got.Final || got.Refusal == nil {
			t.Fatalf("after a %s refusal: %+v", answer, got)
		}
	}
	// A SUCCEEDED record.
	succeeded := platform.NewID()
	if failure := submit(succeeded, "execute"); failure != nil {
		t.Fatal(failure)
	}
	for _, answer := range []string{"policy", "expired"} {
		if failure := submit(succeeded, answer); !unknownSameCommand(failure) {
			t.Fatalf("a %s refusal of a resend of a SUCCEEDED record: %v", answer, failure)
		}
		if got := h.record(user, succeeded); got.State != fleet.RoutedSucceeded || !got.Final {
			t.Fatalf("a final record after a %s refusal: %+v", answer, got)
		}
	}
	codes := h.count(`SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.routed.result' AND
    (convert_from(payload, 'UTF8')::jsonb->>'refusal')::int IN ($1, $2)`, int(fleet.RefusalCode("authorization/permission_denied")),
		int(fleet.RefusalCode("state/expired")))
	if codes != 4 {
		t.Fatalf("%d audited node codes", codes)
	}
}

// TestARevocationDuringAnInFlightCallAnswersResendsUnknown (R2, review B B-5): the node is revoked while a Submit is in flight; the
// first reply is UNKNOWN, and every duplicate sent after the revocation (the ownership stage's not_found, the caller's own record
// consulted) is node_unreachable UNKNOWN SAME_COMMAND; a new command for the revoked node and a read keep not_found.
func TestARevocationDuringAnInFlightCallAnswersResendsUnknown(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	held := make(chan struct{}, 1)
	serve(t, node, channel, func(*relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		held <- struct{}{}
		return nil, nil, false
	})
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	payload := submitPayload(t, command, "REVOKED")
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	first := make(chan *foundationv1.ArcError, 1)
	go func() { first <- h.submit(issued.AccessToken, command, node.node.ID, payload).GetError() }()
	<-held
	h.proveFor(issued, user, "fleet.revokeNode", node.node.ID)
	if failure := h.revokeNode(issued.AccessToken, commandMeta(), node.node.ID).GetError(); failure != nil {
		t.Fatalf("the revocation: %v", failure)
	}
	if failure := <-first; !unknownSameCommand(failure) {
		t.Fatalf("the first reply: %v", failure)
	}
	const duplicates = 8
	replies := make(chan *foundationv1.ArcError, duplicates)
	for range duplicates {
		go func() { replies <- h.submit(issued.AccessToken, command, node.node.ID, payload).GetError() }()
	}
	for range duplicates {
		if failure := <-replies; !unknownSameCommand(failure) {
			t.Fatalf("a duplicate after the revocation: %v", failure)
		}
	}
	fresh := platform.NewID()
	if failure := h.submit(issued.AccessToken, fresh, node.node.ID, submitPayload(t, fresh, "REVOKED")).GetError(); errorKey(failure) != "STATE/not_found" {
		t.Fatalf("a new command for the revoked node: %v", failure)
	}
	response := &fleetv1.FleetServiceGetNodeTaskResponse{}
	h.rpc(fleetv1connect.FleetServiceGetNodeTaskProcedure, &fleetv1.FleetServiceGetNodeTaskRequest{Meta: &foundationv1.RequestMeta{}, NodeId: idValue(node.node.ID),
		Request: marshalInner(t, &nodev1.TaskServiceGetTaskRequest{TaskId: idValue(platform.NewID())})}, issued.AccessToken, response)
	if errorKey(response.GetError()) != "STATE/not_found" {
		t.Fatalf("a read of the revoked node: %v", response.GetError())
	}
}

// TestAResendOverTheQuotaKeepsItsPair (R3): a resend of a record that may have reached the node, refused by the account's routed-call
// quota before routing, keeps the catalogue pair of rate_limited (AFTER_TIME): it asks for the same command later.
func TestAResendOverTheQuotaKeepsItsPair(t *testing.T) {
	h := newHarness(t, settings{surfaces: "identity,pages,fleet,relay,nodes", policy: `{"routedCallsAccountLimit": 1}`,
		tune: func(s *hub.Settings) { s.Heartbeat, s.HeartbeatDeadline = time.Second, 30*time.Second }})
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	serve(t, node, channel, func(*relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		_ = channel.WS.CloseNow()
		return nil, nil, false
	})
	issued := h.accountSession(user, session.ScopeAccount)
	command := platform.NewID()
	payload := submitPayload(t, command, "QUOTA")
	h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
	if failure := h.submit(issued.AccessToken, command, node.node.ID, payload).GetError(); !unknownSameCommand(failure) {
		t.Fatalf("the first attempt: %v", failure)
	}
	failure := h.submit(issued.AccessToken, command, node.node.ID, payload).GetError()
	if errorKey(failure) != "RESOURCE/rate_limited" || failure.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME ||
		failure.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN {
		t.Fatalf("a resend over the quota: %v", failure)
	}
}

// handlerError is a node's EXECUTED Submit response that carries the handler's own error with an effect (UNSPECIFIED leaves it unset).
func handlerError(t *testing.T, effect foundationv1.EffectCertainty) []byte {
	t.Helper()
	value := &foundationv1.ArcError{Code: proto.String("overloaded"), Category: foundationv1.ErrorCategory_ERROR_CATEGORY_RESOURCE.Enum(),
		Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND.Enum()}}
	if effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNSPECIFIED {
		value.Effect = effect.Enum()
	}
	return marshalInner(t, &nodev1.TaskServiceSubmitTaskResponse{Outcome: &nodev1.TaskServiceSubmitTaskResponse_Error{Error: value}})
}

// TestAHandlerErrorOfAResendIsUnknown (R1, review B B-6, N-15): the handler's error of a resend whose effect is not HAPPENED is answered
// node_unreachable UNKNOWN SAME_COMMAND, whatever order the node replays in: case A, a first attempt FAILED and not final (DID_NOT_HAPPEN),
// then a resend answered the same; case B, an UNKNOWN record, then a resend answered with an UNKNOWN effect. A handler error without an
// effect counts as UNKNOWN. A resend answered with HAPPENED is the node's answer (FAILED, final).
func TestAHandlerErrorOfAResendIsUnknown(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	answers := make(chan []byte, 8)
	serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		response := <-answers
		return node.node.Executed(call, response), response, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	submit := func(command platform.ID, response []byte) *fleetv1.FleetServiceSubmitNodeTaskResponse {
		answers <- response
		h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
		return h.submit(issued.AccessToken, command, node.node.ID, submitPayload(t, command, "HANDLER"))
	}
	dnh, unknown := foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN, foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN
	// Case A.
	first := platform.NewID()
	if reply := submit(first, handlerError(t, dnh)); reply.GetError() != nil {
		t.Fatalf("a first attempt's handler error is the node's response: %v", reply.GetError())
	}
	if got := h.record(user, first); got.State != fleet.RoutedFailed || got.Final {
		t.Fatalf("a first attempt FAILED with DID_NOT_HAPPEN: %+v", got)
	}
	if failure := submit(first, handlerError(t, dnh)).GetError(); !unknownSameCommand(failure) {
		t.Fatalf("case A, the resend: %v", failure)
	}
	if got := h.record(user, first); got.State != fleet.RoutedUnknown || got.Refusal == nil || *got.Refusal != fleet.RefusalCode("resource/overloaded") {
		t.Fatalf("case A, the record: %+v", got)
	}
	// Case B: the record is UNKNOWN now; a resend answered with an UNKNOWN effect, then one without an effect.
	for _, effect := range []foundationv1.EffectCertainty{unknown, foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNSPECIFIED} {
		if failure := submit(first, handlerError(t, effect)).GetError(); !unknownSameCommand(failure) {
			t.Fatalf("case B (%s), the resend: %v", effect, failure)
		}
		if got := h.record(user, first); got.State != fleet.RoutedUnknown || got.Final {
			t.Fatalf("case B (%s), the record: %+v", effect, got)
		}
	}
	// A first attempt without an effect is UNKNOWN, not FAILED.
	other := platform.NewID()
	if reply := submit(other, handlerError(t, foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNSPECIFIED)); reply.GetError() != nil {
		t.Fatal(reply.GetError())
	}
	if got := h.record(user, other); got.State != fleet.RoutedUnknown {
		t.Fatalf("a handler error without an effect: %+v", got)
	}
	// HAPPENED: the node's answer, final.
	happened := handlerError(t, foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED)
	if reply := submit(first, happened); reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), happened) {
		t.Fatalf("a resend answered HAPPENED: %v", reply)
	}
	if got := h.record(user, first); got.State != fleet.RoutedFailed || !got.Final {
		t.Fatalf("after HAPPENED: %+v", got)
	}
}

// TestTheAdmissionsNotFoundFollowsTheRecord (R2, review A C2-N4): a node revoked between the ownership stage and the admission is
// STATE/not_found for a new command, and node_unreachable UNKNOWN SAME_COMMAND for a command whose record may have reached it; neither
// writes.
func TestTheAdmissionsNotFoundFollowsTheRecord(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	fence, _ := h.center.Hub.Routable()
	command := platform.NewID()
	accept := func(command platform.ID) error {
		_, err := fleet.AcceptRouted(context.Background(), h.db.Runtime, fleet.RoutedAccept{AccountID: user, NodeID: node.node.ID, CommandID: command, Method: 1,
			Caller: fleet.RoutedCaller{Kind: fleet.RoutedCallerSession, SessionID: platform.NewID(), Actor: identity.Actor(user)}, Digest: make([]byte, 32),
			RequestSHA256: make([]byte, 32), Size: 10, Fence: fence, Window: time.Hour, InFlight: func() bool { return false }, Online: func() bool { return true },
			Now: time.Now()})
		return err
	}
	if err := accept(command); err != nil {
		t.Fatal(err)
	}
	h.db.Exec("UPDATE fleet.node SET revoked_at = now(), revoke_reason = 1, rev = rev + 1 WHERE node_id = '" + node.node.ID.String() + "'")
	var refusal *arc.Refusal
	if err := accept(command); !errors.As(err, &refusal) || refusal.Code != "node_unreachable" || refusal.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
		refusal.Retry != foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND {
		t.Fatalf("a resend to the revoked node: %v", err)
	}
	if err := accept(platform.NewID()); !errors.As(err, &refusal) || refusal.Code != "not_found" {
		t.Fatalf("a new command to the revoked node: %v", err)
	}
	if got := h.record(user, command); got.Attempts != 1 || h.count("SELECT count(*) FROM fleet.routed_call") != 1 {
		t.Fatalf("a refused admission wrote: %+v", got)
	}
}

// TestAFinalOutcomeSurvivesAnIndeterminateHandlerError exercises final SUCCEEDED and FAILED records against verified handler errors
// decided before replay. These errors are not comparable to the recorded result, but their refusal is still audited. Matching and
// genuinely different final outcomes retain their usual replay semantics.
func TestAFinalOutcomeSurvivesAnIndeterminateHandlerError(t *testing.T) {
	h := routedHarness(t)
	user := h.db.Account(1)
	node := h.enrollIn(user)
	channel := h.connect(node)
	answers := make(chan []byte, 8)
	serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
		response := <-answers
		return node.node.Executed(call, response), response, true
	})
	issued := h.accountSession(user, session.ScopeAccount)
	stopping := func(effect foundationv1.EffectCertainty) []byte {
		value := &foundationv1.ArcError{Code: proto.String("node_stopping"), Category: foundationv1.ErrorCategory_ERROR_CATEGORY_STATE.Enum()}
		if effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNSPECIFIED {
			value.Effect = effect.Enum()
		}
		return marshalInner(t, &nodev1.TaskServiceSubmitTaskResponse{Outcome: &nodev1.TaskServiceSubmitTaskResponse_Error{Error: value}})
	}
	snapshot := func(command platform.ID) string {
		var value string
		err := h.db.Migration.QueryRow(context.Background(), `SELECT row_to_json(r)::text FROM (
  SELECT state, delivered, task_id, encode(outcome_sha256, 'hex') AS outcome, encode(response_sha256, 'hex') AS response,
         response_size, executed_at, refusal, final_at
  FROM fleet.routed_call WHERE account_id = $1 AND command_id = $2) AS r`, user, command).Scan(&value)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	task := platform.NewID()
	success := submitResponse(t, task, "FINAL")
	failed := handlerError(t, foundationv1.EffectCertainty_EFFECT_CERTAINTY_HAPPENED)
	var changedError nodev1.TaskServiceSubmitTaskResponse
	if err := proto.Unmarshal(failed, &changedError); err != nil {
		t.Fatal(err)
	}
	changedError.GetError().MessageKey = proto.String("error.changed_final_outcome")
	cases := []struct {
		name      string
		state     fleet.RoutedState
		initial   []byte
		different []byte
	}{
		{"succeeded", fleet.RoutedSucceeded, success, submitResponse(t, task, "DIFFERENT")},
		{"failed", fleet.RoutedFailed, failed, marshalInner(t, &changedError)},
	}
	for _, test := range cases {
		command := platform.NewID()
		payload := submitPayload(t, command, "FINAL-"+test.name)
		submit := func(response []byte) *fleetv1.FleetServiceSubmitNodeTaskResponse {
			answers <- response
			h.proveFor(issued, user, "fleet.submitNodeTask", node.node.ID)
			return h.submit(issued.AccessToken, command, node.node.ID, payload)
		}
		if reply := submit(test.initial); reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), test.initial) {
			t.Fatalf("%s initial answer: %v", test.name, reply)
		}
		if got := h.record(user, command); got.State != test.state || !got.Final {
			t.Fatalf("%s initial record: %+v", test.name, got)
		}
		original := snapshot(command)
		if reply := submit(test.initial); reply.GetError() != nil || !bytes.Equal(reply.GetValue().GetResponse(), test.initial) {
			t.Fatalf("%s matching replay: %v", test.name, reply)
		}
		for index, effect := range []foundationv1.EffectCertainty{
			foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN,
			foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN,
			foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNSPECIFIED,
		} {
			if failure := submit(stopping(effect)).GetError(); !unknownSameCommand(failure) {
				t.Fatalf("%s transient %s: %v", test.name, effect, failure)
			}
			if got := snapshot(command); got != original {
				t.Fatalf("%s transient %s changed the final outcome: before %s after %s", test.name, effect, original, got)
			}
			if got := h.count(`SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.routed.result' AND command_id = $1 AND
    reason = 'replay' AND (convert_from(payload, 'UTF8')::jsonb->>'refusal')::int = $2`, command, int(fleet.RefusalCode("state/node_stopping"))); got != index+1 {
				t.Fatalf("%s transient %s: %d audited refusal results, want %d", test.name, effect, got, index+1)
			}
			if got := h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.routed.replay_differs' AND command_id = $1", command); got != 0 {
				t.Fatalf("%s transient %s: %d false replay-differs events", test.name, effect, got)
			}
		}
		failure := submit(test.different).GetError()
		if errorKey(failure) != "STATE/node_unreachable" || failure.GetDetails().GetState().GetReason() != "replay_digest_differs" ||
			failure.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN || failure.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER {
			t.Fatalf("%s genuinely different replay: %v", test.name, failure)
		}
		if got := h.count("SELECT count(*) FROM audit.audit_event WHERE event_type = 'fleet.routed.replay_differs' AND command_id = $1", command); got != 1 {
			t.Fatalf("%s differing replay: %d replay-differs events", test.name, got)
		}
		if got := snapshot(command); got != original {
			t.Fatalf("%s differing replay changed the final outcome: before %s after %s", test.name, original, got)
		}
	}
}
