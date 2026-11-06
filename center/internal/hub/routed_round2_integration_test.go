// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"sync"
	"testing"
	"time"

	fleetv1 "github.com/ArcForges/Contracts/go/arcforges/fleet/v1"
	"github.com/ArcForges/Contracts/go/arcforges/fleet/v1/fleetv1connect"
	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/hub"
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
	channel = h.connect(node)
	serve(t, node, channel, func(call *relayv1.ChannelCall) (*relayv1.ResultHeader, []byte, bool) {
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
