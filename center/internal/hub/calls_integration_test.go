// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/correlation"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Signed calls and results on the node channel (AF-CTR-05 E1b; Plan CTR5-SIG-01..04, CTR5-HUB-08, -10, G.1 E1-14, E1-17, E1-18;
// EVIDENCE: REAL PostgreSQL, the composed center, its hub and the real WebSocket server; MOCKED: the node, nodetest's channel client with
// a software key, honest or hostile). hub.Call is the routing seam; the routed API that calls it is E2's.

// sessionCall is a routed call of an account session to an enrolled node.
func sessionCall(node *enrolled, method relayv1.RoutedMethod, payload []byte) hub.Call {
	call := hub.Call{AccountID: node.user, TargetNodeID: node.node.ID, Method: method, Payload: payload, Deadline: 5 * time.Second,
		Caller: hub.Caller{Kind: nodev1.CenterCallerKind_CENTER_CALLER_KIND_ACCOUNT_SESSION, UserID: node.user, SessionID: platform.NewID()}}
	if hub.Mutation(method) {
		command := platform.NewID()
		call.CommandID = &command
	}
	return call
}

type called struct {
	result hub.Result
	err    error
}

// callAsync makes a call in the background.
func (h *harness) callAsync(call hub.Call) <-chan called {
	done := make(chan called, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		result, err := h.center.Hub.Call(ctx, call)
		done <- called{result, err}
	}()
	return done
}

func await(t *testing.T, done <-chan called) called {
	t.Helper()
	select {
	case value := <-done:
		return value
	case <-time.After(15 * time.Second):
		t.Fatal("the call did not end")
	}
	return called{}
}

// refused is a call's refusal.
func refused(t *testing.T, err error) *arc.Refusal {
	t.Helper()
	var refusal *arc.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("not a refusal: %v", err)
	}
	return refusal
}

func nextCall(t *testing.T, channel *nodetest.Channel) *relayv1.ChannelCall {
	t.Helper()
	ctx, cancel := background()
	defer cancel()
	call, err := channel.NextCall(ctx)
	if err != nil {
		t.Fatalf("the node read no call: %v", err)
	}
	return call
}

func headerOf(t *testing.T, call *relayv1.ChannelCall) *relayv1.CallHeader {
	t.Helper()
	var header relayv1.CallHeader
	if err := proto.Unmarshal(call.GetHeader().GetHeader(), &header); err != nil {
		t.Fatal(err)
	}
	return &header
}

func idBytes(id platform.ID) []byte { return append([]byte(nil), id[:]...) }

// TestARoutedCallIsSignedAndItsResultForwardedUnchanged is E1-13/E1-14's center half (CTR5-SIG-01..03): the call header is signed with
// the newest valid command key under the routed-call domain string, names the account, the target, the verified caller, the method,
// the payload's digest and size and the call's window; the node's EXECUTED result is verified and its response bytes come back unchanged.
func TestARoutedCallIsSignedAndItsResultForwardedUnchanged(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	channel := h.connect(node)
	payload := []byte("\x0a\x05exact\x12\x03\xff\x00\x01") // the node.v1 request bytes as the caller sent them (never re-encoded)
	call := sessionCall(node, hub.MethodSubmitNodeTask, payload)
	before := time.Now()
	done := h.callAsync(call)
	sent := nextCall(t, channel)
	header := headerOf(t, sent)
	signed := sent.GetHeader()
	if signed.GetKid() != h.kid || header.GetKid() != h.kid || signed.GetAlgorithm() != "ES256" {
		t.Fatalf("the call names the command key %q/%q", signed.GetKid(), header.GetKid())
	}
	// An independent P-256 verifier (fleet's) checks the signature against the registered public key, under the domain string only.
	public := h.commandKey.PublicKey()
	if !fleet.VerifyNodeKeyProof(public, append([]byte(hub.CallDomain), signed.GetHeader()...), signed.GetSignature()) ||
		fleet.VerifyNodeKeyProof(public, signed.GetHeader(), signed.GetSignature()) {
		t.Fatal("the call signature is the command key's over the routed-call domain string and the header")
	}
	audience := sha256.Sum256([]byte(publicBaseURL))
	digest := sha256.Sum256(payload)
	issued, expires, deadline := header.GetIssuedAt(), header.GetExpiresAt(), header.GetDeadline()
	switch {
	case !bytes.Equal(sent.GetPayload(), payload):
		t.Fatal("the payload is not the caller's bytes")
	case !proto.Equal(sent.GetCallId(), header.GetCallId()):
		t.Fatal("the frame's call ID is the header's")
	case !bytes.Equal(header.GetCenterUrlSha256(), audience[:]) || !bytes.Equal(header.GetAccountId().GetValue(), idBytes(node.user)) ||
		!bytes.Equal(header.GetTargetNodeId().GetValue(), idBytes(node.node.ID)):
		t.Fatal("the center, account and target")
	case header.GetMethod() != hub.MethodSubmitNodeTask || !bytes.Equal(header.GetCommandId().GetValue(), idBytes(*call.CommandID)):
		t.Fatal("the method and command")
	case !bytes.Equal(header.GetRequestSha256(), digest[:]) || header.GetRequestSize() != uint32(len(payload)):
		t.Fatal("the request digest and size")
	case header.GetCaller().GetKind() != nodev1.CenterCallerKind_CENTER_CALLER_KIND_ACCOUNT_SESSION ||
		!bytes.Equal(header.GetCaller().GetSessionId().GetValue(), idBytes(call.Caller.SessionID)) || header.RelayAssertionSha256 != nil:
		t.Fatal("the caller is the verified account session")
	case issued.GetUnixSeconds() < before.Unix()-1 || deadline.GetUnixSeconds()-issued.GetUnixSeconds() != 5 || expires.GetUnixSeconds()-issued.GetUnixSeconds() != 35:
		t.Fatalf("the window: issued %v, deadline %v, expires %v", issued, deadline, expires)
	}
	response := []byte("\x0a\x14\x22\x12\x0a\x10exactly-these-16\x00\xfe")
	ctx, cancel := background()
	defer cancel()
	if err := channel.Answer(ctx, node.node, sent.GetCallId(), node.node.Executed(sent, response), response); err != nil {
		t.Fatal(err)
	}
	value := await(t, done)
	if value.err != nil {
		t.Fatal(value.err)
	}
	responseDigest := sha256.Sum256(response)
	if !bytes.Equal(value.result.Response, response) || !bytes.Equal(value.result.ResponseSHA256, responseDigest[:]) || value.result.KID != h.kid ||
		value.result.Outcome != relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED || value.result.Refusal != nil || !bytes.Equal(value.result.RequestSHA256, digest[:]) {
		t.Fatalf("the verified result: %+v", value.result)
	}
	// A read of the same channel, then the node closes nothing: the channel serves the next call.
	read := sessionCall(node, hub.MethodGetNodeTask, []byte{0x0a, 0x00})
	done = h.callAsync(read)
	sent = nextCall(t, channel)
	if headerOf(t, sent).CommandId != nil {
		t.Fatal("a read names no command")
	}
	if err := channel.Answer(ctx, node.node, sent.GetCallId(), node.node.Executed(sent, []byte{1}), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if value := await(t, done); value.err != nil || !bytes.Equal(value.result.Response, []byte{1}) {
		t.Fatalf("the read: %+v", value)
	}
	if h.center.Hub.InFlight() != 0 {
		t.Fatal("a finished call still holds its slot")
	}
}

// TestAResultSignedByAnotherNodeKeyClosesTheChannel is E1-17 (SEC-08, CTR5-SIG-04): a result the hub cannot verify (another key, a
// high-S signature, a signature over the bare header or under another domain, another call, a changed digest, command, node or
// payload) fails its call STATE/node_unreachable (result_unverifiable; UNKNOWN for a delivered mutation, DID_NOT_HAPPEN for a read),
// closes the channel 4403 and is audited fleet.channel.violation.
func TestAResultSignedByAnotherNodeKeyClosesTheChannel(t *testing.T) {
	h := newHarness(t, settings{})
	other, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	// An enrolled peer of the same account: its registered key is a real installation key, just not this connection's.
	peer := h.enroll()
	type hostile func(node *nodetest.Node, call *relayv1.ChannelCall, response []byte) (*relayv1.SignedHeader, []byte)
	sign := func(header *relayv1.ResultHeader, signer func([]byte) []byte) *relayv1.SignedHeader {
		data, _ := proto.Marshal(header)
		return &relayv1.SignedHeader{Header: data, Signature: signer(data), Algorithm: proto.String("ES256")}
	}
	response := []byte{0x0a, 0x01, 0x01}
	cases := []struct {
		name   string
		method relayv1.RoutedMethod
		reason string
		answer hostile
	}{
		{"another node's key", hub.MethodSubmitNodeTask, "result_signature", func(n *nodetest.Node, c *relayv1.ChannelCall, r []byte) (*relayv1.SignedHeader, []byte) {
			return sign(n.Executed(c, r), func(d []byte) []byte { return other.SignResult(d, true) }), r
		}},
		{"another installation's registered key, naming its node", hub.MethodSubmitNodeTask, "result_signature", func(n *nodetest.Node, c *relayv1.ChannelCall, r []byte) (*relayv1.SignedHeader, []byte) {
			header := n.Executed(c, r)
			header.NodeId = &foundationv1.Id{Value: idBytes(peer.node.ID)}
			return sign(header, func(d []byte) []byte { return peer.node.SignResult(d, true) }), r
		}},
		{"a high-S signature", hub.MethodGetNodeTask, "result_signature", func(n *nodetest.Node, c *relayv1.ChannelCall, r []byte) (*relayv1.SignedHeader, []byte) {
			return sign(n.Executed(c, r), func(d []byte) []byte { return n.SignResult(d, false) }), r
		}},
		{"a signature over the bare header", hub.MethodSubmitNodeTask, "result_signature", func(n *nodetest.Node, c *relayv1.ChannelCall, r []byte) (*relayv1.SignedHeader, []byte) {
			return sign(n.Executed(c, r), func(d []byte) []byte { return n.SignMessage(d, true) }), r
		}},
		{"a signature under the call domain", hub.MethodGetNodeTask, "result_signature", func(n *nodetest.Node, c *relayv1.ChannelCall, r []byte) (*relayv1.SignedHeader, []byte) {
			return sign(n.Executed(c, r), func(d []byte) []byte { return n.SignMessage(append([]byte(hub.CallDomain), d...), true) }), r
		}},
		{"another request digest", hub.MethodSubmitNodeTask, "result_mismatch", func(n *nodetest.Node, c *relayv1.ChannelCall, r []byte) (*relayv1.SignedHeader, []byte) {
			header := n.Executed(c, r)
			header.RequestSha256 = make([]byte, 32)
			return sign(header, func(d []byte) []byte { return n.SignResult(d, true) }), r
		}},
		{"another command", hub.MethodCancelNodeTask, "result_mismatch", func(n *nodetest.Node, c *relayv1.ChannelCall, r []byte) (*relayv1.SignedHeader, []byte) {
			header := n.Executed(c, r)
			header.CommandId = &foundationv1.Id{Value: idBytes(platform.NewID())}
			return sign(header, func(d []byte) []byte { return n.SignResult(d, true) }), r
		}},
		{"another method", hub.MethodGetNodeTask, "result_mismatch", func(n *nodetest.Node, c *relayv1.ChannelCall, r []byte) (*relayv1.SignedHeader, []byte) {
			header := n.Executed(c, r)
			header.Method = hub.MethodListNodeTasks.Enum()
			return sign(header, func(d []byte) []byte { return n.SignResult(d, true) }), r
		}},
		{"another answering node", hub.MethodGetNodeTask, "result_mismatch", func(n *nodetest.Node, c *relayv1.ChannelCall, r []byte) (*relayv1.SignedHeader, []byte) {
			header := n.Executed(c, r)
			header.NodeId = &foundationv1.Id{Value: idBytes(other.ID)}
			return sign(header, func(d []byte) []byte { return n.SignResult(d, true) }), r
		}},
		{"a changed payload", hub.MethodSubmitNodeTask, "result_mismatch", func(n *nodetest.Node, c *relayv1.ChannelCall, r []byte) (*relayv1.SignedHeader, []byte) {
			return sign(n.Executed(c, r), func(d []byte) []byte { return n.SignResult(d, true) }), append(bytes.Clone(r), 0)
		}},
		{"another call in the header", hub.MethodGetNodeTask, "result_other_call", func(n *nodetest.Node, c *relayv1.ChannelCall, r []byte) (*relayv1.SignedHeader, []byte) {
			header := n.Executed(c, r)
			header.CallId = &foundationv1.Id{Value: idBytes(platform.NewID())}
			return sign(header, func(d []byte) []byte { return n.SignResult(d, true) }), r
		}},
		{"a free-text refusal", hub.MethodSubmitNodeTask, "result_malformed", func(n *nodetest.Node, c *relayv1.ChannelCall, _ []byte) (*relayv1.SignedHeader, []byte) {
			refusal := policyRefusal()
			refusal.Details = &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{State: &foundationv1.StateFailure{State: proto.String("task.submit"),
				Reason: proto.String("cwd /home/user/project: permission denied")}}}
			return sign(n.Refused(c, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY, refusal), func(d []byte) []byte { return n.SignResult(d, true) }), nil
		}},
	}
	for _, c := range cases {
		node := h.enroll()
		channel := h.connect(node)
		violations := h.audits("fleet.channel.violation")
		done := h.callAsync(sessionCall(node, c.method, []byte{0x0a, 0x00}))
		sent := nextCall(t, channel)
		header, payload := c.answer(node.node, sent, response)
		ctx, cancel := background()
		if err := channel.SendResult(ctx, sent.GetCallId(), header, payload); err != nil {
			t.Fatal(err)
		}
		closed := channel.AwaitClose(ctx, false)
		cancel()
		value := await(t, done)
		refusal := refused(t, value.err)
		unknown := refusal.Effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN
		if refusal.Key() != "STATE/node_unreachable" || refusal.Reason != arc.UnreachableUnverifiable || unknown != hub.Mutation(c.method) {
			t.Errorf("%s: %s %s effect %v", c.name, refusal.Key(), refusal.Reason, refusal.Effect)
		}
		if closed.Code != hub.CloseRefused || closed.Reason != c.reason {
			t.Errorf("%s: closed %+v", c.name, closed)
		}
		if !eventually(t, 2*time.Second, func() bool { return h.audits("fleet.channel.violation") == violations+1 }) {
			t.Errorf("%s: no fleet.channel.violation", c.name)
		}
	}
	// A result for a call the channel never sent is a violation too.
	node := h.enroll()
	channel := h.connect(node)
	ctx, cancel := background()
	defer cancel()
	fake := &relayv1.ChannelCall{CallId: &foundationv1.Id{Value: idBytes(platform.NewID())}}
	header := &relayv1.ResultHeader{CallId: fake.CallId, NodeId: &foundationv1.Id{Value: idBytes(node.node.ID)}, Method: hub.MethodGetNodeTask.Enum(),
		RequestSha256: make([]byte, 32), ResponseSha256: make([]byte, 32), ResponseSize: proto.Uint32(1), ExecutedAt: arc.Instant(time.Now()),
		Outcome: relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED.Enum()}
	if err := channel.Answer(ctx, node.node, fake.CallId, header, []byte{0}); err != nil {
		t.Fatal(err)
	}
	if closed := channel.AwaitClose(ctx, false); closed.Code != hub.CloseRefused || closed.Reason != "result_other_call" {
		t.Fatalf("a result for no call: %+v", closed)
	}
}

func policyRefusal() *foundationv1.ArcError {
	return &foundationv1.ArcError{Code: proto.String("permission_denied"), Category: foundationv1.ErrorCategory_ERROR_CATEGORY_AUTHORIZATION.Enum(),
		MessageKey: proto.String("error.authorization.permission_denied"), Retry: &foundationv1.RetryAdvice{Mode: foundationv1.RetryMode_RETRY_MODE_NEVER.Enum()},
		Effect: foundationv1.EffectCertainty_EFFECT_CERTAINTY_DID_NOT_HAPPEN.Enum(), CorrelationId: &foundationv1.Id{Value: idBytes(platform.NewID())},
		Details: &foundationv1.ErrorDetails{Detail: &foundationv1.ErrorDetails_State{State: &foundationv1.StateFailure{State: proto.String("task.submit"),
			Reason: proto.String("relay_own_node_only")}}}}
}

// TestANodesRefusalIsAnsweredRebuilt (PN-6, rule routedRefusal): a policy refusal comes back as the center's refusal of its closed fields,
// rendered with the caller's correlation ID, never the node's bytes or correlation; the channel stays open.
func TestANodesRefusalIsAnsweredRebuilt(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	channel := h.connect(node)
	done := h.callAsync(sessionCall(node, hub.MethodSubmitNodeTask, []byte{0x0a, 0x00}))
	sent := nextCall(t, channel)
	nodeRefusal := policyRefusal()
	ctx, cancel := background()
	defer cancel()
	if err := channel.Answer(ctx, node.node, sent.GetCallId(), node.node.Refused(sent, relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY, nodeRefusal), nil); err != nil {
		t.Fatal(err)
	}
	value := await(t, done)
	if value.err != nil || value.result.Outcome != relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY || value.result.Refusal == nil || value.result.Response != nil {
		t.Fatalf("the refused call: %+v", value)
	}
	call := correlation.New()
	rendered := value.result.Refusal.ArcError(call)
	want := proto.Clone(nodeRefusal).(*foundationv1.ArcError)
	want.CorrelationId = &foundationv1.Id{Value: correlation.IDBytes(call.CorrelationID)}
	if !proto.Equal(rendered, want) || bytes.Equal(rendered.GetCorrelationId().GetValue(), nodeRefusal.GetCorrelationId().GetValue()) {
		t.Fatalf("the rebuilt refusal:\n%v\nwant\n%v", rendered, want)
	}
	if !h.center.Hub.Connected(node.node.ID) {
		t.Fatal("a valid refusal closed the channel")
	}
}

// TestInFlightBoundsHold is E1-18 (CTR5-HUB-10): at most MaxInFlightCalls calls wait on one node's channel and MaxInFlightPerCenter in
// the process; a call over either is refused RESOURCE/overloaded before anything is sent, and a finished call frees its slot.
func TestInFlightBoundsHold(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) { s.MaxInFlightCalls, s.MaxInFlightPerCenter = 2, 3 }})
	first, second := h.enroll(), h.enroll()
	firstChannel, secondChannel := h.connect(first), h.connect(second)
	waiting := []<-chan called{h.callAsync(sessionCall(first, hub.MethodGetNodeTask, []byte{1})), h.callAsync(sessionCall(first, hub.MethodGetNodeTask, []byte{2}))}
	calls := []*relayv1.ChannelCall{nextCall(t, firstChannel), nextCall(t, firstChannel)}
	value := await(t, h.callAsync(sessionCall(first, hub.MethodGetNodeTask, []byte{3})))
	if refusal := refused(t, value.err); refusal.Key() != "RESOURCE/overloaded" {
		t.Fatalf("the node's third call: %s", refusal.Key())
	}
	waiting = append(waiting, h.callAsync(sessionCall(second, hub.MethodGetNodeTask, []byte{4})))
	calls = append(calls, nextCall(t, secondChannel))
	if !eventually(t, 2*time.Second, func() bool { return h.center.Hub.InFlight() == 3 }) {
		t.Fatalf("in flight: %d", h.center.Hub.InFlight())
	}
	value = await(t, h.callAsync(sessionCall(second, hub.MethodGetNodeTask, []byte{5})))
	if refusal := refused(t, value.err); refusal.Key() != "RESOURCE/overloaded" {
		t.Fatalf("the center's fourth call: %s", refusal.Key())
	}
	if h.center.Metrics.ChannelCount("call", "node_bound") != 1 || h.center.Metrics.ChannelCount("call", "center_bound") != 1 {
		t.Fatal("the two bounds are counted apart")
	}
	ctx, cancel := background()
	defer cancel()
	channels := []*nodetest.Channel{firstChannel, firstChannel, secondChannel}
	nodes := []*enrolled{first, first, second}
	for i, call := range calls {
		if err := channels[i].Answer(ctx, nodes[i].node, call.GetCallId(), nodes[i].node.Executed(call, []byte{9}), []byte{9}); err != nil {
			t.Fatal(err)
		}
	}
	for _, done := range waiting {
		if value := await(t, done); value.err != nil {
			t.Fatal(value.err)
		}
	}
	// The slots are free again.
	done := h.callAsync(sessionCall(first, hub.MethodGetNodeTask, []byte{6}))
	call := nextCall(t, firstChannel)
	if err := firstChannel.Answer(ctx, first.node, call.GetCallId(), first.node.Executed(call, []byte{7}), []byte{7}); err != nil {
		t.Fatal(err)
	}
	if value := await(t, done); value.err != nil {
		t.Fatal(value.err)
	}
}

// TestAFullSendQueueRefusesNewCalls is E1-18's queue half (CTR5-HUB-10): a call frame the bounded send queue cannot take is refused
// RESOURCE/overloaded (DID_NOT_HAPPEN, retry_at), nothing is sent, and the channel stays open.
func TestAFullSendQueueRefusesNewCalls(t *testing.T) {
	h := newHarness(t, settings{tune: func(s *hub.Settings) { s.SendQueueBytes = 4096 }})
	node := h.enroll()
	channel := h.connect(node)
	value := await(t, h.callAsync(sessionCall(node, hub.MethodSubmitNodeTask, make([]byte, 8192))))
	refusal := refused(t, value.err)
	if refusal.Key() != "RESOURCE/overloaded" || refusal.Effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
		refusal.Dated(time.Now()).RetryAt.IsZero() {
		t.Fatalf("a full queue: %+v", refusal)
	}
	if h.center.Metrics.ChannelCount("call", "queue_full") != 1 || h.center.Hub.InFlight() != 0 || !h.center.Hub.Connected(node.node.ID) {
		t.Fatal("the refused call is counted, holds no slot, and the channel stays")
	}
	_ = channel
}

// TestInFlightCallsFailWhenTheChannelCloses (CTR5-HUB-04, -08): a newer connection, a device revocation or any other close fails the
// calls of the closed connection STATE/node_unreachable (channel_closed): UNKNOWN with SAME_COMMAND for a delivered mutation,
// DID_NOT_HAPPEN for a read; a node without a connection is STATE/node_offline.
func TestInFlightCallsFailWhenTheChannelCloses(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	channel := h.connect(node)
	submit := h.callAsync(sessionCall(node, hub.MethodSubmitNodeTask, []byte{1}))
	nextCall(t, channel)
	read := h.callAsync(sessionCall(node, hub.MethodGetNodeTask, []byte{2}))
	nextCall(t, channel)
	h.connect(node) // the replacement
	value := await(t, submit)
	refusal := refused(t, value.err)
	if refusal.Key() != "STATE/node_unreachable" || refusal.Reason != arc.UnreachableChannelClosed || refusal.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
		refusal.Retry != foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND {
		t.Fatalf("a delivered submit of a replaced channel: %+v", refusal)
	}
	value = await(t, read)
	refusal = refused(t, value.err)
	if refusal.Key() != "STATE/node_unreachable" || refusal.Effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
		refusal.Retry != foundationv1.RetryMode_RETRY_MODE_AFTER_TIME {
		t.Fatalf("a delivered read of a replaced channel: %+v", refusal)
	}
	// The node closes its newest channel: a later call finds no connection.
	other := h.enroll()
	otherChannel := h.connect(other)
	pendingCall := h.callAsync(sessionCall(other, hub.MethodCancelNodeTask, []byte{3}))
	nextCall(t, otherChannel)
	_ = otherChannel.WS.CloseNow()
	if refusal := refused(t, await(t, pendingCall).err); refusal.Reason != arc.UnreachableChannelClosed || refusal.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN {
		t.Fatalf("a delivered cancel of a dropped channel: %+v", refusal)
	}
	if !eventually(t, 2*time.Second, func() bool { return !h.center.Hub.Connected(other.node.ID) }) {
		t.Fatal("the dropped channel is still the node's")
	}
	if refusal := refused(t, await(t, h.callAsync(sessionCall(other, hub.MethodSubmitNodeTask, []byte{4}))).err); refusal.Key() != "STATE/node_offline" ||
		refusal.RetryAt.IsZero() {
		t.Fatalf("a call for a node without a connection: %+v", refusal)
	}
	// A call for another account's node is not found.
	wrong := sessionCall(node, hub.MethodGetNodeTask, []byte{5})
	wrong.AccountID = platform.NewID()
	if refusal := refused(t, await(t, h.callAsync(wrong)).err); refusal.Key() != "STATE/not_found" {
		t.Fatalf("another account's node: %s", refusal.Key())
	}
}

// TestADeviceRevocationFailsTheNodesCalls (CTR5-HUB-08): the revocation cascade closes the channel 4401 after commit, and its calls fail
// STATE/node_unreachable (channel_closed): UNKNOWN for the delivered submit, DID_NOT_HAPPEN for the delivered read; nothing more is
// routed to the node from this process (STATE/node_offline here; the routed API answers a revoked node not_found from the store).
func TestADeviceRevocationFailsTheNodesCalls(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	channel := h.connect(node)
	submit := h.callAsync(sessionCall(node, hub.MethodSubmitNodeTask, []byte{1}))
	nextCall(t, channel)
	read := h.callAsync(sessionCall(node, hub.MethodGetNodeTask, []byte{2}))
	nextCall(t, channel)
	ctx, cancel := background()
	defer cancel()
	participants := []device.Participant{fleet.NodeParticipant{}, h.center.Hub.Participant()}
	if err := h.db.Runtime.InTx(ctx, "revoke a device", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := device.Revoke(ctx, tx, node.user, node.result.DeviceID, device.RevokedByOwner, participants, time.Now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if refusal := refused(t, await(t, submit).err); refusal.Reason != arc.UnreachableChannelClosed || refusal.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN {
		t.Fatalf("the delivered submit of a revoked node: %+v", refusal)
	}
	if refusal := refused(t, await(t, read).err); refusal.Reason != arc.UnreachableChannelClosed || refusal.Effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN {
		t.Fatalf("the delivered read of a revoked node: %+v", refusal)
	}
	if closed := channel.AwaitClose(ctx, false); closed.Code != hub.CloseCredential {
		t.Fatalf("the revoked channel: %+v", closed)
	}
	if refusal := refused(t, await(t, h.callAsync(sessionCall(node, hub.MethodGetNodeTask, []byte{3}))).err); refusal.Key() != "STATE/node_offline" {
		t.Fatalf("a call after the revocation: %s", refusal.Key())
	}
}

// TestADeadlinePassedCallIsUnreachableAndItsLateResultIsDropped (CTR5-RTE-05): a delivered call without a result by its deadline fails
// STATE/node_unreachable (deadline_passed); the node's late, verified result is dropped and closes nothing.
func TestADeadlinePassedCallIsUnreachableAndItsLateResultIsDropped(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	channel := h.connect(node)
	call := sessionCall(node, hub.MethodSubmitNodeTask, []byte{1})
	call.Deadline = 300 * time.Millisecond
	done := h.callAsync(call)
	sent := nextCall(t, channel)
	refusal := refused(t, await(t, done).err)
	if refusal.Reason != arc.UnreachableDeadline || refusal.Effect != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN {
		t.Fatalf("a delivered submit past its deadline: %+v", refusal)
	}
	ctx, cancel := background()
	defer cancel()
	if err := channel.Answer(ctx, node.node, sent.GetCallId(), node.node.Executed(sent, []byte{2}), []byte{2}); err != nil {
		t.Fatal(err)
	}
	if !eventually(t, 2*time.Second, func() bool { return h.center.Metrics.ChannelCount("call", "late") == 1 }) || !h.center.Hub.Connected(node.node.ID) {
		t.Fatal("a late result is dropped and the channel stays")
	}
	// A late result with a bad signature is still a violation.
	read := sessionCall(node, hub.MethodGetNodeTask, []byte{3})
	read.Deadline = 200 * time.Millisecond
	done = h.callAsync(read)
	sent = nextCall(t, channel)
	await(t, done)
	header := node.node.Executed(sent, []byte{4})
	data, _ := proto.Marshal(header)
	if err := channel.SendResult(ctx, sent.GetCallId(), &relayv1.SignedHeader{Header: data, Signature: node.node.SignResult(data, false), Algorithm: proto.String("ES256")}, []byte{4}); err != nil {
		t.Fatal(err)
	}
	if closed := channel.AwaitClose(ctx, false); closed.Code != hub.CloseRefused || closed.Reason != "result_signature" {
		t.Fatalf("a late high-S result: %+v", closed)
	}
}

// TestTheCenterSignsWithTheNewestValidKeyItHolds is E1-14 (CTR5-SIG-02; Design 11 section 3): a successor key registered for later
// signs from its not_before on, the health document names the signing kid (never key material), and once no held key is valid the hub
// signs nothing: the call fails STATE/node_unreachable (channel_closed, DID_NOT_HAPPEN) and the node receives no call.
func TestTheCenterSignsWithTheNewestValidKeyItHolds(t *testing.T) {
	// The node reads nothing while it waits for the successor's not_before, so the heartbeat deadline is out of the way.
	h := newHarness(t, settings{tune: func(s *hub.Settings) { s.Heartbeat, s.HeartbeatDeadline = time.Second, 20*time.Second }})
	node := h.enroll()
	channel := h.connect(node)
	if kid := h.health(t); kid != h.kid {
		t.Fatalf("the health document names %q", kid)
	}
	successor, successorKID := h.registerKey(t, "ARCFORGES_CENTER_KEY_NEXT", time.Now().Add(1500*time.Millisecond))
	h.center.Hub.UseCommandKeys([]config.CommandKey{h.commandKey, successor})
	if err := h.center.Hub.RefreshKeys(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := background()
	defer cancel()
	roundTrip := func() *relayv1.ChannelCall {
		done := h.callAsync(sessionCall(node, hub.MethodGetNodeTask, []byte{1}))
		sent := nextCall(t, channel)
		if err := channel.Answer(ctx, node.node, sent.GetCallId(), node.node.Executed(sent, []byte{1}), []byte{1}); err != nil {
			t.Fatal(err)
		}
		if value := await(t, done); value.err != nil {
			t.Fatal(value.err)
		}
		return sent
	}
	if sent := roundTrip(); sent.GetHeader().GetKid() != h.kid {
		t.Fatalf("before the successor's not_before: %q", sent.GetHeader().GetKid())
	}
	time.Sleep(1600 * time.Millisecond)
	sent := roundTrip()
	if sent.GetHeader().GetKid() != successorKID || !fleet.VerifyNodeKeyProof(successor.PublicKey(), append([]byte(hub.CallDomain), sent.GetHeader().GetHeader()...),
		sent.GetHeader().GetSignature()) {
		t.Fatalf("after the successor's not_before: %q", sent.GetHeader().GetKid())
	}
	if kid := h.health(t); kid != successorKID {
		t.Fatalf("the health document names %q after the rotation", kid)
	}
	// Both keys retired: nothing is signed.
	h.retireKeys(t, h.kid, successorKID)
	if err := h.center.Hub.RefreshKeys(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	refusal := refused(t, await(t, h.callAsync(sessionCall(node, hub.MethodSubmitNodeTask, []byte{2}))).err)
	if refusal.Key() != "STATE/node_unreachable" || refusal.Reason != arc.UnreachableChannelClosed || refusal.Effect == foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN {
		t.Fatalf("a call without a valid key: %+v", refusal)
	}
	read, readCancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer readCancel()
	if call, err := channel.NextCall(read); err == nil {
		t.Fatalf("the node received a call signed with no valid key: %v", call.GetHeader().GetKid())
	}
	if kid := h.health(t); kid != "" {
		t.Fatalf("the health document names %q without a valid key", kid)
	}
}

// health reads the center's health document and returns its signing kid; the document never carries key material.
func (h *harness) health(t *testing.T) string {
	t.Helper()
	response, err := http.Get(h.url + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	public := h.commandKey.PublicKey()
	for _, forbidden := range []string{"PRIVATE", string(public)} {
		if strings.Contains(string(body), forbidden) {
			t.Fatal("the health document carries key material")
		}
	}
	var document struct {
		Center struct {
			SigningKid string `json:"signingKid"`
		} `json:"center"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	return document.Center.SigningKid
}

// registerKey registers a command key valid from notBefore (outliving the test's key, as the rotation rule requires) and loads it.
func (h *harness) registerKey(t *testing.T, binding string, notBefore time.Time) (config.CommandKey, string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := config.NewCommandKey(binding, private)
	if err != nil {
		t.Fatal(err)
	}
	kid := "next-" + platform.NewID().String()[:12]
	ctx := context.Background()
	tx, err := h.db.Migration.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := platform.RegisterKey(ctx, tx, platform.SigningKey{KID: kid, Purpose: platform.CommandSigning, Algorithm: "ES256", PublicKey: key.PublicKey(),
		SecretBinding: binding, NotBefore: notBefore, NotAfter: time.Now().Add(40 * 24 * time.Hour)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return key, kid
}

// retireKeys retires command keys now (the operator's admin retire-signing-key).
func (h *harness) retireKeys(t *testing.T, kids ...string) {
	t.Helper()
	ctx := context.Background()
	tx, err := h.db.Migration.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, kid := range kids {
		if _, err := platform.RetireKey(ctx, tx, kid, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
