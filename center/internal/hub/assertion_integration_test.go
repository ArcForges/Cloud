// SPDX-License-Identifier: AGPL-3.0-only

package hub_test

import (
	"bytes"
	"crypto/sha256"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/hub"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/nodetest"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// Relay nonces and relay assertions (AF-CTR-05 E1b; Plan addendum D0-B1, C-N1, C-N2, C-N6; EVIDENCE: REAL PostgreSQL, the composed
// center's hub and the real WebSocket server; MOCKED: the relaying node, nodetest with a software key). VerifyRelayAssertion is the
// function the routed API (E2) calls before it serves or routes a node-relayed call.

// credentialOf is the bearer credential of an enrolled node as the session verifier states it.
func credentialOf(node *enrolled) ingress.Caller {
	return ingress.Caller{Credential: ingress.CredentialNativeBearer, Scope: "node", SessionID: platform.NewID().String(), UserID: node.user.String(),
		InstallationID: node.result.InstallationID.String()}
}

func nonceOf(t *testing.T, channel *nodetest.Channel) []byte {
	t.Helper()
	ctx, cancel := background()
	defer cancel()
	nonce, err := channel.RelayNonce(ctx)
	if err != nil {
		t.Fatalf("relay nonce: %v", err)
	}
	return nonce.GetNonce()
}

// relayed is a relayed GetNodeTask of a node to its own node, with its assertion over a nonce and the request it states.
func relayed(node *enrolled, nonce, payload []byte) (*relayv1.RelayAssertion, hub.RelayRequest) {
	digest := sha256.Sum256(payload)
	target := node.node.ID
	assertion := node.node.Assertion(publicBaseURL, nodetest.Relay{InstallationID: node.result.InstallationID, LocalOrigin: nodev1.Origin_ORIGIN_HUMAN,
		LocalSession: platform.NewID(), Method: hub.MethodGetNodeTask, RequestSHA256: digest[:], Target: &target, Nonce: nonce})
	data, _ := proto.Marshal(assertion)
	return assertion, hub.RelayRequest{Assertion: data, Method: hub.MethodGetNodeTask, RequestSHA256: digest[:], TargetNodeID: &target,
		CallerRelayingNodeID: node.node.ID, CallerLocalOrigin: nodev1.Origin_ORIGIN_HUMAN}
}

func relayRefusal(t *testing.T, err error) string {
	t.Helper()
	refusal := refused(t, err)
	if refusal.Key() != "AUTHENTICATION/unauthenticated" || refusal.State != "relay_assertion" {
		t.Fatalf("a relay refusal: %s %s", refusal.Key(), refusal.State)
	}
	return refusal.Reason
}

// TestARelayNonceIsOneUseAndVoidAtClose (C-N2): a RelayNonceRequest is answered with 32 random bytes valid at most 120 s; an assertion
// spends its nonce, so a replay is refused nonce_reused; a ninth unspent nonce voids the oldest; a nonce is void once its connection
// closes, and only the channel of the node that asked holds it.
func TestARelayNonceIsOneUseAndVoidAtClose(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	channel := h.connect(node)
	ctx, cancel := background()
	defer cancel()
	before := time.Now()
	value, err := channel.RelayNonce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Unix(value.GetExpiresAt().GetUnixSeconds(), int64(value.GetExpiresAt().GetNanos()))
	if len(value.GetNonce()) != 32 || !expires.After(before) || expires.After(time.Now().Add(120*time.Second)) {
		t.Fatalf("the relay nonce: %d bytes, expires %s", len(value.GetNonce()), expires)
	}
	_, request := relayed(node, value.GetNonce(), []byte{1})
	verified, err := h.center.Hub.VerifyRelayAssertion(ctx, credentialOf(node), request)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(request.Assertion)
	if verified.RelayingNodeID != node.node.ID || verified.RelayingInstallationID != node.result.InstallationID || verified.LocalOrigin != nodev1.Origin_ORIGIN_HUMAN ||
		!bytes.Equal(verified.AssertionSHA256, digest[:]) {
		t.Fatalf("the verified relay: %+v", verified)
	}
	// The replay: the nonce is spent.
	_, err = h.center.Hub.VerifyRelayAssertion(ctx, credentialOf(node), request)
	if reason := relayRefusal(t, err); reason != arc.RelayNonceReused || refused(t, err).Retry != foundationv1.RetryMode_RETRY_MODE_SAME_COMMAND {
		t.Fatalf("a replayed assertion: %s", reason)
	}
	// Nine unspent nonces: the oldest is void.
	nonces := make([][]byte, 9)
	for i := range nonces {
		nonces[i] = nonceOf(t, channel)
	}
	_, oldest := relayed(node, nonces[0], []byte{2})
	if _, err := h.center.Hub.VerifyRelayAssertion(ctx, credentialOf(node), oldest); relayRefusal(t, err) != arc.RelayNonceReused {
		t.Fatal("the voided oldest nonce")
	}
	_, newest := relayed(node, nonces[8], []byte{3})
	if _, err := h.center.Hub.VerifyRelayAssertion(ctx, credentialOf(node), newest); err != nil {
		t.Fatalf("the newest nonce: %v", err)
	}
	// Another node's nonce is not this node's.
	other := h.enroll()
	h.connect(other)
	_, foreign := relayed(other, nonces[7], []byte{4})
	if _, err := h.center.Hub.VerifyRelayAssertion(ctx, credentialOf(other), foreign); relayRefusal(t, err) != arc.RelayNonceReused {
		t.Fatal("another channel's nonce")
	}
	// A closed connection voids its nonces, also for its replacement.
	_, kept := relayed(node, nonces[6], []byte{5})
	h.connect(node)
	if !eventually(t, 2*time.Second, func() bool { return h.center.Hub.Connected(node.node.ID) }) {
		t.Fatal("the replacement")
	}
	if _, err := h.center.Hub.VerifyRelayAssertion(ctx, credentialOf(node), kept); relayRefusal(t, err) != arc.RelayNonceReused {
		t.Fatal("a nonce of a replaced connection")
	}
	_ = channel
}

// TestARelayAssertionIsVerifiedBeforeRouting (D0-B1, C-N1, C-N6): each refusal reason of the contract, in its order; then a verified
// relay is the caller the center signs into the call header, with the assertion's digest.
func TestARelayAssertionIsVerifiedBeforeRouting(t *testing.T) {
	h := newHarness(t, settings{})
	node := h.enroll()
	channel := h.connect(node)
	stranger, err := nodetest.New()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := background()
	defer cancel()
	resign := func(assertion *relayv1.RelayAssertion, signer *nodetest.Node) []byte {
		assertion.Signature = signer.SignMessage(nodetest.OriginMessage(publicBaseURL, assertion), true)
		data, _ := proto.Marshal(assertion)
		return data
	}
	cases := []struct {
		name   string
		reason string
		change func(assertion *relayv1.RelayAssertion, request *hub.RelayRequest)
	}{
		{"no assertion", arc.RelayMissing, func(_ *relayv1.RelayAssertion, r *hub.RelayRequest) { r.Assertion = nil }},
		{"bytes that are no assertion", arc.RelaySignatureInvalid, func(_ *relayv1.RelayAssertion, r *hub.RelayRequest) { r.Assertion = []byte{0xff, 0x01} }},
		{"an assertion over 512 bytes", arc.RelaySignatureInvalid, func(_ *relayv1.RelayAssertion, r *hub.RelayRequest) { r.Assertion = make([]byte, 513) }},
		{"another key", arc.RelaySignatureInvalid, func(a *relayv1.RelayAssertion, r *hub.RelayRequest) { r.Assertion = resign(a, stranger) }},
		{"a high-S signature", arc.RelaySignatureInvalid, func(a *relayv1.RelayAssertion, r *hub.RelayRequest) {
			a.Signature = node.node.SignMessage(nodetest.OriginMessage(publicBaseURL, a), false)
			r.Assertion, _ = proto.Marshal(a)
		}},
		{"a signature for another center", arc.RelaySignatureInvalid, func(a *relayv1.RelayAssertion, r *hub.RelayRequest) {
			a.Signature = node.node.SignMessage(nodetest.OriginMessage("https://other.example.test/api", a), true)
			r.Assertion, _ = proto.Marshal(a)
		}},
		{"a signature over the bare fields", arc.RelaySignatureInvalid, func(a *relayv1.RelayAssertion, r *hub.RelayRequest) {
			a.Signature = node.node.SignMessage(nodetest.OriginMessage(publicBaseURL, a)[len(nodetest.OriginDomain):], true)
			r.Assertion, _ = proto.Marshal(a)
		}},
		{"another installation named", arc.RelayCredentialMismatch, func(a *relayv1.RelayAssertion, r *hub.RelayRequest) {
			a.RelayingInstallationId = &foundationv1.Id{Value: idBytes(platform.NewID())}
			r.Assertion = resign(a, node.node)
		}},
		{"another relaying node named", arc.RelayCredentialMismatch, func(a *relayv1.RelayAssertion, r *hub.RelayRequest) {
			a.RelayingNodeId = &foundationv1.Id{Value: idBytes(stranger.ID)}
			r.Assertion = resign(a, node.node)
		}},
		{"an expired assertion", arc.RelayExpired, func(a *relayv1.RelayAssertion, r *hub.RelayRequest) {
			issued := time.Now().Add(-90 * time.Second)
			a.IssuedAt, a.ExpiresAt = arc.Instant(issued), arc.Instant(issued.Add(60*time.Second))
			r.Assertion = resign(a, node.node)
		}},
		{"a nonce the center never sent", arc.RelayNonceReused, func(a *relayv1.RelayAssertion, r *hub.RelayRequest) {
			a.RelayNonce = make([]byte, 32)
			r.Assertion = resign(a, node.node)
		}},
		{"another target", arc.RelayRequestMismatch, func(_ *relayv1.RelayAssertion, r *hub.RelayRequest) {
			target := platform.NewID()
			r.TargetNodeID = &target
		}},
		{"another method", arc.RelayRequestMismatch, func(_ *relayv1.RelayAssertion, r *hub.RelayRequest) { r.Method = hub.MethodWaitNodeTask }},
		{"another request digest", arc.RelayRequestMismatch, func(_ *relayv1.RelayAssertion, r *hub.RelayRequest) { r.RequestSHA256 = make([]byte, 32) }},
		{"a command the assertion does not name", arc.RelayRequestMismatch, func(_ *relayv1.RelayAssertion, r *hub.RelayRequest) {
			command := platform.NewID()
			r.CommandID = &command
		}},
		{"a caller of another local origin", arc.RelayRequestMismatch, func(_ *relayv1.RelayAssertion, r *hub.RelayRequest) {
			r.CallerLocalOrigin = nodev1.Origin_ORIGIN_SCRIPT
		}},
		{"a caller naming another relaying node", arc.RelayRequestMismatch, func(_ *relayv1.RelayAssertion, r *hub.RelayRequest) {
			r.CallerRelayingNodeID = stranger.ID
		}},
	}
	for _, c := range cases {
		assertion, request := relayed(node, nonceOf(t, channel), []byte{1})
		c.change(assertion, &request)
		_, err := h.center.Hub.VerifyRelayAssertion(ctx, credentialOf(node), request)
		if reason := relayRefusal(t, err); reason != c.reason {
			t.Errorf("%s: %s, want %s", c.name, reason, c.reason)
		}
	}
	// A credential of an account session, or of another node, never verifies this node's assertion.
	_, request := relayed(node, nonceOf(t, channel), []byte{1})
	account := credentialOf(node)
	account.Scope = "account"
	if _, err := h.center.Hub.VerifyRelayAssertion(ctx, account, request); relayRefusal(t, err) != arc.RelayCredentialMismatch {
		t.Error("an account session's credential")
	}
	if _, err := h.center.Hub.VerifyRelayAssertion(ctx, credentialOf(h.enroll()), request); relayRefusal(t, err) != arc.RelaySignatureInvalid {
		t.Error("another node's credential")
	}
	// A message off its layout reaches no signing input (relay.proto, "Verifier pre-conditions"): a 15-byte relaying node and a
	// 17-byte local session, which concatenate to the same 228 bytes as a valid assertion's, signed by the node.
	shifted, request := relayed(node, nonceOf(t, channel), []byte{1})
	session := append(bytes.Clone(shifted.RelayingNodeId.Value[15:]), shifted.LocalSessionId.Value...)
	shifted.RelayingNodeId = &foundationv1.Id{Value: shifted.RelayingNodeId.Value[:15]}
	shifted.LocalSessionId = &foundationv1.Id{Value: session}
	request.Assertion = resign(shifted, node.node)
	inputs := hub.SigningInputs()
	if _, err := h.center.Hub.VerifyRelayAssertion(ctx, credentialOf(node), request); relayRefusal(t, err) != arc.RelaySignatureInvalid {
		t.Error("a shifted layout")
	}
	if hub.SigningInputs() != inputs {
		t.Fatal("a malformed assertion reached a signing input")
	}

	// A verified relay is the caller of the call the center signs (C-N1: only from the assertion).
	payload := []byte{0x0a, 0x00}
	_, request = relayed(node, nonceOf(t, channel), payload)
	verified, err := h.center.Hub.VerifyRelayAssertion(ctx, credentialOf(node), request)
	if err != nil {
		t.Fatal(err)
	}
	call := sessionCall(node, hub.MethodGetNodeTask, payload)
	call.Session, call.Relay = nil, &verified
	done := h.callAsync(call)
	sent := nextCall(t, channel)
	header := headerOf(t, sent)
	caller := header.GetCaller()
	if caller.GetKind() != nodev1.CenterCallerKind_CENTER_CALLER_KIND_NODE_RELAY || !bytes.Equal(caller.GetRelayingNodeId().GetValue(), idBytes(node.node.ID)) ||
		caller.GetLocalOrigin() != nodev1.Origin_ORIGIN_HUMAN || !bytes.Equal(caller.GetLocalSessionId().GetValue(), idBytes(verified.LocalSessionID)) ||
		!bytes.Equal(header.GetRelayAssertionSha256(), verified.AssertionSHA256) || caller.UserId != nil || caller.SessionId != nil {
		t.Fatalf("the signed caller: %v", caller)
	}
	if err := channel.Answer(ctx, node.node, sent.GetCallId(), node.node.Executed(sent, []byte{1}), []byte{1}); err != nil {
		t.Fatal(err)
	}
	if value := await(t, done); value.err != nil {
		t.Fatal(value.err)
	}
}
