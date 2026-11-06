// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"time"

	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// Relay nonces and relay assertions (AF-CTR-05 E1b; Plan addendum D0-B1, C-N1, C-N2, C-N6; Contracts relay.proto RelayNonce and
// RelayAssertion; ArcForges-Design 11 section 1, "Relay assertion"). A node that relays a local caller's call first asks its open
// channel for a relay nonce; the center answers with 32 random bytes that only this connection's node may spend, once, before the
// nonce expires (at most 120 s) or the connection closes or is replaced. The relaying node signs the assertion over it, and the routed
// API (E2) calls VerifyRelayAssertion before it serves or routes the call: a bearer token alone never yields a relayed call.

// MaxRelayAssertionBytes is the bound of a routed request's relay_assertion field (fleet.proto: at most 512 bytes).
const MaxRelayAssertionBytes = 512

// relayNonce is one unspent relay nonce of a connection.
type relayNonce struct {
	value   []byte
	expires time.Time
}

// relayNonce answers a RelayNonceRequest with a fresh nonce of this connection. At most MaxRelayNonces are held: a newer one voids the
// oldest (ChannelLimits.max_relay_nonces). A request without a valid request ID is a violation.
func (c *conn) relayNonce(frame inbound, now time.Time) bool {
	if !frame.requestOK {
		c.violation("nonce_request_malformed")
		return false
	}
	value := make([]byte, RelayNonceBytes)
	if _, err := rand.Read(value); err != nil {
		c.closeWith(CloseShuttingDown, "internal")
		return false
	}
	expires := now.Add(c.hub.settings.RelayNonceLifetime)
	c.mu.Lock()
	if c.callsClosed {
		c.mu.Unlock()
		return false
	}
	if len(c.nonces) >= max(c.hub.settings.MaxRelayNonces, 1) {
		c.nonces = c.nonces[1:]
	}
	c.nonces = append(c.nonces, relayNonce{value: value, expires: expires})
	c.mu.Unlock()
	if err := c.send(func(seq uint64) ([]byte, error) { return c.hub.codec.RelayNonce(seq, frame.requestID, value, expires) }); err != nil {
		// A full queue drops the answer; the node asks again.
		c.spend(value, now)
		return true
	}
	c.hub.metrics.ObserveChannel("relay_nonce", "issued")
	return true
}

// spend uses a relay nonce once: it reports whether the connection held it unexpired, and removes it either way.
func (c *conn) spend(value []byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.callsClosed {
		return false
	}
	for i, held := range c.nonces {
		if subtle.ConstantTimeCompare(held.value, value) == 1 {
			c.nonces = append(c.nonces[:i], c.nonces[i+1:]...)
			return now.Before(held.expires)
		}
	}
	return false
}

// spendRelayNonce spends a relay nonce of the accepted connection of a node and installation in this process.
func (h *Hub) spendRelayNonce(nodeID, installationID platform.ID, value []byte, now time.Time) bool {
	h.mu.Lock()
	c := h.nodes[nodeID]
	h.mu.Unlock()
	if c == nil || c.installationID != installationID || c.closing.Load() {
		return false
	}
	return c.spend(value, now)
}

// RelayRequest is what the routed request of a node-relayed call states, for VerifyRelayAssertion: its relay_assertion bytes as
// received, its method, the request digest (for the six routed task methods SHA-256 of the exact node.v1 request bytes; for ListNodes
// and GetNode that of the request's top-level fields as transmitted without relay_assertion), its target node (nil for ListNodes), its
// command (nil for a read) and its caller field (the relaying node and local origin it claims).
type RelayRequest struct {
	Assertion            []byte
	Method               relayv1.RoutedMethod
	RequestSHA256        []byte
	TargetNodeID         *platform.ID
	CommandID            *platform.ID
	CallerRelayingNodeID platform.ID
	CallerLocalOrigin    nodev1.Origin
}

// VerifiedRelay is a relay assertion the center verified: the caller it states, and the SHA-256 of its bytes (the call header's
// relay_assertion_sha256). Every field is unexported and read through an accessor (an accessor of a byte slice returns a copy), and
// only VerifyRelayAssertion fills them: another package can neither build a verified relay nor change one, and a copy of the value
// keeps exactly the verified fields (review A C-N1; TestAVerifiedRelayIsReadOnly pins it). hub.Call refuses a relay whose verified
// flag is not set.
type VerifiedRelay struct {
	relayingNodeID         platform.ID
	relayingInstallationID platform.ID
	localOrigin            nodev1.Origin
	localSessionID         platform.ID
	assertionSHA256        []byte
	expiresAt              time.Time
	verified               bool
}

// RelayingNodeID is the relaying node the assertion states (the bearer credential's node).
func (v VerifiedRelay) RelayingNodeID() platform.ID { return v.relayingNodeID }

// RelayingInstallationID is the relaying installation the assertion states (the bearer credential's installation).
func (v VerifiedRelay) RelayingInstallationID() platform.ID { return v.relayingInstallationID }

// LocalOrigin is the local origin the relaying node classified (HUMAN, SCRIPT or AGENT).
func (v VerifiedRelay) LocalOrigin() nodev1.Origin { return v.localOrigin }

// LocalSessionID is the local caller's client session at the relaying node.
func (v VerifiedRelay) LocalSessionID() platform.ID { return v.localSessionID }

// AssertionSHA256 is a copy of the SHA-256 of the assertion's bytes as received.
func (v VerifiedRelay) AssertionSHA256() []byte { return append([]byte(nil), v.assertionSHA256...) }

// ExpiresAt is the assertion's expiry.
func (v VerifiedRelay) ExpiresAt() time.Time { return v.expiresAt }

// Verified reports a relay that VerifyRelayAssertion produced.
func (v VerifiedRelay) Verified() bool { return v.verified }

// VerifyRelayAssertion verifies the relay assertion of a node-relayed call before it is served or routed (D0-B1, C-N1, C-N6), for the
// bearer credential that sent it, in the contract's order:
//  1. the assertion is present (missing), and decodes with the exact layout of relay.proto (every ID 16 bytes and not zero, digests
//     and nonce 32 bytes, the signature 64, origin 1..3, method 1..8, the target and command as the method needs, at most 120 s
//     between issue and expiry), before any signing input is built (signature_invalid);
//  2. its signature, under the relay-origin domain string over the canonical bytes, by the key registered for the bearer
//     credential's installation, never a key the assertion names (signature_invalid);
//  3. its relaying node and installation are that credential's live node and installation (credential_mismatch);
//  4. it has not expired (expired), and its relay nonce is one the relaying node's open channel holds unspent, which is then spent
//     (nonce_reused);
//  5. its method, request digest, target and command equal the routed request's, and the request's caller its relaying node and
//     local origin (request_mismatch).
//
// Every refusal is AUTHENTICATION/unauthenticated with state.state relay_assertion and the reason (arc.RelayAssertionRefused); a store
// that does not answer is RESOURCE/overloaded. Its error is always an *arc.Refusal.
func (h *Hub) VerifyRelayAssertion(ctx context.Context, credential ingress.Caller, request RelayRequest) (VerifiedRelay, error) {
	now := h.clock()
	refuse := func(reason string) (VerifiedRelay, error) {
		h.metrics.ObserveChannel("assertion", reason)
		return VerifiedRelay{}, arc.RelayAssertionRefused(reason)
	}
	if len(request.Assertion) == 0 {
		return refuse(arc.RelayMissing)
	}
	var assertion relayv1.RelayAssertion
	if len(request.Assertion) > MaxRelayAssertionBytes || proto.Unmarshal(request.Assertion, &assertion) != nil || !validRelayAssertion(&assertion) {
		return refuse(arc.RelaySignatureInvalid)
	}
	if credential.Scope != "node" || h.db == nil {
		return refuse(arc.RelayCredentialMismatch)
	}
	node, err := h.liveNode(ctx, credential)
	switch {
	case err != nil:
		return VerifiedRelay{}, arc.Unavailable()
	case node == nil:
		return refuse(arc.RelayCredentialMismatch)
	}
	audience := sha256.Sum256([]byte(h.centerURL))
	if !verifyES256(node.publicKey, originSigningInput(audience, &assertion), assertion.Signature) {
		return refuse(arc.RelaySignatureInvalid)
	}
	relayingNode, _ := idOf(assertion.RelayingNodeId)
	relayingInstallation, _ := idOf(assertion.RelayingInstallationId)
	installation := parseID(credential.InstallationID)
	if relayingNode != node.nodeID || relayingInstallation != installation {
		return refuse(arc.RelayCredentialMismatch)
	}
	expires := timeOf(assertion.ExpiresAt)
	if !now.Before(expires) {
		return refuse(arc.RelayExpired)
	}
	if !h.spendRelayNonce(relayingNode, installation, assertion.RelayNonce, now) {
		return refuse(arc.RelayNonceReused)
	}
	h.metrics.ObserveChannel("relay_nonce", "spent")
	if assertion.GetMethod() != request.Method || !equalBytes(assertion.RequestSha256, request.RequestSHA256) ||
		!sameOptionalID(assertion.TargetNodeId, request.TargetNodeID) || !sameOptionalID(assertion.CommandId, request.CommandID) ||
		request.CallerRelayingNodeID != relayingNode || request.CallerLocalOrigin != assertion.GetLocalOrigin() {
		return refuse(arc.RelayRequestMismatch)
	}
	localSession, _ := idOf(assertion.LocalSessionId)
	digest := sha256.Sum256(request.Assertion)
	h.metrics.ObserveChannel("assertion", "verified")
	return VerifiedRelay{relayingNodeID: relayingNode, relayingInstallationID: relayingInstallation, localOrigin: assertion.GetLocalOrigin(),
		localSessionID: localSession, assertionSHA256: digest[:], expiresAt: expires, verified: true}, nil
}

// RelayVerifier is VerifyRelayAssertion as the authorizer asks for it (access.WithRelayVerifier; AF-CTR-05 E2a, decisions B-4): the
// authorizer itself verifies the relay of every node-relayed call before it decides anything else, and receives the VerifiedRelay by
// value, whose fields only VerifyRelayAssertion sets.
func (h *Hub) RelayVerifier() access.RelayVerifier {
	return func(ctx context.Context, credential ingress.Caller, claim access.RelayClaim) (access.Relay, error) {
		verified, err := h.VerifyRelayAssertion(ctx, credential, RelayRequest{Assertion: claim.Assertion, Method: claim.Method, RequestSHA256: claim.RequestSHA256,
			TargetNodeID: claim.TargetNodeID, CommandID: claim.CommandID, CallerRelayingNodeID: claim.CallerRelayingNodeID, CallerLocalOrigin: claim.CallerLocalOrigin})
		if err != nil {
			return nil, err
		}
		return verified, nil
	}
}
