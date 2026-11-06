// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/sha256"
	"sync"
	"sync/atomic"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	nodev1 "github.com/ArcForges/Contracts/go/arcforges/node/v1"
	relayv1 "github.com/ArcForges/Contracts/go/arcforges/relay/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// Signed calls and results (AF-CTR-05 part E1b; Plan CTR5-SIG-01..04, CTR5-HUB-08 and -10, PN-6; Contracts relay.proto CallHeader,
// ResultHeader and the rule routedRefusal). Call is the routing seam the routed API (E2) uses: it takes a call whose caller E2 has
// verified (an account session, or a relay assertion through VerifyRelayAssertion), signs its CallHeader with the newest valid
// command key the center holds, sends it on the target node's channel and waits for the node's signed result, which it verifies
// against the key registered for the connection's installation. Nothing of a call or result is stored: the result's response bytes
// are returned unchanged, with their digest, and a node's refusal is rebuilt from its closed fields.

// MaxCallDeadline is the longest a call may wait for its result: its deadline never passes its expiry, at most 300 s after issue.
const MaxCallDeadline = CallWindowSeconds * time.Second

// callExpiryMargin is how long a call stays valid at the node after the center stops waiting (CTR5-RTE-06: the call header's
// expires_at is now + min(deadline + 30 s, 300 s)).
const callExpiryMargin = 30 * time.Second

// lateResults bounds the call IDs of one connection whose deadline passed after delivery: a result that arrives for one of them late
// is verified and dropped, never a violation.
const lateResults = 256

// SessionCaller is an account session's caller of a routed call (CallHeader.caller of kind ACCOUNT_SESSION): its user and session as
// the session verifier stated them.
type SessionCaller struct {
	UserID, SessionID platform.ID
}

// caller is the verified caller the center signs into CallHeader.caller: an account session, or a node relay taken only from a
// VerifiedRelay (Plan addendum C-N1), never from a request field.
type caller struct {
	kind              nodev1.CenterCallerKind
	userID, sessionID platform.ID
	relayingNodeID    platform.ID
	localOrigin       nodev1.Origin
	localSessionID    platform.ID
	assertionSHA256   []byte
}

// Call is one routed call. Exactly one of Session and Relay names its caller. A Relay comes only from VerifyRelayAssertion: it cannot be
// hand-built (its fields are unexported and an unverified one is refused) or changed after verification (it has no setter, and a copy
// keeps exactly the verified fields), so the relayed caller is the verified assertion's. Two ties have no enforcement point at this seam
// and are the routed API's (E2): the relaying node's account (the bearer credential's) is AccountID, and CommandID equals the payload's
// meta.command_id.
type Call struct {
	// AccountID is the account that owns the target node (the caller's; E2 has checked the ownership).
	AccountID    platform.ID
	TargetNodeID platform.ID
	Session      *SessionCaller
	Relay        *VerifiedRelay
	// CommandID is the command of a SubmitNodeTask or CancelNodeTask (equal to the payload's meta.command_id), nil for a read.
	CommandID *platform.ID
	Method    relayv1.RoutedMethod
	// Payload is the exact node.v1 TaskService request bytes the caller sent, never re-encoded (Plan decision Q9): 1..253,952 bytes.
	Payload []byte
	// Deadline is how long the center waits for the result (CTR5-RTE-06): more than zero, at most MaxCallDeadline.
	Deadline time.Duration
}

// callerOf is the call's verified caller; ok is false without exactly one of Session and a verified Relay.
func (call Call) callerOf() (caller, bool) {
	zero := platform.ID{}
	switch {
	case call.Session != nil && call.Relay == nil:
		return caller{kind: nodev1.CenterCallerKind_CENTER_CALLER_KIND_ACCOUNT_SESSION, userID: call.Session.UserID, sessionID: call.Session.SessionID},
			call.Session.UserID != zero && call.Session.SessionID != zero
	case call.Relay != nil && call.Session == nil:
		relay := call.Relay
		return caller{kind: nodev1.CenterCallerKind_CENTER_CALLER_KIND_NODE_RELAY, relayingNodeID: relay.relayingNodeID, localOrigin: relay.localOrigin,
				localSessionID: relay.localSessionID, assertionSHA256: relay.assertionSHA256},
			relay.verified && relay.relayingNodeID != zero && relay.localSessionID != zero && relay.localOrigin >= nodev1.Origin_ORIGIN_HUMAN &&
				relay.localOrigin <= nodev1.Origin_ORIGIN_AGENT && len(relay.assertionSHA256) == DigestBytes
	}
	return caller{}, false
}

// Result is a call's verified result.
type Result struct {
	CallID platform.ID
	// KID is the command key the call was signed with.
	KID string
	// RequestSHA256 is the payload's digest (the call header's request_sha256).
	RequestSHA256 []byte
	Outcome       relayv1.RoutedOutcome
	// Response is the payload of an EXECUTED result: the exact node.v1 response bytes, forwarded unchanged; ResponseSHA256 its digest.
	Response       []byte
	ResponseSHA256 []byte
	ExecutedAt     time.Time
	// Refusal is the node's refusal of a result that is not EXECUTED, rebuilt from its closed fields (rule routedRefusal): rendered
	// with the caller's own correlation ID, never the node's bytes.
	Refusal *arc.Refusal
}

// pending is a call that waits for its result on one connection.
type pending struct {
	callID        platform.ID
	method        relayv1.RoutedMethod
	commandID     *platform.ID
	requestSHA256 []byte
	// expires is the call header's expires_at: the node may act on a delivered call until then, plus its 120 s skew.
	expires time.Time
	// state is queued, delivered or abandoned, moved only by compare-and-swap under the connection's lock: the writer moves a queued
	// call to delivered just before it writes the frame, and a deadline, a caller that went away or a close moves a queued call to
	// abandoned, whose frame the writer then skips. So a call failed DID_NOT_HAPPEN is never written afterwards.
	state atomic.Int32
	once  sync.Once
	done  chan outcome
}

// The states of a pending call.
const (
	callQueued int32 = iota
	callDelivered
	callAbandoned
)

// nodeSkew is the clock skew a node applies on top of a call's expires_at (relay.proto, CallHeader).
const nodeSkew = 120 * time.Second

// outcome is how a pending call ended.
type outcome struct {
	result  Result
	refusal *arc.Refusal
}

func (p *pending) finish(value outcome) {
	p.once.Do(func() { p.done <- value })
}

// unreachable is STATE/node_unreachable for a call: UNKNOWN with SAME_COMMAND for a delivered mutation, DID_NOT_HAPPEN with AFTER_TIME
// otherwise, a delivered read included. That follows the catalogue row of STATE/node_unreachable (errors.md: "every routed read once
// delivered: AFTER_TIME with DID_NOT_HAPPEN"), which supersedes the plan's CTR5-SIG-04 wording (UNKNOWN for any unverifiable result).
// It reads the state after the call left the connection, when no writer can move it any more.
func (p *pending) unreachable(nodeID platform.ID, reason string) *arc.Refusal {
	return arc.NodeUnreachable(nodeID[:], reason, p.state.Load() == callDelivered && Mutation(p.method))
}

// Call sends a routed call to its target node's channel and waits for the verified result (Plan CTR5-SIG-01..04). Its error is always
// an *arc.Refusal:
//   - the call breaks its shape (a bug of the caller): VALIDATION/invalid_argument;
//   - this process does not hold the hub lease, or the node has no accepted connection here: STATE/node_offline (DID_NOT_HAPPEN);
//   - the node's connection is not the account's: STATE/not_found;
//   - the caller has already gone away: STATE/node_unreachable (deadline_passed, DID_NOT_HAPPEN), nothing signed;
//   - no held command key may sign at the call's instant (none valid, or the keyring not re-read for KeyStalePeriods refresh periods):
//     STATE/node_unreachable (channel_closed, DID_NOT_HAPPEN), nothing signed;
//   - the center's or the node's in-flight bound is reached, or the connection's send queue is full: RESOURCE/overloaded (CTR5-HUB-10);
//   - the connection closes (revocation, replacement, a violation, the heartbeat deadline), the deadline passes or the caller goes
//     away before a verified result: STATE/node_unreachable, UNKNOWN for a delivered mutation, DID_NOT_HAPPEN otherwise;
//   - the node answers with a frame that fails verification: STATE/node_unreachable (result_unverifiable), and the connection
//     closes 4403 (fleet.channel.violation).
func (h *Hub) Call(ctx context.Context, call Call) (Result, error) {
	now := h.clock()
	verified, ok := call.callerOf()
	if !ok || !validCall(call) {
		return Result{}, arc.InvalidArgument("call", "shape")
	}
	if _, serving := h.serving(); !serving {
		h.metrics.ObserveChannel("call", "offline")
		return Result{}, arc.NodeOffline(call.TargetNodeID[:], now)
	}
	h.mu.Lock()
	c := h.nodes[call.TargetNodeID]
	h.mu.Unlock()
	switch {
	case c == nil || c.closing.Load():
		h.metrics.ObserveChannel("call", "offline")
		return Result{}, arc.NodeOffline(call.TargetNodeID[:], now)
	case c.userID != call.AccountID:
		return Result{}, arc.NotFound("node", call.TargetNodeID[:])
	}
	if ctx.Err() != nil {
		// The caller went away before anything was signed (review A N-4).
		return Result{}, arc.NodeUnreachable(call.TargetNodeID[:], arc.UnreachableDeadline, false)
	}
	kid, key, ok := h.signingKey(now)
	if !ok {
		// No held key may sign at this instant: none is valid (an expired key never signs), or the keyring is stale, so a key retired
		// meanwhile signs at most KeyStalePeriods refresh periods after its retirement. The call is not sent; a hello closes 4500
		// no_signing_key for the same reason (E1a), so the call fails as a closed channel's undelivered call would.
		h.metrics.ObserveChannel("call", "no_key")
		h.noKey()
		return Result{}, arc.NodeUnreachable(call.TargetNodeID[:], arc.UnreachableChannelClosed, false)
	}
	h.hasKey()
	if !h.reserveCall() {
		h.metrics.ObserveChannel("call", "center_bound")
		return Result{}, arc.Unavailable()
	}
	defer h.releaseCall()
	digest := sha256.Sum256(call.Payload)
	callID := platform.NewID()
	header := callHeader(call, verified, callID, kid, h.centerURL, digest[:], now)
	if !validCallHeader(header) {
		// The call passed validCall, so this is a bug of callHeader; nothing is signed.
		return Result{}, arc.InvalidArgument("call", "shape")
	}
	headerBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(header)
	if err != nil {
		return Result{}, arc.InvalidArgument("call", "shape")
	}
	signature, err := signES256(key, callSigningInput(headerBytes))
	if err != nil {
		return Result{}, arc.Unavailable()
	}
	p := &pending{callID: callID, method: call.Method, commandID: call.CommandID, requestSHA256: digest[:], expires: timeOf(header.ExpiresAt),
		done: make(chan outcome, 1)}
	switch c.addCall(p, now) {
	case registerClosed:
		h.metrics.ObserveChannel("call", "offline")
		return Result{}, arc.NodeOffline(call.TargetNodeID[:], now)
	case registerFull:
		h.metrics.ObserveChannel("call", "node_bound")
		return Result{}, arc.Unavailable()
	}
	if err := c.sendCall(p, func(seq uint64) ([]byte, error) {
		return h.codec.Call(seq, callID, headerBytes, signature, kid, call.Payload)
	}); err != nil {
		c.dropCall(p, false)
		h.metrics.ObserveChannel("call", "queue_full")
		return Result{}, arc.Unavailable()
	}
	h.metrics.ObserveChannel("call", "sent")
	timer := time.NewTimer(call.Deadline)
	defer timer.Stop()
	select {
	case value := <-p.done:
		return h.finished(value, kid)
	case <-timer.C:
	case <-ctx.Done():
	}
	// The deadline passed, or the caller went away: the call is no longer waited for. A queued frame is abandoned (never written); a
	// delivered call's late result is still verified and bound, then dropped.
	c.dropCall(p, true)
	p.finish(outcome{refusal: p.unreachable(c.nodeID, arc.UnreachableDeadline)})
	return h.finished(<-p.done, kid)
}

// finished is the answer of an ended call, counted by its outcome.
func (h *Hub) finished(value outcome, kid string) (Result, error) {
	if value.refusal != nil {
		h.metrics.ObserveChannel("call", value.refusal.Reason)
		return Result{}, value.refusal
	}
	value.result.KID = kid
	h.metrics.ObserveChannel("call", outcomeLabel(value.result.Outcome))
	return value.result, nil
}

// outcomeLabel is a result's metric label.
func outcomeLabel(value relayv1.RoutedOutcome) string {
	switch value {
	case relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED:
		return "executed"
	case relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_BY_POLICY:
		return "refused_by_policy"
	case relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_VERIFICATION:
		return "refused_verification"
	}
	return "expired"
}

// reserveCall takes one of the center's in-flight call slots (MaxInFlightPerCenter, CTR5-HUB-10).
func (h *Hub) reserveCall() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.inFlight >= h.settings.MaxInFlightPerCenter {
		return false
	}
	h.inFlight++
	h.metrics.SetChannelInFlight(h.inFlight)
	return true
}

func (h *Hub) releaseCall() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.inFlight--
	h.metrics.SetChannelInFlight(h.inFlight)
}

// InFlight is the number of calls this process waits for.
func (h *Hub) InFlight() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.inFlight
}

// validCall is a call's shape, checked before anything is built from it: the IDs present and not zero, the method a routed task method
// with its command ID exactly for a mutation, the caller complete for its kind, the payload 1..253,952 bytes, the assertion digest 32
// bytes exactly for a node relay (a verified one), and the deadline within the call's window.
func validCall(call Call) bool {
	zero := platform.ID{}
	if call.AccountID == zero || call.TargetNodeID == zero || call.Method < MethodSubmitNodeTask || call.Method > maxCallMethod ||
		(call.CommandID != nil) != Mutation(call.Method) || (call.CommandID != nil && *call.CommandID == zero) || len(call.Payload) < 1 ||
		len(call.Payload) > MaxCallPayload || call.Deadline <= 0 || call.Deadline > MaxCallDeadline {
		return false
	}
	_, ok := call.callerOf()
	return ok
}

// callHeader is a call's CallHeader (CTR5-SIG-01): issued now, its deadline now + Deadline, its expiry now + min(Deadline + 30 s,
// 300 s), the caller as verified, center_url_sha256 the center's canonical public base URL.
func callHeader(call Call, verified caller, callID platform.ID, kid, centerURL string, requestSHA256 []byte, now time.Time) *relayv1.CallHeader {
	audience := sha256.Sum256([]byte(centerURL))
	expires := min(call.Deadline+callExpiryMargin, MaxCallDeadline)
	signed := &nodev1.CenterCaller{Kind: verified.kind.Enum(), AccountId: idValue(call.AccountID)}
	switch verified.kind {
	case nodev1.CenterCallerKind_CENTER_CALLER_KIND_ACCOUNT_SESSION:
		signed.UserId, signed.SessionId = idValue(verified.userID), idValue(verified.sessionID)
	case nodev1.CenterCallerKind_CENTER_CALLER_KIND_NODE_RELAY:
		signed.RelayingNodeId, signed.LocalOrigin, signed.LocalSessionId = idValue(verified.relayingNodeID), verified.localOrigin.Enum(),
			idValue(verified.localSessionID)
	}
	header := &relayv1.CallHeader{CallId: idValue(callID), Kid: proto.String(kid), CenterUrlSha256: audience[:], AccountId: idValue(call.AccountID),
		TargetNodeId: idValue(call.TargetNodeID), Caller: signed, Method: call.Method.Enum(), RequestSha256: requestSHA256,
		RequestSize: proto.Uint32(uint32(len(call.Payload))), IssuedAt: instant(now), ExpiresAt: instant(now.Add(expires)),
		Deadline: instant(now.Add(call.Deadline))}
	if call.CommandID != nil {
		header.CommandId = idValue(*call.CommandID)
	}
	if verified.assertionSHA256 != nil {
		header.RelayAssertionSha256 = append([]byte(nil), verified.assertionSHA256...)
	}
	return header
}

// The answers of addCall.
const (
	registered = iota
	registerClosed
	registerFull
)

// lateCall is a delivered call no longer waited for: its late result is still verified and bound, then dropped, and it counts against the
// node's in-flight bound until that result or until it can no longer run at the node (its expires_at plus the node's skew).
type lateCall struct {
	call  *pending
	until time.Time
}

// addCall adds a pending call to the connection: refused when the connection is closing, or when the calls waited for and the delivered
// calls that may still run at the node (review A N-3) are MaxInFlightCalls already.
func (c *conn) addCall(p *pending, now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.callsClosed {
		return registerClosed
	}
	c.pruneLateLocked(now)
	if len(c.calls)+len(c.late) >= c.hub.settings.MaxInFlightCalls {
		return registerFull
	}
	c.calls[p.callID] = p
	return registered
}

// pruneLateLocked forgets the late calls that can no longer run at the node.
func (c *conn) pruneLateLocked(now time.Time) {
	kept := c.late[:0]
	for _, late := range c.late {
		if now.Before(late.until) {
			kept = append(kept, late)
		}
	}
	c.late = kept
}

// deliver moves a queued call to delivered, under the connection's lock, just before the writer writes its frame: only a call still
// waited for on an open connection. A false answer is a frame the writer skips (the call was abandoned or the connection is closing).
func (c *conn) deliver(p *pending) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.callsClosed && !c.closing.Load() && c.calls[p.callID] == p && p.state.CompareAndSwap(callQueued, callDelivered)
}

// dropCall removes a pending call. A queued call is abandoned (its frame is never written); a delivered one is kept as late when asked,
// so its late result is bound and dropped, and it counts against the in-flight bound meanwhile.
func (c *conn) dropCall(p *pending, late bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.calls[p.callID] == p {
		delete(c.calls, p.callID)
	}
	if p.state.CompareAndSwap(callQueued, callAbandoned) || !late || p.state.Load() != callDelivered {
		return
	}
	if len(c.late) >= lateResults {
		c.late = c.late[1:]
	}
	c.late = append(c.late, lateCall{call: p, until: p.expires.Add(nodeSkew)})
}

// take removes the call a result names: the pending one, or a late one.
func (c *conn) take(callID platform.ID) (p *pending, late *pending) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if p = c.calls[callID]; p != nil {
		delete(c.calls, callID)
		return p, nil
	}
	for i, entry := range c.late {
		if entry.call.callID == callID {
			c.late = append(c.late[:i], c.late[i+1:]...)
			return nil, entry.call
		}
	}
	return nil, nil
}

// failCalls ends every pending call of a closing connection with STATE/node_unreachable (channel_closed), and takes no call after it
// (CTR5-HUB-04, -08: a revoked, replaced or dead connection's calls). A queued call is abandoned first, so it is DID_NOT_HAPPEN and its
// frame is never written; a delivered mutation is UNKNOWN. The connection's relay nonces are void with it.
func (c *conn) failCalls() {
	c.mu.Lock()
	c.callsClosed = true
	calls := make([]*pending, 0, len(c.calls))
	for id, p := range c.calls {
		p.state.CompareAndSwap(callQueued, callAbandoned)
		calls = append(calls, p)
		delete(c.calls, id)
	}
	c.nonces = nil
	c.mu.Unlock()
	for _, p := range calls {
		p.finish(outcome{refusal: p.unreachable(c.nodeID, arc.UnreachableChannelClosed)})
	}
}

// result verifies a node's ChannelResult (CTR5-SIG-03, -04) and ends its call. A frame that fails verification is a protocol violation:
// the call it names fails STATE/node_unreachable (result_unverifiable), the connection closes 4403 and fleet.channel.violation is
// audited; false ends the reader then.
func (c *conn) result(frame resultFrame) bool {
	header, failure := verifyResult(c.publicKey, frame)
	if failure != "" {
		c.unverifiable(frame, failure)
		return false
	}
	p, late := c.take(frame.CallID)
	switch {
	case late != nil:
		// A result after its call's deadline: verified and bound like any other (a mismatch is still a violation), then dropped.
		if failure := bindResult(late, header, frame.Payload, c.nodeID); failure != "" {
			c.violation(failure)
			return false
		}
		c.hub.metrics.ObserveChannel("call", "late")
		return true
	case p == nil:
		c.unverifiable(frame, "result_other_call")
		return false
	}
	if failure := bindResult(p, header, frame.Payload, c.nodeID); failure != "" {
		p.finish(outcome{refusal: p.unreachable(c.nodeID, arc.UnreachableUnverifiable)})
		c.violation(failure)
		return false
	}
	result := Result{CallID: p.callID, RequestSHA256: p.requestSHA256, Outcome: header.GetOutcome(), ExecutedAt: timeOf(header.ExecutedAt)}
	if result.Outcome == relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED {
		result.Response, result.ResponseSHA256 = frame.Payload, header.ResponseSha256
	} else {
		result.Refusal = rebuildRefusal(header.Error)
	}
	p.finish(outcome{result: result})
	return true
}

// unverifiable ends the call a failed frame names (when it is one of this connection's) and closes the connection as a violation.
func (c *conn) unverifiable(frame resultFrame, reason string) {
	if frame.CallOK {
		if p, _ := c.take(frame.CallID); p != nil {
			p.finish(outcome{refusal: p.unreachable(c.nodeID, arc.UnreachableUnverifiable)})
		}
	}
	c.violation(reason)
}

// verifyResult checks a ChannelResult up to its header (relay.proto ResultHeader): first its shape (call ID, a SignedHeader without kid,
// "ES256", a 64-byte signature, 1..2,048 header bytes, a payload within its bound), before any signing input; then the signature by the
// connection's installation key over the routed-result domain string and the header bytes as received (low-S); then the decoded
// header's shape (routedRefusal included) and its call ID. It returns the closed violation reason of a failure.
func verifyResult(publicKey []byte, frame resultFrame) (*relayv1.ResultHeader, string) {
	if !frame.Shaped || !frame.CallOK || frame.HasKid || frame.Algorithm != "ES256" || len(frame.Signature) != SignatureBytes || len(frame.Header) < 1 ||
		len(frame.Header) > MaxSignedHeader || len(frame.Payload) > MaxResultPayload {
		return nil, "result_malformed"
	}
	if !verifyES256(publicKey, resultSigningInput(frame.Header), frame.Signature) {
		return nil, "result_signature"
	}
	var header relayv1.ResultHeader
	if err := proto.Unmarshal(frame.Header, &header); err != nil || !validResultHeader(&header) {
		return nil, "result_malformed"
	}
	if id, ok := idOf(header.CallId); !ok || id != frame.CallID {
		return nil, "result_other_call"
	}
	return &header, ""
}

// bindResult checks a verified header against its call: the connection's node, the echoed method, command ID and request digest
// (absent from a REFUSED_VERIFICATION result, which echoes nothing it could not verify), and for EXECUTED the response's size and
// digest; any other outcome carries no payload.
func bindResult(p *pending, header *relayv1.ResultHeader, payload []byte, nodeID platform.ID) string {
	if id, _ := idOf(header.NodeId); id != nodeID {
		return "result_mismatch"
	}
	if header.GetOutcome() != relayv1.RoutedOutcome_ROUTED_OUTCOME_REFUSED_VERIFICATION {
		if header.GetMethod() != p.method || !equalBytes(header.RequestSha256, p.requestSHA256) || !sameOptionalID(header.CommandId, p.commandID) {
			return "result_mismatch"
		}
	}
	if header.GetOutcome() == relayv1.RoutedOutcome_ROUTED_OUTCOME_EXECUTED {
		digest := sha256.Sum256(payload)
		if int(header.GetResponseSize()) != len(payload) || !equalBytes(header.ResponseSha256, digest[:]) {
			return "result_mismatch"
		}
	} else if len(payload) != 0 {
		return "result_mismatch"
	}
	return ""
}

func sameOptionalID(echoed *foundationv1.Id, command *platform.ID) bool {
	if command == nil {
		return echoed == nil
	}
	id, ok := idOf(echoed)
	return ok && id == *command
}

func equalBytes(a, b []byte) bool {
	return len(a) == len(b) && string(a) == string(b)
}

// rebuildRefusal is the caller-facing refusal of a node's routed refusal (rule routedRefusal, Plan PN-6): only its closed fields are
// taken (category, code, retry mode, retry_at and the approval's reconciliation operation, effect, and the state's state, reason and
// approval resource), so the node's bytes, its message key and its correlation ID never reach the caller; the center renders it with
// the caller's own correlation ID. The header passed validResultHeader, so every field is in its closed form.
func rebuildRefusal(value *foundationv1.ArcError) *arc.Refusal {
	refusal := &arc.Refusal{Category: value.GetCategory(), Code: value.GetCode(), Retry: value.GetRetry().GetMode(), Effect: value.GetEffect()}
	if at := value.GetRetry().GetRetryAt(); at != nil {
		refusal.RetryAt = timeOf(at)
	}
	refusal.Reconcile = value.GetRetry().GetReconciliationOperation()
	if state := value.GetDetails().GetState(); state != nil {
		refusal.State, refusal.Reason = state.GetState(), state.GetReason()
		if resource := state.GetResource(); resource != nil {
			refusal.Resource = &arc.Resource{Kind: resource.GetKind(), ID: append([]byte(nil), resource.GetId().GetValue()...)}
		}
	}
	return refusal
}

// timeOf is a valid contract instant as a time.
func timeOf(value *foundationv1.Instant) time.Time {
	return time.Unix(value.GetUnixSeconds(), int64(value.GetNanos())).UTC()
}
