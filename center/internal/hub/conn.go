// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/access"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/fleet"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// conn is one upgraded connection, from the challenge to its close.
type conn struct {
	hub *Hub
	ws  *websocket.Conn

	// The credential and the node row the upgrade admitted; the hello must name them.
	sessionID, userID, deviceID, installationID platform.ID
	nodeID, enrollmentID                        platform.ID
	publicKey                                   []byte
	connectionID                                platform.ID
	correlationID                               *platform.ID
	fence                                       int64

	ctx    context.Context
	cancel context.CancelFunc

	mu            sync.Mutex
	nonce         []byte    // the one-use hello nonce; nil once spent or void
	helloDeadline time.Time // the nonce is void from this instant on
	proved        bool      // the hello's proof held in time: the hello deadline no longer applies
	accepted      bool
	recorded      bool     // the accept's presence write succeeded: the close records the node offline
	tokenDigest   [32]byte // the SHA-256 of the access token the connection is bound to
	refreshes     int      // the TokenRefresh frames the connection sent
	lastRefresh   time.Time
	accessExpires time.Time
	lastInbound   time.Time
	lastPresence  time.Time
	sentSeq       uint64

	// calls are the calls waiting for their result (at most MaxInFlightCalls); callsClosed is set once the connection closes, after
	// which it takes no call. late are the delivered calls whose deadline passed, nonces the relay nonces not yet spent.
	calls       map[platform.ID]*pending
	callsClosed bool
	late        []lateCall
	nonces      []relayNonce

	queue chan outbound
	// stall holds the writer after it took a frame until it is closed (tests only: a stalled writer; nil in a running center).
	stall       chan struct{}
	queuedBytes atomic.Int64
	closing     atomic.Bool
	lapsing     atomic.Bool // the lapse close is claimed: it is audited once
	closeOnce   sync.Once
	closeCode   uint32
	closeReason string
	finished    chan struct{}

	windowStart time.Time
	windowCount int
}

// errQueueFull is a frame the send queue could not take.
var errQueueFull = errors.New("the connection's send queue is full")

// outbound is one queued frame; call is the call it carries, marked delivered when the writer starts writing it.
type outbound struct {
	data []byte
	call *pending
}

// run serves the connection until it closes: the challenge, the reader, the writer and the supervisor.
func (c *conn) run() {
	defer c.hub.forget(c)
	defer close(c.finished)
	nonce := make([]byte, NonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		c.closeWith(CloseShuttingDown, "internal")
		c.finish()
		return
	}
	now := c.hub.clock()
	deadline := now.Add(c.hub.settings.HelloDeadline)
	c.mu.Lock()
	c.nonce, c.helloDeadline, c.lastInbound = nonce, deadline, now
	c.mu.Unlock()
	go c.writer()
	if err := c.send(func(seq uint64) ([]byte, error) { return c.hub.codec.Challenge(seq, nonce, c.connectionID, deadline) }); err != nil {
		c.closeWith(CloseShuttingDown, "internal")
	}
	go c.supervise(deadline)
	c.read()
	c.finish()
}

// read reads frames until the connection ends. A message is read through its own bound (the library's read limit is off), so a frame
// over the bound closes 4413 instead of the library's 1009.
func (c *conn) read() {
	limit := int64(c.hub.settings.MaxFrameBytes)
	for {
		kind, reader, err := c.ws.Reader(c.ctx)
		if err != nil {
			c.ended(err)
			return
		}
		data, err := io.ReadAll(io.LimitReader(reader, limit+1))
		if err != nil {
			c.ended(err)
			return
		}
		if int64(len(data)) > limit {
			c.hub.metrics.ObserveChannel("violation", "too_large")
			c.closeWith(CloseTooLarge, "frame_too_large")
			return
		}
		if kind != websocket.MessageBinary {
			c.violation("text_frame")
			return
		}
		now := c.hub.clock()
		if !c.counted(now) {
			c.hub.metrics.ObserveChannel("violation", "rate")
			c.closeWith(CloseRateLimited, "frame_rate")
			return
		}
		c.mu.Lock()
		c.lastInbound = now
		c.mu.Unlock()
		frame, err := c.hub.codec.Decode(data)
		if err != nil {
			c.violation("unreadable_frame")
			return
		}
		if !c.handle(frame, now) {
			return
		}
	}
}

// counted counts one inbound frame in the current one-second window and reports whether the node is within the frame rate.
func (c *conn) counted(now time.Time) bool {
	if now.Sub(c.windowStart) >= time.Second {
		c.windowStart, c.windowCount = now, 0
	}
	c.windowCount++
	return c.windowCount <= c.hub.settings.InboundFramesPerSecond
}

// ended is the end of a read: the node's close, or a transport that went away.
func (c *conn) ended(err error) {
	if c.closing.Load() {
		return
	}
	code := uint32(websocket.CloseStatus(err))
	reason := "transport"
	if code != ^uint32(0) {
		reason = "node_closed"
	} else {
		code = 1006
	}
	c.closeOnce.Do(func() {
		c.closing.Store(true)
		c.closeCode, c.closeReason = code, reason
		c.failCalls()
		go func() {
			_ = c.ws.CloseNow()
		}()
	})
}

// handle acts on one frame; false ends the reader.
func (c *conn) handle(frame inbound, now time.Time) bool {
	c.mu.Lock()
	accepted := c.accepted
	c.mu.Unlock()
	switch {
	case frame.kind == inboundHello && !accepted:
		return c.hello(frame.hello, now)
	case !accepted:
		// Nothing but the hello comes first.
		c.violation("before_hello")
		return false
	case frame.kind == inboundHeartbeat:
		c.heartbeat(now)
		return true
	case frame.kind == inboundTokenRefresh:
		return c.tokenRefresh(frame.token, now)
	case frame.kind == inboundClose:
		c.closeWith(1000, "node_closed")
		return false
	case frame.kind == inboundNonceRequest:
		return c.relayNonce(frame, now)
	case frame.kind == inboundResult:
		return c.result(frame.result)
	}
	c.violation("unexpected_frame")
	return false
}

// hello checks the node's proof (PB-4, D0-B2) and, when it holds, makes this connection the node's. The signature is verified
// against the key registered for the bearer credential's installation, before and apart from the check that the hello names the
// credential's node and installation; the nonce is spent by the first hello whatever its outcome, and a hello at or after the hello
// deadline is refused by the nonce itself (4408), whatever the supervisor's tick. A proved hello then re-reads the credential (a
// revocation committed between the admission and the connection's tracking reaches no revocation hook), finds the signing kids
// (never an empty list: 4500 no_signing_key), and records the node online under the connection's fence before the connection becomes
// the node's: a fence that is no longer live closes 4500 lease_lost, a node row that is no longer live 4401 revoked, a store that does
// not answer 4500 unavailable, each without ChannelAccepted and without displacing the node's older connection.
func (c *conn) hello(claimed hello, now time.Time) bool {
	c.mu.Lock()
	nonce, deadline := c.nonce, c.helloDeadline
	c.nonce = nil
	c.mu.Unlock()
	if nonce == nil {
		c.violation("hello_without_nonce")
		return false
	}
	if !now.Before(deadline) {
		c.hub.metrics.ObserveChannel("hello", "deadline")
		c.closeWith(CloseDeadline, "hello_deadline")
		return false
	}
	if claimed.Malformed || len(nonce) != NonceBytes {
		c.hub.metrics.ObserveChannel("hello", "malformed")
		c.violation("hello_malformed")
		return false
	}
	message := HelloMessage(nonce, c.connectionID, c.hub.centerURL, claimed.NodeID, claimed.InstallationID)
	if !fleet.VerifyNodeKeyProof(c.publicKey, message, claimed.Signature) {
		c.hub.metrics.ObserveChannel("hello", "signature")
		c.violation("hello_signature")
		return false
	}
	if claimed.NodeID != c.nodeID || claimed.InstallationID != c.installationID {
		c.hub.metrics.ObserveChannel("hello", "mismatch")
		c.violation("hello_mismatch")
		return false
	}
	c.mu.Lock()
	c.proved = true
	c.mu.Unlock()
	ctx, cancel := context.WithTimeout(c.ctx, presenceTimeout)
	defer cancel()
	// The connection is tracked (the revocation hooks see it) since before this read, so no revocation falls between them.
	c.recheckSession(ctx)
	if c.closing.Load() {
		return false
	}
	kids := c.hub.signingKids(ctx, now)
	if len(kids) == 0 {
		c.hub.metrics.ObserveChannel("hello", "no_signing_key")
		c.hub.logger.Warn("a node's channel was closed: no command key the center holds is valid")
		c.closeWith(CloseShuttingDown, "no_signing_key")
		return false
	}
	older, err := c.register(ctx, now)
	switch {
	case errors.Is(err, ErrFenced):
		c.hub.metrics.ObserveChannel("hello", "fenced")
		c.closeWith(CloseShuttingDown, "lease_lost")
		return false
	case errors.Is(err, ErrNodeGone):
		c.hub.metrics.ObserveChannel("hello", "node_gone")
		c.closeWith(CloseCredential, "revoked")
		return false
	case errors.Is(err, errNotAccepted):
		c.closeWith(CloseShuttingDown, "shutting_down")
		return false
	case err != nil:
		c.hub.metrics.ObserveChannel("hello", "unrecorded")
		c.hub.logger.Warn("a node's channel could not be recorded", "error", err.Error())
		c.closeWith(CloseShuttingDown, "unavailable")
		return false
	}
	payload := map[string]any{"nodeId": c.nodeID.String(), "connectionId": c.connectionID.String(), "replaced": older != nil}
	if older != nil {
		payload["replacedConnectionId"] = older.connectionID.String()
	}
	c.audit(ctx, "fleet.channel.accepted", "accepted", payload)
	c.hub.metrics.ObserveChannel("hello", "accepted")
	limits := Limits{MaxFrameBytes: c.hub.settings.MaxFrameBytes, MaxInFlightCalls: c.hub.settings.MaxInFlightCalls, Heartbeat: c.hub.settings.Heartbeat,
		HeartbeatDeadline: c.hub.settings.HeartbeatDeadline, MaxRelayNonces: c.hub.settings.MaxRelayNonces}
	if err := c.send(func(seq uint64) ([]byte, error) { return c.hub.codec.Accepted(seq, c.connectionID, limits, kids) }); err != nil {
		c.closeWith(CloseShuttingDown, "internal")
		return false
	}
	return true
}

// errNotAccepted is a proved connection the hub did not take: it is stopping, or the connection is closing.
var errNotAccepted = errors.New("the hub did not accept the connection")

// register records the node online under the connection's fence and then makes the connection the node's (an older one closes 4409),
// as one step per node, so the row names the connection the hub holds. A refused write registers nothing and displaces nothing.
func (c *conn) register(ctx context.Context, now time.Time) (*conn, error) {
	unlock, err := c.hub.lockNode(ctx, c.nodeID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := c.hub.markOnline(ctx, c.enrollmentID, c.connectionID, c.fence, now); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.recorded, c.accepted, c.lastPresence = true, true, now
	c.mu.Unlock()
	older, ok := c.hub.accept(c)
	if !ok {
		return nil, errNotAccepted
	}
	return older, nil
}

// heartbeat records the node's heartbeat in its presence, at most once per presence interval.
func (c *conn) heartbeat(now time.Time) {
	c.mu.Lock()
	due := now.Sub(c.lastPresence) >= c.hub.settings.PresenceInterval
	if due {
		c.lastPresence = now
	}
	c.mu.Unlock()
	if !due {
		return
	}
	ctx, cancel := context.WithTimeout(c.ctx, presenceTimeout)
	defer cancel()
	if err := c.hub.markHeartbeat(ctx, c.enrollmentID, c.connectionID, c.fence, now); err != nil && !errors.Is(err, ErrFenced) {
		c.hub.logger.Warn("a node's heartbeat could not be recorded", "error", err.Error())
	}
}

// tokenRefresh rebinds the connection to a new access token (CTR5-HUB-07): a valid token of the same session and installation; then
// the credential and the gate are re-checked. A refresh costs store work, so it has its own bound before any of it (review A B-1): the
// first is free, and each later one comes at least TokenRefreshInterval after the last one admitted, else the connection closes 4429
// token_refresh_rate; the token the connection is already bound to is answered without the store (and without the re-checks, which
// the periodic SessionRecheck and LapseRecheck still make).
func (c *conn) tokenRefresh(token string, now time.Time) bool {
	digest := sha256.Sum256([]byte(token))
	c.mu.Lock()
	limited := c.refreshes > 0 && now.Sub(c.lastRefresh) < c.hub.settings.TokenRefreshInterval
	c.refreshes++
	if !limited {
		c.lastRefresh = now
	}
	unchanged, boundExpires := digest == c.tokenDigest, c.accessExpires
	c.mu.Unlock()
	if limited {
		c.hub.metrics.ObserveChannel("token", "rate")
		c.closeWith(CloseRateLimited, "token_refresh_rate")
		return false
	}
	if unchanged {
		// The token the connection is bound to: nothing to rebind, and its expiry is known here.
		if !now.Before(boundExpires) {
			c.closeWith(CloseCredential, "token_refused")
			return false
		}
		c.hub.metrics.ObserveChannel("token", "unchanged")
		return true
	}
	ctx, cancel := context.WithTimeout(c.ctx, presenceTimeout)
	defer cancel()
	caller, expires, err := c.hub.verifier.VerifyNative(ctx, token)
	switch {
	case errors.Is(err, ingress.ErrTokenExpired), errors.Is(err, ingress.ErrCredentialRevoked):
		c.closeWith(CloseCredential, "token_refused")
		return false
	case err != nil:
		// The store did not answer: the connection keeps its current token until the next refresh or its expiry.
		c.hub.logger.Warn("a channel's token refresh could not be checked", "error", err.Error())
		return true
	case caller == nil && c.barred(ctx):
		// The verifier admits no account that may no longer sign in; its standing tells that apart from an unknown token (4403, as
		// the periodic re-check answers it).
		c.closeWith(CloseRefused, "account_state")
		return false
	case caller == nil || caller.Scope != "node":
		c.closeWith(CloseCredential, "token_refused")
		return false
	case caller.InstallationID != c.installationID.String():
		// Another installation's token (relay.proto TokenRefresh, review A N-5): the connection's installation key never changes.
		c.closeWith(CloseRefused, "installation_mismatch")
		return false
	case caller.SessionID != c.sessionID.String():
		c.closeWith(CloseCredential, "token_mismatch")
		return false
	}
	// The new credential names the connection's node too: its installation's live node row is this connection's (C2 review).
	node, err := c.hub.liveNode(ctx, *caller)
	switch {
	case err != nil:
		c.hub.logger.Warn("a channel's token refresh could not be checked", "error", err.Error())
		return true
	case node == nil || node.nodeID != c.nodeID || node.enrollmentID != c.enrollmentID:
		c.closeWith(CloseRefused, "node_mismatch")
		return false
	}
	c.mu.Lock()
	c.accessExpires, c.tokenDigest = expires, digest
	c.mu.Unlock()
	c.hub.metrics.ObserveChannel("token", "rebound")
	c.recheckSession(ctx)
	c.recheckLapse(ctx)
	return !c.closing.Load()
}

// barred reports whether the connection's session belongs to an account that may no longer sign in.
func (c *conn) barred(ctx context.Context) bool {
	standing, _, err := c.hub.verifier.Recheck(ctx, c.sessionID)
	return err == nil && standing == session.Barred
}

// supervise sends the heartbeats and enforces the deadlines and the periodic checks.
func (c *conn) supervise(helloDeadline time.Time) {
	settings := c.hub.settings
	tick := min(settings.Heartbeat/5, time.Second)
	if tick < 5*time.Millisecond {
		tick = 5 * time.Millisecond
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	var lastHeartbeat, lastRecheck, lastLapse time.Time
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
		}
		now := c.hub.clock()
		c.mu.Lock()
		accepted, proved, lastInbound, expires := c.accepted, c.proved, c.lastInbound, c.accessExpires
		c.mu.Unlock()
		if !accepted {
			if !proved && !now.Before(helloDeadline) {
				// The nonce is void at the hello deadline.
				c.mu.Lock()
				c.nonce = nil
				c.mu.Unlock()
				c.hub.metrics.ObserveChannel("hello", "deadline")
				c.closeWith(CloseDeadline, "hello_deadline")
				return
			}
			continue
		}
		if lastRecheck.IsZero() {
			lastHeartbeat, lastRecheck, lastLapse = now, now, now
		}
		switch {
		case now.Sub(lastInbound) >= settings.HeartbeatDeadline:
			c.hub.metrics.ObserveChannel("heartbeat", "missed")
			c.closeWith(CloseDeadline, "heartbeat_deadline")
			return
		case !now.Before(expires.Add(settings.TokenGrace)):
			c.closeWith(CloseCredential, "token_expired")
			return
		}
		if now.Sub(lastHeartbeat) >= settings.Heartbeat {
			lastHeartbeat = now
			// A full queue skips a heartbeat; the node's own frames keep the deadline, and a node that reads nothing is closed by the
			// write timeout.
			_ = c.send(func(seq uint64) ([]byte, error) { return c.hub.codec.Heartbeat(seq, now) })
		}
		if now.Sub(lastRecheck) >= settings.SessionRecheck {
			lastRecheck = now
			c.recheckSession(c.ctx)
		}
		if now.Sub(lastLapse) >= settings.LapseRecheck {
			lastLapse = now
			c.recheckLapse(c.ctx)
		}
	}
}

// recheckSession re-reads the connection's credential (CTR5-HUB-07, -08): revoked closes 4401, an account that may no longer sign in
// 4403; a store that does not answer keeps the connection until the next check.
func (c *conn) recheckSession(ctx context.Context) {
	if c.closing.Load() {
		return
	}
	check, cancel := context.WithTimeout(ctx, presenceTimeout)
	defer cancel()
	standing, _, err := c.hub.verifier.Recheck(check, c.sessionID)
	switch {
	case err != nil:
		c.hub.logger.Warn("a channel's credential could not be re-checked", "error", err.Error())
	case standing == session.Revoked:
		c.closeWith(CloseCredential, "revoked")
	case standing == session.Barred:
		c.closeWith(CloseRefused, "account_state")
	}
}

// recheckLapse asks the gate for center.nodes (CTR5-HUB-09, Q23): unavailable closes 4403 with access.gated audited once for the close;
// a gate that cannot decide keeps the connection until the next check.
func (c *conn) recheckLapse(ctx context.Context) {
	gate := c.hub.currentGate()
	if c.closing.Load() || gate == nil {
		return
	}
	decision := gate.Availability(feature.WithAccount(ctx, c.userID.String()), feature.CenterNodes)
	switch {
	case decision.Available:
		return
	case decision.Err != nil:
		c.hub.metrics.ObserveChannel("lapse", "undecided")
		return
	case !c.lapsing.CompareAndSwap(false, true):
		// The supervisor and a refresh can both find the lapse: the first claims the close, so it is audited once (review A N-7).
		return
	}
	c.hub.metrics.ObserveChannel("lapse", "closed")
	audit, cancel := context.WithTimeout(context.WithoutCancel(ctx), presenceTimeout)
	defer cancel()
	c.auditAs(audit, access.AuditGated, string(decision.Reason), "operation", routes.NodeChannelID, map[string]any{"operation": routes.NodeChannelID,
		"feature": string(feature.CenterNodes), "reason": string(decision.Reason)})
	c.closeWith(CloseRefused, "feature_not_entitled")
}

// violation closes the connection 4403 for a frame or proof the hub does not accept, audited fleet.channel.violation.
func (c *conn) violation(reason string) {
	if c.closing.Load() {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.ctx), presenceTimeout)
	defer cancel()
	c.audit(ctx, "fleet.channel.violation", reason, map[string]any{"connectionId": c.connectionID.String(), "reason": reason})
	c.hub.metrics.ObserveChannel("violation", reason)
	c.closeWith(CloseRefused, reason)
}

// send encodes a frame with the next sequence number and queues it; it never blocks.
func (c *conn) send(encode func(seq uint64) ([]byte, error)) error {
	if c.closing.Load() {
		return errQueueFull
	}
	c.mu.Lock()
	c.sentSeq++
	data, err := encode(c.sentSeq)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	return c.enqueue(outbound{data: data})
}

// sendCall queues a call's frame; the call is marked delivered when the writer starts writing it.
func (c *conn) sendCall(p *pending, encode func(seq uint64) ([]byte, error)) error {
	if c.closing.Load() {
		return errQueueFull
	}
	c.mu.Lock()
	c.sentSeq++
	data, err := encode(c.sentSeq)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	return c.enqueue(outbound{data: data, call: p})
}

// enqueue puts a frame in the bounded send queue (CTR5-HUB-10): at most SendQueueFrames frames and SendQueueBytes bytes.
func (c *conn) enqueue(item outbound) error {
	if c.queuedBytes.Add(int64(len(item.data))) > int64(c.hub.settings.SendQueueBytes) {
		c.queuedBytes.Add(-int64(len(item.data)))
		return errQueueFull
	}
	select {
	case c.queue <- item:
		return nil
	default:
		c.queuedBytes.Add(-int64(len(item.data)))
		return errQueueFull
	}
}

// writer writes the queued frames, each within the write timeout: a node that stops reading is closed when one passes.
func (c *conn) writer() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case item := <-c.queue:
			c.queuedBytes.Add(-int64(len(item.data)))
			c.mu.Lock()
			stall := c.stall
			c.mu.Unlock()
			if stall != nil {
				select {
				case <-stall:
				case <-c.ctx.Done():
					return
				}
			}
			if item.call != nil && !c.deliver(item.call) {
				// The call was abandoned (its deadline passed, its caller went away, the connection is closing): it was answered
				// DID_NOT_HAPPEN, so its frame is never written. From a successful deliver on, its loss is UNKNOWN for a mutation.
				continue
			}
			write, cancel := context.WithTimeout(c.ctx, c.hub.settings.WriteTimeout)
			err := c.ws.Write(write, websocket.MessageBinary, item.data)
			cancel()
			if err != nil {
				if !c.closing.Load() {
					c.hub.metrics.ObserveChannel("violation", "write_timeout")
					c.closeWith(CloseDeadline, "write_timeout")
				}
				return
			}
		}
	}
}

// closeWith closes the connection once: the RelayClose frame and the WebSocket close with the code (a 4500 carries the reconnect hint),
// then the reader and writer end and finish records the close.
func (c *conn) closeWith(code uint32, reason string) {
	c.closeOnce.Do(func() {
		c.closing.Store(true)
		c.closeCode, c.closeReason = code, reason
		// A closing connection is no longer the node's: a newer one may take its place at once. Its calls fail now.
		c.hub.release(c)
		c.failCalls()
		go func() {
			hint := time.Duration(0)
			if code == CloseShuttingDown {
				hint = c.hub.reconnectHint()
			}
			c.mu.Lock()
			c.sentSeq++
			frame, err := c.hub.codec.Close(c.sentSeq, code, reason, hint)
			c.mu.Unlock()
			write, cancel := context.WithTimeout(context.WithoutCancel(c.ctx), 2*time.Second)
			if err == nil {
				_ = c.ws.Write(write, websocket.MessageBinary, frame)
			}
			cancel()
			if code >= 1000 && code < 5000 && code != 1006 {
				// The close handshake waits for the node's answer at most a second: a node that stopped reading never answers.
				handshake := make(chan struct{})
				go func() {
					_ = c.ws.Close(websocket.StatusCode(code), reason)
					close(handshake)
				}()
				select {
				case <-handshake:
				case <-time.After(time.Second):
					// The reader's context ends the connection (the library closes it on a cancelled read), which ends the handshake.
					c.cancel()
				}
			}
			c.cancel()
			_ = c.ws.CloseNow()
		}()
	})
}

// finish runs once the reader ended: it waits for the close to be sent, ends the writer and the supervisor, records presence and
// audits the close.
func (c *conn) finish() {
	c.closeOnce.Do(func() {
		c.closing.Store(true)
		c.closeCode, c.closeReason = 1006, "transport"
		_ = c.ws.CloseNow()
	})
	c.failCalls()
	c.cancel()
	now := c.hub.clock()
	ctx, cancel := context.WithTimeout(context.Background(), presenceTimeout)
	defer cancel()
	c.mu.Lock()
	accepted, recorded := c.accepted, c.recorded
	c.nonce = nil
	c.mu.Unlock()
	if recorded {
		if err := c.hub.markOffline(ctx, c.enrollmentID, c.connectionID, c.fence, now); err != nil && !errors.Is(err, ErrFenced) {
			c.hub.logger.Warn("the close of a node's channel could not be recorded", "error", err.Error())
		}
	}
	if accepted {
		c.audit(ctx, "fleet.channel.closed", c.closeReason, map[string]any{"connectionId": c.connectionID.String(), "code": c.closeCode,
			"reason": c.closeReason})
	}
	c.hub.metrics.ObserveChannel("closed", closeLabel(c.closeCode))
}

// closeLabel is the metric label of a close code: one of the channel's codes, normal, or abnormal.
func closeLabel(code uint32) string {
	switch code {
	case CloseCredential, CloseRefused, CloseDeadline, CloseReplaced, CloseTooLarge, CloseRateLimited, CloseShuttingDown, CloseKillSwitch:
		return codeText(code)
	case 1000, 1001:
		return "normal"
	}
	return "abnormal"
}

func codeText(code uint32) string {
	digits := []byte{byte('0' + code/1000%10), byte('0' + code/100%10), byte('0' + code/10%10), byte('0' + code%10)}
	return string(digits)
}

// audit appends a channel event as the node (node:<installation>), aimed at its enrollment.
func (c *conn) audit(ctx context.Context, eventType, reason string, payload map[string]any) {
	c.auditAs(ctx, eventType, reason, "node", c.enrollmentID.String(), payload)
}

func (c *conn) auditAs(ctx context.Context, eventType, reason, targetKind, targetID string, payload map[string]any) {
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	err = c.hub.db.InTx(ctx, "audit a node channel event", store.TxOptions{Timeout: presenceTimeout, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		_, err := platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: c.hub.clock(), ActorRef: "node:" + c.installationID.String(),
			EventType: eventType, Reason: reason, CorrelationID: c.correlationID, TargetKind: targetKind, TargetID: targetID, Payload: data})
		return err
	})
	if err != nil {
		c.hub.logger.Warn("a node channel event could not be audited", "event", eventType, "error", err.Error())
	}
}
