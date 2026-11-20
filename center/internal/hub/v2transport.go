// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/sha256"
	"slices"
	"time"

	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
	"github.com/jackc/pgx/v5"
)

type pendingV2Control struct {
	id        platform.ID
	authority management.V2ControlAuthority
	binding   [sha256.Size]byte
	kid       string
	deadline  time.Time
	ctx       context.Context
	done      chan v2ControlOutcome
	claimed   bool // guarded by conn.mu once registered
	started   bool // guarded by conn.mu; a socket write may have begun
}

type v2ControlOutcome struct {
	body []byte
	err  error
}

type lateV2Control struct {
	id      platform.ID
	binding [sha256.Size]byte
	until   time.Time
}

// The Node bounds simultaneous authenticated control workers independently of V1 routing quotas.
const v2ControlWorkersPerNode = 8

// V2ControlAuthority identifies only the current proved, accepted control peer and its current durable lease.
func (h *Hub) V2ControlAuthority(ctx context.Context, accountID, nodeID, enrollmentID, protocolEpoch platform.ID) (management.V2ControlAuthority, error) {
	cp, authority, err := h.currentV2ControlPeer(accountID, nodeID, enrollmentID, protocolEpoch)
	if err != nil {
		return management.V2ControlAuthority{}, err
	}
	if _, err = cp.checkV2ControlStore(ctx, authority); err != nil {
		return management.V2ControlAuthority{}, management.ErrV2ControlUnavailable
	}
	current, observed, err := h.currentV2ControlPeer(accountID, nodeID, enrollmentID, protocolEpoch)
	if err != nil || current != cp || observed != authority {
		return management.V2ControlAuthority{}, management.ErrV2ControlUnavailable
	}
	return authority, nil
}

func (h *Hub) currentV2ControlPeer(accountID, nodeID, enrollmentID, protocolEpoch platform.ID) (*conn, management.V2ControlAuthority, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fence, held := h.lease.Fence()
	c := h.nodes[nodeID]
	if h.stopping || !held || c == nil || c.userID != accountID || c.enrollmentID != enrollmentID || c.fence != fence || c.closing.Load() {
		return nil, management.V2ControlAuthority{}, management.ErrV2ControlUnavailable
	}
	if c.v2 == nil {
		return nil, management.V2ControlAuthority{}, management.ErrV2ControlUpgradeRequired
	}
	if c.v2.epoch != protocolEpoch {
		return nil, management.V2ControlAuthority{}, management.ErrV2ControlUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.v2ControlReadyLocked(h.clock()) {
		return nil, management.V2ControlAuthority{}, management.ErrV2ControlUnavailable
	}
	if !c.capabilities[v2ControlCapability] {
		return nil, management.V2ControlAuthority{}, management.ErrV2ControlUpgradeRequired
	}
	return c, management.V2ControlAuthority{
		AccountID: c.userID, NodeID: c.nodeID, EnrollmentID: c.enrollmentID, ProtocolEpoch: c.v2.epoch,
		ConnectionID: c.connectionID, NodeOwnerEpoch: c.nodeOwnerEpoch, HubHolder: h.lease.Holder(), HubFence: fence,
	}, nil
}

func (c *conn) v2ControlReadyLocked(now time.Time) bool {
	return c.v2 != nil && c.proved && c.accepted && c.recorded && c.v2Ready && !c.callsClosed && !c.closing.Load() &&
		now.Before(c.accessExpires) && now.Sub(c.lastInbound) < c.hub.settings.HeartbeatDeadline
}

// checkV2ControlStore observes the accepted session's current credential and key, the exact registered
// channel and the holder/fence. It performs no send inside the transaction. The caller rechecks the
// live in-process authority after this observation, immediately before a send or a reported result.
func (c *conn) checkV2ControlStore(ctx context.Context, a management.V2ControlAuthority) ([32]byte, error) {
	c.mu.Lock()
	digest := c.tokenDigest
	c.mu.Unlock()
	if c.hub.db == nil {
		return digest, management.ErrV2ControlUnavailable
	}
	err := c.hub.db.InTx(ctx, "verify current V2 control channel", store.TxOptions{Timeout: presenceTimeout, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		expires, err := c.lockV2Credential(ctx, tx, digest)
		if err != nil || !c.hub.clock().Before(expires) {
			if err != nil {
				return err
			}
			return errChannelCredentialChanged
		}
		var current bool
		err = tx.QueryRow(ctx, `SELECT true FROM fleet.node n JOIN management.node_protocol p
ON (p.enrollment_id,p.node_id,p.account_id)=(n.enrollment_id,n.node_id,n.user_id)
WHERE n.enrollment_id=$1 AND n.node_id=$2 AND n.user_id=$3 AND n.connection_id=$4
AND p.protocol_major=2 AND p.protocol_epoch=$5 AND n.device_id=$6 AND n.installation_id=$7
AND n.revoked_at IS NULL AND p.revoked_at IS NULL FOR SHARE OF n,p`, a.EnrollmentID, a.NodeID, a.AccountID,
			a.ConnectionID, a.ProtocolEpoch, c.deviceID, c.installationID).Scan(&current)
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT true FROM fleet.hub_lease
WHERE singleton AND holder=$1 AND fence=$2 AND expires_at>clock_timestamp() FOR SHARE`, a.HubHolder, a.HubFence).Scan(&current)
	})
	return digest, err
}

// CallV2 sends one bounded typed call to the exact current control connection. Mutations must
// claim possible delivery in beforeSend before a frame enters the queue. Lost or unverifiable
// delivery is uncertain and this method never retries a call on this or any other connection.
func (h *Hub) CallV2(ctx context.Context, authority management.V2ControlAuthority, call management.V2ControlCall,
	beforeSend func(context.Context, management.V2ControlAuthority) (bool, error)) ([]byte, error) {
	now := h.clock()
	selector := v2ControlSelector(call.Selector)
	mutation := selector.requiresCommandID() && selector != v2ControlGetOperation
	deadline := time.UnixMilli(call.Deadline.UnixMilli())
	duration := deadline.Sub(now)
	if duration <= 0 || duration > MaxCallDeadline || mutation && beforeSend == nil ||
		selector != v2ControlGetOperation && call.OriginalOwnerEpoch != authority.NodeOwnerEpoch {
		return nil, management.ErrV2ControlUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	c, current, err := h.currentV2ControlPeer(authority.AccountID, authority.NodeID, authority.EnrollmentID, authority.ProtocolEpoch)
	if err != nil {
		return nil, err
	}
	if current != authority || !h.reserveCall() {
		return nil, management.ErrV2ControlUnavailable
	}
	defer h.releaseCall()
	p := &pendingV2Control{id: platform.NewID(), authority: authority, deadline: deadline, ctx: ctx, done: make(chan v2ControlOutcome, 1)}
	if !c.reserveV2Control(p) {
		return nil, management.ErrV2ControlUnavailable
	}
	defer c.dropV2Control(p, false)
	if _, err = c.checkV2ControlStore(ctx, authority); err != nil {
		c.reportV2Control(p, "admit", "authority_unavailable")
		return nil, management.ErrV2ControlUnavailable
	}
	kid, key, ok := h.signingKey(h.clock())
	if !ok {
		h.noKey()
		return nil, management.ErrV2ControlUnavailable
	}
	h.hasKey()
	request := v2ControlRequest{CallID: p.id, Selector: selector, AccountID: authority.AccountID, ActorID: call.ActorID,
		NodeID: authority.NodeID, EnrollmentID: authority.EnrollmentID, ProtocolEpoch: authority.ProtocolEpoch,
		ConnectionID: authority.ConnectionID, OriginalOwnerEpoch: call.OriginalOwnerEpoch, CommandID: call.CommandID,
		GrantID: call.GrantID, GrantRevision: call.GrantRevision, HubFence: authority.HubFence, DeadlineUnixMillis: deadline.UnixMilli(),
		AudienceSHA256: sha256.Sum256([]byte(h.centerURL)), KID: kid, Body: call.Body}
	// The signed input does not include the outer sequence. The serialized writer assigns that at emission.
	data, binding, err := encodeV2ControlRequest(1, request, h.settings.MaxFrameBytes, h.clock(),
		func(input []byte) ([]byte, error) { return signES256(key, input) })
	if err != nil {
		c.reportV2Control(p, "sign", "request_refused")
		return nil, management.ErrV2ControlUnavailable
	}
	if ctx.Err() != nil || !c.isCurrentV2Control(p) {
		return nil, management.ErrV2ControlUnavailable
	}
	if beforeSend != nil {
		claimed, err := beforeSend(ctx, authority)
		if err != nil {
			c.reportV2Control(p, "claim", "claim_failed")
			return nil, err
		}
		if !claimed {
			c.reportV2Control(p, "claim", "claim_declined")
			return nil, management.ErrV2ControlNotClaimed
		}
		c.mu.Lock()
		p.claimed = mutation
		c.mu.Unlock()
	}
	c.mu.Lock()
	p.binding, p.kid = binding, kid
	route := c.v2Calls[p.id] == p && c.v2ControlReadyLocked(h.clock()) && ctx.Err() == nil
	if route {
		route = c.enqueue(outbound{data: data, v2Control: p}) == nil
	}
	c.mu.Unlock()
	if !route {
		c.reportV2Control(p, "enqueue", "not_enqueued")
		return nil, c.dropV2Control(p, false)
	}
	select {
	case result := <-p.done:
		if result.err != nil {
			c.reportV2Control(p, "wait", "ended_without_verified_result")
			return nil, c.dropV2Control(p, false)
		}
		c.reportV2Control(p, "result", "verified")
		return result.body, nil
	case <-ctx.Done():
		c.reportV2Control(p, "wait", "ended_without_verified_result")
		return nil, c.dropV2Control(p, true)
	}
}

func (c *conn) reserveV2Control(p *pendingV2Control) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.hub.clock()
	active := len(c.v2Calls)
	for _, call := range c.v2Late {
		if now.Before(call.until) {
			active++
		}
	}
	if !c.v2ControlReadyLocked(now) || active >= min(v2ControlWorkersPerNode, c.hub.settings.MaxInFlightCalls) || c.v2Calls[p.id] != nil {
		return false
	}
	if c.v2Calls == nil {
		c.v2Calls = make(map[platform.ID]*pendingV2Control)
	}
	c.v2Calls[p.id] = p
	return true
}

func (c *conn) isCurrentV2Control(p *pendingV2Control) bool {
	a := p.authority
	peer, current, err := c.hub.currentV2ControlPeer(a.AccountID, a.NodeID, a.EnrollmentID, a.ProtocolEpoch)
	return err == nil && peer == c && current == a
}

func (c *conn) dropV2Control(p *pendingV2Control, keepLate bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.v2Calls[p.id] == p {
		delete(c.v2Calls, p.id)
		if keepLate && p.started && !c.callsClosed {
			if len(c.v2Late) == lateResults {
				c.v2Late = c.v2Late[1:]
			}
			c.v2Late = append(c.v2Late, lateV2Control{id: p.id, binding: p.binding, until: p.deadline})
		}
	}
	if p.claimed || p.started {
		return management.ErrV2ControlUncertain
	}
	return management.ErrV2ControlUnavailable
}

func (c *conn) finishV2ControlLocked(p *pendingV2Control, result v2ControlOutcome) {
	if c.v2Calls[p.id] == p {
		delete(c.v2Calls, p.id)
		p.done <- result
	}
}

func (c *conn) failV2ControlsLocked() {
	for _, p := range c.v2Calls {
		c.finishV2ControlLocked(p, v2ControlOutcome{err: management.ErrV2ControlUnavailable})
	}
	c.v2Late = nil
}

func (c *conn) reportV2Control(p *pendingV2Control, phase, outcome string) {
	c.hub.logger.Debug("V2 control channel", "node", c.nodeID.String(), "connection", c.connectionID.String(),
		"call", p.id.String(), "phase", phase, "outcome", outcome)
}

// beginV2ControlWrite runs on the single writer. Failed or abandoned frames take no wire sequence.
func (c *conn) beginV2ControlWrite(p *pendingV2Control, writerDeadline time.Time) (time.Time, func(), bool) {
	ctx, cancel := context.WithDeadline(p.ctx, writerDeadline)
	stop := context.AfterFunc(c.writes, cancel)
	defer stop()
	defer cancel()
	h := c.hub
	// Registration holds the same node lock across its durable replacement and in-memory swap.
	// Retain it through the bounded write so that a local replacement cannot interleave there.
	releaseNode, err := h.lockNode(ctx, c.nodeID)
	var digest [32]byte
	if err == nil {
		if ctx.Err() == nil && c.isCurrentV2Control(p) {
			digest, err = c.checkV2ControlStore(ctx, p.authority)
		} else {
			err = management.ErrV2ControlUnavailable
		}
	}
	keyCurrent := slices.Contains(h.validKids(h.clock()), p.kid)
	h.mu.Lock()
	defer h.mu.Unlock()
	fence, held := h.lease.Fence()
	c.mu.Lock()
	defer c.mu.Unlock()
	start := time.Now()
	now := h.clock()
	if err != nil || !keyCurrent || ctx.Err() != nil || !now.Before(p.deadline) || !held || h.stopping || h.nodes[c.nodeID] != c ||
		fence != p.authority.HubFence || !c.v2ControlReadyLocked(now) || c.v2Calls[p.id] != p || c.tokenDigest != digest {
		c.finishV2ControlLocked(p, v2ControlOutcome{err: management.ErrV2ControlUnavailable})
		if releaseNode != nil {
			releaseNode()
		}
		return time.Time{}, nil, false
	}
	p.started = true
	return start.Add(p.deadline.Sub(now)), releaseNode, true
}

func (c *conn) v2ControlResult(result v2SignedControlResult) bool {
	c.mu.Lock()
	enabled := c.v2Ready && c.capabilities[v2ControlCapability]
	p := c.v2Calls[result.CallID]
	var binding [sha256.Size]byte
	late := -1
	if p != nil && p.started {
		binding = p.binding
	} else if p == nil {
		for i, call := range c.v2Late {
			if call.id == result.CallID {
				late, binding = i, call.binding
				break
			}
		}
	}
	var violation string
	switch {
	case !enabled:
		violation = "unexpected_frame"
	case (p == nil || !p.started) && late < 0:
		violation = "result_other_call"
	case binding != result.RequestBinding:
		violation = "result_mismatch"
	case !verifyES256(c.publicKey, result.SigningInput, result.Signature[:]):
		violation = "result_signature"
	}
	if violation != "" {
		c.mu.Unlock()
		c.violation(violation)
		return false
	}
	if late >= 0 {
		c.v2Late = append(c.v2Late[:late], c.v2Late[late+1:]...)
		c.mu.Unlock()
		return true
	}
	c.mu.Unlock()

	h := c.hub
	releaseNode, err := h.lockNode(p.ctx, c.nodeID)
	var digest [32]byte
	if err == nil {
		defer releaseNode()
		if p.ctx.Err() == nil && c.isCurrentV2Control(p) {
			digest, err = c.checkV2ControlStore(p.ctx, p.authority)
		} else {
			err = management.ErrV2ControlUnavailable
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	fence, held := h.lease.Fence()
	c.mu.Lock()
	defer c.mu.Unlock()
	now := h.clock()
	if c.v2Calls[p.id] != p {
		// The caller left while the verified response was being checked. Consume its late binding once.
		for i, call := range c.v2Late {
			if call.id == p.id {
				c.v2Late = append(c.v2Late[:i], c.v2Late[i+1:]...)
				break
			}
		}
		return true
	}
	if err != nil || !held || h.stopping || h.nodes[c.nodeID] != c || fence != p.authority.HubFence ||
		!c.v2ControlReadyLocked(now) || c.tokenDigest != digest || p.ctx.Err() != nil || !now.Before(p.deadline) {
		c.finishV2ControlLocked(p, v2ControlOutcome{err: management.ErrV2ControlUnavailable})
		return true
	}
	c.finishV2ControlLocked(p, v2ControlOutcome{body: result.Body})
	return true
}
