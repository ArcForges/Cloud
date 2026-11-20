// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/management"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

var (
	errProtocolChanged          = errors.New("the enrollment protocol's epoch changed before registration")
	errChannelCredentialChanged = errors.New("the channel's credential changed before registration")
	errChannelAccountBarred     = errors.New("the channel's account no longer admits a node session")
)

// V2Presence reads the live channel snapshot for the registry's exact account,
// node, enrollment and protocol binding. Presence is never inferred from a V1 channel.
func (h *Hub) V2Presence(accountID, enrollmentID, nodeID, protocolEpoch platform.ID) (management.V2Presence, bool) {
	fence, serving := h.serving()
	if !serving {
		return management.V2Presence{}, false
	}
	h.mu.Lock()
	c := h.nodes[nodeID]
	h.mu.Unlock()
	if c == nil || c.v2 == nil || c.userID != accountID || c.enrollmentID != enrollmentID || c.v2.epoch != protocolEpoch || c.fence != fence {
		return management.V2Presence{}, false
	}
	c.mu.Lock()
	if !c.v2Ready || c.closing.Load() || h.clock().Sub(c.lastInbound) >= h.settings.HeartbeatDeadline {
		c.mu.Unlock()
		return management.V2Presence{}, false
	}
	snapshot := management.V2Presence{ConnectionID: c.connectionID, NodeOwnerEpoch: c.nodeOwnerEpoch, NodeEpoch: c.nodeEpoch,
		Platform: c.platform, Capabilities: slices.Clone(c.v2Capabilities), HubFence: fence, SeenAt: c.lastInbound}
	c.mu.Unlock()
	h.mu.Lock()
	current := h.nodes[nodeID] == c && !h.stopping && !c.closing.Load()
	h.mu.Unlock()
	if !current {
		return management.V2Presence{}, false
	}
	return snapshot, true
}

// markV2Online serializes the first proof's durable protocol binding with the
// existing live node row and its channel replacement. A stale hub or protocol
// generation cannot record an online channel.
func (c *conn) markV2Online(ctx context.Context, now time.Time) error {
	return c.hub.db.InTx(ctx, "record a V2 node's channel", store.TxOptions{Timeout: presenceTimeout, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		expires, err := c.lockV2Credential(ctx, tx, c.upgradeAccessHash)
		if err != nil {
			return err
		}

		var enrollment platform.ID
		err = tx.QueryRow(ctx, `SELECT enrollment_id FROM fleet.node
WHERE enrollment_id=$1 AND node_id=$2 AND user_id=$3 AND installation_id=$4
  AND device_id=$5 AND revoked_at IS NULL FOR UPDATE`,
			c.enrollmentID, c.nodeID, c.userID, c.installationID, c.deviceID).Scan(&enrollment)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNodeGone
		}
		if err != nil {
			return err
		}

		if _, err = tx.Exec(ctx, `INSERT INTO management.node_protocol
    (enrollment_id,node_id,account_id,protocol_major,protocol_epoch,initialized_at,rev)
VALUES ($1,$2,$3,2,$4,$5,1) ON CONFLICT (enrollment_id) DO NOTHING`, enrollment, c.nodeID, c.userID, c.v2.epoch, now); err != nil {
			return err
		}
		var epoch platform.ID
		var revoked bool
		err = tx.QueryRow(ctx, `SELECT protocol_epoch, revoked_at IS NOT NULL FROM management.node_protocol
WHERE enrollment_id=$1 AND node_id=$2 AND account_id=$3 FOR SHARE`, enrollment, c.nodeID, c.userID).Scan(&epoch, &revoked)
		if err != nil {
			return err
		}
		if revoked {
			return ErrNodeGone
		}
		if epoch != c.v2.epoch {
			return errProtocolChanged
		}
		if err = lockPresenceLease(ctx, tx, c.fence); err != nil {
			return err
		}
		if !c.hub.clock().Before(expires) {
			return errChannelCredentialChanged
		}
		return writeOnline(ctx, tx, enrollment, c.connectionID, c.fence, now)
	})
}

// Hold the same account, device, installation and session order as enrollment
// and revocation, before the fleet row. The proof's key and presented access
// credential must still be current at the point this transaction admits it.
func (c *conn) lockV2Credential(ctx context.Context, tx pgx.Tx, accessHash [32]byte) (time.Time, error) {
	security, err := session.LockAccountSecurity(ctx, tx, c.userID)
	if err != nil {
		return time.Time{}, err
	}
	if !security.AdmitsScope(session.ScopeNode) {
		return time.Time{}, errChannelAccountBarred
	}

	var live bool
	err = tx.QueryRow(ctx, `SELECT true FROM device.device
WHERE device_id=$1 AND user_id=$2 AND revoked_at IS NULL FOR SHARE`,
		c.deviceID, c.userID).Scan(&live)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNodeGone
	}
	if err != nil {
		return time.Time{}, err
	}
	err = tx.QueryRow(ctx, `SELECT true FROM device.installation
WHERE installation_id=$1 AND user_id=$2 AND device_id=$3 AND public_key=$4 AND revoked_at IS NULL FOR SHARE`,
		c.installationID, c.userID, c.deviceID, c.publicKey).Scan(&live)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, errChannelCredentialChanged
	}
	if err != nil {
		return time.Time{}, err
	}

	var expires time.Time
	err = tx.QueryRow(ctx, `SELECT least(expires_at,access_expires_at) FROM identity.session
WHERE session_id=$1 AND user_id=$2 AND device_id=$3 AND installation_id=$4 AND scope=$5
  AND credential_kind=1 AND revoked_at IS NULL AND access_expires_at IS NOT NULL
  AND auth_epoch=$6 AND recovery_generation=$7 AND access_token_hash=$8 FOR SHARE`,
		c.sessionID, c.userID, c.deviceID, c.installationID, session.ScopeNode,
		security.AuthEpoch, security.RecoveryGeneration, accessHash[:]).Scan(&expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, errChannelCredentialChanged
	}
	return expires, err
}

func (c *conn) markV2Heartbeat(ctx context.Context, now time.Time) error {
	return c.hub.fencedExec(ctx, "record a V2 node's heartbeat", `UPDATE fleet.node n
SET last_heartbeat_at=greatest(n.last_heartbeat_at,@now),last_seen_at=greatest(n.last_seen_at,@now)
FROM management.node_protocol p
WHERE n.enrollment_id=@enrollment AND n.connection_id=@connection AND n.revoked_at IS NULL
  AND p.enrollment_id=n.enrollment_id AND p.node_id=n.node_id AND p.account_id=n.user_id
  AND p.protocol_epoch=@epoch AND p.revoked_at IS NULL AND `+fencedCondition,
		pgx.NamedArgs{"now": now, "connection": c.connectionID, "enrollment": c.enrollmentID, "epoch": c.v2.epoch, "fence": c.fence})
}
