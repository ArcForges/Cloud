// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Presence (Plan CTR5-HUB-06; migration 0008): the hub writes a node's online_since, last_heartbeat_at and connection_id at accept, at
// most once per presence interval from heartbeats, and at close, each write fenced by the hub lease. last_seen_at, the node's last
// contact, follows every one of them.

// ErrFenced is a hub write the lease refused: the fence it named is no longer the live one.
var ErrFenced = errors.New("the hub lease no longer holds the fence of this write")

// presenceTimeout bounds one presence write.
const presenceTimeout = 5 * time.Second

func (h *Hub) fencedExec(ctx context.Context, operation, statement string, arguments pgx.NamedArgs) error {
	affected := int64(0)
	err := h.db.InTx(ctx, operation, store.TxOptions{Timeout: presenceTimeout, Auxiliary: true}, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, statement, arguments)
		affected = tag.RowsAffected()
		return err
	})
	switch {
	case err != nil:
		return err
	case affected == 0:
		return ErrFenced
	}
	return nil
}

// markOnline records an accepted connection: the node is online since now, with its connection and a heartbeat now.
func (h *Hub) markOnline(ctx context.Context, enrollmentID, connectionID platform.ID, fence int64, now time.Time) error {
	return h.fencedExec(ctx, "record a node's channel", `UPDATE fleet.node SET online_since = @now, last_heartbeat_at = @now, connection_id = @connection,
    last_seen_at = greatest(last_seen_at, @now)
WHERE enrollment_id = @enrollment AND revoked_at IS NULL AND `+fencedCondition,
		pgx.NamedArgs{"now": now, "connection": connectionID, "enrollment": enrollmentID, "fence": fence})
}

// markHeartbeat records a heartbeat of the connection that holds the node.
func (h *Hub) markHeartbeat(ctx context.Context, enrollmentID, connectionID platform.ID, fence int64, now time.Time) error {
	return h.fencedExec(ctx, "record a node's heartbeat", `UPDATE fleet.node SET last_heartbeat_at = greatest(last_heartbeat_at, @now),
    last_seen_at = greatest(last_seen_at, @now)
WHERE enrollment_id = @enrollment AND connection_id = @connection AND `+fencedCondition,
		pgx.NamedArgs{"now": now, "connection": connectionID, "enrollment": enrollmentID, "fence": fence})
}

// markOffline records the close of the connection that holds the node: a replacement that already wrote its own connection is left
// alone (ErrFenced then means only that this connection no longer held the node, or that the lease moved on).
func (h *Hub) markOffline(ctx context.Context, enrollmentID, connectionID platform.ID, fence int64, now time.Time) error {
	return h.fencedExec(ctx, "record the close of a node's channel", `UPDATE fleet.node SET connection_id = NULL,
    last_heartbeat_at = greatest(last_heartbeat_at, @now), last_seen_at = greatest(last_seen_at, @now)
WHERE enrollment_id = @enrollment AND connection_id = @connection AND `+fencedCondition,
		pgx.NamedArgs{"now": now, "connection": connectionID, "enrollment": enrollmentID, "fence": fence})
}

// clearStale clears the connections a previous holder of the lease left recorded (it was killed, or it lost the lease): this process
// holds none of them. It runs once per acquisition, under the new fence.
func (h *Hub) clearStale(ctx context.Context, fence int64, now time.Time) error {
	err := h.fencedExec(ctx, "clear the channels of a previous hub", `UPDATE fleet.node SET connection_id = NULL
WHERE connection_id IS NOT NULL AND `+fencedCondition, pgx.NamedArgs{"now": now, "fence": fence})
	if errors.Is(err, ErrFenced) {
		// No row to clear is the usual answer; a lease lost meanwhile is found by the next renewal.
		return nil
	}
	return err
}

// State is a node's presence as FleetNode.online states it (Plan CTR5-HUB-06; E2 serves it).
type State int

// The presence states.
const (
	// Online: a live connection of the node is open in this process, which holds the hub lease.
	Online State = iota + 1
	// Offline: the node has connected before but has no open connection here.
	Offline
	// NeverConnected: the node has never had a channel accepted (online_since is unset).
	NeverConnected
	// Revoked: the node's enrollment is revoked (or unknown).
	Revoked
)

// Presence is a node's presence state and its last heartbeat (zero when none was recorded), by node ID: the live enrollment of the node
// ID, or Revoked when it has none.
func (h *Hub) Presence(ctx context.Context, nodeID platform.ID) (State, time.Time, error) {
	var onlineSince, lastHeartbeat *time.Time
	found := true
	err := h.db.InTx(ctx, "read a node's presence", store.TxOptions{ReadOnly: true, Timeout: presenceTimeout}, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, "SELECT online_since, last_heartbeat_at FROM fleet.node WHERE node_id = $1 AND revoked_at IS NULL", nodeID).
			Scan(&onlineSince, &lastHeartbeat)
		if errors.Is(err, pgx.ErrNoRows) {
			found = false
			return nil
		}
		return err
	})
	var heartbeat time.Time
	if lastHeartbeat != nil {
		heartbeat = *lastHeartbeat
	}
	switch {
	case err != nil:
		return 0, time.Time{}, err
	case !found:
		return Revoked, time.Time{}, nil
	case h.Connected(nodeID):
		return Online, heartbeat, nil
	case onlineSince == nil:
		return NeverConnected, heartbeat, nil
	}
	return Offline, heartbeat, nil
}
