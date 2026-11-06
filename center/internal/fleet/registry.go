// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The node registry (AF-CTR-05 part E2a; Plan CTR5-API-02, CTR5-API-03 and Q25; Contracts fleet.proto FleetService ListNodes, GetNode,
// RenameNode and FleetNode): the account's live enrollments as FleetService serves them, and the account's name for a node. The
// registry is never gated (Q20). A node ID is unique among the live rows only (plan-ctr-04 Q21), so every read names live rows; an
// unknown, revoked or foreign node is the same STATE/not_found.

// NodeRecord is one live node of an account as the registry reads it.
type NodeRecord struct {
	NodeID, DeviceID, EnrollmentID platform.ID
	// Name is the node's name in the registry (display_name): the account's once it renamed the node, else the reported one.
	// ReportedName is the name the node last reported for itself (a row of the previous release that has not reported since: its
	// display_name, which was always the reported name then).
	Name, ReportedName string
	Version            string
	OS, Arch           int16
	EnrolledAt         time.Time
	// LastSeenAt is the later of the node's last contact (refresh, report, sign-in) and its channel's last recorded heartbeat.
	LastSeenAt time.Time
	// Connected is whether the node's channel was ever accepted (online_since set): it tells OFFLINE from NEVER_CONNECTED.
	Connected bool
	// CredentialExpiresAt is when the node's live credential ends at the latest (identity.session expires_at, the absolute lifetime);
	// nil while it holds none (signed out).
	CredentialExpiresAt *time.Time
}

// recordColumns are the columns of a NodeRecord, over fleet.node n.
const recordColumns = `n.node_id, n.device_id, n.enrollment_id, n.display_name, coalesce(n.reported_name, n.display_name), n.version, n.os, n.arch,
    n.enrolled_at, greatest(n.last_seen_at, coalesce(n.last_heartbeat_at, n.last_seen_at)), n.online_since IS NOT NULL,
    (SELECT max(s.expires_at) FROM identity.session s WHERE s.installation_id = n.installation_id AND s.user_id = n.user_id AND s.scope = 3
        AND s.revoked_at IS NULL)`

func scanRecord(row pgx.Row) (NodeRecord, error) {
	var record NodeRecord
	err := row.Scan(&record.NodeID, &record.DeviceID, &record.EnrollmentID, &record.Name, &record.ReportedName, &record.Version, &record.OS, &record.Arch,
		&record.EnrolledAt, &record.LastSeenAt, &record.Connected, &record.CredentialExpiresAt)
	return record, err
}

// registryTimeout bounds a registry read.
const registryTimeout = 5 * time.Second

// ListNodes are the account's live nodes, oldest enrollment first: one read-only transaction, without a lock.
func ListNodes(ctx context.Context, db *store.DB, userID platform.ID) ([]NodeRecord, error) {
	var records []NodeRecord
	err := db.InTx(ctx, "list the account's nodes", store.TxOptions{ReadOnly: true, Timeout: registryTimeout}, func(ctx context.Context, tx pgx.Tx) error {
		records = records[:0]
		rows, err := tx.Query(ctx, "SELECT "+recordColumns+" FROM fleet.node n WHERE n.user_id = $1 AND n.revoked_at IS NULL ORDER BY n.enrolled_at, n.node_id",
			userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			record, err := scanRecord(rows)
			if err != nil {
				return err
			}
			records = append(records, record)
		}
		return rows.Err()
	})
	return records, store.Sanitize("list the account's nodes", err)
}

// GetNode is one live node of the account, or STATE/not_found.
func GetNode(ctx context.Context, db *store.DB, userID, nodeID platform.ID) (NodeRecord, error) {
	var record NodeRecord
	err := db.InTx(ctx, "read a node", store.TxOptions{ReadOnly: true, Timeout: registryTimeout}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		record, err = readRecord(ctx, tx, userID, nodeID)
		return err
	})
	return record, err
}

func readRecord(ctx context.Context, tx pgx.Tx, userID, nodeID platform.ID) (NodeRecord, error) {
	record, err := scanRecord(tx.QueryRow(ctx, "SELECT "+recordColumns+" FROM fleet.node n WHERE n.node_id = $1 AND n.user_id = $2 AND n.revoked_at IS NULL",
		nodeID, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return NodeRecord{}, arc.NotFound("node", nodeID[:])
	}
	return record, store.Sanitize("read a node", err)
}

// NodeOwner is the account that owns a node (the owner the authorizer's ownership stage asks for a row whose Object is node), as the
// text of its ID; found is false for an unknown node. A read (GetNode) asks for the live enrollment only, so a revoked node is not
// found; a write under a command receipt (RenameNode, RevokeNode) also finds the node's newest revoked enrollment when no enrollment of
// the node ID is live, so the replay of a committed command still reaches its receipt (a new command for a revoked node then answers
// STATE/not_found from its own transaction, kept in its receipt).
func NodeOwner(ctx context.Context, db *store.DB, nodeID platform.ID, includeRevoked bool) (string, bool, error) {
	var owner platform.ID
	found := true
	statement := "SELECT user_id FROM fleet.node WHERE node_id = $1 AND revoked_at IS NULL"
	if includeRevoked {
		statement = "SELECT user_id FROM fleet.node WHERE node_id = $1 ORDER BY revoked_at IS NULL DESC, revoked_at DESC, enrollment_id LIMIT 1"
	}
	err := db.InTx(ctx, "read a node's owner", store.TxOptions{ReadOnly: true, Timeout: registryTimeout}, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, statement, nodeID).Scan(&owner)
		if errors.Is(err, pgx.ErrNoRows) {
			found = false
			return nil
		}
		return err
	})
	if err != nil {
		return "", false, store.Sanitize("read a node's owner", err)
	}
	return owner.String(), found, nil
}

// NodeDevice is the device of one of the account's live nodes (RevokeNode revokes it), read in the caller's transaction, or
// STATE/not_found.
func NodeDevice(ctx context.Context, tx pgx.Tx, userID, nodeID platform.ID) (platform.ID, error) {
	var deviceID platform.ID
	err := tx.QueryRow(ctx, "SELECT device_id FROM fleet.node WHERE node_id = $1 AND user_id = $2 AND revoked_at IS NULL", nodeID, userID).Scan(&deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return platform.ID{}, arc.NotFound("node", nodeID[:])
	}
	return deviceID, store.Sanitize("read a node's device", err)
}

// Rename gives one of the account's live nodes the account's name (RenameNode; CTR5-API-03, Q25) in the caller's receipt transaction:
// the node's registry name and its device's name become the name, and the node is marked as named by its account, so the names it
// reports later are kept as reported_name only (Report, Enroll). The node adopts the name at its next accepted channel
// (ChannelAccepted.node_name). fleet.node.renamed is audited, without the name. The name was checked by the caller (ValidNodeName).
// Locks: the device, then the node row (the global order); a node revoked meanwhile is STATE/not_found. It returns the renamed record.
func (s *Service) Rename(ctx context.Context, tx pgx.Tx, request Request, account Account, nodeID platform.ID, name string, now time.Time) (NodeRecord, error) {
	userID := account.Caller.UserID
	var enrollmentID, deviceID platform.ID
	err := tx.QueryRow(ctx, "SELECT enrollment_id, device_id FROM fleet.node WHERE node_id = $1 AND user_id = $2 AND revoked_at IS NULL", nodeID, userID).
		Scan(&enrollmentID, &deviceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return NodeRecord{}, arc.NotFound("node", nodeID[:])
	}
	if err != nil {
		return NodeRecord{}, store.Sanitize("find the node", err)
	}
	tag, err := tx.Exec(ctx, "SELECT 1 FROM device.device WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL FOR UPDATE", deviceID, userID)
	if err != nil {
		return NodeRecord{}, store.Sanitize("lock the node's device", err)
	}
	if tag.RowsAffected() != 1 {
		return NodeRecord{}, arc.NotFound("node", nodeID[:])
	}
	var live bool
	if err = tx.QueryRow(ctx, "SELECT revoked_at IS NULL FROM fleet.node WHERE enrollment_id = $1 FOR UPDATE", enrollmentID).Scan(&live); err != nil {
		return NodeRecord{}, store.Sanitize("lock the node", err)
	}
	if !live {
		return NodeRecord{}, arc.NotFound("node", nodeID[:])
	}
	if _, err = tx.Exec(ctx, "UPDATE device.device SET display_name = $2, rev = rev + 1 WHERE device_id = $1 AND display_name <> $2", deviceID, name); err != nil {
		return NodeRecord{}, store.Sanitize("rename the node's device", err)
	}
	if _, err = tx.Exec(ctx, "UPDATE fleet.node SET display_name = $2, named_by_account = true, rev = rev + 1 WHERE enrollment_id = $1", enrollmentID,
		name); err != nil {
		return NodeRecord{}, store.Sanitize("rename the node", err)
	}
	if err = s.audit(ctx, tx, request, identity.Actor(userID), "fleet.node.renamed", "renamed", enrollmentID, map[string]any{}, now); err != nil {
		return NodeRecord{}, err
	}
	s.events.ObserveFleet("rename", "renamed")
	return readRecord(ctx, tx, userID, nodeID)
}
