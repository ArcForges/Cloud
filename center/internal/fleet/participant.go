// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// NodeRevokeDevice is fleet.node's revoke reason for a node whose device was revoked (the only one in AF-CTR-04).
const NodeRevokeDevice int16 = 1

// NodeParticipant is the device revocation's cascade participant for enrolled nodes (CTR4-CRD-07, DC-06): in the revocation's own
// transaction, after the device, its installations and its sessions, it marks the device's live fleet.node rows revoked, so the node
// ID is free to enroll again (with a new key: the revoked installation keeps holding the old one). It is registered wherever the
// identity surface is composed, whether or not the fleet surface is on, because a device revoked while fleet is off still ends its
// nodes.
type NodeParticipant struct{}

// Name is the participant's name in the device.revoked audit counts.
func (NodeParticipant) Name() string { return "fleet.node" }

// RevokeDevice revokes the live node rows of a device and returns how many it revoked.
func (NodeParticipant) RevokeDevice(ctx context.Context, tx pgx.Tx, userID, deviceID platform.ID, now time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE fleet.node SET revoked_at = $3, revoke_reason = $4, rev = rev + 1
WHERE device_id = $1 AND user_id = $2 AND revoked_at IS NULL`, deviceID, userID, now, NodeRevokeDevice)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
