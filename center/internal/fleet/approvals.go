// SPDX-License-Identifier: AGPL-3.0-only

package fleet

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// ApprovalParticipant is the account participant of the browser node sign-in (protocol-6; identity.AccountParticipant): when the
// account revokes all its other sessions or removes a credential, its APPROVED flows, whose code no node redeemed (an APPROVED flow's
// code is always unredeemed), become DENIED in the same transaction, so a node that a phished approval let in cannot collect it after
// the remediation. It locks, in flow ID order, the account's APPROVED flows and the PENDING flows the account reviewed last (an
// approval of one of them that holds its row commits first and is then denied; one that comes after waits and is a new approval of a
// live session). It is registered wherever the identity surface is composed, whether or not the fleet surface is on.
type ApprovalParticipant struct{}

// Name is the participant's name in the audit counts.
func (ApprovalParticipant) Name() string { return "fleet.node_sign_in" }

// CancelApprovals denies the account's approved, uncollected browser sign-ins and returns how many it denied.
func (ApprovalParticipant) CancelApprovals(ctx context.Context, tx pgx.Tx, userID platform.ID, now time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE fleet.node_sign_in SET state = 4, decided_at = $2, rev = rev + 1 WHERE state = 2 AND user_id = $1 AND flow_id IN (
    SELECT flow_id FROM fleet.node_sign_in WHERE (user_id = $1 AND state = 2) OR (viewed_by = $1 AND state = 1) ORDER BY flow_id FOR UPDATE)`, userID, now)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
