// SPDX-License-Identifier: AGPL-3.0-only

package mobileauth

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/platform"
)

// ApprovalParticipant is the account participant of the mobile authorization (protocol-6; identity.AccountParticipant), as fleet's
// ApprovalParticipant is for the node sign-in: when the account revokes all its other sessions or removes a credential, its APPROVED
// flows, whose code no app redeemed (an APPROVED flow's code is always unredeemed), become DENIED in the same transaction, so an app
// that a phished approval let in cannot collect the session after the remediation (the approving session itself is neither revoked
// nor moved to a new epoch by "sign out all other sessions", so session.ApprovalStands alone would let it through). Two statements:
// the first locks, in flow ID order, the account's APPROVED flows and the PENDING flows it reviewed last; the second denies the locked
// flows that are APPROVED, with a snapshot taken after the locks. The identity composition registers it after the fleet's two
// participants (the registration order is the lock order between the tables), wherever the identity surface is composed.
type ApprovalParticipant struct{}

// Name is the participant's name in the audit counts.
func (ApprovalParticipant) Name() string { return "identity.mobile_authorization" }

// CancelApprovals denies the account's approved, uncollected mobile authorizations and returns how many it denied.
func (ApprovalParticipant) CancelApprovals(ctx context.Context, tx pgx.Tx, userID platform.ID, now time.Time) (int64, error) {
	rows, err := tx.Query(ctx, `SELECT flow_id::text FROM identity.mobile_authorization WHERE (user_id = $1 AND state = 2) OR (viewed_by = $1 AND state = 1)
ORDER BY flow_id FOR UPDATE`, userID)
	if err != nil {
		return 0, err
	}
	locked, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(locked) == 0 {
		return 0, err
	}
	// A new statement, a new snapshot: an approval that committed while the first statement waited for its row is seen here.
	tag, err := tx.Exec(ctx, `UPDATE identity.mobile_authorization SET state = 4, decided_at = $2, rev = rev + 1 WHERE flow_id = ANY($3::uuid[]) AND state = 2
AND user_id = $1`, userID, now, locked)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
