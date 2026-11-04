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
// the remediation. Two statements: the first locks, in flow ID order, the account's APPROVED flows and the PENDING flows the account
// reviewed last; the second denies the locked flows that are APPROVED, with a snapshot taken after the locks. So an approval that
// holds one of those rows when the hook starts commits first and is then denied; an approval that reaches its row after the lock waits
// for the remediation to commit and is a new approval of a live session (N-4). The identity composition registers it wherever the
// identity surface is composed, whether or not the fleet surface is on.
type ApprovalParticipant struct{}

// Name is the participant's name in the audit counts.
func (ApprovalParticipant) Name() string { return "fleet.node_sign_in" }

// CancelApprovals denies the account's approved, uncollected browser sign-ins and returns how many it denied.
func (ApprovalParticipant) CancelApprovals(ctx context.Context, tx pgx.Tx, userID platform.ID, now time.Time) (int64, error) {
	rows, err := tx.Query(ctx, `SELECT flow_id::text FROM fleet.node_sign_in WHERE (user_id = $1 AND state = 2) OR (viewed_by = $1 AND state = 1)
ORDER BY flow_id FOR UPDATE`, userID)
	if err != nil {
		return 0, err
	}
	locked, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(locked) == 0 {
		return 0, err
	}
	// A new statement, a new snapshot: an approval that committed while the first statement waited for its row is seen here.
	tag, err := tx.Exec(ctx, "UPDATE fleet.node_sign_in SET state = 4, decided_at = $2, rev = rev + 1 WHERE flow_id = ANY($3::uuid[]) AND state = 2 AND user_id = $1",
		userID, now, locked)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// DeviceApprovalParticipant is the account participant of the device-code sign-in (protocol-6; AF-CTR-04 E2): when the account
// revokes all its other sessions or removes a credential, its APPROVED device authorizations (whose credentials no poll delivered
// yet: a delivered one is COMPLETED) become DENIED in the same transaction. It is registered after ApprovalParticipant, so the
// remediation locks the browser flows before the device authorizations, the one order of the two tables (no other writer locks
// both). Two statements, as ApprovalParticipant's: the first locks, in authorization ID order, the account's APPROVED authorizations
// and the PENDING ones it reviewed last; the second denies the locked ones that are APPROVED with a snapshot taken after the locks.
type DeviceApprovalParticipant struct{}

// Name is the participant's name in the audit counts.
func (DeviceApprovalParticipant) Name() string { return "fleet.device_authorization" }

// CancelApprovals denies the account's approved, undelivered device authorizations and returns how many it denied.
func (DeviceApprovalParticipant) CancelApprovals(ctx context.Context, tx pgx.Tx, userID platform.ID, now time.Time) (int64, error) {
	rows, err := tx.Query(ctx, `SELECT authorization_id::text FROM fleet.device_authorization WHERE (user_id = $1 AND state = 3) OR (viewed_by = $1 AND state = 1)
ORDER BY authorization_id FOR UPDATE`, userID)
	if err != nil {
		return 0, err
	}
	locked, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(locked) == 0 {
		return 0, err
	}
	// A new statement, a new snapshot: an approval that committed while the first statement waited for its row is seen here.
	tag, err := tx.Exec(ctx, "UPDATE fleet.device_authorization SET state = 4, decided_at = $2, rev = rev + 1 WHERE authorization_id = ANY($3::uuid[]) AND state = 3 AND user_id = $1",
		userID, now, locked)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
