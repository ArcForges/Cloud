// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// Approver is an approving account's session as an approval recorded it (protocol-6): the session, how and when it authenticated
// and its authentication and recovery epochs at the approval. The node sign-ins (package fleet) and the mobile native authorization
// (package mobileauth) store one with every approval and check it again when the approval is redeemed.
type Approver struct {
	SessionID          platform.ID
	AuthMethod         int16
	AuthenticatedAt    time.Time
	AuthEpoch          int64
	RecoveryGeneration int64
}

// lapsingReasons are the approving session's revoke reasons that end its approvals: revoked by the account, all sessions revoked,
// device revoked, operator. A sign-out (1) and an expiry do not.
var lapsingReasons = map[int16]bool{RevokedByAccount: true, RevokedAll: true, RevokedDevice: true, RevokedOperator: true}

// LapsingReason reports whether a revoke reason of an approving session ends the approvals that session gave.
func LapsingReason(reason int16) bool { return lapsingReasons[reason] }

// ApprovalStands locks the approving session of an account FOR SHARE (the session slot of the global lock order, cloud-1) and
// reports whether the approval still stands: the session exists for that account, it was not revoked for a lapsing reason, and its
// authentication and recovery epochs are those of the approval. An approval that lapsed is false with no error; an error is a store
// failure (sanitized).
func ApprovalStands(ctx context.Context, tx pgx.Tx, approver Approver, userID platform.ID) (bool, error) {
	var reason *int16
	var epoch, recovery int64
	err := tx.QueryRow(ctx, `SELECT revoke_reason, auth_epoch, recovery_generation FROM identity.session WHERE session_id = $1 AND user_id = $2
FOR SHARE`, approver.SessionID, userID).Scan(&reason, &epoch, &recovery)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, store.Sanitize("lock the approving session", err)
	}
	if reason != nil && lapsingReasons[*reason] || epoch != approver.AuthEpoch || recovery != approver.RecoveryGeneration {
		return false, nil
	}
	return true, nil
}
