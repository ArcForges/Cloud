// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// liveAccountSession is the condition of a session an account can sign out or revoke from the API: one of its account sessions
// (account and mobile.limited; DC-03), not revoked and within its absolute and idle expiry. Node, push and automation sessions are
// revoked with their device, and by the operator.
const liveAccountSession = `scope IN (1, 2) AND revoked_at IS NULL AND expires_at > $NOW AND (idle_expires_at IS NULL OR idle_expires_at > $NOW)`

// RevokeOne revokes one live account session of an account in the caller's transaction (RevokeSession: the caller's own session is
// a sign-out, reason RevokedSignedOut; any other is RevokedByAccount) and returns its new revision. A session of another account, a
// node, push or automation session, and a revoked or expired one are all STATE/not_found.
func RevokeOne(ctx context.Context, tx pgx.Tx, userID, sessionID platform.ID, reason int16, now time.Time) (int64, error) {
	var revision int64
	err := tx.QueryRow(ctx, `UPDATE identity.session SET revoked_at = $3, revoke_reason = $4, rev = rev + 1
WHERE session_id = $1 AND user_id = $2 AND `+replaceNow(liveAccountSession, "$3")+` RETURNING rev`, sessionID, userID, now, reason).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, arc.NotFound()
	}
	return revision, err
}

// RevokeAll revokes every live account session of an account except the caller's own (RevokeAllSessions, reason RevokedAll) in the
// caller's transaction and returns how many it revoked. Node, push and automation sessions are untouched (DC-03).
func RevokeAll(ctx context.Context, tx pgx.Tx, userID, except platform.ID, now time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `UPDATE identity.session SET revoked_at = $3, revoke_reason = $4, rev = rev + 1
WHERE user_id = $1 AND session_id <> $2 AND `+replaceNow(liveAccountSession, "$3"), userID, except, now, RevokedAll)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// RevokeByOperator revokes every unrevoked session of every scope (reason RevokedOperator) of one account, or of every account when
// userID is nil, in the caller's transaction (`arcforges-center admin revoke-sessions`, the incident tool, with the migration
// role), and counts them per scope. Every credential is refused at its next call.
func RevokeByOperator(ctx context.Context, tx pgx.Tx, userID *platform.ID, now time.Time) (map[string]int64, error) {
	rows, err := tx.Query(ctx, `UPDATE identity.session SET revoked_at = $2, revoke_reason = $3, rev = rev + 1
WHERE revoked_at IS NULL AND ($1::uuid IS NULL OR user_id = $1) RETURNING scope`, userID, now, RevokedOperator)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var scope int16
		if err = rows.Scan(&scope); err != nil {
			return nil, err
		}
		counts[Scope(scope).String()]++
	}
	return counts, rows.Err()
}

// RevokeOnDevice revokes every unrevoked session bound to a device, whatever its scope (the device revocation cascade, reason
// RevokedDevice), in the caller's transaction, and counts them per scope.
func RevokeOnDevice(ctx context.Context, tx pgx.Tx, deviceID platform.ID, now time.Time) (map[string]int64, error) {
	rows, err := tx.Query(ctx, `UPDATE identity.session SET revoked_at = $2, revoke_reason = $3, rev = rev + 1
WHERE device_id = $1 AND revoked_at IS NULL RETURNING scope`, deviceID, now, RevokedDevice)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[string]int64{}
	for rows.Next() {
		var scope int16
		if err = rows.Scan(&scope); err != nil {
			return nil, err
		}
		counts[Scope(scope).String()]++
	}
	return counts, rows.Err()
}

func replaceNow(condition, parameter string) string {
	result := ""
	for index := 0; index < len(condition); index++ {
		if index+4 <= len(condition) && condition[index:index+4] == "$NOW" {
			result += parameter
			index += 3
			continue
		}
		result += string(condition[index])
	}
	return result
}
