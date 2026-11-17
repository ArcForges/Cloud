// SPDX-License-Identifier: AGPL-3.0-only

package session

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/platform"
)

// AccountSecurity is the account's authoritative security generation. Session and
// proof snapshots never grant authority unless both numbers still match it.
type AccountSecurity struct {
	State                         int16
	AuthEpoch, RecoveryGeneration int64
}

// LockAccountSecurity takes the common account-before-session lock order. A
// caller changing account security first takes the user row FOR UPDATE; issuance
// and renewal hold this shared lock through their transaction's commit.
func LockAccountSecurity(ctx context.Context, tx pgx.Tx, userID platform.ID) (AccountSecurity, error) {
	var security AccountSecurity
	if err := tx.QueryRow(ctx, `SELECT state FROM identity.user WHERE user_id = $1 FOR SHARE`, userID).Scan(&security.State); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return security, arc.Unauthenticated()
		}
		return security, err
	}
	err := tx.QueryRow(ctx, `SELECT auth_epoch, recovery_generation FROM identity.account_security_state WHERE user_id = $1 FOR SHARE`, userID).
		Scan(&security.AuthEpoch, &security.RecoveryGeneration)
	return security, err
}

// AdmitsScope allows pending-deletion accounts to authenticate only an account
// session. The access table separately admits only lifecycle status/cancellation
// and their proof ceremony; remote and mobile authority stay denied.
func (s AccountSecurity) AdmitsScope(scope Scope) bool {
	return s.State == 1 || s.State == 2 || s.State == 4 && scope == ScopeAccount
}
