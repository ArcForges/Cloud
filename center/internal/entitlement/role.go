// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

// The operator role is written by the migration role only, through `arcforges-center admin grant-operator` and `revoke-operator`
// (PLT-10): the runtime role cannot write identity.operator, so no request, however authorized, can make an operator. Both
// commands append their audit event in the transaction that writes the row.
const (
	AuditOperatorRoleGranted = "identity.operator.granted"
	AuditOperatorRoleRevoked = "identity.operator.revoked"

	// DefaultOperatorDays and MaxOperatorDays bound how long an operator row lasts: the role is for a bounded time (decision n2).
	DefaultOperatorDays = 30
	MaxOperatorDays     = 90

	// roleActor is the actor of both commands' audit events.
	roleActor = "operator:cli"
)

// The refusals of the role commands. Each is a condition of the request, not of the store.
var (
	ErrRoleReason       = errors.New("the reason must be 1 to 512 characters without control characters")
	ErrRoleDays         = errors.New("the days must be a whole number from 1 to 90")
	ErrRoleNoAccount    = errors.New("there is no such account")
	ErrRoleAccountState = errors.New("only an active account can be made an operator")
	ErrRoleAlreadyLive  = errors.New("the account already is an operator; revoke the role first to change its end")
)

// OperatorRole is the row a grant wrote.
type OperatorRole struct {
	OperatorID platform.ID
	Account    platform.ID
	GrantedAt  time.Time
	ExpiresAt  time.Time
}

// GrantOperatorRole makes an active account an operator for days days (1 to MaxOperatorDays) and appends the audit event
// identity.operator.granted in the caller's transaction. The reason is kept in the row (up to 512 characters) and only its length
// and digest in the audit. The bootstrap owner needs no row (it is an operator through identity.bootstrap) and may still be given
// one. An account that already holds a live row is refused: the end of a role is changed by revoking and granting it again.
func GrantOperatorRole(ctx context.Context, tx pgx.Tx, account platform.ID, days int, reason string, now time.Time) (OperatorRole, error) {
	switch {
	case !IsReason(reason):
		return OperatorRole{}, ErrRoleReason
	case days < 1 || days > MaxOperatorDays:
		return OperatorRole{}, ErrRoleDays
	}
	now = now.UTC().Truncate(time.Microsecond)
	var state int16
	switch err := tx.QueryRow(ctx, "SELECT state FROM identity.user WHERE user_id = $1 FOR SHARE", account).Scan(&state); {
	case errors.Is(err, pgx.ErrNoRows):
		return OperatorRole{}, ErrRoleNoAccount
	case err != nil:
		return OperatorRole{}, store.Sanitize("read the account", err)
	case state != 1:
		return OperatorRole{}, ErrRoleAccountState
	}
	var live bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM identity.operator WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2)", account, now).Scan(&live); err != nil {
		return OperatorRole{}, store.Sanitize("read the operator role", err)
	}
	if live {
		return OperatorRole{}, ErrRoleAlreadyLive
	}
	role := OperatorRole{OperatorID: platform.NewID(), Account: account, GrantedAt: now, ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour)}
	if _, err := tx.Exec(ctx, `INSERT INTO identity.operator (operator_id, user_id, granted_at, expires_at, granted_by, reason) VALUES ($1, $2, $3, $4, $5, $6)`,
		role.OperatorID, account, role.GrantedAt, role.ExpiresAt, roleActor, reason); err != nil {
		return OperatorRole{}, store.Sanitize("grant the operator role", err)
	}
	payload, err := json.Marshal(map[string]any{"operatorId": role.OperatorID.String(), "expiresAt": role.ExpiresAt.Format(time.RFC3339), "days": days,
		"reasonLength": utf16Length(reason), "reasonSha256": digestOf(reason)})
	if err != nil {
		return OperatorRole{}, err
	}
	_, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now, ActorRef: roleActor, EventType: AuditOperatorRoleGranted,
		TargetKind: "account", TargetID: account.String(), Payload: payload})
	return role, err
}

// RevokeOperatorRole ends every live operator row of the account now and appends identity.operator.revoked (with the number of rows
// ended, possibly none) in the caller's transaction. It cannot end the bootstrap owner's standing, which comes from
// identity.bootstrap and not from a row; the count says so when it is zero.
func RevokeOperatorRole(ctx context.Context, tx pgx.Tx, account platform.ID, now time.Time) (int64, error) {
	now = now.UTC().Truncate(time.Microsecond)
	tag, err := tx.Exec(ctx, "UPDATE identity.operator SET revoked_at = GREATEST($2, granted_at) WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > $2", account, now)
	if err != nil {
		return 0, store.Sanitize("revoke the operator role", err)
	}
	ended := tag.RowsAffected()
	payload, err := json.Marshal(map[string]any{"rowsEnded": ended})
	if err != nil {
		return 0, err
	}
	_, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now, ActorRef: roleActor, EventType: AuditOperatorRoleRevoked,
		TargetKind: "account", TargetID: account.String(), Payload: payload})
	return ended, err
}
