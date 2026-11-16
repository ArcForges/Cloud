// SPDX-License-Identifier: AGPL-3.0-only

package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/ratelimit"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

const (
	LifecycleRecovery      int16 = 1
	LifecycleDeletion      int16 = 2
	LifecycleExport        int16 = 3
	LifecycleAwaitingProof int16 = 1
	LifecycleConfirmed     int16 = 2
	LifecycleProcessing    int16 = 3
	LifecycleCompleted     int16 = 4
	LifecycleFailed        int16 = 5
	LifecycleExpired       int16 = 6
	LifecycleRevoked       int16 = 7
	ClassConfirmDeletion         = "identity.confirmAccountDeletion"
	ClassCancelDeletion          = "identity.cancelAccountDeletion"
	ClassExportAccount           = "identity.exportAccount"
	lifecyclePlanTTL             = 15 * time.Minute
	exportTTL                    = 15 * time.Minute
)

// Lifecycle is retained, content-free account lifecycle evidence. A processing
// deletion with a blocker has not completed external cleanup or a retention purge.
type Lifecycle struct {
	ID                                        platform.ID
	Kind, State                               int16
	PlanRevision, Revision                    int64
	ExpiresAt                                 time.Time
	ActiveSubscriptions, UnresolvedOperations int
	BlockedReason                             int16
	ExportBytes                               int64
}

// CheckLifecycleRate applies the existing sensitive-account and network budgets
// before a transport enters its command transaction. ReadExport calls it itself.
func (s *Service) CheckLifecycleRate(ctx context.Context, caller Caller) error {
	if err := s.take(ctx, caller.Request, s.bucket(ratelimit.SignInPrefix, "lifecycle:"+ratelimit.Prefix(caller.ClientIP)), Actor(caller.UserID)); err != nil {
		return err
	}
	return s.take(ctx, caller.Request, s.bucket(ratelimit.StepUpAccount, "lifecycle:"+caller.UserID.String()), Actor(caller.UserID))
}

type storedLifecycle struct {
	Lifecycle
	authEpoch, recoveryGeneration int64
	commandID                     *platform.ID
	intent, exportDigest          []byte
	priorAccountState             int16
}

const lifecycleColumns = `operation_id, kind, state, plan_rev, rev, expires_at, active_subscription_count,
    unresolved_operation_count, blocked_reason, coalesce(export_bytes, 0), auth_epoch, recovery_generation,
    command_id, intent_sha256, export_sha256, prior_account_state`

func scanLifecycle(row pgx.Row) (storedLifecycle, error) {
	var result storedLifecycle
	err := row.Scan(&result.ID, &result.Kind, &result.State, &result.PlanRevision, &result.Revision, &result.ExpiresAt,
		&result.ActiveSubscriptions, &result.UnresolvedOperations, &result.BlockedReason, &result.ExportBytes,
		&result.authEpoch, &result.recoveryGeneration, &result.commandID, &result.intent, &result.exportDigest, &result.priorAccountState)
	return result, err
}

func lifecycleOf(ctx context.Context, tx pgx.Tx, userID, operationID platform.ID, lock bool) (storedLifecycle, error) {
	query := `SELECT ` + lifecycleColumns + ` FROM identity.lifecycle_operation WHERE operation_id = $1 AND user_id = $2`
	if lock {
		query += ` FOR UPDATE`
	}
	result, err := scanLifecycle(tx.QueryRow(ctx, query, operationID, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return result, arc.NotFound("lifecycle_operation", operationID[:])
	}
	return result, err
}

// lockLifecycleCaller rechecks the session inside the transaction doing the
// sensitive work. A resolved HTTP caller alone never authorizes an export read.
func lockLifecycleCaller(ctx context.Context, tx pgx.Tx, caller Caller, now time.Time, write bool) (session.AccountSecurity, error) {
	return lockCurrentCaller(ctx, tx, caller, now, write, false)
}

// RecheckCaller fences ordinary account writes against a concurrent recovery or
// deletion. Pending-deletion lifecycle methods use their narrower admission.
func RecheckCaller(ctx context.Context, tx pgx.Tx, caller Caller, now time.Time) error {
	security, err := lockCurrentCaller(ctx, tx, caller, now, true, true)
	if err != nil {
		return err
	}
	if !UserState(security.State).MaySignIn() {
		return arc.PermissionDenied("identity.account")
	}
	return nil
}

func lockCurrentCaller(ctx context.Context, tx pgx.Tx, caller Caller, now time.Time, write, allowMobile bool) (session.AccountSecurity, error) {
	if write {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM identity.user WHERE user_id = $1 FOR UPDATE`, caller.UserID); err != nil {
			return session.AccountSecurity{}, err
		}
	}
	security, err := session.LockAccountSecurity(ctx, tx, caller.UserID)
	if err != nil {
		return security, err
	}
	scope := session.ScopeAccount
	if allowMobile && caller.Scope == "mobile.limited" {
		scope = session.ScopeMobileLimited
	}
	if caller.Scope != scope.String() || !security.AdmitsScope(scope) {
		return security, arc.PermissionDenied("identity.lifecycle")
	}
	if caller.AuthEpoch != security.AuthEpoch || caller.RecoveryGeneration != security.RecoveryGeneration {
		return security, arc.CredentialRevoked()
	}
	var live bool
	err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM identity.session s
JOIN device.device d ON d.device_id = s.device_id JOIN device.installation i ON i.installation_id = s.installation_id
WHERE s.session_id = $1 AND s.user_id = $2 AND s.device_id = $3 AND s.scope = $8
AND s.credential_kind = $4 AND s.revoked_at IS NULL AND d.revoked_at IS NULL AND i.revoked_at IS NULL
AND s.auth_epoch = $5 AND s.recovery_generation = $6 AND s.expires_at > $7
AND ((s.credential_kind = 1 AND s.access_expires_at > $7) OR (s.credential_kind = 2 AND s.idle_expires_at > $7)))`,
		caller.SessionID, caller.UserID, caller.DeviceID, map[bool]int16{false: 1, true: 2}[caller.Browser], security.AuthEpoch, security.RecoveryGeneration, now, int16(scope)).Scan(&live)
	if err != nil {
		return security, err
	}
	if !live {
		return security, arc.CredentialRevoked()
	}
	return security, nil
}

func lifecycleIntent(kind int16, userID, operationID platform.ID) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("arcforges.lifecycle.v1\n%d\n%s\n%s", kind, userID.String(), operationID.String())))
}

// deletionFacts reads the retained provider/remote facts. A subscription reference
// or renewal/pending purchase is not proof that a provider has cancelled billing.
func deletionFacts(ctx context.Context, tx pgx.Tx, userID platform.ID, now time.Time) (subscriptions, unresolved int, provider bool, err error) {
	err = tx.QueryRow(ctx, `SELECT
 (SELECT count(DISTINCT subscription_ref) FROM entitlement.service_term t WHERE t.account_id = $1 AND t.kind = 1
   AND coalesce(t.grace_ends_at,t.ends_at) > $2 AND NOT EXISTS (SELECT 1 FROM entitlement.service_term_action a
       WHERE a.account_id = t.account_id AND a.term_id = t.term_id AND a.effective_at <= $2)),
 (SELECT count(*) FROM management.remote_operation WHERE account_id = $1 AND (final_at IS NULL OR effect = 3)) +
 (SELECT count(*) FROM management.legacy_outcome WHERE account_id = $1 AND (final_at IS NULL OR legacy_state = 7)),
 EXISTS (SELECT 1 FROM entitlement.service_term WHERE account_id = $1 AND subscription_ref IS NOT NULL)
 OR coalesce((SELECT auto_renew OR purchase_pending FROM entitlement.account_status_fact WHERE account_id = $1
     ORDER BY recorded_at DESC, status_fact_id DESC LIMIT 1),false)`, userID, now).Scan(&subscriptions, &unresolved, &provider)
	return
}

// PrepareDeletion creates an expiring revision-bound plan. The surrounding
// platform command receipt supplies idempotency; its command is not a proof.
func (s *Service) PrepareDeletion(ctx context.Context, tx pgx.Tx, caller Caller, commandID platform.ID, now time.Time) (Lifecycle, error) {
	security, err := lockLifecycleCaller(ctx, tx, caller, now, true)
	if err != nil {
		return Lifecycle{}, err
	}
	if security.State != int16(StateActive) && security.State != int16(StateRestricted) {
		return Lifecycle{}, arc.InvalidState("account", "pending_deletion")
	}
	subscriptions, unresolved, provider, err := deletionFacts(ctx, tx, caller.UserID, now)
	if err != nil {
		return Lifecycle{}, err
	}
	blocked := int16(0)
	if provider {
		blocked = 1
	} else if unresolved > 0 {
		blocked = 3
	}
	if _, err = tx.Exec(ctx, `UPDATE identity.lifecycle_operation SET state = 6, finished_at = $2, rev = rev + 1
WHERE user_id = $1 AND kind = 2 AND state = 1 AND expires_at <= $2`, caller.UserID, now); err != nil {
		return Lifecycle{}, err
	}
	var existing platform.ID
	err = tx.QueryRow(ctx, `SELECT operation_id FROM identity.lifecycle_operation WHERE user_id = $1 AND kind = 2 AND state IN (1,2,3)`, caller.UserID).Scan(&existing)
	if err == nil {
		result, err := lifecycleOf(ctx, tx, caller.UserID, existing, false)
		if err != nil {
			return Lifecycle{}, err
		}
		if result.State == LifecycleAwaitingProof && (result.authEpoch != security.AuthEpoch || result.recoveryGeneration != security.RecoveryGeneration ||
			result.ActiveSubscriptions != subscriptions || result.UnresolvedOperations != unresolved || result.BlockedReason != blocked || result.priorAccountState != security.State) {
			if _, err = tx.Exec(ctx, `UPDATE identity.lifecycle_operation SET state=7,finished_at=$2,rev=rev+1 WHERE operation_id=$1`, existing, now); err != nil {
				return Lifecycle{}, err
			}
		} else {
			return result.Lifecycle, nil
		}
	}
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Lifecycle{}, err
	}
	result := Lifecycle{ID: platform.NewID(), Kind: LifecycleDeletion, State: LifecycleAwaitingProof, PlanRevision: 1, Revision: 1,
		ExpiresAt: now.Add(lifecyclePlanTTL), ActiveSubscriptions: subscriptions, UnresolvedOperations: unresolved}
	if provider {
		result.BlockedReason = 1
	} else if unresolved > 0 {
		result.BlockedReason = 3
	}
	intent := lifecycleIntent(result.Kind, caller.UserID, result.ID)
	_, err = tx.Exec(ctx, `INSERT INTO identity.lifecycle_operation(operation_id,user_id,kind,state,plan_rev,intent_sha256,
auth_epoch,recovery_generation,created_at,expires_at,rev,active_subscription_count,unresolved_operation_count,blocked_reason,prior_account_state)
VALUES($1,$2,2,1,1,$3,$4,$5,$6,$7,1,$8,$9,$10,$11)`, result.ID, caller.UserID, intent[:], security.AuthEpoch, security.RecoveryGeneration,
		now, result.ExpiresAt, subscriptions, unresolved, result.BlockedReason, security.State)
	if err != nil {
		return Lifecycle{}, err
	}
	err = s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "identity.deletion.prepared", "", "lifecycle_operation", result.ID.String(),
		map[string]any{"planRevision": result.PlanRevision, "subscriptions": subscriptions, "unresolved": unresolved})
	return result, err
}

// ConfirmDeletion consumes the plan's fresh proof and revokes every enrollment
// and session, including the caller, in the same transaction as pending deletion.
func (s *Service) ConfirmDeletion(ctx context.Context, tx pgx.Tx, caller Caller, operationID platform.ID, planRevision int64, commandID platform.ID, now time.Time) (Lifecycle, error) {
	if _, err := s.CancelApprovals(ctx, tx, caller.UserID, now); err != nil {
		return Lifecycle{}, err
	}
	security, err := lockLifecycleCaller(ctx, tx, caller, now, true)
	if err != nil {
		return Lifecycle{}, err
	}
	item, err := lifecycleOf(ctx, tx, caller.UserID, operationID, true)
	if err != nil {
		return Lifecycle{}, err
	}
	if item.Kind != LifecycleDeletion || item.State != LifecycleAwaitingProof {
		return Lifecycle{}, arc.InvalidState("deletion_plan", "not_awaiting_proof")
	}
	if item.PlanRevision != planRevision {
		return Lifecycle{}, arc.RevisionConflict(planRevision, item.PlanRevision)
	}
	if !now.Before(item.ExpiresAt) {
		return Lifecycle{}, arc.Expired()
	}
	if item.authEpoch != security.AuthEpoch || item.recoveryGeneration != security.RecoveryGeneration {
		return Lifecycle{}, arc.Expired()
	}
	subscriptions, unresolved, provider, err := deletionFacts(ctx, tx, caller.UserID, now)
	if err != nil {
		return Lifecycle{}, err
	}
	blocked := int16(0)
	if provider {
		blocked = 1
	} else if unresolved > 0 {
		blocked = 3
	}
	if subscriptions != item.ActiveSubscriptions || unresolved != item.UnresolvedOperations || blocked != item.BlockedReason || security.State != item.priorAccountState {
		return Lifecycle{}, arc.InvalidState("deletion_plan", "facts_changed")
	}
	proofID, err := consumeLifecycleEvidence(ctx, tx, caller, ClassConfirmDeletion, operationID, now)
	if err != nil {
		return Lifecycle{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE identity.user SET state = 4, deletion_requested_at = $2, rev = rev + 1 WHERE user_id = $1`, caller.UserID, now); err != nil {
		return Lifecycle{}, err
	}
	if err = s.rotateAccountSecurity(ctx, tx, caller.UserID, false, now); err != nil {
		return Lifecycle{}, err
	}
	if err = s.revokeAccountDevices(ctx, tx, caller.UserID, now); err != nil {
		return Lifecycle{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE identity.lifecycle_operation SET state = 3, command_id = $3, confirmed_at = $4, proof_id = $5, rev = rev + 1
WHERE operation_id = $1 AND user_id = $2`, operationID, caller.UserID, commandID, now, proofID); err != nil {
		return Lifecycle{}, err
	}
	if _, err = platform.Enqueue(ctx, tx, platform.Message{DedupKey: "identity.deletion:" + operationID.String(), Topic: "identity.lifecycle.changed",
		AggregateKind: "account", AggregateID: caller.UserID, AggregateRev: item.Revision + 1, Payload: []byte(`{"kind":"deletion_pending"}`), CorrelationID: commandID}); err != nil {
		return Lifecycle{}, err
	}
	result, err := lifecycleOf(ctx, tx, caller.UserID, operationID, false)
	if err != nil {
		return Lifecycle{}, err
	}
	err = s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "identity.deletion.confirmed", "pending_cleanup", "lifecycle_operation", operationID.String(), map[string]any{"planRevision": planRevision})
	return result.Lifecycle, err
}

func (s *Service) rotateAccountSecurity(ctx context.Context, tx pgx.Tx, userID platform.ID, recovery bool, now time.Time) error {
	increment := 0
	if recovery {
		increment = 1
	}
	if _, err := tx.Exec(ctx, `UPDATE identity.account_security_state SET auth_epoch = auth_epoch + 1,
recovery_generation = recovery_generation + $3, changed_at = greatest(changed_at,$2), rev = rev + 1 WHERE user_id = $1`, userID, now, increment); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE identity.lifecycle_operation SET state = 7, finished_at = $2, rev = rev + 1
WHERE user_id = $1 AND kind = 3 AND state IN (1,2,3,4)`, userID, now)
	return err
}

func (s *Service) revokeAccountDevices(ctx context.Context, tx pgx.Tx, userID platform.ID, now time.Time) error {
	// The account lock fences new issuance; finite batches bound Go memory while
	// the enclosing transaction/time budget keeps the all-or-nothing cascade.
	for {
		rows, err := tx.Query(ctx, `SELECT device_id FROM device.device WHERE user_id = $1 AND revoked_at IS NULL ORDER BY device_id LIMIT 128`, userID)
		if err != nil {
			return err
		}
		var ids []platform.ID
		for rows.Next() {
			var id platform.ID
			if err = rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err = rows.Err(); err != nil {
			return err
		}
		if len(ids) == 0 {
			break
		}
		for _, id := range ids {
			if _, err = device.Revoke(ctx, tx, userID, id, device.RevokedByOwner, s.participants, now); err != nil {
				return err
			}
		}
	}
	session.Announce(ctx, session.Revocation{Users: []platform.ID{userID}})
	return nil
}

// CancelDeletion requires a new live account session and fresh evidence. It never
// reactivates any revoked device, session or old proof.
func (s *Service) CancelDeletion(ctx context.Context, tx pgx.Tx, caller Caller, operationID platform.ID, commandID platform.ID, now time.Time) (Lifecycle, error) {
	security, err := lockLifecycleCaller(ctx, tx, caller, now, true)
	if err != nil {
		return Lifecycle{}, err
	}
	item, err := lifecycleOf(ctx, tx, caller.UserID, operationID, true)
	if err != nil {
		return Lifecycle{}, err
	}
	if item.Kind != LifecycleDeletion || item.State != LifecycleAwaitingProof && item.State != LifecycleProcessing {
		return Lifecycle{}, arc.InvalidState("deletion", "not_cancellable")
	}
	if err = ConsumeEvidence(ctx, tx, caller, ClassCancelDeletion, operationID, now); err != nil {
		return Lifecycle{}, err
	}
	if security.State == int16(StatePendingDeletion) {
		if _, err = tx.Exec(ctx, `UPDATE identity.user SET state = $2, deletion_requested_at = NULL, rev = rev + 1 WHERE user_id = $1`, caller.UserID, item.priorAccountState); err != nil {
			return Lifecycle{}, err
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE identity.lifecycle_operation SET state = 7, finished_at = $2, rev = rev + 1 WHERE operation_id = $1`, operationID, now); err != nil {
		return Lifecycle{}, err
	}
	result, err := lifecycleOf(ctx, tx, caller.UserID, operationID, false)
	if err != nil {
		return Lifecycle{}, err
	}
	err = s.audit(ctx, tx, caller.Request, Actor(caller.UserID), "identity.deletion.cancelled", "", "lifecycle_operation", operationID.String(), map[string]any{"command": commandID.String()})
	return result.Lifecycle, err
}

func (s *Service) GetLifecycle(ctx context.Context, caller Caller, operationID platform.ID) (Lifecycle, error) {
	var result Lifecycle
	err := s.db.InTx(ctx, "read lifecycle evidence", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		now := s.now()
		security, err := lockLifecycleCaller(ctx, tx, caller, now, false)
		if err != nil {
			return err
		}
		item, err := lifecycleOf(ctx, tx, caller.UserID, operationID, false)
		if err == nil {
			item, err = settleLifecycleExpiry(ctx, tx, caller.UserID, item, security, now)
		}
		result = item.Lifecycle
		return err
	})
	return result, err
}

func (s *Service) GetDeletion(ctx context.Context, caller Caller) (*Lifecycle, error) {
	var result *Lifecycle
	err := s.db.InTx(ctx, "read account deletion", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		now := s.now()
		security, err := lockLifecycleCaller(ctx, tx, caller, now, false)
		if err != nil {
			return err
		}
		item, err := scanLifecycle(tx.QueryRow(ctx, `SELECT `+lifecycleColumns+` FROM identity.lifecycle_operation WHERE user_id = $1 AND kind = 2 ORDER BY created_at DESC,operation_id DESC LIMIT 1`, caller.UserID))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err == nil {
			item, err = settleLifecycleExpiry(ctx, tx, caller.UserID, item, security, now)
		}
		if err == nil {
			result = &item.Lifecycle
		}
		return err
	})
	return result, err
}

func settleLifecycleExpiry(ctx context.Context, tx pgx.Tx, userID platform.ID, item storedLifecycle, security session.AccountSecurity, now time.Time) (storedLifecycle, error) {
	state := int16(0)
	if item.State == LifecycleAwaitingProof || item.Kind == LifecycleExport && item.State == LifecycleCompleted {
		if !now.Before(item.ExpiresAt) {
			state = LifecycleExpired
		} else if item.authEpoch != security.AuthEpoch || item.recoveryGeneration != security.RecoveryGeneration {
			state = LifecycleRevoked
		}
	}
	if state == 0 {
		return item, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE identity.lifecycle_operation SET state=$2,finished_at=$3,rev=rev+1 WHERE operation_id=$1 AND state=$4 AND rev=$5`, item.ID, state, now, item.State, item.Revision); err != nil {
		return item, err
	}
	return lifecycleOf(ctx, tx, userID, item.ID, false)
}
