// SPDX-License-Identifier: AGPL-3.0-only
package commerce

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

const deletionRenewalNamespace = "arcforges.v2.billing.deletion-renewal.v1\n"

type deletionRenewal struct {
	operation, account, subscription, command platform.ID
}

// A confirmed account deletion authorizes only the exact account's known
// provider subscription to stop renewing. The committed claim serializes with
// withdrawal: a prior withdrawal blocks the send; a later withdrawal preserves
// any provider effect already admitted and never re-enables renewal.
func (s *Service) reconcileDeletion(ctx context.Context) error {
	var target deletionRenewal
	var sub storedSubscription
	claimed := false
	err := s.db.InTx(ctx, "claim a confirmed deletion renewal", store.TxOptions{Timeout: 5 * time.Second},
		func(ctx context.Context, tx pgx.Tx) error {
			claimed = false
			now := s.now()
			var err error
			target, err = s.nextDeletionRenewal(ctx, tx, now)
			if err != nil || target.command == (platform.ID{}) {
				return err
			}
			security, err := lockAccount(ctx, tx, target.account)
			if err != nil || security.State != 4 {
				return err
			}
			var confirmed bool
			err = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM identity.lifecycle_operation
WHERE operation_id=$1 AND user_id=$2 AND kind=2 AND state=3
AND confirmed_at<expires_at AND confirmed_at<=$3 AND proof_id IS NOT NULL AND command_id IS NOT NULL)`,
				target.operation, target.account, now).Scan(&confirmed)
			if err != nil || !confirmed {
				return err
			}
			sub, err = scanSubscription(tx.QueryRow(ctx, "SELECT "+subscriptionColumns+` FROM commerce.subscription
WHERE subscription_id=$1 AND account_id=$2 AND provider=1 AND environment=$3 AND auto_renew
AND checkout_id IS NOT NULL AND valid_from IS NOT NULL AND valid_until IS NOT NULL FOR UPDATE`,
				target.subscription, target.account, s.environmentID))
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			digest := sha256.Sum256([]byte(deletionRenewalNamespace + target.operation.String() + "\n" + sub.ID.String()))
			if target.command != platform.ID(digest[:16]) {
				return errors.New("the deletion renewal command does not match its durable identity")
			}
			tag, err := tx.Exec(ctx, `INSERT INTO commerce.renewal(renewal_id,subscription_id,account_id,command_id,provider,environment,
intent_sha256,auto_renew,state,send_claimed_at,created_at,updated_at)
VALUES($1,$2,$3,$1,1,$4,$5,false,3,$6,$6,$6) ON CONFLICT DO NOTHING`,
				target.command, sub.ID, sub.Account, s.environmentID, digest[:], now)
			if err != nil || tag.RowsAffected() != 1 {
				return err
			}
			_, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), OccurredAt: now,
				ActorRef: target.account.String(), EventType: "commerce.deletion_renewal_claimed", Reason: "confirmed_account_deletion",
				CommandID: &target.command, TargetKind: "subscription", TargetID: sub.ID.String(),
				Payload: []byte(`{"deletionOperation":"` + target.operation.String() + `"}`)})
			claimed = err == nil
			return err
		})
	if err != nil || !claimed {
		return err
	}
	fact, err := s.provider.CancelAtPeriodEnd(ctx, sub.Reference)
	if err != nil {
		// A lost reply retains the unresolved original for the ordinary
		// renewal reader. No subsequent worker resends this mutation.
		return nil
	}
	return s.recordRenewal(ctx, sub, fact, target.command, false)
}

func (s *Service) nextDeletionRenewal(ctx context.Context, tx pgx.Tx, now time.Time) (deletionRenewal, error) {
	var target deletionRenewal
	err := tx.QueryRow(ctx, `SELECT o.operation_id, s.account_id, s.subscription_id, binding.id
FROM commerce.subscription s
JOIN identity.user u ON u.user_id=s.account_id AND u.state=4
JOIN identity.lifecycle_operation o ON o.user_id=s.account_id AND o.kind=2 AND o.state=3
CROSS JOIN LATERAL (
  SELECT substring(encode(sha256(convert_to($3::text||o.operation_id::text||chr(10)||s.subscription_id::text,'UTF8')),'hex'),1,32)::uuid AS id
) binding
WHERE s.provider=1 AND s.environment=$1 AND s.auto_renew AND s.checkout_id IS NOT NULL AND s.valid_from IS NOT NULL AND s.valid_until IS NOT NULL
AND o.confirmed_at<o.expires_at AND o.confirmed_at<=$2 AND o.proof_id IS NOT NULL AND o.command_id IS NOT NULL
AND NOT EXISTS (SELECT 1 FROM commerce.renewal r WHERE r.account_id=s.account_id
  AND (r.command_id=binding.id OR (r.subscription_id=s.subscription_id AND r.state IN (1,3))))
ORDER BY o.confirmed_at,o.operation_id,s.subscription_id LIMIT 1`, s.environmentID, now, deletionRenewalNamespace).
		Scan(&target.operation, &target.account, &target.subscription, &target.command)
	if errors.Is(err, pgx.ErrNoRows) {
		return deletionRenewal{}, nil
	}
	return target, err
}

func (s *Service) reconcileDeletionTerminal(ctx context.Context) error {
	var target deletionRenewal
	var sub storedSubscription
	err := s.db.InTx(ctx, "read a deletion subscription after its paid term", store.TxOptions{ReadOnly: true, Timeout: 5 * time.Second},
		func(ctx context.Context, tx pgx.Tx) error {
			now := s.now()
			err := tx.QueryRow(ctx, `SELECT o.operation_id,s.account_id,s.subscription_id
FROM commerce.subscription s JOIN identity.user u ON u.user_id=s.account_id AND u.state=4
JOIN identity.lifecycle_operation o ON o.user_id=s.account_id AND o.kind=2 AND o.state=3
WHERE s.provider=1 AND s.environment=$1 AND s.checkout_id IS NOT NULL AND NOT s.auto_renew
AND s.state<>5 AND s.valid_until<=$2
AND o.confirmed_at<o.expires_at AND o.confirmed_at<=$2 AND o.proof_id IS NOT NULL AND o.command_id IS NOT NULL
ORDER BY s.valid_until,s.subscription_id LIMIT 1`, s.environmentID, now).
				Scan(&target.operation, &target.account, &target.subscription)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			sub, err = scanSubscription(tx.QueryRow(ctx, "SELECT "+subscriptionColumns+` FROM commerce.subscription
WHERE subscription_id=$1 AND account_id=$2 AND provider=1 AND environment=$3`, target.subscription, target.account, s.environmentID))
			return err
		})
	if err != nil || target.subscription == (platform.ID{}) {
		return err
	}
	fact, err := s.provider.GetSubscription(ctx, sub.Reference)
	if err != nil || fact.Status != "canceled" || !renewalMatches(sub, fact) {
		return nil
	}
	return s.db.InTx(ctx, "verify terminal provider cancellation after deletion", store.TxOptions{Timeout: 5 * time.Second},
		func(ctx context.Context, tx pgx.Tx) error {
			security, err := lockAccount(ctx, tx, target.account)
			if err != nil || security.State != 4 {
				return err
			}
			now := s.now()
			var confirmed bool
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM identity.lifecycle_operation
WHERE operation_id=$1 AND user_id=$2 AND kind=2 AND state=3
AND confirmed_at<expires_at AND confirmed_at<=$3 AND proof_id IS NOT NULL AND command_id IS NOT NULL)`,
				target.operation, target.account, now).Scan(&confirmed)
			if err != nil || !confirmed {
				return err
			}
			digest := providerSnapshot(fact)
			at := fact.UpdatedAt.UTC().Truncate(time.Microsecond)
			tag, err := tx.Exec(ctx, `UPDATE commerce.subscription SET state=5,provider_updated_at=$3,
provider_snapshot_sha256=$4,verified_at=$5,rev=rev+1
WHERE subscription_id=$1 AND account_id=$2 AND provider=1 AND environment=$6 AND NOT auto_renew
AND state<>5 AND valid_until<=$5
AND (provider_updated_at<$3 OR provider_updated_at=$3 AND provider_snapshot_sha256=$4)`,
				sub.ID, sub.Account, at, digest[:], now, s.environmentID)
			if err != nil || tag.RowsAffected() != 1 {
				return err
			}
			return s.audit(ctx, tx, now, sub.Account, "deletion_provider_terminal", "subscription", sub.ID, nil, nil)
		})
}
