// SPDX-License-Identifier: AGPL-3.0-only

package commerce

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/commerce/paddle"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/session"
	"github.com/ArcForges/Cloud/center/internal/store"
)

const (
	subscriptionPending     int16 = 1
	subscriptionActive      int16 = 2
	subscriptionCancelAtEnd int16 = 3
	subscriptionGrace       int16 = 4
	subscriptionExpired     int16 = 5
	subscriptionRevoked     int16 = 6
	subscriptionUnknown     int16 = 7
)

var subscriptionNames = [...]string{"", "pending", "active", "cancel_at_term_end", "payment_grace", "expired", "revoked", "provider_unknown"}

type storedSubscription struct {
	SubscriptionView
	Account                             platform.ID
	CheckoutID                          *platform.ID
	Customer, Reference, Product, Price string
	ProviderUpdate                      time.Time
	ProviderDigest                      []byte
	state                               int16
}

const subscriptionColumns = `subscription_id,account_id,checkout_id,catalog_version,provider_customer_ref,
provider_subscription_ref,product_ref,price_ref,valid_from,valid_until,auto_renew,rev,provider_updated_at,provider_snapshot_sha256,state`

func scanSubscription(row pgx.Row) (storedSubscription, error) {
	var result storedSubscription
	var start, end *time.Time
	err := row.Scan(&result.ID, &result.Account, &result.CheckoutID, &result.CatalogueVersion, &result.Customer, &result.Reference,
		&result.Product, &result.Price, &start, &end, &result.AutoRenew, &result.Revision, &result.ProviderUpdate, &result.ProviderDigest, &result.state)
	if start != nil && end != nil {
		result.PeriodStart, result.PeriodEnd = *start, *end
	}
	if err == nil {
		result.State = subscriptionNames[result.state]
	}
	return result, err
}

func (s *Service) subscription(ctx context.Context, actor Actor, id platform.ID) (storedSubscription, error) {
	var result storedSubscription
	err := s.read(ctx, actor, func(ctx context.Context, tx pgx.Tx, now time.Time) error {
		var err error
		result, err = scanSubscription(tx.QueryRow(ctx, "SELECT "+subscriptionColumns+` FROM commerce.subscription
WHERE account_id=$1 AND provider=1 AND environment=$2 AND ($3::uuid='00000000-0000-0000-0000-000000000000' OR subscription_id=$3)
ORDER BY CASE WHEN state IN(2,3,4) AND valid_until>$4 THEN 0 ELSE 1 END, verified_at DESC,subscription_id DESC LIMIT 1`,
			actor.Account, s.environmentID, id, now))
		if errors.Is(err, pgx.ErrNoRows) {
			return arc.NotFound("subscription", id[:])
		}
		if err == nil && (result.state == subscriptionActive || result.state == subscriptionCancelAtEnd || result.state == subscriptionGrace) && !now.Before(result.PeriodEnd) {
			result.State = subscriptionNames[subscriptionExpired]
		}
		return err
	})
	return result, err
}

func (s *Service) GetSubscription(ctx context.Context, actor Actor) (SubscriptionView, error) {
	result, err := s.subscription(ctx, actor, platform.ID{})
	return result.SubscriptionView, err
}

func (s *Service) CreatePortal(ctx context.Context, actor Actor, id platform.ID) (string, error) {
	if id == (platform.ID{}) {
		return "", arc.InvalidArgument("subscription_id", "required")
	}
	var bound storedSubscription
	err := s.db.InTx(ctx, "admit a subscription portal", store.TxOptions{Timeout: 5 * time.Second},
		func(ctx context.Context, tx pgx.Tx) error {
			now := s.now()
			if err := actorCurrent(ctx, tx, actor, now, true); err != nil {
				return err
			}
			var err error
			bound, err = scanSubscription(tx.QueryRow(ctx, "SELECT "+subscriptionColumns+` FROM commerce.subscription
WHERE subscription_id=$1 AND account_id=$2 AND provider=1 AND environment=$3`, id, actor.Account, s.environmentID))
			if errors.Is(err, pgx.ErrNoRows) {
				return arc.NotFound("subscription", id[:])
			}
			if err != nil {
				return err
			}
			if err = identity.ConsumeEvidence(ctx, tx, actor.identityCaller(), "commerce.portal", id, now); err != nil {
				return err
			}
			return s.audit(ctx, tx, now, actor.Account, "portal_admitted", "subscription", id, nil, &actor.Correlation)
		})
	if err != nil {
		return "", err
	}
	location, err := s.provider.CreatePortal(ctx, bound.Customer, bound.Reference)
	if err != nil {
		// The used proof and ephemeral provider link are never replayed.
		return "", arc.Internal()
	}
	if _, err = s.subscription(ctx, actor, id); err != nil {
		return "", err
	}
	return location, nil
}

func (actor Actor) identityCaller() identity.Caller {
	return identity.Caller{UserID: actor.Account, SessionID: actor.Session, DeviceID: actor.Device,
		Scope: session.ScopeAccount.String(), Browser: true, AuthEpoch: actor.AuthEpoch, RecoveryGeneration: actor.RecoveryGeneration}
}

func (s *Service) ListBilling(ctx context.Context, actor Actor, query BillingQuery) (BillingPage, error) {
	if query.Limit <= 0 || query.Limit > 100 || query.From.IsZero() || !query.From.Before(query.Until) ||
		(query.Before.IsZero() != (query.BeforeID == (platform.ID{}))) ||
		(!query.Before.IsZero() && (query.Before.Before(query.From) || !query.Before.Before(query.Until))) {
		return BillingPage{}, arc.InvalidArgument("period", "billing_bounds")
	}
	var result BillingPage
	err := s.read(ctx, actor, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		var before *time.Time
		if !query.Before.IsZero() {
			before = &query.Before
		}
		rows, err := tx.Query(ctx, `SELECT entry_id,kind,currency,amount_minor::bigint,occurred_at FROM commerce.billing_entry
WHERE account_id=$1 AND provider=1 AND environment=$2 AND occurred_at>=$3 AND occurred_at<$4
AND ($5::timestamptz IS NULL OR (occurred_at,entry_id)<($5,$6))
ORDER BY occurred_at DESC, entry_id DESC LIMIT $7`, actor.Account, s.environmentID, query.From, query.Until, before, query.BeforeID, query.Limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item BillingEntry
			var kind int16
			if err = rows.Scan(&item.ID, &kind, &item.Currency, &item.AmountMinor, &item.OccurredAt); err != nil {
				return err
			}
			item.Kind = [...]string{"", "payment", "refund", "chargeback", "credit", "credit_reversal", "chargeback_reversal"}[kind]
			result.Items = append(result.Items, item)
		}
		if len(result.Items) > query.Limit {
			result.HasMore = true
			result.Items = result.Items[:query.Limit]
		}
		return rows.Err()
	})
	return result, err
}

func (s *Service) SetRenewal(ctx context.Context, actor Actor, request RenewalRequest) (SubscriptionView, error) {
	if request.SubscriptionID == (platform.ID{}) || request.ExpectedRevision <= 0 {
		return SubscriptionView{}, arc.InvalidArgument("subscription_id", "renewal_revision")
	}
	method := "CancelSubscription"
	if request.AutoRenew {
		method = "ReactivateSubscription"
	}
	claimed, err := s.reserve(ctx, actor, request.CommandID, method, request.CommandPayload,
		func(ctx context.Context, tx pgx.Tx, now time.Time, digest [32]byte) (bool, error) {
			var original platform.ID
			var recorded []byte
			err := tx.QueryRow(ctx, `SELECT subscription_id,intent_sha256 FROM commerce.renewal
WHERE account_id=$1 AND command_id=$2`, actor.Account, request.CommandID).Scan(&original, &recorded)
			if err == nil {
				if original != request.SubscriptionID || !bytes.Equal(recorded, digest[:]) {
					return false, arc.CommandIDReused()
				}
				return false, nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return false, err
			}
			sub, err := scanSubscription(tx.QueryRow(ctx, "SELECT "+subscriptionColumns+` FROM commerce.subscription
WHERE subscription_id=$1 AND account_id=$2 AND provider=1 AND environment=$3 FOR UPDATE`, request.SubscriptionID, actor.Account, s.environmentID))
			if errors.Is(err, pgx.ErrNoRows) {
				return false, arc.NotFound("subscription", request.SubscriptionID[:])
			}
			if err != nil {
				return false, err
			}
			if sub.Revision != request.ExpectedRevision {
				return false, arc.RevisionConflict(request.ExpectedRevision, sub.Revision)
			}
			if !now.Before(sub.PeriodEnd) || (sub.state != subscriptionActive && sub.state != subscriptionCancelAtEnd) {
				return false, arc.InvalidState("subscription", "renewal_unavailable")
			}
			if !request.AutoRenew {
				if err := identity.ConsumeEvidence(ctx, tx, actor.identityCaller(), "commerce.cancelSubscription", sub.ID, now); err != nil {
					return false, err
				}
			}
			var claimAt *time.Time
			var resultRev *int64
			var resultFrom, resultUntil *time.Time
			state := int16(2)
			needsSend := sub.AutoRenew != request.AutoRenew
			if needsSend {
				state = 3
				claimAt = &now
			} else {
				resultRev = &sub.Revision
				resultFrom, resultUntil = &sub.PeriodStart, &sub.PeriodEnd
			}
			tag, err := tx.Exec(ctx, `INSERT INTO commerce.renewal(renewal_id,subscription_id,account_id,command_id,provider,environment,
intent_sha256,auto_renew,state,send_claimed_at,result_subscription_rev,result_valid_from,result_valid_until,created_at,updated_at)
VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13) ON CONFLICT DO NOTHING`,
				platform.NewID(), sub.ID, actor.Account, request.CommandID, s.environmentID, digest[:], request.AutoRenew, state, claimAt, resultRev, resultFrom, resultUntil, now)
			if err != nil {
				return false, err
			}
			if tag.RowsAffected() != 1 {
				return false, arc.InvalidState("subscription", "renewal_already_pending")
			}
			return needsSend, s.audit(ctx, tx, now, actor.Account, "renewal_reserved", "subscription", sub.ID, &request.CommandID, &actor.Correlation)
		})
	if err != nil {
		return SubscriptionView{}, err
	}
	if result, applied, err := s.renewalResult(ctx, actor, request); err != nil || applied {
		return result, err
	}
	sub, err := s.subscription(ctx, actor, request.SubscriptionID)
	if err != nil {
		return SubscriptionView{}, err
	}
	var fact paddle.Subscription
	if claimed {
		if request.AutoRenew {
			fact, err = s.provider.ResumeRenewal(ctx, sub.Reference)
		} else {
			fact, err = s.provider.CancelAtPeriodEnd(ctx, sub.Reference)
		}
	} else {
		fact, err = s.provider.GetSubscription(ctx, sub.Reference)
	}
	if err == nil {
		err = s.recordRenewal(ctx, sub, fact, request.CommandID, request.AutoRenew)
		if err != nil {
			return SubscriptionView{}, err
		}
	}
	result, applied, err := s.renewalResult(ctx, actor, request)
	if err != nil {
		return SubscriptionView{}, err
	}
	if !applied {
		// The durable claim may have reached Paddle. No second mutation can
		// be sent by a replay, and the last verified read is not its result.
		return SubscriptionView{}, arc.Internal()
	}
	return result, nil
}

func (s *Service) renewalResult(ctx context.Context, actor Actor, request RenewalRequest) (SubscriptionView, bool, error) {
	result := SubscriptionView{ID: request.SubscriptionID}
	applied := false
	err := s.read(ctx, actor, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		var state int16
		var revision *int64
		var from, until *time.Time
		err := tx.QueryRow(ctx, `SELECT r.state,r.result_subscription_rev,r.result_valid_from,r.result_valid_until,
s.catalog_version,r.auto_renew FROM commerce.renewal r JOIN commerce.subscription s ON s.subscription_id=r.subscription_id
WHERE r.account_id=$1 AND r.command_id=$2 AND r.subscription_id=$3 AND r.provider=1 AND r.environment=$4`,
			actor.Account, request.CommandID, request.SubscriptionID, s.environmentID).
			Scan(&state, &revision, &from, &until, &result.CatalogueVersion, &result.AutoRenew)
		if errors.Is(err, pgx.ErrNoRows) {
			return arc.NotFound("renewal", request.CommandID[:])
		}
		if err != nil || state != 2 {
			return err
		}
		if revision == nil || from == nil || until == nil {
			return errors.New("applied renewal lacks its bound period")
		}
		applied = true
		result.Revision, result.PeriodStart, result.PeriodEnd = *revision, *from, *until
		result.State = subscriptionNames[subscriptionActive]
		if !result.AutoRenew {
			result.State = subscriptionNames[subscriptionCancelAtEnd]
		}
		return nil
	})
	return result, applied, err
}

func providerSnapshot(fact paddle.Subscription) [32]byte {
	raw, _ := json.Marshal(fact)
	return sha256.Sum256(raw)
}

func providerSnapshotCurrent(sub storedSubscription, at time.Time, digest [32]byte) bool {
	return at.After(sub.ProviderUpdate) || at.Equal(sub.ProviderUpdate) && bytes.Equal(sub.ProviderDigest, digest[:])
}

func renewalMatches(sub storedSubscription, fact paddle.Subscription) bool {
	return fact.ID == sub.Reference && fact.CustomerID == sub.Customer && fact.CollectionMode == "automatic" &&
		oneProduct(fact.Items, sub.Price, sub.Product) && !fact.UpdatedAt.IsZero()
}

func verifiedAutoRenew(fact paddle.Subscription) bool {
	return fact.Status != "canceled" && fact.ScheduledAction != "cancel"
}

func (s *Service) recordRenewal(ctx context.Context, sub storedSubscription, fact paddle.Subscription, command platform.ID, wanted bool) error {
	if !renewalMatches(sub, fact) || verifiedAutoRenew(fact) != wanted {
		return nil
	}
	return s.db.InTx(ctx, "reconcile a subscription renewal", store.TxOptions{Timeout: 5 * time.Second},
		func(ctx context.Context, tx pgx.Tx) error {
			security, err := lockAccount(ctx, tx, sub.Account)
			if err != nil {
				return err
			}
			current, err := scanSubscription(tx.QueryRow(ctx, "SELECT "+subscriptionColumns+` FROM commerce.subscription
WHERE subscription_id=$1 AND account_id=$2 AND provider=1 AND environment=$3 FOR UPDATE`, sub.ID, sub.Account, s.environmentID))
			if err != nil {
				return err
			}
			at := fact.UpdatedAt.UTC().Truncate(time.Microsecond)
			digest := providerSnapshot(fact)
			if !providerSnapshotCurrent(current, at, digest) {
				return nil
			}
			now := s.now()
			newState := current.state
			switch {
			case !wanted && fact.Status == "canceled" && !now.Before(current.PeriodEnd):
				newState = subscriptionExpired
			case current.state == subscriptionActive || current.state == subscriptionCancelAtEnd:
				if wanted {
					newState = subscriptionActive
				} else {
					newState = subscriptionCancelAtEnd
				}
			}
			rev := current.Revision
			if current.AutoRenew != wanted || newState != current.state || at.After(current.ProviderUpdate) {
				if err = tx.QueryRow(ctx, `UPDATE commerce.subscription SET state=$2,auto_renew=$3,provider_updated_at=$4,provider_snapshot_sha256=$5,
verified_at=$6,rev=rev+1 WHERE subscription_id=$1 RETURNING rev`, sub.ID, newState, wanted, at, digest[:], now).Scan(&rev); err != nil {
					return err
				}
			}
			tag, err := tx.Exec(ctx, `UPDATE commerce.renewal SET state=2,result_subscription_rev=$4,updated_at=$5,
result_valid_from=$6,result_valid_until=$7 WHERE account_id=$1 AND command_id=$2 AND subscription_id=$3 AND state IN(1,3)`,
				sub.Account, command, sub.ID, rev, now, current.PeriodStart, current.PeriodEnd)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			if security.State < 5 {
				if _, err = s.entitlements.ApplyCommerce(ctx, tx, entitlement.CommerceChange{
					AccountID: sub.Account.String(), DefinitionsVersion: s.entitlements.DefinitionsVersion(),
					EventRef: "renewal:" + command.String(), AutoRenew: &wanted,
				}); err != nil {
					return err
				}
			}
			return s.audit(ctx, tx, now, sub.Account, "renewal_reconciled", "subscription", sub.ID, &command, nil)
		})
}
