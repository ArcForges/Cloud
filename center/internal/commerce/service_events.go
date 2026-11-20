// SPDX-License-Identifier: AGPL-3.0-only

package commerce

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/commerce/paddle"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

func CheckEnvironment(ctx context.Context, db *store.DB, environment paddle.Environment, pin bool) error {
	var expected int16
	switch environment {
	case paddle.Live:
		expected = 1
	case paddle.Sandbox:
		expected = 2
	case "":
		if pin {
			return errors.New("an unconfigured commerce realm cannot be pinned")
		}
	default:
		return errors.New("unknown commerce realm")
	}
	return db.InTx(ctx, "check commerce realm", store.TxOptions{ReadOnly: !pin, Timeout: 5 * time.Second},
		func(ctx context.Context, tx pgx.Tx) error {
			if pin {
				if _, err := tx.Exec(ctx, `INSERT INTO commerce.provider_environment(singleton,environment)
VALUES(true,$1) ON CONFLICT(singleton) DO NOTHING`, expected); err != nil {
					return err
				}
			}
			var actual int16
			err := tx.QueryRow(ctx, "SELECT environment FROM commerce.provider_environment WHERE singleton").Scan(&actual)
			if errors.Is(err, pgx.ErrNoRows) && !pin {
				return nil
			}
			if err != nil {
				return err
			}
			if actual != expected {
				return errors.New("commerce database belongs to another provider realm")
			}
			return nil
		})
}

const (
	eventPending  int16 = 1
	eventApplied  int16 = 2
	eventRetry    int16 = 3
	eventRejected int16 = 4
	eventObsolete int16 = 5
)

var eventStates = [...]string{"", "pending", "applied", "retry", "rejected", "obsolete"}

func (s *Service) ReceiveEvent(ctx context.Context, event Event) (EventReceipt, error) {
	prefix := eventPrefix(event.Kind)
	if event.Environment != s.environment || event.Digest == ([32]byte{}) || event.OccurredAt.IsZero() ||
		len(event.Kind) > 96 || prefix == "" ||
		!strings.HasPrefix(event.ID, "evt_") || !idText.MatchString(event.ID) ||
		!strings.HasPrefix(event.ResourceID, prefix) || !idText.MatchString(event.ResourceID) {
		return EventReceipt{}, arc.InvalidArgument("event", "provider_notification")
	}
	semantic := sha256.Sum256(fmt.Appendf(nil, "arcforges.paddle.event.v1\n%s\n%s\n%s\n%d", event.Environment, event.Kind, event.ResourceID, event.OccurredAt.UnixMicro()))
	var result EventReceipt
	err := s.db.InTx(ctx, "record a verified provider event", store.TxOptions{Timeout: 4 * time.Second},
		func(ctx context.Context, tx pgx.Tx) error {
			now := s.now()
			tag, err := tx.Exec(ctx, `INSERT INTO commerce.provider_event(provider,environment,event_ref,payload_sha256,semantic_sha256,
event_kind,resource_ref,occurred_at,state,verified_at,received_at,next_check_at)
VALUES(1,$1,$2,$3,$4,$5,$6,$7,1,$8,$8,$8) ON CONFLICT DO NOTHING`,
				s.environmentID, event.ID, event.Digest[:], semantic[:], event.Kind, event.ResourceID, event.OccurredAt, now)
			if err != nil {
				return err
			}
			result = EventReceipt{State: eventStates[eventPending], Duplicate: tag.RowsAffected() == 0}
			if !result.Duplicate {
				return nil
			}
			var raw, meaning []byte
			var state int16
			if err = tx.QueryRow(ctx, `SELECT payload_sha256,semantic_sha256,state FROM commerce.provider_event
WHERE provider=1 AND environment=$1 AND event_ref=$2`, s.environmentID, event.ID).Scan(&raw, &meaning, &state); err != nil {
				return err
			}
			if !bytes.Equal(raw, event.Digest[:]) || !bytes.Equal(meaning, semantic[:]) {
				return arc.InvalidState("provider_event", "event_digest_mismatch")
			}
			result.State = eventStates[state]
			return nil
		})
	return result, err
}

func eventPrefix(kind string) string {
	switch kind {
	case "transaction.completed", "transaction.paid", "transaction.payment_failed", "transaction.past_due", "transaction.canceled":
		return "txn_"
	case "subscription.created", "subscription.updated", "subscription.activated", "subscription.canceled", "subscription.past_due",
		"subscription.paused", "subscription.resumed", "subscription.trialing":
		return "sub_"
	case "adjustment.created", "adjustment.updated":
		return "adj_"
	default:
		return ""
	}
}

type eventWork struct {
	Event
	Attempt    int
	LeaseUntil time.Time
}

func (s *Service) nextEvent(ctx context.Context) (eventWork, error) {
	var work eventWork
	err := s.db.InTx(ctx, "claim a provider reconciliation read", store.TxOptions{Timeout: 5 * time.Second},
		func(ctx context.Context, tx pgx.Tx) error {
			now := s.now()
			err := tx.QueryRow(ctx, `WITH next AS (
 SELECT event_ref FROM commerce.provider_event WHERE provider=1 AND environment=$1 AND state IN (1,3)
 AND next_check_at<=$2 ORDER BY next_check_at,event_ref LIMIT 1 FOR UPDATE SKIP LOCKED
)
UPDATE commerce.provider_event p SET state=3,attempt_count=attempt_count+CASE WHEN attempt_count<2147483647 THEN 1 ELSE 0 END,next_check_at=$3,failure_code=NULL
FROM next WHERE p.provider=1 AND p.environment=$1 AND p.event_ref=next.event_ref
RETURNING p.event_ref,p.event_kind,p.resource_ref,p.occurred_at,p.attempt_count,p.next_check_at`,
				s.environmentID, now, now.Add(time.Minute)).Scan(&work.ID, &work.Kind, &work.ResourceID, &work.OccurredAt, &work.Attempt, &work.LeaseUntil)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			work.Environment = s.environment
			return err
		})
	return work, err
}

type reconcileFacts struct {
	Transaction  paddle.Transaction
	Subscription paddle.Subscription
	Adjustments  []paddle.Adjustment
}

var errUnboundFacts = errors.New("commerce facts could not establish an exact local binding")

func (s *Service) fetchFacts(ctx context.Context, work eventWork) (reconcileFacts, error) {
	var facts reconcileFacts
	var err error
	switch eventPrefix(work.Kind) {
	case "txn_":
		facts.Transaction, err = s.provider.GetTransaction(ctx, work.ResourceID)
		if err != nil {
			return facts, err
		}
		if facts.Transaction.ID != work.ResourceID {
			return facts, errUnboundFacts
		}
	case "adj_":
		adjustment, err := s.provider.GetAdjustment(ctx, work.ResourceID)
		if err != nil {
			return facts, err
		}
		if adjustment.ID != work.ResourceID || adjustment.TransactionID == "" {
			return facts, errUnboundFacts
		}
		facts.Transaction, err = s.provider.GetTransaction(ctx, adjustment.TransactionID)
		if err != nil {
			return facts, err
		}
		if facts.Transaction.ID != adjustment.TransactionID {
			return facts, errUnboundFacts
		}
	case "sub_":
		facts.Subscription, err = s.provider.GetSubscription(ctx, work.ResourceID)
		if err != nil {
			return facts, err
		}
		if facts.Subscription.ID != work.ResourceID {
			return facts, errUnboundFacts
		}
		candidates, err := s.provider.ListTransactionsBySubscription(ctx, work.ResourceID)
		if err != nil {
			return facts, err
		}
		for _, candidate := range candidates {
			if candidate.SubscriptionID == work.ResourceID && candidate.Status == "completed" &&
				(facts.Transaction.ID == "" || candidate.PeriodEnd.After(facts.Transaction.PeriodEnd)) {
				facts.Transaction = candidate
			}
		}
		if facts.Transaction.ID == "" {
			return facts, errUnboundFacts
		}
	default:
		return facts, errUnboundFacts
	}
	if facts.Transaction.SubscriptionID != "" && facts.Subscription.ID == "" {
		facts.Subscription, err = s.provider.GetSubscription(ctx, facts.Transaction.SubscriptionID)
		if err != nil {
			return facts, err
		}
	}
	if facts.Subscription.ID != facts.Transaction.SubscriptionID {
		return facts, errUnboundFacts
	}
	if facts.Transaction.Status != "completed" {
		if eventPrefix(work.Kind) == "adj_" {
			return facts, errUnboundFacts
		}
		return facts, nil
	}
	if facts.Subscription.ID == "" {
		return facts, errUnboundFacts
	}
	facts.Adjustments, err = s.provider.ListAdjustments(ctx, facts.Transaction.ID)
	if err != nil {
		return facts, err
	}
	if eventPrefix(work.Kind) == "adj_" {
		for _, adjustment := range facts.Adjustments {
			if adjustment.ID == work.ResourceID {
				return facts, nil
			}
		}
		return facts, errUnboundFacts
	}
	return facts, nil
}

// Reconcile performs one bounded cycle. Provider reads take place outside store
// transactions; exact event claims and accounts are checked again before writes.
func (s *Service) Reconcile(ctx context.Context) error {
	work, err := s.nextEvent(ctx)
	if err != nil {
		return err
	}
	if work.ID != "" {
		facts, fetchErr := s.fetchFacts(ctx, work)
		if fetchErr == nil {
			fetchErr = s.applyEvent(ctx, work, facts)
		}
		if fetchErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err = s.retryEvent(ctx, work); err != nil {
				return err
			}
			if !errors.Is(fetchErr, errUnboundFacts) && !errors.Is(fetchErr, paddle.ErrUncertain) &&
				!errors.Is(fetchErr, paddle.ErrRefused) && !errors.Is(fetchErr, paddle.ErrInvalidRequest) {
				return fetchErr
			}
		}
	}
	if err = s.expireUnclaimed(ctx); err != nil {
		return err
	}
	if err = s.reconcileCheckout(ctx); err != nil {
		return err
	}
	if err = s.reconcileRenewal(ctx); err != nil {
		return err
	}
	if err = s.reconcileDeletion(ctx); err != nil {
		return err
	}
	return s.reconcileDeletionTerminal(ctx)
}

func (s *Service) expireUnclaimed(ctx context.Context) error {
	return s.db.InTx(ctx, "expire an untouched purchase", store.TxOptions{Timeout: 5 * time.Second},
		func(ctx context.Context, tx pgx.Tx) error {
			now := s.now()
			var purchase, account platform.ID
			err := tx.QueryRow(ctx, `SELECT p.purchase_id,p.account_id FROM commerce.purchase p
WHERE p.provider=1 AND p.environment=$1 AND p.state=1 AND p.expires_at<=$2
AND NOT EXISTS(SELECT 1 FROM commerce.checkout c WHERE c.purchase_id=p.purchase_id AND c.send_claimed_at IS NOT NULL)
ORDER BY p.expires_at,p.purchase_id LIMIT 1`, s.environmentID, now).Scan(&purchase, &account)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			if _, err = lockAccount(ctx, tx, account); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE commerce.purchase p SET state=4,updated_at=$2,rev=rev+1
WHERE p.purchase_id=$1 AND p.state=1 AND p.expires_at<=$2
AND NOT EXISTS(SELECT 1 FROM commerce.checkout c WHERE c.purchase_id=p.purchase_id AND c.send_claimed_at IS NOT NULL)`,
				purchase, now)
			return err
		})
}

func (s *Service) retryEvent(ctx context.Context, work eventWork) error {
	return s.db.InTx(ctx, "defer provider reconciliation", store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		// Each invocation performs one bounded I/O attempt. A transient
		// outage never retires the durable obligation to reconcile payment.
		exponent := min(max(work.Attempt-1, 0), 8)
		next := s.now().Add(time.Second * time.Duration(1<<exponent))
		_, err := tx.Exec(ctx, `UPDATE commerce.provider_event SET next_check_at=$4,failure_code='provider_pending'
WHERE provider=1 AND environment=$1 AND event_ref=$2 AND attempt_count=$3 AND state=3 AND next_check_at=$5`,
			s.environmentID, work.ID, work.Attempt, next, work.LeaseUntil)
		return err
	})
}

func (s *Service) closeEvent(ctx context.Context, tx pgx.Tx, work eventWork, account platform.ID, state int16, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE commerce.provider_event SET account_id=$4,state=$5,processed_at=$6,next_check_at=NULL,failure_code=NULL
WHERE provider=1 AND environment=$1 AND event_ref=$2 AND attempt_count=$3 AND state=3
AND (account_id IS NULL OR account_id=$4)`, s.environmentID, work.ID, work.Attempt, account, state, now)
	return err
}

func (s *Service) reconcileCheckout(ctx context.Context) error {
	var item storedCheckout
	err := s.db.InTx(ctx, "read a claimed checkout", store.TxOptions{ReadOnly: true, Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		item, err = scanCheckout(tx.QueryRow(ctx, "SELECT "+checkoutColumns+checkoutJoin+`
WHERE c.provider=1 AND c.environment=$1 AND (c.state=5 OR c.state=2 AND c.expires_at<=$2) AND c.updated_at<=$2
ORDER BY c.updated_at,c.checkout_id LIMIT 1`, s.environmentID, s.now().Add(-time.Second)))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	if err != nil || item.ID == (platform.ID{}) {
		return err
	}
	fact, found, err := s.checkoutFact(ctx, item, false)
	if err == nil && found && (item.Transaction == "" || fact.Status == "canceled") {
		return s.recordCheckout(ctx, item, fact)
	}
	return s.db.InTx(ctx, "defer a claimed checkout read", store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := lockAccount(ctx, tx, item.Account); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "UPDATE commerce.checkout SET updated_at=$2 WHERE checkout_id=$1 AND state IN (2,5)", item.ID, s.now())
		return err
	})
}

func (s *Service) reconcileRenewal(ctx context.Context) error {
	var command, id, account platform.ID
	var desired bool
	var sub storedSubscription
	err := s.db.InTx(ctx, "read a claimed renewal", store.TxOptions{ReadOnly: true, Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT command_id,subscription_id,account_id,auto_renew FROM commerce.renewal
WHERE provider=1 AND environment=$1 AND state=3 AND updated_at<=$2 ORDER BY updated_at,renewal_id LIMIT 1`,
			s.environmentID, s.now().Add(-time.Second)).Scan(&command, &id, &account, &desired)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		sub, err = scanSubscription(tx.QueryRow(ctx, "SELECT "+subscriptionColumns+" FROM commerce.subscription WHERE subscription_id=$1 AND account_id=$2", id, account))
		return err
	})
	if err != nil || command == (platform.ID{}) {
		return err
	}
	fact, err := s.provider.GetSubscription(ctx, sub.Reference)
	if err == nil {
		if err = s.recordRenewal(ctx, sub, fact, command, desired); err != nil {
			return err
		}
	}
	return s.db.InTx(ctx, "defer a claimed renewal read", store.TxOptions{Timeout: 5 * time.Second}, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := lockAccount(ctx, tx, account); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "UPDATE commerce.renewal SET updated_at=$3 WHERE account_id=$1 AND command_id=$2 AND state=3", account, command, s.now())
		return err
	})
}
