// SPDX-License-Identifier: AGPL-3.0-only
package commerce

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/commerce/paddle"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

func (s *Service) binding(ctx context.Context, tx pgx.Tx, facts reconcileFacts) (storedCheckout, storedSubscription, error) {
	var sub storedSubscription
	if facts.Subscription.ID != "" {
		var err error
		sub, err = scanSubscription(tx.QueryRow(ctx, "SELECT "+subscriptionColumns+
			" FROM commerce.subscription WHERE provider=1 AND environment=$1 AND provider_subscription_ref=$2", s.environmentID, facts.Subscription.ID))
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return storedCheckout{}, sub, err
		}
	}
	if sub.ID != (platform.ID{}) &&
		(!renewalMatches(sub, facts.Subscription) || facts.Transaction.SubscriptionID != sub.Reference ||
			facts.Transaction.CustomerID != sub.Customer || !oneProduct(facts.Transaction.Items, sub.Price, sub.Product)) {
		return storedCheckout{}, sub, errUnboundFacts
	}
	var checkout storedCheckout
	if sub.ID != (platform.ID{}) && sub.CheckoutID != nil {
		var err error
		checkout, err = scanCheckout(tx.QueryRow(ctx, "SELECT "+checkoutColumns+checkoutJoin+
			"WHERE c.checkout_id=$1 AND c.account_id=$2 AND c.provider=1 AND c.environment=$3",
			*sub.CheckoutID, sub.Account, s.environmentID))
		if err != nil {
			return checkout, sub, err
		}
		if facts.Transaction.IntentID != checkout.IntentID.String() {
			return checkout, sub, errUnboundFacts
		}
	} else if sub.ID == (platform.ID{}) {
		var err error
		checkout, err = scanCheckout(tx.QueryRow(ctx, "SELECT "+checkoutColumns+checkoutJoin+
			"WHERE c.provider=1 AND c.environment=$1 AND c.provider_intent_id::text=$2", s.environmentID, facts.Transaction.IntentID))
		if errors.Is(err, pgx.ErrNoRows) {
			return checkout, sub, errUnboundFacts
		}
		if err != nil {
			return checkout, sub, err
		}
		if checkout.ClaimedAt == nil || !checkoutMatches(checkout, facts.Transaction) {
			return checkout, sub, errUnboundFacts
		}
	}
	return checkout, sub, nil
}

func (s *Service) applyEvent(ctx context.Context, work eventWork, facts reconcileFacts) error {
	var pending bool
	err := s.db.InTx(ctx, "apply a verified provider event", store.TxOptions{Timeout: 8 * time.Second},
		func(ctx context.Context, tx pgx.Tx) error {
			pending = false
			checkout, sub, err := s.binding(ctx, tx, facts)
			if err != nil {
				return err
			}
			account := checkout.Account
			if sub.ID != (platform.ID{}) {
				account = sub.Account
			}
			security, err := lockAccount(ctx, tx, account)
			if err != nil {
				return err
			}
			var bound *platform.ID
			err = tx.QueryRow(ctx, `SELECT account_id FROM commerce.provider_event WHERE provider=1 AND environment=$1 AND event_ref=$2
AND state=3 AND attempt_count=$3 AND next_check_at=$4 FOR UPDATE`,
				s.environmentID, work.ID, work.Attempt, work.LeaseUntil).Scan(&bound)
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			if err != nil {
				return err
			}
			if bound != nil && *bound != account {
				return errUnboundFacts
			}
			// Re-read the immutable ownership and last provider revision after
			// locking the account. Concurrent signed events may have bound it.
			checkout, sub, err = s.binding(ctx, tx, facts)
			if err != nil {
				return err
			}
			if (sub.ID != (platform.ID{}) && sub.Account != account) ||
				(checkout.ID != (platform.ID{}) && checkout.Account != account) {
				return errUnboundFacts
			}
			if bound == nil {
				if _, err := tx.Exec(ctx, `UPDATE commerce.provider_event SET account_id=$4
WHERE provider=1 AND environment=$1 AND event_ref=$2 AND attempt_count=$3 AND account_id IS NULL`,
					s.environmentID, work.ID, work.Attempt, account); err != nil {
					return err
				}
			}
			effect, err := tx.Begin(ctx)
			if err != nil {
				return err
			}
			now := s.now()
			if facts.Transaction.Status == "completed" {
				err = s.settle(ctx, effect, work, facts, checkout, sub, account, security.State, now)
			} else {
				err = s.observeUnpaid(ctx, effect, work, checkout, sub, account, facts, now)
			}
			if err == nil {
				return effect.Commit(ctx)
			}
			if rollback := effect.Rollback(ctx); rollback != nil {
				return rollback
			}
			// Retain only the proven account binding for incomplete or
			// contradictory facts. Partial financial changes are rolled back.
			pending = errors.Is(err, errUnboundFacts)
			if pending {
				return nil
			}
			return err
		})
	if err == nil && pending {
		return errUnboundFacts
	}
	return err
}

func (s *Service) observeUnpaid(ctx context.Context, tx pgx.Tx, work eventWork, checkout storedCheckout, sub storedSubscription,
	account platform.ID, facts reconcileFacts, now time.Time) error {
	fact := facts.Transaction
	if sub.ID != (platform.ID{}) {
		return s.observeUnpaidRenewal(ctx, tx, work, sub, facts.Subscription, now)
	}
	if checkout.ID == (platform.ID{}) || !checkoutMatches(checkout, fact) {
		return errUnboundFacts
	}
	if err := s.bindCheckout(ctx, tx, checkout, fact, now); err != nil {
		return err
	}
	if fact.Status == "canceled" {
		if err := expireVerifiedCheckout(ctx, tx, checkout, now); err != nil {
			return err
		}
	}
	return s.closeEvent(ctx, tx, work, account, eventObsolete, now)
}

// A nonpaid renewal can change verified subscription facts. An event or
// subscription status alone never creates a payment, term or grace interval.
func (s *Service) observeUnpaidRenewal(ctx context.Context, tx pgx.Tx, work eventWork,
	sub storedSubscription, fact paddle.Subscription, now time.Time) error {
	if !renewalMatches(sub, fact) || fact.UpdatedAt.After(now) {
		return errUnboundFacts
	}
	rev := sub.Revision
	latest := providerSnapshotCurrent(sub, fact.UpdatedAt.UTC().Truncate(time.Microsecond), providerSnapshot(fact))
	if latest && !sub.PeriodStart.IsZero() {
		var err error
		rev, err = s.projectSubscription(ctx, tx, sub, fact, sub.PeriodStart, sub.PeriodEnd, time.Time{}, true,
			sub.state == subscriptionPending, now)
		if err != nil {
			return err
		}
		renew := verifiedAutoRenew(fact)
		if _, err = s.entitlements.ApplyCommerce(ctx, tx, entitlement.CommerceChange{
			AccountID: sub.Account.String(), DefinitionsVersion: s.entitlements.DefinitionsVersion(),
			EventRef: work.ID, AutoRenew: &renew,
		}); err != nil {
			return err
		}
	}
	if err := s.audit(ctx, tx, now, sub.Account, "provider_payment_unsettled", "subscription", sub.ID, nil, nil); err != nil {
		return err
	}
	if _, err := platform.Enqueue(ctx, tx, platform.Message{DedupKey: "commerce:" + string(s.environment) + ":" + work.ID,
		Topic: "commerce.subscription.changed", AggregateKind: "subscription", AggregateID: sub.ID, AggregateRev: rev,
		Payload: []byte("{}"), CorrelationID: platform.NewID()}); err != nil {
		return err
	}
	return s.closeEvent(ctx, tx, work, sub.Account, eventApplied, now)
}

type storedPeriod struct {
	Ref, TermID, Transaction string
	GrantIDs                 []string
	Start, End               time.Time
}

var hostedFeatures = []string{"center.nodes", "remote.view", "remote.control"}

func paidWindow(fact paddle.Transaction, observed paddle.Subscription, checkout storedCheckout,
	sub storedSubscription, now time.Time) (time.Time, time.Time, bool) {
	if fact.BilledAt.IsZero() || fact.BilledAt.After(now) || observed.UpdatedAt.IsZero() ||
		observed.UpdatedAt.After(now) || fact.TotalMinor <= 0 {
		return time.Time{}, time.Time{}, false
	}
	start, end := fact.PeriodStart, fact.PeriodEnd
	if start.IsZero() && end.IsZero() && fact.Origin == "api" &&
		checkout.ID != (platform.ID{}) && (sub.ID == (platform.ID{}) || checkout.Transaction == fact.ID) &&
		!fact.BilledAt.Before(observed.PeriodStart) && fact.BilledAt.Before(observed.PeriodEnd) {
		start, end = observed.PeriodStart, observed.PeriodEnd
	}
	if start.IsZero() || !end.After(start) || start.After(now) ||
		(!observed.PeriodEnd.IsZero() && end.After(observed.PeriodEnd)) {
		return time.Time{}, time.Time{}, false
	}
	return start.UTC().Truncate(time.Microsecond), end.UTC().Truncate(time.Microsecond), true
}

func periodKey(subscription string, start, end time.Time) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "arcforges.paddle.period.v1\n%s\n%d\n%d", subscription, start.UnixMicro(), end.UnixMicro()))
	return hex.EncodeToString(sum[:])
}

func (s *Service) settle(ctx context.Context, tx pgx.Tx, work eventWork, facts reconcileFacts, checkout storedCheckout,
	sub storedSubscription, account platform.ID, accountState int16, now time.Time) error {
	fact, observed := facts.Transaction, facts.Subscription
	offer := checkout.Offer
	if checkout.ID == (platform.ID{}) || offer.AdjustmentPolicy != AdjustmentPolicy || fact.CustomerID != observed.CustomerID || fact.SubscriptionID != observed.ID ||
		!strings.HasPrefix(observed.ID, "sub_") || !idText.MatchString(observed.ID) ||
		fact.CollectionMode != "automatic" || observed.CollectionMode != "automatic" ||
		!oneProduct(observed.Items, offer.PriceID, offer.ProductID) || !oneProduct(fact.Items, offer.PriceID, offer.ProductID) ||
		fact.Currency != offer.Currency {
		return errUnboundFacts
	}
	if sub.ID != (platform.ID{}) && !renewalMatches(sub, observed) {
		return errUnboundFacts
	}
	start, end, ok := paidWindow(fact, observed, checkout, sub, now)
	if sub.ID != (platform.ID{}) {
		originalStart, originalEnd, err := s.periodWindow(ctx, tx, sub, fact.ID)
		if err != nil {
			return err
		}
		if !originalStart.IsZero() {
			if (!fact.PeriodStart.IsZero() && !fact.PeriodStart.UTC().Truncate(time.Microsecond).Equal(originalStart)) ||
				(!fact.PeriodEnd.IsZero() && !fact.PeriodEnd.UTC().Truncate(time.Microsecond).Equal(originalEnd)) {
				return errUnboundFacts
			}
			start, end, ok = originalStart, originalEnd, !fact.BilledAt.After(now) && !fact.BilledAt.IsZero() && fact.TotalMinor > 0
		}
	}
	if !ok {
		return errUnboundFacts
	}
	initialCharge := checkout.ID != (platform.ID{}) && (sub.ID == (platform.ID{}) || checkout.Transaction == fact.ID)
	if initialCharge && (checkout.ClaimedAt == nil || fact.CreatedAt.IsZero() ||
		fact.CreatedAt.Before(checkout.ClaimedAt.Add(-paddle.SignatureTolerance))) {
		return errUnboundFacts
	}
	latePayment := initialCharge && !fact.BilledAt.Before(checkout.ExpiresAt)
	unsettledInitial := !initialCharge && checkout.ID != (platform.ID{}) && checkout.State != checkoutNames[checkoutComplete]
	ref := periodKey(observed.ID, start, end)
	if sub.ID == (platform.ID{}) {
		if err := s.bindCheckout(ctx, tx, checkout, fact, now); err != nil {
			return err
		}
		sub = storedSubscription{SubscriptionView: SubscriptionView{ID: platform.NewID(), CatalogueVersion: checkout.Catalogue},
			Account: account, CheckoutID: &checkout.ID, Customer: fact.CustomerID, Reference: observed.ID,
			Product: offer.ProductID, Price: offer.PriceID}
		if err := s.insertSubscription(ctx, tx, sub, observed, now); err != nil {
			return err
		}
	}
	old, err := s.findPeriod(ctx, tx, sub, ref, fact.ID)
	if err != nil {
		return err
	}
	financial, err := s.appendFinancialFacts(ctx, tx, account, sub.ID, work.ID, facts, now)
	if err != nil {
		return err
	}
	if old.TermID == "" {
		switch {
		case latePayment || unsettledInitial:
			return s.retainPaymentForReview(ctx, tx, work, sub, observed, start, end, now, "late_payment_review")
		case financial.chargebackReversed:
			return s.retainPaymentForReview(ctx, tx, work, sub, observed, start, end, now, "chargeback_reversal_review")
		case s.entitlements.DefinitionsVersion() != offer.DefinitionsVersion:
			return s.retainPaymentForReview(ctx, tx, work, sub, observed, start, end, now, "definitions_approval_review")
		}
	}
	endAt := financial.cutoff
	// Preserve provider and financial facts for pending-deletion accounts,
	// but a late payment after the account gate closed cannot mint service.
	if old.TermID == "" && accountState == 1 {
		var overlap bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM commerce.settled_period
WHERE subscription_id=$1 AND valid_from<$3 AND valid_until>$2)`, sub.ID, start, end).Scan(&overlap); err != nil {
			return err
		}
		if overlap {
			return errUnboundFacts
		}
		old, err = s.appendPeriod(ctx, tx, sub, offer, work, ref, fact.ID, start, end)
		if err != nil {
			return err
		}
	}
	renew := verifiedAutoRenew(observed)
	pending := false
	change := entitlement.CommerceChange{AccountID: account.String(), DefinitionsVersion: s.entitlements.DefinitionsVersion(),
		EventRef: work.ID}
	if !endAt.IsZero() && old.TermID != "" {
		change.EndTerms = []entitlement.CommerceTermEnd{{TermID: old.TermID, GrantIDs: old.GrantIDs,
			EffectiveAt: entitlement.FromTime(endAt)}}
	}
	currentPeriod := sub.PeriodEnd.IsZero() || !end.Before(sub.PeriodEnd)
	latestProvider := providerSnapshotCurrent(sub, observed.UpdatedAt.UTC().Truncate(time.Microsecond), providerSnapshot(observed))
	if currentPeriod && latestProvider {
		change.AutoRenew = &renew
		change.PurchasePending = &pending
	}
	if len(change.EndTerms) != 0 || change.AutoRenew != nil {
		if _, err := s.entitlements.ApplyCommerce(ctx, tx, change); err != nil {
			return err
		}
	}
	renewalRev, err := s.projectSubscription(ctx, tx, sub, observed, start, end, endAt, currentPeriod, false, now)
	if err != nil {
		return err
	}
	if checkout.ID != (platform.ID{}) && (checkout.Transaction == fact.ID || checkout.Transaction == "") {
		if _, err = tx.Exec(ctx, "UPDATE commerce.checkout SET state=3,updated_at=$2 WHERE checkout_id=$1 AND state=2", checkout.ID, now); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, "UPDATE commerce.purchase SET state=3,updated_at=$2,rev=rev+1 WHERE purchase_id=$1 AND state IN(1,2)", checkout.PurchaseID, now); err != nil {
			return err
		}
	}
	if err = s.audit(ctx, tx, now, account, "provider_reconciled", "subscription", sub.ID, nil, nil); err != nil {
		return err
	}
	_, err = platform.Enqueue(ctx, tx, platform.Message{DedupKey: "commerce:" + string(s.environment) + ":" + work.ID,
		Topic: "commerce.subscription.changed", AggregateKind: "subscription", AggregateID: sub.ID, AggregateRev: renewalRev,
		Payload: []byte("{}"), CorrelationID: platform.NewID()})
	if err != nil {
		return err
	}
	return s.closeEvent(ctx, tx, work, account, eventApplied, now)
}

// Local link expiry does not say Paddle canceled the original transaction.
// Retain verified provider/payment evidence while holding fulfilment for review.
func (s *Service) retainPaymentForReview(ctx context.Context, tx pgx.Tx, work eventWork, sub storedSubscription,
	fact paddle.Subscription, start, end, now time.Time, reason string) error {
	rev, err := s.projectSubscription(ctx, tx, sub, fact, start, end, time.Time{},
		sub.PeriodEnd.IsZero() || !end.Before(sub.PeriodEnd), true, now)
	if err != nil {
		return err
	}
	if err := s.audit(ctx, tx, now, sub.Account, reason, "subscription", sub.ID, nil, nil); err != nil {
		return err
	}
	if _, err = platform.Enqueue(ctx, tx, platform.Message{DedupKey: "commerce:" + string(s.environment) + ":" + work.ID,
		Topic: "commerce.payment.review", AggregateKind: "subscription", AggregateID: sub.ID, AggregateRev: rev,
		Payload: []byte("{}"), CorrelationID: platform.NewID()}); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE commerce.provider_event SET next_check_at=NULL,failure_code=$5
WHERE provider=1 AND environment=$1 AND event_ref=$2 AND state=3 AND attempt_count=$3 AND account_id=$4`,
		s.environmentID, work.ID, work.Attempt, sub.Account, reason)
	return err
}

func (s *Service) insertSubscription(ctx context.Context, tx pgx.Tx, sub storedSubscription, fact paddle.Subscription, now time.Time) error {
	sum := providerSnapshot(fact)
	_, err := tx.Exec(ctx, `INSERT INTO commerce.subscription(subscription_id, account_id, provider, environment, provider_customer_ref,
provider_subscription_ref, checkout_id,catalog_version,product_ref,price_ref,state,auto_renew,provider_updated_at,
provider_snapshot_sha256,verified_at,rev) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,1,$10,$11,$12,$13,1)`,
		sub.ID, sub.Account, s.environmentID, sub.Customer, sub.Reference, sub.CheckoutID, sub.CatalogueVersion, sub.Product, sub.Price,
		verifiedAutoRenew(fact), fact.UpdatedAt.UTC().Truncate(time.Microsecond), sum[:], now)
	return err
}

func (s *Service) projectSubscription(ctx context.Context, tx pgx.Tx, sub storedSubscription, fact paddle.Subscription,
	start, end, endAt time.Time, current, manual bool, now time.Time) (int64, error) {
	if !current {
		return sub.Revision, nil
	}
	digest := providerSnapshot(fact)
	at := fact.UpdatedAt.UTC().Truncate(time.Microsecond)
	if !providerSnapshotCurrent(sub, at, digest) {
		// An independently verified adjustment may shorten this exact
		// paid period without replacing newer subscription provider facts.
		if !endAt.IsZero() && sub.PeriodEnd.Equal(end) &&
			sub.state != subscriptionRevoked && sub.state != subscriptionExpired {
			var rev int64
			err := tx.QueryRow(ctx, `UPDATE commerce.subscription SET state=6,verified_at=$2,rev=rev+1
WHERE subscription_id=$1 RETURNING rev`, sub.ID, now).Scan(&rev)
			return rev, err
		}
		return sub.Revision, nil
	}
	renew := verifiedAutoRenew(fact)
	state := subscriptionActive
	switch {
	case manual:
		state = subscriptionPending
	case fact.Status == "canceled" && !now.Before(end):
		// A scheduled cancellation or an elapsed paid window is not
		// authoritative terminal provider evidence.
		state = subscriptionExpired
	case !endAt.IsZero() || sub.state == subscriptionRevoked && !end.After(sub.PeriodEnd):
		state = subscriptionRevoked
	case !renew:
		state = subscriptionCancelAtEnd
	}
	if sub.Revision > 0 && sub.state == state && sub.AutoRenew == renew && sub.PeriodStart.Equal(start) &&
		sub.PeriodEnd.Equal(end) && at.Equal(sub.ProviderUpdate) {
		return sub.Revision, nil
	}
	var rev int64
	err := tx.QueryRow(ctx, `UPDATE commerce.subscription SET state=$2,auto_renew=$3,valid_from=$4,valid_until=$5,
provider_updated_at=$6,provider_snapshot_sha256=$7,verified_at=$8,rev=rev+1
WHERE subscription_id=$1 RETURNING rev`, sub.ID, state, renew, start, end, at, digest[:], now).Scan(&rev)
	return rev, err
}

// periodWindow reuses the originally verified period for its immutable
// transaction. Paddle initial checkout responses may omit billing_period,
// and the subscription's current period moves forward after renewal.
func (s *Service) periodWindow(ctx context.Context, tx pgx.Tx, sub storedSubscription, transaction string) (time.Time, time.Time, error) {
	var start, end time.Time
	err := tx.QueryRow(ctx, "SELECT valid_from,valid_until FROM commerce.settled_period WHERE provider=1 AND environment=$1 AND provider_transaction_ref=$2 AND subscription_id=$3 AND account_id=$4",
		s.environmentID, transaction, sub.ID, sub.Account).Scan(&start, &end)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, time.Time{}, nil
	}
	return start, end, err
}

func (s *Service) findPeriod(ctx context.Context, tx pgx.Tx, sub storedSubscription, ref, transaction string) (storedPeriod, error) {
	var result storedPeriod
	var subID platform.ID
	var nodes, view, control string
	rows, err := tx.Query(ctx, `SELECT subscription_id,provider_period_ref,provider_transaction_ref,term_id::text,
nodes_grant_id::text,view_grant_id::text,control_grant_id::text,valid_from,valid_until FROM commerce.settled_period
WHERE (provider=1 AND environment=$1 AND provider_transaction_ref=$2) OR (subscription_id=$3 AND provider_period_ref=$4)
LIMIT 2`, s.environmentID, transaction, sub.ID, ref)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	for rows.Next() {
		if result.TermID != "" {
			return result, errUnboundFacts
		}
		if err = rows.Scan(&subID, &result.Ref, &result.Transaction, &result.TermID, &nodes, &view, &control, &result.Start, &result.End); err != nil {
			return result, err
		}
		if subID != sub.ID || result.Ref != ref || result.Transaction != transaction {
			return result, errUnboundFacts
		}
		result.GrantIDs = []string{nodes, view, control}
	}
	return result, rows.Err()
}

func (s *Service) appendPeriod(ctx context.Context, tx pgx.Tx, sub storedSubscription, offer Offer, work eventWork,
	ref, transaction string, start, end time.Time) (storedPeriod, error) {
	result, err := s.entitlements.ApplyCommerce(ctx, tx, entitlement.CommerceChange{
		AccountID: sub.Account.String(), DefinitionsVersion: offer.DefinitionsVersion, EventRef: work.ID,
		NewTerm: &entitlement.CommerceTerm{SubscriptionRef: "paddle:" + string(s.environment) + ":" + sub.Reference,
			PeriodRef: ref, StartsAt: entitlement.FromTime(start), EndsAt: entitlement.FromTime(end), Features: hostedFeatures},
	})
	if err != nil {
		return storedPeriod{}, err
	}
	if result.TermID == "" || len(result.GrantIDs) != 3 {
		return storedPeriod{}, errUnboundFacts
	}
	_, err = tx.Exec(ctx, `INSERT INTO commerce.settled_period(period_id,subscription_id,account_id,provider,environment,provider_transaction_ref,
provider_period_ref,term_id,nodes_grant_id,view_grant_id,control_grant_id,valid_from,valid_until,settled_at,event_ref)
VALUES($1,$2,$3,1,$4,$5,$6,$7::uuid,$8::uuid,$9::uuid,$10::uuid,$11,$12,$13,$14)`,
		platform.NewID(), sub.ID, sub.Account, s.environmentID, transaction, ref, result.TermID,
		result.GrantIDs[0], result.GrantIDs[1], result.GrantIDs[2], start, end, s.now(), work.ID)
	return storedPeriod{Ref: ref, TermID: result.TermID, GrantIDs: result.GrantIDs, Transaction: transaction, Start: start, End: end}, err
}

type financialFacts struct {
	cutoff             time.Time
	chargebackReversed bool
}

func financialAdjustmentKind(action string) int16 {
	switch action {
	case "refund":
		return 2
	case "chargeback":
		return 3
	case "credit":
		return 4
	case "credit_reverse":
		return 5
	case "chargeback_reverse":
		return 6
	default:
		return 0
	}
}

func (s *Service) appendFinancialFacts(ctx context.Context, tx pgx.Tx, account, subscription platform.ID,
	event string, facts reconcileFacts, now time.Time) (financialFacts, error) {
	fact := facts.Transaction
	if err := s.appendBilling(ctx, tx, account, subscription, event, fact.ID, 1, fact.Currency, fact.TotalMinor, fact.BilledAt, now); err != nil {
		return financialFacts{}, err
	}
	adjustments := slices.Clone(facts.Adjustments)
	slices.SortFunc(adjustments, func(a, b paddle.Adjustment) int {
		if a.UpdatedAt.Equal(b.UpdatedAt) {
			return strings.Compare(a.ID, b.ID)
		}
		return a.UpdatedAt.Compare(b.UpdatedAt)
	})
	var observed financialFacts
	var refunded int64
	seen := map[string]struct{}{}
	for _, adjustment := range adjustments {
		if adjustment.TransactionID != fact.ID || adjustment.CustomerID != fact.CustomerID ||
			(adjustment.SubscriptionID != "" && adjustment.SubscriptionID != fact.SubscriptionID) ||
			adjustment.Currency != fact.Currency || !idText.MatchString(adjustment.ID) || !strings.HasPrefix(adjustment.ID, "adj_") {
			return financialFacts{}, errUnboundFacts
		}
		if _, exists := seen[adjustment.ID]; exists {
			return financialFacts{}, errUnboundFacts
		}
		seen[adjustment.ID] = struct{}{}
		kind := financialAdjustmentKind(adjustment.Action)
		reversed := adjustment.Status == "reversed"
		if kind == 0 || (adjustment.Status != "approved" && !(reversed && (kind == 3 || kind == 4))) {
			continue
		}
		if (kind == 2 || kind == 3) && adjustment.TotalMinor <= 0 ||
			adjustment.CreatedAt.IsZero() || adjustment.CreatedAt.Before(fact.BilledAt) ||
			adjustment.UpdatedAt.Before(adjustment.CreatedAt) || adjustment.UpdatedAt.After(now) {
			return financialFacts{}, errUnboundFacts
		}
		if err := s.appendBilling(ctx, tx, account, subscription, event, adjustment.ID, kind, adjustment.Currency,
			adjustment.TotalMinor, adjustment.CreatedAt, now); err != nil {
			return financialFacts{}, err
		}
		switch kind {
		case 2:
			refunded += min(adjustment.TotalMinor, fact.TotalMinor-refunded)
			if observed.cutoff.IsZero() && (adjustment.Type == "full" || refunded >= fact.TotalMinor) {
				observed.cutoff = adjustment.UpdatedAt.UTC().Truncate(time.Microsecond)
			}
		case 3:
			if reversed {
				observed.chargebackReversed = true
			} else if observed.cutoff.IsZero() {
				observed.cutoff = adjustment.UpdatedAt.UTC().Truncate(time.Microsecond)
			}
		case 6:
			observed.chargebackReversed = true
		}
	}
	return observed, nil
}

func (s *Service) appendBilling(ctx context.Context, tx pgx.Tx, account, subscription platform.ID, event, ref string,
	kind int16, currency string, amount int64, occurred, now time.Time) error {
	tag, err := tx.Exec(ctx, `INSERT INTO commerce.billing_entry(entry_id,account_id,subscription_id,provider,environment,provider_entry_ref,kind,
currency,amount_minor,occurred_at,recorded_at,event_ref) VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT DO NOTHING`,
		platform.NewID(), account, subscription, s.environmentID, ref, kind, currency, amount, occurred.UTC().Truncate(time.Microsecond), now, event)
	if err != nil || tag.RowsAffected() == 1 {
		return err
	}
	var match bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM commerce.billing_entry WHERE provider=1 AND environment=$1 AND provider_entry_ref=$2
AND kind=$3 AND account_id=$4 AND subscription_id=$5 AND currency=$6 AND amount_minor=$7 AND occurred_at=$8)`,
		s.environmentID, ref, kind, account, subscription, currency, amount, occurred.UTC().Truncate(time.Microsecond)).Scan(&match)
	if err == nil && !match {
		return errUnboundFacts
	}
	return err
}
