// SPDX-License-Identifier: AGPL-3.0-only

package commerce

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/commerce/paddle"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

const (
	purchasePending  int16 = 1
	purchaseUnknown  int16 = 2
	purchaseComplete int16 = 3
	purchaseExpired  int16 = 4

	checkoutPending  int16 = 1
	checkoutCreated  int16 = 2
	checkoutComplete int16 = 3
	checkoutExpired  int16 = 4
	checkoutUnknown  int16 = 5
)

var purchaseNames = [...]string{"", "pending", "unknown", "completed", "expired"}
var checkoutNames = [...]string{"", "pending", "provider_created", "completed", "expired", "unknown"}

func (s *Service) CreatePurchase(ctx context.Context, actor Actor, request PurchaseRequest) (Purchase, error) {
	if request.PurchaseID == (platform.ID{}) || request.OfferID == (platform.ID{}) {
		return Purchase{}, arc.InvalidArgument("purchase_intent_id", "required")
	}
	_, err := s.reserve(ctx, actor, request.CommandID, "CreatePurchaseIntent", request.CommandPayload,
		func(ctx context.Context, tx pgx.Tx, now time.Time, digest [32]byte) (bool, error) {
			var original platform.ID
			var recorded []byte
			err := tx.QueryRow(ctx, `SELECT purchase_id,intent_sha256 FROM commerce.purchase
WHERE account_id=$1 AND command_id=$2`, actor.Account, request.CommandID).Scan(&original, &recorded)
			if err == nil {
				if request.PurchaseID != original || !bytes.Equal(recorded, digest[:]) {
					return false, arc.CommandIDReused()
				}
				return false, nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return false, err
			}
			offer, exists := s.findOffer(request.OfferID)
			if !s.catalogue.SalesOpen {
				return false, arc.InvalidState("commerce", "sales_closed")
			}
			if !exists || offer.PriceVersion != request.PriceVersion || (offer.Region != "" && offer.Region != request.Region) {
				return false, arc.InvalidArgument("offer_id", "offer_version")
			}
			// A provider can still retry a renewal after the local paid
			// window ends or its service grant is revoked. Only a verified
			// terminal subscription without paid time can admit a new one.
			var blocked bool
			if err := tx.QueryRow(ctx, `SELECT (u.state<>1 OR EXISTS (
SELECT 1 FROM commerce.subscription s WHERE s.account_id=u.user_id AND s.provider=1 AND s.environment=$2
AND (s.state<>$4 OR s.auto_renew OR s.valid_until>$3))) FROM identity.user u WHERE u.user_id=$1`,
				actor.Account, s.environmentID, now, subscriptionExpired).Scan(&blocked); err != nil {
				return false, err
			}
			if blocked {
				return false, arc.InvalidState("commerce", "purchase_unavailable")
			}
			// An expiry without a send claim is safe to retire. An ambiguous
			// send can reconcile indefinitely using its original identity.
			if _, err = tx.Exec(ctx, `UPDATE commerce.purchase p SET state=4,updated_at=$3,rev=rev+1
WHERE p.account_id=$1 AND p.provider=1 AND p.environment=$2 AND p.state=1 AND p.expires_at<=$3
AND NOT EXISTS (SELECT 1 FROM commerce.checkout c WHERE c.purchase_id=p.purchase_id AND c.send_claimed_at IS NOT NULL)`,
				actor.Account, s.environmentID, now); err != nil {
				return false, err
			}
			tag, err := tx.Exec(ctx, `INSERT INTO commerce.purchase(purchase_id,account_id,command_id,provider,environment,catalog_version,
offer_ref,product_ref,price_ref,price_version,definition_version,currency,amount_minor,billing_interval,region,adjustment_policy,
intent_sha256,state,created_at,expires_at,updated_at,rev)
VALUES($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,1,$17,$18,$17,1) ON CONFLICT DO NOTHING`,
				request.PurchaseID, actor.Account, request.CommandID, s.environmentID, s.catalogue.Version, offer.ID.String(),
				offer.ProductID, offer.PriceID, offer.PriceVersion, offer.DefinitionsVersion, offer.Currency, offer.AmountMinor,
				offer.Interval, offer.Region, offer.AdjustmentPolicy, digest[:], now, now.Add(s.catalogue.CheckoutLifetime))
			if err != nil {
				return false, err
			}
			if tag.RowsAffected() != 1 {
				return false, arc.InvalidState("commerce", "purchase_already_pending")
			}
			return false, s.audit(ctx, tx, now, actor.Account, "purchase_reserved", "purchase", request.PurchaseID, &request.CommandID, &actor.Correlation)
		})
	if err != nil {
		return Purchase{}, err
	}
	return s.GetPurchase(ctx, actor, request.PurchaseID)
}

func (s *Service) GetPurchase(ctx context.Context, actor Actor, id platform.ID) (Purchase, error) {
	result := Purchase{ID: id}
	err := s.read(ctx, actor, func(ctx context.Context, tx pgx.Tx, now time.Time) error {
		var state int16
		err := tx.QueryRow(ctx, `SELECT offer_ref::uuid,price_version,
CASE WHEN p.state=1 AND p.expires_at<=$4 THEN 4
     WHEN p.state=2 AND p.expires_at>$4 AND EXISTS(
         SELECT 1 FROM commerce.checkout c WHERE c.purchase_id=p.purchase_id AND c.state=2
         AND NOT EXISTS (SELECT 1 FROM commerce.provider_event e
             WHERE e.account_id=p.account_id AND e.provider=p.provider AND e.environment=p.environment
             AND e.state=3 AND e.failure_code IN ('late_payment_review','chargeback_reversal_review','definitions_approval_review'))
     ) THEN 1
     ELSE p.state END,rev,expires_at
FROM commerce.purchase p WHERE purchase_id=$1 AND account_id=$2 AND provider=1 AND environment=$3`,
			id, actor.Account, s.environmentID, now).Scan(&result.OfferID, &result.PriceVersion, &state, &result.Revision, &result.ExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return arc.NotFound("purchase", id[:])
		}
		if err == nil {
			result.State = purchaseNames[state]
		}
		return err
	})
	return result, err
}

type storedCheckout struct {
	Checkout
	Account, IntentID                platform.ID
	Catalogue, Customer, Transaction string
	Offer                            Offer
	ClaimedAt                        *time.Time
}

const checkoutColumns = `c.checkout_id,c.purchase_id,c.account_id,c.provider_intent_id,p.offer_ref::uuid,
p.catalog_version,p.product_ref,p.price_ref,p.price_version,p.definition_version,p.currency,p.amount_minor,
p.billing_interval,p.region,p.adjustment_policy,coalesce(k.provider_customer_ref,''),coalesce(c.provider_checkout_ref,''),
c.send_claimed_at,c.state,c.expires_at`

const checkoutJoin = ` FROM commerce.checkout c JOIN commerce.purchase p ON p.purchase_id=c.purchase_id
LEFT JOIN commerce.customer k ON (k.account_id,k.provider,k.environment)=(c.account_id,c.provider,c.environment) `

func scanCheckout(row pgx.Row) (storedCheckout, error) {
	var result storedCheckout
	var state int16
	err := row.Scan(&result.ID, &result.PurchaseID, &result.Account, &result.IntentID, &result.Offer.ID,
		&result.Catalogue, &result.Offer.ProductID, &result.Offer.PriceID, &result.Offer.PriceVersion,
		&result.Offer.DefinitionsVersion, &result.Offer.Currency, &result.Offer.AmountMinor, &result.Offer.Interval,
		&result.Offer.Region, &result.Offer.AdjustmentPolicy, &result.Customer, &result.Transaction, &result.ClaimedAt, &state, &result.ExpiresAt)
	if err == nil {
		result.State = checkoutNames[state]
	}
	return result, err
}

func (s *Service) checkout(ctx context.Context, actor Actor, id platform.ID) (storedCheckout, error) {
	var result storedCheckout
	err := s.read(ctx, actor, func(ctx context.Context, tx pgx.Tx, _ time.Time) error {
		var err error
		result, err = scanCheckout(tx.QueryRow(ctx, "SELECT "+checkoutColumns+checkoutJoin+
			"WHERE c.checkout_id=$1 AND c.account_id=$2 AND c.provider=1 AND c.environment=$3", id, actor.Account, s.environmentID))
		if errors.Is(err, pgx.ErrNoRows) {
			return arc.NotFound("checkout", id[:])
		}
		return err
	})
	return result, err
}

func (s *Service) CreateCheckout(ctx context.Context, actor Actor, request CheckoutAttemptRequest) (Checkout, error) {
	if request.PurchaseID == (platform.ID{}) || request.CheckoutID == (platform.ID{}) || request.ReturnPath != "/account/subscription" {
		return Checkout{}, arc.InvalidArgument("checkout_attempt_id", "checkout_identity")
	}
	path := request.ReturnPath
	claimed, err := s.reserve(ctx, actor, request.CommandID, "CreateCheckoutAttempt", request.CommandPayload,
		func(ctx context.Context, tx pgx.Tx, now time.Time, digest [32]byte) (bool, error) {
			var original platform.ID
			var recorded []byte
			err := tx.QueryRow(ctx, `SELECT checkout_id,intent_sha256 FROM commerce.checkout
WHERE account_id=$1 AND command_id=$2`, actor.Account, request.CommandID).Scan(&original, &recorded)
			if err == nil {
				if request.CheckoutID != original || !bytes.Equal(recorded, digest[:]) {
					return false, arc.CommandIDReused()
				}
				return false, nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return false, err
			}
			var expires time.Time
			var state int16
			err = tx.QueryRow(ctx, `SELECT expires_at,state FROM commerce.purchase
WHERE purchase_id=$1 AND account_id=$2 AND provider=1 AND environment=$3 FOR UPDATE`,
				request.PurchaseID, actor.Account, s.environmentID).Scan(&expires, &state)
			if errors.Is(err, pgx.ErrNoRows) {
				return false, arc.NotFound("purchase", request.PurchaseID[:])
			}
			if err != nil {
				return false, err
			}
			if !s.catalogue.SalesOpen || state != purchasePending || !now.Before(expires) {
				return false, arc.InvalidState("checkout", "purchase_unavailable")
			}
			var active bool
			if err = tx.QueryRow(ctx, "SELECT state=1 FROM identity.user WHERE user_id=$1", actor.Account).Scan(&active); err != nil {
				return false, err
			}
			if !active {
				return false, arc.PermissionDenied("commerce.checkout")
			}
			tag, err := tx.Exec(ctx, `INSERT INTO commerce.checkout(checkout_id,purchase_id,account_id,command_id,provider,environment,
intent_sha256,return_path,provider_intent_id,state,send_claimed_at,created_at,expires_at,updated_at)
VALUES($1,$2,$3,$4,1,$5,$6,$7,$8,5,$9,$9,$10,$9) ON CONFLICT DO NOTHING`,
				request.CheckoutID, request.PurchaseID, actor.Account, request.CommandID, s.environmentID,
				digest[:], path, platform.NewID(), now, expires)
			if err != nil {
				return false, err
			}
			if tag.RowsAffected() != 1 {
				return false, arc.InvalidState("checkout", "checkout_already_reserved")
			}
			if _, err = tx.Exec(ctx, "UPDATE commerce.purchase SET state=2,updated_at=$2,rev=rev+1 WHERE purchase_id=$1", request.PurchaseID, now); err != nil {
				return false, err
			}
			return true, s.audit(ctx, tx, now, actor.Account, "checkout_claimed", "checkout", request.CheckoutID, &request.CommandID, &actor.Correlation)
		})
	if err != nil {
		return Checkout{}, err
	}
	checkout, err := s.checkout(ctx, actor, request.CheckoutID)
	if err != nil || checkout.State == checkoutNames[checkoutComplete] || checkout.State == checkoutNames[checkoutExpired] ||
		!s.now().Before(checkout.ExpiresAt) {
		return checkout.Checkout, err
	}
	result, found, err := s.checkoutFact(ctx, checkout, claimed)
	if err != nil || !found {
		// The stable stored identity remains queryable and no retry can
		// dispatch a second provider create.
		return checkout.Checkout, nil
	}
	if err := s.recordCheckout(ctx, checkout, result); err != nil {
		return Checkout{}, err
	}
	current, err := s.checkout(ctx, actor, request.CheckoutID)
	if err == nil && s.catalogue.SalesOpen && current.State == checkoutNames[checkoutCreated] &&
		s.now().Before(current.ExpiresAt) && (result.Status == "draft" || result.Status == "ready") {
		current.URL = result.CheckoutURL
	}
	return current.Checkout, err
}

func (s *Service) checkoutFact(ctx context.Context, checkout storedCheckout, claimed bool) (paddle.Transaction, bool, error) {
	binding := paddle.CheckoutRequest{IntentID: checkout.IntentID.String(), CustomerID: checkout.Customer, PriceID: checkout.Offer.PriceID}
	if checkout.ClaimedAt == nil {
		return paddle.Transaction{}, false, errUnboundFacts
	}
	binding.CreatedAfter = checkout.ClaimedAt.Add(-paddle.SignatureTolerance)
	binding.CreatedBefore = checkout.ClaimedAt.Add(5 * time.Minute)
	if claimed {
		fact, err := s.provider.CreateCheckout(ctx, binding)
		return fact, err == nil, err
	}
	if checkout.Transaction != "" {
		fact, err := s.provider.GetTransaction(ctx, checkout.Transaction)
		return fact, err == nil, err
	}
	return s.provider.FindCheckout(ctx, binding)
}

func checkoutMatches(checkout storedCheckout, fact paddle.Transaction) bool {
	return idText.MatchString(fact.ID) && strings.HasPrefix(fact.ID, "txn_") && fact.IntentID == checkout.IntentID.String() && fact.Origin == "api" && fact.CollectionMode == "automatic" &&
		(checkout.Transaction == "" || checkout.Transaction == fact.ID) &&
		(checkout.Customer == "" || checkout.Customer == fact.CustomerID) &&
		oneProduct(fact.Items, checkout.Offer.PriceID, checkout.Offer.ProductID)
}

func oneProduct(items []paddle.Item, price, product string) bool {
	return len(items) == 1 && items[0].PriceID == price && items[0].ProductID == product && items[0].Quantity == 1
}

func (s *Service) bindCustomer(ctx context.Context, tx pgx.Tx, account platform.ID, customer string, now time.Time) error {
	if !idText.MatchString(customer) || !strings.HasPrefix(customer, "ctm_") {
		return arc.InvalidState("checkout", "provider_customer_unverified")
	}
	if _, err := tx.Exec(ctx, `INSERT INTO commerce.customer(account_id,provider,environment,provider_customer_ref,created_at)
VALUES($1,1,$2,$3,$4) ON CONFLICT DO NOTHING`, account, s.environmentID, customer, now); err != nil {
		return err
	}
	var same bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM commerce.customer
WHERE account_id=$1 AND provider=1 AND environment=$2 AND provider_customer_ref=$3)`, account, s.environmentID, customer).Scan(&same)
	if err != nil {
		return err
	}
	if !same {
		return arc.InvalidState("checkout", "provider_customer_mismatch")
	}
	return nil
}

func (s *Service) recordCheckout(ctx context.Context, checkout storedCheckout, fact paddle.Transaction) error {
	if !checkoutMatches(checkout, fact) {
		return arc.InvalidState("checkout", "provider_result_unverified")
	}
	return s.db.InTx(ctx, "bind a verified checkout", store.TxOptions{Timeout: 5 * time.Second},
		func(ctx context.Context, tx pgx.Tx) error {
			if _, err := lockAccount(ctx, tx, checkout.Account); err != nil {
				return err
			}
			now := s.now()
			if err := s.bindCheckout(ctx, tx, checkout, fact, now); err != nil {
				return err
			}
			if fact.Status == "canceled" {
				return expireVerifiedCheckout(ctx, tx, checkout, now)
			}
			return nil
		})
}

func expireVerifiedCheckout(ctx context.Context, tx pgx.Tx, checkout storedCheckout, now time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE commerce.checkout SET state=4,updated_at=$2 WHERE checkout_id=$1 AND state IN(1,2,5)`,
		checkout.ID, now); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE commerce.purchase SET state=4,updated_at=$2,rev=rev+1 WHERE purchase_id=$1 AND state IN(1,2)`,
		checkout.PurchaseID, now)
	return err
}

func (s *Service) bindCheckout(ctx context.Context, tx pgx.Tx, checkout storedCheckout, fact paddle.Transaction, now time.Time) error {
	if fact.CustomerID != "" {
		if err := s.bindCustomer(ctx, tx, checkout.Account, fact.CustomerID, now); err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `UPDATE commerce.checkout SET provider_checkout_ref=$3,provider_customer_ref=nullif($4,''),
state=2,updated_at=$5 WHERE checkout_id=$1 AND account_id=$2 AND state IN (1,2,5)
AND (provider_checkout_ref IS NULL OR provider_checkout_ref=$3)
AND (provider_customer_ref IS NULL OR provider_customer_ref=$4)
AND (provider_checkout_ref IS NULL OR provider_customer_ref IS DISTINCT FROM nullif($4,'') OR state<>2)`,
		checkout.ID, checkout.Account, fact.ID, fact.CustomerID, now)
	return err
}
