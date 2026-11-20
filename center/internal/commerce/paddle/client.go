// SPDX-License-Identifier: AGPL-3.0-only

package paddle

import (
	"context"
	"net/http"
	"net/url"
	"time"
)

const (
	transactions  = "/transactions"
	subscriptions = "/subscriptions"
	adjustments   = "/adjustments"
)

func validCheckout(request CheckoutRequest) bool {
	return validIntent(request.IntentID) && providerID(request.PriceID, "pri_") &&
		(request.CustomerID == "" || providerID(request.CustomerID, "ctm_"))
}

func matchesCheckout(transaction Transaction, request CheckoutRequest) bool {
	return transaction.IntentID == request.IntentID && transaction.Origin == "api" && transaction.CollectionMode == "automatic" &&
		(request.CustomerID == "" || request.CustomerID == transaction.CustomerID) &&
		len(transaction.Items) == 1 && transaction.Items[0].PriceID == request.PriceID && transaction.Items[0].Quantity == 1
}

func (c *Client) checkoutLink(transaction Transaction, raw string) (string, bool) {
	if raw == "" || transaction.Status != "draft" && transaction.Status != "ready" {
		return "", true
	}
	u, ok := httpsURL(raw)
	if !ok || !c.checkouts[originOf(u)] {
		return "", false
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q["_ptxn"]) != 1 || q.Get("_ptxn") != transaction.ID {
		return "", false
	}
	return raw, true
}

func invalidReply(operation string) error {
	return &Error{Operation: operation, cause: ErrUncertain}
}

// CreateCheckout sends a single automatic-collection transaction request.
// The provider's v1 create operation does not define a generic idempotency
// header. Reconcile the original intent after an uncertain response.
// https://developer.paddle.com/api-reference/transactions/create-transaction/
func (c *Client) CreateCheckout(ctx context.Context, request CheckoutRequest) (Transaction, error) {
	const operation = "create_checkout"
	if !validCheckout(request) {
		return Transaction{}, ErrInvalidRequest
	}
	type line struct {
		PriceID  string `json:"price_id"`
		Quantity int    `json:"quantity"`
	}
	input := struct {
		Items          []line            `json:"items"`
		CustomerID     string            `json:"customer_id,omitempty"`
		CollectionMode string            `json:"collection_mode"`
		CustomData     map[string]string `json:"custom_data"`
	}{
		Items: []line{{PriceID: request.PriceID, Quantity: 1}}, CustomerID: request.CustomerID,
		CollectionMode: "automatic", CustomData: map[string]string{IntentField: request.IntentID},
	}
	var raw wireTransaction
	if _, err := c.request(ctx, operation, http.MethodPost, transactions, nil, input, &raw); err != nil {
		return Transaction{}, err
	}
	result, ok := raw.normalize()
	if !ok || !matchesCheckout(result, request) {
		return Transaction{}, invalidReply(operation)
	}
	result.CheckoutURL, ok = c.checkoutLink(result, raw.Checkout.URL)
	if !ok || result.CheckoutURL == "" {
		return Transaction{}, invalidReply(operation)
	}
	return result, nil
}

// FindCheckout uses bounded official list pagination and the exact opaque
// custom-data marker. An incomplete or ambiguous search stays uncertain.
// https://developer.paddle.com/api-reference/transactions/list-transactions/
func (c *Client) FindCheckout(ctx context.Context, request CheckoutRequest) (Transaction, bool, error) {
	const operation = "find_checkout"
	if !validCheckout(request) || request.CreatedAfter.IsZero() || !request.CreatedBefore.After(request.CreatedAfter) {
		return Transaction{}, false, ErrInvalidRequest
	}
	query := url.Values{
		"origin":          {"api"},
		"created_at[GTE]": {request.CreatedAfter.UTC().Format(time.RFC3339Nano)},
		"created_at[LTE]": {request.CreatedBefore.UTC().Format(time.RFC3339Nano)},
		"order_by":        {"id[DESC]"},
	}
	if request.CustomerID != "" {
		query.Set("customer_id", request.CustomerID)
	}
	batch, err := list[wireTransaction](ctx, c, operation, transactions, "txn_", query)
	if err != nil {
		return Transaction{}, false, err
	}
	var match Transaction
	for _, raw := range batch {
		intent, bound := raw.intent()
		// Confirm that the provider applied the entire requested scope.
		// An unrelated renewal can carry the same custom_data marker.
		if !bound || raw.Origin != "api" || raw.CreatedAt.IsZero() ||
			raw.CreatedAt.Before(request.CreatedAfter) || raw.CreatedAt.After(request.CreatedBefore) ||
			request.CustomerID != "" && raw.CustomerID != request.CustomerID {
			return Transaction{}, false, invalidReply(operation)
		}
		if intent != request.IntentID {
			continue
		}
		result, ok := raw.normalize()
		if !ok || !matchesCheckout(result, request) || match.ID != "" {
			return Transaction{}, false, invalidReply(operation)
		}
		result.CheckoutURL, ok = c.checkoutLink(result, raw.Checkout.URL)
		if !ok {
			return Transaction{}, false, invalidReply(operation)
		}
		match = result
	}
	return match, match.ID != "", nil
}

func (c *Client) GetTransaction(ctx context.Context, id string) (Transaction, error) {
	const operation = "get_transaction"
	if !providerID(id, "txn_") {
		return Transaction{}, ErrInvalidRequest
	}
	var raw wireTransaction
	if _, err := c.request(ctx, operation, http.MethodGet, transactions+"/"+id, nil, nil, &raw); err != nil {
		return Transaction{}, err
	}
	result, ok := raw.normalize()
	if !ok || result.ID != id {
		return Transaction{}, invalidReply(operation)
	}
	result.CheckoutURL, ok = c.checkoutLink(result, raw.Checkout.URL)
	if !ok {
		return Transaction{}, invalidReply(operation)
	}
	return result, nil
}

func (c *Client) ListTransactionsBySubscription(ctx context.Context, id string) ([]Transaction, error) {
	const operation = "list_subscription_transactions"
	if !providerID(id, "sub_") {
		return nil, ErrInvalidRequest
	}
	batch, err := list[wireTransaction](ctx, c, operation, transactions, "txn_", url.Values{"subscription_id": {id}})
	if err != nil {
		return nil, err
	}
	result := make([]Transaction, 0, len(batch))
	seen := make(map[string]bool, len(batch))
	for _, raw := range batch {
		transaction, ok := raw.normalize()
		if !ok || transaction.SubscriptionID != id || seen[transaction.ID] {
			return nil, invalidReply(operation)
		}
		seen[transaction.ID] = true
		result = append(result, transaction)
	}
	return result, nil
}

func (c *Client) GetSubscription(ctx context.Context, id string) (Subscription, error) {
	return c.subscription(ctx, "get_subscription", http.MethodGet, id, "", nil)
}

// CancelAtPeriodEnd requests the published scheduled change.
// https://developer.paddle.com/api-reference/subscriptions/cancel-subscription/
func (c *Client) CancelAtPeriodEnd(ctx context.Context, id string) (Subscription, error) {
	const operation = "schedule_cancel"
	result, err := c.subscription(ctx, operation, http.MethodPost, id, "/cancel",
		map[string]string{"effective_from": "next_billing_period"})
	if err != nil {
		return Subscription{}, err
	}
	if result.ScheduledAction != "cancel" {
		return Subscription{}, invalidReply(operation)
	}
	return result, nil
}

// ResumeRenewal removes a scheduled cancellation while the subscription
// still exists. The Paddle resume endpoint is for already paused plans.
// https://developer.paddle.com/build/subscriptions/cancel-subscriptions/
func (c *Client) ResumeRenewal(ctx context.Context, id string) (Subscription, error) {
	const operation = "remove_scheduled_cancel"
	result, err := c.subscription(ctx, operation, http.MethodPatch, id, "",
		map[string]any{"scheduled_change": nil})
	if err != nil {
		return Subscription{}, err
	}
	if result.ScheduledAction != "" || result.Status == "canceled" || result.Status == "paused" {
		return Subscription{}, invalidReply(operation)
	}
	return result, nil
}

func (c *Client) subscription(ctx context.Context, operation, method, id, suffix string, input any) (Subscription, error) {
	if !providerID(id, "sub_") {
		return Subscription{}, ErrInvalidRequest
	}
	var raw wireSubscription
	if _, err := c.request(ctx, operation, method, subscriptions+"/"+id+suffix, nil, input, &raw); err != nil {
		return Subscription{}, err
	}
	result, ok := raw.normalize()
	if !ok || result.ID != id {
		return Subscription{}, invalidReply(operation)
	}
	return result, nil
}

func (c *Client) GetAdjustment(ctx context.Context, id string) (Adjustment, error) {
	const operation = "get_adjustment"
	if !providerID(id, "adj_") {
		return Adjustment{}, ErrInvalidRequest
	}
	// Paddle v1 exposes an exact ID filter on the adjustment list.
	batch, err := list[wireAdjustment](ctx, c, operation, adjustments, "adj_", url.Values{"id": {id}})
	if err != nil {
		return Adjustment{}, err
	}
	if len(batch) != 1 {
		return Adjustment{}, invalidReply(operation)
	}
	result, ok := batch[0].normalize()
	if !ok || result.ID != id {
		return Adjustment{}, invalidReply(operation)
	}
	return result, nil
}

func (c *Client) ListAdjustments(ctx context.Context, transactionID string) ([]Adjustment, error) {
	const operation = "list_transaction_adjustments"
	if !providerID(transactionID, "txn_") {
		return nil, ErrInvalidRequest
	}
	batch, err := list[wireAdjustment](ctx, c, operation, adjustments, "adj_", url.Values{"transaction_id": {transactionID}})
	if err != nil {
		return nil, err
	}
	result := make([]Adjustment, 0, len(batch))
	seen := make(map[string]bool, len(batch))
	for _, raw := range batch {
		adjustment, ok := raw.normalize()
		if !ok || adjustment.TransactionID != transactionID || seen[adjustment.ID] {
			return nil, invalidReply(operation)
		}
		seen[adjustment.ID] = true
		result = append(result, adjustment)
	}
	return result, nil
}

// CreatePortal returns only a short-lived approved URL for the exact
// provider customer and optional subscription. No portal URL is logged.
// https://developer.paddle.com/api-reference/customer-portals/create-customer-portal-session/
func (c *Client) CreatePortal(ctx context.Context, customerID, subscriptionID string) (string, error) {
	const operation = "create_portal"
	if !providerID(customerID, "ctm_") || subscriptionID != "" && !providerID(subscriptionID, "sub_") {
		return "", ErrInvalidRequest
	}
	input := struct {
		SubscriptionIDs []string `json:"subscription_ids,omitempty"`
	}{}
	if subscriptionID != "" {
		input.SubscriptionIDs = []string{subscriptionID}
	}
	var result struct {
		ID         string `json:"id"`
		CustomerID string `json:"customer_id"`
		URLs       struct {
			General struct {
				Overview string `json:"overview"`
			} `json:"general"`
			Subscriptions []struct {
				ID   string `json:"id"`
				View string `json:"view_subscription"`
			} `json:"subscriptions"`
		} `json:"urls"`
	}
	if _, err := c.request(ctx, operation, http.MethodPost, "/customers/"+customerID+"/portal-sessions", nil, input, &result); err != nil {
		return "", err
	}
	if !providerID(result.ID, "cpls_") || result.CustomerID != customerID {
		return "", invalidReply(operation)
	}
	link := result.URLs.General.Overview
	if subscriptionID != "" {
		if len(result.URLs.Subscriptions) != 1 || result.URLs.Subscriptions[0].ID != subscriptionID {
			return "", invalidReply(operation)
		}
		link = result.URLs.Subscriptions[0].View
	}
	u, ok := httpsURL(link)
	if !ok || !c.portals[originOf(u)] {
		return "", invalidReply(operation)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q["token"]) != 1 || q.Get("token") == "" ||
		subscriptionID != "" && (len(q["subscription_id"]) != 1 || q.Get("subscription_id") != subscriptionID) {
		return "", invalidReply(operation)
	}
	return link, nil
}
