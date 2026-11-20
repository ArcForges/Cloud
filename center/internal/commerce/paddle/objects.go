// SPDX-License-Identifier: AGPL-3.0-only

package paddle

import (
	"encoding/json"
	"strconv"
	"time"
)

type wireItem struct {
	Price struct {
		ID        string `json:"id"`
		ProductID string `json:"product_id"`
	} `json:"price"`
	Quantity int `json:"quantity"`
}

func normalizedItems(raw []wireItem) ([]Item, bool) {
	if len(raw) == 0 || len(raw) > 64 {
		return nil, false
	}
	result := make([]Item, len(raw))
	for i, item := range raw {
		if !providerID(item.Price.ID, "pri_") || !providerID(item.Price.ProductID, "pro_") || item.Quantity < 1 {
			return nil, false
		}
		result[i] = Item{PriceID: item.Price.ID, ProductID: item.Price.ProductID, Quantity: item.Quantity}
	}
	return result, true
}

type wirePeriod struct {
	Start time.Time `json:"starts_at"`
	End   time.Time `json:"ends_at"`
}

func normalizePeriod(p *wirePeriod) (time.Time, time.Time, bool) {
	if p == nil {
		return time.Time{}, time.Time{}, true
	}
	return p.Start.UTC(), p.End.UTC(), !p.Start.IsZero() && p.End.After(p.Start)
}

type wireTransaction struct {
	ID             string                     `json:"id"`
	CustomerID     string                     `json:"customer_id"`
	SubscriptionID string                     `json:"subscription_id"`
	CustomData     map[string]json.RawMessage `json:"custom_data"`
	Origin         string                     `json:"origin"`
	Status         string                     `json:"status"`
	CollectionMode string                     `json:"collection_mode"`
	Currency       string                     `json:"currency_code"`
	Items          []wireItem                 `json:"items"`
	CreatedAt      time.Time                  `json:"created_at"`
	UpdatedAt      time.Time                  `json:"updated_at"`
	BilledAt       time.Time                  `json:"billed_at"`
	BillingPeriod  *wirePeriod                `json:"billing_period"`
	Checkout       struct {
		URL string `json:"url"`
	} `json:"checkout"`
	Details struct {
		Totals struct {
			Total    string `json:"total"`
			Currency string `json:"currency_code"`
		} `json:"totals"`
	} `json:"details"`
}

func (r wireTransaction) intent() (string, bool) {
	raw, ok := r.CustomData[IntentField]
	if !ok {
		return "", true
	}
	var intent string
	if json.Unmarshal(raw, &intent) != nil || !validIntent(intent) {
		return "", false
	}
	return intent, true
}

func (r wireTransaction) normalize() (Transaction, bool) {
	var amount int64
	if !providerID(r.ID, "txn_") || r.UpdatedAt.IsZero() || r.CreatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) ||
		r.CustomerID != "" && !providerID(r.CustomerID, "ctm_") || r.SubscriptionID != "" && !providerID(r.SubscriptionID, "sub_") ||
		r.CollectionMode != "automatic" && r.CollectionMode != "manual" || !safeDiagnostic(r.Origin) || !validCurrency(r.Currency) {
		return Transaction{}, false
	}
	switch r.Status {
	case "draft", "ready", "billed", "paid", "completed", "canceled", "past_due":
	default:
		return Transaction{}, false
	}
	if r.Status == "completed" && (r.CustomerID == "" || r.BilledAt.IsZero()) {
		return Transaction{}, false
	}
	if r.Details.Totals.Total != "" {
		var ok bool
		amount, ok = parseSignedMinor(r.Details.Totals.Total)
		if !ok || amount < 0 || r.Details.Totals.Currency != r.Currency {
			return Transaction{}, false
		}
	} else if r.Status == "completed" || r.Status == "paid" {
		return Transaction{}, false
	}
	items, validItems := normalizedItems(r.Items)
	start, end, validPeriod := normalizePeriod(r.BillingPeriod)
	intent, validBinding := r.intent()
	if !validItems || !validPeriod || !validBinding {
		return Transaction{}, false
	}
	return Transaction{
		ID: r.ID, CustomerID: r.CustomerID, SubscriptionID: r.SubscriptionID, IntentID: intent,
		Origin: r.Origin, Status: r.Status, CollectionMode: r.CollectionMode, Currency: r.Currency, Items: items, TotalMinor: amount,
		CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC(), BilledAt: r.BilledAt.UTC(), PeriodStart: start, PeriodEnd: end,
	}, true
}

type wireSubscription struct {
	ID             string      `json:"id"`
	CustomerID     string      `json:"customer_id"`
	Status         string      `json:"status"`
	CollectionMode string      `json:"collection_mode"`
	Items          []wireItem  `json:"items"`
	UpdatedAt      time.Time   `json:"updated_at"`
	BillingPeriod  *wirePeriod `json:"current_billing_period"`
	Scheduled      *struct {
		Action      string    `json:"action"`
		EffectiveAt time.Time `json:"effective_at"`
	} `json:"scheduled_change"`
}

func (r wireSubscription) normalize() (Subscription, bool) {
	if !providerID(r.ID, "sub_") || !providerID(r.CustomerID, "ctm_") || r.UpdatedAt.IsZero() ||
		r.CollectionMode != "automatic" && r.CollectionMode != "manual" {
		return Subscription{}, false
	}
	switch r.Status {
	case "active", "past_due", "paused", "canceled", "trialing":
	default:
		return Subscription{}, false
	}
	items, validItems := normalizedItems(r.Items)
	start, end, validPeriod := normalizePeriod(r.BillingPeriod)
	if !validItems || !validPeriod {
		return Subscription{}, false
	}
	result := Subscription{ID: r.ID, CustomerID: r.CustomerID, Status: r.Status,
		CollectionMode: r.CollectionMode, Items: items, UpdatedAt: r.UpdatedAt.UTC(), PeriodStart: start, PeriodEnd: end}
	if r.Scheduled != nil {
		switch r.Scheduled.Action {
		case "cancel", "pause", "resume":
		default:
			return Subscription{}, false
		}
		if r.Scheduled.EffectiveAt.IsZero() {
			return Subscription{}, false
		}
		result.ScheduledAction = r.Scheduled.Action
		result.ScheduledAt = r.Scheduled.EffectiveAt.UTC()
	}
	return result, true
}

type wireAdjustment struct {
	ID             string    `json:"id"`
	TransactionID  string    `json:"transaction_id"`
	SubscriptionID string    `json:"subscription_id"`
	CustomerID     string    `json:"customer_id"`
	Action         string    `json:"action"`
	Type           string    `json:"type"`
	Status         string    `json:"status"`
	Currency       string    `json:"currency_code"`
	UpdatedAt      time.Time `json:"updated_at"`
	CreatedAt      time.Time `json:"created_at"`
	Totals         struct {
		Total    string `json:"total"`
		Currency string `json:"currency_code"`
	} `json:"totals"`
}

func (r wireAdjustment) normalize() (Adjustment, bool) {
	if !providerID(r.ID, "adj_") || !providerID(r.TransactionID, "txn_") || !providerID(r.CustomerID, "ctm_") ||
		r.SubscriptionID != "" && !providerID(r.SubscriptionID, "sub_") ||
		r.Type != "full" && r.Type != "partial" || !validCurrency(r.Currency) || r.Currency != r.Totals.Currency {
		return Adjustment{}, false
	}
	switch r.Action {
	case "credit", "refund", "chargeback", "chargeback_reverse", "chargeback_warning", "chargeback_warning_reverse", "credit_reverse":
	default:
		return Adjustment{}, false
	}
	switch r.Status {
	case "pending_approval", "approved", "rejected", "reversed":
	default:
		return Adjustment{}, false
	}
	// Adjustment totals are signed. Paddle's credit_reverse example
	// includes a negative total, and the value is retained as received.
	// https://developer.paddle.com/api-reference/adjustments/list-adjustments/
	amount, ok := parseSignedMinor(r.Totals.Total)
	if !ok || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || r.UpdatedAt.Before(r.CreatedAt) {
		return Adjustment{}, false
	}
	return Adjustment{ID: r.ID, TransactionID: r.TransactionID, SubscriptionID: r.SubscriptionID, CustomerID: r.CustomerID,
		Action: r.Action, Type: r.Type, Status: r.Status, Currency: r.Currency, TotalMinor: amount, CreatedAt: r.CreatedAt.UTC(), UpdatedAt: r.UpdatedAt.UTC()}, true
}

func validCurrency(value string) bool {
	return len(value) == 3 && value[0] >= 'A' && value[0] <= 'Z' &&
		value[1] >= 'A' && value[1] <= 'Z' && value[2] >= 'A' && value[2] <= 'Z'
}

func parseSignedMinor(value string) (int64, bool) {
	n, err := strconv.ParseInt(value, 10, 64)
	return n, err == nil && strconv.FormatInt(n, 10) == value
}
