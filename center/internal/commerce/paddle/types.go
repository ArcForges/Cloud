// SPDX-License-Identifier: AGPL-3.0-only

// Package paddle translates the fixed Paddle Billing v1 API and notification
// format. Its facts carry provider identities. Commerce owns the separately
// persisted intent, account, catalogue, and entitlement decisions.
package paddle

import (
	"errors"
	"fmt"
	"time"
)

const Version = "1"

// Environment selects the configured provider realm for both API requests
// and a webhook destination. A notification body does not select this realm.
type Environment string

const (
	Sandbox Environment = "sandbox"
	Live    Environment = "live"
)

func (e Environment) origin() string {
	switch e {
	case Sandbox:
		return "https://sandbox-api.paddle.com"
	case Live:
		return "https://api.paddle.com"
	default:
		return ""
	}
}

const IntentField = "arcforges_checkout_intent"

var (
	ErrConfiguration    = errors.New("invalid Paddle configuration")
	ErrInvalidRequest   = errors.New("invalid Paddle request")
	ErrRefused          = errors.New("Paddle refused the request")
	ErrUncertain        = errors.New("Paddle response could not establish an outcome")
	ErrSignature        = errors.New("Paddle notification signature refused")
	ErrInvalidEvent     = errors.New("invalid Paddle notification")
	ErrUnsupportedEvent = errors.New("Paddle notification type is outside the configured commerce surface")
)

// Error contains only bounded, classified provider diagnostics. It never
// includes a URL, response body, signature, API key, or provider error detail.
type Error struct {
	Operation string
	Status    int
	Code      string
	RequestID string
	Transport string
	cause     error
}

func (e *Error) Error() string {
	return fmt.Sprintf("Paddle %s: %v (HTTP %d, code %q, request %q, transport %q)",
		e.Operation, e.cause, e.Status, e.Code, e.RequestID, e.Transport)
}

func (e *Error) Unwrap() error { return e.cause }

type CheckoutRequest struct {
	// IntentID is the opaque identity already reserved in the local store.
	IntentID   string
	CustomerID string
	PriceID    string
	// CreatedAfter and CreatedBefore bound discovery of the original
	// submission. The caller derives them from the durable claim and
	// treats a missed result as an unresolved external outcome.
	CreatedAfter  time.Time
	CreatedBefore time.Time
}

type Item struct {
	PriceID   string
	ProductID string
	Quantity  int
}

type Transaction struct {
	ID             string
	CustomerID     string
	SubscriptionID string
	IntentID       string
	Origin         string
	Status         string
	CollectionMode string
	Currency       string
	CheckoutURL    string
	Items          []Item
	TotalMinor     int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
	BilledAt       time.Time
	PeriodStart    time.Time
	PeriodEnd      time.Time
}

type Subscription struct {
	ID              string
	CustomerID      string
	Status          string
	CollectionMode  string
	ScheduledAction string
	Items           []Item
	UpdatedAt       time.Time
	PeriodStart     time.Time
	PeriodEnd       time.Time
	ScheduledAt     time.Time
}

type Adjustment struct {
	ID             string
	TransactionID  string
	SubscriptionID string
	CustomerID     string
	Action         string
	Type           string
	Status         string
	Currency       string
	TotalMinor     int64
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type Event struct {
	ID             string
	Kind           string
	ResourceID     string
	NotificationID string
	Environment    Environment
	OccurredAt     time.Time
	Digest         [32]byte
}
