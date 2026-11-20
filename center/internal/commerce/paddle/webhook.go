// SPDX-License-Identifier: AGPL-3.0-only

package paddle

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Paddle Billing v1 signs the timestamp text, a colon, and the raw body.
// https://developer.paddle.com/webhooks/about/signature-verification/
const (
	MaxWebhookBytes    = 256 << 10
	SignatureTolerance = 5 * time.Second
	maxSignatureHeader = 512
	maxSignatures      = 4
)

// WebhookVerifier binds one configured destination to its environment. At
// most the current and previous secret are admitted during rotation.
type WebhookVerifier struct {
	environment Environment
	keys        [][]byte
}

func NewWebhookVerifier(env Environment, current string, previous ...string) (*WebhookVerifier, error) {
	if env.origin() == "" || len(previous) > 1 || !validSecret(current) {
		return nil, ErrConfiguration
	}
	v := &WebhookVerifier{environment: env, keys: [][]byte{[]byte(current)}}
	if len(previous) == 1 {
		if !validSecret(previous[0]) || current == previous[0] {
			return nil, ErrConfiguration
		}
		v.keys = append(v.keys, []byte(previous[0]))
	}
	return v, nil
}

func validSecret(secret string) bool {
	if len(secret) == 0 || len(secret) > 512 {
		return false
	}
	for i := range len(secret) {
		if secret[i] <= ' ' || secret[i] >= 127 {
			return false
		}
	}
	return true
}

// Verify authenticates the unmodified notification, then extracts the
// narrow reconciliation identity. Resource state in the signed body is
// not payment proof. The caller fetches current Paddle facts separately.
func (v *WebhookVerifier) Verify(raw []byte, header string, now time.Time) (Event, error) {
	if len(raw) == 0 || len(raw) > MaxWebhookBytes {
		return Event{}, ErrInvalidEvent
	}
	timestamp, signatures, ok := parseSignature(header)
	if !ok {
		return Event{}, ErrSignature
	}
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || seconds <= 0 || seconds > 253402300799 || strconv.FormatInt(seconds, 10) != timestamp {
		return Event{}, ErrSignature
	}
	age := now.Sub(time.Unix(seconds, 0))
	if age < -SignatureTolerance || age > SignatureTolerance {
		return Event{}, ErrSignature
	}
	var matched int
	for _, key := range v.keys {
		digest := hmac.New(sha256.New, key)
		digest.Write([]byte(timestamp + ":"))
		digest.Write(raw)
		expected := digest.Sum(nil)
		for _, signature := range signatures {
			matched |= subtle.ConstantTimeCompare(expected, signature)
		}
	}
	if matched != 1 {
		return Event{}, ErrSignature
	}

	var notification struct {
		ID             string          `json:"event_id"`
		Kind           string          `json:"event_type"`
		NotificationID string          `json:"notification_id"`
		OccurredAt     time.Time       `json:"occurred_at"`
		Data           json.RawMessage `json:"data"`
	}
	if err := decodeJSON(raw, &notification); err != nil || !providerID(notification.ID, "evt_") ||
		!providerID(notification.NotificationID, "ntf_") || notification.OccurredAt.IsZero() || len(notification.Data) == 0 {
		return Event{}, ErrInvalidEvent
	}
	prefix := eventResourcePrefix(notification.Kind)
	if prefix == "" {
		return Event{}, ErrUnsupportedEvent
	}
	var data struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(notification.Data, &data); err != nil || !providerID(data.ID, prefix) {
		return Event{}, ErrInvalidEvent
	}
	return Event{ID: notification.ID, Kind: notification.Kind, ResourceID: data.ID,
		NotificationID: notification.NotificationID, Environment: v.environment,
		OccurredAt: notification.OccurredAt.UTC(), Digest: sha256.Sum256(raw)}, nil
}

func parseSignature(header string) (string, [][]byte, bool) {
	if len(header) == 0 || len(header) > maxSignatureHeader {
		return "", nil, false
	}
	var timestamp string
	var signatures [][]byte
	for part := range strings.SplitSeq(header, ";") {
		key, value, ok := strings.Cut(part, "=")
		if !ok || value == "" {
			return "", nil, false
		}
		switch key {
		case "ts":
			if timestamp != "" {
				return "", nil, false
			}
			timestamp = value
		case "h1":
			if len(value) != sha256.Size*2 || len(signatures) == maxSignatures {
				return "", nil, false
			}
			digest, err := hex.DecodeString(value)
			if err != nil {
				return "", nil, false
			}
			signatures = append(signatures, digest)
		default:
			return "", nil, false
		}
	}
	return timestamp, signatures, timestamp != "" && len(signatures) > 0
}

func eventResourcePrefix(kind string) string {
	switch kind {
	case "transaction.completed", "transaction.paid", "transaction.payment_failed", "transaction.past_due", "transaction.canceled":
		return "txn_"
	case "subscription.created", "subscription.updated", "subscription.activated", "subscription.canceled",
		"subscription.past_due", "subscription.paused", "subscription.resumed", "subscription.trialing":
		return "sub_"
	case "adjustment.created", "adjustment.updated":
		return "adj_"
	}
	return ""
}
