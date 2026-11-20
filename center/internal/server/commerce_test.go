// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/commerce"
	"github.com/ArcForges/Cloud/center/internal/commerce/paddle"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

func TestPaddleAdmissionPreservesSignedBytesAndOnlyAcknowledgesARecordedEvent(t *testing.T) {
	const secret = "Paddle-webhook-test-only"
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	verifier, err := paddle.NewWebhookVerifier(paddle.Sandbox, secret)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{ "event_id": "evt_01hv8p95hhbb2nsarbq3f0rwx8", "notification_id": "ntf_01hv8p95hhbb2nsarbq3f0rwx8",
		"event_type": "transaction.completed", "occurred_at": "2026-11-21T11:59:55Z",
		"data": {"id": "txn_01hv8p95hhbb2nsarbq3f0rwx8"} }`)
	address := ClientAddress(config.OfficialHosted, config.Identity{ClientIPHeader: config.ClientIPHeader})
	for _, test := range []struct {
		name   string
		change func(*http.Request)
		body   []byte
		status int
		admit  bool
		store  error
	}{
		{name: "durable receipt", status: http.StatusOK, admit: true},
		{name: "recording unavailable", status: http.StatusServiceUnavailable, admit: true, store: context.DeadlineExceeded},
		{name: "digest conflict", status: http.StatusBadRequest, admit: true, store: arc.InvalidState("provider_event", "event_digest_mismatch")},
		{name: "duplicate signature", status: http.StatusBadRequest, change: func(r *http.Request) {
			r.Header.Add(routes.PaddleWebhookSignatureHeader, r.Header.Get(routes.PaddleWebhookSignatureHeader))
		}},
		{name: "body changed", status: http.StatusBadRequest, body: append(bytes.Clone(raw), ' ')},
		{name: "stale signature", status: http.StatusBadRequest, change: func(r *http.Request) {
			r.Header.Set(routes.PaddleWebhookSignatureHeader, fixturePaddleSignature(secret, now.Add(-6*time.Second), raw))
		}},
		{name: "missing Worker address", status: http.StatusNotFound, change: func(r *http.Request) { r.Header.Del(config.ClientIPHeader) }},
		{name: "other method", status: http.StatusMethodNotAllowed, change: func(r *http.Request) { r.Method = http.MethodGet }},
		{name: "empty query", status: http.StatusNotFound, change: func(r *http.Request) { r.URL.ForceQuery = true }},
		{name: "content encoding", status: http.StatusUnsupportedMediaType, change: func(r *http.Request) { r.Header.Set("Content-Encoding", "identity") }},
		{name: "oversized length", status: http.StatusRequestEntityTooLarge, change: func(r *http.Request) {
			r.ContentLength = routes.PaddleWebhookMaxRequestBytes + 1
		}},
		{name: "oversized streamed body", status: http.StatusRequestEntityTooLarge, body: make([]byte, routes.PaddleWebhookMaxRequestBytes+1),
			change: func(r *http.Request) { r.ContentLength = -1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			handler := paddleWebhook(clock, address, verifier, func(ctx context.Context, event paddle.Event) (commerce.EventReceipt, error) {
				calls++
				deadline, bounded := ctx.Deadline()
				if !bounded || time.Until(deadline) > 5*time.Second ||
					event.Environment != paddle.Sandbox || event.Digest != sha256.Sum256(raw) || event.Kind != "transaction.completed" {
					t.Fatal("notification lost its verified body identity or admission deadline")
				}
				return commerce.EventReceipt{}, test.store
			})
			body := test.body
			if body == nil {
				body = raw
			}
			request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, routes.PaddleWebhookPath, bytes.NewReader(body))
			request.Header.Set(config.ClientIPHeader, "203.0.113.7")
			request.Header.Set("Content-Type", routes.TypeJSON)
			request.Header.Set(routes.PaddleWebhookSignatureHeader, fixturePaddleSignature(secret, now, raw))
			if test.change != nil {
				test.change(request)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || response.Body.Len() != 0 || response.Header().Get("Cache-Control") != "no-store" ||
				test.admit != (calls == 1) {
				t.Fatalf("response %d, callbacks %d", response.Code, calls)
			}
		})
	}
}

func fixturePaddleSignature(secret string, at time.Time, raw []byte) string {
	keyed := hmac.New(sha256.New, []byte(secret))
	timestamp := fmt.Sprint(at.Unix())
	_, _ = keyed.Write([]byte(timestamp + ":"))
	_, _ = keyed.Write(raw)
	return fmt.Sprintf("ts=%s;h1=%x", timestamp, keyed.Sum(nil))
}

func TestMerchantCatalogueRequiresOneRealmAndRejectsAmbiguousFields(t *testing.T) {
	raw := `{"version":"fixture-market-1","environment":"sandbox","sales_open":false,"checkout_lifetime":"20m","offers":[
		{"id":"11111111-2222-4333-8444-555555555555","price_version":"pv1","paddle_price_id":"pri_test",
		"paddle_product_id":"pro_test","definitions_version":"defs1","currency":"USD","interval":"month",
		"region":"US","amount_minor":1250,"adjustment_policy":"preserve_partial_end_full_or_chargeback"}]}`
	merchant, err := parseCommerceCatalogue([]byte(raw), "sandbox")
	if err != nil || merchant.SalesOpen || merchant.CheckoutLifetime != 20*time.Minute ||
		len(merchant.Offers) != 1 || merchant.Offers[0].AmountMinor != 1250 {
		t.Fatal("the paused sandbox catalogue did not load")
	}
	for _, body := range []string{
		strings.Replace(raw, `"environment":"sandbox"`, `"environment":"live"`, 1),
		strings.Replace(raw, `"sales_open":false`, `"sales_open":true,"sales_open":false`, 1),
		strings.Replace(raw, `"sales_open":false`, `"Sales_Open":false`, 1),
		strings.Replace(raw, `"currency":"USD"`, `"currency":"USD","currency":"JPY"`, 1),
		strings.Replace(raw, `"currency":"USD"`, `"currency":"USD","api_key":"test-marker"`, 1),
		strings.Replace(raw, `"sales_open":false`, `"sales_open":null`, 1),
		raw + " {}",
	} {
		if _, err := parseCommerceCatalogue([]byte(body), "sandbox"); err == nil || strings.Contains(err.Error(), "test-marker") {
			t.Fatal("an ambiguous merchant catalogue was accepted or echoed")
		}
	}
	for _, tc := range []struct {
		minor      int64
		code, want string
	}{{1250, "USD", "12.5"}, {1250, "JPY", "1250"}, {-1, "KWD", "-0.001"}, {0, "USD", "0"}} {
		if got, ok := commerceMoney(tc.minor, tc.code); !ok || got.GetValue() != tc.want {
			t.Errorf("%d %s: %s, %v", tc.minor, tc.code, got.GetValue(), ok)
		}
	}
}
