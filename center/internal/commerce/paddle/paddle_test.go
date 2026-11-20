// SPDX-License-Identifier: AGPL-3.0-only

package paddle

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var (
	fixtureTransaction  = "txn_" + strings.Repeat("1", 26)
	fixtureOther        = "txn_" + strings.Repeat("2", 26)
	fixtureCustomer     = "ctm_" + strings.Repeat("3", 26)
	fixtureSubscription = "sub_" + strings.Repeat("4", 26)
	fixturePrice        = "pri_" + strings.Repeat("5", 26)
	fixtureProduct      = "pro_" + strings.Repeat("6", 26)
	fixtureAdjustment   = "adj_" + strings.Repeat("7", 26)
	fixturePortal       = "cpls_" + strings.Repeat("8", 26)
	fixtureEvent        = "evt_" + strings.Repeat("9", 26)
	fixtureNotification = "ntf_" + strings.Repeat("0", 26)
)

const (
	fixtureAPIKey  = "pdl_sdbx_" + "apikey_transport-fixture"
	fixtureIntent  = "reservation_fixture_439"
	checkoutOrigin = "https://checkout.example.test"
	portalOrigin   = "https://customer-portal.example.test"
	fixtureTime    = "2026-11-20T12:00:00Z"
	fixtureEnd     = "2026-12-20T12:00:00Z"
)

type fixtureTransport struct {
	t    *testing.T
	base *url.URL
	http http.RoundTripper
}

func (p fixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	p.t.Helper()
	if request.URL.Scheme != "https" || request.URL.Host != "sandbox-api.paddle.com" ||
		request.Header.Get("Paddle-Version") != "1" || request.Header.Get("Authorization") != "Bearer "+fixtureAPIKey {
		p.t.Error("adapter did not select the exact version, credential and sandbox API authority")
		return nil, errors.New("unexpected fixture authority")
	}
	if request.Header.Get("Idempotency-Key") != "" || request.GetBody != nil {
		p.t.Error("adapter made the request transport-replayable")
		return nil, errors.New("unexpected replay credentials")
	}
	peerRequest := request.Clone(request.Context())
	peerRequest.URL.Host, peerRequest.URL.Scheme = p.base.Host, p.base.Scheme
	peerRequest.Host = p.base.Host
	return p.http.RoundTrip(peerRequest)
}

func newPeer(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	peer := httptest.NewTLSServer(handler)
	t.Cleanup(peer.Close)
	base, err := url.Parse(peer.URL)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(Config{Environment: Sandbox, APIKey: fixtureAPIKey, CheckoutOrigins: []string{checkoutOrigin},
		PortalOrigins: []string{portalOrigin}, Transport: fixtureTransport{t, base, peer.Client().Transport}})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func respond(t *testing.T, w http.ResponseWriter, status int, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Error(err)
	}
}

func providerFixtureTransaction(id, intent, checkout string) map[string]any {
	return map[string]any{
		"id": id, "status": "draft", "origin": "api", "collection_mode": "automatic", "customer_id": fixtureCustomer,
		"currency_code": "USD", "custom_data": map[string]string{IntentField: intent}, "items": fixtureItems(),
		"checkout": map[string]string{"url": checkout}, "created_at": fixtureTime, "updated_at": fixtureTime,
	}
}

func fixtureItems() []any {
	return []any{map[string]any{
		"price": map[string]string{"id": fixturePrice, "product_id": fixtureProduct}, "quantity": 1,
	}}
}

func paged(data []any, more bool, next string) map[string]any {
	return map[string]any{"data": data, "meta": map[string]any{"pagination": map[string]any{"has_more": more, "next": next}}}
}

func fixtureCheckoutRequest(customer string) CheckoutRequest {
	created, _ := time.Parse(time.RFC3339, fixtureTime)
	return CheckoutRequest{IntentID: fixtureIntent, CustomerID: customer, PriceID: fixturePrice,
		CreatedAfter: created.Add(-5 * time.Second), CreatedBefore: created.Add(5 * time.Minute)}
}

func TestCheckoutReconcilesAnOriginalTransactionAfterLostReply(t *testing.T) {
	var posts, reads atomic.Int32
	var stored atomic.Bool
	link := checkoutOrigin + "/payment?_ptxn=" + fixtureTransaction
	client := newPeer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/transactions" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPost {
			if posts.Add(1) != 1 {
				t.Error("checkout was automatically submitted twice")
			}
			var request struct {
				Items []struct {
					PriceID  string `json:"price_id"`
					Quantity int    `json:"quantity"`
				} `json:"items"`
				CustomerID     string            `json:"customer_id"`
				CollectionMode string            `json:"collection_mode"`
				CustomData     map[string]string `json:"custom_data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.CustomerID != fixtureCustomer ||
				request.CollectionMode != "automatic" || len(request.Items) != 1 || request.Items[0].Quantity != 1 ||
				request.Items[0].PriceID != fixturePrice || len(request.CustomData) != 1 || request.CustomData[IntentField] != fixtureIntent {
				t.Error("provider did not receive the exact opaque intent and configured item")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			stored.Store(true)
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error("fixture could not discard the reply after accepting the checkout")
				return
			}
			_ = connection.Close()
			return
		}
		if !stored.Load() || r.Method != http.MethodGet || r.URL.Query().Get("customer_id") != fixtureCustomer {
			t.Error("provider reconciliation was not a read scoped to the original customer")
		}
		switch reads.Add(1) {
		case 1:
			respond(t, w, http.StatusOK, paged([]any{providerFixtureTransaction(fixtureOther, "other_reservation", "")}, true,
				"https://sandbox-api.paddle.com/transactions?after="+fixtureOther+"&customer_id=ignored"))
		case 2:
			if r.URL.Query().Get("after") != fixtureOther {
				t.Error("adapter did not keep the scoped provider cursor")
			}
			respond(t, w, http.StatusOK, paged([]any{providerFixtureTransaction(fixtureTransaction, fixtureIntent, link)}, false, ""))
		default:
			t.Error("adapter made an unexpected list request")
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	request := fixtureCheckoutRequest(fixtureCustomer)
	if result, err := client.CreateCheckout(t.Context(), request); !errors.Is(err, ErrUncertain) || result.ID != "" {
		t.Fatalf("lost provider response became a known outcome: %s, %v", result.ID, err)
	}
	found, ok, err := client.FindCheckout(t.Context(), request)
	if err != nil || !ok || found.ID != fixtureTransaction || found.IntentID != fixtureIntent ||
		found.CheckoutURL != link || posts.Load() != 1 || reads.Load() != 2 {
		t.Fatalf("the exact original checkout was not found: id=%q found=%t sends=%d reads=%d err=%v", found.ID, ok, posts.Load(), reads.Load(), err)
	}
}

func TestCheckoutRejectsUnboundValuesAndUntrustedPagination(t *testing.T) {
	request := fixtureCheckoutRequest(fixtureCustomer)
	for label, mutate := range map[string]func(map[string]any){
		"foreign checkout origin": func(data map[string]any) {
			data["checkout"] = map[string]string{"url": "https://other.example.test/payment?_ptxn=" + fixtureTransaction}
		},
		"wrong transaction target": func(data map[string]any) {
			data["checkout"] = map[string]string{"url": checkoutOrigin + "/payment?_ptxn=" + fixtureOther}
		},
		"wrong customer": func(data map[string]any) {
			data["customer_id"] = "ctm_" + strings.Repeat("4", 26)
		},
		"non-API transaction": func(data map[string]any) {
			data["origin"] = "subscription_recurring"
		},
		"wrong intent": func(data map[string]any) {
			data["custom_data"] = map[string]string{IntentField: "not_the_reserved_intent"}
		},
		"wrong price": func(data map[string]any) {
			data["items"] = []any{map[string]any{
				"price": map[string]string{"id": "pri_" + strings.Repeat("9", 26), "product_id": fixtureProduct}, "quantity": 1,
			}}
		},
	} {
		t.Run(label, func(t *testing.T) {
			data := providerFixtureTransaction(fixtureTransaction, fixtureIntent, checkoutOrigin+"/payment?_ptxn="+fixtureTransaction)
			mutate(data)
			client := newPeer(t, func(w http.ResponseWriter, _ *http.Request) {
				respond(t, w, http.StatusCreated, map[string]any{"data": data})
			})
			if result, err := client.CreateCheckout(t.Context(), request); !errors.Is(err, ErrUncertain) || result.CheckoutURL != "" {
				t.Fatalf("mismatched provider evidence was disclosed: %v", err)
			}
		})
	}

	t.Run("foreign cursor", func(t *testing.T) {
		var calls atomic.Int32
		client := newPeer(t, func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			respond(t, w, http.StatusOK, paged([]any{providerFixtureTransaction(fixtureOther, "another_intent", "")}, true,
				"https://other.example.test/transactions?after="+fixtureOther))
		})
		if _, found, err := client.FindCheckout(t.Context(), request); !errors.Is(err, ErrUncertain) || found || calls.Load() != 1 {
			t.Fatalf("incomplete search did not stay uncertain: found=%t calls=%d err=%v", found, calls.Load(), err)
		}
	})
}

func TestProviderReadsAndManagementUsePublishedShapes(t *testing.T) {
	link := portalOrigin + "/session?action=view_subscription&subscription_id=" + fixtureSubscription + "&token=fixture-link"
	client := newPeer(t, func(w http.ResponseWriter, r *http.Request) {
		scheduled := any(nil)
		switch r.URL.Path {
		case "/subscriptions/" + fixtureSubscription + "/cancel":
			var body map[string]string
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil ||
				len(body) != 1 || body["effective_from"] != "next_billing_period" {
				t.Error("wrong method or current-period cancellation request")
			}
			scheduled = map[string]string{"action": "cancel", "effective_at": fixtureEnd}
		case "/subscriptions/" + fixtureSubscription:
			if r.Method == http.MethodPatch {
				var body map[string]json.RawMessage
				if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 1 || string(body["scheduled_change"]) != "null" {
					t.Error("renewal did not remove only the scheduled cancellation")
				}
			} else if r.Method != http.MethodGet {
				t.Error("wrong subscription method")
			}
		case "/customers/" + fixtureCustomer + "/portal-sessions":
			var body struct {
				Subscriptions []string `json:"subscription_ids"`
			}
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil ||
				len(body.Subscriptions) != 1 || body.Subscriptions[0] != fixtureSubscription {
				t.Error("portal request lacked its exact subscription scope")
			}
			respond(t, w, http.StatusCreated, map[string]any{"data": map[string]any{
				"id": fixturePortal, "customer_id": fixtureCustomer,
				"urls": map[string]any{"subscriptions": []any{map[string]string{"id": fixtureSubscription, "view_subscription": link}}},
			}})
			return
		case "/transactions", "/transactions/" + fixtureTransaction:
			data := providerFixtureTransaction(fixtureTransaction, fixtureIntent, "")
			data["status"], data["subscription_id"], data["billed_at"] = "completed", fixtureSubscription, fixtureTime
			data["billing_period"] = map[string]string{"starts_at": fixtureTime, "ends_at": fixtureEnd}
			data["details"] = map[string]any{"totals": map[string]string{"total": "1275", "currency_code": "USD"}}
			if r.URL.Path == "/transactions" {
				if r.URL.Query().Get("subscription_id") != fixtureSubscription {
					t.Error("subscription transaction reads did not remain scoped")
				}
				respond(t, w, http.StatusOK, paged([]any{data}, false, ""))
			} else {
				respond(t, w, http.StatusOK, map[string]any{"data": data})
			}
			return
		case "/adjustments":
			if r.URL.Query().Get("id") != fixtureAdjustment && r.URL.Query().Get("transaction_id") != fixtureTransaction {
				t.Error("adjustment reads did not preserve their exact scope")
			}
			data := map[string]any{"id": fixtureAdjustment, "transaction_id": fixtureTransaction, "customer_id": fixtureCustomer,
				"subscription_id": fixtureSubscription, "action": "refund", "type": "partial", "status": "approved", "currency_code": "USD",
				"created_at": fixtureTime, "updated_at": fixtureTime, "totals": map[string]string{"total": "127", "currency_code": "USD"}}
			respond(t, w, http.StatusOK, paged([]any{data}, false, ""))
			return
		default:
			t.Errorf("unexpected provider method %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		respond(t, w, http.StatusOK, map[string]any{"data": map[string]any{
			"id": fixtureSubscription, "customer_id": fixtureCustomer, "status": "active", "collection_mode": "automatic",
			"updated_at": fixtureTime, "items": fixtureItems(), "scheduled_change": scheduled,
			"current_billing_period": map[string]string{"starts_at": fixtureTime, "ends_at": fixtureEnd},
		}})
	})
	if sub, err := client.GetSubscription(t.Context(), fixtureSubscription); err != nil || sub.ID != fixtureSubscription ||
		sub.CustomerID != fixtureCustomer || sub.UpdatedAt.IsZero() {
		t.Fatalf("authoritative subscription read failed: %v", err)
	}
	if sub, err := client.CancelAtPeriodEnd(t.Context(), fixtureSubscription); err != nil || sub.ScheduledAction != "cancel" ||
		!sub.ScheduledAt.Equal(sub.PeriodEnd) || sub.Status != "active" {
		t.Fatalf("scheduled cancel failed or lost the paid-through period: %v", err)
	}
	if sub, err := client.ResumeRenewal(t.Context(), fixtureSubscription); err != nil || sub.ScheduledAction != "" || sub.Status != "active" {
		t.Fatalf("remove scheduled cancel did not return the active subscription: %v", err)
	}
	if got, err := client.CreatePortal(t.Context(), fixtureCustomer, fixtureSubscription); err != nil || got != link {
		t.Fatalf("approved portal link was not returned: %v", err)
	}
	if txn, err := client.GetTransaction(t.Context(), fixtureTransaction); err != nil || txn.TotalMinor != 1275 ||
		txn.Currency != "USD" || txn.BilledAt.IsZero() || !txn.PeriodEnd.After(txn.PeriodStart) {
		t.Fatalf("paid transaction facts were not preserved: %v", err)
	}
	if txns, err := client.ListTransactionsBySubscription(t.Context(), fixtureSubscription); err != nil || len(txns) != 1 ||
		txns[0].ID != fixtureTransaction {
		t.Fatalf("unexpected scoped transaction list: %v", err)
	}
	if adj, err := client.GetAdjustment(t.Context(), fixtureAdjustment); err != nil || adj.TotalMinor != 127 || adj.Action != "refund" {
		t.Fatalf("authoritative adjustment read failed: %v", err)
	}
	if adjs, err := client.ListAdjustments(t.Context(), fixtureTransaction); err != nil ||
		len(adjs) != 1 || adjs[0].TransactionID != fixtureTransaction {
		t.Fatalf("unexpected scoped adjustment list: %v", err)
	}
}

func TestProviderRefusalsAndRedirectsStayBounded(t *testing.T) {
	for _, item := range []struct {
		status int
		cause  error
	}{{http.StatusTooManyRequests, ErrRefused}, {http.StatusServiceUnavailable, ErrUncertain}, {http.StatusTemporaryRedirect, ErrUncertain}} {
		t.Run(http.StatusText(item.status), func(t *testing.T) {
			var calls atomic.Int32
			client := newPeer(t, func(w http.ResponseWriter, r *http.Request) {
				if calls.Add(1) != 1 || r.URL.Path != "/transactions" {
					t.Error("a refusal was sent more than once or followed a redirect")
				}
				w.Header().Set("Location", "https://elsewhere.example.test/skip")
				respond(t, w, item.status, map[string]any{"error": map[string]string{
					"type": "request_error", "code": "fixture_refusal", "detail": "do-not-log-private-details",
				}, "meta": map[string]string{"request_id": "request-fixture-1"}})
			})
			_, err := client.CreateCheckout(t.Context(), CheckoutRequest{IntentID: fixtureIntent, PriceID: fixturePrice})
			var failure *Error
			if !errors.Is(err, item.cause) || !errors.As(err, &failure) || failure.Status != item.status ||
				failure.RequestID != "request-fixture-1" || strings.Contains(err.Error(), "private-details") || calls.Load() != 1 {
				t.Fatalf("unexpected provider failure classification: %v", err)
			}
		})
	}
	if _, err := NewClient(Config{Environment: Live, APIKey: fixtureAPIKey,
		CheckoutOrigins: []string{checkoutOrigin}, PortalOrigins: []string{portalOrigin}}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("sandbox credential was accepted for the live endpoint")
	}
}

func fixtureSignature(secret string, timestamp int64, raw []byte) string {
	hash := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(hash, "%d:", timestamp)
	hash.Write(raw)
	return fmt.Sprintf("ts=%d;h1=%s", timestamp, hex.EncodeToString(hash.Sum(nil)))
}

func TestWebhookAuthenticatesRawBytesRotationAndBoundedMetadata(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 10, 0, 0, time.UTC)
	raw := []byte(fmt.Sprintf(`{"event_id":"%s", "event_type":"transaction.completed","notification_id":"%s","occurred_at":"%s",
		"data":{"id":"%s","environment":"live","status":"completed"}}`, fixtureEvent, fixtureNotification, fixtureTime, fixtureTransaction))
	const previous, current = "destination-previous-fixture", "destination-current-fixture"
	verifier, err := NewWebhookVerifier(Sandbox, current, previous)
	if err != nil {
		t.Fatal(err)
	}
	old := fixtureSignature(previous, now.Unix(), raw)
	currentSignature := fixtureSignature(current, now.Unix(), raw)
	_, h1, _ := strings.Cut(currentSignature, ";")
	event, err := verifier.Verify(raw, old+";"+h1, now)
	if err != nil || event.ID != fixtureEvent || event.NotificationID != fixtureNotification || event.ResourceID != fixtureTransaction ||
		event.Kind != "transaction.completed" || event.Environment != Sandbox || event.Digest != sha256.Sum256(raw) ||
		event.OccurredAt.Format(time.RFC3339) != fixtureTime {
		t.Fatalf("verified identity was not scoped and preserved: %v", err)
	}
	for label, body := range map[string][]byte{
		"changed raw formatting": append(append([]byte(nil), raw...), '\n'),
		"changed signed status":  []byte(strings.Replace(string(raw), "completed\"}", "canceled\"}", 1)),
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := verifier.Verify(body, old, now); !errors.Is(err, ErrSignature) {
				t.Fatalf("changed raw bytes passed verification: %v", err)
			}
		})
	}
	for label, signature := range map[string]string{
		"duplicate timestamp": old + fmt.Sprintf(";ts=%d", now.Unix()),
		"stale":               fixtureSignature(current, now.Add(-6*time.Second).Unix(), raw),
		"future":              fixtureSignature(current, now.Add(6*time.Second).Unix(), raw),
		"unsigned":            "",
		"foreign destination": fixtureSignature("live-destination-fixture", now.Unix(), raw),
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := verifier.Verify(raw, signature, now); !errors.Is(err, ErrSignature) {
				t.Fatalf("invalid signature did not fail closed: %v", err)
			}
		})
	}
	replay := []byte(strings.Replace(string(raw), "\"event_id\":", fmt.Sprintf("\"event_id\":\"%s\",\"event_id\":", fixtureEvent), 1))
	wrongKind := []byte(strings.Replace(string(raw), "transaction.completed", "subscription.updated", 1))
	unsupported := []byte(strings.Replace(string(raw), "transaction.completed", "customer.updated", 1))
	for _, item := range []struct {
		raw   []byte
		cause error
	}{{replay, ErrInvalidEvent}, {wrongKind, ErrInvalidEvent}, {unsupported, ErrUnsupportedEvent},
		{[]byte(strings.Repeat(" ", MaxWebhookBytes+1)), ErrInvalidEvent}} {
		if _, err := verifier.Verify(item.raw, fixtureSignature(current, now.Unix(), item.raw), now); !errors.Is(err, item.cause) {
			t.Fatalf("unexpected authenticated event admission: %v", err)
		}
	}
}

// Paddle's v1 list example has an approved credit_reverse for -32662 and
// its reversed credit for 32662 on one transaction. Only the sample amounts
// and action/status shapes are used here. All identities are isolated fixtures.
// https://developer.paddle.com/api-reference/adjustments/list-adjustments/
func TestListAdjustmentsPreservesPaddleCreditReversal(t *testing.T) {
	creditID := "adj_" + strings.Repeat("2", 26)
	adjustment := func(id, action, status, total string) map[string]any {
		return map[string]any{
			"id": id, "action": action, "type": "partial", "status": status,
			"transaction_id": fixtureTransaction, "subscription_id": fixtureSubscription, "customer_id": fixtureCustomer,
			"currency_code": "USD", "totals": map[string]string{"total": total, "currency_code": "USD"},
			"created_at": fixtureTime, "updated_at": fixtureTime,
		}
	}
	const changedAt = "2026-11-20T12:01:00Z"
	var reversed atomic.Bool
	original := adjustment(creditID, "credit", "approved", "32662")
	reversal := adjustment(fixtureAdjustment, "credit_reverse", "approved", "-32662")
	reversal["created_at"], reversal["updated_at"] = changedAt, changedAt
	credit := adjustment(creditID, "credit", "reversed", "32662")
	credit["updated_at"] = changedAt
	client := newPeer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/adjustments" {
			t.Error("unexpected method for the signed adjustment list")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("id") == fixtureAdjustment {
			respond(t, w, http.StatusOK, paged([]any{reversal}, false, ""))
			return
		}
		if r.URL.Query().Get("transaction_id") != fixtureTransaction {
			t.Error("the adjustment list left its transaction scope")
		}
		if !reversed.Load() {
			respond(t, w, http.StatusOK, paged([]any{original}, false, ""))
			return
		}
		respond(t, w, http.StatusOK, paged([]any{reversal, credit}, false, ""))
	})
	initial, err := client.ListAdjustments(t.Context(), fixtureTransaction)
	if err != nil || len(initial) != 1 || initial[0].ID != creditID || initial[0].Status != "approved" ||
		initial[0].CreatedAt.Format(time.RFC3339) != fixtureTime || !initial[0].UpdatedAt.Equal(initial[0].CreatedAt) {
		t.Fatalf("the original approved credit did not expose its creation and update times: %v", err)
	}
	reversed.Store(true)
	listed, err := client.ListAdjustments(t.Context(), fixtureTransaction)
	if err != nil || len(listed) != 2 {
		t.Fatalf("the entire signed adjustment page was not read: %v", err)
	}
	if listed[0].Action != "credit_reverse" || listed[0].Status != "approved" || listed[0].TotalMinor != -32662 ||
		listed[1].Action != "credit" || listed[1].Status != "reversed" || listed[1].TotalMinor != 32662 {
		t.Fatal("the normalized credit and reversal changed action, status, or amount")
	}
	if listed[1].ID != initial[0].ID || !listed[1].CreatedAt.Equal(initial[0].CreatedAt) ||
		!listed[1].UpdatedAt.After(initial[0].UpdatedAt) || !listed[1].UpdatedAt.Equal(listed[0].CreatedAt) ||
		listed[0].CreatedAt.Format(time.RFC3339) != changedAt {
		t.Fatal("the reversal did not retain the original credit creation separately from its later update")
	}
	got, err := client.GetAdjustment(t.Context(), fixtureAdjustment)
	if err != nil || got != listed[0] {
		t.Fatalf("the exact reversal read did not preserve its signed facts: %v", err)
	}
}

func TestOrdinaryTransactionRejectsNegativeTotal(t *testing.T) {
	client := newPeer(t, func(w http.ResponseWriter, _ *http.Request) {
		data := providerFixtureTransaction(fixtureTransaction, fixtureIntent, "")
		data["status"], data["billed_at"] = "completed", fixtureTime
		data["details"] = map[string]any{"totals": map[string]string{"total": "-32662", "currency_code": "USD"}}
		respond(t, w, http.StatusOK, map[string]any{"data": data})
	})
	if observed, err := client.GetTransaction(t.Context(), fixtureTransaction); !errors.Is(err, ErrUncertain) || observed.ID != "" {
		t.Fatalf("a negative ordinary transaction became paid evidence: %v", err)
	}
}

func TestRecoveryWithoutCustomerUsesOriginalWindow(t *testing.T) {
	var posts, reads atomic.Int32
	var accepted atomic.Bool
	request := fixtureCheckoutRequest("")
	link := checkoutOrigin + "/payment?_ptxn=" + fixtureTransaction
	older := make([]map[string]any, maxPages*pageSize+1)
	for i := range older {
		older[i] = providerFixtureTransaction(fmt.Sprintf("txn_%026d", i+1), "older_intent", "")
		older[i]["created_at"] = request.CreatedAfter.Add(-24 * time.Hour).Format(time.RFC3339)
	}
	client := newPeer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/transactions" {
			t.Error("checkout recovery reached an unexpected path")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodPost {
			posts.Add(1)
			var body map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["customer_id"] != nil ||
				body["created_at"] != nil || body["custom_data"] == nil {
				t.Error("initial checkout sent fixture lookup bounds or an unknown customer")
			}
			accepted.Store(true)
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		reads.Add(1)
		query := r.URL.Query()
		after, startErr := time.Parse(time.RFC3339Nano, query.Get("created_at[GTE]"))
		before, endErr := time.Parse(time.RFC3339Nano, query.Get("created_at[LTE]"))
		if r.Method != http.MethodGet || !accepted.Load() || query.Has("customer_id") || query.Get("origin") != "api" ||
			startErr != nil || endErr != nil || !after.Equal(request.CreatedAfter) || !before.Equal(request.CreatedBefore) {
			t.Error("the initial recovery did not request exactly its original time window and API origin")
			respond(t, w, http.StatusOK, paged([]any{older[0]}, true, ""))
			return
		}
		matches := make([]any, 0, 1)
		for _, old := range older {
			at, _ := time.Parse(time.RFC3339Nano, old["created_at"].(string))
			if !at.Before(after) && !at.After(before) {
				matches = append(matches, old)
			}
		}
		original := providerFixtureTransaction(fixtureTransaction, fixtureIntent, link)
		original["customer_id"] = nil
		matches = append(matches, original)
		respond(t, w, http.StatusOK, paged(matches, false, ""))
	})
	if _, err := client.CreateCheckout(t.Context(), request); !errors.Is(err, ErrUncertain) {
		t.Fatalf("the accepted checkout's dropped reply was not uncertain: %v", err)
	}
	got, found, err := client.FindCheckout(t.Context(), request)
	if err != nil || !found || got.ID != fixtureTransaction || got.CustomerID != "" ||
		posts.Load() != 1 || reads.Load() != 1 {
		t.Fatalf("recovery did not narrow the merchant history to its original checkout: found=%t sends=%d reads=%d err=%v",
			found, posts.Load(), reads.Load(), err)
	}
}

func TestOriginalCheckoutDiscoveryRefusesOutOfWindowOrAmbiguousData(t *testing.T) {
	request := fixtureCheckoutRequest("")
	for _, label := range []string{"outside window", "renewal reuses intent", "two original candidates"} {
		t.Run(label, func(t *testing.T) {
			first := providerFixtureTransaction(fixtureTransaction, fixtureIntent, "")
			data := []any{first}
			switch label {
			case "outside window":
				first["created_at"] = request.CreatedBefore.Add(time.Second).Format(time.RFC3339)
			case "renewal reuses intent":
				first["origin"] = "subscription_recurring"
			case "two original candidates":
				data = append(data, providerFixtureTransaction(fixtureOther, fixtureIntent, ""))
			}
			client := newPeer(t, func(w http.ResponseWriter, _ *http.Request) { respond(t, w, http.StatusOK, paged(data, false, "")) })
			if _, found, err := client.FindCheckout(t.Context(), request); found || !errors.Is(err, ErrUncertain) {
				t.Fatalf("uncertain scope became an admitted checkout: found=%t, err=%v", found, err)
			}
		})
	}
}
