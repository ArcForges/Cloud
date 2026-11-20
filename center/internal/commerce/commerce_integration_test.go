// SPDX-License-Identifier: AGPL-3.0-only

package commerce_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/commerce"
	"github.com/ArcForges/Cloud/center/internal/commerce/paddle"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/device"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey"
	"github.com/ArcForges/Cloud/center/internal/identity/passkey/virtual"
	"github.com/ArcForges/Cloud/center/internal/pgtest"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

const (
	fixturePaddleAPI        = "sandbox-api.paddle.com"
	fixturePaddleKey        = "pdl_sdbx_apikey_fixture"
	fixtureWebhookKey       = "loopback-only-commerce-fixture"
	fixtureDifferentKey     = "other-notification-fixture"
	fixtureCheckoutOrigin   = "https://checkout.example.test"
	fixtureProviderVersion  = "1"
	fixtureNotificationTime = 1795219200
	fixtureNotificationBody = `{"event_id":"evt_00000000000000000000000001", "event_type":"transaction.completed", "occurred_at":"2026-11-21T00:00:00Z", "notification_id":"ntf_00000000000000000000000001", "data":{"id":"txn_00000000000000000000000001","description":"fixture café"}}`
	// Python hashlib/hmac generated this independently over UTF-8 timestamp, colon and the exact JSON bytes above.
	fixtureNotificationDigest = "6f8a4ab1d07077a4cc6c7c3b92fdda5fa136963f97ed90661eb2c07686589162"
)

// The isolated peer serves only the documented Paddle v1 HTTP responses configured by a test.
// The product's real adapter selects its sandbox authority before the fixture rewrites transport to loopback.
type commerceHTTPPeer struct {
	t        *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	calls    map[string]int
}

func newCommerceHTTPPeer(t *testing.T) *commerceHTTPPeer {
	t.Helper()
	p := &commerceHTTPPeer{t: t, handlers: make(map[string]http.HandlerFunc), calls: make(map[string]int)}
	p.server = httptest.NewServer(http.HandlerFunc(p.serveHTTP))
	t.Cleanup(p.server.Close)
	return p
}

func (p *commerceHTTPPeer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Paddle-Version") != fixtureProviderVersion || r.Header.Get("Authorization") != "Bearer "+fixturePaddleKey {
		p.t.Error("the actual provider request omitted its pinned version or selected sandbox credential")
		http.Error(w, "fixture request headers", http.StatusBadRequest)
		return
	}
	key := r.Method + " " + r.URL.Path
	p.mu.Lock()
	p.calls[key]++
	handler := p.handlers[key]
	p.mu.Unlock()
	if handler == nil {
		p.t.Errorf("unexpected Paddle v1 fixture request %s", key)
		http.NotFound(w, r)
		return
	}
	handler(w, r)
}

func (p *commerceHTTPPeer) handle(method, path string, handler http.HandlerFunc) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.handlers[method+" "+path] = handler
}

func (p *commerceHTTPPeer) callCount(method, path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls[method+" "+path]
}

func (p *commerceHTTPPeer) transport() http.RoundTripper {
	p.t.Helper()
	origin, err := url.Parse(p.server.URL)
	if err != nil {
		p.t.Fatal("parse the private loopback fixture origin")
	}
	return commerceFixtureTransport{origin: origin, base: p.server.Client().Transport}
}

type commerceFixtureTransport struct {
	origin *url.URL
	base   http.RoundTripper
}

func (p commerceFixtureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" || req.URL.Host != fixturePaddleAPI {
		return nil, fmt.Errorf("commerce fixture received a request outside the pinned sandbox authority")
	}
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme, cloned.URL.Host, cloned.Host = p.origin.Scheme, p.origin.Host, ""
	return p.base.RoundTrip(cloned)
}

func (p *commerceHTTPPeer) jsonReply(w http.ResponseWriter, status int, data, meta any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]any{"data": data, "meta": meta}); err != nil {
		p.t.Error("encode fixture provider response")
	}
}

func (p *commerceHTTPPeer) entity(path string, data any) {
	p.handle(http.MethodGet, path, func(w http.ResponseWriter, _ *http.Request) {
		p.jsonReply(w, http.StatusOK, data, map[string]any{})
	})
}

func (p *commerceHTTPPeer) list(path, filter, value string, data any) {
	p.handle(http.MethodGet, path, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get(filter) != value {
			p.t.Error("provider recovery query did not bind the expected customer or transaction")
			http.Error(w, "fixture recovery filter", http.StatusBadRequest)
			return
		}
		p.jsonReply(w, http.StatusOK, data, map[string]any{"pagination": map[string]any{"has_more": false}})
	})
}

func commerceProviderID(prefix string, n int) string {
	return fmt.Sprintf("%s_%026d", prefix, n)
}

func commerceFixtureSignature(key string, at time.Time, body []byte) string {
	stamp := strconv.FormatInt(at.Unix(), 10)
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(stamp + ":"))
	_, _ = mac.Write(body)
	return "ts=" + stamp + ";h1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestPaddleCrossLanguageSignaturePreservesRawNotification(t *testing.T) {
	at := time.Unix(fixtureNotificationTime, 0).UTC()
	raw := []byte(fixtureNotificationBody)
	header := "ts=1795219200;h1=" + fixtureNotificationDigest
	verifier, err := paddle.NewWebhookVerifier(paddle.Sandbox, fixtureWebhookKey)
	if err != nil {
		t.Fatalf("construct sandbox destination verifier: %v", err)
	}
	event, err := verifier.Verify(raw, header, at)
	if err != nil {
		t.Fatalf("verify independent Python SHA-256 vector: %v", err)
	}
	if event.Environment != paddle.Sandbox || event.ID != commerceProviderID("evt", 1) ||
		event.NotificationID != commerceProviderID("ntf", 1) || event.ResourceID != commerceProviderID("txn", 1) ||
		event.Kind != "transaction.completed" || !event.OccurredAt.Equal(at) || event.Digest != sha256.Sum256(raw) {
		t.Fatal("verified notification identity and raw digest did not survive the provider adapter")
	}

	for _, tc := range []struct {
		name   string
		body   []byte
		header string
		now    time.Time
	}{
		{"missing-signature", raw, "", at},
		{"other-destination", raw, commerceFixtureSignature(fixtureDifferentKey, at, raw), at},
		{"changed-whitespace", append([]byte(fixtureNotificationBody), '\n'), header, at},
		{"expired-timestamp", raw, header, at.Add(6 * time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifier.Verify(tc.body, tc.header, tc.now); !errors.Is(err, paddle.ErrSignature) {
				t.Fatalf("expected the real signature verifier to refuse the fixture: %v", err)
			}
		})
	}
}

type commerceDBFixture struct {
	t               *testing.T
	ctx             context.Context
	db              *dbtest.Database
	peer            *commerceHTTPPeer
	client          *paddle.Client
	verifier        *paddle.WebhookVerifier
	service         *commerce.Service
	entitlement     *entitlement.Service
	actor           commerce.Actor
	other           commerce.Actor
	offer           commerce.Offer
	catalogue       commerce.Catalogue
	at              atomic.Int64
	checkoutCreated time.Time
}

func newCommerceDBFixture(t *testing.T) *commerceDBFixture {
	t.Helper()
	db := dbtest.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	f := &commerceDBFixture{t: t, ctx: ctx, db: db, peer: newCommerceHTTPPeer(t)}
	f.at.Store(time.Now().UTC().Truncate(time.Second).Unix())

	var err error
	f.client, err = paddle.NewClient(paddle.Config{
		Environment: paddle.Sandbox, APIKey: fixturePaddleKey,
		CheckoutOrigins: []string{fixtureCheckoutOrigin}, PortalOrigins: []string{fixtureCheckoutOrigin},
		Transport: f.peer.transport(),
	})
	if err != nil {
		t.Fatalf("construct the actual v1 provider adapter: %v", err)
	}
	f.verifier, err = paddle.NewWebhookVerifier(paddle.Sandbox, fixtureWebhookKey)
	if err != nil {
		t.Fatalf("construct the actual signature verifier: %v", err)
	}
	f.offer = commerce.Offer{
		ID: platform.NewID(), PriceVersion: "fixture-price-v1",
		PriceID: commerceProviderID("pri", 1), ProductID: commerceProviderID("pro", 1), DefinitionsVersion: "dev-host-v2",
		Currency: "USD", Interval: "month", Region: "US", AmountMinor: 900,
		AdjustmentPolicy: commerce.AdjustmentPolicy,
	}
	f.catalogue = commerce.Catalogue{
		Version: "fixture-catalogue-v1", SalesOpen: true, CheckoutLifetime: 15 * time.Minute, Offers: []commerce.Offer{f.offer},
	}
	f.startService(db.Runtime)
	f.actor = f.actorFor(db.Account(1), commerceProviderID("ctm", 1))
	f.other = f.actorFor(db.Account(1), commerceProviderID("ctm", 2))
	return f
}

func (f *commerceDBFixture) now() time.Time {
	return time.Unix(f.at.Load(), 0).UTC()
}

func (f *commerceDBFixture) advance(delta time.Duration) time.Time {
	return time.Unix(f.at.Add(int64(delta/time.Second)), 0).UTC()
}

func (f *commerceDBFixture) actorFor(account platform.ID, customer string) commerce.Actor {
	f.t.Helper()
	session := f.db.Session(account, 1)
	if _, err := f.db.Migration.Exec(f.ctx, `INSERT INTO commerce.customer
		(account_id,provider,environment,provider_customer_ref,created_at)
		VALUES ($1,1,2,$2,$3)`, account, customer, f.now()); err != nil {
		var failure *pgconn.PgError
		if errors.As(err, &failure) {
			f.t.Fatalf("seed the scoped provider customer association: SQLSTATE %s", failure.Code)
		}
		f.t.Fatalf("seed the scoped provider customer association: %T", err)
	}
	return commerce.Actor{Account: account, Session: session.ID, Device: session.DeviceID, Correlation: platform.NewID(), Browser: true}
}

func (f *commerceDBFixture) startService(db *store.DB) {
	f.t.Helper()
	definitions := feature.Configure(feature.Settings{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures})
	f.entitlement = entitlement.NewService(db, definitions, nil, f.now)
	if err := commerce.CheckEnvironment(f.ctx, db, paddle.Sandbox, true); err != nil {
		f.t.Fatalf("pin the fixture store to the sandbox provider realm: %v", err)
	}
	if _, err := f.entitlement.RecordDefinitions(f.ctx, f.now()); err != nil {
		f.t.Fatalf("record the real fixture definitions: %v", err)
	}
	var err error
	f.service, err = commerce.NewService(commerce.Options{
		DB: db, Provider: f.client, Environment: paddle.Sandbox,
		Catalogue: f.catalogue, Entitlements: f.entitlement, Clock: f.now,
	})
	if err != nil {
		f.t.Fatalf("start commerce with real PostgreSQL and the v1 adapter: %v", err)
	}
}

func (f *commerceDBFixture) restart() {
	f.t.Helper()
	// A fresh service and runtime pool have no in-memory view of the prior send or receipt.
	f.startService(store.New(pgtest.Pool(f.t, f.db.RuntimeURL, 8)))
}

func (f *commerceDBFixture) rotateCatalogue() {
	f.t.Helper()
	// The provider's new sale price belongs to the same public offer. The old
	// paid transaction and checkout retain their original quote and single intent.
	current := f.offer
	current.PriceVersion = "fixture-price-v2"
	current.PriceID = commerceProviderID("pri", 2)
	current.AmountMinor = f.offer.AmountMinor + 300
	f.catalogue.Version = "fixture-catalogue-v2"
	f.catalogue.Offers = []commerce.Offer{current}
	f.restart()
}

func (f *commerceDBFixture) reserveCheckout() (commerce.PurchaseRequest, commerce.CheckoutAttemptRequest) {
	f.t.Helper()
	purchase := commerce.PurchaseRequest{
		CommandID: platform.NewID(), PurchaseID: platform.NewID(), OfferID: f.offer.ID,
		PriceVersion: f.offer.PriceVersion, Region: f.offer.Region, CommandPayload: []byte("fixture-purchase-v1"),
	}
	if _, err := f.service.CreatePurchase(f.ctx, f.actor, purchase); err != nil {
		f.t.Fatalf("reserve a durable purchase through the real commerce service: %v", err)
	}
	return purchase, commerce.CheckoutAttemptRequest{
		CommandID: platform.NewID(), PurchaseID: purchase.PurchaseID, CheckoutID: platform.NewID(),
		ReturnPath: "/account/subscription", CommandPayload: []byte("fixture-checkout-v1"),
	}
}

func (f *commerceDBFixture) items() []map[string]any {
	return []map[string]any{{"price": map[string]any{"id": f.offer.PriceID, "product_id": f.offer.ProductID}, "quantity": 1}}
}

func (f *commerceDBFixture) transaction(id, customer, subscription, intent, state string, updated, starts, ends time.Time) map[string]any {
	output := map[string]any{
		"id": id, "status": state, "customer_id": customer, "subscription_id": nil,
		"currency_code": f.offer.Currency, "collection_mode": "automatic", "origin": "api", "items": f.items(),
		"details":    map[string]any{"totals": map[string]any{"total": strconv.FormatInt(f.offer.AmountMinor, 10), "currency_code": f.offer.Currency}},
		"created_at": updated, "updated_at": updated, "billed_at": nil, "billing_period": nil,
		"custom_data": map[string]string{paddle.IntentField: intent},
		"checkout":    map[string]string{"url": fixtureCheckoutOrigin + "/checkout?_ptxn=" + id},
	}
	if subscription != "" {
		output["subscription_id"] = subscription
	}
	if id == commerceProviderID("txn", 1) {
		output["created_at"] = f.checkoutCreated
	} else {
		output["origin"] = "subscription_recurring"
	}
	if !starts.IsZero() {
		output["billing_period"] = map[string]time.Time{"starts_at": starts, "ends_at": ends}
	}
	if state == "completed" || state == "paid" {
		output["billed_at"] = updated
	}
	return output
}

func (f *commerceDBFixture) subscription(id, customer, status string, updated, starts, ends time.Time, cancelAtEnd bool) map[string]any {
	output := map[string]any{
		"id": id, "customer_id": customer, "status": status, "collection_mode": "automatic",
		"updated_at": updated, "items": f.items(), "scheduled_change": nil,
		"current_billing_period": map[string]time.Time{"starts_at": starts, "ends_at": ends},
	}
	if cancelAtEnd {
		output["scheduled_change"] = map[string]any{"action": "cancel", "effective_at": ends}
	}
	return output
}

func (f *commerceDBFixture) configureCheckout(id string, loseReply bool) <-chan string {
	f.t.Helper()
	intent := make(chan string, 1)
	f.checkoutCreated = f.now()
	customer := commerceProviderID("ctm", 1)
	f.peer.handle(http.MethodPost, "/transactions", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Customer       string            `json:"customer_id"`
			CollectionMode string            `json:"collection_mode"`
			CustomData     map[string]string `json:"custom_data"`
			Items          []struct {
				Price    string `json:"price_id"`
				Quantity int    `json:"quantity"`
			} `json:"items"`
		}
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.Customer != customer || input.CollectionMode != "automatic" ||
			len(input.CustomData) != 1 || input.CustomData[paddle.IntentField] == "" || len(input.Items) != 1 ||
			input.Items[0].Price != f.offer.PriceID || input.Items[0].Quantity != 1 {
			f.t.Error("the actual checkout request escaped its original customer, verified offer or opaque intent")
			http.Error(w, "fixture transaction input", http.StatusBadRequest)
			return
		}
		received := input.CustomData[paddle.IntentField]
		select {
		case intent <- received:
		default:
			f.t.Error("the fixture received a second provider create for the same purchase")
			http.Error(w, "duplicate fixture create", http.StatusConflict)
			return
		}
		if !loseReply {
			f.peer.jsonReply(w, http.StatusCreated, f.transaction(id, customer, "", received, "draft", f.now(), time.Time{}, time.Time{}), map[string]any{})
			return
		}
		// The peer accepted the provider create and its opaque intent. Drop the response before any bytes reach the client.
		connection, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			f.t.Error("the private HTTP peer could not drop its checkout response")
			return
		}
		_ = connection.Close()
	})
	return intent
}

func (f *commerceDBFixture) capturedIntent(result <-chan string) string {
	f.t.Helper()
	select {
	case received := <-result:
		return received
	default:
		f.t.Fatal("the provider never observed the durable checkout intent")
		return ""
	}
}

func (f *commerceDBFixture) requireEntitlement(account platform.ID, allowed bool) {
	f.t.Helper()
	resolved, err := f.entitlement.Read(f.ctx, account.String())
	if err != nil {
		f.t.Fatalf("the real entitlement resolver could not read the commerce facts: %v", err)
	}
	for _, key := range feature.Gated() {
		entry, exists := resolved.Capability(string(key))
		if !exists || entry.Granted != allowed {
			f.t.Fatalf("resolved feature %s did not match verified commerce eligibility", key)
		}
	}
}

func (f *commerceDBFixture) requirePeriods(account platform.ID, expected int) {
	f.t.Helper()
	terms := f.db.Count("SELECT count(*) FROM entitlement.service_term WHERE account_id=$1", account)
	grants := f.db.Count("SELECT count(*) FROM entitlement.grant WHERE account_id=$1", account)
	settled := f.db.Count("SELECT count(*) FROM commerce.settled_period WHERE account_id=$1", account)
	if terms != expected || grants != 3*expected || settled != expected {
		var eventSummary string
		_ = f.db.Migration.QueryRow(f.ctx, "SELECT coalesce(string_agg(state::text || '/' || coalesce(failure_code,''), ',' ORDER BY received_at,event_ref),'') FROM commerce.provider_event").Scan(&eventSummary)
		f.t.Fatalf("wanted %d verified payments and three grants per period, found terms=%d grants=%d settled=%d receipts=%s", expected, terms, grants, settled, eventSummary)
	}
}

func TestCommerceLostCheckoutReconcilesOriginalIntentAfterRestart(t *testing.T) {
	f := newCommerceDBFixture(t)
	purchase, checkout := f.reserveCheckout()
	customer, txn := commerceProviderID("ctm", 1), commerceProviderID("txn", 1)
	intent := f.configureCheckout(txn, true)
	f.peer.list("/transactions", "customer_id", customer, []any{})

	_, _ = f.service.CreateCheckout(f.ctx, f.actor, checkout)
	original := f.capturedIntent(intent)
	if f.db.Count(`SELECT count(*) FROM commerce.checkout WHERE account_id=$1 AND purchase_id=$2 AND checkout_id=$3
		AND send_claimed_at IS NOT NULL AND provider_checkout_ref IS NULL AND state=5`, f.actor.Account, purchase.PurchaseID, checkout.CheckoutID) != 1 {
		t.Fatal("the unknown checkout lacks its durable original purchase and irreversible send claim")
	}
	if f.peer.callCount(http.MethodPost, "/transactions") != 1 {
		t.Fatal("the uncertain provider create was repeated")
	}
	second := purchase
	second.CommandID, second.PurchaseID = platform.NewID(), platform.NewID()
	if _, err := f.service.CreatePurchase(f.ctx, f.actor, second); err == nil {
		t.Fatal("a new purchase bypassed the unresolved original checkout")
	}
	if _, err := f.service.GetPurchase(f.ctx, f.other, purchase.PurchaseID); err == nil {
		t.Fatal("a different browser account could read the original purchase")
	}
	f.requirePeriods(f.actor.Account, 0)

	f.advance(2 * time.Second)
	f.rotateCatalogue()
	stored, err := f.service.GetPurchase(f.ctx, f.actor, purchase.PurchaseID)
	if err != nil || stored.ID != purchase.PurchaseID || stored.PriceVersion != f.offer.PriceVersion ||
		f.service.GetCatalogue().Offers[0].PriceVersion == stored.PriceVersion {
		t.Fatalf("restarting with a changed sale price lost the quote of the original attempted purchase: %v", err)
	}
	draft := f.transaction(txn, customer, "", original, "draft", f.now(), time.Time{}, time.Time{})
	f.peer.list("/transactions", "customer_id", customer, []any{draft})
	f.peer.entity("/transactions/"+txn, draft)
	if err := f.service.Reconcile(f.ctx); err != nil {
		t.Fatalf("restart reconciliation could not find the original v1 transaction: %v", err)
	}
	if _, err := f.service.CreateCheckout(f.ctx, f.actor, checkout); err != nil {
		t.Fatalf("same checkout command could not observe its recovered result: %v", err)
	}
	if f.db.Count(`SELECT count(*) FROM commerce.checkout WHERE checkout_id=$1 AND purchase_id=$2 AND provider_checkout_ref=$3 AND state=2`,
		checkout.CheckoutID, purchase.PurchaseID, txn) != 1 || f.peer.callCount(http.MethodPost, "/transactions") != 1 {
		t.Fatal("reconciliation did not bind the original checkout without repeating the provider create")
	}
	altered := checkout
	altered.CommandPayload = []byte("fixture-modified-command")
	if _, err := f.service.CreateCheckout(f.ctx, f.actor, altered); err == nil {
		t.Fatal("changed checkout payload re-used its command identity")
	}
	f.requirePeriods(f.actor.Account, 0)
	f.requireEntitlement(f.actor.Account, false)
}

const commerceRawPayloadMarker = "fixture marker from the raw notification body"

func (f *commerceDBFixture) eventBody(sequence int, kind, ref string, occurred time.Time) []byte {
	f.t.Helper()
	body, err := json.Marshal(map[string]any{
		"event_id": commerceProviderID("evt", sequence), "notification_id": commerceProviderID("ntf", sequence),
		"event_type": kind, "occurred_at": occurred,
		"data": map[string]string{"id": ref, "description": commerceRawPayloadMarker},
	})
	if err != nil {
		f.t.Fatalf("encode the version-pinned test notification: %v", err)
	}
	return body
}

func (f *commerceDBFixture) event(sequence int, kind, ref string, occurred time.Time) paddle.Event {
	f.t.Helper()
	body := f.eventBody(sequence, kind, ref, occurred)
	now := f.now()
	event, err := f.verifier.Verify(body, commerceFixtureSignature(fixtureWebhookKey, now, body), now)
	if err != nil {
		f.t.Fatalf("verify the fixture notification with the actual Paddle verifier: %v", err)
	}
	return event
}

func (f *commerceDBFixture) process(event paddle.Event) {
	f.t.Helper()
	if _, err := f.service.ReceiveEvent(f.ctx, event); err != nil {
		f.t.Fatalf("receive a signed provider event: %v", err)
	}
	if err := f.service.Reconcile(f.ctx); err != nil {
		f.t.Fatalf("reconcile a signed event against authoritative fixture reads: %v", err)
	}
}

func (f *commerceDBFixture) openCheckout() (commerce.CheckoutAttemptRequest, string) {
	f.t.Helper()
	_, checkout := f.reserveCheckout()
	intent := f.configureCheckout(commerceProviderID("txn", 1), false)
	out, err := f.service.CreateCheckout(f.ctx, f.actor, checkout)
	if err != nil || out.ID != checkout.CheckoutID || out.PurchaseID != checkout.PurchaseID || out.URL == "" {
		f.t.Fatalf("provider checkout did not bind its original durable identity: %v", err)
	}
	return checkout, f.capturedIntent(intent)
}

func TestCommerceWebhookEvidenceCannotCrossAccountOrRealm(t *testing.T) {
	f := newCommerceDBFixture(t)
	_, intent := f.openCheckout()
	if err := commerce.CheckEnvironment(f.ctx, f.db.Runtime, paddle.Live, false); err == nil {
		t.Fatal("the durable sandbox provider store admitted a live configuration")
	}
	txn, sub := commerceProviderID("txn", 1), commerceProviderID("sub", 1)

	body := f.eventBody(1, "transaction.completed", txn, f.now())
	if _, err := f.verifier.Verify(body, commerceFixtureSignature(fixtureDifferentKey, f.now(), body), f.now()); !errors.Is(err, paddle.ErrSignature) {
		t.Fatalf("the forge test did not reach the real signature verifier: %v", err)
	}
	live, err := paddle.NewWebhookVerifier(paddle.Live, fixtureDifferentKey)
	if err != nil {
		t.Fatal("construct the separately configured destination")
	}
	wrongRealm, err := live.Verify(body, commerceFixtureSignature(fixtureDifferentKey, f.now(), body), f.now())
	if err != nil {
		t.Fatalf("the notification must authenticate at its own destination: %v", err)
	}
	if _, err = f.service.ReceiveEvent(f.ctx, wrongRealm); err == nil {
		t.Fatal("the sandbox commerce service accepted a separately verified live event")
	}
	if f.db.Count("SELECT count(*) FROM commerce.provider_event") != 0 ||
		f.peer.callCount(http.MethodGet, "/transactions/"+txn) != 0 {
		t.Fatal("forged or wrong-environment input reached the durable ledger or provider reads")
	}

	// This exact checkout is assigned to the first account. The authenticated
	// remote event purports to settle it with a different mapped customer.
	otherCustomer := commerceProviderID("ctm", 2)
	starts, ends := f.now().Add(-time.Minute), f.now().Add(time.Hour)
	f.peer.entity("/transactions/"+txn, f.transaction(txn, otherCustomer, sub, intent, "completed", f.now(), starts, ends))
	f.peer.entity("/subscriptions/"+sub, f.subscription(sub, otherCustomer, "active", f.now(), starts, ends, false))
	f.peer.list("/adjustments", "transaction_id", txn, []any{})
	wrongCustomer := f.event(2, "transaction.completed", txn, f.now())
	if _, err := f.service.ReceiveEvent(f.ctx, wrongCustomer); err != nil {
		t.Fatalf("admit the valid signed notice before its business binding can be verified: %v", err)
	}
	_ = f.service.Reconcile(f.ctx)
	if f.db.Count("SELECT count(*) FROM commerce.provider_event WHERE event_ref=$1 AND state<>2", wrongCustomer.ID) != 1 ||
		f.db.Count("SELECT count(*) FROM commerce.subscription") != 0 ||
		f.peer.callCount(http.MethodGet, "/transactions/"+txn) == 0 {
		t.Fatal("the provider customer mismatch was not processed as an unapplied receipt")
	}
	for _, account := range []platform.ID{f.actor.Account, f.other.Account} {
		f.requirePeriods(account, 0)
		f.requireEntitlement(account, false)
	}
}

func (f *commerceDBFixture) expectDuplicateEventOnlyOnce(event paddle.Event) {
	f.t.Helper()
	const deliveries = 8
	type result struct {
		receipt commerce.EventReceipt
		err     error
	}
	results := make(chan result, deliveries)
	for range deliveries {
		go func() {
			receipt, err := f.service.ReceiveEvent(f.ctx, event)
			results <- result{receipt, err}
		}()
	}
	duplicates := 0
	for range deliveries {
		result := <-results
		if result.err != nil {
			f.t.Fatalf("an exact provider replay did not return the durable outcome: %v", result.err)
		}
		if result.receipt.Duplicate {
			duplicates++
		}
	}
	if duplicates != deliveries-1 || f.db.Count("SELECT count(*) FROM commerce.provider_event WHERE event_ref=$1", event.ID) != 1 {
		f.t.Fatalf("expected one original admission and %d exact duplicates, got %d duplicates", deliveries-1, duplicates)
	}

	var digest []byte
	if err := f.db.Migration.QueryRow(f.ctx, "SELECT payload_sha256 FROM commerce.provider_event WHERE event_ref=$1", event.ID).Scan(&digest); err != nil || !bytes.Equal(digest, event.Digest[:]) {
		f.t.Fatal("the exact signed-body digest was not durably retained")
	}
	if f.db.Count("SELECT count(*) FROM commerce.provider_event e WHERE strpos(row_to_json(e)::text,$1)>0", commerceRawPayloadMarker) != 0 {
		f.t.Fatal("the event ledger retained the raw notification payload")
	}
}

func (f *commerceDBFixture) configurePaidFacts(transaction, subscription string, facts map[string]any, subscriptionFacts map[string]any) {
	f.t.Helper()
	f.peer.entity("/transactions/"+transaction, facts)
	f.peer.entity("/subscriptions/"+subscription, subscriptionFacts)
	f.peer.list("/transactions", "subscription_id", subscription, []any{facts})
	f.peer.list("/adjustments", "transaction_id", transaction, []any{})
}

func (f *commerceDBFixture) confirmPaid(intent string, txn, sub string, start, end time.Time, eventSequence int) paddle.Event {
	f.t.Helper()
	customer := commerceProviderID("ctm", 1)
	facts := f.transaction(txn, customer, sub, intent, "completed", f.now(), start, end)
	if txn == commerceProviderID("txn", 1) {
		// The initial API transaction can leave this field empty. The paired authoritative subscription supplies the paid period.
		facts["billing_period"] = nil
	}
	subscriptionFacts := f.subscription(sub, customer, "active", f.now(), start, end, false)
	f.configurePaidFacts(txn, sub, facts, subscriptionFacts)
	return f.event(eventSequence, "transaction.completed", txn, f.now())
}

func (f *commerceDBFixture) currentSubscription() commerce.SubscriptionView {
	f.t.Helper()
	view, err := f.service.GetSubscription(f.ctx, f.actor)
	if err != nil || view.ID == (platform.ID{}) {
		f.t.Fatalf("read the account-bound subscription projection: %v", err)
	}
	return view
}

func TestCommerceWebhookDeliveryRenewalAndOldCancellation(t *testing.T) {
	f := newCommerceDBFixture(t)
	_, intent := f.openCheckout()
	f.requirePeriods(f.actor.Account, 0)
	f.requireEntitlement(f.actor.Account, false)
	first, second, sub := commerceProviderID("txn", 1), commerceProviderID("txn", 2), commerceProviderID("sub", 1)
	start, firstEnd := f.now().Add(-time.Minute), f.now().Add(3*time.Minute)
	initial := f.confirmPaid(intent, first, sub, start, firstEnd, 3)
	f.expectDuplicateEventOnlyOnce(initial)

	// A second syntactically valid notification with the same signed event id and different resource cannot replace the original.
	changed := f.event(3, "transaction.completed", second, f.now())
	if _, err := f.service.ReceiveEvent(f.ctx, changed); err == nil {
		t.Fatal("changed signed content re-used a durable provider event identity")
	}
	if f.db.Count("SELECT count(*) FROM commerce.provider_event WHERE event_ref=$1 AND resource_ref=$2", initial.ID, first) != 1 {
		t.Fatal("the changed provider notification rewrote the original ledger identity")
	}
	f.requirePeriods(f.actor.Account, 0)

	originalCatalogue := f.catalogue.Version
	f.rotateCatalogue()
	if err := f.service.Reconcile(f.ctx); err != nil {
		t.Fatalf("restart with a replacement sale quote could not process the original signed payment: %v", err)
	}
	f.requirePeriods(f.actor.Account, 1)
	f.requireEntitlement(f.actor.Account, true)
	active := f.currentSubscription()
	if active.State != "active" || !active.AutoRenew || !active.PeriodEnd.Equal(firstEnd) || active.CatalogueVersion != originalCatalogue {
		t.Fatal("the first confirmed payment did not preserve its verified service interval")
	}

	cancelAt := f.advance(time.Second)
	customer := commerceProviderID("ctm", 1)
	cancelFact := f.subscription(sub, customer, "active", cancelAt, start, firstEnd, true)
	f.peer.entity("/subscriptions/"+sub, cancelFact)
	f.peer.handle(http.MethodPost, "/subscriptions/"+sub+"/cancel", func(w http.ResponseWriter, r *http.Request) {
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request["effective_from"] != "next_billing_period" {
			t.Error("the actual renewal command did not cancel at the current paid term's end")
			http.Error(w, "fixture cancellation shape", http.StatusBadRequest)
			return
		}
		f.peer.jsonReply(w, http.StatusOK, cancelFact, map[string]any{})
	})
	renewal := commerce.RenewalRequest{
		CommandID: platform.NewID(), SubscriptionID: active.ID, AutoRenew: false,
		ExpectedRevision: active.Revision, CommandPayload: []byte("fixture-cancel-at-term-end"),
	}
	_, err := f.service.SetRenewal(f.ctx, f.actor, renewal)
	var refusal *arc.Refusal
	if !errors.As(err, &refusal) || refusal.Code != "step_up_required" ||
		f.peer.callCount(http.MethodPost, "/subscriptions/"+sub+"/cancel") != 0 {
		t.Fatalf("cancellation reached the provider without the account-bound step-up evidence: %v", err)
	}
	const stepUpClass = "commerce.cancelSubscription"
	target, err := hex.DecodeString(identity.TargetHash(stepUpClass, f.actor.Account, active.ID))
	if err != nil {
		t.Fatal("encode the fixture's exact cancellation target")
	}
	proof := f.db.ProveStepUp(dbtest.Session{ID: f.actor.Session, User: f.actor.Account}, stepUpClass, target, f.now())
	updated, err := f.service.SetRenewal(f.ctx, f.actor, renewal)
	if err != nil || updated.AutoRenew || updated.State != "cancel_at_term_end" || !updated.PeriodEnd.Equal(firstEnd) {
		t.Fatalf("the requested cancellation did not preserve paid-through service: %v", err)
	}
	if _, err := f.service.SetRenewal(f.ctx, f.actor, renewal); err != nil {
		t.Fatalf("the original renewal command could not replay: %v", err)
	}
	if count := f.peer.callCount(http.MethodPost, "/subscriptions/"+sub+"/cancel"); count != 1 {
		t.Fatalf("the cancellation command triggered %d outbound provider requests", count)
	}
	if f.db.Count("SELECT count(*) FROM identity.step_up_challenge WHERE challenge_id=$1 AND state=3", proof) != 1 {
		t.Fatal("the committed cancellation did not consume its original one-use proof")
	}
	f.requireEntitlement(f.actor.Account, true)

	// The same paid period has a newer cancel decision. An old authoritative
	// read cannot restore auto-renewal or rewrite the paid entitlement projection.
	beforeOld, err := f.entitlement.Read(f.ctx, f.actor.Account.String())
	if err != nil {
		t.Fatalf("read the canonical cancel-at-term-end entitlement: %v", err)
	}
	f.peer.entity("/subscriptions/"+sub, f.subscription(sub, customer, "active", initial.OccurredAt, start, firstEnd, false))
	f.process(f.event(14, "subscription.updated", sub, initial.OccurredAt))
	afterOld, err := f.entitlement.Read(f.ctx, f.actor.Account.String())
	if err != nil || !beforeOld.SameEffectAs(afterOld) || beforeOld.Version != afterOld.Version {
		t.Fatalf("older same-period provider facts rewrote the newer entitlement decision: %v", err)
	}
	if retained := f.currentSubscription(); retained.State != updated.State || retained.AutoRenew || retained.Revision != updated.Revision {
		t.Fatal("older same-period provider facts replaced the current verified billing projection")
	}

	failureAt := f.advance(time.Second)
	f.peer.entity("/transactions/"+second, f.transaction(second, customer, sub, intent, "past_due", failureAt, time.Time{}, time.Time{}))
	f.peer.entity("/subscriptions/"+sub, f.subscription(sub, customer, "past_due", failureAt, start, firstEnd, true))
	failedCharge := f.event(15, "transaction.payment_failed", second, failureAt)
	f.process(failedCharge)
	f.requireApplied(failedCharge)
	f.requirePeriods(f.actor.Account, 1)
	f.requireEntitlement(f.actor.Account, true)
	if retained := f.currentSubscription(); !retained.PeriodEnd.Equal(firstEnd) || retained.State == "payment_grace" ||
		f.db.Count("SELECT count(*) FROM commerce.billing_entry WHERE account_id=$1", f.actor.Account) != 1 {
		t.Fatal("the failed recurring charge invented a payment, paid term, or grace window")
	}

	// Local expiration of paid time leaves an existing provider subscription
	// unresolved. It must still prevent a second potentially billed checkout.
	f.advance(firstEnd.Sub(f.now()) + time.Second)
	if view := f.currentSubscription(); view.State != "expired" {
		t.Fatal("the failed recurring payment fixture did not cross its original local expiry")
	}
	currentOffer := f.service.GetCatalogue().Offers[0]
	_, err = f.service.CreatePurchase(f.ctx, f.actor, commerce.PurchaseRequest{
		CommandID: platform.NewID(), PurchaseID: platform.NewID(), OfferID: currentOffer.ID,
		PriceVersion: currentOffer.PriceVersion, Region: currentOffer.Region, CommandPayload: []byte("fixture-block-duplicate-billing"),
	})
	if !errors.As(err, &refusal) || refusal.Code != "invalid_state" || refusal.Reason != "purchase_unavailable" ||
		f.db.Count("SELECT count(*) FROM commerce.purchase WHERE account_id=$1", f.actor.Account) != 1 ||
		f.peer.callCount(http.MethodPost, "/transactions") != 1 {
		t.Fatalf("local expiry permitted a replacement purchase before verified termination: %v", err)
	}

	// A later authoritative subscription and completed renewal transaction establish the second paid period.
	f.advance(4 * time.Minute)
	secondEnd := firstEnd.Add(5 * time.Minute)
	f.process(f.confirmPaid(intent, second, sub, firstEnd, secondEnd, 4))
	f.requirePeriods(f.actor.Account, 2)
	f.requireEntitlement(f.actor.Account, true)
	renewed := f.currentSubscription()
	if renewed.State != "active" || !renewed.AutoRenew || !renewed.PeriodEnd.Equal(secondEnd) || renewed.CatalogueVersion != originalCatalogue {
		t.Fatal("the verified renewal did not advance to the paid-through date")
	}

	// Even a stale provider read observed while processing a late cancellation cannot replace the newer verified term.
	f.peer.entity("/subscriptions/"+sub, cancelFact)
	f.process(f.event(5, "subscription.canceled", sub, cancelAt))
	f.requirePeriods(f.actor.Account, 2)
	f.requireEntitlement(f.actor.Account, true)
	afterLate := f.currentSubscription()
	if !afterLate.PeriodEnd.Equal(secondEnd) || !afterLate.AutoRenew || afterLate.State != "active" || afterLate.Revision != renewed.Revision {
		t.Fatal("a delayed stale cancellation rolled back the newer verified provider projection")
	}
	if f.db.Count("SELECT count(*) FROM commerce.billing_entry WHERE account_id=$1 AND kind=1 AND amount_minor=$2",
		f.actor.Account, f.offer.AmountMinor) != 2 {
		t.Fatal("the original and renewal payments did not produce exactly two verified billing facts")
	}
	query := commerce.BillingQuery{From: start.Add(-time.Minute), Until: f.now().Add(time.Minute), Limit: 1}
	firstPage, err := f.service.ListBilling(f.ctx, f.actor, query)
	if err != nil || !firstPage.HasMore || len(firstPage.Items) != 1 || firstPage.Items[0].Kind != "payment" ||
		firstPage.Items[0].AmountMinor != f.offer.AmountMinor || firstPage.Items[0].Currency != f.offer.Currency {
		t.Fatalf("bounded billing history did not return the current verified payment: %v", err)
	}
	item := firstPage.Items[0]
	query.Before, query.BeforeID = item.OccurredAt, item.ID
	page, err := f.service.ListBilling(f.ctx, f.actor, query)
	if err != nil || page.HasMore || len(page.Items) != 1 || page.Items[0].ID == item.ID {
		t.Fatalf("the billing cursor repeated or lost an immutable entry: %v", err)
	}
	if page, err := f.service.ListBilling(f.ctx, f.other, query); err != nil || len(page.Items) != 0 {
		t.Fatalf("the billing cursor escaped its original account: %v", err)
	}

	// An approved adjustment of the first charge must leave the independently paid renewal in force.
	f.peer.entity("/subscriptions/"+sub, f.subscription(sub, customer, "active", f.now(), firstEnd, secondEnd, false))
	oldTransaction := f.transaction(first, customer, sub, intent, "completed", initial.OccurredAt, time.Time{}, time.Time{})
	oldRefund := commerceProviderID("adj", 1)
	facts := f.adjustment(oldRefund, first, sub, "refund", "full", f.offer.AmountMinor, f.advance(time.Second))
	f.adjustmentReads(first, oldRefund, oldTransaction, facts)
	f.process(f.event(10, "adjustment.updated", oldRefund, f.now()))
	f.requirePeriods(f.actor.Account, 2)
	f.requireEntitlement(f.actor.Account, true)
	if current := f.currentSubscription(); current.State != "active" || !current.PeriodEnd.Equal(secondEnd) {
		t.Fatal("refunding the older charge removed the active renewal's paid-through projection")
	}
	if f.db.Count("SELECT count(*) FROM commerce.billing_entry WHERE account_id=$1 AND provider_entry_ref=$2 AND kind=2",
		f.actor.Account, oldRefund) != 1 {
		t.Fatal("the older charge's confirmed adjustment was lost from billing history")
	}
}

func (f *commerceDBFixture) adjustment(ref, txn, sub, action, typ string, amount int64, at time.Time) map[string]any {
	return map[string]any{
		"id": ref, "transaction_id": txn, "subscription_id": sub, "customer_id": commerceProviderID("ctm", 1),
		"action": action, "type": typ, "status": "approved", "currency_code": f.offer.Currency,
		"created_at": at, "updated_at": at,
		"totals": map[string]any{"total": strconv.FormatInt(amount, 10), "currency_code": f.offer.Currency},
	}
}

func (f *commerceDBFixture) adjustmentReads(txn, ref string, transactions map[string]any, adjustments ...map[string]any) {
	f.t.Helper()
	f.peer.entity("/transactions/"+txn, transactions)
	f.peer.handle(http.MethodGet, "/adjustments", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		var data []map[string]any
		switch {
		case query.Get("transaction_id") == txn:
			data = adjustments
		case query.Get("id") == ref:
			for _, row := range adjustments {
				if row["id"] == ref {
					data = append(data, row)
				}
			}
		default:
			f.t.Error("adjustment recovery queried a different transaction or adjustment")
			http.Error(w, "fixture adjustment binding", http.StatusBadRequest)
			return
		}
		f.peer.jsonReply(w, http.StatusOK, data, map[string]any{"pagination": map[string]any{"has_more": false}})
	})
}

func TestCommerceAdjustmentsBindTheOriginalPaidTerm(t *testing.T) {
	for _, tc := range []struct {
		name   string
		action string
		kind   int
	}{
		{"full-refund", "refund", 2},
		{"chargeback", "chargeback", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newCommerceDBFixture(t)
			_, intent := f.openCheckout()
			txn, sub := commerceProviderID("txn", 1), commerceProviderID("sub", 1)
			start, end := f.now().Add(-time.Minute), f.now().Add(time.Hour)
			f.process(f.confirmPaid(intent, txn, sub, start, end, 6))
			f.requirePeriods(f.actor.Account, 1)
			f.requireEntitlement(f.actor.Account, true)

			customer := commerceProviderID("ctm", 1)
			paid := f.transaction(txn, customer, sub, intent, "completed", f.now(), time.Time{}, time.Time{})
			partialID := commerceProviderID("adj", 1)
			partial := f.adjustment(partialID, txn, sub, "refund", "partial", 100, f.advance(time.Second))
			f.adjustmentReads(txn, partialID, paid, partial)
			f.process(f.event(7, "adjustment.updated", partialID, f.now()))
			f.requireEntitlement(f.actor.Account, true)
			if f.db.Count("SELECT count(*) FROM commerce.billing_entry WHERE account_id=$1 AND kind=2 AND amount_minor=100", f.actor.Account) != 1 ||
				f.db.Count("SELECT count(*) FROM entitlement.service_term_action WHERE account_id=$1", f.actor.Account) != 0 {
				t.Fatal("the catalog's partial-refund policy changed access or lost its billing fact")
			}

			fullID := commerceProviderID("adj", 2)
			facts := f.adjustment(fullID, txn, sub, tc.action, "full", f.offer.AmountMinor, f.advance(time.Second))
			f.adjustmentReads(txn, fullID, paid, partial, facts)
			corrected := f.event(8, "adjustment.updated", fullID, f.now())
			if _, err := f.service.ReceiveEvent(f.ctx, corrected); err != nil {
				t.Fatalf("admit the signed adjustment: %v", err)
			}
			f.restart()
			if err := f.service.Reconcile(f.ctx); err != nil {
				t.Fatalf("reconcile the original adjustment after restart: %v", err)
			}
			if receipt, err := f.service.ReceiveEvent(f.ctx, corrected); err != nil || !receipt.Duplicate {
				t.Fatalf("a replay of the adjustment did not return its original receipt: %v", err)
			}
			f.requirePeriods(f.actor.Account, 1)
			f.requireEntitlement(f.actor.Account, false)
			if f.db.Count(`SELECT count(*) FROM entitlement.service_term_action a JOIN commerce.settled_period p
				ON p.account_id=a.account_id AND p.term_id=a.term_id
				WHERE p.account_id=$1 AND p.provider_transaction_ref=$2 AND a.kind=2`, f.actor.Account, txn) != 1 ||
				f.db.Count("SELECT count(*) FROM commerce.billing_entry WHERE account_id=$1 AND provider_entry_ref=$2 AND kind=$3",
					f.actor.Account, fullID, tc.kind) != 1 {
				t.Fatal("the adjusted payment did not retain one billing fact and one revocation of its original term")
			}

			f.process(f.event(9, "transaction.completed", txn, start))
			f.requirePeriods(f.actor.Account, 1)
			f.requireEntitlement(f.actor.Account, false)
		})
	}
}

func TestCommerceLatePaymentKeepsTheOriginalPurchasePendingManualReview(t *testing.T) {
	f := newCommerceDBFixture(t)
	checkout, intent := f.openCheckout()
	first, sub := commerceProviderID("txn", 1), commerceProviderID("sub", 1)

	// Only the private application clock advances. The provider transaction
	// retains the exact original creation and is paid after local expiry.
	paidAt := f.advance(16 * time.Minute)
	event := f.confirmPaid(intent, first, sub, paidAt.Add(-time.Second), paidAt.Add(time.Hour), 11)
	f.process(event)
	if f.db.Count(`SELECT count(*) FROM commerce.provider_event WHERE event_ref=$1 AND state=3
		AND failure_code='late_payment_review' AND next_check_at IS NULL`, event.ID) != 1 {
		t.Fatal("the verified late payment did not keep its original durable manual-review receipt")
	}
	if f.db.Count("SELECT count(*) FROM commerce.purchase WHERE purchase_id=$1 AND account_id=$2 AND state=2", checkout.PurchaseID, f.actor.Account) != 1 {
		t.Fatal("late payment freed or replaced the original unknown purchase identity")
	}
	f.requirePeriods(f.actor.Account, 0)
	f.requireEntitlement(f.actor.Account, false)
	if f.db.Count("SELECT count(*) FROM commerce.billing_entry WHERE account_id=$1 AND kind=1 AND provider_entry_ref=$2", f.actor.Account, first) != 1 {
		t.Fatal("the single confirmed late payment was lost or duplicated in billing history")
	}

	f.restart()
	if err := f.service.Reconcile(f.ctx); err != nil {
		t.Fatalf("restart did not preserve a durable manual-review state: %v", err)
	}
	if duplicate, err := f.service.ReceiveEvent(f.ctx, event); err != nil || !duplicate.Duplicate {
		t.Fatalf("late payment redelivery did not return the original receipt: %v", err)
	}
	replayed, _ := f.service.CreateCheckout(f.ctx, f.actor, checkout)
	if replayed.URL != "" || f.peer.callCount(http.MethodPost, "/transactions") != 1 {
		t.Fatal("manual review issued another checkout or returned a stale payment URL")
	}
	f.requirePeriods(f.actor.Account, 0)
}

func TestCommerceTransientProviderReadDoesNotAbandonTheOriginalEvent(t *testing.T) {
	f := newCommerceDBFixture(t)
	_, intent := f.openCheckout()
	transaction, subscription := commerceProviderID("txn", 1), commerceProviderID("sub", 1)
	paidAt := f.now()
	start, end := paidAt.Add(-time.Minute), paidAt.Add(31*24*time.Hour)
	event := f.confirmPaid(intent, transaction, subscription, start, end, 12)
	path := "/transactions/" + transaction
	f.peer.handle(http.MethodGet, path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"type":"api_error","code":"service_unavailable","detail":"fixture-only transient provider diagnostic"},"meta":{}}`))
	})
	if _, err := f.service.ReceiveEvent(f.ctx, event); err != nil {
		t.Fatalf("receive the original signed notification: %v", err)
	}

	const transientFailures = 13
	for attempt := 1; attempt <= transientFailures; attempt++ {
		if err := f.service.Reconcile(f.ctx); err != nil {
			t.Fatalf("temporary provider failure at attempt %d became final: %v", attempt, err)
		}
		var recorded, state int
		var next *time.Time
		if err := f.db.Migration.QueryRow(f.ctx, `SELECT attempt_count,state,next_check_at FROM commerce.provider_event
			WHERE environment=2 AND event_ref=$1`, event.ID).Scan(&recorded, &state, &next); err != nil {
			t.Fatalf("read the pinned event's durable retry receipt: %v", err)
		}
		if recorded != attempt || state != 3 || next == nil || !next.After(f.now()) || next.Sub(f.now()) > 256*time.Second {
			t.Fatalf("provider read attempt %d lost its bounded future retry (recorded=%d state=%d)", attempt, recorded, state)
		}
		f.at.Store(next.Unix())
	}
	f.requirePeriods(f.actor.Account, 0)
	if receipt, err := f.service.ReceiveEvent(f.ctx, event); err != nil || !receipt.Duplicate {
		t.Fatalf("transient failure changed the original notification identity: %v", err)
	}

	// Recovery uses the same authoritative provider fact and durable event after a new service starts.
	// Expired checkout reconciliation can read the same provider resource
	// separately. Count the new event attempt independently of prior reads.
	previousReads := f.peer.callCount(http.MethodGet, path)
	customer := commerceProviderID("ctm", 1)
	f.peer.entity(path, f.transaction(transaction, customer, subscription, intent, "completed", paidAt, time.Time{}, time.Time{}))
	f.restart()
	if err := f.service.Reconcile(f.ctx); err != nil {
		t.Fatalf("process the original event after thirteen temporary read failures: %v", err)
	}
	f.requirePeriods(f.actor.Account, 1)
	f.requireEntitlement(f.actor.Account, true)
	var recorded, state int
	var next *time.Time
	if err := f.db.Migration.QueryRow(f.ctx, `SELECT attempt_count,state,next_check_at
		FROM commerce.provider_event WHERE environment=2 AND event_ref=$1`, event.ID).Scan(&recorded, &state, &next); err != nil {
		t.Fatalf("read the original recovered provider event: %v", err)
	}
	newReads := f.peer.callCount(http.MethodGet, path) - previousReads
	creates := f.peer.callCount(http.MethodPost, "/transactions")
	if state != 2 || recorded != transientFailures+1 || next != nil || newReads != 1 || creates != 1 {
		t.Fatalf("recovery did not settle the original receipt (state=%d attempt=%d deferred=%t reads=%d creates=%d)",
			state, recorded, next != nil, newReads, creates)
	}
}

type commerceDeletionFixture struct {
	test    *commerceDBFixture
	service *identity.Service
	auth    *virtual.Authenticator
	key     *virtual.Key
	caller  identity.Caller
}

func newCommerceDeletionFixture(f *commerceDBFixture) *commerceDeletionFixture {
	f.t.Helper()
	const host, origin = "center.example", "https://center.example"
	rp, err := passkey.New(host, origin)
	if err != nil {
		f.t.Fatalf("configure the actual deletion proof relying party: %v", err)
	}
	d := &commerceDeletionFixture{test: f, auth: virtual.New(host, origin), service: identity.New(identity.Options{
		DB: f.db.Runtime, Policy: config.DefaultIdentityPolicy(), RP: rp, Clock: f.now,
	})}
	d.caller = identity.Caller{
		Request: identity.Request{ClientIP: netip.MustParseAddr("192.0.2.23")},
		UserID:  f.actor.Account, SessionID: f.actor.Session, DeviceID: f.actor.Device, Scope: "account", Browser: true,
		AuthEpoch: f.actor.AuthEpoch, RecoveryGeneration: f.actor.RecoveryGeneration,
	}

	var handle []byte
	if err = f.db.Migration.QueryRow(f.ctx, "SELECT passkey_user_handle FROM identity.user WHERE user_id=$1", f.actor.Account).Scan(&handle); err != nil {
		f.t.Fatalf("read the fixture account's original passkey identity: %v", err)
	}
	challenge := make([]byte, 32)
	if _, err = rand.Read(challenge); err != nil {
		f.t.Fatalf("generate the private registration challenge: %v", err)
	}
	creation, key := d.auth.Create(challenge, handle)
	d.key = key
	credential, err := rp.VerifyCreation(challenge, handle, creation, f.now().Add(time.Minute))
	if err != nil {
		f.t.Fatalf("verify the real test passkey registration: %v", err)
	}
	if _, err = f.db.Migration.Exec(f.ctx, `INSERT INTO identity.auth_identity
		(auth_identity_id,user_id,method,provider_id,subject,public_key,user_handle,sign_count,backup_eligible,backup_state,transports,aaguid,attestation_format,created_at,rev)
		VALUES ($1,$2,1,'passkey',$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,1)`,
		platform.NewID(), f.actor.Account, base64.RawURLEncoding.EncodeToString(credential.ID), credential.PublicKey, handle,
		int64(credential.SignCount), credential.BackupEligible, credential.BackupState, credential.Transports, credential.AAGUID,
		credential.AttestationFormat, f.now()); err != nil {
		f.t.Fatalf("store the verified public test credential: %v", err)
	}
	return d
}

func (d *commerceDeletionFixture) prove(class string, target platform.ID) {
	d.test.t.Helper()
	method := int32(identity.MethodValuePasskey)
	hash := identity.TargetHash(class, d.caller.UserID, target)
	challenge, err := d.service.BeginStepUp(d.test.ctx, d.caller, identity.StepUpBegin{
		Class: &class, Method: &method, TargetHash: &hash,
	})
	if err != nil {
		d.test.t.Fatalf("start the account-bound lifecycle proof: %v", err)
	}
	assertion := d.auth.Assert(d.key, challenge.Challenge)
	if _, err = d.service.CompleteStepUp(d.test.ctx, d.caller, challenge.FlowID, identity.StepUpProof{Passkey: &assertion}); err != nil {
		d.test.t.Fatalf("verify the real signed lifecycle proof: %v", err)
	}
}

func (d *commerceDeletionFixture) signIn() {
	f := d.test
	f.t.Helper()
	challenge, err := d.service.BeginAuthentication(f.ctx, d.caller.Request, identity.Begin{
		Method: identity.MethodValuePasskey, Purpose: int32(identity.PurposeAuthenticate), Browser: true, HasClaim: true,
		Claim: device.Claim{InstallationID: platform.NewID(), Product: "arcforges-web", Platform: "web", AppVersion: "web"},
	})
	if err != nil {
		f.t.Fatalf("begin new passkey authentication after account confirmation: %v", err)
	}
	result, err := d.service.CompleteBrowserPasskey(f.ctx, d.caller.Request, challenge.FlowID, d.auth.Assert(d.key, challenge.Challenge))
	if err != nil {
		f.t.Fatalf("verify new browser authentication after account confirmation: %v", err)
	}
	d.caller.SessionID, d.caller.DeviceID = result.Browser.SessionID, result.Device.DeviceID
	d.caller.AuthEpoch, d.caller.RecoveryGeneration = result.Browser.AuthEpoch, result.Browser.RecoveryGeneration
	f.actor.Session, f.actor.Device = d.caller.SessionID, d.caller.DeviceID
	f.actor.AuthEpoch, f.actor.RecoveryGeneration = d.caller.AuthEpoch, d.caller.RecoveryGeneration
}

func TestCommerceConfirmedDeletionCancelsRenewalOnceWithoutShorteningPaidTerm(t *testing.T) {
	f := newCommerceDBFixture(t)
	_, intent := f.openCheckout()
	transaction, sub, customer := commerceProviderID("txn", 1), commerceProviderID("sub", 1), commerceProviderID("ctm", 1)
	start, paidThrough := f.now().Add(-time.Minute), f.now().Add(time.Hour)
	f.process(f.confirmPaid(intent, transaction, sub, start, paidThrough, 13))
	active := f.currentSubscription()
	d := newCommerceDeletionFixture(f)
	var plan identity.Lifecycle
	if err := f.db.Runtime.InTx(f.ctx, "prepare commerce account deletion", store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		plan, err = d.service.PrepareDeletion(ctx, tx, d.caller, platform.NewID(), f.now())
		return err
	}); err != nil || plan.State != identity.LifecycleAwaitingProof || plan.ActiveSubscriptions != 1 {
		t.Fatalf("prepare the real deletion preview against its paid provider association: %v", err)
	}
	cancelPath := "/subscriptions/" + sub + "/cancel"
	if err := f.service.Reconcile(f.ctx); err != nil ||
		f.peer.callCount(http.MethodPost, cancelPath) != 0 || f.db.Count("SELECT count(*) FROM commerce.renewal") != 0 {
		t.Fatalf("an unconfirmed preview sent or reserved a cancellation: %v", err)
	}

	const confirmLabel = "confirm commerce account deletion"
	command := platform.NewID()
	confirm := func() error {
		return f.db.Runtime.InTx(f.ctx, confirmLabel, store.TxOptions{}, func(ctx context.Context, tx pgx.Tx) error {
			_, err := d.service.ConfirmDeletion(ctx, tx, d.caller, plan.ID, plan.PlanRevision, command, f.now())
			return err
		})
	}
	var refusal *arc.Refusal
	if err := confirm(); !errors.As(err, &refusal) || refusal.Code != "step_up_required" {
		t.Fatalf("unproved confirmation was not refused before any provider action: %v", err)
	}
	d.prove(identity.ClassConfirmDeletion, plan.ID)
	if err := confirm(); err != nil {
		t.Fatalf("confirm deletion with the real target-bound signed proof: %v", err)
	}
	if f.db.Count(`SELECT count(*) FROM identity.lifecycle_operation l JOIN identity.user u ON u.user_id=l.user_id
		JOIN identity.step_up_challenge p ON p.challenge_id=l.proof_id
		WHERE l.operation_id=$1 AND l.state=3 AND l.confirmed_at IS NOT NULL AND p.state=3 AND u.state=4`, plan.ID) != 1 {
		t.Fatal("the actual confirmed lifecycle did not consume its proof and fence the account")
	}

	f.advance(time.Second)
	f.peer.handle(http.MethodPost, cancelPath, func(w http.ResponseWriter, r *http.Request) {
		var request map[string]string
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request["effective_from"] != "next_billing_period" {
			t.Error("confirmed deletion sent a cancellation outside the verified term boundary")
			http.Error(w, "fixture cancellation shape", http.StatusBadRequest)
			return
		}
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error("the fixture could not drop the accepted cancellation reply")
			return
		}
		_ = conn.Close()
	})
	if err := f.service.Reconcile(f.ctx); err != nil || f.peer.callCount(http.MethodPost, cancelPath) != 1 ||
		f.db.Count(`SELECT count(*) FROM commerce.renewal WHERE subscription_id=$1 AND state=3
			AND send_claimed_at IS NOT NULL AND NOT auto_renew`, active.ID) != 1 {
		t.Fatalf("confirmed deletion did not retain one ambiguous original provider cancellation: %v", err)
	}

	// The owner returns with newly verified credentials, and withdraws while the provider result is still uncertain.
	d.signIn()
	d.prove(identity.ClassCancelDeletion, plan.ID)
	if err := f.db.Runtime.InTx(f.ctx, "withdraw the confirmed commerce account deletion", store.TxOptions{},
		func(ctx context.Context, tx pgx.Tx) error {
			_, err := d.service.CancelDeletion(ctx, tx, d.caller, plan.ID, platform.NewID(), f.now())
			return err
		}); err != nil {
		t.Fatalf("withdraw through the live reauthenticated lifecycle and fresh signed proof: %v", err)
	}
	if f.db.Count(`SELECT count(*) FROM identity.lifecycle_operation l JOIN identity.user u ON u.user_id=l.user_id
		WHERE l.operation_id=$1 AND l.state=7 AND u.state=1`, plan.ID) != 1 {
		t.Fatal("the proved withdrawal did not restore the original account state")
	}

	f.advance(2 * time.Second)
	f.peer.entity("/subscriptions/"+sub, f.subscription(sub, customer, "active", f.now(), start, paidThrough, true))
	f.restart()
	if err := f.service.Reconcile(f.ctx); err != nil {
		t.Fatalf("read back the original cancellation after restart and withdrawal: %v", err)
	}
	if err := f.service.Reconcile(f.ctx); err != nil {
		t.Fatalf("repeat reconciliation after withdrawal: %v", err)
	}
	if f.peer.callCount(http.MethodPost, cancelPath) != 1 || f.peer.callCount(http.MethodPatch, "/subscriptions/"+sub) != 0 ||
		f.db.Count("SELECT count(*) FROM commerce.renewal WHERE subscription_id=$1 AND state=2 AND NOT auto_renew", active.ID) != 1 {
		t.Fatal("recovery repeated or reactivated the provider cancellation")
	}
	current := f.currentSubscription()
	if current.State != "cancel_at_term_end" || current.AutoRenew || !current.PeriodStart.Equal(active.PeriodStart) ||
		!current.PeriodEnd.Equal(paidThrough) || current.CatalogueVersion != active.CatalogueVersion {
		t.Fatal("the original verified paid interval changed during deletion cancellation")
	}
	f.requirePeriods(f.actor.Account, 1)
	f.requireEntitlement(f.actor.Account, true)
	if f.db.Count("SELECT count(*) FROM entitlement.service_term_action WHERE account_id=$1", f.actor.Account) != 0 {
		t.Fatal("scheduled cancellation ended the original paid term before its boundary")
	}
}

func (f *commerceDBFixture) requireApplied(event paddle.Event) {
	f.t.Helper()
	if f.db.Count("SELECT count(*) FROM commerce.provider_event WHERE event_ref=$1 AND state=2 AND processed_at IS NOT NULL", event.ID) != 1 {
		f.t.Fatalf("the exact %s notification did not receive a durable applied result", event.Kind)
	}
}

func TestCommerceReversalsRetainOriginalCashOccurrences(t *testing.T) {
	f := newCommerceDBFixture(t)
	_, intent := f.openCheckout()
	txn, sub, customer := commerceProviderID("txn", 1), commerceProviderID("sub", 1), commerceProviderID("ctm", 1)
	initialPaidAt := f.now()
	start, end := initialPaidAt.Add(-time.Minute), initialPaidAt.Add(time.Hour)
	f.process(f.confirmPaid(intent, txn, sub, start, end, 16))
	f.requirePeriods(f.actor.Account, 1)

	paid := f.transaction(txn, customer, sub, intent, "completed", initialPaidAt, time.Time{}, time.Time{})
	const amount = int64(150)
	credited := f.advance(time.Second)
	creditID := commerceProviderID("adj", 1)
	credit := f.adjustment(creditID, txn, sub, "credit", "partial", amount, credited)
	f.adjustmentReads(txn, creditID, paid, credit)
	applied := f.event(17, "adjustment.updated", creditID, f.now())
	f.process(applied)
	f.requireApplied(applied)

	reversalAt := f.advance(time.Second)
	credit["status"] = "reversed"
	credit["updated_at"] = reversalAt
	f.adjustmentReads(txn, creditID, paid, credit)
	reversed := f.event(18, "adjustment.updated", creditID, f.now())
	f.process(reversed)
	f.requireApplied(reversed)

	reversalID := commerceProviderID("adj", 2)
	reversal := f.adjustment(reversalID, txn, sub, "credit_reverse", "partial", -amount, reversalAt)
	f.adjustmentReads(txn, reversalID, paid, credit, reversal)
	reversalEvent := f.event(19, "adjustment.created", reversalID, f.now())
	f.process(reversalEvent)
	f.requireApplied(reversalEvent)
	if f.db.Count(`SELECT count(*) FROM commerce.billing_entry WHERE account_id=$1 AND provider_entry_ref=$2
		AND kind=4 AND amount_minor=$3 AND occurred_at=$4`, f.actor.Account, creditID, amount, credited) != 1 ||
		f.db.Count(`SELECT count(*) FROM commerce.billing_entry WHERE account_id=$1 AND provider_entry_ref=$2
		AND kind=5 AND amount_minor=$3 AND occurred_at=$4`, f.actor.Account, reversalID, -amount, reversalAt) != 1 ||
		f.db.Count("SELECT count(*) FROM commerce.billing_entry WHERE account_id=$1", f.actor.Account) != 3 {
		t.Fatal("credit status changes did not preserve one original occurrence and its signed reversal")
	}
	f.requirePeriods(f.actor.Account, 1)
	f.requireEntitlement(f.actor.Account, true)
	if f.db.Count("SELECT count(*) FROM entitlement.service_term_action WHERE account_id=$1", f.actor.Account) != 0 {
		t.Fatal("a credit or its reversal modified the original paid service authority")
	}

	disputed := f.advance(time.Second)
	chargebackID, chargebackReversalID := commerceProviderID("adj", 3), commerceProviderID("adj", 4)
	chargebackAmount := f.offer.AmountMinor
	chargeback := f.adjustment(chargebackID, txn, sub, "chargeback", "full", chargebackAmount, disputed)
	chargebackReversedAt := f.advance(time.Second)
	chargeback["status"] = "reversed"
	chargeback["updated_at"] = chargebackReversedAt
	chargebackReversal := f.adjustment(chargebackReversalID, txn, sub, "chargeback_reverse", "full", -chargebackAmount, chargebackReversedAt)
	f.adjustmentReads(txn, chargebackReversalID, paid, credit, reversal, chargeback, chargebackReversal)
	chargebackEvent := f.event(20, "adjustment.created", chargebackReversalID, f.now())
	f.process(chargebackEvent)
	f.requireApplied(chargebackEvent)
	if f.db.Count(`SELECT count(*) FROM commerce.billing_entry WHERE account_id=$1 AND provider_entry_ref=$2
		AND kind=3 AND amount_minor=$3 AND occurred_at=$4`, f.actor.Account, chargebackID, chargebackAmount, disputed) != 1 ||
		f.db.Count(`SELECT count(*) FROM commerce.billing_entry WHERE account_id=$1 AND provider_entry_ref=$2
		AND kind=6 AND amount_minor=$3 AND occurred_at=$4`, f.actor.Account, chargebackReversalID, -chargebackAmount, chargebackReversedAt) != 1 ||
		f.db.Count("SELECT count(*) FROM commerce.billing_entry WHERE account_id=$1", f.actor.Account) != 5 {
		t.Fatal("a chargeback first seen after reversal lost either financial occurrence")
	}
	f.requirePeriods(f.actor.Account, 1)
	f.requireEntitlement(f.actor.Account, true)
	if f.db.Count("SELECT count(*) FROM entitlement.service_term_action WHERE account_id=$1", f.actor.Account) != 0 {
		t.Fatal("an already reversed chargeback changed the paid term")
	}
}
