// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	foundationv1 "github.com/ArcForges/Contracts/go/arcforges/foundation/v1"
	publicapiv1 "github.com/ArcForges/Contracts/go/arcforges/publicapi/v1"
	"github.com/ArcForges/Contracts/go/arcforges/publicapi/v1/publicapiv1connect"
	"google.golang.org/protobuf/proto"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/dbtest"
	"github.com/ArcForges/Cloud/center/internal/identity"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/routes"
	"github.com/ArcForges/Cloud/center/internal/session"
)

const (
	host02Origin        = "https://center.example"
	host02WebhookSecret = "sandbox-webhook-fixture-only"
	host02Customer      = "ctm_01hv8p95hhbb2nsarbq3f0rwx8"
	host02Subscription  = "sub_01hv8p95hhbb2nsarbq3f0rwx8"
	host02Offer         = "11111111-2222-4333-8444-555555555555"
	host02PortalURL     = "https://portal.fixture.test/subscriptions?token=fixture-ephemeral&subscription_id=" + host02Subscription
)

type commerceFixtureTransport struct {
	portal   atomic.Int64
	checkout atomic.Int64
}

func (f *commerceFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Scheme != "https" || request.URL.Host != "sandbox-api.paddle.com" {
		return nil, fmt.Errorf("unexpected isolated fixture operation")
	}
	if request.URL.Path == "/transactions" {
		if request.Method == http.MethodPost {
			f.checkout.Add(1)
		}
		return nil, fmt.Errorf("fixture checkout provider result unavailable")
	}
	if request.Method != http.MethodPost || request.URL.Path != "/customers/"+host02Customer+"/portal-sessions" {
		return nil, fmt.Errorf("unexpected isolated fixture operation")
	}
	f.portal.Add(1)
	body := fmt.Sprintf(`{"data":{"id":"cpls_01hv8p95hhbb2nsarbq3f0rwx8","customer_id":%q,
		"urls":{"subscriptions":[{"id":%q,"view_subscription":%q}]}}}`, host02Customer, host02Subscription, host02PortalURL)
	return &http.Response{StatusCode: http.StatusCreated, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

func host02Catalogue(environment string, salesOpen bool) []byte {
	return []byte(fmt.Sprintf(`{"version":"fixture-merchant-1","environment":%q,"sales_open":%t,"checkout_lifetime":"20m","offers":[
		{"id":%q,"price_version":"pv1","paddle_price_id":"pri_01hv8p95hhbb2nsarbq3f0rwx8",
		"paddle_product_id":"pro_01hv8p95hhbb2nsarbq3f0rwx8","definitions_version":"2026-q4","currency":"USD","interval":"month",
		"region":"US","amount_minor":1250,"adjustment_policy":"preserve_partial_end_full_or_chargeback"}]}`,
		environment, salesOpen, host02Offer))
}

func TestConfiguredCommerceBrowserRoutesAndDurableSignedAdmission(t *testing.T) {
	db := dbtest.New(t)
	fixtures := &Center{Config: config.Config{Mode: config.OfficialHosted, Plan: config.PlanDevelopmentFixtures}, Store: db.Runtime}
	if err := fixtures.checkCommerceFixtureStore(t.Context()); err != nil ||
		db.Count("SELECT count(*) FROM commerce.provider_environment") != 0 {
		t.Fatal("development fixtures could not use a pristine store without selecting a provider")
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	cfg := testConfig(config.OfficialHosted)
	cfg.Plan = config.PlanConfigured
	cfg.HostedCatalogue = []byte(`{"version":"2026-q4","fixture":false,"capabilities":["center.nodes","remote.view","remote.control"],
		"plans":[{"id":"fixture","name":"Isolated service fixture","features":["center.nodes","remote.view","remote.control"]}]}`)
	cfg.Identity.Surfaces = []config.Surface{config.SurfaceIdentity, config.SurfaceCommerce}
	cfg.Identity.ClientIPHeader = config.ClientIPHeader
	var err error
	cfg.Identity.Policy, err = config.ParseIdentityPolicy("")
	if err != nil {
		t.Fatal(err)
	}
	// Use the disposable test listener's loopback transport. Official env loading still requires verified PostgreSQL TLS.
	cfg.Database = db.Runtime.Pool().Config()
	cfg.Commerce = config.Commerce{Environment: "sandbox", APIKey: config.NewSecret("pdl_sdbx_apikey_fixture_only"),
		WebhookSecret: config.NewSecret(host02WebhookSecret), CheckoutOrigins: []string{"https://checkout.fixture.test"},
		PortalOrigins: []string{"https://portal.fixture.test"}, Catalogue: host02Catalogue("sandbox", true)}
	peer := &commerceFixtureTransport{}
	options := Options{Clock: func() time.Time { return now }, commerceTransport: peer}
	logger := slog.New(slog.DiscardHandler)
	open := func(settings config.Config) (*Center, *httptest.Server) {
		t.Helper()
		center, err := New(settings, logger, options)
		if err != nil {
			t.Fatal(err)
		}
		listener := httptest.NewServer(center.Public())
		t.Cleanup(center.Close)
		t.Cleanup(listener.Close)
		return center, listener
	}
	center, listener := open(cfg)
	if db.Count("SELECT count(*) FROM commerce.provider_environment WHERE environment=2") != 1 {
		t.Fatal("the deployment's Paddle realm is not durable")
	}

	account := db.Account(1)
	browser := db.Session(account, 1)
	headers := host02BrowserHeaders(browser)
	catalogue := &publicapiv1.CommerceServiceGetCatalogueResponse{}
	catalogueRequest := &publicapiv1.CommerceServiceGetCatalogueRequest{Meta: &foundationv1.RequestMeta{}, Region: proto.String("US")}
	path := publicapiv1connect.CommerceServiceGetCatalogueProcedure
	readHost02Commerce(t, listener, path, headers, catalogueRequest, catalogue)
	items := catalogue.GetValue().GetItems()
	if len(items) != 1 || items[0].GetAmount().GetValue() != "12.5" || len(items[0].GetEntitlements()) != 3 ||
		items[0].GetOfferId().GetValue() == nil || catalogue.GetValue().GetCatalogueVersion() != "fixture-merchant-1" {
		t.Fatal("a current browser account without hosted access did not receive the approved quote")
	}
	wrongCSRF := host02BrowserHeaders(browser)
	wrongCSRF[ingress.CSRFHeader] = "wrong"
	requestBytes, _ := proto.Marshal(catalogueRequest)
	refused := grpcWeb(t, listener.URL, path, ingress.Frame(requestBytes), wrongCSRF)
	if refused.trailers["grpc-status"] != "7" || len(refused.messages) != 0 {
		t.Fatal("invalid CSRF reached typed commerce")
	}
	retired := grpcWeb(t, listener.URL, publicapiv1connect.CommerceServiceGetCreditsProcedure, ingress.Frame(requestBytes), headers)
	if retired.trailers["grpc-status"] != "12" || len(retired.messages) != 0 {
		t.Fatal("the legacy credits procedure is registered")
	}

	purchaseID, commandID := platform.NewID(), platform.NewID()
	create := &publicapiv1.CommerceServiceCreatePurchaseIntentRequest{Meta: &foundationv1.RequestMeta{CommandId: wireCommerceID(commandID)},
		PurchaseIntentId: wireCommerceID(purchaseID), OfferId: wireCommerceID(commerceTextID(host02Offer)), PriceVersion: proto.String("pv1"), Region: proto.String("US")}
	intent := &publicapiv1.CommerceServiceCreatePurchaseIntentResponse{}
	readHost02Commerce(t, listener, publicapiv1connect.CommerceServiceCreatePurchaseIntentProcedure, headers, create, intent)
	if intent.GetValue().GetPurchase().GetState() != "pending" ||
		db.Count("SELECT count(*) FROM commerce.purchase WHERE purchase_id=$1 AND account_id=$2", purchaseID, account) != 1 {
		t.Fatalf("typed purchase intent did not create its account receipt, code %q", intent.GetError().GetCode())
	}
	other := db.Session(db.Account(1), 1)
	purchase := &publicapiv1.CommerceServiceGetPurchaseStateResponse{}
	readHost02Commerce(t, listener, publicapiv1connect.CommerceServiceGetPurchaseStateProcedure, host02BrowserHeaders(other),
		&publicapiv1.CommerceServiceGetPurchaseStateRequest{Meta: &foundationv1.RequestMeta{}, PurchaseIntentId: wireCommerceID(purchaseID)}, purchase)
	if purchase.GetError().GetCode() != "not_found" {
		t.Fatal("another account could read a purchase")
	}

	checkout := &publicapiv1.CommerceServiceCreateCheckoutAttemptResponse{}
	checkoutRequest := &publicapiv1.CommerceServiceCreateCheckoutAttemptRequest{
		Meta: &foundationv1.RequestMeta{CommandId: wireCommerceID(platform.NewID())}, PurchaseIntentId: wireCommerceID(purchaseID),
		CheckoutAttemptId: wireCommerceID(platform.NewID()), ReturnRoute: proto.String("/account/subscription"),
	}
	for range 2 {
		readHost02Commerce(t, listener, publicapiv1connect.CommerceServiceCreateCheckoutAttemptProcedure, headers, checkoutRequest, checkout)
		failure := checkout.GetError()
		if failure.GetCode() != "internal" || failure.GetEffect() != foundationv1.EffectCertainty_EFFECT_CERTAINTY_UNKNOWN ||
			failure.GetRetry().GetMode() != foundationv1.RetryMode_RETRY_MODE_NEVER || checkout.GetValue() != nil || peer.checkout.Load() != 1 {
			t.Fatal("the uncertain provider outcome was misreported or the checkout was dispatched twice")
		}
	}
	readHost02Commerce(t, listener, publicapiv1connect.CommerceServiceGetPurchaseStateProcedure, headers,
		&publicapiv1.CommerceServiceGetPurchaseStateRequest{Meta: &foundationv1.RequestMeta{}, PurchaseIntentId: wireCommerceID(purchaseID)}, purchase)
	if purchase.GetValue().GetPurchase().GetState() != "unknown" {
		t.Fatal("the earlier provider outcome was not recoverable by its original purchase identity")
	}

	subscriptionID := platform.NewID()
	seedHost02Subscription(t, db, account, subscriptionID, now)
	body := []byte(fmt.Sprintf(`{"subscription_id":%q}`, subscriptionID.String()))
	portal := func(from map[string]string) (int, []byte) {
		return sendHost02HTTP(t, listener, routes.CommercePortalPath, body, from)
	}
	if status, _ := portal(headers); status != http.StatusForbidden || peer.portal.Load() != 0 {
		t.Fatal("a browser session without subscription-bound evidence reached the Paddle portal")
	}
	target, err := hex.DecodeString(identity.TargetHash(routes.CommercePortalID, account, subscriptionID))
	if err != nil {
		t.Fatal(err)
	}
	db.ProveStepUp(browser, routes.CommercePortalID, target, now)
	if status, _ := portal(host02BrowserHeaders(other)); status != http.StatusNotFound || peer.portal.Load() != 0 {
		t.Fatal("another account reached the Paddle portal")
	}
	if status, payload := portal(headers); status != http.StatusOK || peer.portal.Load() != 1 {
		t.Fatalf("the target-bound portal request answered %d and %d calls", status, peer.portal.Load())
	} else {
		var reply map[string]string
		if json.Unmarshal(payload, &reply) != nil || len(reply) != 1 || reply["url"] != host02PortalURL {
			t.Fatal("the portal did not return only its approved short-lived link")
		}
	}
	if status, _ := portal(headers); status != http.StatusForbidden || peer.portal.Load() != 1 {
		t.Fatal("a consumed portal proof was accepted again")
	}

	event := []byte(fmt.Sprintf(`{"event_id":"evt_01hv8p95hhbb2nsarbq3f0rwx8","notification_id":"ntf_01hv8p95hhbb2nsarbq3f0rwx8",
		"event_type":"subscription.updated","occurred_at":%q,"data":{"id":%q}}`, now.Format(time.RFC3339Nano), host02Subscription))
	callback := func(listener *httptest.Server, raw []byte, signed bool) int {
		t.Helper()
		header := map[string]string{config.ClientIPHeader: "203.0.113.7"}
		if signed {
			header[routes.PaddleWebhookSignatureHeader] = fixturePaddleSignature(host02WebhookSecret, now, raw)
		}
		status, _ := sendHost02HTTP(t, listener, routes.PaddleWebhookPath, raw, header)
		return status
	}
	count := func() int { return db.Count("SELECT count(*) FROM commerce.provider_event") }
	if status := callback(listener, event, false); status != http.StatusBadRequest || count() != 0 {
		t.Fatal("unsigned notification became a durable event")
	}
	if status := callback(listener, event, true); status != http.StatusOK || count() != 1 {
		t.Fatalf("signed notification answered %d with %d durable receipts", status, count())
	}
	digest := sha256.Sum256(event)
	if db.Count("SELECT count(*) FROM commerce.provider_event WHERE environment=2 AND event_kind='subscription.updated' AND payload_sha256=$1 AND state=1", digest[:]) != 1 {
		t.Fatal("the acknowledged webhook receipt lacks the original body digest")
	}

	listener.Close()
	center.Close()
	cfg.Commerce.Catalogue = host02Catalogue("sandbox", false)
	_, restarted := open(cfg)
	if status := callback(restarted, event, true); status != http.StatusOK || count() != 1 {
		t.Fatal("the persisted exact notification did not deduplicate after restart")
	}
	if status := callback(restarted, append(bytes.Clone(event), ' '), true); status != http.StatusBadRequest || count() != 1 {
		t.Fatal("a changed body under the retained event identity was acknowledged")
	}
	readHost02Commerce(t, restarted, path, headers, catalogueRequest, catalogue)
	if catalogue.GetError().GetDetails().GetState().GetReason() != "sales_closed" {
		t.Fatal("a sales-paused catalogue offered new purchases")
	}
	subscription := &publicapiv1.CommerceServiceGetSubscriptionResponse{}
	readHost02Commerce(t, restarted, publicapiv1connect.CommerceServiceGetSubscriptionProcedure, headers,
		&publicapiv1.CommerceServiceGetSubscriptionRequest{Meta: &foundationv1.RequestMeta{}}, subscription)
	if subscription.GetValue().GetSubscription().GetState() != publicapiv1.SubscriptionState_SUBSCRIPTION_STATE_ACTIVE {
		t.Fatal("a sales pause blocked account billing remediation")
	}

	wrongRealm := cfg
	wrongRealm.Commerce.Environment = "live"
	wrongRealm.Commerce.APIKey = config.NewSecret("pdl_live_apikey_fixture_only")
	wrongRealm.Commerce.Catalogue = host02Catalogue("live", false)
	if incorrect, err := New(wrongRealm, logger, options); err == nil {
		incorrect.Close()
		t.Fatal("the pinned sandbox store composed a live merchant")
	} else if !strings.Contains(err.Error(), "runtime store could not confirm") {
		t.Fatalf("live configuration failed before the store's provider realm check: %s", err)
	}
	dark := cfg
	dark.Plan, dark.HostedCatalogue, dark.Commerce = config.PlanNone, nil, config.Commerce{}
	dark.Identity.Surfaces = []config.Surface{config.SurfaceIdentity}
	_, disabled := open(dark)
	if status := callback(disabled, event, true); status != http.StatusNotFound || count() != 1 {
		t.Fatal("a disabled surface accepted a notification")
	}
	readHost02Commerce(t, disabled, path, headers, catalogueRequest, catalogue)
	if catalogue.GetError().GetCode() != "not_activated" {
		t.Fatal("a disabled commerce surface exposed a catalogue")
	}
	development := dark
	development.Plan = config.PlanDevelopmentFixtures
	development.HTTPAddress = "127.0.0.1:0"
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := Run(ctx, development, logger); err == nil || !strings.Contains(err.Error(), "without a configured Paddle environment") {
		t.Fatal("a Center with development fixtures served a merchant-pinned store")
	}
}

func readHost02Commerce(t *testing.T, listener *httptest.Server, path string, headers map[string]string, input, output proto.Message) {
	t.Helper()
	raw, err := proto.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	reply := grpcWeb(t, listener.URL, path, ingress.Frame(raw), headers)
	if reply.trailers["grpc-status"] != "0" || len(reply.messages) != 1 || proto.Unmarshal(reply.messages[0], output) != nil {
		t.Fatalf("no typed response from %s (gRPC %q, frames %d)", path, reply.trailers["grpc-status"], len(reply.messages))
	}
}

func host02BrowserHeaders(browser dbtest.Session) map[string]string {
	handle := session.Secret(browser.Handle)
	return map[string]string{config.ClientIPHeader: "203.0.113.7", "Origin": host02Origin,
		"Cookie": ingress.SessionCookieName + "=" + handle.Text(), ingress.CSRFHeader: session.CSRF(handle)}
}

func sendHost02HTTP(t *testing.T, listener *httptest.Server, path string, raw []byte, headers map[string]string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, listener.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := listener.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data
}

func seedHost02Subscription(t *testing.T, db *dbtest.Database, account, id platform.ID, now time.Time) {
	t.Helper()
	_, err := db.Migration.Exec(t.Context(), `INSERT INTO commerce.customer(account_id, provider, environment, provider_customer_ref, created_at)
VALUES ($1, 1, 2, $2, $3)`, account, host02Customer, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Migration.Exec(t.Context(), `INSERT INTO commerce.subscription(subscription_id,account_id,provider,environment,
provider_customer_ref,provider_subscription_ref,catalog_version,product_ref,price_ref,state,valid_from,valid_until,auto_renew,
provider_updated_at,provider_snapshot_sha256,verified_at,rev)
VALUES ($1,$2,1,2,$3,$4,'fixture-merchant-1','pro_01hv8p95hhbb2nsarbq3f0rwx8','pri_01hv8p95hhbb2nsarbq3f0rwx8',2,$5,$6,true,
$7,decode(repeat('b0',32),'hex'),$7,1)`, id, account, host02Customer, host02Subscription, now.Add(-time.Hour), now.Add(24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
}
