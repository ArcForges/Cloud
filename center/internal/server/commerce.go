// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/ArcForges/Cloud/center/internal/arc"
	"github.com/ArcForges/Cloud/center/internal/commerce"
	"github.com/ArcForges/Cloud/center/internal/commerce/paddle"
	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/feature"
	"github.com/ArcForges/Cloud/center/internal/ingress"
	"github.com/ArcForges/Cloud/center/internal/routes"
)

func (c *Center) composeCommerce(options Options, clock func() time.Time) (http.Handler, error) {
	if c.Config.Mode != config.OfficialHosted || c.Store == nil || c.Entitlements == nil || c.Authorizer == nil {
		return nil, errors.New("commerce requires the official hosted Center with account identity and the runtime store")
	}
	active := c.FeatureConfiguration
	if active.State != feature.StateValid || active.Class != feature.ClassProduction || active.Catalogue == nil {
		return nil, errors.New("commerce requires a validated hosted entitlement catalogue")
	}
	if !slices.ContainsFunc(active.Catalogue.Plans, func(plan feature.Plan) bool {
		return len(plan.Features) == len(active.Catalogue.Capabilities)
	}) {
		return nil, errors.New("the hosted entitlement catalogue does not define the offered hosted capabilities as one plan")
	}
	settings := c.Config.Commerce
	merchant, err := parseCommerceCatalogue(settings.Catalogue, settings.Environment)
	if err != nil {
		return nil, err
	}
	for _, offer := range merchant.Offers {
		if offer.DefinitionsVersion != active.Catalogue.Version {
			return nil, errors.New("a commerce offer references a different entitlement definitions version")
		}
		if _, ok := commerceMoney(offer.AmountMinor, offer.Currency); !ok || offer.Region != "" && !regionCode(offer.Region) {
			return nil, errors.New("a commerce offer has an invalid currency or region")
		}
	}
	environment := paddle.Environment(settings.Environment)
	client, err := paddle.NewClient(paddle.Config{Environment: environment, APIKey: settings.APIKey.Reveal(),
		CheckoutOrigins: settings.CheckoutOrigins, PortalOrigins: settings.PortalOrigins, Transport: options.commerceTransport})
	if err != nil {
		return nil, errors.New("invalid Paddle API credential or approved origins for the configured environment")
	}
	var previous []string
	if !settings.PreviousWebhookSecret.Empty() {
		previous = append(previous, settings.PreviousWebhookSecret.Reveal())
	}
	verifier, err := paddle.NewWebhookVerifier(environment, settings.WebhookSecret.Reveal(), previous...)
	if err != nil {
		return nil, errors.New("invalid Paddle webhook signing secrets")
	}
	c.commerce, err = commerce.NewService(commerce.Options{DB: c.Store, Provider: client, Entitlements: c.Entitlements,
		Environment: environment, Catalogue: merchant, Clock: clock})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = commerce.CheckEnvironment(ctx, c.Store, environment, true); err != nil {
		return nil, errors.New("the runtime store could not confirm the configured Paddle environment")
	}
	return paddleWebhook(clock, ClientAddress(c.Config.Mode, c.Config.Identity), verifier, c.commerce.ReceiveEvent), nil
}

type commerceCatalogueDocument struct {
	Version          string            `json:"version"`
	Environment      string            `json:"environment"`
	SalesOpen        *bool             `json:"sales_open"`
	CheckoutLifetime string            `json:"checkout_lifetime"`
	Offers           []json.RawMessage `json:"offers"`
}

type commerceOfferDocument struct {
	ID                 string `json:"id"`
	PriceVersion       string `json:"price_version"`
	PriceID            string `json:"paddle_price_id"`
	ProductID          string `json:"paddle_product_id"`
	DefinitionsVersion string `json:"definitions_version"`
	Currency           string `json:"currency"`
	Interval           string `json:"interval"`
	Region             string `json:"region"`
	AmountMinor        int64  `json:"amount_minor"`
	AdjustmentPolicy   string `json:"adjustment_policy"`
}

func parseCommerceCatalogue(raw []byte, environment string) (commerce.Catalogue, error) {
	var document commerceCatalogueDocument
	if !commerceDocument(raw, &document, "version", "environment", "sales_open", "checkout_lifetime", "offers") ||
		document.Environment != environment || document.SalesOpen == nil {
		return commerce.Catalogue{}, errors.New("the commerce catalogue is invalid or belongs to a different Paddle environment")
	}
	lifetime, err := time.ParseDuration(document.CheckoutLifetime)
	if err != nil {
		return commerce.Catalogue{}, errors.New("the commerce catalogue has an invalid checkout lifetime")
	}
	result := commerce.Catalogue{Version: document.Version, SalesOpen: *document.SalesOpen, CheckoutLifetime: lifetime}
	for _, rawOffer := range document.Offers {
		var offer commerceOfferDocument
		if !commerceDocument(rawOffer, &offer, "id", "price_version", "paddle_price_id", "paddle_product_id", "definitions_version",
			"currency", "interval", "region", "amount_minor", "adjustment_policy") {
			return commerce.Catalogue{}, errors.New("the commerce catalogue contains an invalid offer document")
		}
		result.Offers = append(result.Offers, commerce.Offer{ID: commerceTextID(offer.ID), PriceVersion: offer.PriceVersion, PriceID: offer.PriceID,
			ProductID: offer.ProductID, DefinitionsVersion: offer.DefinitionsVersion, Currency: offer.Currency, Interval: offer.Interval,
			Region: offer.Region, AmountMinor: offer.AmountMinor, AdjustmentPolicy: offer.AdjustmentPolicy})
	}
	return result, nil
}

// commerceDocument permits each explicitly listed field once, with its exact spelling.
func commerceDocument(raw []byte, destination any, fields ...string) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return false
	}
	allowed := make(map[string]bool, len(fields))
	for _, name := range fields {
		allowed[name] = true
	}
	for decoder.More() {
		token, err := decoder.Token()
		key, isString := token.(string)
		if err != nil || !isString || !allowed[key] {
			return false
		}
		delete(allowed, key)
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return false
		}
	}
	return json.Unmarshal(raw, destination) == nil
}

func paddleWebhook(clock func() time.Time, address func(*http.Request) (netip.Addr, bool), verifier *paddle.WebhookVerifier,
	receive func(context.Context, paddle.Event) (commerce.EventReceipt, error)) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		status := receivePaddleNotification(writer, request, clock, address, verifier, receive)
		writer.Header().Set("Cache-Control", "no-store")
		if status == http.StatusMethodNotAllowed {
			writer.Header().Set("Allow", http.MethodPost)
		}
		if status == http.StatusServiceUnavailable {
			writer.Header().Set("Retry-After", "5")
		}
		if entry := recordFrom(request.Context()); entry != nil {
			entry.code = "http_" + strconv.Itoa(status)
		}
		writer.WriteHeader(status)
	})
}

func receivePaddleNotification(writer http.ResponseWriter, request *http.Request, clock func() time.Time,
	address func(*http.Request) (netip.Addr, bool), verifier *paddle.WebhookVerifier,
	receive func(context.Context, paddle.Event) (commerce.EventReceipt, error)) int {
	if !ingress.IsCanonical(request) || request.URL.Path != routes.PaddleWebhookPath || request.URL.RawQuery != "" || request.URL.ForceQuery {
		return http.StatusNotFound
	}
	if _, ok := address(request); !ok {
		return http.StatusNotFound
	}
	if request.Method != http.MethodPost {
		return http.StatusMethodNotAllowed
	}
	types := request.Header.Values("Content-Type")
	if len(types) != 1 || len(request.Header.Values("Content-Encoding")) != 0 || len(request.Header.Values("Content-Range")) != 0 {
		return http.StatusUnsupportedMediaType
	}
	mimeType, parameters, err := mime.ParseMediaType(types[0])
	if err != nil || mimeType != "application/json" || len(parameters) != 0 {
		return http.StatusUnsupportedMediaType
	}
	signature := request.Header.Values(routes.PaddleWebhookSignatureHeader)
	if len(signature) != 1 || len(signature[0]) == 0 || len(signature[0]) > routes.PaddleWebhookMaxSignatureBytes {
		return http.StatusBadRequest
	}
	if request.ContentLength > routes.PaddleWebhookMaxRequestBytes {
		return http.StatusRequestEntityTooLarge
	}
	ctx, cancel := context.WithTimeout(request.Context(), routes.PaddleWebhookMaxDurationMilliseconds*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	controller := http.NewResponseController(writer)
	if controller.SetReadDeadline(deadline) == nil {
		defer func() { _ = controller.SetReadDeadline(time.Time{}) }()
	}
	raw, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, routes.PaddleWebhookMaxRequestBytes))
	var tooLarge *http.MaxBytesError
	switch {
	case errors.As(err, &tooLarge):
		return http.StatusRequestEntityTooLarge
	case ctx.Err() != nil:
		return http.StatusServiceUnavailable
	case err != nil:
		return http.StatusBadRequest
	}
	event, err := verifier.Verify(raw, signature[0], clock())
	if errors.Is(err, paddle.ErrUnsupportedEvent) {
		return http.StatusOK
	}
	if err != nil {
		return http.StatusBadRequest
	}
	if _, err := receive(ctx, event); err != nil {
		var refusal *arc.Refusal
		if errors.As(err, &refusal) && (refusal.Code == "invalid_argument" || refusal.Reason == "event_digest_mismatch") {
			return http.StatusBadRequest
		}
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

func (c *Center) runCommerceReconciliation(ctx context.Context) {
	if c.commerce == nil {
		return
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		attempt, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.commerce.Reconcile(attempt)
		cancel()
		if err != nil && ctx.Err() == nil {
			c.Logger.WarnContext(ctx, "commerce reconciliation will retry")
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (c *Center) checkCommerceFixtureStore(ctx context.Context) error {
	if c.Config.Mode != config.OfficialHosted || c.Config.Plan != config.PlanDevelopmentFixtures || c.Store == nil {
		return nil
	}
	check, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := commerce.CheckEnvironment(check, c.Store, "", false); err != nil {
		return errors.New("the hosted development fixtures need a runtime store without a configured Paddle environment")
	}
	return nil
}
