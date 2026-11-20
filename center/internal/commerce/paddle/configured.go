// SPDX-License-Identifier: AGPL-3.0-only

package paddle

import (
	"errors"
	"net/http"

	"github.com/ArcForges/Cloud/center/internal/config"
)

// NewConfigured consumes local credentials at the Paddle adapter boundary.
func NewConfigured(settings config.Commerce, transport http.RoundTripper) (*Client, *WebhookVerifier, error) {
	environment := Environment(settings.Environment)
	client, err := NewClient(Config{Environment: environment, APIKey: settings.APIKey.Reveal(),
		CheckoutOrigins: settings.CheckoutOrigins, PortalOrigins: settings.PortalOrigins, Transport: transport})
	if err != nil {
		return nil, nil, errors.New("invalid Paddle API credential or approved origins for the configured environment")
	}
	var previous []string
	if !settings.PreviousWebhookSecret.Empty() {
		previous = append(previous, settings.PreviousWebhookSecret.Reveal())
	}
	verifier, err := NewWebhookVerifier(environment, settings.WebhookSecret.Reveal(), previous...)
	if err != nil {
		return nil, nil, errors.New("invalid Paddle webhook signing secrets")
	}
	return client, verifier, nil
}
