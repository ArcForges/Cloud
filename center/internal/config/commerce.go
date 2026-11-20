// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"encoding/json"
	"strings"
)

const (
	SurfaceCommerce Surface = "commerce"

	EnvHostedCatalogue             = "ARCFORGES_CENTER_HOSTED_CATALOGUE"
	EnvCommerceCatalogue           = "ARCFORGES_CENTER_COMMERCE_CATALOGUE"
	EnvPaddleEnvironment           = "ARCFORGES_CENTER_PADDLE_ENVIRONMENT"
	EnvPaddleAPIKey                = "ARCFORGES_CENTER_PADDLE_API_KEY"
	EnvPaddleWebhookSecret         = "ARCFORGES_CENTER_PADDLE_WEBHOOK_SECRET"
	EnvPaddlePreviousWebhookSecret = "ARCFORGES_CENTER_PADDLE_PREVIOUS_WEBHOOK_SECRET"
	EnvPaddleCheckoutOrigins       = "ARCFORGES_CENTER_PADDLE_CHECKOUT_ORIGINS"
	EnvPaddlePortalOrigins         = "ARCFORGES_CENTER_PADDLE_PORTAL_ORIGINS"
)

const maxCatalogueConfigBytes = 16 * 1024

// Commerce holds local merchant configuration. The service validates catalogue
// data and the Paddle adapter validates its environments and origin allowlists.
type Commerce struct {
	Environment           string
	APIKey                Secret
	WebhookSecret         Secret
	PreviousWebhookSecret Secret
	CheckoutOrigins       []string
	PortalOrigins         []string
	Catalogue             []byte
}

func loadHostedCatalogue(lookup func(string) (string, bool), mode Mode) (PlanConfiguration, []byte, error) {
	value, present := lookup(EnvHostedCatalogue)
	plan, _ := lookup(EnvPlanConfiguration)
	switch PlanConfiguration(plan) {
	case PlanNone:
	case PlanDevelopmentFixtures, PlanConfigured:
		if mode != OfficialHosted {
			return PlanNone, nil, invalid("%s applies to an official-hosted center only", EnvPlanConfiguration)
		}
	default:
		return PlanNone, nil, invalid("%s must be empty, %s or %s", EnvPlanConfiguration, PlanDevelopmentFixtures, PlanConfigured)
	}
	if !present {
		if PlanConfiguration(plan) == PlanConfigured {
			return PlanNone, nil, invalid("%s is required for the configured plan", EnvHostedCatalogue)
		}
		return PlanConfiguration(plan), nil, nil
	}
	if mode != OfficialHosted || PlanConfiguration(plan) == PlanDevelopmentFixtures {
		return PlanNone, nil, invalid("%s applies to the official-hosted production plan only", EnvHostedCatalogue)
	}
	if !validCatalogueDocument(value) {
		return PlanNone, nil, invalid("%s must be a bounded JSON object", EnvHostedCatalogue)
	}
	return PlanConfigured, []byte(value), nil
}

func loadCommerce(lookup func(string) (string, bool), enabled bool, plan PlanConfiguration) (Commerce, error) {
	get := func(name string) string {
		value, _ := lookup(name)
		return value
	}
	if !enabled {
		if plan == PlanConfigured {
			return Commerce{}, invalid("%s needs the commerce surface and a configured Paddle environment", EnvHostedCatalogue)
		}
		for _, name := range []string{EnvCommerceCatalogue, EnvPaddleEnvironment, EnvPaddleAPIKey, EnvPaddleWebhookSecret,
			EnvPaddlePreviousWebhookSecret, EnvPaddleCheckoutOrigins, EnvPaddlePortalOrigins} {
			if _, present := lookup(name); present {
				return Commerce{}, invalid("%s requires the commerce surface", name)
			}
		}
		return Commerce{}, nil
	}
	if plan != PlanConfigured {
		return Commerce{}, invalid("the commerce surface requires %s", EnvHostedCatalogue)
	}
	environment := get(EnvPaddleEnvironment)
	if environment != "sandbox" && environment != "live" {
		return Commerce{}, invalid("%s must be sandbox or live", EnvPaddleEnvironment)
	}
	for _, name := range []string{EnvPaddleAPIKey, EnvPaddleWebhookSecret, EnvPaddleCheckoutOrigins, EnvPaddlePortalOrigins} {
		if get(name) == "" {
			return Commerce{}, invalid("%s is required for the commerce surface", name)
		}
	}
	catalogue := get(EnvCommerceCatalogue)
	if !validCatalogueDocument(catalogue) {
		return Commerce{}, invalid("%s must be a bounded JSON object", EnvCommerceCatalogue)
	}
	return Commerce{
		Environment: environment, APIKey: NewSecret(get(EnvPaddleAPIKey)),
		WebhookSecret: NewSecret(get(EnvPaddleWebhookSecret)), PreviousWebhookSecret: NewSecret(get(EnvPaddlePreviousWebhookSecret)),
		CheckoutOrigins: strings.Split(get(EnvPaddleCheckoutOrigins), ","), PortalOrigins: strings.Split(get(EnvPaddlePortalOrigins), ","),
		Catalogue: []byte(catalogue),
	}, nil
}

func validCatalogueDocument(value string) bool {
	trimmed := strings.TrimSpace(value)
	return len(value) <= maxCatalogueConfigBytes && strings.HasPrefix(trimmed, "{") && json.Valid([]byte(value))
}
