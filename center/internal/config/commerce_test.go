// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"maps"
	"strings"
	"testing"
)

func TestCommerceRequiresPairedOfficialConfigurationAndNeverPrintsCredentials(t *testing.T) {
	values := withIdentity(OfficialHosted, map[string]string{
		EnvSurfaces: "identity,commerce", EnvClientIPHeader: ClientIPHeader,
		EnvHostedCatalogue: `{"version":"test-definitions"}`, EnvCommerceCatalogue: `{"environment":"sandbox"}`,
		EnvPaddleEnvironment: "sandbox", EnvPaddleAPIKey: "fixture-api-secret",
		EnvPaddleWebhookSecret: "fixture-webhook-secret", EnvPaddleCheckoutOrigins: "https://checkout.example.test",
		EnvPaddlePortalOrigins: "https://portal.example.test",
	})
	cfg, err := Load(environment(values))
	if err != nil || cfg.Plan != PlanConfigured || !cfg.Identity.Enabled(SurfaceCommerce) || cfg.Commerce.Environment != "sandbox" ||
		cfg.Commerce.APIKey.Empty() || len(cfg.HostedCatalogue) == 0 {
		t.Fatal("the explicit official commerce configuration did not load")
	}
	for name, change := range map[string]func(map[string]string){
		"self-hosted":      func(values map[string]string) { values[EnvMode] = string(SelfHosted) },
		"missing identity": func(values map[string]string) { values[EnvSurfaces] = "commerce" },
		"no commerce":      func(values map[string]string) { values[EnvSurfaces] = "identity" },
		"no definition":    func(values map[string]string) { delete(values, EnvHostedCatalogue) },
		"no signing key":   func(values map[string]string) { delete(values, EnvPaddleWebhookSecret) },
		"no realm":         func(values map[string]string) { delete(values, EnvPaddleEnvironment) },
		"malformed seller": func(values map[string]string) { values[EnvCommerceCatalogue] = "fixture-api-secret" },
		"development":      func(values map[string]string) { values[EnvPlanConfiguration] = string(PlanDevelopmentFixtures) },
	} {
		t.Run(name, func(t *testing.T) {
			modified := maps.Clone(values)
			change(modified)
			_, err := Load(environment(modified))
			if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "fixture-api-secret") || strings.Contains(err.Error(), "fixture-webhook-secret") {
				t.Fatal("configuration was admitted or returned a credential")
			}
		})
	}
}
