// SPDX-License-Identifier: AGPL-3.0-only

package feature

import (
	"testing"

	"github.com/ArcForges/Cloud/center/internal/config"
)

func TestOfficialHostedEnablesNoGatedFeatureWithoutPlanConfiguration(t *testing.T) {
	gate := NewGate(config.OfficialHosted, config.PlanNone)
	for _, key := range Gated() {
		if decision := gate.Availability(t.Context(), key); decision.Available || decision.Reason != ReasonPlanConfigurationMissing {
			t.Fatalf("%s: %+v", key, decision)
		}
	}
}

func TestSelfHostedEnablesTheGatedFeaturesByDefault(t *testing.T) {
	gate := NewGate(config.SelfHosted, config.PlanNone)
	for _, key := range Gated() {
		if decision := gate.Availability(t.Context(), key); !decision.Available || decision.Reason != ReasonSelfHostedDefault {
			t.Fatalf("%s: %+v", key, decision)
		}
	}
}

func TestUnknownKeysAndModesFailClosed(t *testing.T) {
	for _, mode := range []config.Mode{config.OfficialHosted, config.SelfHosted, "", "hosted"} {
		for _, key := range []Key{"", "center.Nodes", "hello", "remote", "center.nodes "} {
			if decision := NewGate(mode, config.PlanNone).Availability(t.Context(), key); decision.Available || decision.Reason != ReasonUnknownFeature {
				t.Fatalf("%s/%q: %+v", mode, key, decision)
			}
		}
	}
	for _, mode := range []config.Mode{"", "hosted", "Official-Hosted"} {
		if decision := NewGate(mode, config.PlanNone).Availability(t.Context(), CenterNodes); decision.Available || decision.Reason != ReasonModeInvalid {
			t.Fatalf("%q: %+v", mode, decision)
		}
	}
	if len(Gated()) != 6 {
		t.Fatal("the catalogue keys of AD-0021 section 13a")
	}
}

func TestTheDevelopmentFixturesEnableNothingYet(t *testing.T) {
	gate := NewGate(config.OfficialHosted, config.PlanDevelopmentFixtures)
	for _, key := range Gated() {
		if decision := gate.Availability(t.Context(), key); decision.Available || decision.Reason != ReasonPlanCataloguePending {
			t.Fatalf("%s: %+v", key, decision)
		}
	}
}
