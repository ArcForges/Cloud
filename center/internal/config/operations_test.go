// SPDX-License-Identifier: AGPL-3.0-only

package config

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// TestTheOperationsSurfaceIsNeverADefaultAndNeedsTheAccountSurfaces: the interim operations page is on only where the list names it,
// together with the identity and pages surfaces, and only on the official hosted center.
func TestTheOperationsSurfaceIsNeverADefaultAndNeedsTheAccountSurfaces(t *testing.T) {
	self, err := Load(environment(withIdentity(SelfHosted, nil)))
	if err != nil || self.Identity.Enabled(SurfaceOperations) || !self.Identity.Enabled(SurfaceIdentity) || !self.Identity.Enabled(SurfacePages) {
		t.Fatalf("the self-hosted default: %v %v", self.Identity.Surfaces, err)
	}
	hosted := func(list string) map[string]string {
		return withIdentity(OfficialHosted, map[string]string{EnvSurfaces: list, EnvClientIPHeader: ClientIPHeader})
	}
	loaded, err := Load(environment(hosted("identity,pages,operations")))
	if err != nil || !loaded.Identity.Enabled(SurfaceOperations) {
		t.Fatalf("identity,pages,operations: %v %v", loaded.Identity.Surfaces, err)
	}
	for _, list := range []string{"operations", "identity,operations", "pages,operations", "identity,pages,operations,operations"} {
		if _, err = Load(environment(hosted(list))); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", list, err)
		}
	}
	if _, err = Load(environment(withIdentity(SelfHosted, map[string]string{EnvSurfaces: "identity,pages,operations"}))); !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), "official hosted center only") {
		t.Fatalf("operations on a self-hosted center: %v", err)
	}
}

// TestTheDisabledFeaturesAreASelfHostedOperatorLimit (PLT-18): known keys only, exact, never repeated, refused on the hosted center
// whatever their value.
func TestTheDisabledFeaturesAreASelfHostedOperatorLimit(t *testing.T) {
	self := func(value string) map[string]string {
		return withIdentity(SelfHosted, map[string]string{EnvDisabledFeatures: value})
	}
	loaded, err := Load(environment(self("push,remote.control")))
	if err != nil || !slices.Equal(loaded.DisabledFeatures, []string{"push", "remote.control"}) {
		t.Fatalf("two keys: %v %v", loaded.DisabledFeatures, err)
	}
	if loaded, err = Load(environment(self(""))); err != nil || len(loaded.DisabledFeatures) != 0 {
		t.Fatalf("an empty list: %v %v", loaded.DisabledFeatures, err)
	}
	if loaded, err = Load(environment(withIdentity(SelfHosted, nil))); err != nil || loaded.DisabledFeatures != nil {
		t.Fatalf("unset: %v %v", loaded.DisabledFeatures, err)
	}
	for _, value := range []string{"remote.contol", "push,", ",push", "push,push", " push", "push ", "Push", "center.nodes,unknown", "push;center.mcp"} {
		if _, err = Load(environment(self(value))); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), EnvDisabledFeatures) {
			t.Errorf("%q: %v", value, err)
		}
		if strings.Contains(err.Error(), value) && strings.TrimSpace(value) != "" && len(value) > 8 {
			t.Errorf("the error repeats the value %q: %v", value, err)
		}
	}
	// The hosted center refuses the variable whatever it holds, even empty: the Worker never passes it.
	for _, value := range []string{"", "push", "none"} {
		hostedValues := withIdentity(OfficialHosted, map[string]string{EnvDisabledFeatures: value})
		if _, err = Load(environment(hostedValues)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "self-hosted center only") {
			t.Errorf("hosted with %q: %v", value, err)
		}
	}
}
