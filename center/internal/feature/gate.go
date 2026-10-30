// SPDX-License-Identifier: AGPL-3.0-only

package feature

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/ArcForges/Cloud/center/internal/config"
	"github.com/ArcForges/Cloud/center/internal/entitlement"
)

// State is what the center's start made of its plan configuration (official-hosted mode).
type State int

// The states.
const (
	// StateMissing: no plan configuration (production until H-07): no catalogue exists and every gated key is unavailable.
	StateMissing State = iota + 1
	// StateInvalid: a catalogue was configured and does not validate: every gated key is unavailable, and the start logs it.
	StateInvalid
	// StateValid: a catalogue validated; the entitlement of the caller's account decides.
	StateValid
)

// Settings are what the composition hands the feature package.
type Settings struct {
	Mode config.Mode
	Plan config.PlanConfiguration
	// Injected is a catalogue document a test supplies instead of the embedded fixtures, with its classification (tests only: no
	// environment variable and no file reaches it, DC-12, and the composition of a running center never sets it; a test pins that).
	Injected      []byte
	InjectedClass Classification
	// Disabled are the keys the operator of a self-hosted center disabled (ARCFORGES_CENTER_DISABLED_FEATURES).
	Disabled []Key
	// PushSender is true when a push sender is configured; self-hosted `push` is available only then (DC-22). No sender exists until
	// AF-CLD-06.
	PushSender bool
}

// Configuration is the validated plan configuration of one center process.
type Configuration struct {
	Mode  config.Mode
	State State
	// Catalogue is set when State is StateValid.
	Catalogue *Catalogue
	// Class is the classification of the configuration: Production without a catalogue (and with a test-injected production
	// catalogue), Development with the fixtures.
	Class Classification
	// Problem says why State is StateInvalid; it names a rule, never a value.
	Problem    string
	Disabled   []Key
	PushSender bool
}

// Configure reads the plan configuration at start. It never fails: an official-hosted center whose catalogue is absent or invalid
// serves with every gated key unavailable (the caller logs Problem), and nothing here ever enables a key.
func Configure(settings Settings) Configuration {
	configuration := Configuration{Mode: settings.Mode, State: StateMissing, Class: ClassProduction, Disabled: settings.Disabled, PushSender: settings.PushSender}
	if settings.Mode != config.OfficialHosted {
		return configuration
	}
	var catalogue Catalogue
	var err error
	switch {
	case settings.Injected != nil:
		configuration.Class = settings.InjectedClass
		catalogue, err = ParseCatalogue(settings.Injected, settings.InjectedClass)
	case settings.Plan == config.PlanDevelopmentFixtures:
		configuration.Class = ClassDevelopment
		catalogue, err = DevelopmentFixtures()
	default:
		return configuration
	}
	if err != nil {
		configuration.State, configuration.Problem = StateInvalid, err.Error()
		return configuration
	}
	configuration.State, configuration.Catalogue = StateValid, &catalogue
	return configuration
}

// Definitions is the definition source of the entitlement service: the valid catalogue's definitions. A center without a valid
// catalogue never reads an entitlement, so its definitions are empty (the version stays well formed).
func (c Configuration) Definitions() entitlement.Definitions {
	if c.Catalogue == nil {
		return entitlement.Definitions{Version: "none", IsSelfHostRealm: c.Mode == config.SelfHosted}
	}
	return c.Catalogue.Definitions(c.Mode == config.SelfHosted)
}

// Current makes a Configuration the entitlement service's definition source.
func (c Configuration) Current() entitlement.Definitions { return c.Definitions() }

// OperatorGrants is the policy of operator grants, or the reason they are refused (entitlement.ErrGrantsSelfHosted,
// entitlement.ErrGrantsNoCatalogue): in self-hosted mode (there the built-in default and the operator's own limits decide), and in a
// configuration without a valid catalogue (the production configuration until H-07). A production-classified catalogue allows at most
// 90 days and no catalogue-wide grant; any other allows at most 400 days.
func (c Configuration) OperatorGrants() (entitlement.OperatorPolicy, error) {
	switch {
	case c.Mode != config.OfficialHosted:
		return entitlement.OperatorPolicy{}, entitlement.ErrGrantsSelfHosted
	case c.State != StateValid:
		return entitlement.OperatorPolicy{}, entitlement.ErrGrantsNoCatalogue
	}
	keys := make([]string, len(c.Catalogue.Capabilities))
	for index, key := range c.Catalogue.Capabilities {
		keys[index] = string(key)
	}
	if c.Class == ClassProduction {
		return entitlement.OperatorPolicy{MaxExpiry: 90 * 24 * time.Hour, Keys: keys}, nil
	}
	return entitlement.OperatorPolicy{MaxExpiry: 400 * 24 * time.Hour, AllowCatalogueWide: true, Keys: keys}, nil
}

var errNoStore = errors.New("no entitlement store is configured")

// Reader reads an account's current entitlement snapshot (entitlement.Service).
type Reader interface {
	Read(ctx context.Context, account string) (entitlement.StoredSnapshot, error)
}

type gate struct {
	configuration Configuration
	reader        Reader
}

// NewGate is the feature gate of a configuration. The reader is the entitlement service; it is not used in self-hosted mode or
// without a valid catalogue.
func NewGate(configuration Configuration, reader Reader) Gate {
	return gate{configuration: configuration, reader: reader}
}

func (g gate) Availability(ctx context.Context, key Key) Decision {
	if !IsGated(key) {
		return Decision{Reason: ReasonUnknownFeature}
	}
	switch g.configuration.Mode {
	case config.SelfHosted:
		switch {
		case slices.Contains(g.configuration.Disabled, key):
			return Decision{Reason: ReasonOperatorLimit}
		case key == Push && !g.configuration.PushSender:
			return Decision{Reason: ReasonPushSenderNotConfigured}
		}
		return Decision{Available: true, Reason: ReasonSelfHostedDefault}
	case config.OfficialHosted:
	default:
		return Decision{Reason: ReasonModeInvalid}
	}
	switch g.configuration.State {
	case StateMissing:
		return Decision{Reason: ReasonPlanConfigurationMissing}
	case StateValid:
	default:
		return Decision{Reason: ReasonPlanConfigurationInvalid}
	}
	account, ok := AccountFrom(ctx)
	if !ok {
		return Decision{Reason: ReasonNoAccount}
	}
	if g.reader == nil {
		return Decision{Reason: ReasonEntitlementUnavailable, Err: errNoStore}
	}
	snapshot, err := g.reader.Read(ctx, account)
	if err != nil {
		return Decision{Reason: ReasonEntitlementUnavailable, Err: err}
	}
	entry, found := snapshot.Capability(string(key))
	if !found {
		return Decision{Reason: ReasonFeatureUnavailable}
	}
	return decisionOf(entry)
}

// decisionOf maps the resolver's reason of a capability to the gate's closed vocabulary.
func decisionOf(entry entitlement.CapabilityEntry) Decision {
	if entry.Granted {
		return Decision{Available: true, Reason: ReasonEntitled}
	}
	switch entry.Reason {
	case entitlement.ReasonSubscriptionExpired:
		return Decision{Reason: ReasonSubscriptionExpired}
	case entitlement.ReasonPaymentGrace:
		return Decision{Reason: ReasonPaymentGrace}
	case entitlement.ReasonTemporarilyRestricted:
		return Decision{Reason: ReasonTemporarilyRestricted}
	case entitlement.ReasonWorkspaceSuspended:
		return Decision{Reason: ReasonAccountSuspended}
	case entitlement.ReasonFeatureUnavailable:
		return Decision{Reason: ReasonFeatureUnavailable}
	}
	return Decision{Reason: ReasonNoEntitlement}
}
