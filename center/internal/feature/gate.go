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
	Problem  string
	Disabled []Key
}

// Configure reads the plan configuration at start. It never fails: an official-hosted center whose catalogue is absent or invalid
// serves with every gated key unavailable (the caller logs Problem), and nothing here ever enables a key.
func Configure(settings Settings) Configuration {
	configuration := Configuration{Mode: settings.Mode, State: StateMissing, Class: ClassProduction, Disabled: slices.Clone(settings.Disabled)}
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
	definitions := c.Catalogue.Definitions(c.Mode == config.SelfHosted)
	// Resolve derives the stored version from the complete decision history under these inputs. Replay the original meanings of
	// the retired keys so switching to the V2 catalogue cannot roll that version backwards. These entries are outside V2 status
	// and grant issuance. Only CenterExecute remains callable through the retained, separately selected V1 route group.
	for _, key := range []Key{CenterExecute, CenterMCP, Push} {
		definitions.Capabilities = append(definitions.Capabilities, entitlement.CapabilityDefinition{Key: string(key), RequiresPaidTerm: true})
	}
	return definitions
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

// ErrNoEntitlementStore is why a hosted gate with a valid catalogue cannot decide: the center has no entitlement store, so nothing is
// entitled. A caller answers it as an unavailable store.
var ErrNoEntitlementStore = errors.New("no entitlement store is configured")

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
	return g.availability(ctx, key)
}

// LegacyAvailability permits the original V1 submission key for callers that selected the retained V1 route.
func LegacyAvailability(g Gate, ctx context.Context, key Key) Decision {
	if g == nil {
		return Decision{Reason: ReasonModeInvalid}
	}
	if configured, ok := g.(gate); ok && key == CenterExecute {
		return configured.availability(ctx, key)
	}
	return g.Availability(ctx, key)
}

func (g gate) selfHostedDecision(key Key) Decision {
	if slices.Contains(g.configuration.Disabled, key) {
		return Decision{Reason: ReasonOperatorLimit}
	}
	return Decision{Available: true, Reason: ReasonSelfHostedDefault}
}

func (g gate) availability(ctx context.Context, key Key) Decision {
	if g.configuration.Mode == config.SelfHosted {
		return g.selfHostedDecision(key)
	}
	snapshot, refusal := g.readHosted(ctx)
	if refusal.Reason != "" {
		return refusal
	}
	return snapshotDecision(snapshot, key)
}

func (g gate) readHosted(ctx context.Context) (entitlement.StoredSnapshot, Decision) {
	if g.configuration.Mode != config.OfficialHosted {
		return entitlement.StoredSnapshot{}, Decision{Reason: ReasonModeInvalid}
	}
	switch g.configuration.State {
	case StateMissing:
		return entitlement.StoredSnapshot{}, Decision{Reason: ReasonPlanConfigurationMissing}
	case StateValid:
	default:
		return entitlement.StoredSnapshot{}, Decision{Reason: ReasonPlanConfigurationInvalid}
	}
	account, ok := AccountFrom(ctx)
	if !ok {
		return entitlement.StoredSnapshot{}, Decision{Reason: ReasonNoAccount}
	}
	if g.reader == nil {
		return entitlement.StoredSnapshot{}, Decision{Reason: ReasonEntitlementUnavailable, Err: ErrNoEntitlementStore}
	}
	snapshot, err := g.reader.Read(ctx, account)
	if err != nil {
		return entitlement.StoredSnapshot{}, Decision{Reason: ReasonEntitlementUnavailable, Err: err}
	}
	return snapshot, Decision{}
}

func snapshotDecision(snapshot entitlement.StoredSnapshot, key Key) Decision {
	entry, found := snapshot.Capability(string(key))
	if !found {
		return Decision{Reason: ReasonFeatureUnavailable}
	}
	return decisionOf(entry)
}

// FeatureStatus is one eligible V2 service decision in the account's hosting snapshot.
type FeatureStatus struct {
	Key      Key
	Decision Decision
}

// SnapshotStatus contains the V2 service decisions. A version is present only for an actual official entitlement snapshot.
type SnapshotStatus struct {
	Version  *int64
	Features []FeatureStatus
}

// Status reads the three active service decisions from one account snapshot. Static self-hosted and unconfigured official modes
// consult no entitlement record. Store errors are returned without fabricating unavailable or expired account decisions.
func Status(ctx context.Context, source Gate) (SnapshotStatus, error) {
	g, ok := source.(gate)
	if !ok {
		return SnapshotStatus{}, ErrNoEntitlementStore
	}
	status := SnapshotStatus{}
	selfHosted := g.configuration.Mode == config.SelfHosted
	var snapshot entitlement.StoredSnapshot
	var refusal Decision
	if !selfHosted {
		snapshot, refusal = g.readHosted(ctx)
		if refusal.Err != nil {
			return SnapshotStatus{}, refusal.Err
		}
		if refusal.Reason == "" {
			status.Version = &snapshot.Version
		}
	}
	for _, key := range Gated() {
		decision := refusal
		switch {
		case selfHosted:
			decision = g.selfHostedDecision(key)
		case refusal.Reason == "":
			decision = snapshotDecision(snapshot, key)
		}
		status.Features = append(status.Features, FeatureStatus{key, decision})
	}
	return status, nil
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
