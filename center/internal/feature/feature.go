// SPDX-License-Identifier: AGPL-3.0-only

// Package feature answers whether a gated feature of the center is available (ArcForges-Design AD-0021 section 13a). This is
// the fail-closed stub of AF-CTR-02: in official-hosted mode no plan configuration exists yet, so every gated feature is
// unavailable; in self-hosted mode the built-in default enables every self-hostable gated feature. The plan catalogue, the
// subscription resolver and operator-configured limits replace the stub in AF-CTR-03. Availability is one more check after
// authentication, ownership, authorization, AGENT/HUMAN separation, audit and resource controls; it never bypasses them.
// Essential operations (Hello, health, sign-in, account, billing, security and recovery) have no key and are never gated.
package feature

import (
	"context"

	"github.com/ArcForges/Cloud/center/internal/config"
)

// Key is a feature key of the plan catalogue.
type Key string

// The gated feature keys of AD-0021 section 13a.
const (
	CenterNodes   Key = "center.nodes"
	CenterExecute Key = "center.execute"
	RemoteView    Key = "remote.view"
	RemoteControl Key = "remote.control"
	CenterMCP     Key = "center.mcp"
	Push          Key = "push"
)

// Gated is every gated feature key, in catalogue order.
func Gated() []Key {
	return []Key{CenterNodes, CenterExecute, RemoteView, RemoteControl, CenterMCP, Push}
}

// Reason explains a decision; it is a closed vocabulary, never request text.
type Reason string

// The reasons of the stub.
const (
	// ReasonPlanConfigurationMissing is every gated feature in official-hosted mode until the plan configuration exists.
	ReasonPlanConfigurationMissing Reason = "plan_configuration_missing"
	// ReasonSelfHostedDefault is the built-in default of a self-hosted center.
	ReasonSelfHostedDefault Reason = "self_hosted_default"
	// ReasonUnknownFeature is a key that is not in the catalogue; it is never available.
	ReasonUnknownFeature Reason = "unknown_feature"
	// ReasonModeInvalid is a gate without a valid mode; nothing is available.
	ReasonModeInvalid Reason = "mode_invalid"
)

// Decision is the availability of one feature for one caller.
type Decision struct {
	Available bool
	Reason    Reason
}

// Gate decides feature availability. AF-CTR-03 replaces the stub with the plan resolver behind the same interface; the context
// will then carry the caller's account.
type Gate interface {
	Availability(ctx context.Context, key Key) Decision
}

// NewGate is the stub gate of a center mode.
func NewGate(mode config.Mode) Gate { return stub{mode: mode} }

type stub struct{ mode config.Mode }

func (s stub) Availability(_ context.Context, key Key) Decision {
	known := false
	for _, gated := range Gated() {
		known = known || gated == key
	}
	switch {
	case !known:
		return Decision{Reason: ReasonUnknownFeature}
	case s.mode == config.SelfHosted:
		return Decision{Available: true, Reason: ReasonSelfHostedDefault}
	case s.mode == config.OfficialHosted:
		return Decision{Reason: ReasonPlanConfigurationMissing}
	default:
		return Decision{Reason: ReasonModeInvalid}
	}
}
