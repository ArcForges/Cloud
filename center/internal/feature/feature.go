// SPDX-License-Identifier: AGPL-3.0-only

// Package feature answers whether a hosted service is available to a caller. Official-hosted mode uses the plan catalogue and the
// account's entitlement snapshot. Self-hosted mode uses the operator's local limits and needs no entitlement snapshot.
// Availability is one more check after authentication, ownership, authorization, AGENT/HUMAN separation, audit and resource controls
// (access.Authorize); it never bypasses them. Essential operations (Hello, health, sign-in, account, billing, security and recovery)
// have no key and are never gated.
package feature

import (
	"context"
)

// Key is a feature key of the plan catalogue.
type Key string

// The active V2 service keys.
const (
	CenterNodes   Key = "center.nodes"
	RemoteView    Key = "remote.view"
	RemoteControl Key = "remote.control"
)

// The old keys retain their identity in historical entitlement replay. CenterExecute also gates the finite V1 routed adapter.
const (
	CenterExecute Key = "center.execute"
	CenterMCP     Key = "center.mcp"
	Push          Key = "push"
)

// Gated is every active V2 service key, in catalogue order.
func Gated() []Key {
	return []Key{CenterNodes, RemoteView, RemoteControl}
}

// IsGated reports whether a key is one of the gated keys.
func IsGated(key Key) bool {
	for _, gated := range Gated() {
		if gated == key {
			return true
		}
	}
	return false
}

// Group names one group of the center's routed operations in the routed task control table: an operation row that carries a Feature
// names its group, and its key must be the key of that group (access.CheckRow, AF-CTR-05 E0, CTR5-GATE-06). The value is a closed
// vocabulary, never request text.
type Group string

// The groups of the routed task control table.
const (
	GroupControl         Group = "control"
	GroupSubmission      Group = "submission"
	GroupStatusAndOutput Group = "status_and_output"
	GroupNodeConnection  Group = "node_connection"
	GroupMCP             Group = "mcp"
	GroupPush            Group = "push"
)

// OperationKey associates a V2 route group with its hosted service key. Node enrollment and account remediation are essential and
// carry no key.
type OperationKey struct {
	Key   Key
	Group Group
	Gates string
}

// OperationKeys is the active V2 hosted service table.
func OperationKeys() []OperationKey {
	return []OperationKey{
		{RemoteControl, GroupControl, "Sandbox, Run, resource and data mutations"},
		{RemoteView, GroupStatusAndOutput, "Sandbox, Run, resource and data reads and watches"},
		{CenterNodes, GroupNodeConnection, "node connection"},
	}
}

// KeyOfGroup is the key of an active V2 route group.
func KeyOfGroup(group Group) (Key, bool) {
	for _, row := range OperationKeys() {
		if row.Group == group {
			return row.Key, true
		}
	}
	return "", false
}

// LegacyKeyOfGroup is for retained V1 routes. Their submission authority has no V2 alias.
func LegacyKeyOfGroup(group Group) (Key, bool) {
	if group == GroupSubmission {
		return CenterExecute, true
	}
	return KeyOfGroup(group)
}

// Reason explains a decision; it is a closed vocabulary, never request text.
type Reason string

// The reasons.
const (
	// ReasonPlanConfigurationMissing is every gated feature in official-hosted mode without a plan configuration (production until H-07).
	ReasonPlanConfigurationMissing Reason = "plan_configuration_missing"
	// ReasonPlanConfigurationInvalid is every gated feature in official-hosted mode whose plan configuration does not validate: an
	// invalid catalogue never enables anything.
	ReasonPlanConfigurationInvalid Reason = "plan_configuration_invalid"
	// ReasonSelfHostedDefault is the built-in default of a self-hosted center.
	ReasonSelfHostedDefault Reason = "self_hosted_default"
	// ReasonOperatorLimit is a key the operator of a self-hosted center disabled.
	ReasonOperatorLimit Reason = "operator_limit"
	// ReasonUnknownFeature is a key that is not in the catalogue; it is never available.
	ReasonUnknownFeature Reason = "unknown_feature"
	// ReasonModeInvalid is a gate without a valid mode; nothing is available.
	ReasonModeInvalid Reason = "mode_invalid"
	// ReasonNoAccount is a call whose context names no account: nothing is entitled to nobody.
	ReasonNoAccount Reason = "no_account"
	// ReasonEntitlementUnavailable is a call whose entitlement the store could not answer; the decision carries the store error.
	ReasonEntitlementUnavailable Reason = "entitlement_unavailable"
	// The reasons of an account's entitlement (the resolver's reasons, ES-02).
	ReasonEntitled              Reason = "entitled"
	ReasonNoEntitlement         Reason = "no_entitlement"
	ReasonSubscriptionExpired   Reason = "subscription_expired"
	ReasonPaymentGrace          Reason = "payment_grace"
	ReasonTemporarilyRestricted Reason = "temporarily_restricted"
	ReasonAccountSuspended      Reason = "account_suspended"
	ReasonFeatureUnavailable    Reason = "feature_unavailable"
)

// Decision is the availability of one feature for one caller.
type Decision struct {
	Available bool
	Reason    Reason
	// Err is set only with ReasonEntitlementUnavailable: the store failure, which the caller answers as an unavailable store and not
	// as a missing entitlement.
	Err error
}

// Gate decides feature availability. The context carries the caller's account (WithAccount) in official-hosted mode.
type Gate interface {
	Availability(ctx context.Context, key Key) Decision
}

type accountKey struct{}

// WithAccount is the context of a call made by an account: the entitlement of that account decides official-hosted availability.
func WithAccount(ctx context.Context, account string) context.Context {
	return context.WithValue(ctx, accountKey{}, account)
}

// AccountFrom is the account of a context.
func AccountFrom(ctx context.Context) (string, bool) {
	account, ok := ctx.Value(accountKey{}).(string)
	return account, ok && account != ""
}
