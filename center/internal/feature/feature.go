// SPDX-License-Identifier: AGPL-3.0-only

// Package feature answers whether a gated feature of the center is available to a caller (ArcForges-Design AD-0021 section 13a). In
// official-hosted mode the answer comes from the plan catalogue and the account's entitlement snapshot (package entitlement); an
// absent or invalid catalogue enables nothing. In self-hosted mode a built-in default enables every self-hostable gated feature,
// minus the keys the operator disabled (ARCFORGES_CENTER_DISABLED_FEATURES) and `push` while no push sender is configured.
// Availability is one more check after authentication, ownership, authorization, AGENT/HUMAN separation, audit and resource controls
// (access.Authorize); it never bypasses them. Essential operations (Hello, health, sign-in, account, billing, security and recovery)
// have no key and are never gated.
package feature

import (
	"context"
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

// IsGated reports whether a key is one of the gated keys.
func IsGated(key Key) bool {
	for _, gated := range Gated() {
		if gated == key {
			return true
		}
	}
	return false
}

// OperationKey is one row of the routed task control table (plan section (g)): the key that gates a group of the center's routed
// operations once AF-CTR-04 and later tasks serve them. The table is the policy; docs/center.md prints it, a test compares the two,
// and the operation table of package access takes its keys from here.
type OperationKey struct {
	Key   Key
	Gates string
}

// OperationKeys is the routed task control table.
func OperationKeys() []OperationKey {
	return []OperationKey{
		{RemoteControl, "control of existing tasks (cancel, retry, priority)"},
		{CenterExecute, "submission, and file and workspace operations"},
		{RemoteView, "status and output"},
		{CenterNodes, "node connection"},
		{CenterMCP, "MCP"},
		{Push, "push"},
	}
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
	// ReasonPushSenderNotConfigured is `push` on a self-hosted center that has no push sender (DC-22).
	ReasonPushSenderNotConfigured Reason = "push_sender_not_configured"
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
