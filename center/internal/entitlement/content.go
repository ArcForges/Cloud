// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"strconv"
	"strings"
)

// Reason is the reason vocabulary of a snapshot entry (ES-02). The resolver assigns every value except QuotaExceeded, which is a
// usage fact owned by quota admission: the snapshot is derived from grants and terms only and never from measured usage. The names
// are the C# enum names, which the canonical text keeps (DC-19).
type Reason int

// The reasons, in the C# declaration order.
const (
	ReasonAvailable Reason = iota
	ReasonNoEntitlement
	ReasonSubscriptionExpired
	ReasonPaymentGrace
	ReasonQuotaExceeded
	ReasonTemporarilyRestricted
	ReasonWorkspaceSuspended
	ReasonFeatureUnavailable
)

var reasonNames = [...]string{"Available", "NoEntitlement", "SubscriptionExpired", "PaymentGrace", "QuotaExceeded", "TemporarilyRestricted",
	"WorkspaceSuspended", "FeatureUnavailable"}

// String is the C# enum name.
func (r Reason) String() string {
	if r >= 0 && int(r) < len(reasonNames) {
		return reasonNames[r]
	}
	return strconv.Itoa(int(r))
}

// ParseReason is the reason of an enum name.
func ParseReason(name string) (Reason, bool) {
	for index, candidate := range reasonNames {
		if candidate == name {
			return Reason(index), true
		}
	}
	return 0, false
}

// ServiceState is the normalised service state, driven by paid-through and never by a provider status string (EN-05, SU-01).
type ServiceState int

// The states, in the C# declaration order.
const (
	StateNone ServiceState = iota
	StatePending
	StateActive
	StateCancelScheduled
	StateGrace
	StateEnded
	StateSuspended
)

var stateNames = [...]string{"None", "Pending", "Active", "CancelScheduled", "Grace", "Ended", "Suspended"}

// String is the C# enum name.
func (s ServiceState) String() string {
	if s >= 0 && int(s) < len(stateNames) {
		return stateNames[s]
	}
	return strconv.Itoa(int(s))
}

// ServiceStateResult is the service state of an evaluation.
type ServiceStateResult struct {
	State          ServiceState
	PaidThrough    *Micros
	GraceEndsAt    *Micros
	PaidTermActive bool
}

// CapabilityResult is the entry of one capability.
type CapabilityResult struct {
	Key            string
	Granted        bool
	Reason         Reason
	SourceGrantIDs []string
}

// QuotaContribution is one grant's share of a quota.
type QuotaContribution struct {
	GrantID string
	Source  GrantSource
	Amount  int64
}

// QuotaResult is the entry of one quota.
type QuotaResult struct {
	Key           string
	Limit         int64
	Reason        Reason
	Contributions []QuotaContribution
}

// AllowanceResult is the entry of one allowance.
type AllowanceResult struct {
	Key                string
	Granted            bool
	Reason             Reason
	CapacityPlanRef    *string
	SelectedGrantID    *string
	SupersededGrantIDs []string
}

// FeatureResult is the entry of one feature gate.
type FeatureResult struct {
	Key       string
	Available bool
	Reason    Reason
}

// Content is the effective entitlement at one instant: everything a client may read, with a reason for every entry. It carries no
// version and no computation time, so two evaluations that mean the same thing compare equal by Canonical.
type Content struct {
	DefinitionsVersion   string
	Service              ServiceStateResult
	Capabilities         []CapabilityResult
	Quotas               []QuotaResult
	Allowances           []AllowanceResult
	Features             []FeatureResult
	UnrecognizedGrantIDs []string
	IgnoredTermIDs       []string
	ValidUntil           *Micros
}

func microsText(value *Micros) string {
	if value == nil {
		return "-"
	}
	return value.String()
}

func flag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func optionalText(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

// Canonical is a stable text of everything effective, excluding ValidUntil, which only says when to look again. It is the C#
// Canonical() text byte for byte, the enum names included.
func (c Content) Canonical() string {
	var text strings.Builder
	text.WriteString("defs=" + c.DefinitionsVersion + "\n")
	text.WriteString("service=" + c.Service.State.String() + "|" + microsText(c.Service.PaidThrough) + "|" + microsText(c.Service.GraceEndsAt) + "|" +
		flag(c.Service.PaidTermActive) + "\n")
	for _, capability := range c.Capabilities {
		text.WriteString("cap=" + capability.Key + "|" + flag(capability.Granted) + "|" + capability.Reason.String() + "|" +
			strings.Join(capability.SourceGrantIDs, ",") + "\n")
	}
	for _, quota := range c.Quotas {
		contributions := make([]string, len(quota.Contributions))
		for index, contribution := range quota.Contributions {
			contributions[index] = contribution.GrantID + ":" + contribution.Source.String() + ":" + strconv.FormatInt(contribution.Amount, 10)
		}
		text.WriteString("quota=" + quota.Key + "|" + strconv.FormatInt(quota.Limit, 10) + "|" + quota.Reason.String() + "|" +
			strings.Join(contributions, ",") + "\n")
	}
	for _, allowance := range c.Allowances {
		text.WriteString("allow=" + allowance.Key + "|" + flag(allowance.Granted) + "|" + allowance.Reason.String() + "|" +
			optionalText(allowance.CapacityPlanRef) + "|" + optionalText(allowance.SelectedGrantID) + "|" + strings.Join(allowance.SupersededGrantIDs, ",") + "\n")
	}
	for _, feature := range c.Features {
		text.WriteString("feature=" + feature.Key + "|" + flag(feature.Available) + "|" + feature.Reason.String() + "\n")
	}
	text.WriteString("unrecognized=" + strings.Join(c.UnrecognizedGrantIDs, ",") + "\n")
	text.WriteString("ignoredTerms=" + strings.Join(c.IgnoredTermIDs, ",") + "\n")
	return text.String()
}

// SameEffectAs compares two contents by their canonical text.
func (c Content) SameEffectAs(other Content) bool { return c.Canonical() == other.Canonical() }

// Snapshot is the stored snapshot (entitlement.snapshot): the content, the monotonically derived version and the instant it was
// computed for.
type Snapshot struct {
	AccountID  string
	Version    int64
	ComputedAt Micros
	Content    Content
}

// ValidUntil is the instant after which the snapshot must be recomputed, or nil when nothing known changes it.
func (s Snapshot) ValidUntil() *Micros { return s.Content.ValidUntil }

// SameAs is full equality, the one a rebuild must satisfy: account, version, computation instant, validity and every entry.
func (s Snapshot) SameAs(other Snapshot) bool {
	return s.AccountID == other.AccountID && s.Version == other.Version && s.ComputedAt == other.ComputedAt &&
		equalMicros(s.Content.ValidUntil, other.Content.ValidUntil) && s.Content.SameEffectAs(other.Content)
}

func equalMicros(left, right *Micros) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
