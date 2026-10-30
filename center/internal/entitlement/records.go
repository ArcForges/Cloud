// SPDX-License-Identifier: AGPL-3.0-only

// Package entitlement is the center's entitlement resolver (AF-CTR-03 part B; ArcForges-Design AD-0021 section 13a): a line-for-line
// Go port of the C# Entitlement module's pure resolver (src/ArcForges.Cloud.Modules.Entitlement/Resolver: EntitlementResolver,
// RecordSetValidator, InputRules, Snapshot.Canonical and GrantAdmission), the PostgreSQL store and service that persist its records
// and snapshots (migration 0003), the plan catalogue's definitions, and the operator grant of the interim operations page.
//
// The pure resolver (this file and rules.go, resolve.go, content.go, admission.go) reads no clock, no store and no randomness and
// iterates only sorted inputs; testdata/csharp-resolver-vectors.json holds every input and output the C# suites reach, recorded by
// the C# test project, and TestResolverParityWithEveryCSharpVector replays them all.
//
// Mapping from the C# model (DC-19): the C# "workspace" is the center's account. Go names say Account (AccountID, the account's
// uuid text), the messages of the resolver's refusals keep the C# wording verbatim (so the parity vectors compare exactly; no message
// ever reaches a client, the service maps them to closed reasons), and the canonical text keeps the C# enum names (WorkspaceSuspended
// stays WorkspaceSuspended). A request that names a workspace stays refused by the identity surface (VALIDATION, meta.workspace_id).
package entitlement

import (
	"strconv"
	"time"
)

// Micros is an instant as whole microseconds since the Unix epoch in UTC, the precision of every instant of the data model. The
// resolver never reads a clock: every instant it handles is a Micros supplied by the single authoritative time source (EN-08).
type Micros int64

// The extremes of Micros, the C# long.MinValue and long.MaxValue.
const (
	MinMicros Micros = -1 << 63
	MaxMicros Micros = 1<<63 - 1
)

// String is the decimal text of the value, the form the canonical text uses.
func (m Micros) String() string { return strconv.FormatInt(int64(m), 10) }

// FromTime is the instant in whole microseconds, floored (an instant before the epoch rounds toward the past, as the C# conversion
// does). The conversion is the caller's: the resolver itself never sees a time.Time.
func FromTime(at time.Time) Micros { return Micros(at.UnixMicro()) }

// Time is the instant as a UTC time.Time.
func (m Micros) Time() time.Time { return time.UnixMicro(int64(m)).UTC() }

func maxMicros(left, right Micros) Micros {
	if left >= right {
		return left
	}
	return right
}

func minMicros(left, right Micros) Micros {
	if left <= right {
		return left
	}
	return right
}

// GrantKind is the grant row kind of the data model. A consumable balance is a commerce ledger projection and is never a grant.
type GrantKind int

// The grant kinds, in the C# declaration order.
const (
	KindCapability GrantKind = iota
	KindQuota
	KindAllowance
)

// String is the C# enum name; an undefined value is its decimal number, as C# prints it.
func (k GrantKind) String() string {
	switch k {
	case KindCapability:
		return "Capability"
	case KindQuota:
		return "Quota"
	case KindAllowance:
		return "Allowance"
	}
	return strconv.Itoa(int(k))
}

// Defined is Enum.IsDefined.
func (k GrantKind) Defined() bool { return k >= KindCapability && k <= KindAllowance }

// GrantSource is the closed grant-source vocabulary (GR-02, EO-04). No provider identifier is part of it.
type GrantSource int

// The grant sources, in the C# declaration order.
const (
	SourceSubscription GrantSource = iota
	SourceCloudPass
	SourceStorageAddOn
	SourcePurchasedCredit
	SourceAdminGrant
	SourceMigration
	SourceCompensation
)

// String is the C# enum name; an undefined value is its decimal number.
func (s GrantSource) String() string {
	switch s {
	case SourceSubscription:
		return "Subscription"
	case SourceCloudPass:
		return "CloudPass"
	case SourceStorageAddOn:
		return "StorageAddOn"
	case SourcePurchasedCredit:
		return "PurchasedCredit"
	case SourceAdminGrant:
		return "AdminGrant"
	case SourceMigration:
		return "Migration"
	case SourceCompensation:
		return "Compensation"
	}
	return strconv.Itoa(int(s))
}

// Defined is Enum.IsDefined.
func (s GrantSource) Defined() bool { return s >= SourceSubscription && s <= SourceCompensation }

// Administrative reports the sources that need a recorded reason (GR-04, GR-05): AdminGrant, Migration and Compensation.
func (s GrantSource) Administrative() bool {
	return s == SourceAdminGrant || s == SourceMigration || s == SourceCompensation
}

// GrantValue is the kind-specific grant payload. A capability grant carries no flag: it can only grant, and loss is a revocation
// (GR-03). The implementations are comparable values (CapabilityValue, QuotaValue, AllowanceValue).
type GrantValue interface{ grantValue() }

// CapabilityValue is the payload of a capability grant.
type CapabilityValue struct{}

// QuotaValue is a quota limit in the quota's own unit. Priority only matters to a priority-replace quota.
type QuotaValue struct{ Limit, Priority int64 }

// AllowanceValue references the one capacity plan an allowance grant selects.
type AllowanceValue struct {
	CapacityPlanRef string
	Priority        int64
}

func (CapabilityValue) grantValue() {}
func (QuotaValue) grantValue()      {}
func (AllowanceValue) grantValue()  {}

// Grant is an immutable grant (entitlement.grant). Nothing about it is ever edited; its end is a revocation or its own end date.
type Grant struct {
	GrantID        string
	AccountID      string
	Kind           GrantKind
	Subject        string
	Value          GrantValue
	Source         GrantSource
	SourceRef      *string
	EffectiveFrom  Micros
	EffectiveUntil *Micros
	IssuedByActor  string
	CreatedAt      Micros
	Reason         *string
}

// Revocation is an immutable revocation (entitlement.revocation) of one exact grant.
type Revocation struct {
	RevocationID  string
	GrantID       string
	ReasonCode    string
	EffectiveFrom Micros
	IssuedByActor string
	CreatedAt     Micros
}

// ServiceTermKind is the kind of a service term.
type ServiceTermKind int

// The term kinds, in the C# declaration order.
const (
	TermSubscription ServiceTermKind = iota
	TermPass
	TermCompensation
	TermSelfHostGrant
)

// String is the C# enum name; an undefined value is its decimal number.
func (k ServiceTermKind) String() string {
	switch k {
	case TermSubscription:
		return "Subscription"
	case TermPass:
		return "Pass"
	case TermCompensation:
		return "Compensation"
	case TermSelfHostGrant:
		return "SelfHostGrant"
	}
	return strconv.Itoa(int(k))
}

// Defined is Enum.IsDefined.
func (k ServiceTermKind) Defined() bool { return k >= TermSubscription && k <= TermSelfHostGrant }

// ServiceTermFact is one row of entitlement.service_term as the resolver reads it: an interval, never a flag (SV-01).
type ServiceTermFact struct {
	TermID       string
	Kind         ServiceTermKind
	StartsAt     Micros
	EndsAt       Micros
	GraceEndsAt  *Micros
	AuthorizedAt Micros
	CreatedAt    Micros
}

// TermActionKind is the kind of a term action.
type TermActionKind int

// The term action kinds, in the C# declaration order.
const (
	ActionSupersede TermActionKind = iota
	ActionRevoke
)

// String is the C# enum name; an undefined value is its decimal number.
func (k TermActionKind) String() string {
	switch k {
	case ActionSupersede:
		return "Supersede"
	case ActionRevoke:
		return "Revoke"
	}
	return strconv.Itoa(int(k))
}

// Defined is Enum.IsDefined.
func (k TermActionKind) Defined() bool { return k >= ActionSupersede && k <= ActionRevoke }

// TermActionFact is an append-only supersede or revoke of a term (TM-04). The original end is never rewritten; the action truncates
// the effective interval.
type TermActionFact struct {
	TermID      string
	Kind        TermActionKind
	EffectiveAt Micros
	RecordedAt  Micros
}

// AccountStatus is the administrative status of an account.
type AccountStatus int

// The statuses, in the C# declaration order.
const (
	StatusNormal AccountStatus = iota
	StatusRestricted
	StatusSuspended
)

// String is the C# enum name; an undefined value is its decimal number.
func (s AccountStatus) String() string {
	switch s {
	case StatusNormal:
		return "Normal"
	case StatusRestricted:
		return "Restricted"
	case StatusSuspended:
		return "Suspended"
	}
	return strconv.Itoa(int(s))
}

// Defined is Enum.IsDefined.
func (s AccountStatus) Defined() bool { return s >= StatusNormal && s <= StatusSuspended }

// StatusFact is an append-only administrative or risk fact about the account. AutoRenew and PurchasePending are two independent
// facts and are never merged into one flag (SU-03). The newest fact recorded at or before the evaluated instant applies.
type StatusFact struct {
	RecordedAt      Micros
	Status          AccountStatus
	AutoRenew       bool
	PurchasePending bool
}

// FeatureReleaseFact is a feature flag release fact: the feature is released from ReleasedAt. A feature without one is not released.
type FeatureReleaseFact struct {
	Feature    string
	ReleasedAt Micros
}

// DefinitionsActivation is the activation of one definitions version for an account. Each activation after the first is a change
// every client must notice (BN-02, ES-03), so it raises the entitlement version. The history of activations is an append-only
// record like every other input, which keeps the version rebuildable from the records alone.
type DefinitionsActivation struct {
	Version     string
	ActivatedAt Micros
}

// RecordSet is everything the resolver reads for one account. All collections are append-only records; the resolver mutates none.
type RecordSet struct {
	AccountID       string
	Grants          []Grant
	Revocations     []Revocation
	Terms           []ServiceTermFact
	TermActions     []TermActionFact
	StatusFacts     []StatusFact
	FeatureReleases []FeatureReleaseFact
	Activations     []DefinitionsActivation
}

// Count is the number of records of every kind.
func (r RecordSet) Count() int {
	return len(r.Grants) + len(r.Revocations) + len(r.Terms) + len(r.TermActions) + len(r.StatusFacts) + len(r.FeatureReleases) + len(r.Activations)
}

// EmptyRecords is the record set of an account with no history.
func EmptyRecords(accountID string) RecordSet { return RecordSet{AccountID: accountID} }

// QuotaCombination is how the grants of one quota combine (requirements section 6.1).
type QuotaCombination int

// The combinations, in the C# declaration order.
const (
	CombineSum QuotaCombination = iota
	CombineMax
	CombinePriorityReplace
)

// Defined is Enum.IsDefined.
func (c QuotaCombination) Defined() bool { return c >= CombineSum && c <= CombinePriorityReplace }

// String is the C# enum name; an undefined value is its decimal number.
func (c QuotaCombination) String() string {
	switch c {
	case CombineSum:
		return "Sum"
	case CombineMax:
		return "Max"
	case CombinePriorityReplace:
		return "PriorityReplace"
	}
	return strconv.Itoa(int(c))
}

// CapabilityDefinition is a capability the resolver may grant. Which capabilities need an active paid term is data, never code
// (BN-01).
type CapabilityDefinition struct {
	Key              string
	RequiresPaidTerm bool
	FeatureGate      *string
}

// QuotaDefinition is a quota the resolver may grant.
type QuotaDefinition struct {
	Key         string
	Combination QuotaCombination
}

// AllowanceDefinition is an allowance subject. An allowance always requires an active paid term: included capacity only recovers
// during eligible service.
type AllowanceDefinition struct{ Key string }

// Definitions is the versioned definition set the resolver evaluates against (a bundle version, BN-02). IsSelfHostRealm decides
// which term kinds count: an official realm ignores a self-host service grant and a self-host realm ignores every official term
// (SV-04).
type Definitions struct {
	Version         string
	Capabilities    []CapabilityDefinition
	Quotas          []QuotaDefinition
	Allowances      []AllowanceDefinition
	IsSelfHostRealm bool
}
