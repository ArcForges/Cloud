// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"math"
	"sort"
)

// Resolve is EntitlementResolver.Resolve: a pure function from immutable grants, revocations, service terms and definitions,
// evaluated at one authoritative instant, to a snapshot with a reason for every entry and a version (BC-04, EN-01 to EN-08).
//
// Determinism is the contract. The function reads no clock, no random source and no store; it iterates only sorted, immutable
// inputs; and the version is itself a function of the inputs: the number of distinct effective changes across every instant at
// which anything the resolver knew could change meaning, up to the evaluated instant. A snapshot is therefore independent of how
// often it was evaluated (RF-04 for entitlement), and a rebuild from the records alone reproduces the stored snapshot exactly,
// version included.
//
// Knowledge time is part of the contract. At each instant only records created, recorded or released at or before it are known, so
// a grant that is issued late with an earlier start does not rewrite what was served before (TM-01), and a late revocation takes
// effect when it is recorded.
//
// An input it cannot interpret is an *InputError; arithmetic that would overflow is ErrOverflow (the C# checked arithmetic).
func Resolve(records RecordSet, definitions Definitions, asOf Micros) (Snapshot, error) {
	if err := Validate(records, definitions); err != nil {
		return Snapshot{}, err
	}
	previous, err := EvaluateAt(records, definitions, MinMicros)
	if err != nil {
		return Snapshot{}, err
	}
	var version int64
	activationsSeen := 0
	current := previous
	for _, point := range points(records, asOf) {
		if current, err = EvaluateAt(records, definitions, point); err != nil {
			return Snapshot{}, err
		}
		if !current.SameEffectAs(previous) {
			version++
		}
		// A definitions activation after the first is itself a change clients must notice (ES-03, BN-02), even when the contents
		// that the current definitions produce happen to be equal: the earlier definitions are not part of the record set.
		activated := 0
		for _, activation := range records.Activations {
			if activation.ActivatedAt <= point {
				activated++
			}
		}
		if activated > activationsSeen {
			if activationsSeen == 0 {
				version += int64(activated - 1)
			} else {
				version += int64(activated - activationsSeen)
			}
			activationsSeen = activated
		}
		previous = current
	}
	return Snapshot{AccountID: records.AccountID, Version: version, ComputedAt: asOf, Content: current}, nil
}

// EvaluateAt evaluates the effective content at one instant using only what was known then. It never fails on validated input
// except for ErrOverflow.
func EvaluateAt(records RecordSet, definitions Definitions, at Micros) (Content, error) {
	var grants []Grant
	for _, grant := range records.Grants {
		if grant.CreatedAt <= at {
			grants = append(grants, grant)
		}
	}
	revocations := map[string]Micros{}
	for _, revocation := range records.Revocations {
		if revocation.CreatedAt > at {
			continue
		}
		if known, seen := revocations[revocation.GrantID]; !seen || revocation.EffectiveFrom < known {
			revocations[revocation.GrantID] = revocation.EffectiveFrom
		}
	}
	service, ignoredTerms, serviceBoundaries := evaluateService(records, definitions, at)
	status := statusAt(records, at)

	capabilityDefinitions := append([]CapabilityDefinition(nil), definitions.Capabilities...)
	sort.SliceStable(capabilityDefinitions, func(i, j int) bool { return capabilityDefinitions[i].Key < capabilityDefinitions[j].Key })
	capabilities := make([]CapabilityResult, 0, len(capabilityDefinitions))
	for _, definition := range capabilityDefinitions {
		valid := validGrants(grants, revocations, KindCapability, definition.Key, at)
		lapsed := hasLapsed(grants, revocations, KindCapability, definition.Key, at)
		ids := make([]string, len(valid))
		for index, grant := range valid {
			ids[index] = grant.GrantID
		}
		reason := capabilityReason(definition, len(valid) > 0, lapsed, service, status, isReleased(records, definition.FeatureGate, at))
		sources := ids
		if reason == ReasonWorkspaceSuspended || reason == ReasonFeatureUnavailable {
			sources = []string{}
		}
		capabilities = append(capabilities, CapabilityResult{Key: definition.Key, Granted: reason == ReasonAvailable, Reason: reason, SourceGrantIDs: sources})
	}

	quotaDefinitions := append([]QuotaDefinition(nil), definitions.Quotas...)
	sort.SliceStable(quotaDefinitions, func(i, j int) bool { return quotaDefinitions[i].Key < quotaDefinitions[j].Key })
	quotas := make([]QuotaResult, 0, len(quotaDefinitions))
	for _, definition := range quotaDefinitions {
		quota, err := resolveQuota(definition, grants, revocations, service, status, at)
		if err != nil {
			return Content{}, err
		}
		quotas = append(quotas, quota)
	}

	allowanceDefinitions := append([]AllowanceDefinition(nil), definitions.Allowances...)
	sort.SliceStable(allowanceDefinitions, func(i, j int) bool { return allowanceDefinitions[i].Key < allowanceDefinitions[j].Key })
	allowances := make([]AllowanceResult, 0, len(allowanceDefinitions))
	for _, definition := range allowanceDefinitions {
		allowances = append(allowances, resolveAllowance(definition, grants, revocations, service, status, at))
	}

	gates := map[string]bool{}
	var gateKeys []string
	for _, definition := range definitions.Capabilities {
		if definition.FeatureGate != nil && !gates[*definition.FeatureGate] {
			gates[*definition.FeatureGate] = true
			gateKeys = append(gateKeys, *definition.FeatureGate)
		}
	}
	sort.Strings(gateKeys)
	features := make([]FeatureResult, 0, len(gateKeys))
	for _, key := range gateKeys {
		if isReleased(records, &key, at) {
			features = append(features, FeatureResult{Key: key, Available: true, Reason: ReasonAvailable})
		} else {
			features = append(features, FeatureResult{Key: key, Available: false, Reason: ReasonFeatureUnavailable})
		}
	}

	recognized := map[string]bool{}
	for _, capability := range definitions.Capabilities {
		recognized[KindCapability.String()+"/"+capability.Key] = true
	}
	for _, quota := range definitions.Quotas {
		recognized[KindQuota.String()+"/"+quota.Key] = true
	}
	for _, allowance := range definitions.Allowances {
		recognized[KindAllowance.String()+"/"+allowance.Key] = true
	}
	unrecognized := []string{}
	for _, grant := range grants {
		if !recognized[grant.Kind.String()+"/"+grant.Subject] {
			unrecognized = append(unrecognized, grant.GrantID)
		}
	}
	sort.Strings(unrecognized)

	validUntil := nextBoundary(records, revocations, serviceBoundaries, at)
	ignored := append([]string{}, ignoredTerms...)
	sort.Strings(ignored)
	return Content{DefinitionsVersion: definitions.Version, Service: service, Capabilities: capabilities, Quotas: quotas, Allowances: allowances,
		Features: features, UnrecognizedGrantIDs: unrecognized, IgnoredTermIDs: ignored, ValidUntil: validUntil}, nil
}

// ---- service state ---------------------------------------------------------------------------------------------------

type run struct {
	start, end Micros
	graceEnd   *Micros
}

type interval struct {
	start, end Micros
	grace      *Micros
}

// statusAt is the newest status fact recorded at or before the instant. Facts recorded at the same instant are decided by the
// total order of moreRestrictive, so the result never depends on the order a store returns them in.
func statusAt(records RecordSet, at Micros) StatusFact {
	var found *StatusFact
	for index := range records.StatusFacts {
		fact := records.StatusFacts[index]
		if fact.RecordedAt > at {
			continue
		}
		if found == nil || fact.RecordedAt > found.RecordedAt || fact.RecordedAt == found.RecordedAt && moreRestrictive(fact, *found) {
			found = &fact
		}
	}
	if found == nil {
		return StatusFact{RecordedAt: MinMicros, Status: StatusNormal, AutoRenew: true, PurchasePending: false}
	}
	return *found
}

// moreRestrictive: the more restrictive status wins, then a cancelled renewal over a continuing one, then no pending purchase over
// a pending one.
func moreRestrictive(candidate, incumbent StatusFact) bool {
	if candidate.Status != incumbent.Status {
		return candidate.Status > incumbent.Status
	}
	if candidate.AutoRenew != incumbent.AutoRenew {
		return !candidate.AutoRenew
	}
	return !candidate.PurchasePending && incumbent.PurchasePending
}

func latest(left, right *Micros) *Micros {
	switch {
	case left == nil:
		return right
	case right == nil:
		return left
	}
	value := maxMicros(*left, *right)
	return &value
}

func evaluateService(records RecordSet, definitions Definitions, at Micros) (ServiceStateResult, []string, []Micros) {
	ignoredTerms := []string{}
	boundaries := []Micros{}
	var intervals []interval
	for _, term := range records.Terms {
		if term.CreatedAt > at {
			continue
		}
		official := term.Kind != TermSelfHostGrant
		if official == definitions.IsSelfHostRealm {
			ignoredTerms = append(ignoredTerms, term.TermID)
			continue
		}
		start := maxMicros(term.StartsAt, term.AuthorizedAt)
		end := term.EndsAt
		for _, action := range records.TermActions {
			if action.TermID == term.TermID && action.RecordedAt <= at {
				end = minMicros(end, action.EffectiveAt)
				boundaries = append(boundaries, action.EffectiveAt)
			}
		}
		boundaries = append(boundaries, start, end)
		if term.GraceEndsAt != nil {
			boundaries = append(boundaries, *term.GraceEndsAt)
		}
		if end > start {
			var grace *Micros
			if end == term.EndsAt {
				grace = term.GraceEndsAt
			}
			intervals = append(intervals, interval{start, end, grace})
		}
	}

	sort.SliceStable(intervals, func(i, j int) bool {
		if intervals[i].start != intervals[j].start {
			return intervals[i].start < intervals[j].start
		}
		return intervals[i].end < intervals[j].end
	})
	var runs []run
	for _, item := range intervals {
		if len(runs) > 0 && item.start <= runs[len(runs)-1].end {
			last := runs[len(runs)-1]
			end := maxMicros(last.end, item.end)
			var grace *Micros
			if last.end == end {
				grace = latest(grace, last.graceEnd)
			}
			if item.end == end {
				grace = latest(grace, item.grace)
			}
			runs[len(runs)-1] = run{last.start, end, grace}
		} else {
			runs = append(runs, run{item.start, item.end, item.grace})
		}
	}

	status := statusAt(records, at)
	var active, past *run
	future := false
	for index := range runs {
		candidate := runs[index]
		switch {
		case candidate.start <= at && at < candidate.end:
			active = &candidate
		case candidate.end <= at:
			past = &candidate
		case candidate.start > at:
			future = true
		}
	}

	current := active
	if current == nil {
		current = past
	}
	var paidThrough, graceEnds *Micros
	if current != nil {
		end := current.end
		paidThrough, graceEnds = &end, current.graceEnd
	}
	eligible := active != nil && status.Status != StatusSuspended
	var state ServiceState
	switch {
	case status.Status == StatusSuspended:
		state = StateSuspended
	case active != nil:
		if status.AutoRenew {
			state = StateActive
		} else {
			state = StateCancelScheduled
		}
	case past != nil:
		if past.graceEnd != nil && at < *past.graceEnd {
			state = StateGrace
		} else {
			state = StateEnded
		}
	case future || status.PurchasePending:
		state = StatePending
	default:
		state = StateNone
	}
	return ServiceStateResult{State: state, PaidThrough: paidThrough, GraceEndsAt: graceEnds, PaidTermActive: eligible}, ignoredTerms, boundaries
}

// ---- grants ----------------------------------------------------------------------------------------------------------

func endOf(grant Grant, revocations map[string]Micros) Micros {
	end := MaxMicros
	if grant.EffectiveUntil != nil {
		end = *grant.EffectiveUntil
	}
	if revoked, ok := revocations[grant.GrantID]; ok {
		return minMicros(end, revoked)
	}
	return end
}

func validGrants(grants []Grant, revocations map[string]Micros, kind GrantKind, subject string, at Micros) []Grant {
	var valid []Grant
	for _, grant := range grants {
		if grant.Kind == kind && grant.Subject == subject && grant.EffectiveFrom <= at && at < endOf(grant, revocations) {
			valid = append(valid, grant)
		}
	}
	sort.SliceStable(valid, func(i, j int) bool { return valid[i].GrantID < valid[j].GrantID })
	return valid
}

// hasLapsed is a grant that ran out by its own end date, was never revoked, and so lapsed with time.
func hasLapsed(grants []Grant, revocations map[string]Micros, kind GrantKind, subject string, at Micros) bool {
	for _, grant := range grants {
		if _, revoked := revocations[grant.GrantID]; grant.Kind == kind && grant.Subject == subject && grant.EffectiveFrom <= at && !revoked &&
			grant.EffectiveUntil != nil && *grant.EffectiveUntil <= at {
			return true
		}
	}
	return false
}

func isReleased(records RecordSet, feature *string, at Micros) bool {
	if feature == nil {
		return true
	}
	for _, release := range records.FeatureReleases {
		if release.Feature == *feature && release.ReleasedAt <= at {
			return true
		}
	}
	return false
}

func stateReason(state ServiceState) Reason {
	switch state {
	case StateGrace:
		return ReasonPaymentGrace
	case StateEnded:
		return ReasonSubscriptionExpired
	case StateSuspended:
		return ReasonWorkspaceSuspended
	}
	return ReasonNoEntitlement
}

func absenceReason(lapsed bool, service ServiceStateResult) Reason {
	if lapsed && (service.State == StateGrace || service.State == StateEnded) {
		return stateReason(service.State)
	}
	return ReasonNoEntitlement
}

// capabilityReason is the combination rule of a capability, explicit and ordered (EN-06): suspension first, then the feature gate,
// then a valid sourced grant, then (for capabilities that require it) restriction and an active paid term. Administrative credit
// alone never enables a paid capability because no grant can stand in for the term.
func capabilityReason(definition CapabilityDefinition, hasValidGrant, lapsed bool, service ServiceStateResult, status StatusFact, released bool) Reason {
	switch {
	case status.Status == StatusSuspended:
		return ReasonWorkspaceSuspended
	case !released:
		return ReasonFeatureUnavailable
	case !hasValidGrant:
		return absenceReason(lapsed, service)
	case !definition.RequiresPaidTerm:
		return ReasonAvailable
	case status.Status == StatusRestricted:
		return ReasonTemporarilyRestricted
	case service.PaidTermActive:
		return ReasonAvailable
	}
	return stateReason(service.State)
}

func resolveQuota(definition QuotaDefinition, grants []Grant, revocations map[string]Micros, service ServiceStateResult, status StatusFact, at Micros) (QuotaResult, error) {
	valid := validGrants(grants, revocations, KindQuota, definition.Key, at)
	contributions := make([]QuotaContribution, len(valid))
	for index, grant := range valid {
		contributions[index] = QuotaContribution{GrantID: grant.GrantID, Source: grant.Source, Amount: grant.Value.(QuotaValue).Limit}
	}
	var limit int64
	switch definition.Combination {
	case CombineSum:
		for _, contribution := range contributions {
			if contribution.Amount > 0 && limit > math.MaxInt64-contribution.Amount || contribution.Amount < 0 && limit < math.MinInt64-contribution.Amount {
				return QuotaResult{}, ErrOverflow
			}
			limit += contribution.Amount
		}
	case CombineMax:
		for _, contribution := range contributions {
			limit = max(limit, contribution.Amount)
		}
	case CombinePriorityReplace:
		var selected *Grant
		for index := range valid {
			candidate := valid[index]
			if selected == nil || candidate.Value.(QuotaValue).Priority > selected.Value.(QuotaValue).Priority {
				selected = &candidate
			}
		}
		if selected != nil {
			limit = selected.Value.(QuotaValue).Limit
		}
	}

	// A suspended account reports no limit and no contributions, like its capabilities, so a consumer that reads the limit alone
	// fails closed. A lapsed term keeps the granted limit on purpose: the data stays readable and downloadable and only new paid
	// writes stop (QU-03), which capability entries and not quota limits express.
	if status.Status == StatusSuspended {
		return QuotaResult{Key: definition.Key, Limit: 0, Reason: ReasonWorkspaceSuspended, Contributions: []QuotaContribution{}}, nil
	}
	reason := ReasonAvailable
	if len(valid) == 0 {
		reason = absenceReason(hasLapsed(grants, revocations, KindQuota, definition.Key, at), service)
	}
	return QuotaResult{Key: definition.Key, Limit: limit, Reason: reason, Contributions: contributions}, nil
}

func resolveAllowance(definition AllowanceDefinition, grants []Grant, revocations map[string]Micros, service ServiceStateResult, status StatusFact, at Micros) AllowanceResult {
	valid := validGrants(grants, revocations, KindAllowance, definition.Key, at)
	sort.SliceStable(valid, func(i, j int) bool {
		left, right := valid[i].Value.(AllowanceValue).Priority, valid[j].Value.(AllowanceValue).Priority
		if left != right {
			return left > right
		}
		return valid[i].GrantID < valid[j].GrantID
	})
	lapsed := hasLapsed(grants, revocations, KindAllowance, definition.Key, at)
	var reason Reason
	switch {
	case status.Status == StatusSuspended:
		reason = ReasonWorkspaceSuspended
	case len(valid) == 0:
		reason = absenceReason(lapsed, service)
	case status.Status == StatusRestricted:
		reason = ReasonTemporarilyRestricted
	case service.PaidTermActive:
		reason = ReasonAvailable
	default:
		reason = stateReason(service.State)
	}
	result := AllowanceResult{Key: definition.Key, Granted: reason == ReasonAvailable, Reason: reason, SupersededGrantIDs: []string{}}
	if len(valid) > 0 {
		plan, selected := valid[0].Value.(AllowanceValue).CapacityPlanRef, valid[0].GrantID
		result.CapacityPlanRef, result.SelectedGrantID = &plan, &selected
		for _, grant := range valid[1:] {
			result.SupersededGrantIDs = append(result.SupersededGrantIDs, grant.GrantID)
		}
		sort.Strings(result.SupersededGrantIDs)
	}
	return result
}

// ---- time boundaries -------------------------------------------------------------------------------------------------

func nextBoundary(records RecordSet, revocations map[string]Micros, serviceBoundaries []Micros, at Micros) *Micros {
	var next *Micros
	consider := func(candidate Micros) {
		if candidate > at && (next == nil || candidate < *next) {
			value := candidate
			next = &value
		}
	}
	for _, grant := range records.Grants {
		if grant.CreatedAt > at {
			continue
		}
		consider(grant.EffectiveFrom)
		if grant.EffectiveUntil != nil {
			consider(*grant.EffectiveUntil)
		}
	}
	for _, effective := range revocations {
		consider(effective)
	}
	for _, boundary := range serviceBoundaries {
		consider(boundary)
	}
	for _, release := range records.FeatureReleases {
		consider(release.ReleasedAt)
	}
	return next
}

// points is every instant up to asOf at which a record becomes known or an effective interval opens or closes, plus asOf itself, in
// ascending order.
func points(records RecordSet, asOf Micros) []Micros {
	set := map[Micros]bool{asOf: true}
	add := func(value Micros) {
		if value <= asOf {
			set[value] = true
		}
	}
	for _, grant := range records.Grants {
		add(grant.CreatedAt)
		add(grant.EffectiveFrom)
		if grant.EffectiveUntil != nil {
			add(*grant.EffectiveUntil)
		}
	}
	for _, revocation := range records.Revocations {
		add(revocation.CreatedAt)
		add(revocation.EffectiveFrom)
	}
	for _, term := range records.Terms {
		add(term.CreatedAt)
		add(term.StartsAt)
		add(term.AuthorizedAt)
		add(term.EndsAt)
		if term.GraceEndsAt != nil {
			add(*term.GraceEndsAt)
		}
	}
	for _, action := range records.TermActions {
		add(action.RecordedAt)
		add(action.EffectiveAt)
	}
	for _, fact := range records.StatusFacts {
		add(fact.RecordedAt)
	}
	for _, release := range records.FeatureReleases {
		add(release.ReleasedAt)
	}
	for _, activation := range records.Activations {
		add(activation.ActivatedAt)
	}
	ordered := make([]Micros, 0, len(set))
	for value := range set {
		ordered = append(ordered, value)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	return ordered
}
