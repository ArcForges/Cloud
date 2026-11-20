// SPDX-License-Identifier: AGPL-3.0-only

package entitlement

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/ArcForges/Cloud/center/internal/platform"
	"github.com/ArcForges/Cloud/center/internal/store"
)

var (
	// ErrCommerceDefinitions means the exact hosted definitions are unavailable to this process.
	ErrCommerceDefinitions = errors.New("commerce: hosted entitlement definitions are unavailable")
	// ErrCommerceFact means the verified input cannot be joined to an unambiguous immutable entitlement history.
	ErrCommerceFact = errors.New("commerce: entitlement fact is invalid or conflicts with its original binding")
)

const commerceActor = "service:commerce"

// These are the three hosted V2 capabilities in stable grant order. Historical catalogue keys never enter a purchase.
var hostedServiceKeys = [...]string{"center.nodes", "remote.view", "remote.control"}

// CommerceChange carries admitted provider facts. The commerce caller owns signature, ordering, receipt and offer verification.
type CommerceChange struct {
	AccountID          string
	DefinitionsVersion string
	EventRef           string
	NewTerm            *CommerceTerm
	EndTerms           []CommerceTermEnd
	AutoRenew          *bool
	PurchasePending    *bool
}

// CommerceTerm is a verified paid period. A grace deadline records remediation time and does not extend the paid window.
type CommerceTerm struct {
	SubscriptionRef string
	PeriodRef       string
	StartsAt        Micros
	EndsAt          Micros
	GraceEndsAt     *Micros
	Features        []string
}

// CommerceTermEnd shortens one exact period and its own capability grants. Supersede requires its verified replacement term.
type CommerceTermEnd struct {
	TermID      string
	GrantIDs    []string
	EffectiveAt Micros
	Supersede   bool
}

// CommerceResult identifies the original or new period. GrantIDs use hosted service order.
type CommerceResult struct {
	TermID   string
	GrantIDs []string
	Version  int64
	Changed  bool
}

// ApplyCommerce records entitlement effects in a caller's event transaction. The caller commits the receipt, billing projection
// and outbox with these effects or rolls the whole transaction back on any error.
func (s *Service) ApplyCommerce(ctx context.Context, tx pgx.Tx, change CommerceChange) (CommerceResult, error) {
	if !validAccount(change.AccountID) || !IsOpaqueReference(change.EventRef) || len(change.EndTerms) > MaxRecords {
		return CommerceResult{}, ErrCommerceFact
	}
	definitions := s.definitions.Current()
	if !acceptsCommerceDefinitions(definitions, change.DefinitionsVersion) {
		return CommerceResult{}, ErrCommerceDefinitions
	}
	var revision int64
	err := tx.QueryRow(ctx, "SELECT rev FROM entitlement.revision WHERE account_id = $1::uuid FOR UPDATE", change.AccountID).Scan(&revision)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return CommerceResult{}, store.Sanitize("lock the commerce entitlement revision", err)
	}
	state, err := Load(ctx, tx, change.AccountID)
	if err != nil {
		return CommerceResult{}, err
	}
	if state.CurrentDefinitions != definitions.Version {
		return CommerceResult{}, ErrDefinitionsSuperseded
	}
	at, err := WriteInstant(state, s.clock())
	if err != nil {
		return CommerceResult{}, err
	}
	records := state.Records
	var result CommerceResult
	var add Append
	if change.NewTerm != nil {
		result.TermID, result.GrantIDs, err = s.commerceTerm(ctx, tx, &add, records, change.AccountID, *change.NewTerm, at)
		if err != nil {
			return CommerceResult{}, err
		}
	}
	seen := make(map[string]bool, len(change.EndTerms))
	for _, ending := range change.EndTerms {
		if seen[ending.TermID] {
			return CommerceResult{}, ErrCommerceFact
		}
		seen[ending.TermID] = true
		if err = s.endCommerceTerm(ctx, tx, &add, records, change, ending, result.TermID, at); err != nil {
			return CommerceResult{}, err
		}
	}
	s.commerceStatus(&add, records, change, at)
	if len(add.Terms)+len(add.TermActions)+len(add.StatusFacts)+len(add.Revocations) == 0 {
		if state.Snapshot != nil {
			result.Version = state.Snapshot.Version
		}
		return result, nil
	}
	records, add.Activations = withActivation(records, definitions, at)
	records.Grants = append(records.Grants, add.Grants...)
	records.Revocations = append(records.Revocations, add.Revocations...)
	for _, term := range add.Terms {
		records.Terms = append(records.Terms, term.Fact)
	}
	for _, action := range add.TermActions {
		records.TermActions = append(records.TermActions, action.Fact)
	}
	for _, status := range add.StatusFacts {
		records.StatusFacts = append(records.StatusFacts, status.Fact)
	}
	snapshot, err := seal(state, records, definitions, at)
	if err != nil {
		return CommerceResult{}, err
	}
	outcome, err := Commit(ctx, tx, change.AccountID, state.Revision, add, snapshot, at.Time())
	if err != nil {
		return CommerceResult{}, err
	}
	if outcome != Committed {
		return CommerceResult{}, &store.Error{Operation: "append verified commerce entitlement facts", Kind: store.ErrContention}
	}
	result.Version, result.Changed = snapshot.Version, true
	if err = appendCommerceAudit(ctx, tx, change, add, result, at); err != nil {
		return CommerceResult{}, err
	}
	return result, nil
}

func acceptsCommerceDefinitions(definitions Definitions, requested string) bool {
	if definitions.IsSelfHostRealm || !IsOpaqueReference(requested) || definitions.Version != requested {
		return false
	}
	for _, key := range hostedServiceKeys {
		if !slices.ContainsFunc(definitions.Capabilities, func(capability CapabilityDefinition) bool {
			return capability.Key == key && capability.RequiresPaidTerm && capability.FeatureGate == nil
		}) {
			return false
		}
	}
	return true
}

func (s *Service) commerceTerm(ctx context.Context, tx pgx.Tx, add *Append, records RecordSet, account string, term CommerceTerm, at Micros) (string, []string, error) {
	if !IsOpaqueReference(term.SubscriptionRef) || !IsOpaqueReference(term.PeriodRef) ||
		term.EndsAt <= term.StartsAt || term.GraceEndsAt != nil && *term.GraceEndsAt < term.EndsAt ||
		!isSetOfHostedFeatures(term.Features) {
		return "", nil, ErrCommerceFact
	}
	var originalID, originalSubscription string
	err := tx.QueryRow(ctx, `SELECT term_id::text, subscription_ref FROM entitlement.service_term
WHERE account_id = $1::uuid AND kind = 1 AND period_ref = $2`, account, term.PeriodRef).Scan(&originalID, &originalSubscription)
	switch {
	case err == nil:
		original, found := commerceTermFact(records, originalID)
		if originalSubscription != term.SubscriptionRef || !found || original.StartsAt != term.StartsAt || original.EndsAt != term.EndsAt ||
			!equalMicros(original.GraceEndsAt, term.GraceEndsAt) {
			return "", nil, ErrCommerceFact
		}
		grantIDs, err := commerceGrantIDs(records, original, term.SubscriptionRef, term.PeriodRef)
		return originalID, grantIDs, err
	case !errors.Is(err, pgx.ErrNoRows):
		return "", nil, store.Sanitize("read the original commerce entitlement period", err)
	}
	newTerm := ServiceTermFact{TermID: s.ids.NewID(), Kind: TermSubscription, StartsAt: term.StartsAt, EndsAt: term.EndsAt,
		GraceEndsAt: term.GraceEndsAt, AuthorizedAt: at, CreatedAt: at}
	add.Terms = append(add.Terms, TermRow{Fact: newTerm, SubscriptionRef: &term.SubscriptionRef, PeriodRef: term.PeriodRef})
	grantIDs := make([]string, 0, len(hostedServiceKeys))
	for _, key := range hostedServiceKeys {
		ref := commerceReference("grant", term.SubscriptionRef, term.PeriodRef, key)
		grant := Grant{GrantID: s.ids.NewID(), AccountID: account, Kind: KindCapability, Subject: key, Value: CapabilityValue{},
			Source: SourceSubscription, SourceRef: &ref, EffectiveFrom: term.StartsAt, EffectiveUntil: &term.EndsAt, IssuedByActor: commerceActor, CreatedAt: at}
		add.Grants = append(add.Grants, grant)
		grantIDs = append(grantIDs, grant.GrantID)
	}
	return newTerm.TermID, grantIDs, nil
}

func isSetOfHostedFeatures(features []string) bool {
	if len(features) != len(hostedServiceKeys) {
		return false
	}
	for _, key := range hostedServiceKeys {
		if !slices.Contains(features, key) {
			return false
		}
	}
	return true
}

func (s *Service) endCommerceTerm(ctx context.Context, tx pgx.Tx, add *Append, records RecordSet, change CommerceChange, ending CommerceTermEnd, newTermID string, at Micros) error {
	if !validAccount(ending.TermID) || len(ending.GrantIDs) != len(hostedServiceKeys) || ending.EffectiveAt > at {
		return ErrCommerceFact
	}
	original, found := commerceTermFact(records, ending.TermID)
	if !found {
		return ErrCommerceFact
	}
	var subscription, period string
	err := tx.QueryRow(ctx, `SELECT subscription_ref, period_ref FROM entitlement.service_term
WHERE term_id = $1::uuid AND account_id = $2::uuid AND kind = 1`, ending.TermID, change.AccountID).Scan(&subscription, &period)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrCommerceFact
	}
	if err != nil {
		return store.Sanitize("read the bound commerce entitlement period", err)
	}
	originalGrants, err := commerceGrantIDs(records, original, subscription, period)
	if err != nil {
		return err
	}
	for _, grantID := range originalGrants {
		if !slices.Contains(ending.GrantIDs, grantID) {
			return ErrCommerceFact
		}
	}
	kind := ActionRevoke
	var replacement *string
	if ending.Supersede {
		if newTermID == "" || newTermID == ending.TermID || change.NewTerm.SubscriptionRef != subscription {
			return ErrCommerceFact
		}
		kind, replacement = ActionSupersede, &newTermID
	}
	cutoff := minMicros(ending.EffectiveAt, original.EndsAt)
	existingEnd := original.EndsAt
	for _, action := range records.TermActions {
		if action.TermID == original.TermID {
			existingEnd = minMicros(existingEnd, action.EffectiveAt)
		}
	}
	if cutoff < existingEnd {
		add.TermActions = append(add.TermActions, TermActionRow{
			Fact:     TermActionFact{TermID: original.TermID, Kind: kind, EffectiveAt: cutoff, RecordedAt: at},
			ActionID: s.ids.NewID(), SourceRef: commerceReference("action", change.AccountID, change.EventRef, original.TermID), ReplacementTermID: replacement,
		})
	}
	for _, grantID := range originalGrants {
		grantEnd := original.EndsAt
		for _, revocation := range records.Revocations {
			if revocation.GrantID == grantID {
				grantEnd = minMicros(grantEnd, revocation.EffectiveFrom)
			}
		}
		if cutoff < grantEnd {
			add.Revocations = append(add.Revocations, Revocation{RevocationID: s.ids.NewID(), GrantID: grantID, ReasonCode: "commerce_period_ended",
				EffectiveFrom: cutoff, IssuedByActor: commerceActor, CreatedAt: at})
		}
	}
	return nil
}

func commerceTermFact(records RecordSet, termID string) (ServiceTermFact, bool) {
	index := slices.IndexFunc(records.Terms, func(term ServiceTermFact) bool { return term.TermID == termID && term.Kind == TermSubscription })
	if index < 0 {
		return ServiceTermFact{}, false
	}
	return records.Terms[index], true
}

func commerceGrantIDs(records RecordSet, term ServiceTermFact, subscription, period string) ([]string, error) {
	ids := make([]string, 0, len(hostedServiceKeys))
	for _, key := range hostedServiceKeys {
		ref := commerceReference("grant", subscription, period, key)
		index := slices.IndexFunc(records.Grants, func(grant Grant) bool {
			return grant.Kind == KindCapability && grant.Source == SourceSubscription && grant.Subject == key &&
				grant.IssuedByActor == commerceActor && grant.SourceRef != nil && *grant.SourceRef == ref &&
				grant.EffectiveFrom == term.StartsAt && grant.EffectiveUntil != nil && *grant.EffectiveUntil == term.EndsAt && grant.CreatedAt == term.CreatedAt
		})
		if index < 0 {
			return nil, ErrCommerceFact
		}
		ids = append(ids, records.Grants[index].GrantID)
	}
	return ids, nil
}

func (s *Service) commerceStatus(add *Append, records RecordSet, change CommerceChange, at Micros) {
	previous := statusAt(records, at)
	status := previous
	if change.AutoRenew != nil {
		status.AutoRenew = *change.AutoRenew
	}
	if change.PurchasePending != nil {
		status.PurchasePending = *change.PurchasePending
	}
	if status != previous {
		status.RecordedAt = at
		add.StatusFacts = append(add.StatusFacts, StatusRow{Fact: status, StatusFactID: s.ids.NewID(),
			SourceRef: commerceReference("status", change.AccountID, change.EventRef)})
	}
}

func commerceReference(kind string, fields ...string) string {
	// Every component was checked against the opaque-reference grammar or is a generated UUID/key, so the separator is unambiguous.
	return "commerce:" + kind + ":" + digestOf(strings.Join(fields, "\x00"))
}

func appendCommerceAudit(ctx context.Context, tx pgx.Tx, change CommerceChange, add Append, result CommerceResult, at Micros) error {
	ended := make([]string, 0, len(add.TermActions))
	for _, action := range add.TermActions {
		ended = append(ended, action.Fact.TermID)
	}
	payload, err := json.Marshal(map[string]any{
		"eventDigest": digestOf(change.EventRef), "termId": result.TermID, "endedTermIds": ended,
		"entitlementVersion": result.Version, "definitionsVersion": change.DefinitionsVersion,
		"terms": len(add.Terms), "grants": len(add.Grants), "revocations": len(add.Revocations), "statusFacts": len(add.StatusFacts),
	})
	if err != nil {
		return err
	}
	_, err = platform.AppendAudit(ctx, tx, platform.Event{EventID: platform.NewID(), ActorRef: commerceActor, OccurredAt: at.Time(),
		EventType: "entitlement.commerce.applied", TargetKind: "account", TargetID: change.AccountID, Payload: payload})
	return err
}
