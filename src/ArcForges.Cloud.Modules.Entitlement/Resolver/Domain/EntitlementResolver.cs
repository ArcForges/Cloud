// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

/// <summary>
/// The entitlement resolver: a pure function from immutable grants, revocations, service terms and definitions, evaluated at one
/// authoritative instant, to a snapshot with a reason for every entry and a version (BC-04, EN-01 to EN-08).
/// <para>
/// Determinism is the contract. The function reads no clock, no random source and no store; it iterates only sorted, immutable
/// inputs; and the version is itself a function of the inputs: the number of distinct effective changes across every instant at which
/// anything the resolver knew could change meaning, up to the evaluated instant. A snapshot is therefore independent of how often it
/// was evaluated (RF-04 for entitlement), and a rebuild from the records alone reproduces the stored snapshot exactly, version included.
/// </para>
/// <para>
/// Knowledge time is part of the contract. At each instant only records created, recorded or released at or before it are known, so a
/// grant that is issued late with an earlier start does not rewrite what was served before (TM-01), and a late revocation takes
/// effect when it is recorded.
/// </para>
/// </summary>
internal static class EntitlementResolver
{
    private static readonly UtcMicros NothingIsKnown = new(long.MinValue);

    /// <summary>Resolves the snapshot of the record set at <paramref name="asOf"/>. Throws <see cref="ResolverInputException"/> for any input it cannot interpret.</summary>
    public static EntitlementSnapshot Resolve(EntitlementRecordSet records, EntitlementDefinitions definitions, UtcMicros asOf)
    {
        RecordSetValidator.Validate(records, definitions);
        var previous = EvaluateAt(records, definitions, NothingIsKnown);
        long version = 0;
        var activationsSeen = 0;
        EntitlementContent current = previous;
        foreach (var point in Points(records, asOf))
        {
            current = EvaluateAt(records, definitions, point);
            if (!current.SameEffectAs(previous)) version++;

            // A definitions activation after the first is itself a change clients must notice (ES-03, BN-02), even when the contents
            // that the current definitions produce happen to be equal: the earlier definitions are not part of the record set.
            var activated = records.Activations.Count(activation => activation.ActivatedAt <= point);
            if (activated > activationsSeen)
            {
                version += activationsSeen == 0 ? activated - 1 : activated - activationsSeen;
                activationsSeen = activated;
            }

            previous = current;
        }

        return new EntitlementSnapshot(records.WorkspaceId, version, asOf, current);
    }

    /// <summary>Evaluates the effective content at one instant using only what was known then. It never throws for validated input.</summary>
    internal static EntitlementContent EvaluateAt(EntitlementRecordSet records, EntitlementDefinitions definitions, UtcMicros at)
    {
        var grants = records.Grants.Where(grant => grant.CreatedAt <= at).ToImmutableArray();
        var revocations = records.Revocations.Where(revocation => revocation.CreatedAt <= at)
            .GroupBy(revocation => revocation.GrantId, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Min(revocation => revocation.EffectiveFrom), StringComparer.Ordinal);
        var service = EvaluateService(records, definitions, at, out var ignoredTerms, out var serviceBoundaries);
        var state = service.State;

        var capabilities = definitions.Capabilities.OrderBy(definition => definition.Key, StringComparer.Ordinal).Select(definition =>
        {
            var valid = ValidGrants(grants, revocations, GrantKind.Capability, definition.Key, at);
            var lapsed = HasLapsed(grants, revocations, GrantKind.Capability, definition.Key, at);
            var ids = valid.Select(grant => grant.GrantId).ToImmutableArray();
            var reason = CapabilityReason(definition, valid.Length > 0, lapsed, service, StatusAt(records, at), IsReleased(records, definition.FeatureGate, at));
            return new CapabilityResult(definition.Key, reason == EntitlementReason.Available,
                reason, reason is EntitlementReason.WorkspaceSuspended or EntitlementReason.FeatureUnavailable ? [] : ids);
        }).ToImmutableArray();

        var quotas = definitions.Quotas.OrderBy(definition => definition.Key, StringComparer.Ordinal)
            .Select(definition => ResolveQuota(definition, grants, revocations, service, StatusAt(records, at), at)).ToImmutableArray();

        var allowances = definitions.Allowances.OrderBy(definition => definition.Key, StringComparer.Ordinal)
            .Select(definition => ResolveAllowance(definition, grants, revocations, service, StatusAt(records, at), at)).ToImmutableArray();

        var features = definitions.Capabilities.Where(definition => definition.FeatureGate is not null)
            .Select(definition => definition.FeatureGate!).Distinct(StringComparer.Ordinal).OrderBy(key => key, StringComparer.Ordinal)
            .Select(key => IsReleased(records, key, at) ? new FeatureResult(key, true, EntitlementReason.Available) : new FeatureResult(key, false, EntitlementReason.FeatureUnavailable))
            .ToImmutableArray();

        var recognized = new HashSet<string>(StringComparer.Ordinal);
        foreach (var capability in definitions.Capabilities) recognized.Add(GrantKind.Capability + "/" + capability.Key);
        foreach (var quota in definitions.Quotas) recognized.Add(GrantKind.Quota + "/" + quota.Key);
        foreach (var allowance in definitions.Allowances) recognized.Add(GrantKind.Allowance + "/" + allowance.Key);
        var unrecognized = grants.Where(grant => !recognized.Contains(grant.Kind + "/" + grant.Subject))
            .Select(grant => grant.GrantId).OrderBy(id => id, StringComparer.Ordinal).ToImmutableArray();

        var validUntil = NextBoundary(records, revocations, serviceBoundaries, at);
        return new EntitlementContent(definitions.Version, service, capabilities, quotas, allowances, features, unrecognized,
            ignoredTerms.OrderBy(id => id, StringComparer.Ordinal).ToImmutableArray(), validUntil);
    }

    // ---- service state ---------------------------------------------------------------------------------------------------

    private readonly record struct Run(UtcMicros Start, UtcMicros End, UtcMicros? GraceEnd);

    private static WorkspaceStatusFact StatusAt(EntitlementRecordSet records, UtcMicros at)
    {
        WorkspaceStatusFact? found = null;
        foreach (var fact in records.StatusFacts)
        {
            if (fact.RecordedAt > at) continue;
            if (found is null || fact.RecordedAt > found.RecordedAt || (fact.RecordedAt == found.RecordedAt && MoreRestrictive(fact, found))) found = fact;
        }

        return found ?? new WorkspaceStatusFact(NothingIsKnown, WorkspaceStatus.Normal, AutoRenew: true, PurchasePending: false);
    }

    /// <summary>
    /// The total order that decides facts recorded at the same instant, so the result never depends on the order a store returns them in:
    /// the more restrictive status wins, then a cancelled renewal over a continuing one, then no pending purchase over a pending one.
    /// </summary>
    private static bool MoreRestrictive(WorkspaceStatusFact candidate, WorkspaceStatusFact incumbent)
    {
        if (candidate.Status != incumbent.Status) return candidate.Status > incumbent.Status;
        if (candidate.AutoRenew != incumbent.AutoRenew) return !candidate.AutoRenew;
        return !candidate.PurchasePending && incumbent.PurchasePending;
    }

    private static ServiceStateResult EvaluateService(
        EntitlementRecordSet records, EntitlementDefinitions definitions, UtcMicros at,
        out List<string> ignoredTerms, out List<UtcMicros> boundaries)
    {
        ignoredTerms = [];
        boundaries = [];
        var intervals = new List<(UtcMicros Start, UtcMicros End, UtcMicros? Grace)>();
        foreach (var term in records.Terms.Where(term => term.CreatedAt <= at))
        {
            var official = term.Kind != ServiceTermKind.SelfHostGrant;
            if (official == definitions.IsSelfHostRealm)
            {
                ignoredTerms.Add(term.TermId);
                continue;
            }

            var start = UtcMicros.Max(term.StartsAt, term.AuthorizedAt);
            var end = term.EndsAt;
            foreach (var action in records.TermActions.Where(action => action.TermId == term.TermId && action.RecordedAt <= at))
            {
                end = UtcMicros.Min(end, action.EffectiveAt);
                boundaries.Add(action.EffectiveAt);
            }

            boundaries.Add(start);
            boundaries.Add(end);
            if (term.GraceEndsAt is { } graceBoundary) boundaries.Add(graceBoundary);
            if (end > start) intervals.Add((start, end, end == term.EndsAt ? term.GraceEndsAt : null));
        }

        var runs = new List<Run>();
        foreach (var interval in intervals.OrderBy(interval => interval.Start).ThenBy(interval => interval.End))
        {
            if (runs.Count > 0 && interval.Start <= runs[^1].End)
            {
                var last = runs[^1];
                var end = UtcMicros.Max(last.End, interval.End);
                UtcMicros? grace = null;
                if (last.End == end) grace = Latest(grace, last.GraceEnd);
                if (interval.End == end) grace = Latest(grace, interval.Grace);
                runs[^1] = new Run(last.Start, end, grace);
            }
            else
            {
                runs.Add(new Run(interval.Start, interval.End, interval.Grace));
            }
        }

        var status = StatusAt(records, at);
        Run? active = null;
        Run? past = null;
        var future = false;
        foreach (var run in runs)
        {
            if (run.Start <= at && at < run.End) active = run;
            else if (run.End <= at) past = run;
            else if (run.Start > at) future = true;
        }

        var current = active ?? past;
        var paidThrough = current?.End;
        var graceEnds = current?.GraceEnd;
        var eligible = active is not null && status.Status != WorkspaceStatus.Suspended;
        ServiceState state;
        if (status.Status == WorkspaceStatus.Suspended) state = ServiceState.Suspended;
        else if (active is not null) state = status.AutoRenew ? ServiceState.Active : ServiceState.CancelScheduled;
        else if (past is { } ended) state = ended.GraceEnd is { } graceEnd && at < graceEnd ? ServiceState.Grace : ServiceState.Ended;
        else state = future || status.PurchasePending ? ServiceState.Pending : ServiceState.None;
        return new ServiceStateResult(state, paidThrough, graceEnds, eligible);
    }

    private static UtcMicros? Latest(UtcMicros? left, UtcMicros? right) =>
        left is null ? right : right is null ? left : UtcMicros.Max(left.Value, right.Value);

    // ---- grants ----------------------------------------------------------------------------------------------------------

    private static UtcMicros EndOf(Grant grant, Dictionary<string, UtcMicros> revocations)
    {
        var end = grant.EffectiveUntil ?? new UtcMicros(long.MaxValue);
        return revocations.TryGetValue(grant.GrantId, out var revoked) ? UtcMicros.Min(end, revoked) : end;
    }

    private static ImmutableArray<Grant> ValidGrants(
        ImmutableArray<Grant> grants, Dictionary<string, UtcMicros> revocations, GrantKind kind, string subject, UtcMicros at) =>
        grants.Where(grant => grant.Kind == kind && grant.Subject == subject && grant.EffectiveFrom <= at && at < EndOf(grant, revocations))
            .OrderBy(grant => grant.GrantId, StringComparer.Ordinal).ToImmutableArray();

    /// <summary>A grant that ran out by its own end date, was never revoked, and so lapsed with time.</summary>
    private static bool HasLapsed(
        ImmutableArray<Grant> grants, Dictionary<string, UtcMicros> revocations, GrantKind kind, string subject, UtcMicros at) =>
        grants.Any(grant => grant.Kind == kind && grant.Subject == subject && grant.EffectiveFrom <= at
            && !revocations.ContainsKey(grant.GrantId) && grant.EffectiveUntil is { } until && until <= at);

    private static bool IsReleased(EntitlementRecordSet records, string? feature, UtcMicros at) =>
        feature is null || records.FeatureReleases.Any(release => release.Feature == feature && release.ReleasedAt <= at);

    private static EntitlementReason StateReason(ServiceState state) => state switch
    {
        ServiceState.Grace => EntitlementReason.PaymentGrace,
        ServiceState.Ended => EntitlementReason.SubscriptionExpired,
        ServiceState.Suspended => EntitlementReason.WorkspaceSuspended,
        _ => EntitlementReason.NoEntitlement,
    };

    private static EntitlementReason AbsenceReason(bool lapsed, ServiceStateResult service) =>
        lapsed && service.State is ServiceState.Grace or ServiceState.Ended ? StateReason(service.State) : EntitlementReason.NoEntitlement;

    /// <summary>
    /// The combination rule of a capability, explicit and ordered (EN-06): suspension first, then the feature gate, then a valid
    /// sourced grant, then (for capabilities that require it) restriction and an active paid term. Administrative credit alone never
    /// enables a paid capability because no grant can stand in for the term.
    /// </summary>
    private static EntitlementReason CapabilityReason(
        CapabilityDefinition definition, bool hasValidGrant, bool lapsed, ServiceStateResult service, WorkspaceStatusFact status, bool released)
    {
        if (status.Status == WorkspaceStatus.Suspended) return EntitlementReason.WorkspaceSuspended;
        if (!released) return EntitlementReason.FeatureUnavailable;
        if (!hasValidGrant) return AbsenceReason(lapsed, service);
        if (!definition.RequiresPaidTerm) return EntitlementReason.Available;
        if (status.Status == WorkspaceStatus.Restricted) return EntitlementReason.TemporarilyRestricted;
        return service.PaidTermActive ? EntitlementReason.Available : StateReason(service.State);
    }

    private static QuotaResult ResolveQuota(
        QuotaDefinition definition, ImmutableArray<Grant> grants, Dictionary<string, UtcMicros> revocations,
        ServiceStateResult service, WorkspaceStatusFact status, UtcMicros at)
    {
        var valid = ValidGrants(grants, revocations, GrantKind.Quota, definition.Key, at);
        var contributions = valid.Select(grant => new QuotaContribution(grant.GrantId, grant.Source, ((QuotaValue)grant.Value).Limit)).ToImmutableArray();
        long limit = 0;
        switch (definition.Combination)
        {
            case QuotaCombination.Sum:
                foreach (var contribution in contributions) limit = checked(limit + contribution.Amount);
                break;
            case QuotaCombination.Max:
                foreach (var contribution in contributions) limit = Math.Max(limit, contribution.Amount);
                break;
            case QuotaCombination.PriorityReplace:
                var selected = valid.OrderByDescending(grant => ((QuotaValue)grant.Value).Priority).ThenBy(grant => grant.GrantId, StringComparer.Ordinal).FirstOrDefault();
                limit = selected is null ? 0 : ((QuotaValue)selected.Value).Limit;
                break;
        }

        // A suspended workspace reports no limit and no contributions, like its capabilities, so a consumer that reads the limit alone
        // fails closed. A lapsed term keeps the granted limit on purpose: the data stays readable and downloadable and only new
        // paid writes stop (QU-03), which capability entries and not quota limits express.
        if (status.Status == WorkspaceStatus.Suspended) return new QuotaResult(definition.Key, 0, EntitlementReason.WorkspaceSuspended, []);
        var reason = valid.Length > 0 ? EntitlementReason.Available
            : AbsenceReason(HasLapsed(grants, revocations, GrantKind.Quota, definition.Key, at), service);
        return new QuotaResult(definition.Key, limit, reason, contributions);
    }

    private static AllowanceResult ResolveAllowance(
        AllowanceDefinition definition, ImmutableArray<Grant> grants, Dictionary<string, UtcMicros> revocations,
        ServiceStateResult service, WorkspaceStatusFact status, UtcMicros at)
    {
        var valid = ValidGrants(grants, revocations, GrantKind.Allowance, definition.Key, at)
            .OrderByDescending(grant => ((AllowanceValue)grant.Value).Priority).ThenBy(grant => grant.GrantId, StringComparer.Ordinal).ToImmutableArray();
        var lapsed = HasLapsed(grants, revocations, GrantKind.Allowance, definition.Key, at);
        var reason = status.Status == WorkspaceStatus.Suspended ? EntitlementReason.WorkspaceSuspended
            : valid.Length == 0 ? AbsenceReason(lapsed, service)
            : status.Status == WorkspaceStatus.Restricted ? EntitlementReason.TemporarilyRestricted
            : service.PaidTermActive ? EntitlementReason.Available
            : StateReason(service.State);
        var selected = valid.Length > 0 ? valid[0] : null;
        return new AllowanceResult(definition.Key, reason == EntitlementReason.Available, reason,
            selected is null ? null : ((AllowanceValue)selected.Value).CapacityPlanRef, selected?.GrantId,
            valid.Skip(1).Select(grant => grant.GrantId).OrderBy(id => id, StringComparer.Ordinal).ToImmutableArray());
    }

    // ---- time boundaries -------------------------------------------------------------------------------------------------

    private static UtcMicros? NextBoundary(
        EntitlementRecordSet records, Dictionary<string, UtcMicros> revocations, List<UtcMicros> serviceBoundaries, UtcMicros at)
    {
        UtcMicros? next = null;
        void Consider(UtcMicros candidate)
        {
            if (candidate > at && (next is null || candidate < next.Value)) next = candidate;
        }

        foreach (var grant in records.Grants.Where(grant => grant.CreatedAt <= at))
        {
            Consider(grant.EffectiveFrom);
            if (grant.EffectiveUntil is { } until) Consider(until);
        }

        foreach (var effective in revocations.Values) Consider(effective);
        foreach (var boundary in serviceBoundaries) Consider(boundary);
        foreach (var release in records.FeatureReleases) Consider(release.ReleasedAt);
        return next;
    }

    /// <summary>Every instant up to <paramref name="asOf"/> at which a record becomes known or an effective interval opens or closes, plus <paramref name="asOf"/> itself.</summary>
    private static SortedSet<UtcMicros> Points(EntitlementRecordSet records, UtcMicros asOf)
    {
        var points = new SortedSet<UtcMicros> { asOf };
        void Add(UtcMicros value)
        {
            if (value <= asOf) points.Add(value);
        }

        foreach (var grant in records.Grants)
        {
            Add(grant.CreatedAt);
            Add(grant.EffectiveFrom);
            if (grant.EffectiveUntil is { } until) Add(until);
        }

        foreach (var revocation in records.Revocations)
        {
            Add(revocation.CreatedAt);
            Add(revocation.EffectiveFrom);
        }

        foreach (var term in records.Terms)
        {
            Add(term.CreatedAt);
            Add(term.StartsAt);
            Add(term.AuthorizedAt);
            Add(term.EndsAt);
            if (term.GraceEndsAt is { } grace) Add(grace);
        }

        foreach (var action in records.TermActions)
        {
            Add(action.RecordedAt);
            Add(action.EffectiveAt);
        }

        foreach (var fact in records.StatusFacts) Add(fact.RecordedAt);
        foreach (var release in records.FeatureReleases) Add(release.ReleasedAt);
        foreach (var activation in records.Activations) Add(activation.ActivatedAt);
        return points;
    }
}
