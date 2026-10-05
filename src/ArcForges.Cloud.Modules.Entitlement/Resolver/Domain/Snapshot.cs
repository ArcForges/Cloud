// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using System.Globalization;
using System.Text;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

/// <summary>
/// The reason vocabulary of a snapshot entry (ES-02). The resolver assigns every value except <see cref="QuotaExceeded"/>, which is a
/// usage fact owned by quota admission: the snapshot is derived from grants and terms only and never from measured usage.
/// </summary>
internal enum EntitlementReason
{
    Available,
    NoEntitlement,
    SubscriptionExpired,
    PaymentGrace,
    QuotaExceeded,
    TemporarilyRestricted,
    WorkspaceSuspended,
    FeatureUnavailable,
}

/// <summary>The normalised service state, driven by paid-through and never by a provider status string (EN-05, SU-01).</summary>
internal enum ServiceState
{
    None,
    Pending,
    Active,
    CancelScheduled,
    Grace,
    Ended,
    Suspended,
}

internal sealed record ServiceStateResult(ServiceState State, UtcMicros? PaidThrough, UtcMicros? GraceEndsAt, bool PaidTermActive);

internal sealed record CapabilityResult(string Key, bool Granted, EntitlementReason Reason, ImmutableArray<string> SourceGrantIds);

internal sealed record QuotaContribution(string GrantId, GrantSource Source, long Amount);

internal sealed record QuotaResult(string Key, long Limit, EntitlementReason Reason, ImmutableArray<QuotaContribution> Contributions);

internal sealed record AllowanceResult(
    string Key,
    bool Granted,
    EntitlementReason Reason,
    string? CapacityPlanRef,
    string? SelectedGrantId,
    ImmutableArray<string> SupersededGrantIds);

internal sealed record FeatureResult(string Key, bool Available, EntitlementReason Reason);

/// <summary>
/// The effective entitlement at one instant: everything a client may read, with a reason for every entry. It carries no version and no
/// computation time, so two evaluations that mean the same thing compare equal by <see cref="Canonical"/>.
/// </summary>
internal sealed record EntitlementContent(
    string DefinitionsVersion,
    ServiceStateResult Service,
    ImmutableArray<CapabilityResult> Capabilities,
    ImmutableArray<QuotaResult> Quotas,
    ImmutableArray<AllowanceResult> Allowances,
    ImmutableArray<FeatureResult> Features,
    ImmutableArray<string> UnrecognizedGrantIds,
    ImmutableArray<string> IgnoredTermIds,
    UtcMicros? ValidUntil)
{
    /// <summary>A stable text of everything effective, excluding <see cref="ValidUntil"/>, which only says when to look again.</summary>
    public string Canonical()
    {
        var text = new StringBuilder();
        text.Append("defs=").Append(DefinitionsVersion).Append('\n');
        text.Append("service=").Append(Service.State).Append('|').Append(Micros(Service.PaidThrough)).Append('|')
            .Append(Micros(Service.GraceEndsAt)).Append('|').Append(Service.PaidTermActive ? '1' : '0').Append('\n');
        foreach (var capability in Capabilities)
        {
            text.Append("cap=").Append(capability.Key).Append('|').Append(capability.Granted ? '1' : '0').Append('|')
                .Append(capability.Reason).Append('|').AppendJoin(',', capability.SourceGrantIds).Append('\n');
        }

        foreach (var quota in Quotas)
        {
            text.Append("quota=").Append(quota.Key).Append('|').Append(quota.Limit.ToString(CultureInfo.InvariantCulture)).Append('|')
                .Append(quota.Reason).Append('|')
                .AppendJoin(',', quota.Contributions.Select(c => c.GrantId + ":" + c.Source + ":" + c.Amount.ToString(CultureInfo.InvariantCulture)))
                .Append('\n');
        }

        foreach (var allowance in Allowances)
        {
            text.Append("allow=").Append(allowance.Key).Append('|').Append(allowance.Granted ? '1' : '0').Append('|').Append(allowance.Reason)
                .Append('|').Append(allowance.CapacityPlanRef).Append('|').Append(allowance.SelectedGrantId).Append('|')
                .AppendJoin(',', allowance.SupersededGrantIds).Append('\n');
        }

        foreach (var feature in Features)
        {
            text.Append("feature=").Append(feature.Key).Append('|').Append(feature.Available ? '1' : '0').Append('|').Append(feature.Reason).Append('\n');
        }

        text.Append("unrecognized=").AppendJoin(',', UnrecognizedGrantIds).Append('\n');
        text.Append("ignoredTerms=").AppendJoin(',', IgnoredTermIds).Append('\n');
        return text.ToString();
    }

    public bool SameEffectAs(EntitlementContent other) => string.Equals(Canonical(), other.Canonical(), StringComparison.Ordinal);

    private static string Micros(UtcMicros? value) => value is { } micros ? micros.ToString() : "-";
}

/// <summary>The stored snapshot (entitlement.snapshot): the content, the monotonically derived version and the instant it was computed for.</summary>
internal sealed record EntitlementSnapshot(string WorkspaceId, long Version, UtcMicros ComputedAt, EntitlementContent Content)
{
    public UtcMicros? ValidUntil => Content.ValidUntil;

    /// <summary>Full equality, the one a rebuild must satisfy: workspace, version, computation instant, validity and every entry.</summary>
    public bool SameAs(EntitlementSnapshot other) =>
        WorkspaceId == other.WorkspaceId && Version == other.Version && ComputedAt == other.ComputedAt
        && Content.ValidUntil == other.Content.ValidUntil && Content.SameEffectAs(other.Content);
}
