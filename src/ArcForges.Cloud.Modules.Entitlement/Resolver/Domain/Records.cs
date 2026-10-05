// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

/// <summary>The grant row kinds of the data model. A consumable balance is a Commerce ledger projection and is never a grant.</summary>
internal enum GrantKind
{
    Capability,
    Quota,
    Allowance,
}

/// <summary>The closed grant-source vocabulary (GR-02, EO-04). No provider identifier is part of it.</summary>
internal enum GrantSource
{
    Subscription,
    CloudPass,
    StorageAddOn,
    PurchasedCredit,
    AdminGrant,
    Migration,
    Compensation,
}

/// <summary>Kind-specific grant payload. A capability grant carries no flag: it can only grant, and loss is a revocation (GR-03).</summary>
internal abstract record GrantValue
{
    private protected GrantValue()
    {
    }
}

internal sealed record CapabilityValue : GrantValue;

/// <summary>A quota limit in the quota's own unit. <see cref="Priority"/> only matters to a priority-replace quota.</summary>
internal sealed record QuotaValue(long Limit, long Priority = 0) : GrantValue;

/// <summary>A reference to the one capacity plan an allowance grant selects. The capacity account itself belongs to the capacity task.</summary>
internal sealed record AllowanceValue(string CapacityPlanRef, long Priority = 0) : GrantValue;

/// <summary>An immutable grant (entitlement.grant). Nothing about it is ever edited; its end is a revocation or its own end date.</summary>
internal sealed record Grant(
    string GrantId,
    string WorkspaceId,
    GrantKind Kind,
    string Subject,
    GrantValue Value,
    GrantSource Source,
    string? SourceRef,
    UtcMicros EffectiveFrom,
    UtcMicros? EffectiveUntil,
    string IssuedByActor,
    UtcMicros CreatedAt,
    string? Reason = null);

/// <summary>An immutable revocation (entitlement.revocation) of one exact grant.</summary>
internal sealed record Revocation(
    string RevocationId,
    string GrantId,
    string ReasonCode,
    UtcMicros EffectiveFrom,
    string IssuedByActor,
    UtcMicros CreatedAt);

internal enum ServiceTermKind
{
    Subscription,
    Pass,
    Compensation,
    SelfHostGrant,
}

/// <summary>One row of entitlement.service_term as the resolver reads it: an interval, never a flag (SV-01).</summary>
internal sealed record ServiceTermFact(
    string TermId,
    ServiceTermKind Kind,
    UtcMicros StartsAt,
    UtcMicros EndsAt,
    UtcMicros? GraceEndsAt,
    UtcMicros AuthorizedAt,
    UtcMicros CreatedAt);

internal enum ServiceTermActionKind
{
    Supersede,
    Revoke,
}

/// <summary>An append-only supersede or revoke of a term (TM-04). The original end is never rewritten; the action truncates the effective interval.</summary>
internal sealed record TermActionFact(string TermId, ServiceTermActionKind Kind, UtcMicros EffectiveAt, UtcMicros RecordedAt);

internal enum WorkspaceStatus
{
    Normal,
    Restricted,
    Suspended,
}

/// <summary>
/// An append-only administrative or risk fact about the workspace. <see cref="AutoRenew"/> and <see cref="PurchasePending"/> are two
/// independent facts and are never merged into one flag (SU-03). The newest fact recorded at or before the evaluated instant applies.
/// </summary>
internal sealed record WorkspaceStatusFact(UtcMicros RecordedAt, WorkspaceStatus Status, bool AutoRenew, bool PurchasePending);

/// <summary>A feature flag release fact: the feature is released from <see cref="ReleasedAt"/>. A feature without one is not released.</summary>
internal sealed record FeatureReleaseFact(string Feature, UtcMicros ReleasedAt);

/// <summary>
/// The activation of one definitions version for a workspace. Each activation after the first is a change every client must notice
/// (BN-02, ES-03), so it raises the entitlement version. The history of activations is an append-only record like every other input,
/// which keeps the version rebuildable from the records alone.
/// </summary>
internal sealed record DefinitionsActivation(string Version, UtcMicros ActivatedAt);

/// <summary>Everything the resolver reads for one workspace. All collections are append-only records; the resolver mutates none of them.</summary>
internal sealed record EntitlementRecordSet(
    string WorkspaceId,
    ImmutableArray<Grant> Grants,
    ImmutableArray<Revocation> Revocations,
    ImmutableArray<ServiceTermFact> Terms,
    ImmutableArray<TermActionFact> TermActions,
    ImmutableArray<WorkspaceStatusFact> StatusFacts,
    ImmutableArray<FeatureReleaseFact> FeatureReleases,
    ImmutableArray<DefinitionsActivation> Activations)
{
    public static EntitlementRecordSet Empty(string workspaceId) =>
        new(workspaceId, [], [], [], [], [], [], []);

    public int Count => Grants.Length + Revocations.Length + Terms.Length + TermActions.Length + StatusFacts.Length
        + FeatureReleases.Length + Activations.Length;
}
