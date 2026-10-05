// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

/// <summary>The grant kinds of the data model. A consumable balance is a Commerce ledger projection and is never a grant.</summary>
public enum EntitlementGrantKind
{
    Capability,
    Quota,
    Allowance,
}

/// <summary>The closed grant-source vocabulary (GR-02, EO-04). No provider identifier is part of it.</summary>
public enum EntitlementGrantSource
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
public abstract record EntitlementGrantTerms
{
    private protected EntitlementGrantTerms()
    {
    }
}

public sealed record CapabilityGrantTerms : EntitlementGrantTerms;

/// <summary>A quota limit in the quota's own unit. <see cref="Priority"/> only matters to a priority-replace quota.</summary>
public sealed record QuotaGrantTerms(long Limit, long Priority = 0) : EntitlementGrantTerms;

/// <summary>A reference to the one capacity plan an allowance grant selects.</summary>
public sealed record AllowanceGrantTerms(string CapacityPlanRef, long Priority = 0) : EntitlementGrantTerms;

/// <summary>
/// A request to issue one grant (EO-03). The grant identifier and the creation time are assigned by the Entitlement module, never by the
/// caller. An administrative, compensation or migration grant carries its reason (GR-05) and, in <see cref="SourceRef"/>, the ticket,
/// incident or audited action that called the port. Instants have whole-microsecond precision.
/// </summary>
public sealed record IssueGrantCommand(
    string WorkspaceId,
    EntitlementGrantKind Kind,
    string Subject,
    EntitlementGrantTerms Terms,
    EntitlementGrantSource Source,
    string SourceRef,
    DateTimeOffset EffectiveFrom,
    DateTimeOffset? EffectiveUntil,
    string IssuedByActor,
    string? Reason);

/// <summary>A request to revoke one exact grant. <see cref="ExpectedEntitlementVersion"/> is the entitlement version the caller decided against.</summary>
public sealed record RevokeGrantCommand(
    string WorkspaceId,
    string GrantId,
    string ReasonCode,
    DateTimeOffset? EffectiveFrom,
    string IssuedByActor,
    long ExpectedEntitlementVersion);

/// <summary>A stored grant as the port reports it: primitives only, no Entitlement type.</summary>
public sealed record EntitlementGrantRecord(
    string GrantId,
    string WorkspaceId,
    EntitlementGrantKind Kind,
    string Subject,
    EntitlementGrantTerms Terms,
    EntitlementGrantSource Source,
    string? SourceRef,
    DateTimeOffset EffectiveFrom,
    DateTimeOffset? EffectiveUntil,
    string IssuedByActor,
    DateTimeOffset CreatedAt,
    string? Reason);

/// <summary>A stored revocation as the port reports it.</summary>
public sealed record EntitlementRevocationRecord(
    string RevocationId,
    string GrantId,
    string ReasonCode,
    DateTimeOffset EffectiveFrom,
    string IssuedByActor,
    DateTimeOffset CreatedAt);

/// <summary>The typed refusals and successes of the grant port. Nothing is coerced and no refusal carries a value of the request.</summary>
public enum EntitlementPortStatus
{
    /// <summary>The record was appended with the snapshot that reflects it.</summary>
    Succeeded,

    /// <summary>An equal grant or revocation already existed (a replay by source reference); nothing was written and the stored record is returned.</summary>
    Duplicate,

    /// <summary>A request the admission rules refuse (a malformed value, a missing reason, an unknown source).</summary>
    InvalidRequest,

    /// <summary>The stored history cannot be interpreted or would make the entitlement version fall; nothing was written.</summary>
    InvalidHistory,

    /// <summary>The source reference was already used for a different grant.</summary>
    Conflict,

    /// <summary>The entitlement version changed since the caller decided; nothing was written.</summary>
    StaleVersion,

    /// <summary>No such grant exists in the workspace.</summary>
    UnknownGrant,

    /// <summary>The workspace changed concurrently on every attempt; nothing was written.</summary>
    ConcurrentUpdate,

    /// <summary>The store could not tell whether the commit happened; only the same request may be sent again.</summary>
    OutcomeUnknown,

    /// <summary>The store was overloaded or unreachable; nothing was written and the same request may be sent again later.</summary>
    Unavailable,
}

/// <summary>The outcome of a port call: a value, or a typed refusal with a reason a caller or operator can read.</summary>
public sealed record EntitlementPortResult<T>(EntitlementPortStatus Status, T? Value, string? Detail)
    where T : class
{
    public bool Succeeded => Status is EntitlementPortStatus.Succeeded or EntitlementPortStatus.Duplicate;
}

/// <summary>
/// The only way Commerce, the operator path and the refund path reach Entitlement (EO-03, MD-03). It lives in the shared boundary project so
/// that no module references the Entitlement project, and it is implemented by the Entitlement module. A grant and the snapshot and
/// entitlement version that reflect it commit atomically in the module's own store; this port commits on its own and joining it to a
/// purchase unit of work is the Entitlement participation of the shared family.
/// </summary>
public interface IEntitlementGrantPort
{
    ValueTask<EntitlementPortResult<EntitlementGrantRecord>> IssueGrantAsync(IssueGrantCommand command, CancellationToken cancellationToken);

    ValueTask<EntitlementPortResult<EntitlementRevocationRecord>> RevokeGrantAsync(RevokeGrantCommand command, CancellationToken cancellationToken);
}
