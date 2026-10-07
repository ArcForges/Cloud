// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Application;

/// <summary>
/// The Entitlement module's implementation of the published grant port (EO-03). It carries the request across the boundary as
/// primitives, hands it to <see cref="EntitlementService"/> unchanged (admission, idempotent replay by source reference, the stale-version
/// refusal and the atomic commit with the snapshot are the service's, not redefined here) and returns primitives: no Entitlement type
/// crosses the port. A store that could not be reached is a typed status; a store defect is not hidden and propagates.
/// </summary>
internal sealed class EntitlementGrantPortAdapter(EntitlementService service) : IEntitlementGrantPort
{
    public async ValueTask<EntitlementPortResult<EntitlementGrantRecord>> IssueGrantAsync(IssueGrantCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (!WellFormed(command.WorkspaceId, command.Subject, command.SourceRef, command.IssuedByActor, command.Reason, (command.Terms as AllowanceGrantTerms)?.CapacityPlanRef)
            || !TryRequest(command, out var request)) return Refusal<EntitlementGrantRecord>(EntitlementPortStatus.InvalidRequest, "The grant request is malformed.");
        try
        {
            var result = await service.IssueGrantAsync(request, cancellationToken).ConfigureAwait(false);
            return result.Succeeded
                ? new EntitlementPortResult<EntitlementGrantRecord>(result.Duplicate ? EntitlementPortStatus.Duplicate : EntitlementPortStatus.Succeeded, ToRecord(result.Value!), null)
                : Refusal<EntitlementGrantRecord>(ToStatus(result.Error!.Value), result.Detail);
        }
        catch (EntitlementStoreException exception) when (exception.Failure == EntitlementStoreFailure.Unavailable)
        {
            return Refusal<EntitlementGrantRecord>(EntitlementPortStatus.Unavailable, exception.Message);
        }
    }

    public async ValueTask<EntitlementPortResult<EntitlementRevocationRecord>> RevokeGrantAsync(RevokeGrantCommand command, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(command);
        if (!WellFormed(command.WorkspaceId, command.GrantId, command.ReasonCode, command.IssuedByActor)
            || (command.EffectiveFrom is { } effective && !IsWholeMicroseconds(effective)))
        {
            return Refusal<EntitlementRevocationRecord>(EntitlementPortStatus.InvalidRequest, "Instants have whole-microsecond precision.");
        }

        var request = new RevokeGrantRequest(
            command.WorkspaceId, command.GrantId, command.ReasonCode, command.EffectiveFrom is { } from ? UtcMicros.FromDateTimeOffset(from) : null,
            command.IssuedByActor, command.ExpectedEntitlementVersion);
        try
        {
            var result = await service.RevokeGrantAsync(request, cancellationToken).ConfigureAwait(false);
            if (!result.Succeeded) return Refusal<EntitlementRevocationRecord>(ToStatus(result.Error!.Value), result.Detail);
            var revocation = result.Value!;
            return new EntitlementPortResult<EntitlementRevocationRecord>(
                result.Duplicate ? EntitlementPortStatus.Duplicate : EntitlementPortStatus.Succeeded,
                new EntitlementRevocationRecord(revocation.RevocationId, revocation.GrantId, revocation.ReasonCode, revocation.EffectiveFrom.ToDateTimeOffset(),
                    revocation.IssuedByActor, revocation.CreatedAt.ToDateTimeOffset()),
                null);
        }
        catch (EntitlementStoreException exception) when (exception.Failure == EntitlementStoreFailure.Unavailable)
        {
            return Refusal<EntitlementRevocationRecord>(EntitlementPortStatus.Unavailable, exception.Message);
        }
    }

    private static EntitlementPortResult<T> Refusal<T>(EntitlementPortStatus status, string? detail) where T : class => new(status, null, detail);

    // The async production source validates the existing boundary before any authority I/O; the admission implementation stays shared.
    internal static bool ValidBoundary(IssueGrantCommand command)
        => WellFormed(command.WorkspaceId, command.Subject, command.SourceRef, command.IssuedByActor, command.Reason, (command.Terms as AllowanceGrantTerms)?.CapacityPlanRef)
            && TryRequest(command, out var request) && GrantAdmission.Validate(request) is null;
    internal static bool ValidBoundary(RevokeGrantCommand command)
        => WellFormed(command.WorkspaceId, command.GrantId, command.ReasonCode, command.IssuedByActor)
            && (command.EffectiveFrom is not { } from || IsWholeMicroseconds(from))
            && InputRules.IsIdentifier(command.WorkspaceId) && InputRules.IsIdentifier(command.GrantId)
            && InputRules.IsKey(command.ReasonCode) && InputRules.IsActor(command.IssuedByActor);

    private static bool TryRequest(IssueGrantCommand command, out IssueGrantRequest request)
    {
        request = null!;
        if (command.Terms is null || command.SourceRef is null || !IsWholeMicroseconds(command.EffectiveFrom)
            || (command.EffectiveUntil is { } until && !IsWholeMicroseconds(until)) || !Enum.IsDefined(command.Kind) || !Enum.IsDefined(command.Source))
        {
            return false;
        }

        GrantValue value = command.Terms switch
        {
            CapabilityGrantTerms => new CapabilityValue(),
            QuotaGrantTerms quota => new QuotaValue(quota.Limit, quota.Priority),
            AllowanceGrantTerms allowance => new AllowanceValue(allowance.CapacityPlanRef, allowance.Priority),
            _ => null!,
        };
        if (value is null) return false;
        request = new IssueGrantRequest(
            command.WorkspaceId, Kind(command.Kind), command.Subject, value, Source(command.Source), command.SourceRef,
            UtcMicros.FromDateTimeOffset(command.EffectiveFrom), command.EffectiveUntil is { } end ? UtcMicros.FromDateTimeOffset(end) : null,
            command.IssuedByActor, command.Reason);
        return true;
    }

    /// <summary>
    /// Text with an unpaired UTF-16 surrogate cannot be stored: it would be replaced on the way to D1 and the stored row would differ from the
    /// record returned to the caller. It is refused at the boundary, before any admission rule or store call.
    /// </summary>
    private static bool WellFormed(params string?[] values) => values.All(value => value is null || Utf16.IsWellFormed(value));

    private static bool IsWholeMicroseconds(DateTimeOffset instant) => instant.UtcTicks % (TimeSpan.TicksPerMillisecond / 1000) == 0;

    private static GrantKind Kind(EntitlementGrantKind kind) => kind switch
    {
        EntitlementGrantKind.Capability => GrantKind.Capability,
        EntitlementGrantKind.Quota => GrantKind.Quota,
        _ => GrantKind.Allowance,
    };

    private static GrantSource Source(EntitlementGrantSource source) => source switch
    {
        EntitlementGrantSource.Subscription => GrantSource.Subscription,
        EntitlementGrantSource.CloudPass => GrantSource.CloudPass,
        EntitlementGrantSource.StorageAddOn => GrantSource.StorageAddOn,
        EntitlementGrantSource.PurchasedCredit => GrantSource.PurchasedCredit,
        EntitlementGrantSource.AdminGrant => GrantSource.AdminGrant,
        EntitlementGrantSource.Migration => GrantSource.Migration,
        _ => GrantSource.Compensation,
    };

    private static EntitlementGrantRecord ToRecord(Grant grant) => new(
        grant.GrantId, grant.WorkspaceId,
        grant.Kind switch { GrantKind.Capability => EntitlementGrantKind.Capability, GrantKind.Quota => EntitlementGrantKind.Quota, _ => EntitlementGrantKind.Allowance },
        grant.Subject,
        grant.Value switch
        {
            QuotaValue quota => new QuotaGrantTerms(quota.Limit, quota.Priority),
            AllowanceValue allowance => new AllowanceGrantTerms(allowance.CapacityPlanRef, allowance.Priority),
            _ => new CapabilityGrantTerms(),
        },
        grant.Source switch
        {
            GrantSource.Subscription => EntitlementGrantSource.Subscription,
            GrantSource.CloudPass => EntitlementGrantSource.CloudPass,
            GrantSource.StorageAddOn => EntitlementGrantSource.StorageAddOn,
            GrantSource.PurchasedCredit => EntitlementGrantSource.PurchasedCredit,
            GrantSource.AdminGrant => EntitlementGrantSource.AdminGrant,
            GrantSource.Migration => EntitlementGrantSource.Migration,
            _ => EntitlementGrantSource.Compensation,
        },
        grant.SourceRef, grant.EffectiveFrom.ToDateTimeOffset(), grant.EffectiveUntil?.ToDateTimeOffset(), grant.IssuedByActor, grant.CreatedAt.ToDateTimeOffset(), grant.Reason);

    private static EntitlementPortStatus ToStatus(EntitlementError error) => error switch
    {
        EntitlementError.InvalidRequest => EntitlementPortStatus.InvalidRequest,
        EntitlementError.InvalidHistory => EntitlementPortStatus.InvalidHistory,
        EntitlementError.Conflict => EntitlementPortStatus.Conflict,
        EntitlementError.StaleVersion => EntitlementPortStatus.StaleVersion,
        EntitlementError.UnknownGrant => EntitlementPortStatus.UnknownGrant,
        EntitlementError.ConcurrentUpdate => EntitlementPortStatus.ConcurrentUpdate,
        _ => EntitlementPortStatus.OutcomeUnknown,
    };
}

/// <summary>Well-formedness of UTF-16 text: no unpaired surrogate.</summary>
internal static class Utf16
{
    public static bool IsWellFormed(string value) => !value.Where((c, i) => char.IsHighSurrogate(c) ? i + 1 == value.Length || !char.IsLowSurrogate(value[i + 1]) : char.IsLowSurrogate(c) && (i == 0 || !char.IsHighSurrogate(value[i - 1]))).Any();
}
