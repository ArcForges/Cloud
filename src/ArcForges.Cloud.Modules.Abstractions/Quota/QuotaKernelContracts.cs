// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

public enum QuotaScopeKind { Workspace = 1, Deployment = 2 }
public enum QuotaReservationState { Held = 1, Settled = 2, Releasing = 3, Released = 4 }
public enum QuotaEffectKind { Consume = 1, Release = 2, Adjust = 3 }
public enum QuotaKernelStatus
{
    Succeeded, Replayed, NotFound, Invalid, Denied, LimitExceeded, Conflict,
    ReusedIdentifier, ReceiptExpired, StaleGeneration, Unavailable, UnknownOutcome,
}

/// <summary>A period is an explicit owner-resolved entitlement period, or gauge. A gauge never resets at renewal.</summary>
public sealed record QuotaBudgetKey(QuotaScopeKind ScopeKind, string ScopeId, string QuotaKey, string PeriodKey);

/// <summary>Authoritative persisted accounting; display counters are never substituted for these quantities.</summary>
public sealed record QuotaBudgetState(QuotaBudgetKey Key, string Unit, long Limit, long Used, long Held, long PolicyVersion, long Revision);

public sealed record QuotaReservation(Guid ReservationId, Guid OperationId, QuotaBudgetKey Key, string OwnerKind,
    Guid OwnerId, long Bound, long Consumed, QuotaReservationState State, long ExpiresAtMicros, long? LeaseUntilMicros, long? Fence);

/// <summary>Established by the owning operation's actual authentication adapter. These fields alone confer no permission.</summary>
public sealed record QuotaOwnerContext(Guid RealmId, Guid? WorkspaceId, string ActorRef, long AuthEpoch, long RecoveryGeneration,
    string OwnerKind, Guid OwnerId);

public sealed record QuotaBudgetChange(QuotaBudgetKey Key, string Unit, long Limit, long PolicyVersion, long ExpectedRevision);
public sealed record QuotaBudgetCommand(Guid CommandId, QuotaOwnerContext Context, QuotaBudgetChange Change);
/// <summary>AdmissionCeiling is an optional stricter server-approved operator ceiling. It can never
/// increase the persisted hard limit. The current policy authority binds its exact value.</summary>
public sealed record QuotaAdmissionItem(Guid ReservationId, QuotaBudgetKey Key, long Bound, long PolicyVersion, long ExpectedRevision,
    long? AdmissionCeiling = null);
public sealed record QuotaAdmissionCommand(Guid CommandId, Guid OperationId, QuotaOwnerContext Context,
    IReadOnlyList<QuotaAdmissionItem> Items, long ExpiresAtMicros, CapacityJobLease? JobLease = null);

/// <summary>
/// A measurement names immutable server evidence. Client sizes are admission bounds, never settlement authority.
/// Negative gauge adjustments require verified physical deletion/replacement; cleanup scheduling does not free bytes.
/// </summary>
public sealed record QuotaMeasurement(Guid EffectId, QuotaEffectKind Kind, long Quantity, Guid? SourceObjectId,
    Guid? SourceSegmentId, Guid? DeletionReceiptId);
public sealed record QuotaEffectCommand(Guid CommandId, QuotaOwnerContext Context, Guid ReservationId,
    long ExpectedBudgetRevision, QuotaMeasurement Measurement, bool Complete, CapacityJobLease? JobLease = null);
public sealed record QuotaCleanupCommand(Guid CommandId, QuotaOwnerContext Context, Guid ReservationId,
    long ExpectedBudgetRevision, CapacityJobLease? JobLease = null);

public sealed record QuotaKernelResult(QuotaKernelStatus Status, IReadOnlyList<QuotaBudgetState>? Budgets = null,
    IReadOnlyList<QuotaReservation>? Reservations = null, string? Reason = null);
public sealed record QuotaReadResult<T>(QuotaKernelStatus Status, T? Value);

public enum QuotaAuthorityStatus { Authorized, Denied, Stale, Unavailable }
public enum QuotaKernelOperation { Read, PublishBudget, Reserve, ApplyEffect, RequestCleanup }

/// <summary>
/// Current owner policy and scope authority, supplied by COM.07/actual business owners. The production kernel has no permissive
/// fallback. Each authorization binds the exact command, operation owner, actor/realm/epochs, resolved period, unit and policy.
/// A supplied JobLease must belong to this exact owning operation/reservation. The atomic owner plan additionally
/// checks its actual Platform row; preauthorization alone cannot prevent a stale worker publishing after takeover.
/// A caller-provided success flag, declared size or cached display counter is not an implementation of this boundary.
/// </summary>
public interface IQuotaKernelAuthority
{
    Task<QuotaAuthorityStatus> AuthorizeCommandAsync(QuotaOwnerContext context, QuotaKernelOperation operation, CancellationToken cancellationToken);
    Task<QuotaAuthorityStatus> AuthorizeReadAsync(QuotaOwnerContext context, QuotaBudgetKey? key, Guid? reservationId, CancellationToken cancellationToken);
    Task<QuotaAuthorityStatus> AuthorizeBudgetAsync(QuotaBudgetCommand command, CancellationToken cancellationToken);
    Task<QuotaAuthorityStatus> AuthorizeAdmissionAsync(QuotaAdmissionCommand command, CancellationToken cancellationToken);
    Task<QuotaAuthorityStatus> AuthorizeEffectAsync(QuotaEffectCommand command, QuotaReservation reservation, CancellationToken cancellationToken);
    Task<QuotaAuthorityStatus> AuthorizeCleanupAsync(QuotaCleanupCommand command, QuotaReservation reservation, CancellationToken cancellationToken);
}

/// <summary>
/// The owning object/segment/deletion producer verifies its actual immutable evidence and exact quantity/scope/fence.
/// This is separate from permission: an authorized client still cannot invent measured bytes or a deletion receipt.
/// </summary>
public interface IQuotaMeasurementAuthority
{
    Task<QuotaAuthorityStatus> VerifyAsync(QuotaOwnerContext context, QuotaReservation reservation,
        QuotaMeasurement measurement, CancellationToken cancellationToken);
}

/// <summary>The production durable multi-limit kernel. An admission commits every budget/reservation, or none.</summary>
public interface IQuotaKernelPort
{
    Task<QuotaReadResult<QuotaBudgetState>> ReadBudgetAsync(QuotaOwnerContext context, QuotaBudgetKey key, CancellationToken cancellationToken);
    Task<QuotaReadResult<QuotaReservation>> ReadReservationAsync(QuotaOwnerContext context, Guid reservationId, CancellationToken cancellationToken);
    Task<QuotaKernelResult> PublishBudgetAsync(QuotaBudgetCommand command, CancellationToken cancellationToken);
    Task<QuotaKernelResult> ReserveAsync(QuotaAdmissionCommand command, CancellationToken cancellationToken);
    Task<QuotaKernelResult> ApplyAsync(QuotaEffectCommand command, CancellationToken cancellationToken);
    Task<QuotaKernelResult> RequestCleanupAsync(QuotaCleanupCommand command, CancellationToken cancellationToken);
}
