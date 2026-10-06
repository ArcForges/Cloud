// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

public enum CapacityJobState { Ready = 1, Leased = 2, Succeeded = 3, DeadLettered = 4 }
public enum CapacityJobStatus { Succeeded, Replayed, NotFound, Invalid, Denied, Conflict, ReusedIdentifier, ReceiptExpired, StaleGeneration, Unavailable, UnknownOutcome }
public sealed record CapacityJobOwner(Guid RealmId, Guid? WorkspaceId, string Kind, Guid OwnerId);
public sealed record CapacityJobDefinition(Guid JobId, string JobType, CapacityJobOwner Owner,
    [property: System.Text.Json.Serialization.JsonNumberHandling(System.Text.Json.Serialization.JsonNumberHandling.WriteAsString | System.Text.Json.Serialization.JsonNumberHandling.AllowReadingFromString)] ulong RecoveryGeneration, string InputJson,
    string InputHash, int MaximumAttempts, long AvailableAtMicros);
public sealed record CapacityJobSnapshot(CapacityJobDefinition Definition, string? Holder, long? LeasedUntilMicros,
    int Attempts, long Fence, CapacityJobState State, string ProgressJson, long AvailableAtMicros);
public sealed record CapacityJobLease(Guid JobId, string Holder, long Fence, long LeasedUntilMicros);
public sealed record CapacityJobClaim(Guid CommandId, CapacityJobOwner Owner, Guid JobId, string Holder,
    long ExpectedFence, long LeasedUntilMicros);
public sealed record CapacityJobCheckpoint(Guid CommandId, CapacityJobOwner Owner, CapacityJobLease Lease,
    string ProgressJson, CapacityJobState State, long AvailableAtMicros);
public sealed record CapacityJobResult(CapacityJobStatus Status, CapacityJobSnapshot? Job = null);
public enum CapacityJobMutation { Claim, Checkpoint }

/// <summary>Infrastructure-owned production Platform lease port. A wake is a hint; D1's current lease/fence
/// remains the publication authority. No Foundation probe row or checksum substitutes this state.</summary>
public interface ICapacityJobPort
{
    Task<CapacityJobResult> ReadAsync(CapacityJobOwner owner, Guid jobId, CancellationToken cancellationToken);
    Task<CapacityJobResult> CreateAsync(Guid commandId, CapacityJobDefinition definition, CancellationToken cancellationToken);
    Task<CapacityJobResult> ClaimAsync(CapacityJobClaim claim, CancellationToken cancellationToken);
    Task<CapacityJobResult> CheckpointAsync(CapacityJobCheckpoint checkpoint, CancellationToken cancellationToken);
    /// <summary>Reports an already accepted immutable claim/checkpoint under current job ownership.
    /// It performs no write and grants no future lease; receipt metadata must still match current state.</summary>
    Task<CapacityJobResult> ReconcileAsync(CapacityJobOwner owner, Guid jobId, Guid commandId, CapacityJobMutation mutation,
        CancellationToken cancellationToken);
}

/// <summary>Actual owning operation current realm/scope/recovery authority. Caller hints confer no permission.</summary>
public interface ICapacityJobAuthority
{
    Task<QuotaAuthorityStatus> AuthorizeCreateAsync(CapacityJobDefinition definition, CancellationToken cancellationToken);
    Task<QuotaAuthorityStatus> AuthorizeAsync(CapacityJobOwner owner, Guid jobId, string operation, CancellationToken cancellationToken);
}

public sealed record CapacityRecoveryScope(Guid RealmId, ulong RecoveryGeneration);
public sealed record CapacityRecoveryScopeResult(QuotaAuthorityStatus Status, CapacityRecoveryScope? Scope = null);
/// <summary>Actual trusted deployment/recovery authority, independent of a wake's caller fields.
/// Returns the current authorized realm and generation, never a globally permissive scan grant.</summary>
public interface ICapacityJobRecoveryAuthority
{
    Task<CapacityRecoveryScopeResult> GetCurrentAsync(CancellationToken cancellationToken);
}
public sealed record CapacityDueCursor(long DueAtMicros, Guid JobId);
public sealed record CapacityDuePage(CapacityJobStatus Status, IReadOnlyList<CapacityJobSnapshot>? Jobs = null,
    CapacityDueCursor? Next = null);
/// <summary>Bounded primary recovery scan. Returned rows are hints; dispatch still performs each
/// job's current owner authorization and guarded claim. Historical generations are excluded.</summary>
public interface ICapacityJobRecoveryPort
{
    Task<CapacityDuePage> ReadDueAsync(CapacityDueCursor? after, CancellationToken cancellationToken);
}

/// <summary>One bounded processor handles at most the supplied item count and time budget. Effects must
/// guard the supplied current Platform lease in their registered atomic D1 publication, not just check it first.
/// External effects additionally require their owning durable dispatch barrier/reconciliation contracts.</summary>
public interface ICapacityJobProcessor
{
    string JobType { get; }
    Task<CapacityJobSlice> ProcessAsync(CapacityJobSnapshot job, CapacityJobLease lease, int maximumItems,
        TimeSpan budget, CancellationToken cancellationToken);
}
public sealed record CapacityJobSlice(int ProcessedItems, string ProgressJson, bool Complete, long NextAvailableAtMicros);

public enum CapacityScheduleStatus { Scheduled, AlreadyScheduled, Invalid, Denied, Conflict, Unavailable, UnknownOutcome }
public sealed record CapacityScheduleCommand(Guid CommandId, CapacityJobOwner Owner, Guid JobId, long AvailableAtMicros);
public sealed record CapacityScheduleResult(CapacityScheduleStatus Status);
/// <summary>Production signed pacer adapter. Scheduling is a hint; it does not create a job, authorize
/// its owner, advance progress, settle quota or replace the actual current D1 lease.</summary>
public interface ICapacityWakeScheduler
{
    Task<CapacityScheduleResult> ScheduleAsync(CapacityScheduleCommand command, CancellationToken cancellationToken);
}
