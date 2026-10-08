// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Application;

/// <summary>One run of one workspace. The workspace is the owner scope every plan checks.</summary>
internal readonly record struct HarnessRun(Guid WorkspaceId, Guid RunId);

/// <summary>The fence every write of a claimed run carries: the holder of this claim, its epoch and the recovery generation.</summary>
internal sealed record Fence(HarnessRun Run, Guid Holder, long Epoch, long RecoveryGeneration);

/// <summary>What a store call did. Only <see cref="Succeeded"/> means the write committed in this call.</summary>
internal enum StoreStatus
{
    Succeeded,

    /// <summary>A guard was false (a stale fence, an expired lease, a state or budget precondition): nothing committed.</summary>
    Refused,

    /// <summary>The outcome is unknown: nothing may be assumed committed or uncommitted; the executor stops and reconciles.</summary>
    Unknown,

    /// <summary>Nothing was executed; the store is overloaded or unreachable.</summary>
    Unavailable,

    /// <summary>The recovery generation of the call is no longer current.</summary>
    Stale,
}

internal sealed record LeaseRow(Guid Holder, long Epoch, long ExpiresAtMicros, long RecoveryGeneration);

/// <summary>What a load reads of one run: its state and revision, the lease, the durable counters and the last checkpoint receipt.</summary>
internal sealed record RunSnapshot(
    RunState State,
    long Revision,
    long RecoveryGeneration,
    string WorkflowId,
    string WorkerVersion,
    LeaseRow? Lease,
    BudgetCounters Budget,
    byte[]? LastReceipt);

/// <summary>The newest attempt that is still open (pending or running) and its command, as a load reads them.</summary>
internal sealed record OpenAttempt(Guid AttemptId, Guid StepId, Guid CommandId, int Ordinal, AttemptState State, string? CommandState);

internal sealed record ClaimCommand(Guid GuardId, Guid Holder, string WorkflowId, string WorkerVersion, long RecoveryGeneration, long NowMicros, long ExpiresAtMicros);

/// <summary>One counted step reserved under the fence, before any dispatch. The limits are the policy values the guard compares against.</summary>
internal sealed record ReserveCommand(
    Guid GuardId,
    Guid CommandId,
    Guid AttemptId,
    Guid StepId,
    int Ordinal,
    string Operation,
    string RequestSha256,
    EffectCost Cost,
    long StepLimit,
    long SubrequestLimit,
    long ModelLimit,
    long ToolLimit,
    long NowMicros);

/// <summary>One attempt outcome. The expected states are the guard: a stale or repeated outcome matches nothing and commits nothing.</summary>
internal sealed record OutcomeCommand(
    Guid GuardId,
    Guid AttemptId,
    AttemptState ExpectedAttemptState,
    string ExpectedCommandState,
    AttemptState NewAttemptState,
    FailureClass? Failure,
    EffectCertainty? Certainty,
    string NewCommandState,
    string? ResultRef,
    long NowMicros);

/// <summary>
/// The durable store of the executor. Each write is one guarded batch: its guard checks the fence (holder, epoch, recovery generation and
/// an unexpired lease) and the state it changes, and a false guard rolls everything back. Implementations never retry a write.
/// </summary>
internal interface IHarnessStore
{
    Task<RunSnapshot?> LoadAsync(HarnessRun run, CancellationToken cancellationToken);

    Task<OpenAttempt?> LoadOpenAttemptAsync(HarnessRun run, CancellationToken cancellationToken);

    Task<StoreStatus> ClaimAsync(HarnessRun run, ClaimCommand command, CancellationToken cancellationToken);

    Task<StoreStatus> RenewAsync(Fence fence, Guid guardId, long nowMicros, long expiresAtMicros, CancellationToken cancellationToken);

    Task<StoreStatus> ReserveStepAsync(Fence fence, ReserveCommand command, CancellationToken cancellationToken);

    Task<StoreStatus> MarkDispatchAsync(Fence fence, Guid guardId, Guid attemptId, long nowMicros, CancellationToken cancellationToken);

    Task<StoreStatus> RecordOutcomeAsync(Fence fence, OutcomeCommand command, CancellationToken cancellationToken);

    Task<StoreStatus> CheckpointAsync(Fence fence, Guid guardId, byte[] receiptSha256, long nowMicros, CancellationToken cancellationToken);

    Task<StoreStatus> YieldAsync(Fence fence, Guid guardId, RunState nextState, long nowMicros, CancellationToken cancellationToken);
}

/// <summary>A dispatch to the external supplier. Its result is what the supplier is known to have done.</summary>
internal sealed record EffectCall(Guid CommandId, Guid AttemptId, Guid StepId, string Operation, string RequestSha256, PinnedSnapshot Pinned, EffectCost Cost);

/// <summary>The supplier's answer. <paramref name="ResultRef"/> is a bounded reference, never the content.</summary>
internal sealed record EffectResult(EffectResultKind Kind, string? ResultRef);

/// <summary>The one external I/O port of the executor. The executor calls it only after the dispatch intent is durable.</summary>
internal interface IEffectPort
{
    Task<EffectResult> DispatchAsync(EffectCall call, CancellationToken cancellationToken);
}

/// <summary>Allocates identifiers. Production uses random identifiers; tests use a deterministic sequence.</summary>
internal interface IHarnessIds
{
    Guid NewId();
}

internal sealed class RandomHarnessIds : IHarnessIds
{
    public Guid NewId() => Guid.NewGuid();
}
