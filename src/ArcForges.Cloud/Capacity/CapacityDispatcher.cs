// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using ArcForges.Cloud.Modules;

namespace ArcForges.Cloud.Capacity;

internal enum CapacityDispatchStatus { Complete, Reschedule, Busy, Refused, Unavailable, UnknownOutcome }
internal sealed record CapacityDispatchResult(CapacityDispatchStatus Status, long? AvailableAtMicros = null, long? Fence = null);
internal sealed record CapacityWake(Guid WakeId, CapacityJobOwner Owner, Guid JobId, string Holder,
    Guid ClaimCommandId, Guid CheckpointCommandId);

/// <summary>A wake processes one bounded slice, never a whole unbounded job. Durable D1 state decides
/// whether a duplicate/lost wake may do anything; the alarm/queue is scheduling only.</summary>
internal sealed class CapacityDispatcher
{
    private readonly ICapacityJobPort jobs;
    private readonly IReadOnlyDictionary<string, ICapacityJobProcessor> processors;
    private readonly TimeProvider time;
    private readonly SemaphoreSlim activeSlices = new(8, 8);
    public CapacityDispatcher(ICapacityJobPort jobs, IEnumerable<ICapacityJobProcessor> processors, TimeProvider time)
    {
        this.jobs = jobs; this.time = time;
        // Duplicate type owners are a configuration defect, not an arbitrary first-writer choice.
        this.processors = processors.ToDictionary(processor => processor.JobType, StringComparer.Ordinal);
    }

    internal async Task<CapacityDispatchResult> RunAsync(CapacityWake wake, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!await activeSlices.WaitAsync(0, cancellationToken).ConfigureAwait(false))
            return new(CapacityDispatchStatus.Busy, checked(Now() + 2000000));
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        lifetime.CancelAfter(TimeSpan.FromSeconds(20));
        var elapsed = Stopwatch.StartNew();
        try { return await RunSliceAsync(wake, elapsed, lifetime.Token).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // Setup, processing and checkpoint all share this deadline. A dispatched claim or
            // checkpoint may already be durable; retain the original wake IDs for reconciliation.
            return new(CapacityDispatchStatus.UnknownOutcome);
        }
        finally { activeSlices.Release(); }
    }

    private async Task<CapacityDispatchResult> RunSliceAsync(CapacityWake wake, Stopwatch elapsed, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (wake.WakeId == Guid.Empty || wake.ClaimCommandId == Guid.Empty || wake.CheckpointCommandId == Guid.Empty
            || wake.ClaimCommandId == wake.CheckpointCommandId || wake.WakeId == wake.ClaimCommandId || wake.WakeId == wake.CheckpointCommandId
            || wake.JobId == Guid.Empty || wake.Holder is not { Length: > 0 and <= 128 })
            return new(CapacityDispatchStatus.Refused);
        var read = await jobs.ReadAsync(wake.Owner, wake.JobId, cancellationToken).ConfigureAwait(false);
        if (read.Status != CapacityJobStatus.Succeeded) return Failed(read.Status);
        var old = read.Job!;
        if (old.State is CapacityJobState.Succeeded or CapacityJobState.DeadLettered) return new(CapacityDispatchStatus.Complete, Fence: old.Fence);
        var now = Now();
        var completed = await jobs.ReconcileAsync(wake.Owner, wake.JobId, wake.CheckpointCommandId,
            CapacityJobMutation.Checkpoint, cancellationToken).ConfigureAwait(false);
        if (completed.Status != CapacityJobStatus.NotFound)
        {
            if (completed.Status != CapacityJobStatus.Replayed) return Failed(completed.Status);
            var accepted = completed.Job!;
            if (accepted.State is CapacityJobState.Succeeded or CapacityJobState.DeadLettered)
                return new(CapacityDispatchStatus.Complete, Fence: accepted.Fence);
            return accepted.State == CapacityJobState.Ready
                ? new(CapacityDispatchStatus.Reschedule, Math.Max(checked(now + 100000), accepted.AvailableAtMicros), accepted.Fence)
                : new(CapacityDispatchStatus.Refused);
        }
        if (!processors.TryGetValue(old.Definition.JobType, out var processor)) return new(CapacityDispatchStatus.Refused);
        var previous = await jobs.ReconcileAsync(wake.Owner, wake.JobId, wake.ClaimCommandId,
            CapacityJobMutation.Claim, cancellationToken).ConfigureAwait(false);
        CapacityJobSnapshot active;
        if (previous.Status == CapacityJobStatus.Replayed)
        {
            active = previous.Job!;
            if (active != old || active.State != CapacityJobState.Leased || active.Holder != wake.Holder || active.LeasedUntilMicros <= now)
                return old.State == CapacityJobState.Leased && old.LeasedUntilMicros > now
                    ? new(CapacityDispatchStatus.Busy, old.LeasedUntilMicros, old.Fence)
                    : new(CapacityDispatchStatus.Reschedule, checked(now + 100000), old.Fence);
        }
        else
        {
            if (previous.Status != CapacityJobStatus.NotFound) return Failed(previous.Status);
            if (old.State == CapacityJobState.Leased && old.LeasedUntilMicros > now)
                return new(CapacityDispatchStatus.Busy, old.LeasedUntilMicros, old.Fence);
            if (old.AvailableAtMicros > now) return new(CapacityDispatchStatus.Reschedule, old.AvailableAtMicros, old.Fence);
            var claimed = await jobs.ClaimAsync(new(wake.ClaimCommandId, wake.Owner, wake.JobId, wake.Holder,
                old.Fence, checked(now + 60000000)), cancellationToken).ConfigureAwait(false);
            if (claimed.Status is not (CapacityJobStatus.Succeeded or CapacityJobStatus.Replayed)) return Failed(claimed.Status);
            active = claimed.Job!;
            if (active.State == CapacityJobState.DeadLettered) return new(CapacityDispatchStatus.Complete, Fence: active.Fence);
        }
        // A replayed claim may be obsolete after a takeover/checkpoint. Reread the actual row before
        // invoking the owner, and every owner's effect must additionally guard this lease in its batch.
        var current = await jobs.ReadAsync(wake.Owner, wake.JobId, cancellationToken).ConfigureAwait(false);
        if (current.Status != CapacityJobStatus.Succeeded) return Failed(current.Status);
        if (current.Job != active || active.State != CapacityJobState.Leased || active.Holder != wake.Holder || active.LeasedUntilMicros <= Now())
            return new(CapacityDispatchStatus.Refused);
        var lease = new CapacityJobLease(wake.JobId, wake.Holder, active.Fence, active.LeasedUntilMicros!.Value);
        var remaining = TimeSpan.FromSeconds(20) - elapsed.Elapsed;
        if (remaining <= TimeSpan.Zero) return new(CapacityDispatchStatus.UnknownOutcome);
        CapacityJobSlice result;
        try
        {
            result = await processor.ProcessAsync(active, lease, 100, remaining, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // A possibly applied owner effect is reconciled by that owner on the next slice. Do not
            // advance the checkpoint, invent completed work or free its quota after an elapsed budget.
            return new(CapacityDispatchStatus.Reschedule, active.LeasedUntilMicros, active.Fence);
        }
        catch (CapacityProcessingRefusedException) { return new(CapacityDispatchStatus.Refused, Fence: active.Fence); }
        cancellationToken.ThrowIfCancellationRequested();
        if (result is null || elapsed.Elapsed > TimeSpan.FromSeconds(20) || result.ProcessedItems is < 0 or > 100
            || !ArcForges.Cloud.Storage.Capacity.CapacityJobCodec.Json(result.ProgressJson, 4096)
            || !result.Complete && result.NextAvailableAtMicros <= Now())
            return new(CapacityDispatchStatus.Refused);
        var checkpoint = await jobs.CheckpointAsync(new(wake.CheckpointCommandId, wake.Owner, lease, result.ProgressJson,
            result.Complete ? CapacityJobState.Succeeded : CapacityJobState.Ready, result.Complete ? Now() : result.NextAvailableAtMicros), cancellationToken).ConfigureAwait(false);
        if (checkpoint.Status is not (CapacityJobStatus.Succeeded or CapacityJobStatus.Replayed)) return Failed(checkpoint.Status);
        return result.Complete ? new(CapacityDispatchStatus.Complete, Fence: active.Fence)
            : new(CapacityDispatchStatus.Reschedule, checkpoint.Job!.AvailableAtMicros, active.Fence);
    }

    private long Now() => checked((time.GetUtcNow().UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10);
    private static CapacityDispatchResult Failed(CapacityJobStatus status) => new(status switch
    {
        CapacityJobStatus.UnknownOutcome => CapacityDispatchStatus.UnknownOutcome,
        CapacityJobStatus.Unavailable => CapacityDispatchStatus.Unavailable,
        CapacityJobStatus.Conflict => CapacityDispatchStatus.Busy,
        _ => CapacityDispatchStatus.Refused,
    });
}
