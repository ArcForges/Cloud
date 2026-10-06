// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Cloud.Modules;

namespace ArcForges.Cloud.Capacity;

internal sealed record CapacityRecoveryResult(CapacityJobStatus Status, CapacityDueCursor? Next = null, int RefusedJobs = 0);

/// <summary>Repairs lost/evicted scheduling hints from the actual current primary job rows. It
/// neither creates jobs nor advances them. All dispatches retain ordinary owner and lease guards.</summary>
internal sealed class CapacityRecoveryService(ICapacityJobRecoveryPort jobs, ICapacityWakeScheduler scheduler)
{
    private readonly SemaphoreSlim admission = new(1, 1);
    internal async Task<CapacityRecoveryResult> RunAsync(Guid requestId, CapacityDueCursor? after, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (requestId == Guid.Empty) return new(CapacityJobStatus.Invalid);
        if (!admission.Wait(0)) return new(CapacityJobStatus.Unavailable);
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(TimeSpan.FromSeconds(20));
        try
        {
            var page = await jobs.ReadDueAsync(after, bounded.Token).ConfigureAwait(false);
            if (page.Status != CapacityJobStatus.Succeeded || page.Jobs is null) return new(page.Status);
            var failed = 0; var refused = 0;
            await Parallel.ForEachAsync(page.Jobs, new ParallelOptions { MaxDegreeOfParallelism = 2, CancellationToken = bounded.Token }, async (job, token) =>
            {
                var identity = SHA256.HashData(Encoding.UTF8.GetBytes(requestId.ToString("D") + ":" + job.Definition.JobId.ToString("D")));
                var due = job.State == CapacityJobState.Ready ? job.AvailableAtMicros : job.LeasedUntilMicros!.Value;
                var result = await scheduler.ScheduleAsync(new(new Guid(identity.AsSpan(0, 16)), job.Definition.Owner,
                    job.Definition.JobId, due), token).ConfigureAwait(false);
                if (result.Status is CapacityScheduleStatus.Unavailable or CapacityScheduleStatus.UnknownOutcome)
                    Interlocked.Exchange(ref failed, 1);
                else if (result.Status is CapacityScheduleStatus.Invalid or CapacityScheduleStatus.Denied or CapacityScheduleStatus.Conflict)
                    Interlocked.Increment(ref refused);
            }).ConfigureAwait(false);
            bounded.Token.ThrowIfCancellationRequested();
            // Definite per-job refusals cannot strand every later authorized job behind this
            // page. Advance the scan, then reevaluate them on wrap; no refused hint is dispatched.
            // Only a genuinely ambiguous/unavailable dispatch retains this page for reconciliation.
            return failed == 0 ? new(CapacityJobStatus.Succeeded, page.Next, refused) : new(CapacityJobStatus.UnknownOutcome, RefusedJobs: refused);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        { return new(CapacityJobStatus.UnknownOutcome); }
        finally { admission.Release(); }
    }
}
