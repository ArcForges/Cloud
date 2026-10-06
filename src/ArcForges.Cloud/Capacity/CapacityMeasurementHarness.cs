// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage.Capacity;

namespace ArcForges.Cloud.Capacity;

internal sealed record CapacityMeasurementStart(Guid CommandId, CapacityJobOwner Owner, Guid JobId, ulong RecoveryGeneration,
    long AvailableAtMicros, string ApprovedProfileJson, string ApprovedProfileHash, CapacityAllocation VerifiedProviderLimits, int Reads);
internal sealed record CapacityMeasurementReport(CapacityJobStatus Status, bool Complete, int AcknowledgedReads,
    string? MeanReadMicros, string? MaximumReadMicros, string? P95UpperBoundMicros, string? WorkloadHash,
    string? SourceSnapshotHash, string? ProposedProfileHash, string AcceptanceStatus);

/// <summary>Runnable measurement orchestration through the actual owner-authorized persistent job
/// and signed pacer. A successful sample reports observations, never full L16/paid-launch acceptance.
/// The actual deployment owner supplies approved profile/provider evidence and current generation.
/// A caller cannot turn a bootstrap Container allocation into an approved launch envelope.</summary>
internal sealed class CapacityMeasurementHarness(ICapacityJobPort jobs, ICapacityWakeScheduler scheduler)
{
    internal async Task<CapacityJobResult> StartAsync(CapacityMeasurementStart start, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (start.Owner.Kind != "capacity.measurement" || start.Reads is <= 0 or > 1000 || start.AvailableAtMicros < 0
            || !CapacityProfileCodec.TryDecode(start.ApprovedProfileJson, start.ApprovedProfileHash, start.Owner.RealmId,
                start.VerifiedProviderLimits, out var profile)) return new(CapacityJobStatus.Invalid);
        var input = JsonSerializer.Serialize(new CapacityMeasurementInput(profile!.WorkloadHash, profile.SourceSnapshotHash, start.ApprovedProfileHash, start.Reads),
            CapacityMeasurementJson.Default.CapacityMeasurementInput);
        var created = await jobs.CreateAsync(start.CommandId, new(start.JobId, "capacity.measurement", start.Owner,
            start.RecoveryGeneration, input, CapacityJobCodec.Hash(input), 20, start.AvailableAtMicros), cancellationToken).ConfigureAwait(false);
        if (created.Status is not (CapacityJobStatus.Succeeded or CapacityJobStatus.Replayed)) return created;
        var scheduled = await scheduler.ScheduleAsync(new(start.CommandId, start.Owner, start.JobId, start.AvailableAtMicros), cancellationToken).ConfigureAwait(false);
        // The real durable Ready row is retained on unknown/unavailable wake. Cron recovery repairs
        // it; the job is neither rolled back nor falsely reported as a completed measurement.
        return scheduled.Status is CapacityScheduleStatus.Scheduled or CapacityScheduleStatus.AlreadyScheduled ? created
            : new(scheduled.Status == CapacityScheduleStatus.Unavailable ? CapacityJobStatus.Unavailable : CapacityJobStatus.UnknownOutcome, created.Job);
    }
    internal async Task<CapacityMeasurementReport> ReadReportAsync(CapacityJobOwner owner, Guid jobId, string approvedProfileHash,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var result = await jobs.ReadAsync(owner, jobId, cancellationToken).ConfigureAwait(false);
        if (result.Status != CapacityJobStatus.Succeeded || result.Job is not { } job)
            return Empty(result.Status);
        try
        {
            if (job.Definition.JobType != "capacity.measurement" || owner.Kind != "capacity.measurement" || !CapacityProfileCodec.Hash(approvedProfileHash))
                return Empty(CapacityJobStatus.Invalid);
            var input = JsonSerializer.Deserialize(job.Definition.InputJson, CapacityMeasurementJson.Default.CapacityMeasurementInput);
            if (input is null || input.ProposedProfileHash != approvedProfileHash || !CapacityProfileCodec.Hash(input.WorkloadHash)
                || !CapacityProfileCodec.Hash(input.SourceSnapshotHash) || input.Reads is <= 0 or > 1000) return Empty(CapacityJobStatus.Conflict);
            if (job.ProgressJson == "{}") return new(CapacityJobStatus.Succeeded, false, 0, null, null, null,
                input.WorkloadHash, input.SourceSnapshotHash, approvedProfileHash, "not-assessed");
            var progress = JsonSerializer.Deserialize(job.ProgressJson, CapacityMeasurementJson.Default.CapacityMeasurementProgress);
            if (progress is null || progress.WorkloadHash != input.WorkloadHash || progress.SourceSnapshotHash != input.SourceSnapshotHash
                || progress.ProposedProfileHash != input.ProposedProfileHash
                || progress.CompletedReads < 0 || progress.CompletedReads > input.Reads || progress.Histogram is not { Length: 32 }
                || progress.Histogram.Any(n => n < 0) || progress.Histogram.Sum(n => (long)n) != progress.CompletedReads
                || progress.TotalReadMicros < 0 || progress.MaximumReadMicros < 0 || progress.MaximumReadMicros > progress.TotalReadMicros)
                return Empty(CapacityJobStatus.Conflict);
            long p95 = 0; var cumulative = 0;
            for (var index = 0; index < 32; index++)
            {
                cumulative += progress.Histogram[index];
                if (cumulative * 100 >= progress.CompletedReads * 95)
                { p95 = index == 31 ? progress.MaximumReadMicros : Math.Min(progress.MaximumReadMicros, 1L << index); break; }
            }
            cancellationToken.ThrowIfCancellationRequested();
            return new(CapacityJobStatus.Succeeded, job.State == CapacityJobState.Succeeded && progress.CompletedReads == input.Reads,
                progress.CompletedReads, progress.CompletedReads == 0 ? null : (progress.TotalReadMicros / progress.CompletedReads).ToString(CultureInfo.InvariantCulture),
                progress.MaximumReadMicros.ToString(CultureInfo.InvariantCulture), p95.ToString(CultureInfo.InvariantCulture),
                progress.WorkloadHash, progress.SourceSnapshotHash, approvedProfileHash, "not-assessed");
        }
        catch (JsonException) { return Empty(CapacityJobStatus.Conflict); }
    }
    private static CapacityMeasurementReport Empty(CapacityJobStatus status) => new(status, false, 0, null, null, null, null, null, null, "not-assessed");
}
