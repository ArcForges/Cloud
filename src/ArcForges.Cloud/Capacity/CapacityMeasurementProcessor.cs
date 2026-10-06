// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using ArcForges.Cloud.Modules;

namespace ArcForges.Cloud.Capacity;

internal sealed class CapacityProcessingRefusedException : Exception { }
internal sealed record CapacityMeasurementInput(string WorkloadHash, string SourceSnapshotHash, string ProposedProfileHash, int Reads);
internal sealed record CapacityMeasurementProgress(string WorkloadHash, string SourceSnapshotHash, string ProposedProfileHash, int CompletedReads,
    long TotalReadMicros, long MaximumReadMicros, int[] Histogram);
[JsonSerializable(typeof(CapacityMeasurementInput))]
[JsonSerializable(typeof(CapacityMeasurementProgress))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
internal sealed partial class CapacityMeasurementJson : JsonSerializerContext { }

/// <summary>A real bounded primary-read measurement workload over the owned production job adapter.
/// It records observed latency only, not achieved paid-launch throughput or an invented business
/// result. D1 checkpoint/lease/receipts remain the same production path as every other typed job.</summary>
internal sealed class CapacityMeasurementProcessor(ICapacityJobPort jobs, TimeProvider time) : ICapacityJobProcessor
{
    public string JobType => "capacity.measurement";
    public async Task<CapacityJobSlice> ProcessAsync(CapacityJobSnapshot job, CapacityJobLease lease, int maximumItems,
        TimeSpan budget, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (maximumItems is <= 0 or > 100 || budget <= TimeSpan.Zero || budget > TimeSpan.FromSeconds(20)
            || job.Definition.JobType != JobType || job.Definition.Owner.Kind != "capacity.measurement") throw new CapacityProcessingRefusedException();
        CapacityMeasurementInput input;
        CapacityMeasurementProgress progress;
        try
        {
            input = JsonSerializer.Deserialize(job.Definition.InputJson, CapacityMeasurementJson.Default.CapacityMeasurementInput)
                ?? throw new CapacityProcessingRefusedException();
            if (!Hash(input.WorkloadHash) || !Hash(input.SourceSnapshotHash) || !Hash(input.ProposedProfileHash) || input.Reads is <= 0 or > 1000) throw new CapacityProcessingRefusedException();
            progress = job.ProgressJson == "{}" ? new(input.WorkloadHash, input.SourceSnapshotHash, input.ProposedProfileHash, 0, 0, 0, new int[32])
                : JsonSerializer.Deserialize(job.ProgressJson, CapacityMeasurementJson.Default.CapacityMeasurementProgress)
                    ?? throw new CapacityProcessingRefusedException();
            if (progress.WorkloadHash != input.WorkloadHash || progress.SourceSnapshotHash != input.SourceSnapshotHash || progress.ProposedProfileHash != input.ProposedProfileHash
                || progress.CompletedReads < 0 || progress.CompletedReads > input.Reads || progress.TotalReadMicros < 0
                || progress.MaximumReadMicros < 0 || progress.MaximumReadMicros > progress.TotalReadMicros
                || progress.Histogram is not { Length: 32 } || progress.Histogram.Any(n => n < 0)
                || progress.Histogram.Sum(n => (long)n) != progress.CompletedReads) throw new CapacityProcessingRefusedException();
        }
        catch (JsonException) { throw new CapacityProcessingRefusedException(); }
        var elapsed = Stopwatch.StartNew();
        var count = 0;
        while (progress.CompletedReads < input.Reads && count < maximumItems && elapsed.Elapsed < budget)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (Now() >= lease.LeasedUntilMicros) throw new CapacityProcessingRefusedException();
            var started = Stopwatch.GetTimestamp();
            var read = await jobs.ReadAsync(job.Definition.Owner, job.Definition.JobId, cancellationToken).ConfigureAwait(false);
            if (read.Status != CapacityJobStatus.Succeeded || read.Job is null || read.Job.State != CapacityJobState.Leased
                || read.Job.Fence != lease.Fence || read.Job.Holder != lease.Holder || read.Job.LeasedUntilMicros != lease.LeasedUntilMicros
                || Now() >= lease.LeasedUntilMicros)
                throw new CapacityProcessingRefusedException();
            var micros = Math.Max(0, checked((long)(Stopwatch.GetElapsedTime(started).TotalMilliseconds * 1000)));
            var bin = 0; while (bin < 31 && micros > (1L << bin)) bin++;
            progress.Histogram[bin]++;
            progress = progress with
            {
                CompletedReads = progress.CompletedReads + 1,
                TotalReadMicros = checked(progress.TotalReadMicros + micros),
                MaximumReadMicros = Math.Max(progress.MaximumReadMicros, micros)
            };
            count++;
        }
        cancellationToken.ThrowIfCancellationRequested();
        // Dispatcher applies the actual publication fence, current time and next wake. This processor
        // never writes an intermediate progress sample or invents a successful measurement when read fails.
        var next = checked((time.GetUtcNow().UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10 + 100000);
        return new(count, JsonSerializer.Serialize(progress, CapacityMeasurementJson.Default.CapacityMeasurementProgress),
            progress.CompletedReads == input.Reads, next);
    }
    private static bool Hash(string? value) => value is { Length: 64 } && value.All(character => character is >= '0' and <= '9' or >= 'a' and <= 'f');
    private long Now() => checked((time.GetUtcNow().UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10);
}
