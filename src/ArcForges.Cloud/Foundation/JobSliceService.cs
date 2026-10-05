// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Ingress;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Foundation;

internal enum SliceState
{
    Running,
    Complete,
    Duplicate,
    Busy,
    Stale,
    NotFound,
}

internal sealed record JobRecord(long Total, long Cursor, long Fence, string? LeaseOwner, long? LeaseUntil, string State, ulong Checksum, long Revision)
{
    public bool IsComplete => State == "complete";
}

internal sealed record SliceResult(SliceState State, long Cursor, int Processed, long Fence, ulong Checksum, bool JobComplete);

internal sealed record JobStatus(string State, long Total, long Cursor, long Fence, ulong Checksum, long ItemCount, long ItemSum, ulong ExpectedChecksum)
{
    /// <summary>Stored cursor, checksum, item count and item sum all equal what C# computes independently of storage.</summary>
    public bool Matches => Checksum == ExpectedChecksum && ItemCount == Cursor && ItemSum >= 0 && (ulong)ItemSum == ExpectedChecksum;
}

/// <summary>
/// A finite checkpointed job: each slice claims a lease with a monotonic fence, generates a bounded number of
/// deterministic items from the stored cursor and commits items, cursor, checksum, inbox row and outbox row in one
/// guarded batch. A stale holder, a replayed event or an expired lease can never finalize a slice twice.
/// </summary>
internal sealed class JobSliceService(IPlanExecutor executor, TimeProvider time, ulong recoveryGeneration)
{
    public const long ItemUnit = 4_611_686_018_427;
    public const long LeaseMicroseconds = 60_000_000;
    public const int MaxItemsPerSlice = 100;
    public const int MaxMillisecondsPerSlice = 20_000;
    public const int MaxTotal = 1000;

    private readonly string owner = Guid.NewGuid().ToString("D");

    /// <summary>Item n (0-based) is (n + 1) * 4611686018427 as an exact checked int64. With at most 1000 items no single item reaches 2^53; the running sum passes it from the 63rd item on.</summary>
    public static long ItemAmount(long n) => checked((n + 1) * ItemUnit);

    /// <summary>The checked uint64 sum of the first <paramref name="count"/> items, independent of storage.</summary>
    public static ulong ExpectedChecksum(long count)
    {
        ulong sum = 0;
        for (long n = 0; n < count; n++) sum = checked(sum + (ulong)ItemAmount(n));
        return sum;
    }

    public async Task<string> StartAsync(string scope, int total, CancellationToken cancellationToken)
    {
        if (total is < 1 or > MaxTotal) throw new ArgumentOutOfRangeException(nameof(total));
        var jobId = Guid.NewGuid().ToString("D");
        var payload = JsonSerializer.Serialize(new JobStartedPayload(jobId, total.ToString(CultureInfo.InvariantCulture)), FoundationJsonContext.Default.JobStartedPayload);
        await Execute(PlanManifest.Foundation.JobStart, scope, cancellationToken,
            [D1Values.Text(scope), D1Values.Text(jobId), D1Values.Int64(total)],
            [D1Values.Text(scope), D1Values.Text(Guid.NewGuid().ToString("D")), D1Values.Text("job.started"), D1Values.Text(payload)]);
        return jobId;
    }

    public async Task<JobRecord?> LoadAsync(string scope, string jobId, CancellationToken cancellationToken)
    {
        var result = await Execute(PlanManifest.Foundation.JobLoad, scope, cancellationToken, [D1Values.Text(scope), D1Values.Text(jobId)]);
        if (result.Rows.Count == 0) return null;
        var row = result.Rows[0];
        long? leaseUntil = null;
        string? leaseOwner = null;
        var valid = D1Values.TryGetInt64(row[0], out var total) & D1Values.TryGetInt64(row[1], out var cursor) & D1Values.TryGetInt64(row[2], out var fence)
            & D1Values.TryGetText(row[5], out var state) & D1Values.TryGetUint64(row[6], out var checksum) & D1Values.TryGetInt64(row[7], out var revision);
        if (D1Values.TryGetText(row[3], out var ownerText)) leaseOwner = ownerText;
        else if (!D1Values.IsNull(row[3])) valid = false;
        if (D1Values.TryGetInt64(row[4], out var until)) leaseUntil = until;
        else if (!D1Values.IsNull(row[4])) valid = false;
        if (!valid) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        return new JobRecord(total, cursor, fence, leaseOwner, leaseUntil, state, checksum, revision);
    }

    public async Task<JobStatus?> StatusAsync(string scope, string jobId, CancellationToken cancellationToken)
    {
        if (await LoadAsync(scope, jobId, cancellationToken) is not { } job) return null;
        var items = await Execute(PlanManifest.Foundation.JobItems, scope, cancellationToken, [D1Values.Text(scope), D1Values.Text(jobId)]);
        if (items.Rows.Count != 1 || !D1Values.TryGetInt64(items.Rows[0][0], out var count) || !D1Values.TryGetInt64(items.Rows[0][1], out var sum))
            throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        return new JobStatus(job.State, job.Total, job.Cursor, job.Fence, job.Checksum, count, sum, ExpectedChecksum(job.Cursor));
    }

    /// <summary>One bounded slice: at most 100 items and 20 seconds, and always at least one item so progress is guaranteed.</summary>
    public async Task<SliceResult> SliceAsync(string scope, string jobId, string eventId, int maxItems, int maxMilliseconds, CorrelationContext correlation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(correlation);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxItems, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxItems, MaxItemsPerSlice);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxMilliseconds, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxMilliseconds, MaxMillisecondsPerSlice);
        var started = time.GetTimestamp();
        var seen = await Execute(PlanManifest.Foundation.InboxSeen, scope, cancellationToken,
            [D1Values.Text(scope), D1Values.Text(eventId), D1Values.Int64((long)recoveryGeneration)]);
        if (seen.Rows.Count != 1 || !D1Values.TryGetInt64(seen.Rows[0][0], out var seenCount)) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        if (seenCount != 0) return await ReportAsync(scope, jobId, SliceState.Duplicate, cancellationToken);
        var job = await LoadAsync(scope, jobId, cancellationToken);
        if (job is null) return new SliceResult(SliceState.NotFound, 0, 0, 0, 0, false);
        if (job.IsComplete) return await ReportAsync(scope, jobId, SliceState.Complete, cancellationToken);

        try
        {
            var claim = Guid.NewGuid().ToString("D");
            await Execute(PlanManifest.Foundation.JobClaim, scope, cancellationToken,
                [D1Values.Text(claim), D1Values.Text(scope), D1Values.Text(jobId), D1Values.Int64(Now()), D1Values.Text(owner)],
                [D1Values.Text(owner), D1Values.Int64(Now() + LeaseMicroseconds), D1Values.Text(scope), D1Values.Text(jobId)],
                [D1Values.Text(claim)]);
        }
        catch (PlanFailureException failure) when (failure.Kind == PlanFailureKind.Precondition)
        {
            return await ReportAsync(scope, jobId, SliceState.Busy, cancellationToken);
        }

        job = await LoadAsync(scope, jobId, cancellationToken);
        if (job is null || job.LeaseOwner != owner) return await ReportAsync(scope, jobId, SliceState.Busy, cancellationToken);
        if (job.IsComplete || job.Cursor >= job.Total) return await ReportAsync(scope, jobId, SliceState.Complete, cancellationToken);

        var items = new StringBuilder("[");
        var checksum = job.Checksum;
        var cursor = job.Cursor;
        var processed = 0;
        while (cursor < job.Total && processed < maxItems)
        {
            var amount = ItemAmount(cursor);
            checksum = checked(checksum + (ulong)amount);
            if (processed > 0) items.Append(',');
            items.Append("{\"n\":\"").Append(cursor.ToString(CultureInfo.InvariantCulture)).Append("\",\"a\":\"")
                .Append(amount.ToString(CultureInfo.InvariantCulture)).Append("\"}");
            cursor++;
            processed++;
            if (time.GetElapsedTime(started).TotalMilliseconds >= maxMilliseconds) break;
        }

        items.Append(']');
        var payload = JsonSerializer.Serialize(
            new JobSlicePayload(jobId, cursor.ToString(CultureInfo.InvariantCulture), processed.ToString(CultureInfo.InvariantCulture),
                correlation.CorrelationId, correlation.CausationId ?? ""),
            FoundationJsonContext.Default.JobSlicePayload);
        var command = Guid.NewGuid().ToString("D");
        try
        {
            await Execute(PlanManifest.Foundation.JobCommit, scope, cancellationToken,
                [D1Values.Text(command), D1Values.Text(scope), D1Values.Text(jobId), D1Values.Int64(job.Fence), D1Values.Text(owner), D1Values.Int64(job.Cursor), D1Values.Int64(Now())],
                [D1Values.Text(scope), D1Values.Text(jobId), D1Values.Text(items.ToString())],
                [D1Values.Int64(cursor), D1Values.Uint64(checksum), D1Values.Int64(cursor), D1Values.Text(scope), D1Values.Text(jobId), D1Values.Int64(job.Fence)],
                [D1Values.Text(scope), D1Values.Text(eventId), D1Values.Int64((long)recoveryGeneration)],
                [D1Values.Text(scope), D1Values.Text(command), D1Values.Text("job.slice"), D1Values.Text(payload)],
                [D1Values.Text(command)]);
        }
        catch (PlanFailureException failure) when (failure.Kind == PlanFailureKind.Precondition)
        {
            return await ReportAsync(scope, jobId, SliceState.Stale, cancellationToken);
        }
        catch (PlanFailureException failure) when (failure.Kind == PlanFailureKind.Constraint)
        {
            return await ReportAsync(scope, jobId, SliceState.Duplicate, cancellationToken);
        }

        var complete = cursor >= job.Total;
        return new SliceResult(complete ? SliceState.Complete : SliceState.Running, cursor, processed, job.Fence, checksum, complete);
    }

    private async Task<SliceResult> ReportAsync(string scope, string jobId, SliceState state, CancellationToken cancellationToken)
    {
        var job = await LoadAsync(scope, jobId, cancellationToken);
        return job is null
            ? new SliceResult(SliceState.NotFound, 0, 0, 0, 0, false)
            : new SliceResult(state, job.Cursor, 0, job.Fence, job.Checksum, job.IsComplete);
    }

    private long Now() => SessionService.Micros(time.GetUtcNow());

    private Task<PlanResult> Execute(PlanDefinition plan, string scope, CancellationToken cancellationToken, params D1Scalar[][] arguments) =>
        executor.ExecuteAsync(PlanCall.New(plan, scope, recoveryGeneration, arguments), cancellationToken);
}
