// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Storage;
using Xunit;

namespace ArcForges.Cloud.Tests;

public sealed class JobSliceTests
{
    private const string Scope = "proof/jobs";
    private static readonly DateTimeOffset Start = new(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);

    private static (JobSliceService Jobs, FakeStorage Storage, FakeTime Time) Create()
    {
        var storage = new FakeStorage();
        var time = new FakeTime(Start);
        return (new JobSliceService(storage, time, 0), storage, time);
    }

    private static async Task<string> StartAsync(JobSliceService jobs, int total) => await jobs.StartAsync(Scope, total, T.Ct);

    private static Task<SliceResult> SliceAsync(JobSliceService jobs, string job, string? eventId = null, int items = 100, int milliseconds = 20_000) =>
        jobs.SliceAsync(Scope, job, eventId ?? T.Uuid(), items, milliseconds, T.Ct);

    [Fact]
    public void ItemAmountsAreExactCheckedInt64AboveTwoToTheFiftyThree()
    {
        Assert.Equal(4_611_686_018_427, JobSliceService.ItemAmount(0));
        Assert.True(JobSliceService.ItemAmount(1953) > 9_007_199_254_740_992L);
        Assert.Equal(4_611_686_018_427UL * 3UL, JobSliceService.ExpectedChecksum(2));
        Assert.Throws<OverflowException>(() => JobSliceService.ItemAmount(2_000_000_000));
        Assert.Equal(0UL, JobSliceService.ExpectedChecksum(0));
    }

    [Fact]
    public async Task ASliceNeverExceedsItsItemBoundAndProgressIsCheckpointedExactly()
    {
        var (jobs, storage, _) = Create();
        var job = await StartAsync(jobs, 250);
        var first = await SliceAsync(jobs, job);
        Assert.Equal(SliceState.Running, first.State);
        Assert.Equal(100, first.Processed);
        Assert.Equal(100, first.Cursor);
        Assert.False(first.JobComplete);
        Assert.Equal(JobSliceService.ExpectedChecksum(100), first.Checksum);
        Assert.Equal(100, storage.Items.Count);
        var second = await SliceAsync(jobs, job);
        Assert.Equal(200, second.Cursor);
        var third = await SliceAsync(jobs, job);
        Assert.Equal(SliceState.Complete, third.State);
        Assert.Equal(50, third.Processed);
        Assert.True(third.JobComplete);
        var status = await jobs.StatusAsync(Scope, job, T.Ct);
        Assert.NotNull(status);
        Assert.Equal(JobSliceService.ExpectedChecksum(250), status.Checksum);
        Assert.True(status.Checksum > 9_007_199_254_740_992UL);
        Assert.Equal(250, status.ItemCount);
        Assert.True(status.Matches);
        // A finished job reports completion and does nothing more.
        var done = await SliceAsync(jobs, job);
        Assert.Equal(SliceState.Complete, done.State);
        Assert.Equal(250, storage.Items.Count);
    }

    [Fact]
    public async Task TheTimeBudgetEndsASliceButAlwaysAfterAtLeastOneItem()
    {
        var (jobs, storage, time) = Create();
        var job = await StartAsync(jobs, 100);
        time.Tick = TimeSpan.FromMilliseconds(10);
        var bounded = await SliceAsync(jobs, job, milliseconds: 35);
        Assert.InRange(bounded.Processed, 1, 5);
        Assert.Equal(bounded.Processed, storage.Items.Count);
        var minimum = await SliceAsync(jobs, job, milliseconds: 1);
        Assert.Equal(1, minimum.Processed);
        time.Tick = TimeSpan.Zero;
        var rest = await SliceAsync(jobs, job);
        Assert.True(rest.JobComplete);
        Assert.Equal(100, (await jobs.StatusAsync(Scope, job, T.Ct))!.ItemCount);
    }

    [Fact]
    public async Task SliceBoundsAndJobSizeAreValidatedBeforeAnyWork()
    {
        var (jobs, storage, _) = Create();
        var job = await StartAsync(jobs, 5);
        var before = storage.Calls.Count;
        foreach (var (items, milliseconds) in new[] { (0, 1000), (101, 1000), (10, 0), (10, 20_001) })
            await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => SliceAsync(jobs, job, items: items, milliseconds: milliseconds));
        Assert.Equal(before, storage.Calls.Count);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => jobs.StartAsync(Scope, 0, T.Ct));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => jobs.StartAsync(Scope, 1001, T.Ct));
        Assert.Equal(new SliceResult(SliceState.NotFound, 0, 0, 0, 0, false), await SliceAsync(jobs, T.Uuid()));
        Assert.Null(await jobs.StatusAsync(Scope, T.Uuid(), T.Ct));
    }

    [Fact]
    public async Task ADuplicateEventNeverRepeatsItsEffect()
    {
        var (jobs, storage, _) = Create();
        var job = await StartAsync(jobs, 250);
        var eventId = T.Uuid();
        var first = await SliceAsync(jobs, job, eventId, items: 10);
        Assert.Equal(10, first.Cursor);
        var repeat = await SliceAsync(jobs, job, eventId, items: 10);
        Assert.Equal(SliceState.Duplicate, repeat.State);
        Assert.Equal(10, repeat.Cursor);
        Assert.False(repeat.JobComplete);
        Assert.Equal(10, storage.Items.Count);
        Assert.Equal(1, storage.Executions("foundation.job-claim"));
    }

    [Fact]
    public async Task TheCommitStopsARepeatedEventThatSlipsPastTheEarlyCheck()
    {
        var (jobs, storage, _) = Create();
        var job = await StartAsync(jobs, 20);
        var shared = T.Uuid();
        // Another delivery of the same event commits between this slice's early check and its commit.
        storage.Before = call =>
        {
            if (call.Plan.Id == "foundation.job-claim") storage.Inbox.Add((Scope, shared, 0));
            return Task.CompletedTask;
        };
        var result = await SliceAsync(jobs, job, shared, items: 5);
        Assert.Equal(SliceState.Duplicate, result.State);
        Assert.Empty(storage.Items);
        Assert.Equal(0, storage.Jobs[(Scope, job)].Cursor);
    }

    [Fact]
    public async Task AStaleHolderCannotFinalizeAfterTakeover()
    {
        var (jobs, storage, _) = Create();
        var job = await StartAsync(jobs, 50);
        var key = (Scope, job);
        var taken = false;
        storage.Before = call =>
        {
            if (call.Plan.Id == "foundation.job-commit" && !taken)
            {
                taken = true;
                // Another holder takes the job over between this holder's claim and its commit.
                storage.Jobs[key] = storage.Jobs[key] with { Owner = "other", Fence = storage.Jobs[key].Fence + 1 };
            }

            return Task.CompletedTask;
        };
        var result = await SliceAsync(jobs, job, items: 10);
        Assert.Equal(SliceState.Stale, result.State);
        Assert.Empty(storage.Items);
        Assert.Equal(0, storage.Jobs[key].Cursor);
        Assert.Empty(storage.Inbox);
    }

    [Fact]
    public async Task ALiveLeaseOfAnotherHolderIsBusyUntilItExpires()
    {
        var (jobs, storage, time) = Create();
        var job = await StartAsync(jobs, 20);
        var key = (Scope, job);
        var until = SessionService.Micros(Start.AddSeconds(60));
        storage.Jobs[key] = storage.Jobs[key] with { Owner = "other", Until = until, Fence = 3 };
        var busy = await SliceAsync(jobs, job, items: 5);
        Assert.Equal(SliceState.Busy, busy.State);
        Assert.Equal(0, busy.Cursor);
        Assert.Empty(storage.Items);
        time.Advance(TimeSpan.FromSeconds(61));
        var taken = await SliceAsync(jobs, job, items: 5);
        Assert.Equal(SliceState.Running, taken.State);
        Assert.Equal(4, taken.Fence);
        Assert.Equal(5, taken.Cursor);
    }

    [Fact]
    public async Task ARestartedProcessResumesFromTheCheckpointWithTheIdenticalChecksum()
    {
        var (first, storage, time) = Create();
        var job = await StartAsync(first, 250);
        Assert.Equal(100, (await SliceAsync(first, job)).Cursor);
        // A new process has a new lease owner and no memory of the previous one.
        var restarted = new JobSliceService(storage, time, 0);
        var second = await SliceAsync(restarted, job);
        Assert.Equal(200, second.Cursor);
        Assert.Equal(SliceState.Complete, (await SliceAsync(restarted, job)).State);
        var status = await restarted.StatusAsync(Scope, job, T.Ct);
        Assert.Equal(JobSliceService.ExpectedChecksum(250), status!.Checksum);
        Assert.Equal(250, status.ItemCount);
        Assert.True(status.Matches);
        Assert.Equal(250, storage.Items.Count);
    }

    [Fact]
    public async Task AFailureOfTheStorageIsPropagatedNotSwallowed()
    {
        var (jobs, storage, _) = Create();
        var job = await StartAsync(jobs, 20);
        storage.Fault = call => call.Plan.Id == "foundation.job-commit" ? PlanFailureKind.UnknownOutcome : null;
        var failure = await Assert.ThrowsAsync<PlanFailureException>(() => SliceAsync(jobs, job, items: 5));
        Assert.Equal(PlanFailureKind.UnknownOutcome, failure.Kind);
    }
}
