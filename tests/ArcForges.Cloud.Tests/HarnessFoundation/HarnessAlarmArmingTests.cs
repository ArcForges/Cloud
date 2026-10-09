// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Infrastructure;
using Xunit;

namespace ArcForges.Cloud.Tests.HarnessFoundation;

/// <summary>A crash raised by the alarm port before its arming request is sent: the process dies with nothing armed.</summary>
internal sealed class SimulatedAlarmCrash() : Exception("A simulated crash before the alarm was armed.");

/// <summary>
/// The alarm port of the tests. It records every arm and cancel in order, answers from a script (armed when no script is set), and can die
/// before it records an arm, which is the crash point before arming.
/// </summary>
internal sealed class RecordingAlarm : IHarnessAlarmPort
{
    public List<string> Events { get; } = [];

    public List<HarnessAlarmSchedule> Schedules { get; } = [];

    public Func<HarnessAlarmSchedule, HarnessAlarmReply>? Reply { get; set; }

    public bool CrashBeforeArm { get; set; }

    public bool CancelThrows { get; set; }

    public Task<HarnessAlarmReply> ScheduleAsync(HarnessAlarmSchedule schedule, CancellationToken cancellationToken)
    {
        if (CrashBeforeArm) throw new SimulatedAlarmCrash();
        Events.Add("arm");
        Schedules.Add(schedule);
        return Task.FromResult(Reply?.Invoke(schedule) ?? HarnessAlarmReply.Armed);
    }

    public Task CancelAsync(Guid workspaceId, Guid runId, CancellationToken cancellationToken)
    {
        Events.Add("cancel");
        if (CancelThrows) throw new InvalidOperationException("The cancel did not reach the alarm.");
        return Task.CompletedTask;
    }
}

/// <summary>
/// The store of the executor with its yield answered by a script. A scripted outcome commits nothing, so the run stays as the claim left it;
/// every yield is recorded in order, which proves the arm happens before the waiting commit.
/// </summary>
internal sealed class YieldScriptStore(IHarnessStore inner, List<string> events, StoreStatus? yieldOutcome = null) : IHarnessStore
{
    public Task<RunSnapshot?> LoadAsync(HarnessRun run, CancellationToken cancellationToken) => inner.LoadAsync(run, cancellationToken);

    public Task<OpenAttempt?> LoadOpenAttemptAsync(HarnessRun run, CancellationToken cancellationToken) => inner.LoadOpenAttemptAsync(run, cancellationToken);

    public Task<StoreStatus> ClaimAsync(HarnessRun run, ClaimCommand command, CancellationToken cancellationToken) => inner.ClaimAsync(run, command, cancellationToken);

    public Task<StoreStatus> RenewAsync(Fence fence, Guid guardId, long nowMicros, long expiresAtMicros, CancellationToken cancellationToken) =>
        inner.RenewAsync(fence, guardId, nowMicros, expiresAtMicros, cancellationToken);

    public Task<StoreStatus> ReserveStepAsync(Fence fence, ReserveCommand command, CancellationToken cancellationToken) => inner.ReserveStepAsync(fence, command, cancellationToken);

    public Task<StoreStatus> MarkDispatchAsync(Fence fence, Guid guardId, Guid attemptId, long nowMicros, CancellationToken cancellationToken) =>
        inner.MarkDispatchAsync(fence, guardId, attemptId, nowMicros, cancellationToken);

    public Task<StoreStatus> RecordOutcomeAsync(Fence fence, OutcomeCommand command, CancellationToken cancellationToken) => inner.RecordOutcomeAsync(fence, command, cancellationToken);

    public Task<StoreStatus> CheckpointAsync(Fence fence, Guid guardId, byte[] receiptSha256, long nowMicros, CancellationToken cancellationToken) =>
        inner.CheckpointAsync(fence, guardId, receiptSha256, nowMicros, cancellationToken);

    public Task<StoreStatus> YieldAsync(Fence fence, Guid guardId, RunState nextState, long nowMicros, CancellationToken cancellationToken)
    {
        events.Add("commit:" + nextState);
        return yieldOutcome is { } outcome
            ? Task.FromResult(outcome)
            : inner.YieldAsync(fence, guardId, nextState, nowMicros, cancellationToken);
    }
}

/// <summary>
/// The alarm arming of a parked run (HAR.40 alarm arming): the order of the arm and the waiting commit, a refused arm that does not park the
/// run, the best-effort cancel after a commit that did not commit, and the crash rows at the arm boundary. Every crash row ends with the run
/// claimed by a wake that settles it once, with no supplier call and no second advance.
/// </summary>
public sealed class HarnessAlarmArmingTests
{
    private static long WakeAtMs(HarnessFixture fixture) => fixture.Clock.Micros() / 1000 + 5_000;

    private static async Task<ClaimedRun> ClaimAsync(HarnessFixture fixture, IHarnessStore store)
    {
        var claimed = await new HarnessExecutor(store, new FakeEffects(), fixture.Ids, fixture.Clock).ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
        return Assert.IsType<ClaimedRun>(claimed.Claim);
    }

    private static Task<WakeOutcome> WakeAsync(HarnessFixture fixture, FakeEffects supplier) =>
        new HarnessWakeHandler(new HarnessExecutor(fixture.Store, supplier, fixture.Ids, fixture.Clock)).HandleAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);

    [Fact]
    public async Task TheWakeIsArmedBeforeTheWaitingCommitAndTheRunIsParkedWithItsLeaseReleased()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var events = new List<string>();
        var alarm = new RecordingAlarm();
        var claim = await ClaimAsync(fixture, fixture.Store);

        var parked = await new HarnessExecutor(new YieldScriptStore(fixture.Store, events), new FakeEffects(), fixture.Ids, fixture.Clock)
            .ParkWithTimerAsync(claim, WakeAtMs(fixture), alarm, T.Ct);

        Assert.Equal(ParkStatus.Parked, parked.Status);
        Assert.Equal(StoreStatus.Succeeded, parked.Commit);
        Assert.Equal(new[] { "arm" }, alarm.Events);
        Assert.Equal(new[] { "commit:Waiting" }, events);
        Assert.Equal(HarnessFixture.WorkspaceId, alarm.Schedules[0].WorkspaceId);
        Assert.Equal(HarnessFixture.RunId, alarm.Schedules[0].RunId);
        Assert.Equal(WakeAtMs(fixture), alarm.Schedules[0].WakeAtMs);
        Assert.True(claim.Released);
        Assert.Equal("3", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task ARefusedArmDoesNotParkTheRunAndTheRetryableWakeClaimsItAfterTheLeaseTerm()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var alarm = new RecordingAlarm { Reply = _ => HarnessAlarmReply.Refused };
        var claim = await ClaimAsync(fixture, fixture.Store);

        var parked = await new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock)
            .ParkWithTimerAsync(claim, WakeAtMs(fixture), alarm, T.Ct);

        Assert.Equal(ParkStatus.ArmRefused, parked.Status);
        Assert.Null(parked.Commit);
        Assert.Equal(new[] { "arm" }, alarm.Events);
        Assert.False(claim.Released, "the lease is left to its term; nothing was released");
        Assert.Equal("2", await fixture.RunStateAsync());

        // The typed retryable reply: a wake delivered while the lease is live is refused, not taken, and the retry settles the run.
        var early = await WakeAsync(fixture, new FakeEffects());
        Assert.Equal(WakeStatus.Stopped, early.Status);
        Assert.Equal("2", await fixture.RunStateAsync());

        fixture.Clock.AdvanceSeconds(61);
        var late = await WakeAsync(fixture, new FakeEffects());
        Assert.Equal(WakeStatus.Settled, late.Status);
        Assert.Equal("3", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task ACommitThatDidNotHappenAfterArmingCancelsTheWakeBestEffortAndDoesNotPark()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var events = new List<string>();
        var alarm = new RecordingAlarm();
        var claim = await ClaimAsync(fixture, fixture.Store);

        var parked = await new HarnessExecutor(new YieldScriptStore(fixture.Store, events, StoreStatus.Refused), new FakeEffects(), fixture.Ids, fixture.Clock)
            .ParkWithTimerAsync(claim, WakeAtMs(fixture), alarm, T.Ct);

        Assert.Equal(ParkStatus.CommitRefused, parked.Status);
        Assert.Equal(StoreStatus.Refused, parked.Commit);
        Assert.Equal(new[] { "arm", "cancel" }, alarm.Events);
        Assert.Equal(new[] { "commit:Waiting" }, events);
        Assert.False(claim.Released);
        Assert.Equal("2", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task ACancelThatFailsAfterAFailedCommitIsStillReportedAsTheFailedCommit()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var alarm = new RecordingAlarm { CancelThrows = true };
        var claim = await ClaimAsync(fixture, fixture.Store);

        var parked = await new HarnessExecutor(new YieldScriptStore(fixture.Store, [], StoreStatus.Unavailable), new FakeEffects(), fixture.Ids, fixture.Clock)
            .ParkWithTimerAsync(claim, WakeAtMs(fixture), alarm, T.Ct);

        Assert.Equal(ParkStatus.CommitRefused, parked.Status);
        Assert.Equal(new[] { "arm", "cancel" }, alarm.Events);
    }

    [Fact]
    public async Task AnUnknownCommitAfterArmingKeepsTheWakeArmedBecauseAStrayWakeIsHarmless()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var alarm = new RecordingAlarm();
        var claim = await ClaimAsync(fixture, fixture.Store);

        var parked = await new HarnessExecutor(new YieldScriptStore(fixture.Store, [], StoreStatus.Unknown), new FakeEffects(), fixture.Ids, fixture.Clock)
            .ParkWithTimerAsync(claim, WakeAtMs(fixture), alarm, T.Ct);

        Assert.Equal(ParkStatus.CommitUnknown, parked.Status);
        Assert.Equal(new[] { "arm" }, alarm.Events);
    }

    [Fact]
    public async Task AReleasedClaimArmsNothingAndWritesNothing()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var alarm = new RecordingAlarm();
        var claim = await ClaimAsync(fixture, fixture.Store);
        Assert.Equal(StoreStatus.Succeeded, await new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock).YieldAsync(claim, RunState.Waiting, T.Ct));

        var parked = await new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock).ParkWithTimerAsync(claim, WakeAtMs(fixture), alarm, T.Ct);

        Assert.Equal(ParkStatus.Released, parked.Status);
        Assert.Empty(alarm.Events);
    }

    /// <summary>
    /// The three crash rows at the arm boundary. Before arm: the process dies before any arming request, so nothing is armed and the run keeps
    /// its lease. After arm and before commit: the wake is armed and the commit never happens. After commit: the run is waiting and its lease is
    /// released before the process dies. In each row the wake that arrives later claims the run and settles it once, and no supplier is called.
    /// </summary>
    [Theory]
    [InlineData("before-arm")]
    [InlineData("after-arm-before-commit")]
    [InlineData("after-commit")]
    public async Task ACrashAtTheArmBoundaryIsRecoveredByTheWakeAndNeverAdvancesTheRunTwice(string crashPoint)
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var alarm = new RecordingAlarm { CrashBeforeArm = crashPoint == "before-arm" };
        var firstSupplier = new FakeEffects();
        // The claim is write 1 and the waiting commit is write 2 of the first process.
        var crashing = new CrashingPlanPort(fixture.Port, crashAtWrite: 2, after: crashPoint == "after-commit");
        var first = new HarnessExecutor(new D1HarnessStore(crashing), firstSupplier, fixture.Ids, fixture.Clock);
        var claim = Assert.IsType<ClaimedRun>((await first.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim);

        var crashed = false;
        try
        {
            await first.ParkWithTimerAsync(claim, WakeAtMs(fixture), alarm, T.Ct);
        }
        catch (SimulatedCrash)
        {
            crashed = true;
        }
        catch (SimulatedAlarmCrash)
        {
            crashed = true;
        }

        Assert.True(crashed, "the crash point must be reached");
        Assert.Equal(crashPoint == "before-arm" ? 0 : 1, alarm.Schedules.Count);
        Assert.Equal(crashPoint == "after-commit" ? "3" : "2", await fixture.RunStateAsync());

        // The armed alarm fires while the crashed lease may still be live: the wake is refused and retried, never taken.
        if (crashPoint == "after-arm-before-commit")
        {
            fixture.Clock.AdvanceSeconds(6);
            var refused = await WakeAsync(fixture, new FakeEffects());
            Assert.Equal(WakeStatus.Stopped, refused.Status);
            Assert.Equal("2", await fixture.RunStateAsync());
        }

        // The lease of the dead process expires within its term; the wake then claims the run.
        fixture.Clock.AdvanceSeconds(61);
        var secondSupplier = new FakeEffects();
        var wake = await WakeAsync(fixture, secondSupplier);

        Assert.Equal(WakeStatus.Settled, wake.Status);
        Assert.Equal("3", await fixture.RunStateAsync());
        Assert.Equal(0, secondSupplier.Count);
        Assert.Equal(0, firstSupplier.Count);
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());

        // A second wake for the waiting run dispatches nothing and leaves the run waiting.
        var again = await WakeAsync(fixture, new FakeEffects());
        Assert.Equal(WakeStatus.Settled, again.Status);
        Assert.Equal("3", await fixture.RunStateAsync());
    }
}
