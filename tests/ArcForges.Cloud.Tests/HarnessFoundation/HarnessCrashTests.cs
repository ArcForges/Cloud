// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Infrastructure;
using Xunit;

namespace ArcForges.Cloud.Tests.HarnessFoundation;

/// <summary>
/// Crash injection at every fenced write of one effect run (claim 1, reserve 2, dispatch intent 3, outcome 4, yield 5), each killed
/// just before and just after its commit. The process restarts as a new executor after the lease expires, and the wake must settle
/// the run without ever repeating an effect: a supplier call is made only after its dispatch intent is durable, and an intent without an
/// outcome is recorded as unknown, never dispatched again.
/// </summary>
public sealed class HarnessCrashTests
{
    private static readonly EffectRequest Request = new(EffectKind.ModelCall, "model.call", "digest.crash-matrix", HarnessFixture.Pin, 1024, 100, 0);

    /// <param name="write">The fenced write that crashes: 1 claim, 2 reserve, 3 dispatch intent, 4 outcome, 5 yield.</param>
    /// <param name="after">True when the crash happens after the write committed; false when it happens before.</param>
    /// <param name="resume">The name of the resume kind the restarted executor must report.</param>
    /// <param name="suppliedCalls">The supplier calls the first process made; the restarted process never calls the supplier.</param>
    /// <param name="countedSteps">The counted steps that committed: the claim 3, a reservation 5 (its state read and four batches with the outbound
    /// fetch), the wake 6 (its wait cycle, container call, claim and reads), a resumed outcome 1 and a yield 1 (BudgetDefinition).</param>
    /// <param name="subrequests">The subrequests that committed: the same charges, without the wait cycle and the retry.</param>
    [Theory]
    [InlineData(1, false, "NothingOpen", 0, 7, 6)]
    [InlineData(1, true, "NothingOpen", 0, 10, 9)]
    [InlineData(2, false, "NothingOpen", 0, 10, 9)]
    [InlineData(2, true, "ReleasedBeforeDispatch", 0, 16, 15)]
    [InlineData(3, false, "ReleasedBeforeDispatch", 0, 16, 15)]
    [InlineData(3, true, "UnknownEffectRecorded", 0, 16, 15)]
    [InlineData(4, false, "UnknownEffectRecorded", 1, 16, 15)]
    [InlineData(4, true, "NothingOpen", 1, 15, 14)]
    [InlineData(5, false, "NothingOpen", 1, 15, 14)]
    [InlineData(5, true, "NothingOpen", 1, 16, 15)]
    public async Task ACrashAtAFencedWriteNeverRepeatsAnEffectAndTheWakeSettlesTheRun(int write, bool after, string resume, int suppliedCalls, int countedSteps, int subrequests)
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var firstSupplier = new FakeEffects();
        var crashing = new CrashingPlanPort(fixture.Port, write, after);
        var first = new HarnessExecutor(new D1HarnessStore(crashing), firstSupplier, fixture.Ids, fixture.Clock);

        var crashed = false;
        try
        {
            var claimed = await first.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
            if (claimed.Claim is { } claim)
            {
                await first.RunEffectAsync(claim, Request, LoopBounds.Default, T.Ct);
                await first.YieldAsync(claim, RunState.Waiting, T.Ct);
            }
        }
        catch (SimulatedCrash)
        {
            crashed = true;
        }

        Assert.True(crashed, "the crash point must be reached");
        Assert.Equal(suppliedCalls, firstSupplier.Count);

        // The dead process's lease expires; a new process wakes the run.
        fixture.Clock.AdvanceSeconds(61);
        var secondSupplier = new FakeEffects();
        var restarted = new HarnessExecutor(fixture.Store, secondSupplier, fixture.Ids, fixture.Clock);
        var wake = await new HarnessWakeHandler(restarted).HandleAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);

        Assert.Equal(WakeStatus.Settled, wake.Status);
        Assert.Equal(resume, wake.Resume?.ToString());
        Assert.Equal(0, secondSupplier.Count);
        Assert.Equal(suppliedCalls, firstSupplier.Count);
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
        Assert.Equal("3", await fixture.RunStateAsync());

        var counters = await fixture.BudgetAsync();
        Assert.Equal(countedSteps, counters.CountedSteps);
        Assert.Equal(subrequests, counters.Subrequests);
    }

    [Fact]
    public async Task AFreshProcessCannotClaimWhileTheCrashedLeaseIsStillLive()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var crashing = new CrashingPlanPort(fixture.Port, 1, after: true);
        var first = new HarnessExecutor(new D1HarnessStore(crashing), new FakeEffects(), fixture.Ids, fixture.Clock);
        await Assert.ThrowsAsync<SimulatedCrash>(() => first.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct));

        // The lease committed before the crash and is live for its full term: a second process is refused until it expires.
        var second = new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock);
        Assert.Equal(ClaimStatus.Refused, (await second.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Status);
        fixture.Clock.AdvanceSeconds(60);
        Assert.Equal(ClaimStatus.Claimed, (await second.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Status);
    }

    [Fact]
    public async Task ACrashedDispatchIntentWithNoOutcomeIsRecordedAsUnknownWhenTheRunResumes()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var supplier = new FakeEffects();
        var crashing = new CrashingPlanPort(fixture.Port, 4, after: false);
        var first = new HarnessExecutor(new D1HarnessStore(crashing), supplier, fixture.Ids, fixture.Clock);
        var claim = (await first.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        await Assert.ThrowsAsync<SimulatedCrash>(() => first.RunEffectAsync(claim, Request, LoopBounds.Default, T.Ct));
        Assert.Equal(1, supplier.Count);

        var before = await fixture.QueryAsync("SELECT state FROM task_attempt WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal("2", before[0][0]);

        fixture.Clock.AdvanceSeconds(61);
        var resumed = new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock);
        var claimed = (await resumed.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        var result = await resumed.ResumeAsync(claimed, T.Ct);
        Assert.Equal(ResumeKind.UnknownEffectRecorded, result.Kind);
        var after = await fixture.QueryAsync("SELECT state, failure_class, effect_certainty FROM task_attempt WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal("4|5|3", after[0][0] + "|" + after[0][1] + "|" + after[0][2]);
        Assert.Equal(1, supplier.Count);
    }

    /// <summary>
    /// Crash injection at the lease renewal, a fenced write the effect matrix above does not reach. The first effect runs at claim time
    /// (writes 1 to 4); after 20 seconds the second effect renews the lease first (write 5), so a crash there is at the renewal.
    /// </summary>
    /// <param name="after">True when the crash happens after the renewal committed; false when it happens before.</param>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ACrashDuringLeaseRenewalAfterAnEffectNeverRepeatsItAndTheWakeSettlesTheRun(bool after)
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var firstSupplier = new FakeEffects();
        var crashing = new CrashingPlanPort(fixture.Port, 5, after);
        var first = new HarnessExecutor(new D1HarnessStore(crashing), firstSupplier, fixture.Ids, fixture.Clock);

        var claim = (await first.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        Assert.Equal(EffectStepStatus.Succeeded, (await first.RunEffectAsync(claim, Request, LoopBounds.Default, T.Ct)).Status);

        fixture.Clock.AdvanceSeconds(20);
        await Assert.ThrowsAsync<SimulatedCrash>(() => first.RunEffectAsync(claim, Request, LoopBounds.Default, T.Ct));
        Assert.Equal(5, crashing.Writes);
        Assert.Equal("task.harness-executor-renew", crashing.CrashedPlanId);
        Assert.Equal(1, firstSupplier.Count);

        // The lease lasts at most 60 seconds past the renewal, so a restarted process claims it after 61 more seconds.
        fixture.Clock.AdvanceSeconds(61);
        var secondSupplier = new FakeEffects();
        var restarted = new HarnessExecutor(fixture.Store, secondSupplier, fixture.Ids, fixture.Clock);
        var wake = await new HarnessWakeHandler(restarted).HandleAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);

        Assert.Equal(WakeStatus.Settled, wake.Status);
        Assert.Equal(ResumeKind.NothingOpen, wake.Resume);
        Assert.Equal(0, secondSupplier.Count);
        Assert.Equal(1, firstSupplier.Count);
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
        Assert.Equal("3", await fixture.RunStateAsync());
        // Claim 3 and the reservation 5, the renewal (1, written only when it committed), the wake's claim 6 and its yield 1.
        Assert.Equal(new BudgetCounters(after ? 16 : 15, after ? 15 : 14, 1, 0), await fixture.BudgetAsync());
    }

    /// <summary>
    /// Crash injection at the checkpoint (write 5, after the first effect's outcome). A crash before the commit stores no receipt
    /// reference; a crash after it stores one. Either way the completed effect is never dispatched again and the run settles.
    /// </summary>
    /// <param name="after">True when the crash happens after the checkpoint committed; false when it happens before.</param>
    /// <param name="receiptIsNull">The SQL null test of the stored receipt reference after the crash: "1" when none is stored.</param>
    [Theory]
    [InlineData(false, "1")]
    [InlineData(true, "0")]
    public async Task ACrashAtACheckpointStoresTheReferenceAllOrNothingAndNeverRepeatsAnEffect(bool after, string receiptIsNull)
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var firstSupplier = new FakeEffects();
        var crashing = new CrashingPlanPort(fixture.Port, 5, after);
        var first = new HarnessExecutor(new D1HarnessStore(crashing), firstSupplier, fixture.Ids, fixture.Clock);
        var claim = (await first.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        Assert.Equal(EffectStepStatus.Succeeded, (await first.RunEffectAsync(claim, Request, LoopBounds.Default, T.Ct)).Status);

        var receipt = SHA256.HashData(Encoding.UTF8.GetBytes("harness.checkpoint.crash-matrix"));
        await Assert.ThrowsAsync<SimulatedCrash>(() => new D1HarnessStore(crashing).CheckpointAsync(claim.Fence, Guid.NewGuid(), receipt, fixture.Clock.Micros(), T.Ct));
        Assert.Equal("task.harness-executor-checkpoint", crashing.CrashedPlanId);
        Assert.Equal(1, firstSupplier.Count);

        var stored = await fixture.QueryAsync("SELECT last_iteration_receipt IS NULL FROM task_run WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal(receiptIsNull, stored[0][0]);

        fixture.Clock.AdvanceSeconds(61);
        var secondSupplier = new FakeEffects();
        var restarted = new HarnessExecutor(fixture.Store, secondSupplier, fixture.Ids, fixture.Clock);
        var wake = await new HarnessWakeHandler(restarted).HandleAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);

        Assert.Equal(WakeStatus.Settled, wake.Status);
        Assert.Equal(0, secondSupplier.Count);
        Assert.Equal(1, firstSupplier.Count);
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
        Assert.Equal("3", await fixture.RunStateAsync());
        // Claim 3 and the reservation 5, the checkpoint (1, written only when it committed), the wake's claim 6 and its yield 1.
        Assert.Equal(new BudgetCounters(after ? 16 : 15, after ? 15 : 14, 1, 0), await fixture.BudgetAsync());
    }
}
