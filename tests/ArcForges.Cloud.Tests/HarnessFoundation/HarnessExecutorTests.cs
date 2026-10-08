// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Infrastructure;
using Xunit;

namespace ArcForges.Cloud.Tests.HarnessFoundation;

/// <summary>The executor over the real Task plans on the SQLite oracle: claim and fencing, renewal, effects, retries, guards and wake.</summary>
public sealed class HarnessExecutorTests
{
    private static EffectRequest ModelRequest(PinnedSnapshot? pin = null, int maxOutputTokens = 1024) =>
        new(EffectKind.ModelCall, "model.call", "digest.step-1", pin ?? HarnessFixture.Pin, maxOutputTokens, 100, 0);

    private static HarnessExecutor Executor(HarnessFixture fixture, FakeEffects effects, IModulePlanPort? port = null) =>
        new(new D1HarnessStore(port ?? fixture.Port), effects, fixture.Ids, fixture.Clock);

    [Fact]
    public async Task TheFirstClaimHoldsEpochOneAndALiveSecondClaimIsRefused()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var first = await Executor(fixture, effects).ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
        Assert.Equal(ClaimStatus.Claimed, first.Status);
        Assert.Equal(1, first.Epoch);
        Assert.Equal("2", await fixture.RunStateAsync());

        var second = await Executor(fixture, effects).ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
        Assert.Equal(ClaimStatus.Refused, second.Status);
        Assert.Null(second.Claim);
    }

    [Fact]
    public async Task AClaimOfAnotherGenerationOrAMissingRunIsRefusedWithoutAWrite()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = Executor(fixture, new FakeEffects());
        Assert.Equal(ClaimStatus.StaleGeneration, (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(generation: 2), T.Ct)).Status);
        var missing = new HarnessRun(HarnessFixture.WorkspaceId, Guid.Parse("00000000-0000-4000-8000-00000000ffff"));
        var missingIdentity = new RunIdentity(missing.RunId, "cloud.build.1", "worker.v1", 1, HarnessFixture.Pin);
        Assert.Equal(ClaimStatus.NotFound, (await executor.ClaimAsync(missing, missingIdentity, T.Ct)).Status);
        Assert.Equal("1", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task AnExpiredLeaseIsTakenOverWithAStrictlyNewerEpochAndTheOldHolderIsFenced()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var old = await Executor(fixture, effects).ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
        var oldClaim = old.Claim!;

        fixture.Clock.AdvanceSeconds(61);
        var replacement = await Executor(fixture, effects).ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
        Assert.Equal(ClaimStatus.Claimed, replacement.Status);
        Assert.Equal(2, replacement.Epoch);

        // The old holder can neither renew nor reserve: its fence no longer matches the lease, and the database guard refuses it.
        Assert.False(await Executor(fixture, effects).RenewIfDueAsync(oldClaim, T.Ct));
        var reserve = await fixture.Store.ReserveStepAsync(oldClaim.Fence, Reserve(fixture, oldClaim.Fence), T.Ct);
        Assert.Equal(StoreStatus.Refused, reserve);
        Assert.Equal(new BudgetCounters(6, 6, 0, 0), await fixture.BudgetAsync());
    }

    [Fact]
    public async Task ARenewalIsWrittenOnlyWhenDueAndExtendsTheLease()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = Executor(fixture, new FakeEffects());
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        var initial = claim.ExpiresAtMicros;

        fixture.Clock.AdvanceSeconds(19);
        Assert.True(await executor.RenewIfDueAsync(claim, T.Ct));
        Assert.Equal(initial, claim.ExpiresAtMicros);

        fixture.Clock.AdvanceSeconds(1);
        Assert.True(await executor.RenewIfDueAsync(claim, T.Ct));
        Assert.True(claim.ExpiresAtMicros > initial);
        var stored = await fixture.QueryAsync("SELECT expires_at FROM task_execution_lease WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal(claim.ExpiresAtMicros.ToString(System.Globalization.CultureInfo.InvariantCulture), stored[0][0]);
    }

    [Fact]
    public async Task ALostLeaseStopsRenewalAndEveryEffect()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var executor = Executor(fixture, effects);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        fixture.Clock.AdvanceSeconds(61);
        var result = await executor.RunEffectAsync(claim, ModelRequest(), LoopBounds.Default, T.Ct);
        Assert.Equal(EffectStepStatus.NotDispatched, result.Status);
        Assert.Equal(NotDispatchedReason.LeaseLost, result.Reason);
        Assert.Equal(0, effects.Count);
        Assert.Equal(new BudgetCounters(3, 3, 0, 0), await fixture.BudgetAsync());
    }

    [Fact]
    public async Task ASuccessfulModelCallIsReservedDispatchedAndRecordedWithItsCounters()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var executor = Executor(fixture, effects);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;

        var result = await executor.RunEffectAsync(claim, ModelRequest(), LoopBounds.Default, T.Ct);
        Assert.Equal(EffectStepStatus.Succeeded, result.Status);
        Assert.Equal(1, result.Attempts);
        Assert.Equal(1, effects.Count);
        Assert.Equal(new BudgetCounters(8, 8, 1, 0), await fixture.BudgetAsync());
        var attempt = await fixture.QueryAsync("SELECT state, failure_class, effect_certainty FROM task_attempt WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal("3|NULL|2", Flat(attempt));
        var command = await fixture.QueryAsync("SELECT state, result_ref FROM task_execution_command WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal("outcome|{\"ref\":\"result.ok\"}", Flat(command));
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
    }

    [Fact]
    public async Task ARefusalBeforeDispatchIsRetriedAtMostTwiceWithAFreshAttemptIdentity()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        effects.Answer(new EffectResult(EffectResultKind.RefusedBeforeDispatch, null));
        effects.Answer(new EffectResult(EffectResultKind.RefusedBeforeDispatch, null));
        var executor = Executor(fixture, effects);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;

        var result = await executor.RunEffectAsync(claim, ModelRequest(), LoopBounds.Default, T.Ct);
        Assert.Equal(EffectStepStatus.Succeeded, result.Status);
        Assert.Equal(3, result.Attempts);
        Assert.Equal(3, effects.Count);
        Assert.Equal(3, effects.Calls.Select(call => call.AttemptId).Distinct().Count());
        Assert.Single(effects.Calls.Select(call => call.CommandId).Distinct());
        Assert.Equal(new BudgetCounters(18, 16, 3, 0), await fixture.BudgetAsync());
        var attempts = await fixture.QueryAsync("SELECT attempt_ordinal, state FROM task_attempt WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "' ORDER BY attempt_ordinal");
        Assert.Equal("1|4;2|4;3|3", Flat(attempts));
    }

    [Fact]
    public async Task ARefusalAfterTheLastRetryIsSettledAsRefusedWithNoFourthCall()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        for (var index = 0; index < 3; index++) effects.Answer(new EffectResult(EffectResultKind.RefusedBeforeDispatch, null));
        var executor = Executor(fixture, effects);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;

        var result = await executor.RunEffectAsync(claim, ModelRequest(), LoopBounds.Default, T.Ct);
        Assert.Equal(EffectStepStatus.RefusedExhausted, result.Status);
        Assert.Equal(3, effects.Count);
        var command = await fixture.QueryAsync("SELECT state FROM task_execution_command WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal("refused", Flat(command));
    }

    [Fact]
    public async Task AnUnknownEffectIsRecordedAndNeverRetried()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        effects.Answer(new EffectResult(EffectResultKind.Unknown, null));
        var executor = Executor(fixture, effects);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;

        var result = await executor.RunEffectAsync(claim, ModelRequest(), LoopBounds.Default, T.Ct);
        Assert.Equal(EffectStepStatus.UnknownEffect, result.Status);
        Assert.Equal(1, effects.Count);
        var attempt = await fixture.QueryAsync("SELECT state, failure_class, effect_certainty FROM task_attempt WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal("4|5|3", Flat(attempt));
    }

    [Fact]
    public async Task ACallThatRaisesAfterSendingIsAnUnknownEffectAndIsNotRetried()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects { Throws = true };
        var executor = Executor(fixture, effects);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;

        var result = await executor.RunEffectAsync(claim, ModelRequest(), LoopBounds.Default, T.Ct);
        Assert.Equal(EffectStepStatus.UnknownEffect, result.Status);
        Assert.Equal(1, effects.Count);
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
    }

    [Fact]
    public async Task ADefinitiveFailureWithoutAnEffectIsSettledWithoutRetry()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        effects.Answer(new EffectResult(EffectResultKind.FailedDidNotHappen, null));
        var executor = Executor(fixture, effects);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;

        var result = await executor.RunEffectAsync(claim, ModelRequest(), LoopBounds.Default, T.Ct);
        Assert.Equal(EffectStepStatus.FailedDidNotHappen, result.Status);
        Assert.Equal(1, effects.Count);
        var attempt = await fixture.QueryAsync("SELECT state, failure_class, effect_certainty FROM task_attempt WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal("4|2|1", Flat(attempt));
    }

    [Fact]
    public async Task APinMismatchIsRefusedBeforeAnyWriteOrCall()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var executor = Executor(fixture, effects);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;

        var other = new PinnedSnapshot("model.beta", "tariff.2026-10");
        var result = await executor.RunEffectAsync(claim, ModelRequest(pin: other), LoopBounds.Default, T.Ct);
        Assert.Equal(NotDispatchedReason.PinRefused, result.Reason);
        Assert.Equal(0, effects.Count);
        Assert.Equal(new BudgetCounters(3, 3, 0, 0), await fixture.BudgetAsync());
    }

    [Fact]
    public async Task ARequestOutsideTheModelCapsIsRefusedBeforeAnyWrite()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var executor = Executor(fixture, effects);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;

        var result = await executor.RunEffectAsync(claim, ModelRequest(maxOutputTokens: 4097), LoopBounds.Default, T.Ct);
        Assert.Equal(NotDispatchedReason.RequestOutsideCaps, result.Reason);
        Assert.Equal(0, effects.Count);
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
    }

    [Fact]
    public async Task TheEffectGuardPausesAtTwentyFourThousandStepsWithoutAnyWrite()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var executor = Executor(fixture, effects);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        await fixture.ExecAsync("UPDATE task_harness_budget SET counted_steps = 23995 WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "';");

        Assert.Equal(EffectStepStatus.Succeeded, (await executor.RunEffectAsync(claim, ModelRequest(), LoopBounds.Default, T.Ct)).Status);
        Assert.Equal(new BudgetCounters(24_000, 8, 1, 0), await fixture.BudgetAsync());

        var paused = await executor.RunEffectAsync(claim, ModelRequest(), LoopBounds.Default, T.Ct);
        Assert.Equal(NotDispatchedReason.BudgetPausedAtEffectGuard, paused.Reason);
        Assert.Equal(1, effects.Count);
        Assert.Equal(new BudgetCounters(24_000, 8, 1, 0), await fixture.BudgetAsync());
    }

    [Fact]
    public async Task TheSubrequestStopRefusesAnEffectBeforeAnyWrite()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var executor = Executor(fixture, effects);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        await fixture.ExecAsync("UPDATE task_harness_budget SET subrequests = 899997 WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "';");

        var result = await executor.RunEffectAsync(claim, ModelRequest(), LoopBounds.Default, T.Ct);
        Assert.Equal(NotDispatchedReason.BudgetSubrequestStop, result.Reason);
        Assert.Equal(0, effects.Count);
        Assert.Equal(new BudgetCounters(3, 899_997, 0, 0), await fixture.BudgetAsync());
    }

    [Fact]
    public async Task ANarrowedModelCallBoundStopsTheSecondCall()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var executor = Executor(fixture, effects);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        var bounds = LoopBounds.Narrow(modelCalls: 1, toolInvocations: 64, toolParallelism: 4);

        Assert.Equal(EffectStepStatus.Succeeded, (await executor.RunEffectAsync(claim, ModelRequest(), bounds, T.Ct)).Status);
        var second = await executor.RunEffectAsync(claim, ModelRequest(), bounds, T.Ct);
        Assert.Equal(NotDispatchedReason.BudgetModelCallCap, second.Reason);
        Assert.Equal(1, effects.Count);
    }

    [Fact]
    public async Task ALostLeaseBeforeTheOutcomeLeavesTheEffectUnknownAndNeverRepeatsIt()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var executorA = Executor(fixture, effects);
        var executorB = Executor(fixture, effects);
        var claimA = (await executorA.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;

        // While A is in the call, its lease expires and B takes the run over.
        effects.DuringCall = async _ =>
        {
            fixture.Clock.AdvanceSeconds(61);
            var takeover = await executorB.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
            Assert.Equal(ClaimStatus.Claimed, takeover.Status);
        };

        var result = await executorA.RunEffectAsync(claimA, ModelRequest(), LoopBounds.Default, T.Ct);
        // The supplier was called, so the step is not NotDispatched: its outcome was refused under a stale fence and is not recorded.
        Assert.Equal(EffectStepStatus.OutcomeNotRecorded, result.Status);
        Assert.Equal(NotDispatchedReason.StoreRefused, result.Reason);
        Assert.Equal(1, effects.Count);

        fixture.Clock.AdvanceSeconds(61);
        var wake = await new HarnessWakeHandler(executorB).HandleAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
        Assert.Equal(WakeStatus.Settled, wake.Status);
        Assert.Equal(ResumeKind.UnknownEffectRecorded, wake.Resume);
        Assert.Equal(1, effects.Count);
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
        var attempt = await fixture.QueryAsync("SELECT state, failure_class, effect_certainty FROM task_attempt WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal("4|5|3", Flat(attempt));
    }

    [Fact]
    public async Task ACheckpointIsWrittenOnlyUnderTheLiveFenceAndReadBack()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = Executor(fixture, new FakeEffects());
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        var receipt = Enumerable.Range(0, 32).Select(index => (byte)index).ToArray();

        Assert.Equal(StoreStatus.Succeeded, await fixture.Store.CheckpointAsync(claim.Fence, Guid.NewGuid(), receipt, fixture.Clock.Micros(), T.Ct));
        var snapshot = await fixture.Store.LoadAsync(fixture.Run, T.Ct);
        Assert.Equal(receipt, snapshot!.LastReceipt);

        var stale = claim.Fence with { Holder = Guid.NewGuid() };
        Assert.Equal(StoreStatus.Refused, await fixture.Store.CheckpointAsync(stale, Guid.NewGuid(), receipt, fixture.Clock.Micros(), T.Ct));
    }

    [Fact]
    public async Task AYieldReleasesTheLeaseSoTheNextClaimIsNewerAndTheRunIsWaiting()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = Executor(fixture, new FakeEffects());
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;

        Assert.Equal(StoreStatus.Succeeded, await executor.YieldAsync(claim, RunState.Waiting, T.Ct));
        Assert.Equal("3", await fixture.RunStateAsync());
        Assert.False(await executor.RenewIfDueAsync(claim, T.Ct));
        var next = await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
        Assert.Equal(ClaimStatus.Claimed, next.Status);
        Assert.Equal(2, next.Epoch);
    }

    [Fact]
    public async Task ARunCannotBeYieldedBackToQueuedOrRunning()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = Executor(fixture, new FakeEffects());
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => executor.YieldAsync(claim, RunState.Queued, T.Ct));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => executor.YieldAsync(claim, RunState.Running, T.Ct));
    }

    [Fact]
    public async Task AWakeClaimsResumesAndReleasesToWaitingAndTheNextWakeIsNewer()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var wake = new HarnessWakeHandler(Executor(fixture, new FakeEffects()));
        var first = await wake.HandleAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
        Assert.Equal(WakeStatus.Settled, first.Status);
        Assert.Equal(ResumeKind.NothingOpen, first.Resume);
        Assert.Equal(RunState.Waiting, first.ReleasedTo);

        var second = await wake.HandleAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
        Assert.Equal(WakeStatus.Settled, second.Status);
        var epoch = await fixture.QueryAsync("SELECT epoch FROM task_execution_lease WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal("2", Flat(epoch));
    }

    [Fact]
    public async Task TheRunIdentityIsBoundIntoEveryDispatchIntent()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var executor = Executor(fixture, effects);
        var first = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(worker: "worker.v1"), T.Ct)).Claim!;
        await executor.RunEffectAsync(first, ModelRequest(), LoopBounds.Default, T.Ct);
        await executor.YieldAsync(first, RunState.Waiting, T.Ct);

        var second = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(worker: "worker.v2"), T.Ct)).Claim!;
        await executor.RunEffectAsync(second, ModelRequest(), LoopBounds.Default, T.Ct);

        var digests = await fixture.QueryAsync("SELECT request_sha256 FROM task_execution_command WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "' ORDER BY created_at");
        Assert.Equal(2, digests.Count);
        Assert.NotEqual(digests[0][0], digests[1][0]);
        Assert.Equal(64, digests[0][0]!.Length);
    }

    /// <summary>Rows as text, one row per ';' and one cell per '|' (a NULL cell reads as NULL), for exact assertions.</summary>
    private static string Flat(List<string?[]> rows) =>
        string.Join(";", rows.Select(row => string.Join("|", row.Select(cell => cell ?? "NULL"))));

    private static ReserveCommand Reserve(HarnessFixture fixture, Fence fence) => new(
        fixture.Ids.NewId(),
        fixture.Ids.NewId(),
        fixture.Ids.NewId(),
        fixture.Ids.NewId(),
        1,
        "model.call",
        new string('a', 64),
        EffectCost.ModelCall,
        BudgetPolicy.EffectStepGuard,
        BudgetPolicy.EffectSubrequestStop,
        LoopBounds.DefaultModelCalls,
        LoopBounds.DefaultToolInvocations,
        fixture.Clock.Micros(),
        HarnessFixture.Pin);
}
