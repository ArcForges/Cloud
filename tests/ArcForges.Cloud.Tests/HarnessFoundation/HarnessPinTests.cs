// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.HarnessFoundation;

/// <summary>
/// The model and tariff pin of a run (HAR.40 validation (f)): stored at its first claim, checked by every claim and reservation, and never
/// changed. A resume, a wake or a reservation under a different pair is refused before any dispatch.
/// </summary>
public sealed class HarnessPinTests
{
    private static readonly PinnedSnapshot Changed = new("model.alpha", "tariff.2026-11");

    [Fact]
    public async Task TheFirstClaimStoresThePinOnTheRun()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock);

        Assert.Equal(ClaimStatus.Claimed, (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Status);

        var stored = await fixture.QueryAsync("SELECT pinned_model_id, pinned_tariff_snapshot_id FROM task_harness_budget WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal("model.alpha|tariff.2026-10", Flat(stored));
        Assert.Equal(HarnessFixture.Pin, (await fixture.Store.LoadAsync(fixture.Run, T.Ct))!.Pin);
    }

    [Fact]
    public async Task AResumeUnderAChangedPinIsRefusedBeforeAnyLeaseIsTaken()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var executor = new HarnessExecutor(fixture.Store, effects, fixture.Ids, fixture.Clock);
        var first = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        Assert.Equal(StoreStatus.Succeeded, await executor.YieldAsync(first, RunState.Waiting, T.Ct));

        var refused = await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(pin: Changed), T.Ct);

        Assert.Equal(ClaimStatus.PinRefused, refused.Status);
        Assert.Null(refused.Claim);
        Assert.Equal("1", await Epoch(fixture));
        Assert.Equal(0, effects.Count);
    }

    [Fact]
    public async Task AWakeUnderAChangedPinIsNotClaimedAndDispatchesNothing()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var executor = new HarnessExecutor(fixture.Store, effects, fixture.Ids, fixture.Clock);
        var first = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        Assert.Equal(StoreStatus.Succeeded, await executor.YieldAsync(first, RunState.Waiting, T.Ct));
        var budget = await fixture.BudgetAsync();

        var wake = await new HarnessWakeHandler(executor).HandleAsync(fixture.Run, HarnessFixture.Identity(pin: Changed), T.Ct);

        Assert.Equal(WakeStatus.NotClaimed, wake.Status);
        Assert.Equal(ClaimStatus.PinRefused, wake.Claim);
        Assert.Equal("3", await fixture.RunStateAsync());
        Assert.Equal("1", await Epoch(fixture));
        Assert.Equal(budget, await fixture.BudgetAsync());
        Assert.Equal(0, effects.Count);
    }

    [Fact]
    public async Task AnUnpinnedIdentityIsRefusedAtClaim()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock);

        var unpinned = await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(pin: new PinnedSnapshot("", "tariff.2026-10")), T.Ct);

        Assert.Equal(ClaimStatus.PinRefused, unpinned.Status);
        Assert.Equal("1", await fixture.RunStateAsync());
        Assert.Equal(new BudgetCounters(0, 0, 0, 0), await fixture.BudgetAsync());
    }

    [Fact]
    public async Task TheDatabaseRefusesAReservationUnderAChangedPinEvenWhenTheExecutorCheckIsSkipped()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        var before = await fixture.BudgetAsync();

        Assert.Equal(StoreStatus.Refused, await fixture.Store.ReserveStepAsync(claim.Fence, Reserve(fixture, Changed), T.Ct));
        Assert.Equal(before, await fixture.BudgetAsync());
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());

        // The same reservation under the stored pin is accepted: the refusal above is the pin, not the request.
        Assert.Equal(StoreStatus.Succeeded, await fixture.Store.ReserveStepAsync(claim.Fence, Reserve(fixture, HarnessFixture.Pin), T.Ct));
        Assert.Equal(1, await fixture.CountOpenAttemptsAsync());
    }

    [Fact]
    public async Task AWakeChargesItsWaitCycleContainerCallAndReadsInItsClaimAndYield()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock);

        var wake = await new HarnessWakeHandler(executor).HandleAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);

        Assert.Equal(WakeStatus.Settled, wake.Status);
        // The claim 3 (claim batch and two reads), the wake's wait cycle and container call 2, the resume read 1, and the yield batch 1.
        Assert.Equal(new BudgetCounters(7, 6, 0, 0), await fixture.BudgetAsync());
    }

    private static ReserveCommand Reserve(HarnessFixture fixture, PinnedSnapshot pinned) =>
        new(
            fixture.Ids.NewId(),
            fixture.Ids.NewId(),
            fixture.Ids.NewId(),
            fixture.Ids.NewId(),
            1,
            "request-tool",
            new string('a', 64),
            BudgetDefinition.ModelAttempt(1),
            BudgetPolicy.EffectStepGuard,
            BudgetPolicy.EffectSubrequestStop,
            LoopBounds.Default.ModelCalls,
            LoopBounds.Default.ToolInvocations,
            fixture.Clock.Micros(),
            pinned);

    private static async Task<string> Epoch(HarnessFixture fixture) =>
        Flat(await fixture.QueryAsync("SELECT epoch FROM task_execution_lease WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'"));

    private static string Flat(IEnumerable<string?[]> rows) =>
        string.Join(";", rows.Select(row => string.Join("|", row.Select(value => value ?? "NULL"))));
}
