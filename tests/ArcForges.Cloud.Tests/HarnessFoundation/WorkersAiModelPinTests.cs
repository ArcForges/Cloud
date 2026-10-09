// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Infrastructure;
using ArcForges.Cloud.Modules.Task.Harness.HelloSlice.Application;
using ArcForges.Cloud.Modules.Task.Harness.HelloSlice.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.HarnessFoundation;

/// <summary>
/// A Workers AI model identifier starts with '@cf/' and is pinned like any other model (HAR.40 validation (f)). These tests run the claim,
/// the wake and the Hello slice under the real identifier, so a pin that refused '@' would fail here and not only in the proof.
/// </summary>
public sealed class WorkersAiModelPinTests
{
    private const string WorkersAiModel = "@cf/openai/gpt-oss-20b";

    private static readonly PinnedSnapshot WorkersAiPin = new(WorkersAiModel, "tariff.2026-10");

    [Fact]
    public void AWorkersAiModelIdentifierIsAPinnedSnapshot()
    {
        Assert.True(WorkersAiPin.IsPinned);
        Assert.True(WorkersAiPin.Matches(WorkersAiPin));
        Assert.False(new PinnedSnapshot("@cf/openai/gpt-oss-20b ", "tariff.2026-10").IsPinned);
        Assert.False(new PinnedSnapshot("@cf/openai/gpt-oss-20b\n", "tariff.2026-10").IsPinned);
    }

    [Fact]
    public async Task TheFirstClaimUnderAWorkersAiPinStoresThePinOnTheRun()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock);

        var claimed = await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(pin: WorkersAiPin), T.Ct);

        Assert.Equal(ClaimStatus.Claimed, claimed.Status);
        Assert.Equal(WorkersAiPin, (await fixture.Store.LoadAsync(fixture.Run, T.Ct))!.Pin);
    }

    [Fact]
    public async Task AWakeUnderTheStoredWorkersAiPinIsTakenAndNotRefused()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var effects = new FakeEffects();
        var executor = new HarnessExecutor(fixture.Store, effects, fixture.Ids, fixture.Clock);
        var first = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(pin: WorkersAiPin), T.Ct)).Claim!;
        Assert.Equal(StoreStatus.Succeeded, await executor.YieldAsync(first, RunState.Waiting, T.Ct));

        var wake = await new HarnessWakeHandler(executor).HandleAsync(fixture.Run, HarnessFixture.Identity(pin: WorkersAiPin), T.Ct);

        Assert.Equal(WakeStatus.Settled, wake.Status);
        Assert.NotEqual(ClaimStatus.PinRefused, wake.Claim);
        Assert.Equal(0, effects.Count);
    }

    [Fact]
    public async Task AWakeUnderAChangedWorkersAiTariffIsStillRefused()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock);
        var first = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(pin: WorkersAiPin), T.Ct)).Claim!;
        Assert.Equal(StoreStatus.Succeeded, await executor.YieldAsync(first, RunState.Waiting, T.Ct));

        var wake = await new HarnessWakeHandler(executor).HandleAsync(
            fixture.Run,
            HarnessFixture.Identity(pin: new PinnedSnapshot(WorkersAiModel, "tariff.2026-11")),
            T.Ct);

        Assert.Equal(WakeStatus.NotClaimed, wake.Status);
        Assert.Equal(ClaimStatus.PinRefused, wake.Claim);
    }

    [Fact]
    public async Task TheHelloSliceRunsAgainstTheWorkersAiPinAndCallsOnlyThatModel()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        models.Snapshots[WorkersAiModel] = new ModelSnapshot(WorkersAiModel, "tariff.2026-10");
        var slice = new HelloAgentSlice(
            new D1HarnessStore(fixture.Port),
            models,
            fixture.Ids,
            fixture.Clock,
            HelloModelSettings.Deployed,
            TimeSpan.FromHours(1));

        var result = await slice.RunAsync(fixture.Run, HarnessFixture.Identity(pin: WorkersAiPin), "Ada", T.Ct);

        Assert.Equal(HelloStatus.Succeeded, result.Status);
        Assert.Equal("ok", result.Reason);
        Assert.Equal(2, models.Calls.Count);
        Assert.All(models.Calls, call =>
        {
            Assert.Equal(WorkersAiModel, call.ModelId);
            Assert.Equal("tariff.2026-10", call.TariffSnapshotId);
        });
    }

    [Fact]
    public async Task TheHelloSliceRefusesAWorkersAiRunWhenTheSnapshotIsMissing()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        var slice = new HelloAgentSlice(
            new D1HarnessStore(fixture.Port),
            models,
            fixture.Ids,
            fixture.Clock,
            HelloModelSettings.Deployed,
            TimeSpan.FromHours(1));

        var result = await slice.RunAsync(fixture.Run, HarnessFixture.Identity(pin: WorkersAiPin), "Ada", T.Ct);

        Assert.Equal(HelloStatus.Refused, result.Status);
        Assert.Equal("snapshot_missing", result.Reason);
        Assert.Empty(models.Calls);
        Assert.Equal("1", await fixture.RunStateAsync());
    }
}
