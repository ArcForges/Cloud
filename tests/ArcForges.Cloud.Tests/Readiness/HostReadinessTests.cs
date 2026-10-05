// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Readiness;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests.Readiness;

/// <summary>
/// WP-21.07, host half: D1 readiness runs the named readiness plan once, and a failure is classified instead of collapsed,
/// so a plan-manifest or recovery-generation mismatch and a refused signature are reported as a misconfigured deployment,
/// never as a transient outage, and the report is ready only when its component is.
/// </summary>
public sealed class HostReadinessTests
{
    private sealed class Executor(Func<PlanCall, PlanResult> run) : IPlanExecutor
    {
        public List<string> Calls { get; } = [];

        public Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken)
        {
            Calls.Add(call.Plan.Id);
            return Task.FromResult(run(call));
        }
    }

    private static PlanResult Rows(params long[] values) => new(values.Select(value => (IReadOnlyList<D1Scalar>)[D1Values.Int64(value)]).ToArray(), 0);

    private static IPlanExecutor Failing(PlanFailureKind kind) => new Executor(_ => throw new PlanFailureException(kind));

    private static Task<ReadinessResponse> Report(IPlanExecutor executor) => new HostReadiness(executor, T.Options()).ReportAsync(T.Ct);

    [Fact]
    public async Task AHealthyReadinessPlanIsReadyAndCarriesTheHostIdentity()
    {
        var executor = new Executor(_ => Rows(1));
        var report = await Report(executor);
        Assert.True(report.Ready);
        Assert.Equal(new ReadinessComponent("ready"), report.Components.D1);
        Assert.Equal(PlanManifest.Hash, report.ManifestHash);
        Assert.Equal("1", report.SchemaVersion);
        Assert.Equal(HostRevision.Current, report.Revision);
        Assert.Equal([PlanManifest.Foundation.Readiness.Id], executor.Calls);
    }

    [Theory]
    [InlineData("ManifestMismatch", "misconfigured", "plan_hash_mismatch")]
    [InlineData("StaleGeneration", "misconfigured", "recovery_generation_mismatch")]
    [InlineData("Transport", "misconfigured", "key_mismatch")]
    [InlineData("Unavailable", "unavailable", "d1_unavailable")]
    [InlineData("Overloaded", "unavailable", "d1_unavailable")]
    [InlineData("UnknownOutcome", "unavailable", "d1_unavailable")]
    [InlineData("InvalidPlan", "unavailable", "d1_unavailable")]
    [InlineData("Constraint", "unavailable", "d1_unavailable")]
    [InlineData("Precondition", "unavailable", "d1_unavailable")]
    public async Task AFailedReadinessPlanIsClassifiedAndNeverReady(string kindName, string state, string reason)
    {
        var kind = Enum.Parse<PlanFailureKind>(kindName);
        var executor = new Executor(_ => throw new PlanFailureException(kind));
        var report = await Report(executor);
        Assert.False(report.Ready);
        Assert.Equal(new ReadinessComponent(state, reason), report.Components.D1);
        Assert.Single(executor.Calls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public async Task AnyReadinessRowOtherThanSchemaVersionOneIsAMisconfiguration(long version)
    {
        var report = await Report(new Executor(_ => version == 0 ? Rows() : Rows(version)));
        Assert.False(report.Ready);
        Assert.Equal(new ReadinessComponent("misconfigured", "schema_mismatch"), report.Components.D1);
        var twoRows = await Report(new Executor(_ => Rows(1, 1)));
        Assert.False(twoRows.Ready);
        Assert.Equal("schema_mismatch", twoRows.Components.D1.Reason);
    }

    [Fact]
    public async Task ARecoveryGenerationThatDiffersFromTheWorkersIsAMismatchNotAnOutage()
    {
        var storage = new FakeStorage { ActiveGeneration = 5 };
        var report = await new HostReadiness(storage, T.Options(generation: 0)).ReportAsync(T.Ct);
        Assert.False(report.Ready);
        Assert.Equal(new ReadinessComponent("misconfigured", "recovery_generation_mismatch"), report.Components.D1);
        var agreed = await new HostReadiness(new FakeStorage { ActiveGeneration = 5 }, T.Options(generation: 5)).ReportAsync(T.Ct);
        Assert.True(agreed.Ready);
    }

    [Fact]
    public async Task ACancelledReadinessIsNotReportedAsAnyStateAndNothingIsRetried()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        var executor = new Executor(_ => throw new OperationCanceledException());
        await Assert.ThrowsAsync<OperationCanceledException>(() => new HostReadiness(executor, T.Options()).ReportAsync(cancelled.Token));
        Assert.Single(executor.Calls);
    }

    [Fact]
    public async Task TheReportIsClosedAndCarriesNoContent()
    {
        var failed = await Report(Failing(PlanFailureKind.ManifestMismatch));
        var json = JsonSerializer.Serialize(failed, FoundationJsonContext.Default.ReadinessResponse);
        using var document = JsonDocument.Parse(json);
        Assert.Equal(["ready", "manifestHash", "schemaVersion", "revision", "components"], document.RootElement.EnumerateObject().Select(p => p.Name));
        var d1 = document.RootElement.GetProperty("components").GetProperty("d1");
        Assert.Equal(["state", "reason"], d1.EnumerateObject().Select(p => p.Name));
        Assert.Equal("misconfigured", d1.GetProperty("state").GetString());
        // A ready component omits its reason.
        var ready = JsonSerializer.Serialize(await Report(new Executor(_ => Rows(1))), FoundationJsonContext.Default.ReadinessResponse);
        using var readyDocument = JsonDocument.Parse(ready);
        Assert.Equal(["state"], readyDocument.RootElement.GetProperty("components").GetProperty("d1").EnumerateObject().Select(p => p.Name));
        Assert.DoesNotContain("SELECT", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheBoundsBehindAnUnknownOutcomeAreTheDocumentedOnes()
    {
        // A write whose storage call does not answer is an unknown outcome after the deadline plus the grace, never earlier.
        Assert.Equal(TimeSpan.FromSeconds(8), WorkerPlanExecutor.DefaultTimeout);
        Assert.Equal(TimeSpan.FromSeconds(10), WorkerPlanExecutor.MaxTimeout);
    }
}
