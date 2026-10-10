// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Readiness;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests.Readiness;

/// <summary>
/// WP-21.07, host half (CLOUD.84 S39(1)): D1 readiness runs the named readiness plan once, and a failure is classified instead of collapsed,
/// so a plan-manifest or recovery-generation mismatch and a refused signature are reported as a misconfigured deployment, never as a
/// transient outage. The whole report is judged from the Worker's observations, and it is ready only when every required component is.
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

    private static Task<ReadinessReport> Report(IPlanExecutor executor) => new HostReadiness(executor, T.Options()).ReportAsync(ObservationsOfAHealthyWorker(), T.Ct);

    /// <summary>What a Worker whose every declared binding is met and whose probes answered forwards.</summary>
    private static ReadinessObservations ObservationsOfAHealthyWorker() => new(
        ReadinessVocabulary.Proof,
        "0123456789abcdef0123456789abcdef01234567",
        PlanManifest.Hash,
        ReadinessVocabulary.Bindings.ToDictionary(binding => binding.Name, _ => true),
        new ReadinessProbe("ready", 3),
        new ReadinessProbe("ready", 3));

    [Fact]
    public async Task AHealthyReadinessPlanIsReadyAndCarriesTheHostIdentity()
    {
        var executor = new Executor(_ => Rows(1));
        var report = await new HostReadiness(executor, T.Options()).ReportAsync(ObservationsOfAHealthyWorker(), T.Ct);
        Assert.True(report.Ready);
        Assert.Equal("ready", report.Status);
        Assert.Equal(new ReadinessComponent("ready", null, "probed"), report.Components.D1);
        Assert.NotNull(report.Host);
        Assert.Equal(PlanManifest.Hash, report.Host.ManifestHash);
        Assert.Equal("1", report.Host.SchemaVersion);
        Assert.Equal(HostRevision.Current, report.Host.Revision);
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
        var report = await new HostReadiness(executor, T.Options()).ReportAsync(ObservationsOfAHealthyWorker(), T.Ct);
        Assert.False(report.Ready);
        Assert.Equal(state, report.Status);
        Assert.Equal(new ReadinessComponent(state, reason, "probed"), report.Components.D1);
        Assert.Single(executor.Calls);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(2)]
    public async Task AnyReadinessRowOtherThanSchemaVersionOneIsAMisconfiguration(long version)
    {
        var report = await new HostReadiness(new Executor(_ => version == 0 ? Rows() : Rows(version)), T.Options()).ReportAsync(ObservationsOfAHealthyWorker(), T.Ct);
        Assert.False(report.Ready);
        Assert.Equal(new ReadinessComponent("misconfigured", "schema_mismatch", "probed"), report.Components.D1);
        var twoRows = await new HostReadiness(new Executor(_ => Rows(1, 1)), T.Options()).ReportAsync(ObservationsOfAHealthyWorker(), T.Ct);
        Assert.False(twoRows.Ready);
        Assert.Equal("schema_mismatch", twoRows.Components.D1.Reason);
    }

    [Fact]
    public async Task ARecoveryGenerationThatDiffersFromTheWorkersIsAMismatchNotAnOutage()
    {
        var storage = new FakeStorage { ActiveGeneration = 5 };
        var report = await new HostReadiness(storage, T.Options(generation: 0)).ReportAsync(ObservationsOfAHealthyWorker(), T.Ct);
        Assert.False(report.Ready);
        Assert.Equal(new ReadinessComponent("misconfigured", "recovery_generation_mismatch", "probed"), report.Components.D1);
        var agreed = await new HostReadiness(new FakeStorage { ActiveGeneration = 5 }, T.Options(generation: 5)).ReportAsync(ObservationsOfAHealthyWorker(), T.Ct);
        Assert.True(agreed.Ready);
    }

    [Fact]
    public async Task ACancelledReadinessIsNotReportedAsAnyStateAndNothingIsRetried()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        var executor = new Executor(_ => throw new OperationCanceledException());
        await Assert.ThrowsAsync<OperationCanceledException>(() => new HostReadiness(executor, T.Options()).ReportAsync(ObservationsOfAHealthyWorker(), cancelled.Token));
        Assert.Single(executor.Calls);
    }

    [Fact]
    public async Task TheReportIsClosedAndCarriesNoContent()
    {
        var failed = await new HostReadiness(Failing(PlanFailureKind.ManifestMismatch), T.Options()).ReportAsync(ObservationsOfAHealthyWorker(), T.Ct);
        var json = JsonSerializer.Serialize(failed, FoundationJsonContext.Default.ReadinessReport);
        using var document = JsonDocument.Parse(json);
        Assert.Equal(["schema", "status", "ready", "environment", "workerRevision", "components", "host"], document.RootElement.EnumerateObject().Select(p => p.Name));
        Assert.Equal(["ingress", "container", "d1", "durableObject", "r2", "queue"], document.RootElement.GetProperty("components").EnumerateObject().Select(p => p.Name));
        var d1 = document.RootElement.GetProperty("components").GetProperty("d1");
        Assert.Equal(["state", "reason", "evidence"], d1.EnumerateObject().Select(p => p.Name));
        Assert.Equal("misconfigured", d1.GetProperty("state").GetString());
        // A ready component omits its reason and its missing list.
        var ready = await new HostReadiness(new Executor(_ => Rows(1)), T.Options()).ReportAsync(ObservationsOfAHealthyWorker(), T.Ct);
        var readyJson = JsonSerializer.Serialize(ready, FoundationJsonContext.Default.ReadinessReport);
        using var readyDocument = JsonDocument.Parse(readyJson);
        Assert.Equal(["state", "evidence"], readyDocument.RootElement.GetProperty("components").GetProperty("d1").EnumerateObject().Select(p => p.Name));
        Assert.DoesNotContain("SELECT", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("PRAGMA", json, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void TheBoundsBehindAnUnknownOutcomeAreTheDocumentedOnes()
    {
        // A write whose storage call does not answer is an unknown outcome after the deadline plus the grace, never earlier.
        Assert.Equal(TimeSpan.FromSeconds(8), WorkerPlanExecutor.DefaultTimeout);
        Assert.Equal(TimeSpan.FromSeconds(10), WorkerPlanExecutor.MaxTimeout);
    }
}
