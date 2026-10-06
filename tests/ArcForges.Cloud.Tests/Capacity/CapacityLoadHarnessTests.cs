// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Capacity;
using ArcForges.Cloud.Storage.Capacity;
using ArcForges.Cloud.Modules;
using Xunit;

namespace ArcForges.Cloud.Tests.CapacityTests;

/// <summary>The actual load scheduler, bounded queue, intent journal and lifecycle are exercised.
/// Only absent full-system foreground/feed/Sync/Simulator owner adapters are external fixtures;
/// the real persistent quota command/read adapter is separately tested over actual Worker SQL.</summary>
public sealed class CapacityLoadHarnessTests
{
    private static readonly CapacityLoadConfiguration Small = new(1, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1);
    [Fact]
    public async Task DefectiveOwnerAbortsRunAndDisposesConnectionsBeforeExclusiveAdmissionIsReusable()
    {
        using var artifact = new MemoryStream(); var session = new ConnectionOperation(CapacityLoadKind.Session);
        var harness = new CapacityLoadHarness([session,
            new Operation(CapacityLoadKind.Command, new(CapacityLoadStatus.Refused)),
            new Operation(CapacityLoadKind.PrimaryRead, new(CapacityLoadStatus.Unavailable)),
            new DefectiveOperation()], TimeProvider.System, new(artifact), new RunAuthority());
        await Assert.ThrowsAsync<InvalidOperationException>(() => Run(harness, Small with { DurationSeconds = 10, Streams = 0 }));
        Assert.Equal(1, session.Disposed);
        await Assert.ThrowsAsync<InvalidOperationException>(() => Run(harness, Small with { DurationSeconds = 10, Streams = 0 }));
        Assert.Equal(2, session.Disposed);
    }

    [Fact]
    public async Task PartialArtifactWriteFencesLaterAppendsBeforeAnyOwnerCanReuseBrokenIdentityHistory()
    {
        using var stream = new InterruptedArtifact(); var journal = new CapacityLoadJournal(stream);
        var call = new CapacityLoadCall(Guid.NewGuid(), Guid.NewGuid(), CapacityLoadKind.Command, 0, new('a', 64));
        await Assert.ThrowsAsync<IOException>(() => journal.RecordAsync(call, T.Ct));
        var partialLength = stream.Length; Assert.True(partialLength > 0);
        await Assert.ThrowsAsync<IOException>(() => journal.RecordAsync(call with { OperationId = Guid.NewGuid() }, T.Ct));
        Assert.Equal(partialLength, stream.Length);
    }
    [Fact]
    public async Task CompleteOwnerAdaptersAreRequiredBeforeAnyWorkOrArtifactDispatch()
    {
        using var artifact = new MemoryStream();
        var harness = new CapacityLoadHarness([], TimeProvider.System, new(artifact), new RunAuthority());
        var report = await Run(harness, Small);
        Assert.Equal("producer-unavailable", report.Status); Assert.Empty(report.Metrics); Assert.Equal(0, artifact.Length);
        Assert.Equal("not-assessed", report.AcceptanceStatus); Assert.False(report.FullLaunchShape);
    }

    [Fact]
    public async Task OpenLoopReportsQueuePressureUnverifiedAcknowledgementAndClosesRealConnectionLifecycle()
    {
        using var artifact = new MemoryStream();
        var session = new ConnectionOperation(CapacityLoadKind.Session); var stream = new ConnectionOperation(CapacityLoadKind.Stream);
        var command = new Operation(CapacityLoadKind.Command, new(CapacityLoadStatus.Acknowledged, DurableVerified: false));
        var read = new Operation(CapacityLoadKind.PrimaryRead, new(CapacityLoadStatus.Acknowledged));
        var cold = new Operation(CapacityLoadKind.ColdStart, new(CapacityLoadStatus.Acknowledged));
        var harness = new CapacityLoadHarness([session, stream, command, read, cold], TimeProvider.System, new(artifact), new RunAuthority());
        var report = await Run(harness, Small with { CommandsPerSecond = 20, ReadsPerSecond = 50 });
        Assert.Equal("observed", report.Status); Assert.Equal(1, report.ObservedSeconds);
        var commands = report.Metrics.Single(metric => metric.Kind == CapacityLoadKind.Command);
        Assert.Equal(20, commands.Offered); Assert.True(commands.InvariantFailures > 0);
        Assert.True(report.Metrics.Sum(metric => metric.QueueRejected) > 0);
        Assert.Equal(1, session.Opened); Assert.Equal(1, session.Disposed);
        Assert.Equal(1, stream.Opened); Assert.Equal(1, stream.Disposed);
        Assert.Equal("not-assessed", report.AcceptanceStatus); Assert.False(report.FullLaunchShape);
        var lines = Encoding.UTF8.GetString(artifact.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        Assert.NotEmpty(lines);
        foreach (var line in lines)
        {
            using var document = JsonDocument.Parse(line);
            if (document.RootElement.TryGetProperty("operationId", out var operationId)) Assert.NotEqual(Guid.Empty, operationId.GetGuid());
            else Assert.Equal(report.ProfileHash, document.RootElement.GetProperty("profileHash").GetString());
            Assert.Equal(new string('a', 64), document.RootElement.GetProperty("workloadHash").GetString());
        }
        Assert.True(JsonSerializer.SerializeToUtf8Bytes(report, CapacityLoadJson.Default.CapacityLoadReport).Length > 0);
    }

    [Fact]
    public async Task CancellationAwaitsConnectionDisposalAndReleasesExclusiveRunForReuse()
    {
        using var artifact = new MemoryStream(); using var cancellation = new CancellationTokenSource();
        var session = new ConnectionOperation(CapacityLoadKind.Session);
        var harness = new CapacityLoadHarness([session,
            new Operation(CapacityLoadKind.Command, new(CapacityLoadStatus.Refused)),
            new Operation(CapacityLoadKind.PrimaryRead, new(CapacityLoadStatus.Unavailable)),
            new Operation(CapacityLoadKind.ColdStart, new(CapacityLoadStatus.Unavailable))], TimeProvider.System, new(artifact), new RunAuthority());
        var first = Run(harness, Small with { DurationSeconds = 10, Streams = 0 }, cancellation.Token);
        await session.ReadStarted.Task.WaitAsync(TimeSpan.FromSeconds(5), T.Ct);
        var busy = await Run(harness, Small with { Streams = 0 }); Assert.Equal("busy", busy.Status);
        cancellation.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(() => first);
        Assert.Equal(1, session.Disposed);
        var resumed = await Run(harness, Small with { Streams = 0 }); Assert.Equal("observed", resumed.Status);
        Assert.Equal(2, session.Disposed);
    }

    private static Task<CapacityLoadReport> Run(CapacityLoadHarness harness, CapacityLoadConfiguration configuration, CancellationToken? token = null)
    {
        var profile = CapacityProfileTests.Selected(); var json = CapacityProfileCodec.Encode(profile);
        return harness.RunAsync(Guid.NewGuid(), configuration, json, CapacityJobCodec.Hash(json), profile.RealmId,
            profile.RealmBudgets, token ?? T.Ct);
    }
    private sealed class Operation(CapacityLoadKind kind, CapacityLoadObservation observation) : ICapacityLoadOperation
    {
        public CapacityLoadKind Kind => kind;
        public Task<CapacityLoadObservation> ExecuteAsync(CapacityLoadCall call, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(observation); }
    }
    private sealed class DefectiveOperation : ICapacityLoadOperation
    {
        public CapacityLoadKind Kind => CapacityLoadKind.ColdStart;
        public Task<CapacityLoadObservation> ExecuteAsync(CapacityLoadCall call, CancellationToken cancellationToken) =>
            Task.FromException<CapacityLoadObservation>(new InvalidOperationException("Injected owner defect"));
    }
    private sealed class ConnectionOperation(CapacityLoadKind kind) : ICapacityLoadConnectionOperation
    {
        internal int Opened, Disposed;
        internal TaskCompletionSource ReadStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public CapacityLoadKind Kind => kind;
        public Task<CapacityLoadObservation> ExecuteAsync(CapacityLoadCall call, CancellationToken cancellationToken) => throw new InvalidOperationException("Connection requires owned lifecycle.");
        public Task<CapacityLoadConnectionResult> OpenAsync(CapacityLoadCall call, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Interlocked.Increment(ref Opened);
            return Task.FromResult(new CapacityLoadConnectionResult(CapacityLoadStatus.Acknowledged, new Connection(this)));
        }
        private sealed class Connection(ConnectionOperation owner) : ICapacityLoadConnection
        {
            public async Task<CapacityLoadObservation> ObserveAsync(CancellationToken cancellationToken)
            { owner.ReadStarted.TrySetResult(); await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken); return new(CapacityLoadStatus.Unavailable); }
            public ValueTask DisposeAsync() { Interlocked.Increment(ref owner.Disposed); return ValueTask.CompletedTask; }
        }
    }
    private sealed class InterruptedArtifact : MemoryStream
    {
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested(); Write(buffer.Span[..Math.Max(1, buffer.Length / 2)]);
            return ValueTask.FromException(new IOException("Injected interrupted artifact append"));
        }
    }
    private sealed class RunAuthority : ICapacityLoadRunAuthority
    {
        public Task<QuotaAuthorityStatus> AuthorizeAsync(CapacityLoadRunAdmission admission, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); var profile = CapacityProfileTests.Selected();
            return Task.FromResult(admission.RealmId == profile.RealmId && admission.WorkloadHash == profile.WorkloadHash
                && admission.SourceSnapshotHash == profile.SourceSnapshotHash && admission.VerifiedProviderLimits == profile.RealmBudgets
                && admission.ProfileHash == CapacityJobCodec.Hash(CapacityProfileCodec.Encode(profile)) && admission.Configuration.Valid
                ? QuotaAuthorityStatus.Authorized : QuotaAuthorityStatus.Denied);
        }
    }
}
