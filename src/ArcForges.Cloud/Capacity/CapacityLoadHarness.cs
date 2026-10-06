// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Channels;
using ArcForges.Cloud.Modules;

namespace ArcForges.Cloud.Capacity;

internal enum CapacityLoadKind { Command, PrimaryRead, Session, Stream, SyncBootstrap, Simulation, ColdStart }
internal enum CapacityLoadStatus { Acknowledged, Refused, Unavailable, UnknownOutcome, InvariantFailure }
internal sealed record CapacityLoadCall(Guid RunId, Guid OperationId, CapacityLoadKind Kind, int SessionIndex, string WorkloadHash);
internal sealed record CapacityLoadRunAdmission(Guid RunId, Guid RealmId, CapacityLoadConfiguration Configuration,
    string ProfileHash, string WorkloadHash, string SourceSnapshotHash, CapacityAllocation VerifiedProviderLimits);
/// <summary>The actual operator activation owner authorizes the exact current approved profile,
/// verified account limits and retained run identity. Hash equality and caller parameters alone
/// never grant permission to apply load or approve the bootstrap deployment as a launch envelope.</summary>
internal interface ICapacityLoadRunAuthority
{
    Task<QuotaAuthorityStatus> AuthorizeAsync(CapacityLoadRunAdmission admission, CancellationToken cancellationToken);
}
internal sealed record CapacityLoadObservation(CapacityLoadStatus Status, bool DurableVerified = false,
    int DuplicateDebits = 0, int AcknowledgedLoss = 0, int SkippedFeedSequences = 0, bool Complete = false);

/// <summary>An adapter for an actual owned operation, not a caller success flag. The operation owns
/// current auth, immutable metadata/body fixtures and durable receipt/feed verification. Session and
/// stream calls remain active until the supplied run token is cancelled; every other call is finite.
/// No default implements an unavailable producer as success.</summary>
internal interface ICapacityLoadOperation
{
    CapacityLoadKind Kind { get; }
    Task<CapacityLoadObservation> ExecuteAsync(CapacityLoadCall call, CancellationToken cancellationToken);
}
internal sealed record CapacityLoadConnectionResult(CapacityLoadStatus Status, ICapacityLoadConnection? Connection = null);
internal interface ICapacityLoadConnection : IAsyncDisposable
{
    // The actual feed owner verifies its cursor/sequence/generation before producing observations.
    Task<CapacityLoadObservation> ObserveAsync(CancellationToken cancellationToken);
}
internal interface ICapacityLoadConnectionOperation : ICapacityLoadOperation
{
    Task<CapacityLoadConnectionResult> OpenAsync(CapacityLoadCall call, CancellationToken cancellationToken);
}

internal sealed record CapacityLoadConfiguration(int DurationSeconds, int BurstStartSeconds, int BurstSeconds,
    int ForegroundSessions, int Streams, int CommandsPerSecond, int ReadsPerSecond, int BootstrapRuns,
    int SimulatorRuns, int UnaryConcurrency, int QueueCapacity, int OperationTimeoutSeconds)
{
    internal static readonly CapacityLoadConfiguration Launch = new(3600, 1800, 60, 100, 200, 20, 50, 10, 10, 64, 128, 30);
    internal bool Valid => DurationSeconds is > 0 and <= 3600 && BurstStartSeconds >= 0 && BurstSeconds >= 0
        && BurstStartSeconds <= DurationSeconds && BurstSeconds <= DurationSeconds - BurstStartSeconds
        && ForegroundSessions is > 0 and <= 100 && Streams is >= 0 and <= 200 && CommandsPerSecond is > 0 and <= 20
        && ReadsPerSecond is > 0 and <= 50 && BootstrapRuns is >= 0 and <= 10 && SimulatorRuns is >= 0 and <= 10
        && UnaryConcurrency is > 0 and <= 64 && QueueCapacity is > 0 and <= 128 && OperationTimeoutSeconds is > 0 and <= 30;
}

internal sealed record CapacityLoadMetric(CapacityLoadKind Kind, long Offered, long Acknowledged, long Refused,
    long Unavailable, long Unknown, long QueueRejected, long InvariantFailures, string? P95UpperBoundMicros);
internal sealed record CapacityLoadReport(Guid RunId, string Status, string ProfileHash, string WorkloadHash,
    string SourceSnapshotHash, string ConfigurationHash, CapacityLoadConfiguration Configuration, int ObservedSeconds, bool FullLaunchShape,
    CapacityLoadMetric[] Metrics, string AcceptanceStatus);
[JsonSerializable(typeof(CapacityLoadConfiguration))]
[JsonSerializable(typeof(CapacityLoadReport))]
[JsonSerializable(typeof(CapacityLoadCall))]
[JsonSerializable(typeof(CapacityLoadRunIdentity))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
internal sealed partial class CapacityLoadJson : JsonSerializerContext { }

/// <summary>Bounded open-loop load orchestration. A slow system cannot silently lower the requested
/// offered rate: queue rejection and missed ticks are reported. Mutation retries belong to each
/// actual receipt-aware owner adapter, never this generic scheduler. Reports assess observations,
/// not deployment, OS isolation, paid-provider limits or whole-series acceptance.</summary>
internal sealed class CapacityLoadHarness
{
    private readonly IReadOnlyDictionary<CapacityLoadKind, ICapacityLoadOperation> operations;
    private readonly TimeProvider time;
    private readonly CapacityLoadJournal journal;
    private readonly ICapacityLoadRunAuthority authority;
    private readonly SemaphoreSlim runs = new(1, 1);
    internal CapacityLoadHarness(IEnumerable<ICapacityLoadOperation> operations, TimeProvider time, CapacityLoadJournal journal, ICapacityLoadRunAuthority authority)
    {
        this.operations = operations.ToDictionary(operation => operation.Kind);
        this.time = time;
        this.journal = journal;
        this.authority = authority;
    }

    internal async Task<CapacityLoadReport> RunAsync(Guid runId, CapacityLoadConfiguration configuration,
        string approvedProfileJson, string approvedProfileHash, Guid realmId, CapacityAllocation verifiedProviderLimits,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var configurationHash = ArcForges.Cloud.Storage.Capacity.CapacityJobCodec.Hash(
            JsonSerializer.Serialize(configuration, CapacityLoadJson.Default.CapacityLoadConfiguration));
        CapacityProfile? profile = null;
        CapacityLoadReport Empty(string status) => new(runId, status, approvedProfileHash, profile?.WorkloadHash ?? "",
            profile?.SourceSnapshotHash ?? "", configurationHash, configuration, 0, false, [], "not-assessed");
        if (runId == Guid.Empty || !configuration.Valid || !CapacityProfileCodec.TryDecode(approvedProfileJson,
            approvedProfileHash, realmId, verifiedProviderLimits, out profile)) return Empty("invalid");
        var permission = await authority.AuthorizeAsync(new(runId, realmId, configuration, approvedProfileHash,
            profile!.WorkloadHash, profile.SourceSnapshotHash, verifiedProviderLimits), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (permission != QuotaAuthorityStatus.Authorized) return Empty(permission == QuotaAuthorityStatus.Unavailable ? "producer-unavailable" : "refused");
        var required = new List<CapacityLoadKind> { CapacityLoadKind.Command, CapacityLoadKind.PrimaryRead, CapacityLoadKind.Session, CapacityLoadKind.ColdStart };
        if (configuration.Streams > 0) required.Add(CapacityLoadKind.Stream);
        if (configuration.BootstrapRuns > 0) required.Add(CapacityLoadKind.SyncBootstrap);
        if (configuration.SimulatorRuns > 0) required.Add(CapacityLoadKind.Simulation);
        if (required.Any(kind => !operations.ContainsKey(kind))
            || operations[CapacityLoadKind.Session] is not ICapacityLoadConnectionOperation
            || configuration.Streams > 0 && operations[CapacityLoadKind.Stream] is not ICapacityLoadConnectionOperation)
            return Empty("producer-unavailable");
        if (!runs.Wait(0)) return Empty("busy");
        using var active = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var persistent = CancellationTokenSource.CreateLinkedTokenSource(active.Token);
        var elapsed = Stopwatch.StartNew();
        var metrics = Enum.GetValues<CapacityLoadKind>().ToDictionary(kind => kind, kind => new Meter(kind));
        var queue = Channel.CreateBounded<CapacityLoadCall>(new BoundedChannelOptions(configuration.QueueCapacity)
        { FullMode = BoundedChannelFullMode.Wait, SingleWriter = true, SingleReader = false });
        var workers = Enumerable.Range(0, configuration.UnaryConcurrency).Select(_ => Consume()).ToArray();
        var longCalls = new List<Task>();
        var session = 0;
        CapacityLoadCall Call(CapacityLoadKind kind, int index) => new(runId, Guid.NewGuid(), kind, index, profile!.WorkloadHash);
        void Offer(CapacityLoadKind kind, int index)
        {
            var meter = metrics[kind]; meter.Offer();
            if (!queue.Writer.TryWrite(Call(kind, index))) meter.RejectQueue();
        }
        async Task Invoke(CapacityLoadCall call, CancellationToken token, bool sustained)
        {
            var meter = metrics[call.Kind]; var started = Stopwatch.GetTimestamp();
            using var bounded = CancellationTokenSource.CreateLinkedTokenSource(token);
            if (!sustained) bounded.CancelAfter(TimeSpan.FromSeconds(configuration.OperationTimeoutSeconds));
            try
            {
                await journal.RecordAsync(call, bounded.Token).ConfigureAwait(false);
                var observation = await operations[call.Kind].ExecuteAsync(call, bounded.Token).ConfigureAwait(false);
                bounded.Token.ThrowIfCancellationRequested();
                meter.Record(observation, Stopwatch.GetElapsedTime(started));
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Planned teardown of sustained calls is not acknowledged work. A timed-out
                // command could have committed: its actual owner must reconcile that identity.
                if (!sustained || !token.IsCancellationRequested) meter.Record(new(CapacityLoadStatus.UnknownOutcome), Stopwatch.GetElapsedTime(started));
            }
            catch (Exception error) when (error is HttpRequestException or IOException or TimeoutException)
            { meter.Record(new(call.Kind == CapacityLoadKind.Command ? CapacityLoadStatus.UnknownOutcome : CapacityLoadStatus.Unavailable), Stopwatch.GetElapsedTime(started)); }
        }
        async Task Consume()
        {
            try
            {
                await foreach (var call in queue.Reader.ReadAllAsync(active.Token).ConfigureAwait(false))
                    await Invoke(call, active.Token, false).ConfigureAwait(false);
            }
            catch { active.Cancel(); throw; }
        }
        async Task Sustain(CapacityLoadCall call)
        {
            var owner = (ICapacityLoadConnectionOperation)operations[call.Kind];
            var meter = metrics[call.Kind];
            var first = true;
            try
            {
                while (!persistent.IsCancellationRequested)
                {
                    if (!first) meter.Offer(); first = false;
                    using var openBudget = CancellationTokenSource.CreateLinkedTokenSource(persistent.Token);
                    openBudget.CancelAfter(TimeSpan.FromSeconds(10));
                    var started = Stopwatch.GetTimestamp();
                    await journal.RecordAsync(call, openBudget.Token).ConfigureAwait(false);
                    var opened = await owner.OpenAsync(call, openBudget.Token).ConfigureAwait(false);
                    await using var connection = opened.Connection;
                    openBudget.Token.ThrowIfCancellationRequested();
                    meter.Record(new(opened.Status == CapacityLoadStatus.Acknowledged && connection is null
                        ? CapacityLoadStatus.InvariantFailure : opened.Status), Stopwatch.GetElapsedTime(started));
                    if (opened.Status != CapacityLoadStatus.Acknowledged || connection is null)
                    {
                        await Task.Delay(TimeSpan.FromMilliseconds(250), time, persistent.Token).ConfigureAwait(false);
                        continue;
                    }
                    while (!persistent.IsCancellationRequested)
                    {
                        using var readBudget = CancellationTokenSource.CreateLinkedTokenSource(persistent.Token);
                        readBudget.CancelAfter(TimeSpan.FromSeconds(30));
                        started = Stopwatch.GetTimestamp();
                        var observation = await connection.ObserveAsync(readBudget.Token).ConfigureAwait(false);
                        readBudget.Token.ThrowIfCancellationRequested();
                        meter.Record(observation, Stopwatch.GetElapsedTime(started));
                        if (observation.Complete || observation.Status != CapacityLoadStatus.Acknowledged) break;
                        await Task.Delay(TimeSpan.FromMilliseconds(100), time, persistent.Token).ConfigureAwait(false);
                    }
                    await Task.Delay(TimeSpan.FromMilliseconds(250), time, persistent.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                if (!persistent.IsCancellationRequested) meter.Record(new(CapacityLoadStatus.Unavailable), TimeSpan.FromSeconds(30));
            }
            catch (Exception error) when (error is HttpRequestException or IOException or TimeoutException)
            { meter.Record(new(CapacityLoadStatus.Unavailable), TimeSpan.Zero); }
            catch { active.Cancel(); throw; }
        }
        try
        {
            await journal.StartAsync(new(runId, realmId, approvedProfileHash, profile!.WorkloadHash,
                profile.SourceSnapshotHash, configurationHash, configuration), active.Token).ConfigureAwait(false);
            // Prepare actual foreground owners/finite feeds first; no synthesized session or feed
            // count is reported as an opened connection. Failures remain observable per adapter.
            for (var index = 0; index < configuration.ForegroundSessions; index++)
            { metrics[CapacityLoadKind.Session].Offer(); longCalls.Add(Sustain(Call(CapacityLoadKind.Session, index))); }
            for (var index = 0; index < configuration.Streams; index++)
            { metrics[CapacityLoadKind.Stream].Offer(); longCalls.Add(Sustain(Call(CapacityLoadKind.Stream, index % configuration.ForegroundSessions))); }
            Offer(CapacityLoadKind.ColdStart, 0);
            for (var index = 0; index < configuration.BootstrapRuns; index++) Offer(CapacityLoadKind.SyncBootstrap, index);
            for (var index = 0; index < configuration.SimulatorRuns; index++) Offer(CapacityLoadKind.Simulation, index);
            var tick = 0;
            while (tick < configuration.DurationSeconds * 10)
            {
                active.Token.ThrowIfCancellationRequested();
                var due = TimeSpan.FromMilliseconds(tick * 100);
                var remaining = due - elapsed.Elapsed;
                if (remaining > TimeSpan.Zero) await Task.Delay(remaining, time, active.Token).ConfigureAwait(false);
                var burst = tick >= configuration.BurstStartSeconds * 10 && tick < (configuration.BurstStartSeconds + configuration.BurstSeconds) * 10 ? 2 : 1;
                var commands = (tick + 1) * configuration.CommandsPerSecond / 10 - tick * configuration.CommandsPerSecond / 10;
                var reads = (tick + 1) * configuration.ReadsPerSecond / 10 - tick * configuration.ReadsPerSecond / 10;
                // A scheduler stall skips overdue offers with explicit loss of offered rate,
                // rather than releasing an unbounded catch-up burst against production.
                var missed = elapsed.Elapsed - due > TimeSpan.FromMilliseconds(200);
                for (var count = 0; count < commands * burst; count++)
                    if (missed) { metrics[CapacityLoadKind.Command].Offer(); metrics[CapacityLoadKind.Command].RejectQueue(); }
                    else Offer(CapacityLoadKind.Command, session++ % configuration.ForegroundSessions);
                for (var count = 0; count < reads * burst; count++)
                    if (missed) { metrics[CapacityLoadKind.PrimaryRead].Offer(); metrics[CapacityLoadKind.PrimaryRead].RejectQueue(); }
                    else Offer(CapacityLoadKind.PrimaryRead, session++ % configuration.ForegroundSessions);
                tick++;
            }
            var untilEnd = TimeSpan.FromSeconds(configuration.DurationSeconds) - elapsed.Elapsed;
            if (untilEnd > TimeSpan.Zero) await Task.Delay(untilEnd, time, active.Token).ConfigureAwait(false);
            queue.Writer.TryComplete();
            await Task.WhenAll(workers).ConfigureAwait(false);
            persistent.Cancel(); await Task.WhenAll(longCalls).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            return new(runId, "observed", approvedProfileHash, profile!.WorkloadHash, profile.SourceSnapshotHash,
                configurationHash, configuration, configuration.DurationSeconds, configuration == CapacityLoadConfiguration.Launch,
                metrics.Values.Select(meter => meter.Snapshot()).ToArray(), "not-assessed");
        }
        finally
        {
            active.Cancel(); queue.Writer.TryComplete(); persistent.Cancel();
            // Owner adapters are cancellation-cooperative; await their lifecycle and release the
            // admission only after no operation from this run can overlap the next one.
            try
            {
                try { await Task.WhenAll(workers.Concat(longCalls)).ConfigureAwait(false); }
                catch (OperationCanceledException) { }
            }
            finally { runs.Release(); }
        }
    }

    private sealed class Meter(CapacityLoadKind kind)
    {
        private readonly object gate = new();
        private readonly long[] histogram = new long[3001]; // 10 ms buckets through 30 seconds, capped overflow.
        private long offered, acknowledged, refused, unavailable, unknown, queued, failed, observed;
        internal void Offer() { lock (gate) offered++; }
        internal void RejectQueue() { lock (gate) queued++; }
        internal void Record(CapacityLoadObservation value, TimeSpan duration)
        {
            lock (gate)
            {
                if (!Enum.IsDefined(value.Status) || value.DuplicateDebits != 0 || value.AcknowledgedLoss != 0 || value.SkippedFeedSequences != 0
                    || value.Status == CapacityLoadStatus.Acknowledged && kind == CapacityLoadKind.Command && !value.DurableVerified) failed++;
                else switch (value.Status)
                {
                    case CapacityLoadStatus.Acknowledged: acknowledged++; break;
                    case CapacityLoadStatus.Refused: refused++; break;
                    case CapacityLoadStatus.Unavailable: unavailable++; break;
                    case CapacityLoadStatus.UnknownOutcome: unknown++; break;
                    case CapacityLoadStatus.InvariantFailure: failed++; break;
                }
                observed++; histogram[Math.Min(3000, (int)Math.Ceiling(duration.TotalMilliseconds / 10))]++;
            }
        }
        internal CapacityLoadMetric Snapshot()
        {
            lock (gate)
            {
                long cumulative = 0; string? p95 = null;
                for (var index = 0; index < histogram.Length && observed > 0; index++)
                {
                    cumulative += histogram[index];
                    if (cumulative * 100 >= observed * 95)
                    { p95 = index == 3000 ? ">=30000000" : (index * 10000L).ToString(CultureInfo.InvariantCulture); break; }
                }
                return new(kind, offered, acknowledged, refused, unavailable, unknown, queued, failed, p95);
            }
        }
    }
}

/// <summary>Bounded append-only measurement intent artifact, written before dispatch. It preserves
/// every exact uncertain operation ID for owner reconciliation. It is not a business receipt or
/// security journal and never records credentials, bodies or client content. The caller owns the
/// supplied artifact stream lifetime; a file should be CreateNew under the retained run directory.</summary>
internal sealed class CapacityLoadJournal(Stream output)
{
    private const long MaximumBytes = 134217728;
    private readonly SemaphoreSlim writes = new(1, 1);
    private long written;
    private bool faulted;
    internal Task StartAsync(CapacityLoadRunIdentity identity, CancellationToken cancellationToken) =>
        WriteAsync(JsonSerializer.SerializeToUtf8Bytes(identity, CapacityLoadJson.Default.CapacityLoadRunIdentity), cancellationToken);
    internal async Task RecordAsync(CapacityLoadCall call, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var bytes = JsonSerializer.SerializeToUtf8Bytes(call, CapacityLoadJson.Default.CapacityLoadCall);
        await WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
    }
    private async Task WriteAsync(byte[] bytes, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (bytes.Length > 4096) throw new IOException("Capacity measurement identity exceeds artifact bound.");
        await writes.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (faulted) throw new IOException("Capacity measurement artifact requires a fresh stream after a failed append.");
            if (written > MaximumBytes - bytes.Length - 1) throw new IOException("Capacity measurement artifact limit reached.");
            try
            {
                await output.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
                await output.WriteAsync("\n"u8.ToArray(), cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                written += bytes.Length + 1;
            }
            catch { faulted = true; throw; }
        }
        finally { writes.Release(); }
    }
}
internal sealed record CapacityLoadRunIdentity(Guid RunId, Guid RealmId, string ProfileHash, string WorkloadHash,
    string SourceSnapshotHash, string ConfigurationHash, CapacityLoadConfiguration Configuration);
