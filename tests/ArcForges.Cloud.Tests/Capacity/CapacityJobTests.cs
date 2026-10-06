// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Net;
using System.Text;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Capacity;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.Capacity;
using ArcForges.Cloud.Tests.Entitlement;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.CapacityTests;

/// <summary>Actual production job/store/receipts/Worker plans/migrations over SQLite. Only the
/// unavailable configuration/job authority and injected D1 transport faults are substituted.</summary>
public sealed class CapacityJobTests
{
    [Fact]
    public async Task ActualRecoveryAdvancesPastDefinitivelyDeniedHeadWithoutDispatchingIt()
    {
        using var h = new Harness();
        for (var index = 0; index < 13; index++) await h.Port.CreateAsync(Id(500 + index), h.Definition(400 + index), T.Ct);
        h.Authority.DeniedJobs.Add(Id(400));
        List<Guid> dispatched = []; var gate = new object();
        using var handler = new ScheduleHandler(async (request, token) =>
        {
            using var body = JsonDocument.Parse(await request.Content!.ReadAsByteArrayAsync(token));
            var id = body.RootElement.GetProperty("wake").GetProperty("jobId").GetGuid();
            lock (gate) dispatched.Add(id);
            return Receipt("scheduled");
        });
        using var scheduler = new CapacityWakeScheduler(new(handler), T.Key("c2w"), h.Port, h.Clock);
        var recovery = new CapacityRecoveryService(new CapacityJobRecoveryPort(h.Bridge, h.Bridge.Generation, h.Clock, h.Authority, ["component-job"]), scheduler);
        var first = await recovery.RunAsync(Id(600), null, T.Ct);
        Assert.Equal(CapacityJobStatus.Succeeded, first.Status); Assert.Equal(1, first.RefusedJobs); Assert.NotNull(first.Next);
        var second = await recovery.RunAsync(Id(601), first.Next, T.Ct);
        Assert.Equal(CapacityJobStatus.Succeeded, second.Status); Assert.Null(second.Next);
        Assert.Equal(12, dispatched.Count); Assert.DoesNotContain(Id(400), dispatched);
        Assert.Contains(Id(412), dispatched); Assert.Equal(13, await h.Count("platform_command"));
    }

    [Fact]
    public async Task ActualSignedPrivateWakeRunsRealMeasurementAndProducesBoundHistoricalReport()
    {
        using var h = new Harness(); var definition = h.Measurement(70, 3); await h.Port.CreateAsync(Id(71), definition, T.Ct);
        var wake = new CapacityWake(Id(72), h.Owner, definition.JobId, "capacity-" + Id(72).ToString("D"), Id(73), Id(74));
        var bytes = JsonSerializer.SerializeToUtf8Bytes(wake, CapacityHttpJson.Default.CapacityWake);
        var key = T.Key("w2c");
        using var services = new ServiceCollection().AddSingleton<TimeProvider>(h.Clock)
            .AddSingleton(new CapacityIngressOptions([key], T.Key("c2w")))
            .AddSingleton(new CapacityDispatcher(h.Port, [new CapacityMeasurementProcessor(h.Port, h.Clock)], h.Clock)).BuildServiceProvider();
        var context = Context(services, bytes, key, h.Clock, wake.WakeId);
        await CapacityEndpoints.HandleAsync(context);
        Assert.Equal(200, context.Response.StatusCode);
        using var response = JsonDocument.Parse(((MemoryStream)context.Response.Body).ToArray());
        Assert.Equal("Complete", response.RootElement.GetProperty("status").GetString());
        using var scheduler = new CapacityWakeScheduler(new(new ScheduleHandler((_, _) => Task.FromResult(Receipt("scheduled")))), T.Key("c2w"), h.Port, h.Clock);
        var harness = new CapacityMeasurementHarness(h.Port, scheduler);
        var report = await harness.ReadReportAsync(h.Owner, definition.JobId, new('c', 64), T.Ct);
        Assert.True(report.Complete); Assert.Equal(3, report.AcknowledgedReads); Assert.Equal("not-assessed", report.AcceptanceStatus);
        Assert.NotNull(report.P95UpperBoundMicros);
        Assert.Equal(CapacityJobStatus.Conflict, (await harness.ReadReportAsync(h.Owner, definition.JobId, new('d', 64), T.Ct)).Status);
        var repeated = Context(services, bytes, key, h.Clock, wake.WakeId);
        await CapacityEndpoints.HandleAsync(repeated);
        Assert.Equal(200, repeated.Response.StatusCode); Assert.Equal(3, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task PrivateWakeRefusesForgedBodiesAmbiguousJsonAndAlternateTargetsBeforeJobWork()
    {
        using var h = new Harness(); var definition = h.Measurement(80, 3); await h.Port.CreateAsync(Id(81), definition, T.Ct);
        var wake = new CapacityWake(Id(82), h.Owner, definition.JobId, "capacity-" + Id(82).ToString("D"), Id(83), Id(84));
        var valid = JsonSerializer.SerializeToUtf8Bytes(wake, CapacityHttpJson.Default.CapacityWake); var key = T.Key("w2c");
        using var services = new ServiceCollection().AddSingleton<TimeProvider>(h.Clock).AddSingleton(new CapacityIngressOptions([key], T.Key("c2w")))
            .AddSingleton(new CapacityDispatcher(h.Port, [new CapacityMeasurementProcessor(h.Port, h.Clock)], h.Clock)).BuildServiceProvider();
        var forged = Context(services, valid, key, h.Clock, wake.WakeId); forged.Request.Body = new MemoryStream("{}"u8.ToArray());
        await CapacityEndpoints.HandleAsync(forged); Assert.Equal(401, forged.Response.StatusCode);
        var duplicateText = Encoding.UTF8.GetString(valid).Replace("\"wakeId\":", "\"wakeId\":\"" + wake.WakeId.ToString("D") + "\",\"wakeId\":", StringComparison.Ordinal);
        var duplicate = Context(services, Encoding.UTF8.GetBytes(duplicateText), key, h.Clock, wake.WakeId);
        await CapacityEndpoints.HandleAsync(duplicate); Assert.Equal(400, duplicate.Response.StatusCode);
        var alternate = Context(services, valid, key, h.Clock, wake.WakeId);
        alternate.Features.Get<IHttpRequestFeature>()!.RawTarget = CapacityEndpoints.Path + "?other=true";
        await CapacityEndpoints.HandleAsync(alternate); Assert.Equal(404, alternate.Response.StatusCode);
        var large = Context(services, new byte[4097], key, h.Clock, wake.WakeId);
        await CapacityEndpoints.HandleAsync(large); Assert.Equal(413, large.Response.StatusCode);
        Assert.Equal(1, await h.Count("platform_command")); Assert.Equal(CapacityJobState.Ready, (await h.Port.ReadAsync(h.Owner, definition.JobId, T.Ct)).Job!.State);
    }

    [Fact]
    public async Task ActualSignedSchedulerRetriesSameDurableWakeAndKeepsCurrentAuthorizationBeforeDispatch()
    {
        using var h = new Harness(); var definition = h.Definition(40); await h.Port.CreateAsync(Id(41), definition, T.Ct);
        var key = T.Key("c2w"); List<string> bodies = []; List<string> nonces = [];
        using var handler = new ScheduleHandler(async (request, token) =>
        {
            var bytes = await request.Content!.ReadAsByteArrayAsync(token); bodies.Add(Encoding.UTF8.GetString(bytes));
            Assert.Equal("http://capacity.internal/internal/capacity/v1/schedule", request.RequestUri!.AbsoluteUri);
            string? Header(string name) => request.Headers.TryGetValues(name, out var values) ? values.Single() : null;
            Assert.True(PrivateRequestVerifier.Verify("POST", request.RequestUri.PathAndQuery, T.Sha256Hex(bytes), Header, [key], h.Clock.GetUtcNow(), out _));
            nonces.Add(Header("X-AF-Nonce")!);
            return bodies.Count < 3 ? new(HttpStatusCode.ServiceUnavailable) : Receipt("duplicate");
        });
        using var scheduler = new CapacityWakeScheduler(new(handler), key, h.NewPort(), h.Clock);
        var scheduled = await scheduler.ScheduleAsync(new(Id(42), h.Owner, definition.JobId, h.Now), T.Ct);
        Assert.Equal(CapacityScheduleStatus.AlreadyScheduled, scheduled.Status);
        Assert.Equal(3, bodies.Count); Assert.Single(bodies.Distinct()); Assert.Equal(3, nonces.Distinct().Count());
        h.Authority.Status = QuotaAuthorityStatus.Denied;
        Assert.Equal(CapacityScheduleStatus.Denied, (await scheduler.ScheduleAsync(new(Id(43), h.Owner, definition.JobId, h.Now), T.Ct)).Status);
        Assert.Equal(3, bodies.Count); Assert.Equal(1, await h.Count("platform_command"));
    }

    [Fact]
    public async Task SchedulerBoundsActiveAndQueuedRequestsAndShutdownDistinguishesForwardedHints()
    {
        using var h = new Harness(); var definition = h.Definition(60); await h.Port.CreateAsync(Id(61), definition, T.Ct);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously); var calls = 0;
        using var handler = new ScheduleHandler(async (_, token) =>
        {
            if (Interlocked.Increment(ref calls) == 2) entered.SetResult();
            await Task.Delay(Timeout.InfiniteTimeSpan, token); return Receipt("scheduled");
        });
        using var scheduler = new CapacityWakeScheduler(new(handler), T.Key("c2w"), h.NewPort(), h.Clock);
        Task<CapacityScheduleResult> Schedule(int id) => scheduler.ScheduleAsync(new(Id(id), h.Owner, definition.JobId, h.Now), T.Ct);
        var first = Schedule(62); var second = Schedule(63); await entered.Task.WaitAsync(TimeSpan.FromSeconds(5), T.Ct);
        var third = Schedule(64); var fourth = Schedule(65); var bridgeCalls = h.Bridge.Calls;
        Assert.Equal(CapacityScheduleStatus.Unavailable, (await Schedule(66)).Status);
        Assert.Equal(bridgeCalls, h.Bridge.Calls); Assert.Equal(2, calls);
        scheduler.Dispose();
        Assert.Equal(CapacityScheduleStatus.UnknownOutcome, (await first).Status);
        Assert.Equal(CapacityScheduleStatus.UnknownOutcome, (await second).Status);
        Assert.Equal(CapacityScheduleStatus.Unavailable, (await third).Status);
        Assert.Equal(CapacityScheduleStatus.Unavailable, (await fourth).Status);
        Assert.Equal(1, await h.Count("platform_command"));
    }

    [Fact]
    public async Task SchedulerCancellationAfterBufferedReceiptCannotBecomeSuccessOrZeroBorrowedKey()
    {
        using var h = new Harness(); var definition = h.Definition(50); await h.Port.CreateAsync(Id(51), definition, T.Ct);
        var key = T.Key("c2w"); var borrowed = key.Secret.ToArray(); using var cancellation = new CancellationTokenSource();
        CapacityWakeScheduler? scheduler = null;
        using var handler = new ScheduleHandler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StreamContent(new EndCancelledStream("{\"status\":\"scheduled\"}", () => cancellation.Cancel())),
        }));
        // Media type is the production required type; the stream intentionally ignores read tokens.
        handler.ContentType = "application/json";
        scheduler = new(new(handler), key, h.NewPort(), h.Clock);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => scheduler.ScheduleAsync(new(Id(52), h.Owner, definition.JobId, h.Now), cancellation.Token));
        scheduler.Dispose(); Assert.Equal(borrowed, key.Secret);
        Assert.Equal(CapacityScheduleStatus.Unavailable, (await scheduler.ScheduleAsync(new(Id(53), h.Owner, definition.JobId, h.Now), T.Ct)).Status);
    }

    [Fact]
    public async Task PersistentCreateReplayCompetingClaimsAndGuardedCheckpointSurviveAdapterRestart()
    {
        using var h = new Harness(); var definition = h.Definition(10); var createId = Id(11);
        Assert.Equal(CapacityJobStatus.Succeeded, (await h.Port.CreateAsync(createId, definition, T.Ct)).Status);
        Assert.Equal(CapacityJobStatus.Replayed, (await h.Port.CreateAsync(createId, definition, T.Ct)).Status);
        var outcomes = await Task.WhenAll(h.Port.ClaimAsync(new(Id(12), h.Owner, definition.JobId, "left", 0, h.Now + 30000000), T.Ct),
            h.Port.ClaimAsync(new(Id(13), h.Owner, definition.JobId, "right", 0, h.Now + 30000000), T.Ct));
        var accepted = Assert.Single(outcomes, value => value.Status == CapacityJobStatus.Succeeded).Job!;
        Assert.Single(outcomes, value => value.Status == CapacityJobStatus.Conflict);
        var lease = new CapacityJobLease(definition.JobId, accepted.Holder!, accepted.Fence, accepted.LeasedUntilMicros!.Value);
        var checkpoint = new CapacityJobCheckpoint(Id(14), h.Owner, lease, "{\"completed\":1}", CapacityJobState.Ready, h.Now + 100000);
        Assert.Equal(CapacityJobStatus.Conflict, (await h.Port.CheckpointAsync(checkpoint with { Lease = lease with { Holder = "foreign" } }, T.Ct)).Status);
        Assert.Equal(CapacityJobStatus.Succeeded, (await h.Port.CheckpointAsync(checkpoint, T.Ct)).Status);
        var restarted = h.NewPort();
        var read = await restarted.ReadAsync(h.Owner, definition.JobId, T.Ct);
        Assert.Equal(CapacityJobState.Ready, read.Job!.State); Assert.Equal("{\"completed\":1}", read.Job.ProgressJson);
        Assert.Equal(CapacityJobStatus.Replayed, (await restarted.ReconcileAsync(h.Owner, definition.JobId, checkpoint.CommandId, CapacityJobMutation.Checkpoint, T.Ct)).Status);
        Assert.Equal(CapacityJobStatus.ReusedIdentifier, (await restarted.ReconcileAsync(h.Owner, definition.JobId, checkpoint.CommandId, CapacityJobMutation.Claim, T.Ct)).Status);
        Assert.Equal(1, await h.Count("platform_job_lease")); Assert.Equal(3, await h.Count("platform_command")); Assert.Equal(3, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task LostClaimAndContinuationAcknowledgementsReconcileWithoutNewLeaseTermsOrDuplicateReadWork()
    {
        using var h = new Harness(); var definition = h.Measurement(20, 150); await h.Port.CreateAsync(Id(21), definition, T.Ct);
        var wake = new CapacityWake(Id(22), h.Owner, definition.JobId, "capacity-" + Id(22).ToString("D"), Id(23), Id(24));
        var acceptedClaim = await h.Port.ClaimAsync(new(wake.ClaimCommandId, h.Owner, definition.JobId, wake.Holder, 0, h.Now + 50000000), T.Ct);
        Assert.Equal(CapacityJobStatus.Succeeded, acceptedClaim.Status);
        // Represents a lost host response after the real atomic claim, followed by a delayed same wake.
        // The dispatcher must recover the original expiry rather than fingerprint a new expiry.
        h.Clock.SetSeconds(h.Clock.GetUtcNow().ToUnixTimeSeconds() + 1);
        var dispatcher = new CapacityDispatcher(h.NewPort(), [new CapacityMeasurementProcessor(h.NewPort(), h.Clock)], h.Clock);
        var first = await dispatcher.RunAsync(wake, T.Ct);
        Assert.Equal(CapacityDispatchStatus.Reschedule, first.Status);
        var progress = (await h.Port.ReadAsync(h.Owner, definition.JobId, T.Ct)).Job!;
        var parsed = JsonSerializer.Deserialize(progress.ProgressJson, CapacityMeasurementJson.Default.CapacityMeasurementProgress)!;
        Assert.Equal(100, parsed.CompletedReads);
        var archives = await h.Count("platform_change_archive");
        // Represents a lost checkpoint acknowledgement: repeat original wake under current state.
        var repeated = await dispatcher.RunAsync(wake, T.Ct);
        Assert.Equal(CapacityDispatchStatus.Reschedule, repeated.Status);
        Assert.Equal(progress, (await h.Port.ReadAsync(h.Owner, definition.JobId, T.Ct)).Job);
        Assert.Equal(archives, await h.Count("platform_change_archive"));
        Assert.Equal(100, parsed.Histogram.Sum());
    }

    [Fact]
    public async Task CurrentAuthorizationGenerationAndCancelledReadsDoNotExposeOrMutateAcceptedJob()
    {
        using var h = new Harness(); var definition = h.Definition(30); await h.Port.CreateAsync(Id(31), definition, T.Ct);
        h.Authority.Status = QuotaAuthorityStatus.Denied;
        Assert.Equal(CapacityJobStatus.Denied, (await h.Port.ReadAsync(h.Owner, definition.JobId, T.Ct)).Status);
        Assert.Equal(CapacityJobStatus.Denied, (await h.Port.CreateAsync(Id(31), definition, T.Ct)).Status);
        h.Authority.Status = QuotaAuthorityStatus.Authorized;
        await h.Bridge.ExecAsync($"UPDATE platform_job_lease SET payload=json_set(payload,'$.Definition.RecoveryGeneration','2') WHERE job_id='{definition.JobId:D}';", T.Ct);
        Assert.Equal(CapacityJobStatus.StaleGeneration, (await h.Port.ReadAsync(h.Owner, definition.JobId, T.Ct)).Status);
        Assert.Equal(CapacityJobStatus.StaleGeneration, (await h.Port.CreateAsync(Id(32), definition with { RecoveryGeneration = 2 }, T.Ct)).Status);
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel(); var calls = h.Bridge.Calls;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Port.ReadAsync(h.Owner, definition.JobId, cancelled.Token));
        Assert.Equal(calls, h.Bridge.Calls); Assert.Equal(1, await h.Count("platform_command"));
    }

    [Fact]
    public async Task RecoveryEnumeratesOnlyRegisteredCurrentRealmGenerationDueRowsWithBoundedKeyset()
    {
        using var h = new Harness();
        for (var index = 0; index < 13; index++) await h.Port.CreateAsync(Id(100 + index), h.Definition(200 + index), T.Ct);
        var unknown = h.Definition(300) with { JobType = "unregistered" }; h.Authority.Approved[unknown.JobId] = unknown;
        await h.Port.CreateAsync(Id(301), unknown, T.Ct);
        await h.Bridge.ExecAsync($"UPDATE platform_job_lease SET payload=json_set(payload,'$.Definition.RecoveryGeneration','2') WHERE job_id='{Id(200):D}';", T.Ct);
        await h.Bridge.ExecAsync($"UPDATE platform_job_lease SET payload=json_set(payload,'$.Definition.Owner.RealmId','{Id(999):D}') WHERE job_id='{Id(201):D}';", T.Ct);
        var recovery = new CapacityJobRecoveryPort(h.Bridge, h.Bridge.Generation, h.Clock, h.Authority, ["component-job"]);
        var first = await recovery.ReadDueAsync(null, T.Ct);
        Assert.Equal(CapacityJobStatus.Succeeded, first.Status); Assert.Equal(10, first.Jobs!.Count); Assert.NotNull(first.Next);
        var last = await recovery.ReadDueAsync(first.Next, T.Ct);
        Assert.Single(last.Jobs!); Assert.Null(last.Next);
        Assert.DoesNotContain(first.Jobs!.Concat(last.Jobs!), job => job.Definition.JobId is var id && (id == Id(200) || id == Id(201) || id == Id(300)));
        h.Authority.Status = QuotaAuthorityStatus.Unavailable;
        Assert.Equal(CapacityJobStatus.Unavailable, (await recovery.ReadDueAsync(null, T.Ct)).Status);
    }

    private static Guid Id(int number) => Guid.Parse("30000000-0000-0000-0000-" + number.ToString("D12", System.Globalization.CultureInfo.InvariantCulture));
    private static DefaultHttpContext Context(IServiceProvider services, byte[] body, SigningKey key, TimeProvider time, Guid requestId)
    {
        var context = new DefaultHttpContext { RequestServices = services, RequestAborted = T.Ct };
        context.Request.Method = "POST"; context.Request.Path = CapacityEndpoints.Path; context.Request.ContentType = "application/json";
        context.Request.ContentLength = body.Length; context.Request.Body = new MemoryStream(body); context.Response.Body = new MemoryStream();
        context.Features.Get<IHttpRequestFeature>()!.RawTarget = CapacityEndpoints.Path;
        PrivateRequestSigner.Sign("POST", CapacityEndpoints.Path, T.Sha256Hex(body), requestId.ToString("D"), key, time)
            .CopyTo((name, value) => context.Request.Headers[name] = value);
        return context;
    }
    private static HttpResponseMessage Receipt(string status) => new(HttpStatusCode.OK)
    { Content = new StringContent("{\"status\":\"" + status + "\"}", Encoding.UTF8, "application/json") };
    private sealed class ScheduleHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
    {
        internal string? ContentType;
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = await respond(request, cancellationToken);
            if (ContentType is not null) response.Content.Headers.ContentType = new(ContentType);
            return response;
        }
    }
    private sealed class EndCancelledStream(string body, Action cancel) : MemoryStream(Encoding.UTF8.GetBytes(body))
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        { var read = Read(buffer.Span); if (read == 0) cancel(); return ValueTask.FromResult(read); }
    }
    private sealed class Harness : IDisposable
    {
        internal SqliteBridgeExecutor Bridge { get; } = new();
        internal SettableTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);
        internal CapacityJobOwner Owner { get; } = new(Id(1), Id(2), "capacity.measurement", Id(3));
        internal Authority Authority { get; }
        internal ICapacityJobPort Port { get; }
        internal long Now => CapacityJobCodec.Now(Clock);
        internal Harness() { Authority = new(Owner); Port = NewPort(); }
        internal ICapacityJobPort NewPort() => new CapacityJobPortFactory(Bridge, Bridge.Generation, Clock, Authority).Create();
        internal CapacityJobDefinition Definition(int number)
        {
            var value = new CapacityJobDefinition(Id(number), "component-job", Owner, Bridge.Generation, "{}", CapacityJobCodec.Hash("{}"), 3, Now - 1000);
            Authority.Approved[value.JobId] = value; return value;
        }
        internal CapacityJobDefinition Measurement(int number, int reads)
        {
            var input = JsonSerializer.Serialize(new CapacityMeasurementInput(new('a', 64), new('b', 64), new('c', 64), reads), CapacityMeasurementJson.Default.CapacityMeasurementInput);
            var value = Definition(number) with { JobType = "capacity.measurement", InputJson = input, InputHash = CapacityJobCodec.Hash(input) };
            Authority.Approved[value.JobId] = value; return value;
        }
        internal Task<long> Count(string table) => Bridge.CountAsync(table, "1=1", T.Ct);
        public void Dispose() => Bridge.Dispose();
    }
    private sealed class Authority(CapacityJobOwner owner) : ICapacityJobAuthority, ICapacityJobRecoveryAuthority
    {
        internal Dictionary<Guid, CapacityJobDefinition> Approved { get; } = [];
        internal HashSet<Guid> DeniedJobs { get; } = [];
        internal QuotaAuthorityStatus Status = QuotaAuthorityStatus.Authorized;
        public Task<QuotaAuthorityStatus> AuthorizeCreateAsync(CapacityJobDefinition definition, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(Approved.GetValueOrDefault(definition.JobId) == definition ? Status : QuotaAuthorityStatus.Denied); }
        public Task<QuotaAuthorityStatus> AuthorizeAsync(CapacityJobOwner requested, Guid jobId, string operation, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(requested == owner && Approved.ContainsKey(jobId) && !DeniedJobs.Contains(jobId)
            && operation is "read" or "platform.capacity-job-create" or "platform.capacity-job-claim" or "platform.capacity-job-checkpoint" ? Status : QuotaAuthorityStatus.Denied); }
        public Task<CapacityRecoveryScopeResult> GetCurrentAsync(CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(new CapacityRecoveryScopeResult(Status, new(owner.RealmId, 1))); }
    }
}
