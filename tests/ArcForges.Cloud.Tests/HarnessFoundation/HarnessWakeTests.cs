// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Infrastructure;
using ArcForges.Cloud.Modules.Task.Harness.Wake;
using ArcForges.Cloud.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.HarnessFoundation;

/// <summary>The plan port with one named write answered with a failure status (unavailable by default), so that write cannot settle.</summary>
internal sealed class FailingPlanPort(IModulePlanPort inner, string failingPlan, ModulePlanStatus status = ModulePlanStatus.Unavailable) : IModulePlanPort
{
    public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken) => inner.ReadAsync(read, cancellationToken);

    public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken) =>
        write.PlanId == failingPlan
            ? Task.FromResult(ModulePlanOutcome.Of(status))
            : inner.WriteAsync(write, cancellationToken);
}

/// <summary>The plan port with one named read answered as unavailable, so that read is not served and nothing is read or written by it.</summary>
internal sealed class FailingReadPlanPort(IModulePlanPort inner, string failingPlan) : IModulePlanPort
{
    public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken) =>
        read.PlanId == failingPlan
            ? Task.FromResult(ModulePlanOutcome.Of(ModulePlanStatus.Unavailable))
            : inner.ReadAsync(read, cancellationToken);

    public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken) => inner.WriteAsync(write, cancellationToken);
}

/// <summary>The wake port the endpoint tests drive: it accepts the one signature the test sends and records what the endpoint passed on.</summary>
internal sealed class StubWakePort : IHarnessWakePort
{
    public bool Accept { get; set; } = true;

    public HarnessWakeReply Reply { get; set; } = HarnessWakeReply.Taken;

    public List<HarnessWakeMessage> Messages { get; } = [];

    public List<(string Method, string Target, string BodyHash)> Checked { get; } = [];

    public bool Authenticate(string method, string rawTarget, string bodySha256Hex, Func<string, string?> header)
    {
        Checked.Add((method, rawTarget, bodySha256Hex));
        return Accept && header("x-test-signature") == "ok";
    }

    public Task<HarnessWakeReply> HandleAsync(HarnessWakeMessage message, CancellationToken cancellationToken)
    {
        Messages.Add(message);
        return Task.FromResult(Reply);
    }
}

public sealed class HarnessWakeTests
{
    private const string WorkerVersion = "wv-test-7";

    private static readonly EffectRequest Request = new(EffectKind.ModelCall, "model.call", "digest.wake-resume", HarnessFixture.Pin, 1024, 100, 0);

    private static string Body(string? workerVersion = WorkerVersion, string runId = "00000000-0000-4000-8000-0000000000d1") =>
        "{\"v\":1,\"kind\":\"harness.wake\",\"workspaceId\":\"00000000-0000-4000-8000-0000000000b1\",\"runId\":\"" + runId
        + "\",\"wakeAtMs\":1700000000000" + (workerVersion is null ? string.Empty : ",\"workerVersion\":\"" + workerVersion + "\"") + "}";

    private static HarnessWakeService Service(HarnessFixture fixture, IModulePlanPort? port = null) =>
        new(port ?? fixture.Port, "cloud.build.1", 1, fixture.Clock, (_, _, _, _) => true);

    [Fact]
    public void AWakeBodyIsAcceptedOnlyInItsClosedShapeWithCanonicalIdentifiersAndAWorkerVersion()
    {
        Assert.True(HarnessWakeEndpoint.TryParse(Encoding.UTF8.GetBytes(Body()), out var message));
        Assert.Equal(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, WorkerVersion, 1_700_000_000_000), message);

        var refused = new[]
        {
            Body(workerVersion: null),
            Body(workerVersion: "bad version"),
            Body(workerVersion: string.Empty),
            Body(runId: "00000000-0000-4000-8000-0000000000D1"),
            Body(runId: "not-a-uuid"),
            Body(runId: "00000000-0000-4000-8000-0000000000d1 "),
            Body().Replace("\"v\":1", "\"v\":2", StringComparison.Ordinal),
            Body().Replace("harness.wake", "harness.other", StringComparison.Ordinal),
            Body().Replace("1700000000000", "\"1700000000000\"", StringComparison.Ordinal),
            Body().Replace("}", ",\"extra\":1}", StringComparison.Ordinal),
            "[]",
            "not json",
        };
        foreach (var body in refused) Assert.False(HarnessWakeEndpoint.TryParse(Encoding.UTF8.GetBytes(body), out _), body);
    }

    [Fact]
    public async Task AWakeClaimsAQueuedRunUnderTheWorkerVersionAndReleasesItToWaiting()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var reply = await Service(fixture).HandleAsync(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, WorkerVersion, 1), T.Ct);

        Assert.Equal(HarnessWakeReply.Taken, reply);
        Assert.Equal("3", await fixture.RunStateAsync());
        var run = await fixture.QueryAsync("SELECT worker_version FROM task_run WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal(WorkerVersion, run[0][0]);
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
    }

    [Fact]
    public async Task AWakeForAHeldRunIsRetriedUntilItsLeaseExpiresAndAnAbsentRunIsTakenAndChangesNothing()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = new HarnessExecutor(new D1HarnessStore(fixture.Port), new NoEffects(), fixture.Ids, fixture.Clock);
        Assert.Equal(ClaimStatus.Claimed, (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity("worker.held"), T.Ct)).Status);

        // A live lease of another holder refuses the claim. The holder may have crashed, so the wake is retried rather than dropped (HAR.40 (b)).
        var held = await Service(fixture).HandleAsync(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, WorkerVersion, 1), T.Ct);
        Assert.Equal(HarnessWakeReply.Stopped, held);
        Assert.Equal("2", await fixture.RunStateAsync());
        var run = await fixture.QueryAsync("SELECT worker_version FROM task_run WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal("worker.held", run[0][0]);

        // Once the lease has expired, the retry claims the run and releases it to waiting.
        fixture.Clock.AdvanceSeconds(61);
        var retry = await Service(fixture).HandleAsync(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, WorkerVersion, 1), T.Ct);
        Assert.Equal(HarnessWakeReply.Taken, retry);
        Assert.Equal("3", await fixture.RunStateAsync());

        var absent = await Service(fixture).HandleAsync(new HarnessWakeMessage(HarnessFixture.WorkspaceId, Guid.Parse("00000000-0000-4000-8000-00000000ffff"), WorkerVersion, 1), T.Ct);
        Assert.Equal(HarnessWakeReply.Taken, absent);
    }

    [Fact]
    public async Task AWakeWhoseReleaseCannotSettleIsStoppedSoItIsRetried()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var reply = await Service(fixture, new FailingPlanPort(fixture.Port, "task.harness-executor-yield"))
            .HandleAsync(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, WorkerVersion, 1), T.Ct);
        Assert.Equal(HarnessWakeReply.Stopped, reply);
    }

    [Theory]
    [InlineData(ModulePlanStatus.Unavailable)]
    [InlineData(ModulePlanStatus.UnknownOutcome)]
    public async Task AWakeWhoseClaimCannotBeSettledIsStoppedSoItIsRetriedAndChangesNothing(ModulePlanStatus status)
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var reply = await Service(fixture, new FailingPlanPort(fixture.Port, "task.harness-executor-claim", status))
            .HandleAsync(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, WorkerVersion, 1), T.Ct);

        Assert.Equal(HarnessWakeReply.Stopped, reply);
        Assert.Equal("1", await fixture.RunStateAsync());
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
    }

    [Fact]
    public async Task AWakeWhoseRunReadIsNotServedIsUnavailableAndChangesNothing()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var reply = await Service(fixture, new FailingReadPlanPort(fixture.Port, "task.harness-executor-run-load"))
            .HandleAsync(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, WorkerVersion, 1), T.Ct);

        Assert.Equal(HarnessWakeReply.Unavailable, reply);
        Assert.Equal("1", await fixture.RunStateAsync());
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
    }

    [Fact]
    public async Task AWakeWhoseAttemptReadIsNotServedReleasesItsLeaseAndTheRetryClaimsAndSettles()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        // A reserved attempt with no dispatch intent is left by a crash after the reserve committed (write 2).
        var first = new HarnessExecutor(new D1HarnessStore(new CrashingPlanPort(fixture.Port, 2, after: true)), new FakeEffects(), fixture.Ids, fixture.Clock);
        var claim = (await first.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        await Assert.ThrowsAsync<SimulatedCrash>(() => first.RunEffectAsync(claim, Request, LoopBounds.Default, T.Ct));
        fixture.Clock.AdvanceSeconds(61);

        // The open attempt cannot be read, so the wake releases its own lease to waiting and answers the typed retryable reply.
        var unavailable = await Service(fixture, new FailingReadPlanPort(fixture.Port, "task.harness-executor-attempt-load"))
            .HandleAsync(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, WorkerVersion, 1), T.Ct);
        Assert.Equal(HarnessWakeReply.Unavailable, unavailable);
        Assert.Equal("3", await fixture.RunStateAsync());
        Assert.Equal(1, await fixture.CountOpenAttemptsAsync());

        // The retry claims the released run and settles the open attempt.
        var retry = await Service(fixture).HandleAsync(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, WorkerVersion, 1), T.Ct);
        Assert.Equal(HarnessWakeReply.Taken, retry);
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
    }

    [Fact]
    public async Task AWakeWhoseResumeCannotSettleReleasesItsLeaseSoTheRetryClaimsAndSettles()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        // A reserved attempt with no dispatch intent is left by a crash after the reserve committed (write 2).
        var first = new HarnessExecutor(new D1HarnessStore(new CrashingPlanPort(fixture.Port, 2, after: true)), new FakeEffects(), fixture.Ids, fixture.Clock);
        var claim = (await first.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        await Assert.ThrowsAsync<SimulatedCrash>(() => first.RunEffectAsync(claim, Request, LoopBounds.Default, T.Ct));
        fixture.Clock.AdvanceSeconds(61);

        // The first wake cannot record the refusal of the open attempt, so it stops and releases its own lease to waiting.
        var stopped = await Service(fixture, new FailingPlanPort(fixture.Port, "task.harness-executor-record-outcome"))
            .HandleAsync(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, WorkerVersion, 1), T.Ct);
        Assert.Equal(HarnessWakeReply.Stopped, stopped);
        Assert.Equal("3", await fixture.RunStateAsync());
        Assert.Equal(1, await fixture.CountOpenAttemptsAsync());

        // The retry claims the released run at once (not taken as held by a live lease) and settles the open attempt.
        var retry = await Service(fixture).HandleAsync(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, WorkerVersion, 1), T.Ct);
        Assert.Equal(HarnessWakeReply.Taken, retry);
        Assert.Equal("3", await fixture.RunStateAsync());
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
    }

    [Fact]
    public async Task AWakeWithAMalformedWorkerVersionIsRefusedByTheService()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        await Assert.ThrowsAsync<ArgumentException>(() => Service(fixture).HandleAsync(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, "bad version", 1), T.Ct));
        Assert.Equal("1", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task TheServiceAuthenticatesOnlyWhatTheHostVerifierAccepts()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var seen = new List<string>();
        var service = new HarnessWakeService(fixture.Port, "cloud.build.1", 1, fixture.Clock, (method, target, hash, _) =>
        {
            seen.Add(method + " " + target + " " + hash);
            return method == "POST" && hash == "abc";
        });
        Assert.True(service.Authenticate("POST", "/internal/harness/v1/wake", "abc", _ => null));
        Assert.False(service.Authenticate("POST", "/internal/harness/v1/wake", "def", _ => null));
        Assert.Equal(["POST /internal/harness/v1/wake abc", "POST /internal/harness/v1/wake def"], seen);
    }

    [Fact]
    public void TheWakePathIsDeclaredToTheIngressOnlyUnderTheFoundationConfiguration()
    {
        var identity = BuildIdentity.FromAssembly(typeof(HelloEndpoint).Assembly);
        var without = WebApplication.CreateSlimBuilder();
        var absent = new HarnessWakeModule(identity);
        absent.Register(without);
        Assert.Empty(absent.PlainPaths);

        var with = WebApplication.CreateSlimBuilder();
        with.Services.AddSingleton(T.Options());
        var configured = new HarnessWakeModule(identity);
        configured.Register(with);
        Assert.Equal([HarnessWakeRoute.Path], configured.PlainPaths);
    }

    [Fact]
    public async Task TheEndpointVerifiesBeforeItParsesAndAnswersThroughItsStatusCodes()
    {
        var (app, client, port) = await StartAsync(register: true);
        await using var running = new Running(app, client);

        var body = Body();
        var unsigned = await client.PostAsync(HarnessWakeRoute.Path, Json(body), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.Unauthorized, unsigned.StatusCode);
        Assert.Empty(port.Messages);
        Assert.Equal((HttpMethod.Post.Method, HarnessWakeRoute.Path, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(body)))), port.Checked[0]);

        var signed = await Post(client, body);
        Assert.Equal(HttpStatusCode.OK, signed.StatusCode);
        Assert.Equal(new HarnessWakeMessage(HarnessFixture.WorkspaceId, HarnessFixture.RunId, WorkerVersion, 1_700_000_000_000), Assert.Single(port.Messages));

        port.Reply = HarnessWakeReply.Stopped;
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await Post(client, body)).StatusCode);

        port.Reply = HarnessWakeReply.Unavailable;
        var unavailable = await Post(client, body);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, unavailable.StatusCode);
        Assert.Equal("1", Assert.Single(unavailable.Headers.GetValues("Retry-After")));

        port.Reply = HarnessWakeReply.Taken;
        Assert.Equal(HttpStatusCode.BadRequest, (await Post(client, Body(workerVersion: null))).StatusCode);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await PostAs(client, body, "text/plain")).StatusCode);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await Post(client, new string('x', HarnessWakeRoute.MaxBodyBytes + 1))).StatusCode);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await client.GetAsync(HarnessWakeRoute.Path, TestContext.Current.CancellationToken)).StatusCode);
    }

    [Fact]
    public async Task WithoutAWakePortTheRouteDoesNotExist()
    {
        var (app, client, _) = await StartAsync(register: false);
        await using var running = new Running(app, client);
        Assert.Equal(HttpStatusCode.NotFound, (await Post(client, Body())).StatusCode);
    }

    private static Task<HttpResponseMessage> Post(HttpClient client, string body) => PostAs(client, body, "application/json", signed: true);

    private static Task<HttpResponseMessage> PostAs(HttpClient client, string body, string contentType, bool signed = true)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, HarnessWakeRoute.Path) { Content = Json(body, contentType) };
        if (signed) request.Headers.Add("x-test-signature", "ok");
        return client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static StringContent Json(string body, string contentType = "application/json") =>
        new(body, Encoding.UTF8, contentType);

    private static async Task<(WebApplication App, HttpClient Client, StubWakePort Port)> StartAsync(bool register)
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = HttpProtocols.Http1));
        var port = new StubWakePort();
        if (register) builder.Services.AddSingleton<IHarnessWakePort>(port);
        var app = builder.Build();
        ArcForges.Cloud.Modules.Task.TaskModule.Instance.Map(app);
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        return (app, new HttpClient { BaseAddress = new Uri(address) }, port);
    }

    private sealed class Running(WebApplication app, HttpClient client) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            client.Dispose();
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }

    /// <summary>An effect port for the wake, which dispatches nothing; any call is a test failure.</summary>
    private sealed class NoEffects : IEffectPort
    {
        public Task<EffectResult> DispatchAsync(EffectCall call, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("No external effect is expected in this test.");
    }
}
