// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Storage;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests;

/// <summary>The real host pipeline on a loopback port with the plan executor replaced by the in-memory plan model.</summary>
public sealed class FoundationHostTests
{
    private const string Origin = "https://app.example.test";
    private static readonly DateTimeOffset Start = new(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);

    private sealed class Running(WebApplication app, HttpClient client, FakeStorage storage, FakeTime time, FoundationOptions options) : IAsyncDisposable
    {
        public HttpClient Client { get; } = client;
        public FakeStorage Storage { get; } = storage;
        public FakeTime Time { get; } = time;
        public FoundationOptions Options { get; } = options;
        public SessionService Sessions => app.Services.GetRequiredService<SessionService>();

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await app.StopAsync();
            await app.DisposeAsync();
        }
    }

    private static async Task<Running> StartAsync(bool enabled = true, EgressProbe? probe = null)
    {
        var storage = new FakeStorage();
        var time = new FakeTime(Start);
        var options = T.Options();
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Limits.MaxRequestBodySize = 4096;
            kestrel.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = HttpProtocols.Http1);
        });
        builder.Services.AddSingleton<IPlanExecutor>(storage);
        builder.Services.AddSingleton<TimeProvider>(time);
        if (probe is not null) builder.Services.AddSingleton(probe);
        IHostModule[] modules =
        [
            new HelloModule(BuildIdentity.FromAssembly(typeof(HelloEndpoint).Assembly)),
            enabled ? new FoundationModule(options) : new FoundationModule(_ => null),
        ];
        foreach (var module in modules) module.Register(builder);
        var app = builder.Build();
        foreach (var module in modules) module.Map(app);
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        return new Running(app, new HttpClient { BaseAddress = new Uri(address) }, storage, time, options);
    }

    private static HttpRequestMessage Signed(Running host, string path, byte[] body, string method = "POST", SigningKey? key = null, string? contentType = "application/json", DateTimeOffset? at = null)
    {
        var request = new HttpRequestMessage(new HttpMethod(method), path) { Content = new ByteArrayContent(body) };
        if (contentType is not null) request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        var clock = new FakeTime(at ?? host.Time.Now);
        PrivateRequestSigner.Sign(method, path, T.Sha256Hex(body), T.Uuid(), key ?? host.Options.VerifyKeyW2c, clock)
            .CopyTo((name, value) => request.Headers.TryAddWithoutValidation(name, value));
        return request;
    }

    private static async Task<(HttpStatusCode Status, JsonElement Json, HttpResponseHeaders Headers, string Text)> Send(Running host, HttpRequestMessage request)
    {
        using var response = await host.Client.SendAsync(request, T.Ct);
        var text = await response.Content.ReadAsStringAsync(T.Ct);
        JsonElement json = default;
        if (text.Length > 0 && response.Content.Headers.ContentType?.MediaType == "application/json")
        {
            using var document = JsonDocument.Parse(text);
            json = document.RootElement.Clone();
        }

        return (response.StatusCode, json, response.Headers, text);
    }

    private static Task<(HttpStatusCode Status, JsonElement Json, HttpResponseHeaders Headers, string Text)> Operation(Running host, string operation, object body) =>
        Send(host, Signed(host, "/internal/foundation/v1/" + operation, JsonSerializer.SerializeToUtf8Bytes(body)));

    private static HttpRequestMessage Browser(string method, string path, string? cookie = null, string? origin = null, string? csrf = null, string? body = null)
    {
        var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (cookie is not null) request.Headers.TryAddWithoutValidation("Cookie", cookie);
        if (origin is not null) request.Headers.TryAddWithoutValidation("Origin", origin);
        if (csrf is not null) request.Headers.TryAddWithoutValidation("X-AF-CSRF", csrf);
        if (body is not null) request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        return request;
    }

    private static string Cookie(IssuedSession issued) => "__Host-af_session=" + issued.Handle;

    private static Task<IssuedSession> Issue(Running host) =>
        host.Sessions.IssueAsync(T.Uuid(), T.Uuid(), [T.Uuid()], T.Ct);

    [Fact]
    public async Task ADisabledModuleServesNoFoundationRouteAndHelloStillAnswers()
    {
        await using var host = await StartAsync(enabled: false);
        Assert.Equal(HttpStatusCode.OK, (await Send(host, new HttpRequestMessage(HttpMethod.Get, "/healthz"))).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await Send(host, Signed(host, "/internal/foundation/v1/readiness", "{}"u8.ToArray()))).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await Send(host, Browser("GET", "/session/v1/bootstrap"))).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await Send(host, Browser("POST", "/session/v1/logout", origin: Origin))).Status);
        Assert.Empty(host.Storage.Calls);
    }

    [Fact]
    public async Task BootstrapIsAnonymousWithoutACookieAndNeverSetsOne()
    {
        await using var host = await StartAsync();
        var reply = await Send(host, Browser("GET", "/session/v1/bootstrap", origin: Origin));
        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.False(reply.Json.GetProperty("authenticated").GetBoolean());
        Assert.Equal(43, reply.Json.GetProperty("csrfToken").GetString()!.Length);
        Assert.False(reply.Json.TryGetProperty("session", out _));
        Assert.False(reply.Headers.Contains("Set-Cookie"));
        Assert.Contains("no-store", reply.Headers.CacheControl!.ToString(), StringComparison.Ordinal);
        Assert.Equal("nosniff", reply.Headers.GetValues("X-Content-Type-Options").Single());
        // A safe GET may omit Origin, but a present Origin must be exactly the configured one.
        Assert.Equal(HttpStatusCode.OK, (await Send(host, Browser("GET", "/session/v1/bootstrap"))).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await Send(host, Browser("GET", "/session/v1/bootstrap", origin: "https://evil.example.test"))).Status);
        Assert.Equal(HttpStatusCode.Forbidden, (await Send(host, Browser("GET", "/session/v1/bootstrap", origin: Origin + "/"))).Status);
        Assert.Equal(0, host.Storage.Executions("foundation.session-load"));
    }

    [Fact]
    public async Task BootstrapReturnsTheSessionProjectionAndRenewsIdleExpiry()
    {
        await using var host = await StartAsync();
        var issued = await Issue(host);
        host.Time.Advance(TimeSpan.FromMinutes(20));
        var reply = await Send(host, Browser("GET", "/session/v1/bootstrap", Cookie(issued), Origin));
        Assert.True(reply.Json.GetProperty("authenticated").GetBoolean());
        Assert.Equal(issued.CsrfToken, reply.Json.GetProperty("csrfToken").GetString());
        var session = reply.Json.GetProperty("session");
        Assert.Equal(issued.SessionId, session.GetProperty("sessionId").GetString());
        Assert.Equal("0", session.GetProperty("recoveryGeneration").GetString());
        Assert.Equal("authenticate", session.GetProperty("purpose").GetString());
        Assert.Equal(1, session.GetProperty("workspaceIds").GetArrayLength());
        Assert.Matches(@"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$", session.GetProperty("expiresAt").GetString());
        // The bootstrap renewed the idle window, so the session outlives its original 30 minutes.
        host.Time.Advance(TimeSpan.FromMinutes(20));
        Assert.True((await Send(host, Browser("GET", "/session/v1/bootstrap", Cookie(issued), Origin))).Json.GetProperty("authenticated").GetBoolean());
        host.Time.Advance(TimeSpan.FromMinutes(31));
        Assert.False((await Send(host, Browser("GET", "/session/v1/bootstrap", Cookie(issued), Origin))).Json.GetProperty("authenticated").GetBoolean());
    }

    [Fact]
    public async Task EveryMissingOrWrongLogoutElementIsRefusedBeforeAnyWrite()
    {
        await using var host = await StartAsync();
        var issued = await Issue(host);
        var refusals = new (string Label, HttpRequestMessage Request, HttpStatusCode Status)[]
        {
            ("no origin", Browser("POST", "/session/v1/logout", Cookie(issued), null, issued.CsrfToken), HttpStatusCode.Forbidden),
            ("wrong origin", Browser("POST", "/session/v1/logout", Cookie(issued), "https://evil.example.test", issued.CsrfToken), HttpStatusCode.Forbidden),
            ("no csrf", Browser("POST", "/session/v1/logout", Cookie(issued), Origin), HttpStatusCode.Forbidden),
            ("wrong csrf", Browser("POST", "/session/v1/logout", Cookie(issued), Origin, new string('x', 43)), HttpStatusCode.Forbidden),
            ("anonymous csrf", Browser("POST", "/session/v1/logout", Cookie(issued), Origin, host.Sessions.AnonymousCsrf()), HttpStatusCode.Forbidden),
            ("no cookie", Browser("POST", "/session/v1/logout", null, Origin, issued.CsrfToken), HttpStatusCode.Unauthorized),
            ("malformed cookie", Browser("POST", "/session/v1/logout", "__Host-af_session=abc", Origin, issued.CsrfToken), HttpStatusCode.Unauthorized),
            ("other cookie name", Browser("POST", "/session/v1/logout", "af_session=" + issued.Handle, Origin, issued.CsrfToken), HttpStatusCode.Unauthorized),
            ("duplicate cookie", Browser("POST", "/session/v1/logout", Cookie(issued) + "; " + Cookie(issued), Origin, issued.CsrfToken), HttpStatusCode.Unauthorized),
            ("with a body", Browser("POST", "/session/v1/logout", Cookie(issued), Origin, issued.CsrfToken, "{}"), HttpStatusCode.BadRequest),
        };
        foreach (var (label, request, status) in refusals)
            Assert.Equal(status, (await Send(host, request)).Status);
        Assert.Equal(0, host.Storage.Executions("foundation.session-revoke"));
        Assert.True((await Send(host, Browser("GET", "/session/v1/bootstrap", Cookie(issued), Origin))).Json.GetProperty("authenticated").GetBoolean());
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await Send(host, Browser("GET", "/session/v1/logout", Cookie(issued), Origin, issued.CsrfToken))).Status);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await Send(host, Browser("POST", "/session/v1/bootstrap", Cookie(issued), Origin))).Status);
    }

    [Fact]
    public async Task LogoutRevokesDurablyClearsTheCookieAndAnotherContainerSeesIt()
    {
        await using var host = await StartAsync();
        var issued = await Issue(host);
        var reply = await Send(host, Browser("POST", "/session/v1/logout", Cookie(issued), Origin, issued.CsrfToken));
        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.Equal("happened", reply.Json.GetProperty("effect").GetString());
        Assert.True(Guid.TryParseExact(reply.Json.GetProperty("commandId").GetString(), "D", out _));
        var cookie = reply.Headers.GetValues("Set-Cookie").Single();
        Assert.Equal("__Host-af_session=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax", cookie);
        Assert.DoesNotContain("Domain", cookie, StringComparison.Ordinal);
        Assert.NotNull(host.Storage.Sessions[0].Revoked);
        // A second host over the same storage (another Container) sees the revocation on its next read.
        var another = new SessionService(host.Storage, host.Options, host.Time);
        Assert.False((await another.ResolveAsync(issued.Handle, T.Ct)).IsAuthenticated);
        Assert.False((await Send(host, Browser("GET", "/session/v1/bootstrap", Cookie(issued), Origin))).Json.GetProperty("authenticated").GetBoolean());
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(host, Browser("POST", "/session/v1/logout", Cookie(issued), Origin, issued.CsrfToken))).Status);
    }

    [Fact]
    public async Task AStorageOutageIsAnUnavailableReplyAndNeverAnAuthentication()
    {
        await using var host = await StartAsync();
        var issued = await Issue(host);
        host.Storage.Fault = call => call.Plan.Id == "foundation.session-load" ? PlanFailureKind.Unavailable : null;
        var bootstrap = await Send(host, Browser("GET", "/session/v1/bootstrap", Cookie(issued), Origin));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, bootstrap.Status);
        Assert.Equal("unavailable", bootstrap.Json.GetProperty("error").GetString());
        Assert.DoesNotContain("foundation", bootstrap.Text, StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await Send(host, Browser("POST", "/session/v1/logout", Cookie(issued), Origin, issued.CsrfToken))).Status);
    }

    [Fact]
    public async Task InternalRoutesRefuseEveryUnsignedForgedExpiredOrMalformedRequestTheSameWay()
    {
        await using var host = await StartAsync();
        var body = "{}"u8.ToArray();
        var unsigned = new HttpRequestMessage(HttpMethod.Post, "/internal/foundation/v1/readiness") { Content = new ByteArrayContent(body) };
        unsigned.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        var refusals = new[]
        {
            unsigned,
            Signed(host, "/internal/foundation/v1/readiness", body, key: T.Key("w2c-1")),
            Signed(host, "/internal/foundation/v1/readiness", body, key: host.Options.SigningKeyC2w),
            Signed(host, "/internal/foundation/v1/readiness", body, at: Start.AddSeconds(-61)),
            Signed(host, "/internal/foundation/v1/readiness", body, at: Start.AddSeconds(61)),
        };
        foreach (var request in refusals)
        {
            var reply = await Send(host, request);
            Assert.Equal(HttpStatusCode.Unauthorized, reply.Status);
            Assert.Equal("", reply.Text);
        }

        // A body altered after signing and a signature for another path are refused as well.
        var tampered = Signed(host, "/internal/foundation/v1/readiness", body);
        tampered.Content = new ByteArrayContent("{ }"u8.ToArray());
        tampered.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(host, tampered)).Status);
        var elsewhere = Signed(host, "/internal/foundation/v1/readiness", body);
        elsewhere.RequestUri = new Uri("/internal/foundation/v1/exact", UriKind.Relative);
        Assert.Equal(HttpStatusCode.Unauthorized, (await Send(host, elsewhere)).Status);
        Assert.Empty(host.Storage.Calls);
    }

    [Fact]
    public async Task SignedRequestsAreCheckedForContentTypeSizeShapeAndRoute()
    {
        await using var host = await StartAsync();
        var json = "{}"u8.ToArray();
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await Send(host, Signed(host, "/internal/foundation/v1/readiness", json, contentType: "text/plain"))).Status);
        Assert.Equal(HttpStatusCode.UnsupportedMediaType, (await Send(host, Signed(host, "/internal/foundation/v1/readiness", json, contentType: null))).Status);
        Assert.Equal(HttpStatusCode.OK, (await Send(host, Signed(host, "/internal/foundation/v1/readiness", json, contentType: "application/json; charset=utf-8"))).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(host, Signed(host, "/internal/foundation/v1/readiness", "{\"extra\":1}"u8.ToArray()))).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Send(host, Signed(host, "/internal/foundation/v1/readiness", "not json"u8.ToArray()))).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await Send(host, Signed(host, "/internal/foundation/v1/unknown", json))).Status);
        var huge = new byte[FoundationEndpoints.MaxBodyBytes + 1];
        Array.Fill(huge, (byte)' ');
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await Send(host, Signed(host, "/internal/foundation/v1/readiness", huge))).Status);
        var wrongMethod = await host.Client.GetAsync("/internal/foundation/v1/readiness", T.Ct);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, wrongMethod.StatusCode);
        var ok = await Send(host, Signed(host, "/internal/foundation/v1/readiness", json));
        Assert.True(ok.Json.GetProperty("ready").GetBoolean());
        Assert.Equal(PlanManifest.Hash, ok.Json.GetProperty("manifestHash").GetString());
        // The host-wide bound of 4096 bytes protects Hello; the foundation routes raise only their own bound.
        var padded = Encoding.UTF8.GetBytes("{" + new string(' ', 5000) + "}");
        Assert.Equal(HttpStatusCode.OK, (await Send(host, Signed(host, "/internal/foundation/v1/readiness", padded))).Status);
    }

    /// <summary>A body with no known length, so the client sends it chunked and no Content-Length header exists.</summary>
    private sealed class ForwardOnlyStream(byte[] data) : Stream
    {
        private int position;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            var read = Math.Min(count, data.Length - position);
            Array.Copy(data, position, buffer, offset, read);
            position += read;
            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    private static HttpRequestMessage Chunked(Running host, byte[] body)
    {
        var request = Signed(host, "/internal/foundation/v1/readiness", body);
        request.Content = new StreamContent(new ForwardOnlyStream(body), 4096);
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("application/json");
        Assert.Null(request.Content.Headers.ContentLength);
        return request;
    }

    [Fact]
    public async Task ABodyWithoutAContentLengthIsBoundedWhileItIsRead()
    {
        await using var host = await StartAsync();
        // Above the host-wide 4096 bytes that protect Hello, but within the route's own bound. (Kestrel counts the
        // chunk framing against the limit, so a chunked body exactly at the bound is not asserted either way.)
        var within = Encoding.UTF8.GetBytes("{" + new string(' ', 8190) + "}");
        Assert.Equal(HttpStatusCode.OK, (await Send(host, Chunked(host, within))).Status);
        var over = Encoding.UTF8.GetBytes("{" + new string(' ', FoundationEndpoints.MaxBodyBytes - 1) + "}");
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await Send(host, Chunked(host, over))).Status);
        // A far larger chunked body is refused without being buffered whole: either the 413 arrives or the server
        // closes the connection while the client is still sending, which is also a bounded outcome.
        try
        {
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await Send(host, Chunked(host, new byte[1 << 20]))).Status);
        }
        catch (HttpRequestException)
        {
        }
    }

    [Fact]
    public async Task SignedClientsNeverFollowARedirect()
    {
        var targetHits = 0;
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = HttpProtocols.Http1));
        var server = builder.Build();
        server.MapGet("/start", () => Results.Redirect("/target"));
        server.MapGet("/target", () => { targetHits++; return Results.Ok(); });
        await server.StartAsync(T.Ct);
        try
        {
            var address = server.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            using var client = FoundationModule.NewClient();
            using var response = await client.GetAsync(new Uri(new Uri(address), "/start"), T.Ct);
            Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
            Assert.Equal(0, targetHits);
        }
        finally
        {
            await server.StopAsync(T.Ct);
            await server.DisposeAsync();
        }
    }

    [Fact]
    public async Task ExactValuesRoundTripAndEveryRefusalHasItsStatus()
    {
        await using var host = await StartAsync();
        var scope = "proof/exact";
        object Request(string id, string signed, string unsigned, string dec, string revision, string? command = null) =>
            new { scope, id, signed, unsigned, @decimal = dec, expectedRevision = revision, commandId = command ?? T.Uuid(), payloadBase64Url = Base64Url.Encode(new byte[] { 0, 1, 255 }) };
        var ok = await Operation(host, "exact", Request("a", "-9223372036854775808", "18446744073709551615", "-1234567890123456789.123456789", "0"));
        Assert.Equal(HttpStatusCode.OK, ok.Status);
        Assert.True(ok.Json.GetProperty("roundTripExact").GetBoolean());
        Assert.Equal("1", ok.Json.GetProperty("revision").GetString());
        var arithmetic = ok.Json.GetProperty("arithmetic");
        Assert.Equal("-9223372036854775807", arithmetic.GetProperty("signedPlusOne").GetString());
        Assert.Equal("overflow", arithmetic.GetProperty("unsignedPlusOne").GetString());
        Assert.Equal("-2469135780246913578.246913578", arithmetic.GetProperty("decimalTimesTwo").GetString());
        var max = await Operation(host, "exact", Request("b", "9223372036854775807", "9007199254740993", "9999999999999999999.999999999", "0"));
        Assert.Equal("overflow", max.Json.GetProperty("arithmetic").GetProperty("signedPlusOne").GetString());
        Assert.Equal("9007199254740994", max.Json.GetProperty("arithmetic").GetProperty("unsignedPlusOne").GetString());
        Assert.Equal("overflow", max.Json.GetProperty("arithmetic").GetProperty("decimalTimesTwo").GetString());
        Assert.Equal(HttpStatusCode.Conflict, (await Operation(host, "exact", Request("a", "1", "1", "1", "0"))).Status);
        foreach (var bad in new[]
        {
            Request("c", "9223372036854775808", "1", "1", "0"),
            Request("c", "1", "-1", "1", "0"),
            Request("c", "1", "1", "1.50", "0"),
            Request("c", "1", "1", "1e3", "0"),
            Request("c", "01", "1", "1", "0"),
            Request("c", "1", "1", "1", "-1"),
            Request("c", "1", "1", "1", "9223372036854775807"),
            Request("bad id!", "1", "1", "1", "0"),
            Request("c", "1", "1", "1", "0", "not-a-uuid"),
        })
            Assert.Equal(HttpStatusCode.BadRequest, (await Operation(host, "exact", bad)).Status);
        // A numeric JSON value where text is required is refused: no number path exists.
        var numeric = await Operation(host, "exact", new { scope, id = "n", signed = 1, unsigned = "1", @decimal = "1", expectedRevision = "0", commandId = T.Uuid() });
        Assert.Equal(HttpStatusCode.BadRequest, numeric.Status);
        // The same command replayed with the same request returns the stored result; a different request conflicts.
        var command = T.Uuid();
        var first = await Operation(host, "exact", Request("r", "5", "5", "5", "0", command));
        Assert.Equal(HttpStatusCode.OK, first.Status);
        var replay = await Operation(host, "exact", Request("r", "5", "5", "5", "0", command));
        Assert.Equal(HttpStatusCode.OK, replay.Status);
        Assert.True(replay.Json.GetProperty("replayed").GetBoolean());
        Assert.Equal(HttpStatusCode.Conflict, (await Operation(host, "exact", Request("r", "6", "6", "6", "0", command))).Status);
    }

    [Fact]
    public async Task GuardedTransfersCommitRollBackReplayAndConflictHonestly()
    {
        await using var host = await StartAsync();
        var scope = "proof/guard";
        var committed = await Operation(host, "guard", new { scope, from = "alpha", to = "beta", amount = "9223372036854774900", commandId = T.Uuid(), seedFrom = "9223372036854775000", seedTo = "100" });
        Assert.Equal("committed", committed.Json.GetProperty("outcome").GetString());
        Assert.Equal("100", committed.Json.GetProperty("after").GetProperty("fromBalance").GetString());
        Assert.Equal("9223372036854775000", committed.Json.GetProperty("after").GetProperty("toBalance").GetString());
        var rejected = await Operation(host, "guard", new { scope, from = "alpha", to = "beta", amount = "5", commandId = T.Uuid(), expectedFromRevisionOverride = "99" });
        Assert.Equal("rejected", rejected.Json.GetProperty("outcome").GetString());
        Assert.True(rejected.Json.GetProperty("rolledBack").GetBoolean());
        Assert.Equal(rejected.Json.GetProperty("outboxBefore").GetProperty("count").GetString(), rejected.Json.GetProperty("outboxAfter").GetProperty("count").GetString());
        var insufficient = await Operation(host, "guard", new { scope, from = "alpha", to = "beta", amount = "101", commandId = T.Uuid() });
        Assert.Equal("rejected", insufficient.Json.GetProperty("outcome").GetString());
        Assert.True(insufficient.Json.GetProperty("rolledBack").GetBoolean());
        var command = T.Uuid();
        Assert.Equal("committed", (await Operation(host, "guard", new { scope, from = "alpha", to = "beta", amount = "1", commandId = command })).Json.GetProperty("outcome").GetString());
        Assert.Equal("replayed", (await Operation(host, "guard", new { scope, from = "alpha", to = "beta", amount = "1", commandId = command })).Json.GetProperty("outcome").GetString());
        Assert.Equal("idempotencyConflict", (await Operation(host, "guard", new { scope, from = "alpha", to = "beta", amount = "2", commandId = command })).Json.GetProperty("outcome").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await Operation(host, "guard", new { scope, from = "gamma", to = "beta", amount = "1", commandId = T.Uuid() })).Status);
        foreach (var bad in new object[]
        {
            new { scope, from = "alpha", to = "alpha", amount = "1", commandId = T.Uuid() },
            new { scope, from = "alpha", to = "beta", amount = "0", commandId = T.Uuid() },
            new { scope, from = "alpha", to = "beta", amount = "-1", commandId = T.Uuid() },
            new { scope, from = "alpha", to = "beta", amount = "1.5", commandId = T.Uuid() },
            new { scope, from = "alpha", to = "beta", amount = "1", commandId = "x" },
        })
            Assert.Equal(HttpStatusCode.BadRequest, (await Operation(host, "guard", bad)).Status);
    }

    [Fact]
    public async Task StorageFailuresMapToClosedErrorCodes()
    {
        await using var host = await StartAsync();
        var body = new { scope = "proof/x", total = 5 };
        foreach (var (kind, status, code) in new[]
        {
            (PlanFailureKind.UnknownOutcome, HttpStatusCode.ServiceUnavailable, "unknown_outcome"),
            (PlanFailureKind.Unavailable, HttpStatusCode.ServiceUnavailable, "unavailable"),
            (PlanFailureKind.ManifestMismatch, HttpStatusCode.ServiceUnavailable, "unavailable"),
            (PlanFailureKind.Overloaded, HttpStatusCode.ServiceUnavailable, "unavailable"),
            (PlanFailureKind.Constraint, HttpStatusCode.Conflict, "conflict"),
        })
        {
            host.Storage.Fault = _ => kind;
            var reply = await Operation(host, "job/start", body);
            Assert.Equal(status, reply.Status);
            Assert.Equal(code, reply.Json.GetProperty("error").GetString());
            Assert.DoesNotContain("job-start", reply.Text, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task IssuingASessionOverTheInternalRouteYieldsAWorkingBrowserSession()
    {
        await using var host = await StartAsync();
        var issued = await Operation(host, "session/issue", new { userId = T.Uuid(), deviceId = T.Uuid(), workspaceIds = new[] { T.Uuid() } });
        Assert.Equal(HttpStatusCode.OK, issued.Status);
        var cookie = "__Host-af_session=" + issued.Json.GetProperty("handle").GetString();
        var csrf = issued.Json.GetProperty("csrfToken").GetString();
        var bootstrap = await Send(host, Browser("GET", "/session/v1/bootstrap", cookie, Origin));
        Assert.True(bootstrap.Json.GetProperty("authenticated").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await Send(host, Browser("POST", "/session/v1/logout", cookie, Origin, csrf))).Status);
        foreach (var bad in new object[]
        {
            new { userId = "x", deviceId = T.Uuid(), workspaceIds = Array.Empty<string>() },
            new { userId = T.Uuid(), deviceId = T.Uuid(), workspaceIds = new[] { T.Uuid(), T.Uuid(), T.Uuid(), T.Uuid() } },
        })
            Assert.Equal(HttpStatusCode.BadRequest, (await Operation(host, "session/issue", bad)).Status);
        // The handle is only ever returned by the issue reply; the stored row has its hash alone.
        Assert.DoesNotContain(host.Storage.Sessions, s => Encoding.UTF8.GetString(s.Hash).Contains(issued.Json.GetProperty("handle").GetString()!, StringComparison.Ordinal));
    }

    [Fact]
    public async Task JobRoutesRunBoundedSlicesToACompleteExactChecksum()
    {
        await using var host = await StartAsync();
        var scope = "proof/job";
        var started = await Operation(host, "job/start", new { scope, total = 150 });
        var job = started.Json.GetProperty("jobId").GetString()!;
        var eventId = T.Uuid();
        var first = await Operation(host, "job/slice", new { scope, jobId = job, eventId, maxItems = 100, maxMilliseconds = 20000 });
        Assert.Equal("running", first.Json.GetProperty("state").GetString());
        Assert.Equal("100", first.Json.GetProperty("cursor").GetString());
        Assert.False(first.Json.GetProperty("jobComplete").GetBoolean());
        var repeat = await Operation(host, "job/slice", new { scope, jobId = job, eventId, maxItems = 100, maxMilliseconds = 20000 });
        Assert.Equal("duplicate", repeat.Json.GetProperty("state").GetString());
        Assert.Equal("100", repeat.Json.GetProperty("cursor").GetString());
        var last = await Operation(host, "job/slice", new { scope, jobId = job, eventId = T.Uuid(), maxItems = 100, maxMilliseconds = 20000 });
        Assert.Equal("complete", last.Json.GetProperty("state").GetString());
        Assert.True(last.Json.GetProperty("jobComplete").GetBoolean());
        var status = await Operation(host, "job/status", new { scope, jobId = job });
        Assert.Equal(JobSliceService.ExpectedChecksum(150).ToString(System.Globalization.CultureInfo.InvariantCulture), status.Json.GetProperty("checksum").GetString());
        Assert.Equal("150", status.Json.GetProperty("itemCount").GetString());
        Assert.True(status.Json.GetProperty("matches").GetBoolean());
        foreach (var bad in new object[]
        {
            new { scope, jobId = job, eventId = T.Uuid(), maxItems = 101, maxMilliseconds = 1000 },
            new { scope, jobId = job, eventId = T.Uuid(), maxItems = 0, maxMilliseconds = 1000 },
            new { scope, jobId = job, eventId = T.Uuid(), maxItems = 10, maxMilliseconds = 20001 },
            new { scope, jobId = job, eventId = "x", maxItems = 10, maxMilliseconds = 1000 },
        })
            Assert.Equal(HttpStatusCode.BadRequest, (await Operation(host, "job/slice", bad)).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await Operation(host, "job/slice", new { scope, jobId = T.Uuid(), eventId = T.Uuid(), maxItems = 5, maxMilliseconds = 1000 })).Status);
        Assert.Equal(HttpStatusCode.NotFound, (await Operation(host, "job/status", new { scope, jobId = T.Uuid() })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Operation(host, "job/start", new { scope, total = 1001 })).Status);
        Assert.Equal(HttpStatusCode.BadRequest, (await Operation(host, "job/start", new { scope = "../x", total = 5 })).Status);
    }

    private static Uri ClosedLoopbackAddress()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return new Uri($"http://127.0.0.1:{port}/");
    }

    private static async Task<(WebApplication App, Uri Address)> StartAnsweringServerAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(kestrel => kestrel.Listen(IPAddress.Loopback, 0, listen => listen.Protocols = HttpProtocols.Http1));
        var app = builder.Build();
        app.MapMethods("/{**path}", ["HEAD", "GET"], () => Results.Ok());
        await app.StartAsync();
        return (app, new Uri(app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single()));
    }

    [Fact]
    public async Task TheEgressProbeReportsBlockedOnlyWhenEveryTargetRefusesTheConnectionAndTheControlAnswers()
    {
        var closedA = ClosedLoopbackAddress();
        var closedB = ClosedLoopbackAddress();
        // The real HTTP stack and the real host route: a refused connection is the blocked outcome.
        await using var blocked = await StartAsync(probe: new EgressProbe(FoundationModule.NewClient, [closedA, closedB], _ => Task.FromResult(true)));
        var reply = await Operation(blocked, "egress/probe", new { });
        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.True(reply.Json.GetProperty("blocked").GetBoolean());
        Assert.True(reply.Json.GetProperty("controlOk").GetBoolean());
        var attempts = reply.Json.GetProperty("attempts").EnumerateArray().ToArray();
        Assert.Equal(2, attempts.Length);
        Assert.All(attempts, attempt => Assert.Equal("connection_failed", attempt.GetProperty("outcome").GetString()));
        Assert.Equal(["127.0.0.1", "127.0.0.1"], attempts.Select(attempt => attempt.GetProperty("host").GetString()));
        // The default route also exercises the production wiring: the control is the host's own storage readiness.
        var (server, open) = await StartAnsweringServerAsync();
        try
        {
            // One answering target is an open route: never "blocked", whatever else was refused.
            await using var leaking = await StartAsync(probe: new EgressProbe(FoundationModule.NewClient, [closedA, open], _ => Task.FromResult(true)));
            var leak = await Operation(leaking, "egress/probe", new { });
            Assert.False(leak.Json.GetProperty("blocked").GetBoolean());
            var outcomes = leak.Json.GetProperty("attempts").EnumerateArray().Select(a => a.GetProperty("outcome").GetString()).ToArray();
            Assert.Equal(["connection_failed", "http_response"], outcomes);
            Assert.Equal(200, leak.Json.GetProperty("attempts")[1].GetProperty("status").GetInt32());
        }
        finally
        {
            await server.StopAsync(T.Ct);
            await server.DisposeAsync();
        }

        Assert.Equal(HttpStatusCode.BadRequest, (await Operation(blocked, "egress/probe", new { extra = 1 })).Status);
    }

    [Fact]
    public async Task TheEgressProbeFailsClosedWithoutTheControlOnATimeoutOrWithoutTargets()
    {
        var closed = ClosedLoopbackAddress();
        // A broken control path means the probe proves nothing: never blocked.
        var noControl = await new EgressProbe(FoundationModule.NewClient, [closed], _ => Task.FromResult(false)).RunAsync(T.Ct);
        Assert.False(noControl.Blocked);
        Assert.False(noControl.ControlOk);
        Assert.False((await new EgressProbe(FoundationModule.NewClient, [], _ => Task.FromResult(true)).RunAsync(T.Ct)).Blocked);
        // A target that accepts the connection but never answers is a timeout, which is not a block.
        var silent = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        silent.Start();
        try
        {
            var address = new Uri($"http://127.0.0.1:{((IPEndPoint)silent.LocalEndpoint).Port}/");
            var result = await new EgressProbe(FoundationModule.NewClient, [address], _ => Task.FromResult(true), TimeSpan.FromMilliseconds(300)).RunAsync(T.Ct);
            Assert.False(result.Blocked);
            Assert.Equal("timeout", Assert.Single(result.Attempts).Outcome);
        }
        finally
        {
            silent.Stop();
        }

        // A peer that completes the TCP handshake and then closes or resets was reachable: never blocked.
        foreach (var reset in new[] { false, true })
        {
            var peer = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            peer.Start();
            var accepting = Task.Run(async () =>
            {
                using var accepted = await peer.AcceptTcpClientAsync(T.Ct);
                if (reset) accepted.LingerState = new System.Net.Sockets.LingerOption(true, 0);
            }, T.Ct);
            try
            {
                var address = new Uri($"http://127.0.0.1:{((IPEndPoint)peer.LocalEndpoint).Port}/");
                var result = await new EgressProbe(FoundationModule.NewClient, [address], _ => Task.FromResult(true)).RunAsync(T.Ct);
                await accepting;
                Assert.False(result.Blocked);
                Assert.Equal("reached_then_failed", Assert.Single(result.Attempts).Outcome);
            }
            finally
            {
                peer.Stop();
            }
        }

        Assert.Equal(["example.com", "1.1.1.1"], EgressProbe.PublicTargets.Select(uri => uri.Host));
    }
}
