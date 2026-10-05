// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Ingress;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.Foundation.V1;
using ArcForges.Contracts.Hello.V1;
using Google.Protobuf;
using Grpc.AspNetCore.Server;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests;

/// <summary>The public ingress pipeline on the real Kestrel host, the real gRPC-Web adapter and the plan model for sessions.</summary>
public sealed partial class IngressPipelineTests
{
    private const string Origin = "https://app.example.test";
    private const string GrpcWeb = "application/grpc-web+proto";
    private static readonly DateTimeOffset Start = new(2026, 10, 4, 12, 0, 0, TimeSpan.Zero);

    private sealed class Running(WebApplication app, HttpClient client, FakeStorage storage, FakeTime time, FoundationOptions options, PipelineProbeState probe)
        : IAsyncDisposable
    {
        public WebApplication App { get; } = app;
        public HttpClient Client { get; } = client;
        public FakeStorage Storage { get; } = storage;
        public FakeTime Time { get; } = time;
        public FoundationOptions Options { get; } = options;
        public PipelineProbeState Probe { get; } = probe;
        public SessionService Sessions => App.Services.GetRequiredService<SessionService>();

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await App.StopAsync();
            await App.DisposeAsync();
        }
    }

    private sealed class BearerStub(CallerContext? result) : IBearerTokenVerifier
    {
        public List<string> Tokens { get; } = [];

        public Task<CallerContext?> VerifyAsync(string token, CancellationToken cancellationToken)
        {
            Tokens.Add(token);
            return Task.FromResult(result);
        }
    }

    private static async Task<Running> StartAsync(IBearerTokenVerifier? bearer = null, bool proof = true, IHostModule? extra = null)
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
        if (bearer is not null) builder.Services.AddSingleton(bearer);
        IHostModule[] served =
        [
            new HelloModule(BuildIdentity.FromAssembly(typeof(HelloEndpoint).Assembly)),
            proof ? new FoundationModule(options) : new FoundationModule(_ => null),
            .. extra is null ? Array.Empty<IHostModule>() : [extra],
        ];
        IHostModule[] modules = [new IngressModule(served), .. served];
        foreach (var module in modules) module.Register(builder);
        var app = builder.Build();
        foreach (var module in modules) module.Map(app);
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        var probe = app.Services.GetService<PipelineProbeState>() ?? new PipelineProbeState();
        return new Running(app, new HttpClient { BaseAddress = new Uri(address), Timeout = TimeSpan.FromSeconds(30) }, storage, time, options, probe);
    }

    private static byte[] IdBytes(string uuid) => Convert.FromHexString(uuid.Replace("-", "", StringComparison.Ordinal));

    private static byte[] Meta(string? workspace, ulong? generation = null, params (int Field, ulong Value)[] extra)
    {
        var meta = new RequestMeta();
        if (workspace is not null) meta.WorkspaceId = new Id { Value = ByteString.CopyFrom(IdBytes(workspace)) };
        if (generation is { } value) meta.RecoveryGeneration = value;
        var bytes = new List<byte> { 0x0a };
        var body = meta.ToByteArray();
        bytes.Add((byte)body.Length);
        bytes.AddRange(body);
        foreach (var (field, number) in extra)
        {
            bytes.Add((byte)(field << 3));
            bytes.Add((byte)number);
        }

        return [.. bytes];
    }

    private static byte[] Varint(ulong value)
    {
        var bytes = new List<byte>();
        while (value >= 0x80)
        {
            bytes.Add((byte)(value | 0x80));
            value >>= 7;
        }

        bytes.Add((byte)value);
        return [.. bytes];
    }

    private static byte[] StreamRequest(string workspace, int frames, int interval) =>
        [.. Meta(workspace), .. Varint((10 << 3) | 0), .. Varint((ulong)frames), .. Varint((11 << 3) | 0), .. Varint((ulong)interval)];

    private static HttpRequestMessage Rpc(string path, byte[]? message, string? cookie = null, string? origin = null, string? csrf = null,
        string? authorization = null, string contentType = GrpcWeb, string? timeout = null, byte[]? rawBody = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new ByteArrayContent(rawBody ?? GrpcWebFraming.Frame(message ?? [])),
        };
        request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);
        if (cookie is not null) request.Headers.TryAddWithoutValidation("Cookie", cookie);
        if (origin is not null) request.Headers.TryAddWithoutValidation("Origin", origin);
        if (csrf is not null) request.Headers.TryAddWithoutValidation("X-AF-CSRF", csrf);
        if (authorization is not null) request.Headers.TryAddWithoutValidation("Authorization", authorization);
        if (timeout is not null) request.Headers.TryAddWithoutValidation("grpc-timeout", timeout);
        return request;
    }

    private sealed record Reply(HttpStatusCode Status, HttpResponseHeaders Headers, List<(byte Flag, byte[] Payload)> Frames)
    {
        public byte[]? Message => Frames.FirstOrDefault(f => f.Flag == 0).Payload;

        public (int Status, string? Message, Dictionary<string, string> All) Trailer()
        {
            var payload = Frames.Last(f => f.Flag == 0x80).Payload;
            var all = new Dictionary<string, string>();
            foreach (var line in Encoding.ASCII.GetString(payload).Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
            {
                var separator = line.IndexOf(": ", StringComparison.Ordinal);
                all[line[..separator]] = line[(separator + 2)..];
            }

            return (int.Parse(all["grpc-status"], System.Globalization.CultureInfo.InvariantCulture), all.GetValueOrDefault("grpc-message"), all);
        }
    }

    private static List<(byte Flag, byte[] Payload)> ParseFrames(byte[] body)
    {
        var frames = new List<(byte, byte[])>();
        var position = 0;
        while (position < body.Length)
        {
            var length = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(body.AsSpan(position + 1));
            frames.Add((body[position], body.AsSpan(position + 5, length).ToArray()));
            position += 5 + length;
        }

        return frames;
    }

    private static async Task<Reply> Send(Running host, HttpRequestMessage request)
    {
        using var response = await host.Client.SendAsync(request, T.Ct);
        var body = await response.Content.ReadAsByteArrayAsync(T.Ct);
        return new Reply(response.StatusCode, response.Headers, response.StatusCode == HttpStatusCode.OK ? ParseFrames(body) : []);
    }

    private static async Task<(IssuedSession Issued, string Workspace)> Issue(Running host, params string[] extraWorkspaces)
    {
        var workspace = T.Uuid();
        var issued = await host.Sessions.IssueAsync(T.Uuid(), T.Uuid(), [workspace, .. extraWorkspaces], T.Ct);
        return (issued, workspace);
    }

    private static HttpRequestMessage Authorized(string path, byte[] message, IssuedSession issued, string? origin = Origin, string? csrf = null, string? timeout = null) =>
        Rpc(path, message, cookie: "__Host-af_session=" + issued.Handle, origin: origin, csrf: csrf ?? issued.CsrfToken, timeout: timeout);

    private static string ReadString(byte[] message, int wanted)
    {
        var position = 0;
        while (position < message.Length)
        {
            Assert.True(ProtoWire.TryReadTag(message, ref position, out var field, out var wire));
            if (wire == 2)
            {
                Assert.True(ProtoWire.TryReadLengthDelimited(message, ref position, out var bytes));
                if (field == wanted) return Encoding.UTF8.GetString(bytes);
            }
            else
            {
                Assert.True(ProtoWire.TrySkip(message, ref position, wire));
            }
        }

        throw new InvalidOperationException("field absent");
    }

    private static ulong ReadVarint(byte[] message, int wanted)
    {
        var position = 0;
        while (position < message.Length)
        {
            Assert.True(ProtoWire.TryReadTag(message, ref position, out var field, out var wire));
            if (wire == 0)
            {
                Assert.True(ProtoWire.TryReadVarint(message, ref position, out var value));
                if (field == wanted) return value;
            }
            else
            {
                Assert.True(ProtoWire.TrySkip(message, ref position, wire));
            }
        }

        return 0;
    }

    private static int Status(Reply reply) => reply.Trailer().Status;

    // ---- anonymous Hello through the real pipeline and the real gRPC-Web adapter ----

    [Fact]
    public async Task AnonymousHelloIsAdmittedAndAnswersWithDataAndTrailerFrames()
    {
        await using var host = await StartAsync();
        var reply = await Send(host, Rpc("/arcforges.hello.v1.HelloService/SayHello", new SayHelloRequest { Name = "pipeline" }.ToByteArray()));
        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.Equal("Hello, pipeline!", SayHelloResponse.Parser.ParseFrom(reply.Message).Message);
        Assert.Equal(0, Status(reply));
        Assert.True(reply.Headers.CacheControl!.NoStore);
        Assert.Empty(host.Storage.Calls);
    }

    [Fact]
    public async Task AnonymousHelloIgnoresEveryCredentialAndNeverReadsAStore()
    {
        var bearer = new BearerStub(null);
        await using var host = await StartAsync(bearer);
        var reply = await Send(host, Rpc("/arcforges.hello.v1.HelloService/SayHello", new SayHelloRequest { Name = "x" }.ToByteArray(),
            cookie: "__Host-af_session=" + new string('A', 43), origin: "https://evil.example", csrf: "bad", authorization: "Bearer " + new string('b', 40)));
        Assert.Equal(0, Status(reply));
        Assert.Empty(host.Storage.Calls);
        Assert.Empty(bearer.Tokens);
    }

    [Fact]
    public async Task ARequestThatIsNotBinaryGrpcWebUnaryIsRefusedBeforeAnyHandler()
    {
        await using var host = await StartAsync();
        const string path = "/arcforges.hello.v1.HelloService/SayHello";
        var message = new SayHelloRequest { Name = "x" }.ToByteArray();
        using (var get = await host.Client.GetAsync(path, T.Ct)) Assert.Equal(HttpStatusCode.MethodNotAllowed, get.StatusCode);
        foreach (var contentType in new[] { "application/json", "application/grpc", "application/grpc-web-text+proto", "application/grpc-web+json" })
        {
            using var response = await host.Client.SendAsync(Rpc(path, message, contentType: contentType), T.Ct);
            Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        }

        var compressed = Rpc(path, message);
        compressed.Headers.TryAddWithoutValidation("grpc-encoding", "gzip");
        using (var response = await host.Client.SendAsync(compressed, T.Ct)) Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
        var encoded = Rpc(path, message);
        encoded.Content!.Headers.ContentEncoding.Add("gzip");
        using (var response = await host.Client.SendAsync(encoded, T.Ct)) Assert.Equal(HttpStatusCode.UnsupportedMediaType, response.StatusCode);
    }

    [Fact]
    public async Task AnUnregisteredRpcShapedPathIsUnimplementedAndOtherPathsPassThrough()
    {
        await using var host = await StartAsync();
        var reply = await Send(host, Rpc("/arcforges.publicapi.v1.IdentityService/GetProfile", []));
        Assert.Equal(GrpcWebFraming.Unimplemented, Status(reply));
        var shaped = await Send(host, Rpc("/arcforges.proof.v1.PipelineProbe/Unknown", []));
        Assert.Equal(GrpcWebFraming.Unimplemented, Status(shaped));
        using var health = await host.Client.GetAsync("/healthz", T.Ct);
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        using var missing = await host.Client.GetAsync("/other", T.Ct);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
    }

    [Fact]
    public async Task AnOversizedHelloBodyIsNotAdmittedPastItsBound()
    {
        await using var host = await StartAsync();
        var big = GrpcWebFraming.Frame(new byte[5000]);
        using var response = await host.Client.SendAsync(Rpc("/arcforges.hello.v1.HelloService/SayHello", null, rawBody: big), T.Ct);
        var body = await response.Content.ReadAsByteArrayAsync(T.Ct);
        if (response.StatusCode == HttpStatusCode.OK)
        {
            // The gRPC-Web adapter reports a refusal before any message either as a trailer frame or as grpc-status headers.
            var frames = ParseFrames(body);
            var status = frames.Any(f => f.Flag == 0x80)
                ? Status(new Reply(response.StatusCode, response.Headers, frames))
                : int.Parse(response.Headers.GetValues("grpc-status").Single(), System.Globalization.CultureInfo.InvariantCulture);
            Assert.NotEqual(0, status);
            Assert.DoesNotContain(frames, f => f.Flag == 0);
        }
        else
        {
            Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        }
    }

    // ---- credentials, origin, CSRF ----

    [Fact]
    public async Task ASessionMethodAdmitsAValidCookieOriginAndCsrfAndExposesTheCurrentOwner()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        var reply = await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(workspace), issued));
        Assert.Equal(HttpStatusCode.OK, reply.Status);
        Assert.Equal(0, Status(reply));
        Assert.Equal(issued.SessionId, ReadString(reply.Message!, 1));
        Assert.Equal(workspace, ReadString(reply.Message!, 3));
        Assert.Equal(0UL, ReadVarint(reply.Message!, 4));
    }

    [Fact]
    public async Task AMissingOrUnknownCredentialIsUnauthenticatedWithoutTouchingTheHandler()
    {
        await using var host = await StartAsync();
        var (_, workspace) = await Issue(host);
        foreach (var request in new[]
        {
            Rpc(PipelineProbe.WhoamiPath, Meta(workspace)),
            Rpc(PipelineProbe.WhoamiPath, Meta(workspace), cookie: "__Host-af_session=" + new string('A', 43), origin: Origin, csrf: new string('A', 43)),
            Rpc(PipelineProbe.WhoamiPath, Meta(workspace), cookie: "__Host-af_session=short", origin: Origin, csrf: new string('A', 43)),
            Rpc(PipelineProbe.WhoamiPath, Meta(workspace), cookie: "other=" + new string('A', 43), origin: Origin),
        })
        {
            Assert.Equal(GrpcWebFraming.Unauthenticated, Status(await Send(host, request)));
        }

        Assert.Equal(0, host.Probe.Started);
    }

    [Fact]
    public async Task EveryRpcIsUnsafeSoOriginMustBeExactAndCsrfMustBeTheSessionsOwn()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        var (other, _) = await Issue(host);
        foreach (var origin in new string?[] { null, "https://evil.example", Origin + "/", "http://app.example.test", Origin.ToUpperInvariant() })
        {
            Assert.Equal(GrpcWebFraming.PermissionDenied, Status(await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(workspace), issued, origin))));
        }

        var doubleOrigin = Authorized(PipelineProbe.WhoamiPath, Meta(workspace), issued);
        doubleOrigin.Headers.TryAddWithoutValidation("Origin", Origin);
        Assert.Equal(GrpcWebFraming.PermissionDenied, Status(await Send(host, doubleOrigin)));
        var anonymousCsrf = host.Sessions.AnonymousCsrf();
        foreach (var csrf in new[] { "", "x", other.CsrfToken, anonymousCsrf, issued.CsrfToken[..42] + (issued.CsrfToken[^1] == 'A' ? "B" : "A") })
        {
            var request = Authorized(PipelineProbe.WhoamiPath, Meta(workspace), issued, csrf: csrf);
            Assert.Equal(GrpcWebFraming.PermissionDenied, Status(await Send(host, request)));
        }

        var missing = Rpc(PipelineProbe.WhoamiPath, Meta(workspace), cookie: "__Host-af_session=" + issued.Handle, origin: Origin);
        Assert.Equal(GrpcWebFraming.PermissionDenied, Status(await Send(host, missing)));
        Assert.Equal(0, Status(await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(workspace), issued))));
    }

    [Fact]
    public async Task ARepeatedSessionCookieOrBothCredentialKindsAreNoCredential()
    {
        var bearer = new BearerStub(new CallerContext(CredentialKind.NativeBearer, T.Uuid(), T.Uuid(), T.Uuid(), [], 0));
        await using var host = await StartAsync(bearer);
        var (issued, workspace) = await Issue(host);
        var twice = Authorized(PipelineProbe.WhoamiPath, Meta(workspace), issued);
        twice.Headers.TryAddWithoutValidation("Cookie", "__Host-af_session=" + new string('A', 43));
        Assert.Equal(GrpcWebFraming.Unauthenticated, Status(await Send(host, twice)));
        var both = Authorized(PipelineProbe.WhoamiPath, Meta(workspace), issued);
        both.Headers.TryAddWithoutValidation("Authorization", "Bearer " + new string('b', 32));
        Assert.Equal(GrpcWebFraming.Unauthenticated, Status(await Send(host, both)));
        Assert.Empty(bearer.Tokens);
    }

    [Fact]
    public async Task ARevokedExpiredOrForeignGenerationSessionIsUnauthenticatedOnTheNextCall()
    {
        await using var host = await StartAsync();
        var (revoked, workspace) = await Issue(host);
        await host.Sessions.RevokeAsync(revoked.SessionId, T.Ct);
        Assert.Equal(GrpcWebFraming.Unauthenticated, Status(await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(workspace), revoked))));

        var (idle, idleWorkspace) = await Issue(host);
        host.Time.Advance(host.Options.IdleWindow + TimeSpan.FromSeconds(1));
        Assert.Equal(GrpcWebFraming.Unauthenticated, Status(await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(idleWorkspace), idle))));

        var (generation, generationWorkspace) = await Issue(host);
        host.Storage.ActiveGeneration = 1;
        var next = await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(generationWorkspace), generation));
        Assert.Equal(GrpcWebFraming.Unavailable, Status(next));
    }

    [Fact]
    public async Task ABearerCredentialNeedsAVerifierAndAValidatedNativeCaller()
    {
        var workspace = T.Uuid();
        var caller = new CallerContext(CredentialKind.NativeBearer, T.Uuid(), T.Uuid(), T.Uuid(), [workspace], 0);
        var token = "Bearer " + new string('t', 40);
        await using (var none = await StartAsync())
        {
            Assert.Equal(GrpcWebFraming.Unauthenticated, Status(await Send(none, Rpc(PipelineProbe.WhoamiPath, Meta(workspace), authorization: token))));
        }

        var refusing = new BearerStub(null);
        await using (var host = await StartAsync(refusing))
        {
            Assert.Equal(GrpcWebFraming.Unauthenticated, Status(await Send(host, Rpc(PipelineProbe.WhoamiPath, Meta(workspace), authorization: token))));
            foreach (var malformed in new[] { "Bearer short", "Basic " + new string('a', 40), "Bearer " + new string('a', 40) + " x", "Bearer " + new string('a', 4097), "bearer" })
            {
                Assert.Equal(GrpcWebFraming.Unauthenticated, Status(await Send(host, Rpc(PipelineProbe.WhoamiPath, Meta(workspace), authorization: malformed))));
            }

            Assert.Single(refusing.Tokens);
        }

        var accepting = new BearerStub(caller);
        await using (var host = await StartAsync(accepting))
        {
            // A bearer caller needs neither Origin nor CSRF: native clients carry no ambient credential.
            var reply = await Send(host, Rpc(PipelineProbe.WhoamiPath, Meta(workspace), authorization: token));
            Assert.Equal(0, Status(reply));
            Assert.Equal(workspace, ReadString(reply.Message!, 3));
            Assert.Equal(caller.SessionId, ReadString(reply.Message!, 1));
            var cookieKind = new BearerStub(caller with { Credential = CredentialKind.BrowserSession });
            await using var wrong = await StartAsync(cookieKind);
            Assert.Equal(GrpcWebFraming.Unauthenticated, Status(await Send(wrong, Rpc(PipelineProbe.WhoamiPath, Meta(workspace), authorization: token))));
        }
    }

    // ---- the current-owner gate ----

    [Fact]
    public async Task TheOwnerGateRefusesAWorkspaceTheSessionDoesNotOwnAndANonNegotiableEnvelope()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        var foreign = T.Uuid();
        Assert.Equal(GrpcWebFraming.PermissionDenied, Status(await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(foreign), issued))));
        Assert.Equal(GrpcWebFraming.InvalidArgument, Status(await Send(host, Authorized(PipelineProbe.WhoamiPath, [], issued))));
        Assert.Equal(GrpcWebFraming.InvalidArgument, Status(await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(null), issued))));
        Assert.Equal(GrpcWebFraming.InvalidArgument, Status(await Send(host, Authorized(PipelineProbe.WhoamiPath, [0x0a, 0x05, 0x01], issued))));
        var zero = Meta("00000000-0000-0000-0000-000000000000");
        Assert.Equal(GrpcWebFraming.InvalidArgument, Status(await Send(host, Authorized(PipelineProbe.WhoamiPath, zero, issued))));
        Assert.Equal(GrpcWebFraming.FailedPrecondition, Status(await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(workspace, 7), issued))));
        Assert.Equal(0, Status(await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(workspace, 0), issued))));
        var two = Authorized(PipelineProbe.WhoamiPath, [], issued);
        two.Content = new ByteArrayContent([.. GrpcWebFraming.Frame(Meta(workspace)), .. GrpcWebFraming.Frame(Meta(workspace))]);
        two.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(GrpcWeb);
        Assert.Equal(GrpcWebFraming.InvalidArgument, Status(await Send(host, two)));
        var compressedFlag = GrpcWebFraming.Frame(Meta(workspace));
        compressedFlag[0] = 1;
        var flagged = Authorized(PipelineProbe.WhoamiPath, [], issued);
        flagged.Content = new ByteArrayContent(compressedFlag);
        flagged.Content.Headers.ContentType = MediaTypeHeaderValue.Parse(GrpcWeb);
        Assert.Equal(GrpcWebFraming.InvalidArgument, Status(await Send(host, flagged)));
    }

    [Fact]
    public async Task ASessionOwnsEveryWorkspaceItWasIssuedAndNoOtherOne()
    {
        await using var host = await StartAsync();
        var second = T.Uuid();
        var (issued, first) = await Issue(host, second);
        Assert.Equal(first, ReadString((await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(first), issued))).Message!, 3));
        Assert.Equal(second, ReadString((await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(second), issued))).Message!, 3));
    }

    [Fact]
    public async Task TheMethodBodyBoundIsEnforcedOnActualBytes()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        var padded = Meta(workspace).Concat(Varint((12 << 3) | 2)).Concat(Varint(5000)).Concat(new byte[5000]).ToArray();
        Assert.Equal(GrpcWebFraming.ResourceExhausted, Status(await Send(host, Authorized(PipelineProbe.WhoamiPath, padded, issued))));
    }

    // ---- streaming, trailers, cancellation ----

    [Fact]
    public async Task AServerStreamReachesTheClientFrameByFrameAndEndsWithTheOkTrailerAndCustomTrailer()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        var request = Authorized(PipelineProbe.StreamPath, StreamRequest(workspace, 4, 250), issued);
        var clock = Stopwatch.StartNew();
        using var response = await host.Client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, T.Ct);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        await using var stream = await response.Content.ReadAsStreamAsync(T.Ct);
        var arrivals = new List<long>();
        var frames = new List<(byte Flag, byte[] Payload)>();
        while (true)
        {
            var header = new byte[5];
            if (!await ReadFull(stream, header)) break;
            var payload = new byte[System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1))];
            Assert.True(await ReadFull(stream, payload));
            arrivals.Add(clock.ElapsedMilliseconds);
            frames.Add((header[0], payload));
        }

        Assert.Equal(5, frames.Count);
        Assert.All(frames.Take(4), f => Assert.Equal(0, f.Flag));
        for (var i = 0; i < 4; i++)
        {
            Assert.Equal((ulong)i, ReadVarint(frames[i].Payload, 1));
            Assert.Equal(PipelineProbe.Payload(i), Convert.FromHexString(Convert.ToHexString(PayloadOf(frames[i].Payload))));
        }

        Assert.True(arrivals[0] < arrivals[3] - 400, "the first frame must not wait for the others: " + arrivals[0] + " ms");
        Assert.True(arrivals[3] - arrivals[0] >= 600, "the frames must arrive over time, not at the end: " + (arrivals[3] - arrivals[0]) + " ms");
        var trailer = new Reply(response.StatusCode, response.Headers, frames).Trailer();
        Assert.Equal(0, trailer.Status);
        Assert.Equal(PipelineProbe.TrailerValue, trailer.All[PipelineProbe.TrailerName]);
        Assert.Equal(1, host.Probe.Completed);
    }

    private static byte[] PayloadOf(byte[] message)
    {
        var position = 0;
        while (position < message.Length)
        {
            Assert.True(ProtoWire.TryReadTag(message, ref position, out var field, out var wire));
            if (wire == 2)
            {
                Assert.True(ProtoWire.TryReadLengthDelimited(message, ref position, out var bytes));
                if (field == 2) return bytes.ToArray();
            }
            else
            {
                Assert.True(ProtoWire.TrySkip(message, ref position, wire));
            }
        }

        throw new InvalidOperationException("payload absent");
    }

    private static async Task<bool> ReadFull(Stream stream, byte[] buffer)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer.AsMemory(read), T.Ct);
            if (count == 0) return read != 0 ? throw new EndOfStreamException() : false;
            read += count;
        }

        return true;
    }

    [Fact]
    public async Task ClosingAStreamIsObservedByTheHostAndStopsProduction()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        using (var response = await host.Client.SendAsync(Authorized(PipelineProbe.StreamPath, StreamRequest(workspace, 50, 100), issued), HttpCompletionOption.ResponseHeadersRead, T.Ct))
        {
            await using var stream = await response.Content.ReadAsStreamAsync(T.Ct);
            var header = new byte[5];
            Assert.True(await ReadFull(stream, header));
        }

        var deadline = Stopwatch.StartNew();
        while (host.Probe.Canceled == 0 && deadline.Elapsed < TimeSpan.FromSeconds(5)) await Task.Delay(25, T.Ct);
        Assert.Equal(1, host.Probe.Canceled);
        Assert.Equal(0, host.Probe.Completed);
        var observation = await Send(host, Authorized(PipelineProbe.ObservationPath, Meta(workspace), issued));
        Assert.Equal(1UL, ReadVarint(observation.Message!, 3));
    }

    [Fact]
    public async Task AStreamDeadlineEndsWithADeadlineExceededTrailerNotASilentEof()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        var reply = await Send(host, Authorized(PipelineProbe.StreamPath, StreamRequest(workspace, 10, 200), issued, timeout: "300m"));
        Assert.Equal(GrpcWebFraming.DeadlineExceeded, Status(reply));
        Assert.InRange(reply.Frames.Count(f => f.Flag == 0), 1, 3);
        Assert.Equal(1, host.Probe.DeadlineExceeded);
    }

    [Fact]
    public async Task APassiveStreamNeverRenewsTheSessionIdleExpiry()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        var before = host.Storage.Sessions.Single().Idle;
        host.Time.Advance(TimeSpan.FromMinutes(5));
        var reply = await Send(host, Authorized(PipelineProbe.StreamPath, StreamRequest(workspace, 2, 10), issued));
        Assert.Equal(0, Status(reply));
        Assert.Equal(before, host.Storage.Sessions.Single().Idle);
        Assert.DoesNotContain("foundation.session-touch", host.Storage.Calls);
    }

    [Fact]
    public async Task TheProbeRefusesOutOfBoundStreamRequests()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        foreach (var (frames, interval) in new[] { (0, 10), (PipelineProbe.MaxFrames + 1, 1), (10, PipelineProbe.MaxIntervalMilliseconds + 1), (50, 1000) })
        {
            Assert.Equal(GrpcWebFraming.InvalidArgument, Status(await Send(host, Authorized(PipelineProbe.StreamPath, StreamRequest(workspace, frames, interval), issued))));
        }

        Assert.Equal(0, host.Probe.Started);
    }

    // ---- deny by default, composition and the probe boundary ----

    [Fact]
    public async Task TheProbeMethodsExistOnlyWhenTheFoundationProofIsEnabled()
    {
        await using var off = await StartAsync(proof: false);
        Assert.Equal(GrpcWebFraming.Unimplemented, Status(await Send(off, Rpc(PipelineProbe.WhoamiPath, Meta(T.Uuid())))));
        Assert.Equal(GrpcWebFraming.Unimplemented, Status(await Send(off, Rpc(PipelineProbe.StreamPath, StreamRequest(T.Uuid(), 1, 1)))));
    }

    [Fact]
    public async Task EveryMappedGrpcMethodHasAnIngressPolicyAndEveryPolicyHasAnEndpoint()
    {
        await using var host = await StartAsync();
        var endpoints = host.App.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().ToList();
        var grpc = endpoints
            .Select(e => e.Metadata.GetMetadata<GrpcMethodMetadata>())
            .Where(m => m is not null)
            .Select(m => m!.Method.FullName.StartsWith('/') ? m.Method.FullName : "/" + m.Method.FullName)
            .ToList();
        Assert.Contains("/arcforges.hello.v1.HelloService/SayHello", grpc);
        var policies = new IHostModule[] { new HelloModule(BuildIdentity.FromAssembly(typeof(HelloEndpoint).Assembly)), new FoundationModule(host.Options) }
            .SelectMany(m => m.RpcPolicies).ToDictionary(p => p.FullName);
        foreach (var method in grpc) Assert.True(policies.ContainsKey(method), "No ingress policy for " + method);
        var plain = endpoints.Select(e => e.RoutePattern.RawText).ToHashSet();
        foreach (var policy in policies.Values) Assert.True(grpc.Contains(policy.FullName) || plain.Contains(policy.FullName), "No endpoint for " + policy.FullName);
        Assert.All(policies.Values, p => Assert.True(RpcPolicy.IsValidName(p.FullName)));
    }

    [Fact]
    public void ThePolicyTableRefusesDuplicatesAndMalformedNamesAndAnonymousOwnerScope()
    {
        var one = RpcPolicy.Unary("/a.b.Service/Method", RpcAuthentication.Anonymous, RpcScope.None);
        Assert.Throws<InvalidOperationException>(() => RpcPolicyRegistry.Create([one, one]));
        foreach (var name in new[] { "/Service/Method", "/a.b.service/Method", "/a.b.Service/method", "a.b.Service/Method", "/a.b.Service/Method/", "/a.b.Service", "/a..b.Service/M" })
        {
            Assert.False(RpcPolicy.IsValidName(name), name);
            Assert.Throws<ArgumentException>(() => RpcPolicy.Unary(name, RpcAuthentication.Anonymous, RpcScope.None));
        }

        Assert.Throws<ArgumentException>(() => RpcPolicy.Unary("/a.b.Service/Method", RpcAuthentication.Anonymous, RpcScope.Workspace));
        Assert.Throws<ArgumentOutOfRangeException>(() => RpcPolicy.Unary("/a.b.Service/Method", RpcAuthentication.Session, RpcScope.None, 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => RpcPolicy.Unary("/a.b.Service/Method", RpcAuthentication.Session, RpcScope.None, RpcPolicy.AbsoluteMaxRequestBytes + 1));
    }

    [Fact]
    public void TheProductionCompositionRegistersOnlyHelloAndTheSessionCookieNameStaysTheFoundationName()
    {
        Assert.Equal(FoundationOptions.CookieName, IngressPipeline.SessionCookieName);
        var served = new IHostModule[] { new HelloModule(BuildIdentity.FromAssembly(typeof(HelloEndpoint).Assembly)), new FoundationModule(_ => null) };
        var registry = RpcPolicyRegistry.Create(served.SelectMany(m => m.RpcPolicies));
        var only = Assert.Single(registry.All);
        Assert.Equal("/arcforges.hello.v1.HelloService/SayHello", only.FullName);
        Assert.Equal(RpcAuthentication.Anonymous, only.Authentication);
    }

    // ---- deny by default does not depend on the shape of a path ----

    /// <summary>One request with a verbatim target (an HTTP client would normalise it): the status code and the raw reply text.</summary>
    private static async Task<(int Status, string Reply)> RawAsync(Running host, string method, string target, IEnumerable<(string, string)>? headers = null, byte[]? body = null)
    {
        using var tcp = new System.Net.Sockets.TcpClient();
        await tcp.ConnectAsync(host.Client.BaseAddress!.Host, host.Client.BaseAddress.Port, T.Ct);
        var stream = tcp.GetStream();
        var head = new StringBuilder().Append(method).Append(' ').Append(target).Append(" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
        foreach (var (name, value) in headers ?? []) head.Append(name).Append(": ").Append(value).Append("\r\n");
        head.Append("Content-Length: ").Append(body?.Length ?? 0).Append("\r\n\r\n");
        await stream.WriteAsync(Encoding.ASCII.GetBytes(head.ToString()), T.Ct);
        if (body is not null) await stream.WriteAsync(body, T.Ct);
        using var reply = new MemoryStream();
        await stream.CopyToAsync(reply, T.Ct);
        var text = Encoding.Latin1.GetString(reply.ToArray());
        return (int.Parse(text.AsSpan(9, 3), System.Globalization.CultureInfo.InvariantCulture), text);
    }

    private static bool Refused((int Status, string Reply) reply) =>
        reply.Status is 400 or 404 || (reply.Status == 200 && reply.Reply.Contains("grpc-status: 12", StringComparison.Ordinal));

    [Fact]
    public async Task ANonCanonicalPathNeverReachesAnEndpointEvenWithAValidSession()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        var headers = new[] { ("Content-Type", GrpcWeb), ("Cookie", "__Host-af_session=" + issued.Handle), ("Origin", Origin), ("X-AF-CSRF", issued.CsrfToken) };
        var body = GrpcWebFraming.Frame(Meta(workspace));
        const string observation = "/arcforges.proof.v1.PipelineProbe/Observation";
        const string whoami = "/arcforges.proof.v1.PipelineProbe/Whoami";
        // Control: the canonical path is served.
        var control = await RawAsync(host, "POST", whoami, headers, body);
        Assert.Equal(200, control.Status);
        Assert.Contains("grpc-status: 0", control.Reply, StringComparison.Ordinal);
        foreach (var target in new[]
        {
            observation + "/", whoami + "/", whoami + "//", "/" + whoami, "//arcforges.proof.v1.PipelineProbe/Whoami",
            "/arcforges.proof.v1.PipelineProbe//Whoami", "/ARCFORGES.PROOF.V1.PIPELINEPROBE/WHOAMI", "/arcforges.proof.v1.pipelineprobe/whoami",
            "/arcforges.proof.v1.PipelineProbe/Who%61mi", "/arcforges.proof.v1.PipelineProbe/Whoami%2F", "/arcforges.proof.v1.PipelineProbe%2FWhoami",
            "/x/../arcforges.proof.v1.PipelineProbe/Whoami", "/./arcforges.proof.v1.PipelineProbe/Whoami", "/arcforges.proof.v1.PipelineProbe/./Whoami",
            "/arcforges.proof.v1.PipelineProbe/Whoami/.", "/arcforges.proof.v1.PipelineProbe\\Whoami", whoami + "?x=1/", whoami + "/?x=1",
        })
        {
            var reply = await RawAsync(host, "POST", target, headers, body);
            if (target.EndsWith("?x=1/", StringComparison.Ordinal))
            {
                Assert.Equal(200, reply.Status); // a query on the canonical path is still the canonical path
                continue;
            }

            Assert.True(Refused(reply), $"{target} reached an endpoint: {reply.Reply[..Math.Min(80, reply.Reply.Length)]}");
            Assert.DoesNotContain("grpc-status: 0", reply.Reply, StringComparison.Ordinal);
        }

        Assert.Equal(0, host.Probe.Started);
    }

    [Fact]
    public async Task ANonCanonicalPathCannotReadTheAnonymousProbeCountersOrCrashAHandler()
    {
        await using var host = await StartAsync();
        foreach (var target in new[] { "/arcforges.proof.v1.PipelineProbe/Observation/", "/arcforges.proof.v1.PipelineProbe/Whoami/", "/arcforges.proof.v1.PipelineProbe/Stream/" })
        {
            var reply = await RawAsync(host, "POST", target, [("Content-Type", GrpcWeb)], GrpcWebFraming.Frame([]));
            Assert.True(Refused(reply), target);
            Assert.NotEqual(500, reply.Status);
        }
    }

    [Fact]
    public async Task OnlyDeclaredPlainRoutesPassThroughAndTheirVariantsAreRefused()
    {
        await using var host = await StartAsync();
        Assert.Equal(200, (await RawAsync(host, "GET", "/healthz")).Status);
        Assert.Equal(200, (await RawAsync(host, "GET", "/session/v1/bootstrap")).Status);
        foreach (var target in new[]
        {
            "/healthz/", "/HEALTHZ", "/%68ealthz", "//healthz", "/session/v1/bootstrap/", "/Session/v1/bootstrap", "/session//v1/bootstrap",
            "/session/v1/%62ootstrap", "/other", "/internal", "/internal/", "/internal/foundation/v1", "/internal/foundation/v1/", "/Internal/foundation/v1/readiness",
        })
        {
            Assert.Equal(404, (await RawAsync(host, "GET", target)).Status);
        }

        // Under a declared prefix the endpoint's own signature check answers; the pipeline does not authorise it.
        Assert.Equal(401, (await RawAsync(host, "POST", "/internal/foundation/v1/readiness", [("Content-Type", "application/json")], "{}"u8.ToArray())).Status);
        await using var off = await StartAsync(proof: false);
        Assert.Equal(404, (await RawAsync(off, "GET", "/session/v1/bootstrap")).Status);
        Assert.Equal(404, (await RawAsync(off, "POST", "/internal/foundation/v1/readiness", [("Content-Type", "application/json")], "{}"u8.ToArray())).Status);
        Assert.Equal(200, (await RawAsync(off, "GET", "/healthz")).Status);
    }

    [Fact]
    public async Task TheHostServesNoStorageEndpointToAnyCallerAndExecutesNoPlanForOne()
    {
        // The plan bridge is answered by the Worker's outbound handler; the Container never serves it. Whatever a caller signs, the
        // host has no such route, so it can neither execute a plan nor be asked to.
        foreach (var proof in new[] { true, false })
        {
            await using var host = await StartAsync(proof: proof);
            foreach (var target in new[]
            {
                WorkerPlanExecutor.ExecutePath, "/internal/storage/v1", "/internal/storage/v1/", WorkerPlanExecutor.ExecutePath + "/", WorkerPlanExecutor.ExecutePath + "?x=1",
                "/api" + WorkerPlanExecutor.ExecutePath, "/storage/v1/execute-plan",
            })
            {
                foreach (var method in new[] { "POST", "GET" })
                {
                    foreach (var key in new[] { host.Options.VerifyKeyW2c, host.Options.SigningKeyC2w })
                    {
                        var headers = new List<(string, string)> { ("Content-Type", "application/json") };
                        PrivateRequestSigner.Sign(method, target, T.Sha256Hex("{}"u8.ToArray()), T.Uuid(), key, host.Time).CopyTo((name, value) => headers.Add((name, value)));
                        var reply = await RawAsync(host, method, target, headers, "{}"u8.ToArray());
                        Assert.Equal(404, reply.Status);
                        Assert.DoesNotContain("manifest", reply.Reply, StringComparison.OrdinalIgnoreCase);
                    }
                }
            }

            Assert.Empty(host.Storage.Calls);
        }
    }

    [Fact]
    public void ThePathCanonicalityRuleIsExact()
    {
        foreach (var path in new[] { "/healthz", "/a.b.Service/Method", "/a/b-c/d_e", "/" })
            Assert.True(IngressPipeline.IsCanonical(new DefaultHttpContext(), path), path);
        foreach (var path in new[] { null, "", "healthz", "/a/", "//a", "/a//b", "/a/./b", "/a/../b", "/a/.", "/a/..", "/a\\b" })
            Assert.False(IngressPipeline.IsCanonical(new DefaultHttpContext(), path), path ?? "null");
    }

    // ---- wire helpers ----

    [Fact]
    public void TheEnvelopeReaderAgreesWithGeneratedRequestMessages()
    {
        var workspace = T.Uuid();
        var request = new ArcForges.Contracts.PublicApi.V1.WorkspaceServiceGetRequest
        {
            Meta = new RequestMeta
            {
                WorkspaceId = new Id { Value = ByteString.CopyFrom(IdBytes(workspace)) },
                RecoveryGeneration = 18_446_744_073_709_551_615UL,
                CommandId = new Id { Value = ByteString.CopyFrom(IdBytes(T.Uuid())) },
                CorrelationId = new Id { Value = ByteString.CopyFrom(IdBytes(T.Uuid())) },
            },
            WorkspaceId = new Id { Value = ByteString.CopyFrom(IdBytes(T.Uuid())) },
        };
        Assert.True(RequestEnvelopeReader.TryRead(request.ToByteArray(), out var envelope));
        Assert.Equal(workspace, envelope.WorkspaceId);
        Assert.Equal(ulong.MaxValue, envelope.RecoveryGeneration);
        var withoutMeta = new ArcForges.Contracts.PublicApi.V1.WorkspaceServiceGetRequest { WorkspaceId = request.WorkspaceId };
        Assert.True(RequestEnvelopeReader.TryRead(withoutMeta.ToByteArray(), out var none));
        Assert.Null(none.WorkspaceId);
        Assert.True(RequestEnvelopeReader.TryRead([], out var empty));
        Assert.Null(empty.RecoveryGeneration);
        Assert.Equal("00112233-4455-6677-8899-aabbccddeeff", RequestEnvelopeReader.FormatId(IdBytes("00112233-4455-6677-8899-aabbccddeeff")));
    }

    [Fact]
    public void TheEnvelopeReaderRefusesMalformedAndAmbiguousBytes()
    {
        var workspace = T.Uuid();
        var good = Meta(workspace);
        Assert.True(RequestEnvelopeReader.TryRead(good, out _));
        Assert.False(RequestEnvelopeReader.TryRead([.. good, .. good], out _), "a repeated meta is ambiguous");
        Assert.False(RequestEnvelopeReader.TryRead(good[..^1], out _), "truncated");
        Assert.False(RequestEnvelopeReader.TryRead([0x0b, 0x00], out _), "start group");
        Assert.False(RequestEnvelopeReader.TryRead([0x1d, 0x01], out _), "truncated fixed32");
        Assert.False(RequestEnvelopeReader.TryRead([0x08, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01], out _), "varint too long");
        Assert.False(RequestEnvelopeReader.TryRead([0x00, 0x01], out _), "field zero");
        Assert.False(RequestEnvelopeReader.TryRead([0x08, 0x01], out _), "meta with a varint wire type");
        Assert.False(RequestEnvelopeReader.TryRead([0x0a, 0x02, 0x20, 0x01], out _), "workspace as a varint");
        var twoWorkspaces = new List<byte> { 0x0a };
        var idField = new byte[] { 0x22, 0x12, 0x0a, 0x10 }.Concat(IdBytes(workspace)).ToArray();
        twoWorkspaces.Add((byte)(idField.Length * 2));
        twoWorkspaces.AddRange(idField);
        twoWorkspaces.AddRange(idField);
        Assert.False(RequestEnvelopeReader.TryRead(twoWorkspaces.ToArray(), out _), "a repeated workspace is ambiguous");
    }

    [Fact]
    public void TheFramingHelpersAcceptExactlyOneUncompressedDataFrame()
    {
        var message = new byte[] { 1, 2, 3 };
        Assert.True(GrpcWebFraming.TryReadSingleMessage(GrpcWebFraming.Frame(message), out var read));
        Assert.Equal(message, read.ToArray());
        Assert.True(GrpcWebFraming.TryReadSingleMessage(GrpcWebFraming.Frame([]), out _));
        Assert.False(GrpcWebFraming.TryReadSingleMessage([], out _));
        Assert.False(GrpcWebFraming.TryReadSingleMessage([0, 0, 0, 0], out _));
        Assert.False(GrpcWebFraming.TryReadSingleMessage([.. GrpcWebFraming.Frame(message), 0], out _));
        Assert.False(GrpcWebFraming.TryReadSingleMessage(GrpcWebFraming.Frame(message)[..^1], out _));
        Assert.False(GrpcWebFraming.TryReadSingleMessage([0, 0xff, 0xff, 0xff, 0xff, 1], out _));
        var trailer = GrpcWebFraming.TrailerFrame(GrpcWebFraming.Unavailable, "dependency.unavailable", ("x-a", "b"));
        Assert.Equal(0x80, trailer[0]);
        Assert.False(GrpcWebFraming.TryReadSingleMessage(trailer, out _));
        Assert.Equal("grpc-status: 14\r\ngrpc-message: dependency.unavailable\r\nx-a: b\r\n", Encoding.ASCII.GetString(trailer.AsSpan(5)));
    }

    [Fact]
    public void TheGrpcTimeoutHeaderParsesToTheExactDuration()
    {
        Assert.True(PipelineProbe.TryParseTimeout("300m", out var milliseconds));
        Assert.Equal(TimeSpan.FromMilliseconds(300), milliseconds);
        Assert.True(PipelineProbe.TryParseTimeout("2S", out var seconds));
        Assert.Equal(TimeSpan.FromSeconds(2), seconds);
        foreach (var bad in new[] { "", "m", "300", "300x", "123456789m", "-1m", "1.5S" }) Assert.False(PipelineProbe.TryParseTimeout(bad, out _), bad);
    }
}
