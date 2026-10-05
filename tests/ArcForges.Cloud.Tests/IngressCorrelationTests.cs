// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Ingress;
using ArcForges.Contracts.Foundation.V1;
using Google.Protobuf;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Xunit;

namespace ArcForges.Cloud.Tests;

/// <summary>
/// CLOUD.69 on the real Kestrel host and the real ingress pipeline: a client's correlation id is validated, an absent one is created, a
/// malformed one is refused before any handler, the identity is returned in ResponseMeta and ArcError, joined to the Worker's traceparent,
/// and never influences an admission or authorization decision.
/// </summary>
public sealed partial class IngressPipelineTests
{
    private const string EchoOpen = "/arcforges.test.v1.Echo/Open";
    private const string EchoAccount = "/arcforges.test.v1.Echo/Account";
    private const string EchoWorkspace = "/arcforges.test.v1.Echo/Workspace";
    private const string Nil = "00000000-0000-0000-0000-000000000000";

    /// <summary>Test-only module: three methods that report exactly what the pipeline bound to the call.</summary>
    private sealed class EchoModule : IHostModule
    {
        public int Handled;

        public IEnumerable<RpcPolicy> RpcPolicies =>
        [
            RpcPolicy.Unary(EchoOpen, RpcAuthentication.Anonymous, RpcScope.None),
            RpcPolicy.Unary(EchoAccount, RpcAuthentication.Session, RpcScope.None, carriesRequestMeta: true),
            RpcPolicy.Unary(EchoWorkspace, RpcAuthentication.Session, RpcScope.Workspace),
        ];

        public void Register(WebApplicationBuilder builder)
        {
        }

        public void Map(WebApplication app)
        {
            app.MapPost(EchoOpen, Handle);
            app.MapPost(EchoAccount, Handle);
            app.MapPost(EchoWorkspace, Handle);
        }

        private async Task Handle(HttpContext context)
        {
            Interlocked.Increment(ref Handled);
            var call = context.Features.Get<IngressCall>()!;
            var message = Concat(
                Len(1, Encoding.UTF8.GetBytes(call.Correlation.CorrelationId)),
                Len(2, Encoding.UTF8.GetBytes(call.Correlation.ParentSpanId ?? "")),
                Len(3, Encoding.UTF8.GetBytes(call.Correlation.SpanId)),
                Len(4, Encoding.UTF8.GetBytes(call.Correlation.Traceparent)),
                Len(5, Encoding.UTF8.GetBytes(call.Correlation.CausationId ?? "")));
            context.Response.StatusCode = StatusCodes.Status200OK;
            context.Response.ContentType = GrpcWeb;
            await context.Response.Body.WriteAsync(GrpcWebFraming.Frame(message), context.RequestAborted);
            await context.Response.Body.WriteAsync(GrpcWebFraming.TrailerFrame(GrpcWebFraming.Ok), context.RequestAborted);
        }
    }

    // ---- raw protobuf builders (the tests state the wire bytes themselves, not through a generated type) ----

    private static byte[] Concat(params byte[][] parts) => [.. parts.SelectMany(part => part)];

    private static byte[] Tag(int field, int wire) => Varint(((ulong)field << 3) | (uint)wire);

    private static byte[] Len(int field, byte[] body) => Concat(Tag(field, 2), Varint((ulong)body.Length), body);

    private static byte[] IdMessage(byte[] value) => Len(1, value);

    private static byte[] Correlation(string uuid) => Len(3, IdMessage(IdBytes(uuid)));

    private static byte[] Workspace(string uuid) => Len(4, IdMessage(IdBytes(uuid)));

    /// <summary>A request message whose field 1 is a RequestMeta made of the given already-encoded fields, then the given extra message fields.</summary>
    private static byte[] Envelope(byte[] meta, params byte[][] extra) => Concat(Len(1, meta), Concat(extra));

    private static byte[] RefuseRequest(string workspace, string? correlation) =>
        Envelope(Concat(Workspace(workspace), correlation is null ? [] : Correlation(correlation)), Tag(PipelineProbe.RefuseField, 0), [1]);

    private static string Hex(string uuid) => uuid.Replace("-", "", StringComparison.Ordinal);

    private static byte[] ReadField(byte[] message, int wanted)
    {
        var position = 0;
        while (position < message.Length)
        {
            Assert.True(ProtoWire.TryReadTag(message, ref position, out var field, out var wire));
            if (wire == 2)
            {
                Assert.True(ProtoWire.TryReadLengthDelimited(message, ref position, out var bytes));
                if (field == wanted) return bytes.ToArray();
            }
            else
            {
                Assert.True(ProtoWire.TrySkip(message, ref position, wire));
            }
        }

        throw new InvalidOperationException("field absent");
    }

    private static string CorrelationOf(ResponseMeta meta) => RequestEnvelopeReader.FormatId(meta.CorrelationId.Value.Span);

    private static string CorrelationOf(ArcError error) => RequestEnvelopeReader.FormatId(error.CorrelationId.Value.Span);

    private static ResponseMeta MetaOf(byte[] message) => ResponseMeta.Parser.ParseFrom(ReadField(message, PipelineProbe.MetaField));

    private static HttpRequestMessage WithTraceparent(HttpRequestMessage request, params string[] values)
    {
        foreach (var value in values) request.Headers.TryAddWithoutValidation("traceparent", value);
        return request;
    }

    private static string TraceparentFor(string correlation, string span = "00f067aa0ba902b7") => $"00-{Hex(correlation)}-{span}-01";

    private static (string Correlation, string? Parent, string Span, string Traceparent, string? Causation) Echoed(Reply reply)
    {
        Assert.Equal(0, Status(reply));
        var message = reply.Message!;
        string? Optional(int field) => ReadString(message, field) is { Length: > 0 } text ? text : null;
        return (ReadString(message, 1), Optional(2), ReadString(message, 3), ReadString(message, 4), Optional(5));
    }

    // ---- accepted and echoed ----

    [Fact]
    public async Task ASuppliedCorrelationIsEchoedInResponseMetaOfEveryProbeReplyAndStreamFrame()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        var correlation = T.Uuid();
        var envelope = Envelope(Concat(Workspace(workspace), Correlation(correlation)));

        var whoami = await Send(host, Authorized(PipelineProbe.WhoamiPath, envelope, issued));
        Assert.Equal(0, Status(whoami));
        Assert.Equal(correlation, CorrelationOf(MetaOf(whoami.Message!)));
        Assert.Equal(workspace, ReadString(whoami.Message!, 3));

        var observation = await Send(host, Authorized(PipelineProbe.ObservationPath, envelope, issued));
        Assert.Equal(correlation, CorrelationOf(MetaOf(observation.Message!)));

        var stream = await Send(host, Authorized(PipelineProbe.StreamPath,
            Concat(envelope, Tag(10, 0), Varint(3), Tag(11, 0), Varint(0)), issued));
        Assert.Equal(0, Status(stream));
        var frames = stream.Frames.Where(f => f.Flag == 0).ToList();
        Assert.Equal(3, frames.Count);
        foreach (var frame in frames) Assert.Equal(correlation, CorrelationOf(MetaOf(frame.Payload)));
    }

    [Fact]
    public async Task AnAbsentCorrelationIsCreatedAtTheEdgeAndReturnedAsACanonicalUuidThatDiffersPerCall()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        var seen = new HashSet<string>();
        for (var i = 0; i < 5; i++)
        {
            var reply = await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(workspace), issued));
            var created = CorrelationOf(MetaOf(reply.Message!));
            Assert.True(CorrelationContext.IsValidId(created), created);
            Assert.True(seen.Add(created));
        }
    }

    [Fact]
    public async Task ADomainRefusalCarriesTheCallsCorrelationInItsArcErrorAndItsResponseMeta()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        var supplied = T.Uuid();
        var reply = await Send(host, Authorized(PipelineProbe.WhoamiPath, RefuseRequest(workspace, supplied), issued));
        // gRPC OK with an outcome error is an acknowledged domain refusal (wire registry 04), not a transport failure.
        Assert.Equal(0, Status(reply));
        var error = ArcError.Parser.ParseFrom(ReadField(reply.Message!, PipelineProbe.ErrorField));
        Assert.Equal(PipelineProbe.RefusalCode, error.Code);
        Assert.Equal(ErrorCategory.State, error.Category);
        Assert.Equal(PipelineProbe.RefusalCode, error.MessageKey);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
        Assert.Equal(RetryMode.Never, error.Retry.Mode);
        Assert.Equal(supplied, CorrelationOf(error));
        Assert.Equal(supplied, CorrelationOf(MetaOf(reply.Message!)));
        // No session data leaks into a refusal.
        Assert.Throws<InvalidOperationException>(() => ReadField(reply.Message!, 1));

        var created = await Send(host, Authorized(PipelineProbe.WhoamiPath, RefuseRequest(workspace, null), issued));
        var createdError = ArcError.Parser.ParseFrom(ReadField(created.Message!, PipelineProbe.ErrorField));
        Assert.True(CorrelationContext.IsValidId(CorrelationOf(createdError)));
        Assert.Equal(CorrelationOf(createdError), CorrelationOf(MetaOf(created.Message!)));
    }

    [Fact]
    public async Task TheWorkersTraceparentSuppliesTheCorrelationAndTheHostContinuesTheSameTrace()
    {
        var echo = new EchoModule();
        await using var host = await StartAsync(extra: echo);
        var correlation = T.Uuid();
        const string workerSpan = "00f067aa0ba902b7";
        var reply = await Send(host, WithTraceparent(Rpc(EchoOpen, []), TraceparentFor(correlation, workerSpan)));
        var bound = Echoed(reply);
        Assert.Equal(correlation, bound.Correlation);
        Assert.Equal(workerSpan, bound.Parent);
        Assert.NotEqual(workerSpan, bound.Span);
        Assert.Matches("^[0-9a-f]{16}$", bound.Span);
        // One trace: the host's traceparent has the Worker's trace id and the host's own span.
        Assert.Equal($"00-{Hex(correlation)}-{bound.Span}-01", bound.Traceparent);
        Assert.Null(bound.Causation);
        // A reply never reflects trace context in a header: no new header exists.
        Assert.False(reply.Headers.Contains("traceparent"));
        Assert.False(reply.Headers.Contains("tracestate"));
    }

    [Fact]
    public async Task ACallWithoutATraceparentCreatesItsOwnTraceAndNeverReusesOne()
    {
        var echo = new EchoModule();
        await using var host = await StartAsync(extra: echo);
        var first = Echoed(await Send(host, Rpc(EchoOpen, [])));
        var second = Echoed(await Send(host, Rpc(EchoOpen, [])));
        Assert.True(CorrelationContext.IsValidId(first.Correlation));
        Assert.NotEqual(first.Correlation, second.Correlation);
        Assert.Null(first.Parent);
        Assert.Equal($"00-{Hex(first.Correlation)}-{first.Span}-01", first.Traceparent);
    }

    [Fact]
    public async Task AValidatedEnvelopeCorrelationWinsOverATraceparentThatNamesAnotherTrace()
    {
        var echo = new EchoModule();
        await using var host = await StartAsync(extra: echo);
        var (issued, _) = await Issue(host);
        var stated = T.Uuid();
        var other = T.Uuid();
        var mismatched = Echoed(await Send(host, WithTraceparent(Authorized(EchoAccount, Envelope(Correlation(stated)), issued), TraceparentFor(other))));
        Assert.Equal(stated, mismatched.Correlation);
        // The other trace's span is not a parent of this hop: the join is by identifier.
        Assert.Null(mismatched.Parent);
        var agreed = Echoed(await Send(host, WithTraceparent(Authorized(EchoAccount, Envelope(Correlation(stated)), issued), TraceparentFor(stated, "aaaaaaaaaaaaaaaa"))));
        Assert.Equal(stated, agreed.Correlation);
        Assert.Equal("aaaaaaaaaaaaaaaa", agreed.Parent);
        // An account-scoped method without a correlation uses the traceparent's.
        var fromTrace = Echoed(await Send(host, WithTraceparent(Authorized(EchoAccount, Envelope([]), issued), TraceparentFor(other))));
        Assert.Equal(other, fromTrace.Correlation);
    }

    [Fact]
    public async Task AnythingThatIsNotAStrictSingleTraceparentIsIgnoredAndNeverReflected()
    {
        var echo = new EchoModule();
        await using var host = await StartAsync(extra: echo);
        var good = T.Uuid();
        var hostile = new[]
        {
            $"00-{Hex(good).ToUpperInvariant()}-00f067aa0ba902b7-01",
            $"01-{Hex(good)}-00f067aa0ba902b7-01",
            $"ff-{Hex(good)}-00f067aa0ba902b7-01",
            $"00-{Hex(Nil)}-00f067aa0ba902b7-01",
            $"00-{Hex(good)}-0000000000000000-01",
            $"00-{Hex(good)[..31]}-00f067aa0ba902b7-01",
            $"00-{Hex(good)}0-00f067aa0ba902b7-01",
            $"00-{Hex(good)}-00f067aa0ba902b7-0",
            $"00-{Hex(good)}-00f067aa0ba902b7-01-extra",
            $" 00-{Hex(good)}-00f067aa0ba902b7-01",
            $"00-{Hex(good)}-00f067aa0ba902b7-zz",
            "00-<script>alert(1)</script>-00f067aa0ba902b7-01",
            new string('0', 4000),
            "",
        };
        foreach (var value in hostile)
        {
            var bound = Echoed(await Send(host, WithTraceparent(Rpc(EchoOpen, []), value)));
            Assert.NotEqual(good, bound.Correlation);
            Assert.True(CorrelationContext.IsValidId(bound.Correlation), bound.Correlation);
            Assert.Null(bound.Parent);
            Assert.DoesNotContain("script", bound.Traceparent, StringComparison.Ordinal);
        }

        // Two traceparent headers are ambiguous: neither is believed.
        var two = Echoed(await Send(host, WithTraceparent(Rpc(EchoOpen, []), TraceparentFor(good), TraceparentFor(T.Uuid()))));
        Assert.NotEqual(good, two.Correlation);
        Assert.Null(two.Parent);
    }

    // ---- refused: malformed, repeated, wrong size ----

    public static TheoryData<string> MalformedCorrelations =>
    [
        "repeated",
        "fifteen-bytes",
        "seventeen-bytes",
        "all-zero",
        "empty-id",
        "no-value-field",
        "varint-wire-type",
        "repeated-value",
        "uuid-text-bytes",
        "truncated",
    ];

    private static byte[] MalformedCorrelation(string kind) => kind switch
    {
        "repeated" => Concat(Correlation(T.Uuid()), Correlation(T.Uuid())),
        "fifteen-bytes" => Len(3, IdMessage(new byte[15].Select((_, i) => (byte)(i + 1)).ToArray())),
        "seventeen-bytes" => Len(3, IdMessage(new byte[17].Select((_, i) => (byte)(i + 1)).ToArray())),
        "all-zero" => Len(3, IdMessage(new byte[16])),
        "empty-id" => Len(3, []),
        "no-value-field" => Len(3, Concat(Tag(2, 0), [1])),
        "varint-wire-type" => Concat(Tag(3, 0), [1]),
        "repeated-value" => Len(3, Concat(IdMessage(IdBytes(T.Uuid())), IdMessage(IdBytes(T.Uuid())))),
        "uuid-text-bytes" => Len(3, IdMessage(Encoding.ASCII.GetBytes(T.Uuid()))),
        "truncated" => Concat(Tag(3, 2), Varint(16), IdBytes(T.Uuid())[..6]),
        _ => throw new ArgumentOutOfRangeException(nameof(kind)),
    };

    [Theory]
    [MemberData(nameof(MalformedCorrelations))]
    public async Task AMalformedCorrelationIsRefusedAsInvalidRequestBeforeAnyHandlerRuns(string kind)
    {
        var echo = new EchoModule();
        await using var host = await StartAsync(extra: echo);
        var (issued, workspace) = await Issue(host);
        var meta = Concat(Workspace(workspace), MalformedCorrelation(kind));

        foreach (var path in new[] { PipelineProbe.WhoamiPath, PipelineProbe.ObservationPath, PipelineProbe.StreamPath, EchoWorkspace })
        {
            var reply = await Send(host, Authorized(path, Envelope(meta), issued));
            var trailer = reply.Trailer();
            Assert.Equal(GrpcWebFraming.InvalidArgument, trailer.Status);
            Assert.Equal("validation.invalid_request", trailer.Message);
            Assert.DoesNotContain(reply.Frames, f => f.Flag == 0);
        }

        // An account-scoped method that carries RequestMeta is refused the same way, with no workspace in the envelope at all.
        var account = await Send(host, Authorized(EchoAccount, Envelope(MalformedCorrelation(kind)), issued));
        Assert.Equal(GrpcWebFraming.InvalidArgument, account.Trailer().Status);
        Assert.Equal(0, echo.Handled);
        Assert.Equal(0, host.Probe.Started);
    }

    [Fact]
    public async Task AMalformedCorrelationDoesNotChangeWhoIsAskedForCredentialsAndNeverReachesAStoreBeyondTheSession()
    {
        await using var host = await StartAsync();
        var (_, workspace) = await Issue(host);
        var before = host.Storage.Calls.Count;
        var reply = await Send(host, Rpc(PipelineProbe.WhoamiPath, Envelope(Concat(Workspace(workspace), MalformedCorrelation("all-zero")))));
        // Without a credential the answer is the same as for a well-formed request: a correlation id never decides admission.
        Assert.Equal(GrpcWebFraming.Unauthenticated, reply.Trailer().Status);
        Assert.Equal(before, host.Storage.Calls.Count);
    }

    // ---- never an authorization input ----

    [Fact]
    public async Task ASuppliedCorrelationNeverChangesAnAdmissionOrAuthorizationOutcomeOrWhatTheCallerSees()
    {
        await using var host = await StartAsync();
        var (issued, workspace) = await Issue(host);
        var foreign = T.Uuid();
        var (revoked, revokedWorkspace) = await Issue(host);
        await host.Sessions.RevokeAsync(revoked.SessionId, T.Ct);
        string?[] correlations = [null, T.Uuid(), T.Uuid(), issued.SessionId, workspace, foreign];
        var outcomes = new List<(string Case, int Status, string? Key)[]>();
        foreach (var correlation in correlations)
        {
            byte[] CorrelationFields() => correlation is null ? [] : Correlation(correlation);
            var row = new List<(string, int, string?)>();
            async Task Observe(string label, HttpRequestMessage request)
            {
                var reply = await Send(host, request);
                var trailer = reply.Trailer();
                row.Add((label, trailer.Status, trailer.Message));
            }

            await Observe("own", Authorized(PipelineProbe.WhoamiPath, Envelope(Concat(Workspace(workspace), CorrelationFields())), issued));
            await Observe("foreign", Authorized(PipelineProbe.WhoamiPath, Envelope(Concat(Workspace(foreign), CorrelationFields())), issued));
            await Observe("no-workspace", Authorized(PipelineProbe.WhoamiPath, Envelope(CorrelationFields()), issued));
            await Observe("stale-generation", Authorized(PipelineProbe.WhoamiPath,
                Envelope(Concat(Workspace(workspace), Tag(7, 0), Varint(7), CorrelationFields())), issued));
            await Observe("bad-csrf", Authorized(PipelineProbe.WhoamiPath, Envelope(Concat(Workspace(workspace), CorrelationFields())), issued, csrf: new string('x', 43)));
            await Observe("bad-origin", Authorized(PipelineProbe.WhoamiPath, Envelope(Concat(Workspace(workspace), CorrelationFields())), issued, origin: "https://evil.example"));
            await Observe("no-credential", Rpc(PipelineProbe.WhoamiPath, Envelope(Concat(Workspace(workspace), CorrelationFields()))));
            await Observe("revoked", Authorized(PipelineProbe.WhoamiPath, Envelope(Concat(Workspace(revokedWorkspace), CorrelationFields())), revoked));
            outcomes.Add([.. row]);
        }

        // Every case is decided identically whatever correlation the client stated, including none, a value equal to the session
        // id or to the workspace id, and one equal to a workspace the caller does not own.
        foreach (var other in outcomes.Skip(1)) Assert.Equal(outcomes[0], other);
        Assert.Equal(0, outcomes[0].Single(o => o.Case == "own").Status);
        Assert.Equal(GrpcWebFraming.PermissionDenied, outcomes[0].Single(o => o.Case == "foreign").Status);
        Assert.Equal(GrpcWebFraming.InvalidArgument, outcomes[0].Single(o => o.Case == "no-workspace").Status);
        Assert.Equal(GrpcWebFraming.FailedPrecondition, outcomes[0].Single(o => o.Case == "stale-generation").Status);
        Assert.Equal(GrpcWebFraming.Unauthenticated, outcomes[0].Single(o => o.Case == "no-credential").Status);

        // The caller sees the same session, user and owner whatever it stated; only the echoed identity differs.
        var plain = await Send(host, Authorized(PipelineProbe.WhoamiPath, Meta(workspace), issued));
        var stated = await Send(host, Authorized(PipelineProbe.WhoamiPath, Envelope(Concat(Workspace(workspace), Correlation(T.Uuid()))), issued));
        for (var field = 1; field <= 3; field++) Assert.Equal(ReadString(plain.Message!, field), ReadString(stated.Message!, field));
        Assert.Equal(ReadVarint(plain.Message!, 4), ReadVarint(stated.Message!, 4));
    }

    // ---- what the pipeline does not interpret ----

    [Fact]
    public async Task OnlyAMethodThatDeclaresARequestMetaHasItsBodyReadForACorrelation()
    {
        var echo = new EchoModule();
        await using var host = await StartAsync(extra: echo);
        // The anonymous Hello request has no RequestMeta: field 1 is the name. Bytes that would be a malformed meta there are a name.
        var name = new ArcForges.Contracts.Hello.V1.SayHelloRequest { Name = "xy" }.ToByteArray();
        Assert.Equal(0, Status(await Send(host, Rpc("/arcforges.hello.v1.HelloService/SayHello", name, rawBody: GrpcWebFraming.Frame(name)))));
        var open = await Send(host, Rpc(EchoOpen, MalformedCorrelation("all-zero")));
        Assert.Equal(0, Status(open));
        var registry = RpcPolicyRegistry.Create(echo.RpcPolicies
            .Concat(new HelloModule(BuildIdentity.FromAssembly(typeof(HelloEndpoint).Assembly)).RpcPolicies)
            .Concat(PipelineProbe.Policies));
        Assert.True(registry.TryGet("/arcforges.hello.v1.HelloService/SayHello", out var hello));
        Assert.False(hello.ReadsRequestMeta);
        Assert.True(registry.TryGet(PipelineProbe.WhoamiPath, out var whoami));
        Assert.True(whoami.ReadsRequestMeta);
        Assert.True(registry.TryGet(EchoAccount, out var account));
        Assert.True(account.ReadsRequestMeta);
        Assert.Equal(RpcScope.None, account.Scope);
    }

    [Fact]
    public void TheEnvelopeReaderReadsAStatedCorrelationStrictlyAndAgreesWithGeneratedMessages()
    {
        var workspace = T.Uuid();
        var correlation = T.Uuid();
        var generated = new ArcForges.Contracts.PublicApi.V1.WorkspaceServiceGetRequest
        {
            Meta = new RequestMeta
            {
                WorkspaceId = new Id { Value = ByteString.CopyFrom(IdBytes(workspace)) },
                CorrelationId = new Id { Value = ByteString.CopyFrom(IdBytes(correlation)) },
            },
        }.ToByteArray();
        Assert.True(RequestEnvelopeReader.TryRead(generated, out var envelope));
        Assert.Equal(correlation, envelope.CorrelationId);
        Assert.Equal(workspace, envelope.WorkspaceId);
        Assert.True(RequestEnvelopeReader.TryRead(Envelope(Workspace(workspace)), out var absent));
        Assert.Null(absent.CorrelationId);
        foreach (var kind in new[] { "repeated", "fifteen-bytes", "seventeen-bytes", "all-zero", "empty-id", "varint-wire-type", "repeated-value", "truncated" })
            Assert.False(RequestEnvelopeReader.TryRead(Envelope(Concat(Workspace(workspace), MalformedCorrelation(kind))), out _), kind);
    }
}

/// <summary>The call-scoped correlation value itself: strict traceparent reading, identity precedence and the reply messages.</summary>
public sealed class CorrelationContextTests
{
    private const string Trace = "4bf92f3577b34da6a3ce929d0e0e4736";
    private const string Id = "4bf92f35-77b3-4da6-a3ce-929d0e0e4736";

    [Fact]
    public void AStrictTraceparentYieldsTheCorrelationAndTheParentSpan()
    {
        Assert.True(CorrelationContext.TryParseTraceparent($"00-{Trace}-00f067aa0ba902b7-01", out var correlation, out var parent));
        Assert.Equal(Id, correlation);
        Assert.Equal("00f067aa0ba902b7", parent);
        Assert.True(CorrelationContext.TryParseTraceparent($"00-{Trace}-00f067aa0ba902b7-00", out _, out _));
    }

    [Theory]
    [InlineData("")]
    [InlineData("00")]
    [InlineData("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7")]
    [InlineData("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01")]
    [InlineData("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")]
    [InlineData("00-00000000000000000000000000000000-00f067aa0ba902b7-01")]
    [InlineData("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01")]
    [InlineData("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01 ")]
    [InlineData("00_4bf92f3577b34da6a3ce929d0e0e4736_00f067aa0ba902b7_01")]
    [InlineData("00-4bf92f3577b34da6a3ce929d0e0e473g-00f067aa0ba902b7-01")]
    public void AnythingElseIsNotATraceparent(string value) =>
        Assert.False(CorrelationContext.TryParseTraceparent(value, out _, out _), value);

    [Fact]
    public void ARepeatedOrMissingTraceparentHeaderIsNotATraceparent()
    {
        var one = $"00-{Trace}-00f067aa0ba902b7-01";
        Assert.False(CorrelationContext.TryParseTraceparent(Microsoft.Extensions.Primitives.StringValues.Empty, out _, out _));
        Assert.False(CorrelationContext.TryParseTraceparent(new Microsoft.Extensions.Primitives.StringValues([one, one]), out _, out _));
        Assert.True(CorrelationContext.TryParseTraceparent(new Microsoft.Extensions.Primitives.StringValues(one), out _, out _));
    }

    [Fact]
    public void TheCorrelationIsTheEnvelopeValueThenTheTraceThenANewOneAndTheTraceparentAlwaysSharesTheTrace()
    {
        var other = T.Uuid();
        var traceparent = $"00-{Trace}-00f067aa0ba902b7-01";
        var fromTrace = CorrelationContext.ForRequest(traceparent, null);
        Assert.Equal(Id, fromTrace.CorrelationId);
        Assert.Equal("00f067aa0ba902b7", fromTrace.ParentSpanId);
        Assert.Equal($"00-{Trace}-{fromTrace.SpanId}-01", fromTrace.Traceparent);
        var stated = CorrelationContext.ForRequest(traceparent, other);
        Assert.Equal(other, stated.CorrelationId);
        Assert.Null(stated.ParentSpanId);
        Assert.Equal($"00-{other.Replace("-", "", StringComparison.Ordinal)}-{stated.SpanId}-01", stated.Traceparent);
        var created = CorrelationContext.ForRequest(Microsoft.Extensions.Primitives.StringValues.Empty, null);
        Assert.True(CorrelationContext.IsValidId(created.CorrelationId));
        Assert.Null(created.ParentSpanId);
        Assert.Null(created.CausationId);
    }

    [Fact]
    public void AContinuedHopKeepsTheCorrelationAndRecordsItsCause()
    {
        var cause = T.Uuid();
        var hop = CorrelationContext.Continue(Id, cause);
        Assert.Equal(Id, hop.CorrelationId);
        Assert.Equal(cause, hop.CausationId);
        Assert.Null(hop.ParentSpanId);
        Assert.NotEqual(CorrelationContext.Continue(Id, cause).SpanId, hop.SpanId);
    }

    [Fact]
    public void SpanIdsAreNonzeroLowercaseHexAndNeverRepeat()
    {
        var seen = new HashSet<string>();
        for (var i = 0; i < 500; i++)
        {
            var span = CorrelationContext.NewSpanId();
            Assert.Matches("^[0-9a-f]{16}$", span);
            Assert.NotEqual("0000000000000000", span);
            Assert.True(seen.Add(span));
        }
    }

    [Theory]
    [InlineData("4bf92f35-77b3-4da6-a3ce-929d0e0e4736", true)]
    [InlineData("4BF92F35-77B3-4DA6-A3CE-929D0E0E4736", false)]
    [InlineData("00000000-0000-0000-0000-000000000000", false)]
    [InlineData("{4bf92f35-77b3-4da6-a3ce-929d0e0e4736}", false)]
    [InlineData("4bf92f3577b34da6a3ce929d0e0e4736", false)]
    [InlineData("4bf92f35-77b3-4da6-a3ce-929d0e0e4736 ", false)]
    [InlineData("4bf92f35-77b3-4da6-a3ce-929d0e0e4736\r\nx", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void OnlyACanonicalLowercaseNonNilUuidIsAnIdentity(string? text, bool valid) =>
        Assert.Equal(valid, CorrelationContext.IsValidId(text));

    [Fact]
    public void TheReplyMessagesCarryTheIdentityAsSixteenBytesInCanonicalOrder()
    {
        var correlation = CorrelationContext.ForRequest(default, Id);
        var meta = CorrelationReplies.Meta(correlation);
        Assert.Equal(Convert.FromHexString(Trace), meta.CorrelationId.Value.ToByteArray());
        var error = CorrelationReplies.Error(correlation, "validation.invalid_request", ErrorCategory.Validation, "validation.invalid_request");
        Assert.Equal(meta.CorrelationId, error.CorrelationId);
        Assert.Equal("validation.invalid_request", error.Code);
        Assert.Equal(EffectCertainty.DidNotHappen, error.Effect);
        // Wire registry 04: ResponseMeta.correlationId is tag 4 and ArcError.correlationId is tag 6.
        Assert.Equal(4, ResponseMeta.CorrelationIdFieldNumber);
        Assert.Equal(6, ArcError.CorrelationIdFieldNumber);
        Assert.Equal(3, RequestMeta.CorrelationIdFieldNumber);
    }
}
