// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Agent.Dispatch.Application;
using ArcForges.Cloud.Modules.Agent.Dispatch.Domain;
using ArcForges.Cloud.Tests.Entitlement;
using Xunit;

namespace ArcForges.Cloud.Tests.HarnessFoundation;

/// <summary>The transport of the tests: it records every request and answers from a script, so no network is used.</summary>
internal sealed class ScriptedHandler : HttpMessageHandler
{
    public List<HttpRequestMessage> Requests { get; } = [];

    public List<string> Bodies { get; } = [];

    /// <summary>The answer of each request; the default is a 200 with a small JSON object.</summary>
    public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> Respond { get; set; } = (_, _) => Task.FromResult(Json(HttpStatusCode.OK, "{\"success\":true}"));

    public static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        Bodies.Add(request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));
        return await Respond(request, cancellationToken).ConfigureAwait(false);
    }
}

public sealed class AgentDispatchTests
{
    private const string Model = "@cf/openai/gpt-oss-20b";
    private const string Tariff = "tariff.2026-10";
    private const string Frozen = "{\"messages\":[{\"role\":\"user\",\"content\":\"{\\\"name\\\":\\\"Ada\\\"}\"}],\"max_tokens\":1024,\"stream\":false}";

    private static ModelDispatchOptions Options(int capacity = 10, int refill = 10, int maxBody = 65_536, int maxResponse = 65_536) =>
        ModelDispatchOptions.Create(
            new Uri("http://ai.internal/"),
            [new AdmittedModel(Model, Tariff), new AdmittedModel("@cf/other/model", Tariff)],
            maxBody,
            maxResponse,
            capacity,
            refill);

    private static ModelCallRequest Call(string model = Model, string tariff = Tariff, string json = Frozen, int maxTokens = 1024, int tools = 1, double seconds = 90) =>
        new(model, tariff, json, maxTokens, tools, TimeSpan.FromSeconds(seconds));

    private static (ModelDispatchClient Client, ScriptedHandler Handler, SettableTimeProvider Clock) Client(ModelDispatchOptions? options = null)
    {
        var handler = new ScriptedHandler();
        var clock = new SettableTimeProvider(DateTimeOffset.UnixEpoch.AddSeconds(1_000));
        return (new ModelDispatchClient(options ?? Options(), new HttpClient(handler), clock), handler, clock);
    }

    [Theory]
    [InlineData("https://ai.internal/")]
    [InlineData("http://ai.internal:8080/")]
    [InlineData("http://storage.internal/")]
    [InlineData("http://ai.internal/v1/")]
    [InlineData("http://user@ai.internal/")]
    public void TheBaseAddressIsExactlyTheAiInternalRootOverPlainHttp(string address)
    {
        Assert.Throws<ArgumentException>(() => ModelDispatchOptions.Create(new Uri(address), [new AdmittedModel(Model, Tariff)], 1024, 1024, 1, 1));
    }

    [Fact]
    public void AnAdmittedSetAndItsCapsAreBoundedWhenTheOptionsAreBuilt()
    {
        Assert.Throws<ArgumentException>(() => ModelDispatchOptions.Create(new Uri("http://ai.internal/"), [], 1024, 1024, 1, 1));
        Assert.Throws<ArgumentException>(() => ModelDispatchOptions.Create(new Uri("http://ai.internal/"), [new AdmittedModel(Model, Tariff), new AdmittedModel(Model, Tariff)], 1024, 1024, 1, 1));
        Assert.Throws<ArgumentException>(() => ModelDispatchOptions.Create(new Uri("http://ai.internal/"), [new AdmittedModel("bad model", Tariff)], 1024, 1024, 1, 1));
        Assert.Throws<ArgumentException>(() => ModelDispatchOptions.Create(new Uri("http://ai.internal/"), Enumerable.Range(0, 17).Select(i => new AdmittedModel("m" + i, Tariff)), 1024, 1024, 1, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => Options(maxBody: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Options(maxBody: ModelDispatchOptions.HardByteCap + 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => Options(maxResponse: ModelDispatchOptions.HardByteCap + 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => Options(capacity: 0));
        Assert.Throws<ArgumentOutOfRangeException>(() => Options(refill: 1001));
    }

    [Fact]
    public void ASnapshotExistsOnlyForAnAdmittedModel()
    {
        var (client, _, _) = Client();
        Assert.Equal(new ModelSnapshot(Model, Tariff), client.SnapshotOf(Model));
        Assert.Null(client.SnapshotOf("@cf/not/admitted"));
    }

    [Fact]
    public async Task ASuccessfulCallSendsTheClosedEnvelopeWithTheFrozenRequestAndReturnsTheAnswer()
    {
        var (client, handler, _) = Client();
        handler.Respond = (_, _) => Task.FromResult(ScriptedHandler.Json(HttpStatusCode.OK, "{\"result\":{\"response\":\"ok\"}}"));

        var result = await client.DispatchAsync(Call(), T.Ct);

        Assert.Equal(new ModelCallResult(ModelDispatchStatus.Succeeded, "{\"result\":{\"response\":\"ok\"}}", "ok"), result);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal(new Uri("http://ai.internal/v1/run"), request.RequestUri);
        Assert.Null(request.Headers.Authorization);
        Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);

        using var envelope = JsonDocument.Parse(handler.Bodies[0]);
        var root = envelope.RootElement;
        Assert.Equal(new[] { "admittedModels", "maxBodyBytes", "maxResponseBytes", "model", "request", "v" }, root.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray());
        Assert.Equal(1, root.GetProperty("v").GetInt32());
        Assert.Equal(Model, root.GetProperty("model").GetString());
        Assert.Equal(new[] { Model, "@cf/other/model" }, root.GetProperty("admittedModels").EnumerateArray().Select(item => item.GetString()).ToArray());
        Assert.Equal(65_536, root.GetProperty("maxBodyBytes").GetInt32());
        Assert.Equal(65_536, root.GetProperty("maxResponseBytes").GetInt32());
        Assert.Equal(Frozen, root.GetProperty("request").GetRawText(), StringComparer.Ordinal);
    }

    [Fact]
    public async Task EveryPreDispatchAdmissionRefusesWithoutAnyCall()
    {
        var (client, handler, _) = Client();
        Assert.Equal("model_not_admitted", (await client.DispatchAsync(Call(model: "@cf/unknown"), T.Ct)).Reason);
        Assert.Equal("snapshot_mismatch", (await client.DispatchAsync(Call(tariff: "tariff.old"), T.Ct)).Reason);
        Assert.Equal("deadline_out_of_range", (await client.DispatchAsync(Call(seconds: 0), T.Ct)).Reason);
        Assert.Equal("deadline_out_of_range", (await client.DispatchAsync(Call(seconds: 121), T.Ct)).Reason);
        Assert.Equal("output_cap", (await client.DispatchAsync(Call(maxTokens: 0), T.Ct)).Reason);
        Assert.Equal("output_cap", (await client.DispatchAsync(Call(maxTokens: 4097), T.Ct)).Reason);
        Assert.Equal("tool_cap", (await client.DispatchAsync(Call(tools: 33), T.Ct)).Reason);
        Assert.Equal("request_invalid", (await client.DispatchAsync(Call(json: "[1]"), T.Ct)).Reason);
        Assert.Equal("request_invalid", (await client.DispatchAsync(Call(json: "not json"), T.Ct)).Reason);
        Assert.Empty(handler.Requests);
        var result = await client.DispatchAsync(Call(seconds: 120), T.Ct);
        Assert.Equal(ModelDispatchStatus.Succeeded, result.Status);
    }

    [Fact]
    public async Task ARequestOverTheCallerCapIsRefusedBeforeAnyCall()
    {
        var (client, handler, _) = Client(Options(maxBody: 200));
        var big = "{\"v\":\"" + new string('x', 400) + "\"}";
        Assert.Equal("body_over_cap", (await client.DispatchAsync(Call(json: big), T.Ct)).Reason);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task ARefusedAdmissionSpendsNoToken()
    {
        var (client, handler, _) = Client(Options(capacity: 1, refill: 1));
        Assert.Equal("snapshot_mismatch", (await client.DispatchAsync(Call(tariff: "tariff.old"), T.Ct)).Reason);
        Assert.Equal(ModelDispatchStatus.Succeeded, (await client.DispatchAsync(Call(), T.Ct)).Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ARequestThatCannotBeSerialisedSpendsNoToken()
    {
        var (client, handler, _) = Client(Options(capacity: 1, refill: 1));
        Assert.Equal("request_invalid", (await client.DispatchAsync(Call(json: "[1]"), T.Ct)).Reason);
        Assert.Equal(ModelDispatchStatus.Succeeded, (await client.DispatchAsync(Call(), T.Ct)).Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ThePerModelTokenBucketRefusesAnEmptyBucketAndRefillsWithTime()
    {
        var (client, handler, clock) = Client(Options(capacity: 2, refill: 1));
        Assert.Equal(ModelDispatchStatus.Succeeded, (await client.DispatchAsync(Call(), T.Ct)).Status);
        Assert.Equal(ModelDispatchStatus.Succeeded, (await client.DispatchAsync(Call(), T.Ct)).Status);
        Assert.Equal("rate_limited", (await client.DispatchAsync(Call(), T.Ct)).Reason);
        Assert.Equal(2, handler.Requests.Count);

        // A second model has its own bucket, so the empty one of the first model does not block it.
        Assert.Equal(ModelDispatchStatus.Succeeded, (await client.DispatchAsync(Call(model: "@cf/other/model"), T.Ct)).Status);

        clock.SetSeconds(clock.GetUtcNow().ToUnixTimeSeconds() + 1);
        Assert.Equal(ModelDispatchStatus.Succeeded, (await client.DispatchAsync(Call(), T.Ct)).Status);
    }

    [Theory]
    [InlineData(400)]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(405)]
    [InlineData(413)]
    [InlineData(415)]
    public async Task AnAdapterRefusalIsAPreDispatchRefusal(int code)
    {
        var (client, handler, _) = Client();
        handler.Respond = (_, _) => Task.FromResult(ScriptedHandler.Json((HttpStatusCode)code, "{\"error\":\"ai.closed\"}"));
        var result = await client.DispatchAsync(Call(), T.Ct);
        Assert.Equal(new ModelCallResult(ModelDispatchStatus.RefusedBeforeDispatch, null, "adapter_refused_" + code), result);
    }

    [Theory]
    [InlineData(500)]
    [InlineData(502)]
    [InlineData(503)]
    [InlineData(504)]
    public async Task AnAdapterFailureAfterTheBindingIsUnknownAndNeverRetried(int code)
    {
        var (client, handler, _) = Client();
        handler.Respond = (_, _) => Task.FromResult(ScriptedHandler.Json((HttpStatusCode)code, "{\"error\":\"ai.upstream_failed\"}"));
        var result = await client.DispatchAsync(Call(), T.Ct);
        Assert.Equal(new ModelCallResult(ModelDispatchStatus.Unknown, null, "adapter_" + code), result);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ATransportFailureIsUnknown()
    {
        var (client, handler, _) = Client();
        handler.Respond = (_, _) => throw new HttpRequestException("connection reset");
        Assert.Equal(new ModelCallResult(ModelDispatchStatus.Unknown, null, "transport"), await client.DispatchAsync(Call(), T.Ct));
    }

    [Fact]
    public async Task ACallThatOutlastsItsDeadlineIsUnknownWithTheDeadlineReason()
    {
        var (client, handler, _) = Client();
        handler.Respond = async (_, token) =>
        {
            await Task.Delay(Timeout.Infinite, token).ConfigureAwait(false);
            return ScriptedHandler.Json(HttpStatusCode.OK, "{}");
        };
        var result = await client.DispatchAsync(Call(seconds: 0.05), T.Ct);
        Assert.Equal(new ModelCallResult(ModelDispatchStatus.Unknown, null, "deadline"), result);
    }

    [Fact]
    public async Task ACallerCancellationIsUnknownWithTheCancelledReason()
    {
        var (client, handler, _) = Client();
        using var cancel = new CancellationTokenSource();
        handler.Respond = async (_, token) =>
        {
            cancel.Cancel();
            await Task.Delay(Timeout.Infinite, token).ConfigureAwait(false);
            return ScriptedHandler.Json(HttpStatusCode.OK, "{}");
        };
        Assert.Equal(new ModelCallResult(ModelDispatchStatus.Unknown, null, "cancelled"), await client.DispatchAsync(Call(), cancel.Token));
    }

    [Fact]
    public async Task AnAnswerOverTheCallerCapOrNotAJsonObjectIsUnknown()
    {
        var (client, handler, _) = Client(Options(maxResponse: 64));
        handler.Respond = (_, _) => Task.FromResult(ScriptedHandler.Json(HttpStatusCode.OK, "{\"text\":\"" + new string('y', 200) + "\"}"));
        Assert.Equal("response_over_cap", (await client.DispatchAsync(Call(), T.Ct)).Reason);

        handler.Respond = (_, _) => Task.FromResult(ScriptedHandler.Json(HttpStatusCode.OK, "not json"));
        Assert.Equal("response_invalid", (await client.DispatchAsync(Call(), T.Ct)).Reason);

        handler.Respond = (_, _) => Task.FromResult(ScriptedHandler.Json(HttpStatusCode.OK, "[1,2]"));
        Assert.Equal("response_invalid", (await client.DispatchAsync(Call(), T.Ct)).Reason);
    }

    [Fact]
    public async Task AStreamRequestIsRefusedBeforeAnyTokenIsSpent()
    {
        var (client, handler, _) = Client(Options(capacity: 1, refill: 1));
        Assert.Equal("stream_refused", (await client.DispatchAsync(Call(json: "{\"stream\":true}"), T.Ct)).Reason);
        Assert.Equal("stream_refused", (await client.DispatchAsync(Call(json: "{\"stream\":\"yes\"}"), T.Ct)).Reason);
        Assert.Equal("stream_refused", (await client.DispatchAsync(Call(json: "{\"stream\":false,\"stream\":true}"), T.Ct)).Reason);
        Assert.Empty(handler.Requests);

        // Nothing was sent or spent, so the single token still admits a call that does not stream.
        Assert.Equal(ModelDispatchStatus.Succeeded, (await client.DispatchAsync(Call(), T.Ct)).Status);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task AnAnswerThatIsNotJsonIsUnknownWhateverItsBody()
    {
        var (client, handler, _) = Client();
        handler.Respond = (_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("data: {\"response\":\"hi\"}\n\n", Encoding.UTF8, "text/event-stream"),
        });
        Assert.Equal(new ModelCallResult(ModelDispatchStatus.Unknown, null, "response_media_type"), await client.DispatchAsync(Call(), T.Ct));
        Assert.Single(handler.Requests);
    }

    [Fact]
    public void TheEnvelopeWriterAcceptsOnlyAJsonObjectAsTheFrozenRequest()
    {
        Assert.ThrowsAny<System.Text.Json.JsonException>(() => AiEnvelope.Build(Model, [Model], 1024, 1024, "[1]"));
        Assert.ThrowsAny<System.Text.Json.JsonException>(() => AiEnvelope.Build(Model, [Model], 1024, 1024, "{"));
        var bytes = AiEnvelope.Build(Model, [Model], 1024, 1024, "{\"stream\":false}");
        Assert.Contains("\"request\":{\"stream\":false}", Encoding.UTF8.GetString(bytes), StringComparison.Ordinal);
    }

    [Fact]
    public void TheRateBucketsAreIndependentPerModelAndNeverExceedCapacity()
    {
        var buckets = new ArcForges.Cloud.Modules.Agent.Dispatch.Domain.ModelRateBuckets(2, 1);
        Assert.True(buckets.TryTake("a", 0));
        Assert.True(buckets.TryTake("a", 0));
        Assert.False(buckets.TryTake("a", 0));
        Assert.True(buckets.TryTake("b", 0));
        // A long idle time refills to capacity only, never above it.
        Assert.True(buckets.TryTake("a", 1_000_000_000_000));
        Assert.True(buckets.TryTake("a", 1_000_000_000_000));
        Assert.False(buckets.TryTake("a", 1_000_000_000_000));
    }
}
