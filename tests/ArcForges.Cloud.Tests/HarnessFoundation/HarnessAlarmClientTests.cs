// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Task.Harness.Wake;
using Xunit;

namespace ArcForges.Cloud.Tests.HarnessFoundation;

/// <summary>A handler that records every request it receives and answers from a script.</summary>
internal sealed class ScriptedAlarmHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
{
    public List<(string Method, string Url, string? ContentType, string Body)> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Add((request.Method.Method, request.RequestUri!.ToString(), request.Content?.Headers.ContentType?.ToString(), body));
        return respond(request);
    }
}

/// <summary>A handler whose reply never arrives until the request is cancelled.</summary>
internal sealed class HangingAlarmHandler : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        await Task.Delay(Timeout.Infinite, cancellationToken);
        return new HttpResponseMessage(HttpStatusCode.OK);
    }
}

/// <summary>A reply body that never completes: it is read only until the read is cancelled.</summary>
internal sealed class StalledBodyContent : HttpContent
{
    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
        SerializeToStreamAsync(stream, context, CancellationToken.None);

    protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context, CancellationToken cancellationToken) =>
        Task.Delay(Timeout.Infinite, cancellationToken);

    protected override bool TryComputeLength(out long length)
    {
        length = 0;
        return false;
    }
}

/// <summary>
/// The outbound alarm client (HAR.40 alarm arming). It sends one closed JSON request per call to <c>harness.internal</c> and treats every reply
/// other than the exact scheduled reply as a refusal, so a run is parked only when the alarm was confirmed armed.
/// </summary>
public sealed class HarnessAlarmClientTests
{
    private static readonly Guid WorkspaceId = HarnessFixture.WorkspaceId;
    private static readonly Guid RunId = HarnessFixture.RunId;
    private static readonly HarnessAlarmSchedule Schedule = new(WorkspaceId, RunId, 1_800_000_005_000);

    private static (HarnessAlarmClient Client, ScriptedAlarmHandler Handler) ClientFor(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        var handler = new ScriptedAlarmHandler(respond);
        return (new HarnessAlarmClient(new HttpClient(handler), TimeSpan.FromSeconds(5)), handler);
    }

    private static HttpResponseMessage Reply(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    [Fact]
    public async Task AScheduleIsOneClosedPostToTheScheduleRouteOfTheHarnessHost()
    {
        var (client, handler) = ClientFor(_ => Reply(HttpStatusCode.OK, "{\"scheduled\":true}"));

        var reply = await client.ScheduleAsync(Schedule, T.Ct);

        Assert.Equal(HarnessAlarmReply.Armed, reply);
        var request = Assert.Single(handler.Requests);
        Assert.Equal("POST", request.Method);
        Assert.Equal("http://harness.internal/v1/schedule", request.Url);
        Assert.Equal("application/json; charset=utf-8", request.ContentType);

        using var document = JsonDocument.Parse(request.Body);
        var keys = document.RootElement.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(new[] { "runId", "wakeAtMs", "workspaceId" }, keys);
        Assert.Equal(RunId.ToString("D"), document.RootElement.GetProperty("runId").GetString());
        Assert.Equal(WorkspaceId.ToString("D"), document.RootElement.GetProperty("workspaceId").GetString());
        Assert.Equal(1_800_000_005_000, document.RootElement.GetProperty("wakeAtMs").GetInt64());
    }

    [Theory]
    [InlineData(HttpStatusCode.OK, "{\"scheduled\":false}")]
    [InlineData(HttpStatusCode.OK, "{\"scheduled\":true,\"extra\":1}")]
    [InlineData(HttpStatusCode.OK, "")]
    [InlineData(HttpStatusCode.Created, "{\"scheduled\":true}")]
    [InlineData(HttpStatusCode.UnprocessableEntity, "{\"error\":\"harness.schedule_refused\"}")]
    [InlineData(HttpStatusCode.ServiceUnavailable, "{\"error\":\"harness.binding_missing\"}")]
    [InlineData(HttpStatusCode.BadGateway, "{\"error\":\"harness.upstream_failed\"}")]
    public async Task AnyReplyOtherThanTheExactScheduledReplyIsARefusal(HttpStatusCode status, string body)
    {
        var (client, _) = ClientFor(_ => Reply(status, body));

        Assert.Equal(HarnessAlarmReply.Refused, await client.ScheduleAsync(Schedule, T.Ct));
    }

    [Fact]
    public async Task ATransportFailureIsAFailClosedRefusal()
    {
        var (client, _) = ClientFor(_ => throw new HttpRequestException("the container could not reach harness.internal"));

        Assert.Equal(HarnessAlarmReply.Refused, await client.ScheduleAsync(Schedule, T.Ct));
    }

    [Fact]
    public async Task AStalledReplyBodyIsBoundedByTheAlarmDeadlineAndFailsClosed()
    {
        // The headers arrive at once and the body never completes. The read shares the client's deadline, so the schedule is refused within it.
        // The bounded wait makes a body read that ignores the deadline fail the test instead of hanging the run.
        var handler = new ScriptedAlarmHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StalledBodyContent() });
        var client = new HarnessAlarmClient(new HttpClient(handler), TimeSpan.FromMilliseconds(100));

        var cancellation = TestContext.Current.CancellationToken;
        var pending = client.ScheduleAsync(Schedule, cancellation);
        var reply = await pending.WaitAsync(TimeSpan.FromSeconds(10), cancellation);

        Assert.Equal(HarnessAlarmReply.Refused, reply);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ACallerThatIsCancelledOrAHungReplyAreFailClosedRefusals()
    {
        // A reply that never comes is not armed: the caller's cancellation ends the call as a refusal, never as a fault.
        using var cancelled = new CancellationTokenSource(TimeSpan.FromMilliseconds(50));
        var callerCancelled = new HarnessAlarmClient(new HttpClient(new HangingAlarmHandler()), TimeSpan.FromSeconds(30));
        Assert.Equal(HarnessAlarmReply.Refused, await callerCancelled.ScheduleAsync(Schedule, cancelled.Token));

        // The client's own deadline ends a hung call the same way, even when the caller waits.
        var timedOut = new HarnessAlarmClient(new HttpClient(new HangingAlarmHandler()), TimeSpan.FromMilliseconds(50));
        Assert.Equal(HarnessAlarmReply.Refused, await timedOut.ScheduleAsync(Schedule, T.Ct));
    }

    [Fact]
    public async Task ACancelIsOneClosedRunKeyPostToTheCancelRouteAndItsFailureIsSwallowed()
    {
        var (client, handler) = ClientFor(_ => Reply(HttpStatusCode.OK, "{\"cancelled\":true}"));

        await client.CancelAsync(WorkspaceId, RunId, T.Ct);

        var request = Assert.Single(handler.Requests);
        Assert.Equal("http://harness.internal/v1/cancel", request.Url);
        using var document = JsonDocument.Parse(request.Body);
        var keys = document.RootElement.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray();
        Assert.Equal(new[] { "runId", "workspaceId" }, keys);

        var (failing, _) = ClientFor(_ => throw new HttpRequestException("down"));
        await failing.CancelAsync(WorkspaceId, RunId, T.Ct);
    }
}
