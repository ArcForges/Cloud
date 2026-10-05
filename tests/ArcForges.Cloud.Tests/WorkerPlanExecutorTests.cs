// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests;

public sealed class WorkerPlanExecutorTests
{
    private const string Scope = "proof/test";
    private static readonly DateTimeOffset Start = new(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);

    private static PlanCall Read(ulong generation = 0) =>
        PlanCall.New(PlanManifest.Foundation.AccountLoad, Scope, generation, [[D1Values.Text(Scope), D1Values.Text("a")]]);

    private static PlanCall Write() =>
        PlanCall.New(PlanManifest.Foundation.AccountSeed, Scope, 0, [[D1Values.Text(Scope), D1Values.Text("a"), D1Values.Int64(1)]]);

    private static HttpResponseMessage Json(byte[] body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new ByteArrayContent(body) };

    private static ExecutePlanRequest Parse(byte[] body) => ExecutePlanRequestJson.Parse(body);

    private static byte[] Failure(byte[] request, string failure, string? manifest = null, string? requestId = null) =>
        ExecutePlanResponseJson.Serialize(new ExecutePlanResponseExecutePlanFailure(new ExecutePlanFailure
        {
            RequestId = requestId ?? Parse(request).RequestId,
            ManifestHash = manifest ?? PlanManifest.Hash,
            Failure = failure,
        }));

    private static byte[] Success(byte[] request, D1Scalar[][]? rows = null, string changes = "0", string? manifest = null, string? requestId = null) =>
        ExecutePlanResponseJson.Serialize(new ExecutePlanResponseExecutePlanSuccess(new ExecutePlanSuccess
        {
            RequestId = requestId ?? Parse(request).RequestId,
            ManifestHash = manifest ?? PlanManifest.Hash,
            Rows = rows ?? [],
            Changes = changes,
        }));

    private static (WorkerPlanExecutor Executor, StubHandler Handler, SigningKey Key) Create(Func<HttpRequestMessage, byte[], Task<HttpResponseMessage>> respond)
    {
        var handler = new StubHandler(respond);
        var key = T.Key("c2w-1");
        return (new WorkerPlanExecutor(new HttpClient(handler), new Uri("http://storage.test"), key, new FakeTime(Start)), handler, key);
    }

    [Fact]
    public async Task SendsASignedStrictGeneratedRequestToTheExactPathAndDecodesRows()
    {
        var (executor, handler, key) = Create((_, body) => Task.FromResult(Json(Success(body, [[D1Values.Int64(long.MaxValue), D1Values.Int64(7)]]))));
        var result = await executor.ExecuteAsync(Read(), T.Ct);
        Assert.Single(result.Rows);
        Assert.True(D1Values.TryGetInt64(result.Rows[0][0], out var balance));
        Assert.Equal(long.MaxValue, balance);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Post, request.Method);
        Assert.Equal("http://storage.test/internal/storage/v1/execute-plan", request.RequestUri!.ToString());
        Assert.Equal("application/json", request.Content!.Headers.ContentType!.MediaType);
        var body = handler.Bodies[0];
        var parsed = Parse(body);
        Assert.Equal("foundation.account-load", parsed.PlanId);
        Assert.Equal(1, parsed.PlanVersion);
        Assert.Equal(PlanManifest.Hash, parsed.ManifestHash);
        Assert.Equal("0", parsed.RecoveryGeneration);
        Assert.Equal(Scope, parsed.OwnerScope);
        var deadline = DateTimeOffset.Parse(parsed.DeadlineUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
        Assert.Equal(Start.AddSeconds(8), deadline);
        string? Header(string name) => request.Headers.TryGetValues(name, out var values) ? values.Single() : null;
        Assert.Equal(parsed.RequestId, Header("X-AF-Request-Id"));
        Assert.True(PrivateRequestVerifier.Verify("POST", "/internal/storage/v1/execute-plan", T.Sha256Hex(body), Header, [key], Start, out var verified));
        Assert.Equal(parsed.RequestId, verified.RequestId);
    }

    [Theory]
    [InlineData("invalidPlan", "InvalidPlan")]
    [InlineData("staleGeneration", "StaleGeneration")]
    [InlineData("precondition", "Precondition")]
    [InlineData("constraint", "Constraint")]
    [InlineData("overloaded", "Overloaded")]
    [InlineData("unavailable", "Unavailable")]
    [InlineData("unknownOutcome", "UnknownOutcome")]
    public async Task EveryTypedFailureMapsToItsKindWithoutRetry(string wire, string expected)
    {
        var (executor, handler, _) = Create((_, body) => Task.FromResult(Json(Failure(body, wire))));
        var failure = await Assert.ThrowsAsync<PlanFailureException>(() => executor.ExecuteAsync(Write(), T.Ct));
        Assert.Equal(Enum.Parse<PlanFailureKind>(expected), failure.Kind);
        Assert.Equal(1, handler.Count);
        Assert.DoesNotContain("SELECT", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AManifestOrRequestIdMismatchIsRefused()
    {
        var other = new string('0', 64);
        foreach (var respond in new Func<byte[], byte[]>[] { b => Success(b, manifest: other), b => Failure(b, "precondition", manifest: other) })
        {
            var (executor, _, _) = Create((_, body) => Task.FromResult(Json(respond(body))));
            var failure = await Assert.ThrowsAsync<PlanFailureException>(() => executor.ExecuteAsync(Read(), T.Ct));
            Assert.Equal(PlanFailureKind.ManifestMismatch, failure.Kind);
        }

        var (read, _, _) = Create((_, body) => Task.FromResult(Json(Success(body, requestId: "99999999-9999-4999-8999-999999999999"))));
        Assert.Equal(PlanFailureKind.Unavailable, (await Assert.ThrowsAsync<PlanFailureException>(() => read.ExecuteAsync(Read(), T.Ct))).Kind);
        var (write, _, _) = Create((_, body) => Task.FromResult(Json(Failure(body, "precondition", requestId: "99999999-9999-4999-8999-999999999999"))));
        Assert.Equal(PlanFailureKind.UnknownOutcome, (await Assert.ThrowsAsync<PlanFailureException>(() => write.ExecuteAsync(Write(), T.Ct))).Kind);
    }

    [Fact]
    public async Task NoResponseIsAnUnknownOutcomeForWritesAndUnavailableForReads()
    {
        foreach (var respond in new Func<byte[], Task<HttpResponseMessage>>[]
        {
            _ => throw new HttpRequestException("connection reset"),
            _ => throw new IOException("closed"),
            _ => Task.FromResult(Json([], HttpStatusCode.InternalServerError)),
            _ => Task.FromResult(Json([], HttpStatusCode.BadGateway)),
            _ => Task.FromResult(Json("not json"u8.ToArray())),
            _ => Task.FromResult(Json("{}"u8.ToArray())),
        })
        {
            var (writer, writes, _) = Create((_, body) => respond(body));
            Assert.Equal(PlanFailureKind.UnknownOutcome, (await Assert.ThrowsAsync<PlanFailureException>(() => writer.ExecuteAsync(Write(), T.Ct))).Kind);
            Assert.Equal(1, writes.Count);
            var (reader, reads, _) = Create((_, body) => respond(body));
            Assert.Equal(PlanFailureKind.Unavailable, (await Assert.ThrowsAsync<PlanFailureException>(() => reader.ExecuteAsync(Read(), T.Ct))).Kind);
            Assert.Equal(1, reads.Count);
        }
    }

    [Fact]
    public async Task AnUnauthorizedReplyIsATransportFailure()
    {
        var (executor, _, _) = Create((_, _) => Task.FromResult(Json([], HttpStatusCode.Unauthorized)));
        Assert.Equal(PlanFailureKind.Transport, (await Assert.ThrowsAsync<PlanFailureException>(() => executor.ExecuteAsync(Write(), T.Ct))).Kind);
    }

    [Fact]
    public async Task CallerCancellationAfterSendIsUnknownForWritesAndCancellationForReads()
    {
        using var source = new CancellationTokenSource();
        var (writer, _, _) = Create(async (_, _) =>
        {
            await source.CancelAsync();
            source.Token.ThrowIfCancellationRequested();
            return Json([]);
        });
        Assert.Equal(PlanFailureKind.UnknownOutcome, (await Assert.ThrowsAsync<PlanFailureException>(() => writer.ExecuteAsync(Write(), source.Token))).Kind);
        using var second = new CancellationTokenSource();
        var (reader, _, _) = Create(async (_, _) =>
        {
            await second.CancelAsync();
            second.Token.ThrowIfCancellationRequested();
            return Json([]);
        });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reader.ExecuteAsync(Read(), second.Token));
    }

    [Fact]
    public async Task InvalidArgumentsNeverReachTheNetwork()
    {
        var (executor, handler, _) = Create((_, body) => Task.FromResult(Json(Success(body))));
        var plan = PlanManifest.Foundation.AccountLoad;
        var bad = new PlanCall[]
        {
            Read() with { Arguments = [] },
            Read() with { Arguments = [[D1Values.Text(Scope)]] },
            Read() with { Arguments = [[D1Values.Text(Scope), D1Values.Text("a"), D1Values.Text("b")]] },
            Read() with { Arguments = [[D1Values.Text(Scope), D1Values.Int64(1)]] },
            Read() with { Arguments = [[D1Values.Null(), D1Values.Text("a")]] },
            Read() with { Arguments = [[D1Values.Text(Scope), D1Values.Null()]] },
            Read() with { Arguments = [[D1Values.Text("proof/other"), D1Values.Text("a")]] },
            Read() with { Arguments = [[D1Values.Text(Scope), D1Values.Text("a\ud800")]] },
            Read() with { OwnerScope = "" },
            Read() with { RequestId = Guid.Empty },
            PlanCall.New(plan, new string('s', 257), 0, [[D1Values.Text(new string('s', 257)), D1Values.Text("a")]]),
        };
        foreach (var call in bad)
            Assert.Equal(PlanFailureKind.InvalidPlan, (await Assert.ThrowsAsync<PlanFailureException>(() => executor.ExecuteAsync(call, T.Ct))).Kind);
        Assert.Equal(0, handler.Count);
    }

    [Fact]
    public async Task RowsThatDoNotMatchThePlanAreRefused()
    {
        foreach (var rows in new D1Scalar[][][]
        {
            [[D1Values.Int64(1)]],
            [[D1Values.Text("1"), D1Values.Int64(1)]],
            [[D1Values.Int64(1), D1Values.Null()]],
            [[D1Values.Int64(1), D1Values.Int64(1)], [D1Values.Int64(2), D1Values.Int64(2)]],
        })
        {
            var (executor, _, _) = Create((_, body) => Task.FromResult(Json(Success(body, rows))));
            Assert.Equal(PlanFailureKind.InvalidPlan, (await Assert.ThrowsAsync<PlanFailureException>(() => executor.ExecuteAsync(Read(), T.Ct))).Kind);
        }

        // A write plan returns no rows at all.
        var (writer, _, _) = Create((_, body) => Task.FromResult(Json(Success(body, [[D1Values.Int64(1)]]))));
        Assert.Equal(PlanFailureKind.InvalidPlan, (await Assert.ThrowsAsync<PlanFailureException>(() => writer.ExecuteAsync(Write(), T.Ct))).Kind);
    }

    [Fact]
    public async Task ChangesAreAnExactUint64AndTheTimeoutIsBounded()
    {
        var (executor, handler, _) = Create((_, body) => Task.FromResult(Json(Success(body, changes: "18446744073709551615"))));
        Assert.Equal(ulong.MaxValue, (await executor.ExecuteAsync(Write(), T.Ct)).Changes);
        await executor.ExecuteAsync(Write() with { Timeout = TimeSpan.FromMinutes(5) }, T.Ct);
        var body = handler.Bodies[1];
        Assert.Equal(Start.AddSeconds(10), DateTimeOffset.Parse(Parse(body).DeadlineUtc, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal));
        await Assert.ThrowsAsync<PlanFailureException>(() => executor.ExecuteAsync(Write() with { Timeout = TimeSpan.Zero }, T.Ct));
        var (bad, _, _) = Create((_, body2) => Task.FromResult(Json(System.Text.Encoding.UTF8.GetBytes(System.Text.Encoding.UTF8.GetString(Success(body2)).Replace("\"changes\":\"0\"", "\"changes\":\"01\"", StringComparison.Ordinal)))));
        Assert.Equal(PlanFailureKind.UnknownOutcome, (await Assert.ThrowsAsync<PlanFailureException>(() => bad.ExecuteAsync(Write(), T.Ct))).Kind);
    }
}
