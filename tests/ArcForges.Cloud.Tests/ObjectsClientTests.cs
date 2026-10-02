// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Hmac;
using Xunit;

namespace ArcForges.Cloud.Tests;

public sealed class ObjectsClientTests
{
    private static readonly DateTimeOffset Start = new(2026, 10, 2, 12, 0, 0, TimeSpan.Zero);
    private static readonly string Workspace = T.Uuid();
    private static readonly string Resource = T.Uuid();
    private static readonly byte[] Payload = Enumerable.Range(0, 4096).Select(i => (byte)(i * 31)).ToArray();
    private static readonly string PayloadHash = T.Sha256Hex(Payload);

    private static (ObjectsClient Client, StubHandler Handler, SigningKey Key) Create(Func<HttpRequestMessage, byte[], Task<HttpResponseMessage>> respond)
    {
        var handler = new StubHandler(respond);
        var key = T.Key("c2w-1");
        return (new ObjectsClient(new HttpClient(handler), new Uri("http://objects.test"), key, new FakeTime(Start)), handler, key);
    }

    private static HttpResponseMessage Reply(HttpStatusCode status, byte[]? body = null, string? hash = null, string? range = null)
    {
        var response = new HttpResponseMessage(status) { Content = new ByteArrayContent(body ?? []) };
        if (hash is not null) response.Headers.TryAddWithoutValidation("X-AF-Content-SHA256", hash);
        if (range is not null) response.Content.Headers.TryAddWithoutValidation("Content-Range", range);
        return response;
    }

    private static string? Header(HttpRequestMessage request, string name) => request.Headers.TryGetValues(name, out var values) ? values.Single() : null;

    [Fact]
    public async Task PutSignsOverTheDeclaredHashBeforeAnyByteIsAccepted()
    {
        var (client, handler, key) = Create((_, _) => Task.FromResult(Reply(HttpStatusCode.Created)));
        var result = await client.PutAsync(Workspace, Resource, Payload, PayloadHash, T.Ct);
        Assert.Equal(ObjectOutcome.Ok, result.Outcome);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Put, request.Method);
        Assert.Equal($"/internal/objects/v1/probe/{Workspace}/{Resource}", request.RequestUri!.AbsolutePath);
        Assert.Equal(PayloadHash, Header(request, "X-AF-Content-SHA256"));
        Assert.True(PrivateRequestVerifier.Verify("PUT", request.RequestUri.PathAndQuery, PayloadHash, name => Header(request, name), [key], Start, out _));
        // A signature over any other hash does not verify, so a mismatch is caught before bytes are read.
        Assert.False(PrivateRequestVerifier.Verify("PUT", request.RequestUri.PathAndQuery, T.Sha256Hex("other"), name => Header(request, name), [key], Start, out _));
    }

    [Theory]
    [InlineData(HttpStatusCode.UnprocessableEntity, "Rejected")]
    [InlineData(HttpStatusCode.Unauthorized, "Rejected")]
    [InlineData(HttpStatusCode.OK, "Invalid")]
    [InlineData(HttpStatusCode.InternalServerError, "Invalid")]
    public async Task PutMapsStatusesWithoutTransportText(HttpStatusCode status, string expected)
    {
        var (client, _, _) = Create((_, _) => Task.FromResult(Reply(status)));
        Assert.Equal(Enum.Parse<ObjectOutcome>(expected), (await client.PutAsync(Workspace, Resource, Payload, PayloadHash, T.Ct)).Outcome);
    }

    [Fact]
    public async Task ConnectionFailureIsATransportResultAndCallerCancellationPropagates()
    {
        var (client, _, _) = Create((_, _) => throw new HttpRequestException("reset by peer"));
        Assert.Equal(ObjectOutcome.Transport, (await client.PutAsync(Workspace, Resource, Payload, PayloadHash, T.Ct)).Outcome);
        Assert.Equal(ObjectOutcome.Transport, (await client.GetAsync(Workspace, Resource, PayloadHash, null, null, T.Ct)).Outcome);
        using var source = new CancellationTokenSource();
        await source.CancelAsync();
        var (cancelled, _, _) = Create((_, _) => throw new OperationCanceledException(source.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => cancelled.GetAsync(Workspace, Resource, PayloadHash, null, null, source.Token));
    }

    [Fact]
    public async Task InvalidTransfersAreRefusedBeforeTheNetwork()
    {
        var (client, handler, _) = Create((_, _) => Task.FromResult(Reply(HttpStatusCode.Created)));
        await Assert.ThrowsAsync<ArgumentException>(() => client.PutAsync(Workspace, Resource, ReadOnlyMemory<byte>.Empty, PayloadHash, T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => client.PutAsync(Workspace, Resource, new byte[ObjectsClient.MaxBytes + 1], PayloadHash, T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => client.PutAsync(Workspace, Resource, Payload, PayloadHash.ToUpperInvariant(), T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => client.PutAsync("x", Resource, Payload, PayloadHash, T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetAsync(Workspace, "x", PayloadHash, null, null, T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(() => client.GetAsync(Workspace, Resource, "abc", null, null, T.Ct));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => client.GetAsync(Workspace, Resource, PayloadHash, (5, 4), null, T.Ct));
        Assert.Equal(0, handler.Count);
    }

    [Fact]
    public async Task WholeObjectIsVerifiedAgainstTheStoredAndTheLocalHash()
    {
        var (client, handler, key) = Create((_, _) => Task.FromResult(Reply(HttpStatusCode.OK, Payload, PayloadHash)));
        var ok = await client.GetAsync(Workspace, Resource, PayloadHash, null, null, T.Ct);
        Assert.Equal(ObjectOutcome.Ok, ok.Outcome);
        Assert.Equal(Payload, ok.Bytes);
        var request = Assert.Single(handler.Requests);
        Assert.Equal($"/internal/objects/v1/probe/{Workspace}/{Resource}/{PayloadHash}", request.RequestUri!.AbsolutePath);
        Assert.True(PrivateRequestVerifier.Verify("GET", request.RequestUri.PathAndQuery, T.Sha256Hex([]), name => Header(request, name), [key], Start, out _));
        var tampered = Payload.ToArray();
        tampered[10] ^= 1;
        foreach (var response in new Func<HttpResponseMessage>[]
        {
            () => Reply(HttpStatusCode.OK, tampered, PayloadHash),
            () => Reply(HttpStatusCode.OK, Payload, T.Sha256Hex("x")),
            () => Reply(HttpStatusCode.OK, Payload),
            () => Reply(HttpStatusCode.PartialContent, Payload, PayloadHash),
            () => Reply(HttpStatusCode.OK, tampered, T.Sha256Hex(tampered)),
        })
        {
            var (bad, _, _) = Create((_, _) => Task.FromResult(response()));
            Assert.Equal(ObjectOutcome.Invalid, (await bad.GetAsync(Workspace, Resource, PayloadHash, null, null, T.Ct)).Outcome);
        }

        var (missing, _, _) = Create((_, _) => Task.FromResult(Reply(HttpStatusCode.NotFound)));
        Assert.Equal(ObjectOutcome.Rejected, (await missing.GetAsync(Workspace, Resource, PayloadHash, null, null, T.Ct)).Outcome);
    }

    [Fact]
    public async Task RangesNeedAnExactContentRangeAndLength()
    {
        var slice = Payload[10..20];
        var (client, handler, _) = Create((_, _) => Task.FromResult(Reply(HttpStatusCode.PartialContent, slice, PayloadHash, "bytes 10-19/4096")));
        var ok = await client.GetAsync(Workspace, Resource, PayloadHash, (10, 19), 4096, T.Ct);
        Assert.Equal(ObjectOutcome.Ok, ok.Outcome);
        Assert.Equal(slice, ok.Bytes);
        Assert.Equal("bytes=10-19", handler.Requests[0].Headers.GetValues("Range").Single());
        foreach (var response in new Func<HttpResponseMessage>[]
        {
            () => Reply(HttpStatusCode.PartialContent, slice, PayloadHash, "bytes 11-20/4096"),
            () => Reply(HttpStatusCode.PartialContent, slice, PayloadHash, "bytes 10-19/4095"),
            () => Reply(HttpStatusCode.PartialContent, slice, PayloadHash, "bytes 10-19/9"),
            () => Reply(HttpStatusCode.PartialContent, slice, PayloadHash),
            () => Reply(HttpStatusCode.PartialContent, slice[..9], PayloadHash, "bytes 10-19/4096"),
            () => Reply(HttpStatusCode.PartialContent, slice, T.Sha256Hex("x"), "bytes 10-19/4096"),
            () => Reply(HttpStatusCode.OK, slice, PayloadHash, "bytes 10-19/4096"),
        })
        {
            var (bad, _, _) = Create((_, _) => Task.FromResult(response()));
            Assert.Equal(ObjectOutcome.Invalid, (await bad.GetAsync(Workspace, Resource, PayloadHash, (10, 19), 4096, T.Ct)).Outcome);
        }

        // A partial body may be vouched for by its own hash header; a mismatch with both names is refused above.
        var (own, _, _) = Create((_, _) => Task.FromResult(Reply(HttpStatusCode.PartialContent, slice, T.Sha256Hex(slice), "bytes 10-19/4096")));
        Assert.Equal(ObjectOutcome.Ok, (await own.GetAsync(Workspace, Resource, PayloadHash, (10, 19), null, T.Ct)).Outcome);
    }
}
