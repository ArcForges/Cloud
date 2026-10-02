// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Storage;

namespace ArcForges.Cloud.Foundation;

internal enum ObjectOutcome
{
    Ok,
    /// <summary>The Worker answered with a refusal status (for example a declared hash that does not match the bytes).</summary>
    Rejected,
    /// <summary>The response violated the transfer contract: hash header, content range or status.</summary>
    Invalid,
    /// <summary>No usable response: connection failure, timeout or cancellation.</summary>
    Transport,
}

internal sealed record ObjectPutResult(ObjectOutcome Outcome, int StatusCode);

internal sealed record ObjectGetResult(ObjectOutcome Outcome, int StatusCode, byte[]? Bytes, string? ContentRange);

/// <summary>
/// Signed byte transfer to the private object facade. The body hash of a PUT is the declared content hash, so the
/// Worker verifies the signature before accepting a byte; every received byte is re-hashed locally. Failures are results, never raw transport text.
/// </summary>
internal sealed class ObjectsClient(HttpClient client, Uri objectsBaseUrl, SigningKey signingKey, TimeProvider time)
{
    public const int MaxBytes = 8 * 1024 * 1024;
    public const string HashHeader = "X-AF-Content-SHA256";
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    public async Task<ObjectPutResult> PutAsync(string workspaceId, string resourceId, ReadOnlyMemory<byte> bytes, string declaredSha256Hex, CancellationToken cancellationToken)
    {
        ValidateTarget(workspaceId, resourceId);
        if (bytes.Length is 0 or > MaxBytes || !PrivateRequestSigning.IsBodyHash(declaredSha256Hex)) throw new ArgumentException("Invalid transfer.", nameof(bytes));
        var uri = new Uri(objectsBaseUrl, Path(workspaceId, resourceId));
        using var request = new HttpRequestMessage(HttpMethod.Put, uri) { Content = new ReadOnlyMemoryContent(bytes) };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        request.Headers.TryAddWithoutValidation(HashHeader, declaredSha256Hex);
        Sign(request, "PUT", uri, declaredSha256Hex);
        var reply = await SendAsync(request, readBody: false, cancellationToken);
        if (reply.Status is not { } status) return new ObjectPutResult(ObjectOutcome.Transport, 0);
        var code = (int)status;
        return new ObjectPutResult(status == HttpStatusCode.Created ? ObjectOutcome.Ok : code is >= 400 and < 500 ? ObjectOutcome.Rejected : ObjectOutcome.Invalid, code);
    }

    /// <summary>Whole object (<paramref name="range"/> null, expects 200) or <c>bytes=start-end</c> (expects 206 and the exact Content-Range).</summary>
    public async Task<ObjectGetResult> GetAsync(string workspaceId, string resourceId, string objectSha256Hex, (long Start, long End)? range, long? totalSize, CancellationToken cancellationToken)
    {
        ValidateTarget(workspaceId, resourceId);
        if (!PrivateRequestSigning.IsBodyHash(objectSha256Hex)) throw new ArgumentException("Invalid object hash.", nameof(objectSha256Hex));
        var uri = new Uri(objectsBaseUrl, Path(workspaceId, resourceId) + "/" + objectSha256Hex);
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        if (range is { } window)
        {
            if (window.Start < 0 || window.End < window.Start) throw new ArgumentOutOfRangeException(nameof(range));
            request.Headers.TryAddWithoutValidation("Range", string.Create(CultureInfo.InvariantCulture, $"bytes={window.Start}-{window.End}"));
        }

        Sign(request, "GET", uri, Convert.ToHexStringLower(SHA256.HashData([])));
        var reply = await SendAsync(request, readBody: true, cancellationToken);
        if (reply.Status is not { } status) return new ObjectGetResult(ObjectOutcome.Transport, 0, null, null);
        var code = (int)status;
        var (declared, contentRange, body) = (reply.Hash, reply.Range, reply.Body);
        if (code is >= 400 and < 500) return new ObjectGetResult(ObjectOutcome.Rejected, code, null, null);
        if (body is null || status != (range is null ? HttpStatusCode.OK : HttpStatusCode.PartialContent)) return new ObjectGetResult(ObjectOutcome.Invalid, code, null, contentRange);
        var actual = Convert.ToHexStringLower(SHA256.HashData(body));
        var hashOk = range is null
            ? declared == actual && actual == objectSha256Hex
            // A partial body cannot be checked against the whole-object hash; the header must name the object or the partial bytes.
            : declared == objectSha256Hex || declared == actual;
        if (!hashOk) return new ObjectGetResult(ObjectOutcome.Invalid, code, null, contentRange);
        if (range is { } expected)
        {
            var length = expected.End - expected.Start + 1;
            if (body.Length != length || contentRange is null || !RangeMatches(contentRange, expected, totalSize))
                return new ObjectGetResult(ObjectOutcome.Invalid, code, null, contentRange);
        }

        return new ObjectGetResult(ObjectOutcome.Ok, code, body, contentRange);
    }

    private static bool RangeMatches(string contentRange, (long Start, long End) range, long? totalSize)
    {
        var prefix = string.Create(CultureInfo.InvariantCulture, $"bytes {range.Start}-{range.End}/");
        if (!contentRange.StartsWith(prefix, StringComparison.Ordinal)) return false;
        var total = contentRange[prefix.Length..];
        return D1Values.TryParseInt64(total, out var size) && size > range.End && (totalSize is null || size == totalSize);
    }

    private sealed record Reply(HttpStatusCode? Status, string? Hash, string? Range, byte[]? Body);

    private static string? Single(HttpHeaders headers, string name) => headers.TryGetValues(name, out var values) ? values.SingleOrDefault() : null;

    private static string Path(string workspaceId, string resourceId) => "/internal/objects/v1/probe/" + workspaceId + "/" + resourceId;

    private static void ValidateTarget(string workspaceId, string resourceId)
    {
        if (!FoundationIds.IsUuid(workspaceId) || !FoundationIds.IsUuid(resourceId)) throw new ArgumentException("Invalid object target.", nameof(workspaceId));
    }

    private void Sign(HttpRequestMessage request, string method, Uri uri, string bodyHash) =>
        PrivateRequestSigner.Sign(method, uri.PathAndQuery, bodyHash, Guid.NewGuid().ToString("D"), signingKey, time)
            .CopyTo((name, value) => request.Headers.TryAddWithoutValidation(name, value));

    private async Task<Reply> SendAsync(HttpRequestMessage request, bool readBody, CancellationToken cancellationToken)
    {
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bounded.CancelAfter(Timeout);
        try
        {
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, bounded.Token);
            var body = readBody && response.StatusCode is HttpStatusCode.OK or HttpStatusCode.PartialContent
                ? await HttpBodies.ReadLimitedAsync(response.Content, MaxBytes, bounded.Token)
                : null;
            return new Reply(response.StatusCode, Single(response.Headers, HashHeader), Single(response.Content.Headers, "Content-Range") ?? Single(response.Headers, "Content-Range"), body);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is OperationCanceledException or HttpRequestException or IOException)
        {
            return new Reply(null, null, null, null);
        }
    }
}
