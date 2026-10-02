// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Http.Headers;
using System.Security.Cryptography;
using ArcForges.Cloud.Hmac;
using Microsoft.AspNetCore.Http.Features;

namespace ArcForges.Cloud.Foundation;

/// <summary>
/// The signed internal proof routes <c>POST /internal/foundation/v1/&lt;operation&gt;</c>, called only by the Worker over the
/// private path. Order: buffer the body (bounded), hash it, verify the w2c signature, check the content type, and only then parse.
/// </summary>
internal static class FoundationEndpoints
{
    public const string Prefix = "/internal/foundation/v1/";
    public const int MaxBodyBytes = 16384;

    public static void Map(IEndpointRouteBuilder app) => app.MapPost(Prefix + "{**operation}", HandleAsync);

    private static async Task HandleAsync(HttpContext context)
    {
        var options = context.RequestServices.GetRequiredService<FoundationOptions>();
        var time = context.RequestServices.GetRequiredService<TimeProvider>();
        // The host-wide limit protects Hello; these routes raise their own bound before the body is read.
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit) limit.MaxRequestBodySize = MaxBodyBytes + 1;
        if (context.Request.ContentLength > MaxBodyBytes)
        {
            await FoundationHttp.ErrorAsync(context, StatusCodes.Status413PayloadTooLarge, "invalid_request");
            return;
        }

        var body = await ReadBodyAsync(context);
        if (body is null)
        {
            await FoundationHttp.ErrorAsync(context, StatusCodes.Status413PayloadTooLarge, "invalid_request");
            return;
        }

        var rawTarget = context.Features.GetRequiredFeature<IHttpRequestFeature>().RawTarget;
        if (!PrivateRequestVerifier.Verify(context.Request.Method, rawTarget, Convert.ToHexStringLower(SHA256.HashData(body)),
                name => FoundationHttp.Single(context.Request, name), options.VerifyKeys, time.GetUtcNow(), out _))
        {
            // The same empty 401 for every failure: the reply never says which check failed.
            await FoundationHttp.WriteAsync(context, StatusCodes.Status401Unauthorized, []);
            return;
        }

        if (!IsJson(context.Request.ContentType))
        {
            await FoundationHttp.ErrorAsync(context, StatusCodes.Status415UnsupportedMediaType, "invalid_request");
            return;
        }

        var operation = context.GetRouteValue("operation") as string ?? "";
        var reply = await context.RequestServices.GetRequiredService<FoundationOperations>().ExecuteAsync(operation, body, context.RequestAborted);
        await FoundationHttp.WriteAsync(context, reply.Status, reply.Body);
    }

    private static bool IsJson(string? contentType)
    {
        if (!MediaTypeHeaderValue.TryParse(contentType, out var parsed) || !string.Equals(parsed.MediaType, "application/json", StringComparison.OrdinalIgnoreCase)) return false;
        return parsed.Parameters.All(p => string.Equals(p.Name, "charset", StringComparison.OrdinalIgnoreCase) && string.Equals(p.Value?.Trim('"'), "utf-8", StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>The whole body, or null when it exceeds <see cref="MaxBodyBytes"/>.</summary>
    private static async Task<byte[]?> ReadBodyAsync(HttpContext context)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[4096];
        int read;
        try
        {
            while ((read = await context.Request.Body.ReadAsync(chunk, context.RequestAborted)) > 0)
            {
                if (buffer.Length + read > MaxBodyBytes) return null;
                buffer.Write(chunk, 0, read);
            }
        }
        catch (BadHttpRequestException)
        {
            return null;
        }

        return buffer.ToArray();
    }
}
