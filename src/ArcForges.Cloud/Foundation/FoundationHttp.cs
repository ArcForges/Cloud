// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace ArcForges.Cloud.Foundation;

/// <summary>Response helpers shared by the browser and internal foundation routes: closed error bodies, no caching.</summary>
internal static class FoundationHttp
{
    public static Task WriteAsync(HttpContext context, int status, byte[] body)
    {
        var response = context.Response;
        response.StatusCode = status;
        response.Headers.CacheControl = "no-store";
        response.Headers.XContentTypeOptions = "nosniff";
        if (body.Length == 0)
        {
            response.ContentLength = 0;
            return Task.CompletedTask;
        }

        response.ContentType = "application/json";
        response.ContentLength = body.Length;
        return response.Body.WriteAsync(body, context.RequestAborted).AsTask();
    }

    public static Task WriteJsonAsync<T>(HttpContext context, int status, T value, JsonTypeInfo<T> info) =>
        WriteAsync(context, status, JsonSerializer.SerializeToUtf8Bytes(value, info));

    /// <summary>A closed error code: never an exception message, SQL or type name.</summary>
    public static Task ErrorAsync(HttpContext context, int status, string code) =>
        WriteJsonAsync(context, status, new ErrorBody(code), FoundationJsonContext.Default.ErrorBody);

    /// <summary>Exactly one value of a header, or null when it is absent or repeated.</summary>
    public static string? Single(HttpRequest request, string name) =>
        request.Headers.TryGetValue(name, out var values) && values.Count == 1 ? values[0] : null;
}
