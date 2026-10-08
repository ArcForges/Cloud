// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace ArcForges.Cloud.Modules.Task.Harness.Wake;

/// <summary>
/// The wake route of the Task module, <c>POST /internal/harness/v1/wake</c> (HAR.40). It is mapped only when the wake port is registered, which
/// the host does only under the foundation configuration with its W2C key; without it the route does not exist. The order is the one of the
/// signed routes: the bounded body is read, its hash is taken, the W2C signature is verified over the exact target and hash, and only then is
/// the body parsed. A failed signature is an empty 401 that never says which check failed.
/// </summary>
public static class HarnessWakeEndpoint
{
    public static void Map(IEndpointRouteBuilder endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        if (endpoints.ServiceProvider.GetService<IHarnessWakePort>() is null) return;
        endpoints.MapPost(HarnessWakeRoute.Path, HandleAsync);
    }

    private static async global::System.Threading.Tasks.Task HandleAsync(HttpContext context)
    {
        var port = context.RequestServices.GetRequiredService<IHarnessWakePort>();
        if (!IsJson(context.Request.ContentType))
        {
            context.Response.StatusCode = StatusCodes.Status415UnsupportedMediaType;
            return;
        }

        if (context.Request.ContentLength > HarnessWakeRoute.MaxBodyBytes)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }

        var body = await ReadBodyAsync(context.Request.Body, context.RequestAborted).ConfigureAwait(false);
        if (body is null)
        {
            context.Response.StatusCode = StatusCodes.Status413PayloadTooLarge;
            return;
        }

        var rawTarget = context.Features.GetRequiredFeature<IHttpRequestFeature>().RawTarget;
        var bodyHash = Convert.ToHexStringLower(SHA256.HashData(body));
        if (!port.Authenticate(context.Request.Method, rawTarget, bodyHash, name => SingleHeader(context.Request, name)))
        {
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            return;
        }

        if (!TryParse(body, out var message))
        {
            context.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var reply = await port.HandleAsync(message, context.RequestAborted).ConfigureAwait(false);
        // 200 once the wake is taken (the run's own decision follows). Every other reply is the typed retryable 503: the store could not settle the
        // wake, a live lease refused it, or a read was not served. The alarm retries it, and the Retry-After hint is one second (the first backoff).
        if (reply == HarnessWakeReply.Taken)
        {
            context.Response.StatusCode = StatusCodes.Status200OK;
            return;
        }

        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        context.Response.Headers["Retry-After"] = "1";
    }

    /// <summary>The wake body: exactly the closed key set, the exact version and kind, canonical identifiers, a time and a Worker version.</summary>
    internal static bool TryParse(byte[] body, out HarnessWakeMessage message)
    {
        message = null!;
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;
            var keys = new List<string>();
            foreach (var property in root.EnumerateObject()) keys.Add(property.Name);
            keys.Sort(StringComparer.Ordinal);
            if (string.Join(",", keys) != "kind,runId,v,wakeAtMs,workerVersion,workspaceId") return false;
            if (!root.TryGetProperty("v", out var version) || version.ValueKind != JsonValueKind.Number || !version.TryGetInt64(out var v) || v != 1) return false;
            if (!root.TryGetProperty("kind", out var kind) || kind.ValueKind != JsonValueKind.String || kind.GetString() != "harness.wake") return false;
            if (!TryCanonicalGuid(root, "workspaceId", out var workspaceId) || !TryCanonicalGuid(root, "runId", out var runId)) return false;
            if (!root.TryGetProperty("wakeAtMs", out var wakeAt) || wakeAt.ValueKind != JsonValueKind.Number || !wakeAt.TryGetInt64(out var wakeAtMs)) return false;
            if (!root.TryGetProperty("workerVersion", out var workerVersion) || workerVersion.ValueKind != JsonValueKind.String) return false;
            var workerText = workerVersion.GetString() ?? string.Empty;
            if (!HarnessWakeService.IsWorkerVersion(workerText)) return false;
            message = new HarnessWakeMessage(workspaceId, runId, workerText, wakeAtMs);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryCanonicalGuid(JsonElement root, string name, out Guid value)
    {
        value = Guid.Empty;
        if (!root.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String) return false;
        var text = property.GetString() ?? string.Empty;
        return Guid.TryParseExact(text, "D", out value) && string.Equals(value.ToString("D", CultureInfo.InvariantCulture), text, StringComparison.Ordinal);
    }

    private static bool IsJson(string? contentType) =>
        contentType is not null && string.Equals(contentType.Split(';')[0].Trim(), "application/json", StringComparison.OrdinalIgnoreCase);

    /// <summary>A header only when it is present exactly once.</summary>
    private static string? SingleHeader(HttpRequest request, string name) =>
        request.Headers.TryGetValue(name, out var values) && values.Count == 1 ? values[0] : null;

    /// <summary>The whole body, or null when it exceeds the wake limit.</summary>
    private static async Task<byte[]?> ReadBodyAsync(Stream body, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[1024];
        int read;
        while ((read = await body.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
        {
            if (buffer.Length + read > HarnessWakeRoute.MaxBodyBytes) return null;
            buffer.Write(chunk, 0, read);
        }

        return buffer.ToArray();
    }
}
