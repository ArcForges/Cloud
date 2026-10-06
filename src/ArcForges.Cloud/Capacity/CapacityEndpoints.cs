// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage.Capacity;
using Microsoft.AspNetCore.Http.Features;

namespace ArcForges.Cloud.Capacity;

internal sealed record CapacityHttpResult(string Status, string? AvailableAtMicros, string? Fence);
internal sealed record CapacityRecoveryRequest(Guid RequestId, string? AfterDueAtMicros, Guid? AfterJobId);
internal sealed record CapacityRecoveryHttpResult(string Status, string? NextDueAtMicros, Guid? NextJobId);
[JsonSerializable(typeof(CapacityRecoveryRequest))]
[JsonSerializable(typeof(CapacityRecoveryHttpResult))]
[JsonSerializable(typeof(CapacityWake))]
[JsonSerializable(typeof(CapacityHttpResult))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
internal sealed partial class CapacityHttpJson : JsonSerializerContext { }

internal sealed record CapacityIngressOptions(IReadOnlyList<SigningKey> VerifyKeys, SigningKey ScheduleSigner)
{
    internal static CapacityIngressOptions Parse(Func<string, string?> read)
    {
        if (!SigningKey.TryCreate(read("AF_HMAC_W2C_KEY_ID"), read("AF_HMAC_W2C_SECRET"), out var current))
            throw new InvalidOperationException("Invalid capacity AF_HMAC_W2C configuration");
        if (!SigningKey.TryCreate(read("AF_HMAC_C2W_KEY_ID"), read("AF_HMAC_C2W_SECRET"), out var signer))
            throw new InvalidOperationException("Invalid capacity AF_HMAC_C2W configuration");
        var priorId = read("AF_HMAC_W2C_PREVIOUS_KEY_ID");
        var priorSecret = read("AF_HMAC_W2C_PREVIOUS_SECRET");
        if (priorId is null && priorSecret is null) return new([current], signer);
        if (!SigningKey.TryCreate(priorId, priorSecret, out var prior) || prior.Id == current.Id)
            throw new InvalidOperationException("Invalid capacity previous AF_HMAC_W2C configuration");
        return new([current, prior], signer);
    }
}

/// <summary>The exact private wake route. The signature binds the complete bounded bytes and wake ID;
/// current job ownership/recovery is independently checked by the production job port. No public route
/// or unverified scope hint may dispatch work.</summary>
internal static class CapacityEndpoints
{
    internal const string Path = "/internal/capacity/v1/wake";
    internal const string RecoveryPath = "/internal/capacity/v1/recover";
    internal const int MaximumBodyBytes = 4096;
    internal static void Map(IEndpointRouteBuilder app)
    {
        app.MapPost(Path, HandleAsync); app.MapPost(RecoveryPath, HandleAsync);
    }
    internal static async Task HandleAsync(HttpContext context)
    {
        var request = context.Request;
        using var bounded = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        bounded.CancelAfter(TimeSpan.FromSeconds(25));
        var path = request.Path.Value;
        context.Response.Headers.CacheControl = "no-store";
        if (request.Method != "POST" || path is not (Path or RecoveryPath) || request.QueryString.HasValue
            || context.Features.Get<IHttpRequestFeature>()?.RawTarget != path)
        { context.Response.StatusCode = 404; return; }
        if (request.Headers.ContainsKey("Content-Encoding") || request.ContentType is not ("application/json" or "application/json; charset=utf-8"))
        { context.Response.StatusCode = 415; return; }
        if (context.Features.Get<IHttpMaxRequestBodySizeFeature>() is { IsReadOnly: false } limit) limit.MaxRequestBodySize = MaximumBodyBytes + 1;
        if (request.ContentLength > MaximumBodyBytes) { context.Response.StatusCode = 413; return; }
        using var buffered = new MemoryStream();
        var block = new byte[1024];
        try
        {
            int count;
            while ((count = await request.Body.ReadAsync(block, bounded.Token).ConfigureAwait(false)) > 0)
            {
                if (buffered.Length + count > MaximumBodyBytes) { context.Response.StatusCode = 413; return; }
                bounded.Token.ThrowIfCancellationRequested(); buffered.Write(block, 0, count);
            }
        }
        catch (OperationCanceledException) when (!context.RequestAborted.IsCancellationRequested) { context.Response.StatusCode = 503; return; }
        catch (BadHttpRequestException) { context.Response.StatusCode = 413; return; }
        bounded.Token.ThrowIfCancellationRequested();
        var body = buffered.ToArray();
        var options = context.RequestServices.GetRequiredService<CapacityIngressOptions>();
        var time = context.RequestServices.GetRequiredService<TimeProvider>();
        if (!PrivateRequestVerifier.Verify("POST", path!, Convert.ToHexStringLower(SHA256.HashData(body)),
            name => request.Headers.TryGetValue(name, out var values) && values.Count == 1 ? values[0] : null,
            options.VerifyKeys, time.GetUtcNow(), out var verified))
        { context.Response.StatusCode = 401; return; }
        if (path == RecoveryPath)
        {
            CapacityRecoveryRequest? recovery;
            try
            {
                using var document = JsonDocument.Parse(body, new() { MaxDepth = 16 });
                if (!Unique(document.RootElement)) { context.Response.StatusCode = 400; return; }
                recovery = JsonSerializer.Deserialize(body, CapacityHttpJson.Default.CapacityRecoveryRequest);
            }
            catch (JsonException) { context.Response.StatusCode = 400; return; }
            CapacityDueCursor? cursor = null;
            if (recovery is null || recovery.RequestId == Guid.Empty || recovery.RequestId.ToString("D") != verified.RequestId
                || (recovery.AfterDueAtMicros is null) != (recovery.AfterJobId is null))
            { context.Response.StatusCode = 400; return; }
            if (recovery.AfterDueAtMicros is { } due)
            {
                if (!long.TryParse(due, NumberStyles.None, CultureInfo.InvariantCulture, out var value) || value < 0
                    || value.ToString(CultureInfo.InvariantCulture) != due || recovery.AfterJobId == Guid.Empty)
                { context.Response.StatusCode = 400; return; }
                cursor = new(value, recovery.AfterJobId!.Value);
            }
            var recovered = await context.RequestServices.GetRequiredService<CapacityRecoveryService>()
                .RunAsync(recovery.RequestId, cursor, bounded.Token).ConfigureAwait(false);
            var output = new CapacityRecoveryHttpResult(recovered.Status.ToString(),
                recovered.Next?.DueAtMicros.ToString(CultureInfo.InvariantCulture), recovered.Next?.JobId);
            context.Response.StatusCode = 200; context.Response.ContentType = "application/json";
            await context.Response.Body.WriteAsync(JsonSerializer.SerializeToUtf8Bytes(output,
                CapacityHttpJson.Default.CapacityRecoveryHttpResult), bounded.Token).ConfigureAwait(false);
            return;
        }
        CapacityWake? wake;
        try
        {
            using var document = JsonDocument.Parse(body, new() { MaxDepth = 16 });
            if (!Unique(document.RootElement)) { context.Response.StatusCode = 400; return; }
            wake = JsonSerializer.Deserialize(body, CapacityHttpJson.Default.CapacityWake);
        }
        catch (JsonException) { context.Response.StatusCode = 400; return; }
        if (wake is null || wake.WakeId.ToString("D") != verified.RequestId || wake.Holder != "capacity-" + wake.WakeId.ToString("D")
            || !CapacityJobCodec.Owner(wake.Owner))
        { context.Response.StatusCode = 400; return; }
        var result = await context.RequestServices.GetRequiredService<CapacityDispatcher>().RunAsync(wake, bounded.Token).ConfigureAwait(false);
        var reply = new CapacityHttpResult(result.Status.ToString(), result.AvailableAtMicros?.ToString(CultureInfo.InvariantCulture), result.Fence?.ToString(CultureInfo.InvariantCulture));
        context.Response.StatusCode = 200;
        context.Response.ContentType = "application/json";
        await context.Response.Body.WriteAsync(JsonSerializer.SerializeToUtf8Bytes(reply, CapacityHttpJson.Default.CapacityHttpResult), bounded.Token).ConfigureAwait(false);
    }

    private static bool Unique(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Object => value.EnumerateObject().Select(property => property.Name).Distinct(StringComparer.Ordinal).Count() == value.EnumerateObject().Count()
            && value.EnumerateObject().All(property => Unique(property.Value)),
        JsonValueKind.Array => value.EnumerateArray().All(Unique),
        _ => true,
    };
}
