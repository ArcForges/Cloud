// SPDX-License-Identifier: AGPL-3.0-only
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules.Agent.Dispatch.Domain;

namespace ArcForges.Cloud.Modules.Agent.Dispatch.Application;

/// <summary>
/// The model dispatch of the Agent module (HAR.40 section (c)): it admits one call against the C#-admitted set, the pinned snapshot, the
/// per-model token bucket and the caps, then sends the closed envelope to the ai.internal route with the call's own deadline. The Worker
/// refusals of 4xx codes are refusals before the binding was called, so they are pre-dispatch refusals; a timeout, a transport failure, a
/// 5xx, an over-cap or an invalid answer may have reached the binding and is <see cref="ModelDispatchStatus.Unknown"/>, never retried.
/// </summary>
public sealed class ModelDispatchClient(ModelDispatchOptions options, HttpClient http, TimeProvider time) : IModelDispatchPort
{
    private readonly ModelRateBuckets buckets = new(options.RateCapacity, options.RefillPerSecond);

    /// <summary>The pinned snapshot of an admitted model, or null when the model is not admitted (a missing snapshot).</summary>
    public ModelSnapshot? SnapshotOf(string modelId)
    {
        ArgumentNullException.ThrowIfNull(modelId);
        foreach (var admitted in options.Admitted)
        {
            if (string.Equals(admitted.ModelId, modelId, StringComparison.Ordinal)) return new ModelSnapshot(admitted.ModelId, admitted.TariffSnapshotId);
        }

        return null;
    }

    public async Task<ModelCallResult> DispatchAsync(ModelCallRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var refusal = Admit(request);
        if (refusal is not null) return Refused(refusal);

        // Every check that does not spend a token runs first, so a refused call never takes one.
        byte[] envelope;
        try
        {
            envelope = AiEnvelope.Build(request.ModelId, options.Admitted.Select(model => model.ModelId).ToList(), options.MaxBodyBytes, options.MaxResponseBytes, request.RequestJson);
        }
        catch (JsonException)
        {
            return Refused("request_invalid");
        }

        if (envelope.Length > options.MaxBodyBytes) return Refused("body_over_cap");
        if (!buckets.TryTake(request.ModelId, Micros())) return Refused("rate_limited");
        return await SendAsync(envelope, request.Deadline, cancellationToken).ConfigureAwait(false);
    }

    private string? Admit(ModelCallRequest request)
    {
        var snapshot = SnapshotOf(request.ModelId);
        if (snapshot is null) return "model_not_admitted";
        if (!string.Equals(snapshot.TariffSnapshotId, request.TariffSnapshotId, StringComparison.Ordinal)) return "snapshot_mismatch";
        if (request.Deadline <= TimeSpan.Zero || request.Deadline > TimeSpan.FromSeconds(ModelDispatchOptions.MaxDeadlineSeconds)) return "deadline_out_of_range";
        if (request.MaxOutputTokens is < 1 or > ModelDispatchOptions.MaxOutputTokens) return "output_cap";
        if (request.ToolCount is < 0 or > ModelDispatchOptions.MaxToolCount) return "tool_cap";
        if (Encoding.UTF8.GetByteCount(request.RequestJson) > options.MaxBodyBytes) return "body_over_cap";
        return null;
    }

    private async Task<ModelCallResult> SendAsync(byte[] envelope, TimeSpan deadline, CancellationToken cancellationToken)
    {
        using var bound = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        bound.CancelAfter(deadline);
        using var message = new HttpRequestMessage(HttpMethod.Post, new Uri(options.BaseUrl, ModelDispatchRoute.RunPath))
        {
            Content = new ByteArrayContent(envelope),
        };
        message.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json") { CharSet = "utf-8" };

        HttpResponseMessage response;
        try
        {
            response = await http.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, bound.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return Unknown(cancellationToken.IsCancellationRequested ? "cancelled" : "deadline");
        }
        catch (HttpRequestException)
        {
            return Unknown("transport");
        }

        using (response)
        {
            var code = (int)response.StatusCode;
            if (code is 400 or 403 or 404 or 405 or 413 or 415) return Refused("adapter_refused_" + code.ToString(System.Globalization.CultureInfo.InvariantCulture));
            if (code != 200) return Unknown("adapter_" + code.ToString(System.Globalization.CultureInfo.InvariantCulture));

            var body = await ReadBoundedAsync(response.Content, options.MaxResponseBytes, bound.Token).ConfigureAwait(false);
            if (body is null) return Unknown("response_over_cap");
            var text = Encoding.UTF8.GetString(body);
            if (!IsJsonObject(text)) return Unknown("response_invalid");
            return new ModelCallResult(ModelDispatchStatus.Succeeded, text, "ok");
        }
    }

    private long Micros() => (time.GetUtcNow() - DateTimeOffset.UnixEpoch).Ticks / 10;

    private static ModelCallResult Refused(string reason) => new(ModelDispatchStatus.RefusedBeforeDispatch, null, reason);

    private static ModelCallResult Unknown(string reason) => new(ModelDispatchStatus.Unknown, null, reason);

    private static bool IsJsonObject(string text)
    {
        try
        {
            using var document = JsonDocument.Parse(text);
            return document.RootElement.ValueKind == JsonValueKind.Object;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    /// <summary>The whole answer, or null when it is longer than the limit or the read is cancelled.</summary>
    private static async Task<byte[]?> ReadBoundedAsync(HttpContent content, int limit, CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = await content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            var chunk = new byte[4096];
            int read;
            while ((read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false)) > 0)
            {
                if (buffer.Length + read > limit) return null;
                buffer.Write(chunk, 0, read);
            }

            return buffer.ToArray();
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }
}

/// <summary>The one route of the ai.internal Worker transport this module calls.</summary>
internal static class ModelDispatchRoute
{
    internal const string RunPath = "v1/run";
}
