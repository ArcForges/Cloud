// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;

namespace ArcForges.Cloud.Modules.Agent.Dispatch.Domain;

/// <summary>
/// The ai.internal envelope the Worker admits (worker/ai/internal/envelope.ts): a closed object with the version, the model, the C#-admitted
/// set, both caps and the frozen request, which is embedded unchanged. It is the only shape the Worker reads.
/// </summary>
internal static class AiEnvelope
{
    /// <summary>Serialises the envelope. The request must be one JSON object; anything else is refused before any byte is sent.</summary>
    internal static byte[] Build(string model, IReadOnlyList<string> admitted, int maxBodyBytes, int maxResponseBytes, string requestJson)
    {
        using (var document = JsonDocument.Parse(requestJson))
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object) throw new JsonException("A frozen request is a JSON object.");
        }

        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteNumber("v", 1);
            writer.WriteString("model", model);
            writer.WriteStartArray("admittedModels");
            foreach (var name in admitted) writer.WriteStringValue(name);
            writer.WriteEndArray();
            writer.WriteNumber("maxBodyBytes", maxBodyBytes);
            writer.WriteNumber("maxResponseBytes", maxResponseBytes);
            writer.WritePropertyName("request");
            writer.WriteRawValue(requestJson, skipInputValidation: false);
            writer.WriteEndObject();
        }

        return stream.ToArray();
    }

    /// <summary>
    /// True when the frozen request asks for a streamed answer: some top-level <c>stream</c> member is present and is not JSON false. The
    /// Worker answers a streamed request as text/event-stream, which this module never requests (HAR.40 (e)); every occurrence is checked, so
    /// a duplicated member cannot hide a stream request.
    /// </summary>
    internal static bool RequestsStream(string requestJson)
    {
        using var document = JsonDocument.Parse(requestJson);
        foreach (var property in document.RootElement.EnumerateObject())
        {
            if (property.NameEquals("stream") && property.Value.ValueKind != JsonValueKind.False) return true;
        }

        return false;
    }
}
