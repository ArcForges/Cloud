// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ArcForges.Cloud.Modules;

namespace ArcForges.Cloud.Storage.Capacity;

internal sealed record CapacityJobEnvelope(CapacityJobDefinition Definition, string ProgressJson);
[JsonSerializable(typeof(CapacityJobEnvelope))]
[JsonSerializable(typeof(CapacityJobSnapshot))]
[JsonSerializable(typeof(string[]))]
[JsonSourceGenerationOptions(UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
internal sealed partial class CapacityJobJson : JsonSerializerContext { }

internal static class CapacityJobCodec
{
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    internal static bool Text(string? value, int maximum) => value is { Length: > 0 } && value.Length <= maximum && value == value.Trim() && !value.Any(char.IsControl);
    internal static bool Owner(CapacityJobOwner? owner) => owner is not null && owner.RealmId != Guid.Empty && owner.WorkspaceId != Guid.Empty
        && owner.OwnerId != Guid.Empty && Text(owner.Kind, 64) && owner.Kind.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or ':' or '/' or '-');
    internal static bool Definition(CapacityJobDefinition? value) => value is not null && value.JobId != Guid.Empty && Owner(value.Owner)
        && Text(value.JobType, 64) && value.JobType.All(c => char.IsAsciiLetterOrDigit(c) || c is '.' or '_' or '-')
        && value.RecoveryGeneration <= long.MaxValue && Json(value.InputJson, 4096) && value.InputHash == Hash(value.InputJson)
        && value.MaximumAttempts is > 0 and <= 20 && value.AvailableAtMicros >= 0;
    internal static bool Snapshot(CapacityJobSnapshot value) => Definition(value.Definition) && value.Attempts >= 0 && value.Attempts <= value.Definition.MaximumAttempts
        && value.Fence >= 0 && Enum.IsDefined(value.State) && value.AvailableAtMicros >= 0 && Json(value.ProgressJson, 4096)
        && (value.State == CapacityJobState.Leased ? Text(value.Holder, 128) && value.LeasedUntilMicros is > 0 && value.Fence > 0
            : value.Holder is null && value.LeasedUntilMicros is null);
    internal static bool Json(string? value, int maximum)
    {
        if (value is null) return false;
        try
        {
            if (StrictUtf8.GetByteCount(value) > maximum) return false;
            using var document = JsonDocument.Parse(value, new() { MaxDepth = 32 });
            return document.RootElement.ValueKind == JsonValueKind.Object;
        }
        catch (Exception error) when (error is JsonException or EncoderFallbackException) { return false; }
    }
    internal static string Hash(string json) => Convert.ToHexStringLower(SHA256.HashData(StrictUtf8.GetBytes(json)));
    internal static long Now(TimeProvider time) => checked((time.GetUtcNow().UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10);
    internal static string Envelope(CapacityJobSnapshot value) => JsonSerializer.Serialize(new CapacityJobEnvelope(value.Definition, value.ProgressJson), CapacityJobJson.Default.CapacityJobEnvelope);
    internal static CapacityJobEnvelope DecodeEnvelope(string json)
    {
        using var document = JsonDocument.Parse(json, new() { MaxDepth = 32 });
        if (!document.RootElement.TryGetProperty("Definition", out var definition)
            || !definition.TryGetProperty("RecoveryGeneration", out var generation) || generation.ValueKind != JsonValueKind.String
            || !D1Values.TryParseUint64(generation.GetString()!, out var value) || value > long.MaxValue)
            throw new FormatException();
        return JsonSerializer.Deserialize(json, CapacityJobJson.Default.CapacityJobEnvelope) ?? throw new FormatException();
    }
    internal static string Result(CapacityJobSnapshot value) => JsonSerializer.Serialize(value, CapacityJobJson.Default.CapacityJobSnapshot);
    internal static CapacityJobSnapshot DecodeResult(string? json)
    {
        if (json is null || json.Length > 65536) throw new FormatException();
        using var document = JsonDocument.Parse(json, new() { MaxDepth = 32 });
        if (!document.RootElement.TryGetProperty("Definition", out var definition)
            || !definition.TryGetProperty("RecoveryGeneration", out var generation) || generation.ValueKind != JsonValueKind.String
            || !D1Values.TryParseUint64(generation.GetString()!, out var value) || value > long.MaxValue)
            throw new FormatException();
        var result = JsonSerializer.Deserialize(json, CapacityJobJson.Default.CapacityJobSnapshot) ?? throw new FormatException();
        return Snapshot(result) ? result : throw new FormatException();
    }
}
