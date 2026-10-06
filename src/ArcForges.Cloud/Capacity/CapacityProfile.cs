// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ArcForges.Cloud.Capacity;

internal sealed record CapacityConcurrency(int OutputStreams, int UnaryCalls, int QueuedCalls, int Jobs, int ControlSlots);
internal sealed record CapacityAllocation(
    [property: JsonConverter(typeof(CapacityUInt64Converter))] ulong Vectors,
    [property: JsonConverter(typeof(CapacityUInt64Converter))] ulong Namespaces,
    [property: JsonConverter(typeof(CapacityUInt64Converter))] ulong R2Bytes,
    [property: JsonConverter(typeof(CapacityUInt64Converter))] ulong R2Objects,
    [property: JsonConverter(typeof(CapacityUInt64Converter))] ulong ClassAPerDay,
    [property: JsonConverter(typeof(CapacityUInt64Converter))] ulong ClassBPerDay,
    [property: JsonConverter(typeof(CapacityUInt64Converter))] ulong ServedBytesPerDay);
internal sealed record CapacityProfile(string ProfileId, Guid RealmId, string InstanceType, int InstanceSlots,
    int SleepAfterSeconds, int ReadinessTimeoutMs, int FirstResponseDeadlineMs, CapacityConcurrency PerInstance,
    CapacityAllocation AccountPlanning, CapacityAllocation RealmBudgets, int[] ThresholdsPercent,
    string WorkloadHash, string SourceSnapshotHash);
[JsonSerializable(typeof(CapacityProfile))]
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow)]
internal sealed partial class CapacityProfileJson : JsonSerializerContext { }

/// <summary>Wire uint64s never pass through doubles. Int32-sized values are JSON numbers; larger
/// values are canonical decimal strings, exactly as the approved model04 manifest requires.</summary>
internal sealed class CapacityUInt64Converter : JsonConverter<ulong>
{
    public override ulong Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Number && reader.TryGetInt32(out var small) && small >= 0) return (ulong)small;
        if (reader.TokenType == JsonTokenType.String && ulong.TryParse(reader.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out var value)
            && value > int.MaxValue && value.ToString(CultureInfo.InvariantCulture) == reader.GetString()) return value;
        throw new JsonException("Capacity integer must use its exact canonical representation.");
    }
    public override void Write(Utf8JsonWriter writer, ulong value, JsonSerializerOptions options)
    { if (value <= int.MaxValue) writer.WriteNumberValue(value); else writer.WriteStringValue(value.ToString(CultureInfo.InvariantCulture)); }
}

internal static class CapacityProfileCodec
{
    private const ulong GiB = 1073741824;
    internal static readonly CapacityAllocation SelectedAccount = new(2000, 4, 20 * GiB, 2000, 2000, 20000, 5 * GiB);
    internal static readonly CapacityAllocation SelectedRealm = new(2000000, 4000, 20000 * GiB, 2000000, 2000000, 20000000, 5000 * GiB);
    internal static string Encode(CapacityProfile profile) => JsonSerializer.Serialize(profile, CapacityProfileJson.Default.CapacityProfile);
    internal static bool TryDecode(string json, string expectedHash, Guid expectedRealm, CapacityAllocation verifiedProviderLimits,
        out CapacityProfile? profile)
    {
        profile = null;
        if (string.IsNullOrEmpty(json) || verifiedProviderLimits is null) return false;
        try
        {
            var bytes = new UTF8Encoding(false, true).GetBytes(json);
            if (bytes.Length > 16384 || !Hash(expectedHash) || Convert.ToHexStringLower(SHA256.HashData(bytes)) != expectedHash) return false;
            using var document = JsonDocument.Parse(bytes, new() { MaxDepth = 8 });
            if (!Unique(document.RootElement)) return false;
            var value = JsonSerializer.Deserialize(bytes, CapacityProfileJson.Default.CapacityProfile);
            if (value is null || value.ProfileId != "launch-capacity.v1" || value.RealmId == Guid.Empty || value.RealmId != expectedRealm
                || value.InstanceType != "standard-2" || value.InstanceSlots != 4 || value.SleepAfterSeconds != 600
                || value.ReadinessTimeoutMs != 8000 || value.FirstResponseDeadlineMs != 10000
                || value.PerInstance != new CapacityConcurrency(64, 16, 32, 8, 2) || value.AccountPlanning != SelectedAccount
                || value.RealmBudgets != SelectedRealm || value.ThresholdsPercent is null || !value.ThresholdsPercent.SequenceEqual([60, 70, 80, 90])
                || !Hash(value.WorkloadHash) || !Hash(value.SourceSnapshotHash)) return false;
            var accounts = Dimensions(value.AccountPlanning); var realm = Dimensions(value.RealmBudgets); var limits = Dimensions(verifiedProviderLimits);
            for (var index = 0; index < accounts.Length; index++)
                if (realm[index] > limits[index] || checked(accounts[index] * 500) > realm[index] / 2) return false;
            profile = value; return true;
        }
        catch (Exception error) when (error is JsonException or EncoderFallbackException or OverflowException) { return false; }
    }
    internal static ulong[] Dimensions(CapacityAllocation value) => [value.Vectors, value.Namespaces, value.R2Bytes, value.R2Objects,
        value.ClassAPerDay, value.ClassBPerDay, value.ServedBytesPerDay];
    internal static bool Hash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool Unique(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Object => value.EnumerateObject().Select(p => p.Name).Distinct(StringComparer.Ordinal).Count() == value.EnumerateObject().Count()
            && value.EnumerateObject().All(p => Unique(p.Value)),
        JsonValueKind.Array => value.EnumerateArray().All(Unique),
        _ => true,
    };
}
