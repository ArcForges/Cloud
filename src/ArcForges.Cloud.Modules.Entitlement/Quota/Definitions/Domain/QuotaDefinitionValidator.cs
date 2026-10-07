// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;

internal sealed class QuotaDefinitionValidator : IQuotaDefinitionValidator
{
    public const string ProfileName = "entitlement.quota-definitions.v1";
    public const int MaximumBytes = 65536;
    public const int MaximumDefinitions = 64;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public QuotaDefinitionValidationResult Validate(ReadOnlyMemory<byte> canonicalBytes, string definitionsVersion,
        IReadOnlyList<QuotaResolverDefinition> resolverDefinitions, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (canonicalBytes.Length is < 2 or > MaximumBytes || !Version(definitionsVersion)
            || resolverDefinitions is null || resolverDefinitions.Count > MaximumDefinitions) return Invalid();
        var captured = canonicalBytes.ToArray();
        var expected = resolverDefinitions.ToArray();
        try
        {
            if (expected.Any(d => d is null || !InputRules.IsKey(d.Key) || !Enum.IsDefined(d.Combination))
                || expected.Select(d => d.Key).Distinct(StringComparer.Ordinal).Count() != expected.Length) return Invalid();
            _ = Utf8.GetCharCount(captured);
            using var document = JsonDocument.Parse(captured, new() { MaxDepth = 4 });
            var root = document.RootElement;
            if (!Members(root, "definitions", "definitionsVersion", "schemaVersion")
                || Text(root, "schemaVersion") != ProfileName || Text(root, "definitionsVersion") != definitionsVersion
                || !root.TryGetProperty("definitions", out var entries) || entries.ValueKind != JsonValueKind.Array
                || entries.GetArrayLength() != expected.Length) return Invalid();
            var result = new List<QuotaSemanticDefinition>(expected.Length);
            foreach (var entry in entries.EnumerateArray())
            {
                if (!Members(entry, "combination", "key", "mode", "unit") || !InputRules.IsKey(Text(entry, "key"))) return Invalid();
                var key = Text(entry, "key")!;
                if (!Enumeration<QuotaDefinitionCombination>(Text(entry, "combination"), out var combination)
                    || !Enumeration<QuotaDefinitionMode>(Text(entry, "mode"), out var mode)
                    || !Unit(Text(entry, "unit"), out var unit)) return Invalid();
                result.Add(new(key, combination, unit, mode));
            }
            if (!result.Select(d => d.Key).SequenceEqual(expected.Select(d => d.Key).Order(StringComparer.Ordinal), StringComparer.Ordinal)
                || result.Any(d => expected.Single(e => e.Key == d.Key).Combination != d.Combination)) return Invalid();
            var canonical = Encode(definitionsVersion, result);
            if (!captured.AsSpan().SequenceEqual(canonical)) return Invalid();
            cancellationToken.ThrowIfCancellationRequested();
            return new(QuotaDefinitionStatus.Succeeded, new(definitionsVersion,
                Convert.ToHexStringLower(SHA256.HashData(canonical)), canonical, result));
        }
        catch (Exception error) when (error is JsonException or DecoderFallbackException or ArgumentException or InvalidOperationException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Invalid();
        }
        finally { CryptographicOperations.ZeroMemory(captured); }
    }

    internal static byte[] Encode(string version, IEnumerable<QuotaSemanticDefinition> definitions)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteStartArray("definitions");
            foreach (var definition in definitions)
            {
                writer.WriteStartObject();
                writer.WriteString("combination", definition.Combination.ToString());
                writer.WriteString("key", definition.Key);
                writer.WriteString("mode", definition.Mode.ToString());
                writer.WriteString("unit", UnitName(definition.Unit));
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteString("definitionsVersion", version);
            writer.WriteString("schemaVersion", ProfileName);
            writer.WriteEndObject();
        }
        return buffer.WrittenSpan.ToArray();
    }

    internal static bool Version(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Any(char.IsControl)) return false;
        try { return Utf8.GetByteCount(value) <= 128; }
        catch (EncoderFallbackException) { return false; }
    }
    internal static string UnitName(QuotaDefinitionUnit value) => value switch
    {
        QuotaDefinitionUnit.Bytes => "bytes", QuotaDefinitionUnit.Microseconds => "microseconds",
        QuotaDefinitionUnit.Samples => "samples", QuotaDefinitionUnit.Count => "count",
        _ => throw new ArgumentOutOfRangeException(nameof(value)),
    };
    private static bool Unit(string? value, out QuotaDefinitionUnit unit)
    {
        unit = value switch { "bytes" => QuotaDefinitionUnit.Bytes, "microseconds" => QuotaDefinitionUnit.Microseconds,
            "samples" => QuotaDefinitionUnit.Samples, "count" => QuotaDefinitionUnit.Count, _ => (QuotaDefinitionUnit)(-1) };
        return Enum.IsDefined(unit);
    }
    private static bool Enumeration<T>(string? value, out T result) where T : struct, Enum
        => Enum.TryParse(value, false, out result) && Enum.IsDefined(result) && result.ToString() == value;
    private static string? Text(JsonElement value, string name)
        => value.TryGetProperty(name, out var item) && item.ValueKind == JsonValueKind.String ? item.GetString() : null;
    private static bool Members(JsonElement value, params string[] names)
        => value.ValueKind == JsonValueKind.Object && value.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal)
            .SequenceEqual(names, StringComparer.Ordinal);
    private static QuotaDefinitionValidationResult Invalid() => new(QuotaDefinitionStatus.Invalid);
}
