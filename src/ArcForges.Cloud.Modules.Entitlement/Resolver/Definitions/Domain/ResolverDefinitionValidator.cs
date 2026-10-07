// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Domain;

internal sealed class ResolverDefinitionValidator : IResolverDefinitionValidator
{
    public const string ProfileName = "entitlement.resolver-definitions.v1";
    public const int MaximumBytes = 65536;
    public const int MaximumDescriptors = 64;
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public ResolverDefinitionValidationResult Validate(ReadOnlyMemory<byte> canonicalBytes, string definitionsVersion, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (canonicalBytes.Length is < 2 or > MaximumBytes || !InputRules.IsOpaqueReference(definitionsVersion)) return Invalid();
        var captured = canonicalBytes.ToArray();
        try
        {
            _ = Utf8.GetCharCount(captured);
            using var document = JsonDocument.Parse(captured, new() { MaxDepth = 4 });
            var root = document.RootElement;
            if (!Members(root, "allowances", "capabilities", "definitionsVersion", "quotas", "schemaVersion")
                || Text(root, "schemaVersion") != ProfileName || Text(root, "definitionsVersion") != definitionsVersion
                || !Array(root, "allowances", out var allowances) || !Array(root, "capabilities", out var capabilities)
                || !Array(root, "quotas", out var quotas)) return Invalid();
            var capabilityDefinitions = new List<ResolverCapabilityDefinition>();
            foreach (var entry in capabilities.EnumerateArray())
            {
                if (!Members(entry, "featureGate", "key", "requiresPaidTerm") || !InputRules.IsKey(Text(entry, "key"))
                    || !entry.TryGetProperty("featureGate", out var gate)
                    || (gate.ValueKind != JsonValueKind.Null && (gate.ValueKind != JsonValueKind.String || !InputRules.IsKey(gate.GetString())))
                    || !entry.TryGetProperty("requiresPaidTerm", out var paid) || paid.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return Invalid();
                capabilityDefinitions.Add(new(Text(entry, "key")!, paid.GetBoolean(), gate.ValueKind == JsonValueKind.Null ? null : gate.GetString()));
            }
            var quotaDefinitions = new List<ResolverQuotaDefinition>();
            foreach (var entry in quotas.EnumerateArray())
            {
                if (!Members(entry, "combination", "key") || !InputRules.IsKey(Text(entry, "key"))
                    || !Enum.TryParse<ResolverDefinitionCombination>(Text(entry, "combination"), false, out var combination)
                    || !Enum.IsDefined(combination) || combination.ToString() != Text(entry, "combination")) return Invalid();
                quotaDefinitions.Add(new(Text(entry, "key")!, combination));
            }
            var allowanceDefinitions = new List<ResolverAllowanceDefinition>();
            foreach (var entry in allowances.EnumerateArray())
            {
                if (!Members(entry, "key") || !InputRules.IsKey(Text(entry, "key"))) return Invalid();
                allowanceDefinitions.Add(new(Text(entry, "key")!));
            }
            if (!SortedUnique(capabilityDefinitions.Select(d => d.Key)) || !SortedUnique(quotaDefinitions.Select(d => d.Key))
                || !SortedUnique(allowanceDefinitions.Select(d => d.Key))) return Invalid();
            var canonical = Encode(definitionsVersion, capabilityDefinitions, quotaDefinitions, allowanceDefinitions);
            if (!captured.AsSpan().SequenceEqual(canonical)) return Invalid();
            cancellationToken.ThrowIfCancellationRequested();
            return new(ResolverDefinitionStatus.Succeeded, new(definitionsVersion, Convert.ToHexStringLower(SHA256.HashData(canonical)),
                canonical, capabilityDefinitions, quotaDefinitions, allowanceDefinitions));
        }
        catch (Exception error) when (error is JsonException or DecoderFallbackException or ArgumentException or InvalidOperationException)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Invalid();
        }
        finally { CryptographicOperations.ZeroMemory(captured); }
    }

    internal static byte[] Encode(string version, IEnumerable<ResolverCapabilityDefinition> capabilities,
        IEnumerable<ResolverQuotaDefinition> quotas, IEnumerable<ResolverAllowanceDefinition> allowances)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteStartArray("allowances");
            foreach (var entry in allowances)
            {
                writer.WriteStartObject(); writer.WriteString("key", entry.Key); writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteStartArray("capabilities");
            foreach (var entry in capabilities)
            {
                writer.WriteStartObject(); writer.WriteString("featureGate", entry.FeatureGate); writer.WriteString("key", entry.Key);
                writer.WriteBoolean("requiresPaidTerm", entry.RequiresPaidTerm); writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteString("definitionsVersion", version);
            writer.WriteStartArray("quotas");
            foreach (var entry in quotas)
            {
                writer.WriteStartObject(); writer.WriteString("combination", entry.Combination.ToString()); writer.WriteString("key", entry.Key); writer.WriteEndObject();
            }
            writer.WriteEndArray();
            writer.WriteString("schemaVersion", ProfileName);
            writer.WriteEndObject();
        }
        return buffer.WrittenSpan.ToArray();
    }

    internal static EntitlementDefinitions ToDefinitions(ResolverDefinitionProfile profile, string realmKind)
        => new(profile.DefinitionsVersion,
            profile.Capabilities.Select(d => new CapabilityDefinition(d.Key, d.RequiresPaidTerm, d.FeatureGate)).ToImmutableArray(),
            profile.Quotas.Select(d => new QuotaDefinition(d.Key, d.Combination switch
            {
                ResolverDefinitionCombination.Sum => QuotaCombination.Sum,
                ResolverDefinitionCombination.Max => QuotaCombination.Max,
                ResolverDefinitionCombination.PriorityReplace => QuotaCombination.PriorityReplace,
                _ => throw new ResolverInputException("The definition combination is invalid."),
            })).ToImmutableArray(), profile.Allowances.Select(d => new AllowanceDefinition(d.Key)).ToImmutableArray(), realmKind switch
            {
                "official" => false,
                "selfHosted" => true,
                _ => throw new ResolverInputException("The definition realm kind is invalid."),
            });

    private static bool Array(JsonElement root, string name, out JsonElement value)
        => root.TryGetProperty(name, out value) && value.ValueKind == JsonValueKind.Array && value.GetArrayLength() <= MaximumDescriptors;
    private static bool SortedUnique(IEnumerable<string> keys)
    {
        string? previous = null;
        foreach (var key in keys) { if (previous is not null && StringComparer.Ordinal.Compare(previous, key) >= 0) return false; previous = key; }
        return true;
    }
    private static bool Members(JsonElement value, params string[] names)
        => value.ValueKind == JsonValueKind.Object && value.EnumerateObject().Select(p => p.Name).Order(StringComparer.Ordinal).SequenceEqual(names, StringComparer.Ordinal);
    private static string? Text(JsonElement value, string name)
        => value.TryGetProperty(name, out var item) && item.ValueKind == JsonValueKind.String ? item.GetString() : null;
    private static ResolverDefinitionValidationResult Invalid() => new(ResolverDefinitionStatus.Invalid);
}
