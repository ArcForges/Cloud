// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Infrastructure;

/// <summary>
/// The canonical JSON form of a stored snapshot. It is written and read by hand (no reflection, Native AOT safe) with a fixed field
/// order, so the same snapshot always produces the same bytes, and a stored value that does not read back to exactly the snapshot it
/// was written from is refused rather than interpreted.
/// </summary>
internal static class SnapshotCodec
{
    public static string Serialize(EntitlementSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            var content = snapshot.Content;
            writer.WriteStartObject();
            writer.WriteString("workspaceId", snapshot.WorkspaceId);
            writer.WriteNumber("version", snapshot.Version);
            writer.WriteNumber("computedAt", snapshot.ComputedAt.Value);
            writer.WriteString("definitionsVersion", content.DefinitionsVersion);
            writer.WriteStartObject("service");
            writer.WriteString("state", content.Service.State.ToString());
            WriteOptional(writer, "paidThrough", content.Service.PaidThrough);
            WriteOptional(writer, "graceEndsAt", content.Service.GraceEndsAt);
            writer.WriteBoolean("paidTermActive", content.Service.PaidTermActive);
            writer.WriteEndObject();
            writer.WriteStartArray("capabilities");
            foreach (var capability in content.Capabilities)
            {
                writer.WriteStartObject();
                writer.WriteString("key", capability.Key);
                writer.WriteBoolean("granted", capability.Granted);
                writer.WriteString("reason", capability.Reason.ToString());
                WriteStrings(writer, "sourceGrantIds", capability.SourceGrantIds);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteStartArray("quotas");
            foreach (var quota in content.Quotas)
            {
                writer.WriteStartObject();
                writer.WriteString("key", quota.Key);
                writer.WriteNumber("limit", quota.Limit);
                writer.WriteString("reason", quota.Reason.ToString());
                writer.WriteStartArray("contributions");
                foreach (var contribution in quota.Contributions)
                {
                    writer.WriteStartObject();
                    writer.WriteString("grantId", contribution.GrantId);
                    writer.WriteString("source", contribution.Source.ToString());
                    writer.WriteNumber("amount", contribution.Amount);
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteStartArray("allowances");
            foreach (var allowance in content.Allowances)
            {
                writer.WriteStartObject();
                writer.WriteString("key", allowance.Key);
                writer.WriteBoolean("granted", allowance.Granted);
                writer.WriteString("reason", allowance.Reason.ToString());
                if (allowance.CapacityPlanRef is not null) writer.WriteString("capacityPlanRef", allowance.CapacityPlanRef);
                if (allowance.SelectedGrantId is not null) writer.WriteString("selectedGrantId", allowance.SelectedGrantId);
                WriteStrings(writer, "supersededGrantIds", allowance.SupersededGrantIds);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteStartArray("features");
            foreach (var feature in content.Features)
            {
                writer.WriteStartObject();
                writer.WriteString("key", feature.Key);
                writer.WriteBoolean("available", feature.Available);
                writer.WriteString("reason", feature.Reason.ToString());
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            WriteStrings(writer, "unrecognizedGrantIds", content.UnrecognizedGrantIds);
            WriteStrings(writer, "ignoredTermIds", content.IgnoredTermIds);
            WriteOptional(writer, "validUntil", content.ValidUntil);
            writer.WriteEndObject();
        }

        return System.Text.Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    /// <summary>Reads a stored snapshot. Any shape, enum or type deviation throws <see cref="FormatException"/>: a stored value is never half-trusted.</summary>
    public static EntitlementSnapshot Deserialize(string json)
    {
        ArgumentNullException.ThrowIfNull(json);
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { AllowTrailingCommas = false, MaxDepth = 8 });
            var root = document.RootElement;
            var service = root.GetProperty("service");
            var content = new EntitlementContent(
                root.GetProperty("definitionsVersion").GetString()!,
                new ServiceStateResult(Parse<ServiceState>(service, "state"), Optional(service, "paidThrough"), Optional(service, "graceEndsAt"),
                    service.GetProperty("paidTermActive").GetBoolean()),
                [.. root.GetProperty("capabilities").EnumerateArray().Select(item => new CapabilityResult(
                    item.GetProperty("key").GetString()!, item.GetProperty("granted").GetBoolean(), Parse<EntitlementReason>(item, "reason"),
                    Strings(item, "sourceGrantIds")))],
                [.. root.GetProperty("quotas").EnumerateArray().Select(item => new QuotaResult(
                    item.GetProperty("key").GetString()!, item.GetProperty("limit").GetInt64(), Parse<EntitlementReason>(item, "reason"),
                    [.. item.GetProperty("contributions").EnumerateArray().Select(c => new QuotaContribution(
                        c.GetProperty("grantId").GetString()!, Parse<GrantSource>(c, "source"), c.GetProperty("amount").GetInt64()))]))],
                [.. root.GetProperty("allowances").EnumerateArray().Select(item => new AllowanceResult(
                    item.GetProperty("key").GetString()!, item.GetProperty("granted").GetBoolean(), Parse<EntitlementReason>(item, "reason"),
                    item.TryGetProperty("capacityPlanRef", out var plan) ? plan.GetString() : null,
                    item.TryGetProperty("selectedGrantId", out var selected) ? selected.GetString() : null,
                    Strings(item, "supersededGrantIds")))],
                [.. root.GetProperty("features").EnumerateArray().Select(item => new FeatureResult(
                    item.GetProperty("key").GetString()!, item.GetProperty("available").GetBoolean(), Parse<EntitlementReason>(item, "reason")))],
                Strings(root, "unrecognizedGrantIds"),
                Strings(root, "ignoredTermIds"),
                Optional(root, "validUntil"));
            return new EntitlementSnapshot(root.GetProperty("workspaceId").GetString()!, root.GetProperty("version").GetInt64(),
                new UtcMicros(root.GetProperty("computedAt").GetInt64()), content);
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or NullReferenceException)
        {
            throw new FormatException("The stored entitlement snapshot is malformed.", exception);
        }
    }

    private static void WriteOptional(Utf8JsonWriter writer, string name, UtcMicros? value)
    {
        if (value is { } micros) writer.WriteNumber(name, micros.Value);
    }

    private static void WriteStrings(Utf8JsonWriter writer, string name, ImmutableArray<string> values)
    {
        writer.WriteStartArray(name);
        foreach (var value in values) writer.WriteStringValue(value);
        writer.WriteEndArray();
    }

    private static UtcMicros? Optional(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) ? new UtcMicros(value.GetInt64()) : null;

    private static ImmutableArray<string> Strings(JsonElement element, string name) =>
        [.. element.GetProperty(name).EnumerateArray().Select(item => item.GetString()!)];

    private static T Parse<T>(JsonElement element, string name) where T : struct, Enum =>
        Enum.TryParse<T>(element.GetProperty(name).GetString(), ignoreCase: false, out var value) && Enum.IsDefined(value)
            && string.Equals(value.ToString(), element.GetProperty(name).GetString(), StringComparison.Ordinal)
            ? value
            : throw new FormatException("Unknown " + typeof(T).Name + " value.");
}
