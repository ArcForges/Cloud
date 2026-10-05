// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;

/// <summary>The stored columns of one entitlement.snapshot row (model 01): the version, the instants and the three json columns.</summary>
internal sealed record SnapshotColumns(long Version, long ComputedAt, long? ValidUntil, string Capabilities, string Quotas, string Features);

/// <summary>
/// The mapping between a snapshot and the three json columns of <c>entitlement_snapshot</c>. The model gives <c>capabilities</c> and
/// <c>quotas</c> an object root keyed by capability and quota key, and gives <c>features</c> the rest of the resolver output (the
/// feature entries, the service state, the allowances, the definitions version and the two lists of identifiers), so the stored row is the
/// whole snapshot and a rebuild can be compared with it in full. It is written and read by hand (no reflection, Native AOT safe) in the
/// resolver's own sorted order with fixed member names; a stored value that does not read back exactly is refused rather than interpreted.
/// </summary>
internal static class SnapshotMapper
{
    public static SnapshotColumns ToColumns(EntitlementSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        var content = snapshot.Content;
        return new SnapshotColumns(
            snapshot.Version, snapshot.ComputedAt.Value, content.ValidUntil?.Value,
            Write(writer =>
            {
                writer.WriteStartObject();
                foreach (var capability in content.Capabilities)
                {
                    writer.WriteStartObject(capability.Key);
                    writer.WriteBoolean("granted", capability.Granted);
                    writer.WriteString("reason", capability.Reason.ToString());
                    Strings(writer, "sourceGrantIds", capability.SourceGrantIds);
                    writer.WriteEndObject();
                }

                writer.WriteEndObject();
            }),
            Write(writer =>
            {
                writer.WriteStartObject();
                foreach (var quota in content.Quotas)
                {
                    writer.WriteStartObject(quota.Key);
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

                writer.WriteEndObject();
            }),
            Write(writer =>
            {
                writer.WriteStartObject();
                writer.WriteStartObject("features");
                foreach (var feature in content.Features)
                {
                    writer.WriteStartObject(feature.Key);
                    writer.WriteBoolean("available", feature.Available);
                    writer.WriteString("reason", feature.Reason.ToString());
                    writer.WriteEndObject();
                }

                writer.WriteEndObject();
                writer.WriteStartObject("service");
                writer.WriteString("state", content.Service.State.ToString());
                if (content.Service.PaidThrough is { } paid) writer.WriteNumber("paidThrough", paid.Value);
                if (content.Service.GraceEndsAt is { } grace) writer.WriteNumber("graceEndsAt", grace.Value);
                writer.WriteBoolean("paidTermActive", content.Service.PaidTermActive);
                writer.WriteEndObject();
                writer.WriteStartObject("allowances");
                foreach (var allowance in content.Allowances)
                {
                    writer.WriteStartObject(allowance.Key);
                    writer.WriteBoolean("granted", allowance.Granted);
                    writer.WriteString("reason", allowance.Reason.ToString());
                    if (allowance.CapacityPlanRef is not null) writer.WriteString("capacityPlanRef", allowance.CapacityPlanRef);
                    if (allowance.SelectedGrantId is not null) writer.WriteString("selectedGrantId", allowance.SelectedGrantId);
                    Strings(writer, "supersededGrantIds", allowance.SupersededGrantIds);
                    writer.WriteEndObject();
                }

                writer.WriteEndObject();
                writer.WriteString("definitionsVersion", content.DefinitionsVersion);
                Strings(writer, "unrecognizedGrantIds", content.UnrecognizedGrantIds);
                Strings(writer, "ignoredTermIds", content.IgnoredTermIds);
                writer.WriteEndObject();
            }));
    }

    public static EntitlementSnapshot FromColumns(string workspaceId, SnapshotColumns columns)
    {
        ArgumentNullException.ThrowIfNull(columns);
        try
        {
            using var capabilities = JsonDocument.Parse(columns.Capabilities, Options);
            using var quotas = JsonDocument.Parse(columns.Quotas, Options);
            using var rest = JsonDocument.Parse(columns.Features, Options);
            var root = rest.RootElement;
            var members = root.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray();
            if (!members.SequenceEqual(["allowances", "definitionsVersion", "features", "ignoredTermIds", "service", "unrecognizedGrantIds"], StringComparer.Ordinal))
            {
                throw EntitlementRowCodec.Defect("The stored features column has unexpected members.");
            }

            var service = root.GetProperty("service");
            var content = new EntitlementContent(
                root.GetProperty("definitionsVersion").GetString()!,
                new ServiceStateResult(Enumeration<ServiceState>(service, "state"), Optional(service, "paidThrough"), Optional(service, "graceEndsAt"),
                    service.GetProperty("paidTermActive").GetBoolean()),
                [.. Entries(capabilities.RootElement).Select(entry => new CapabilityResult(
                    entry.Name, entry.Value.GetProperty("granted").GetBoolean(), Enumeration<EntitlementReason>(entry.Value, "reason"), StringList(entry.Value, "sourceGrantIds")))],
                [.. Entries(quotas.RootElement).Select(entry => new QuotaResult(
                    entry.Name, entry.Value.GetProperty("limit").GetInt64(), Enumeration<EntitlementReason>(entry.Value, "reason"),
                    [.. entry.Value.GetProperty("contributions").EnumerateArray().Select(c => new QuotaContribution(
                        c.GetProperty("grantId").GetString()!, Enumeration<GrantSource>(c, "source"), c.GetProperty("amount").GetInt64()))]))],
                [.. Entries(root.GetProperty("allowances")).Select(entry => new AllowanceResult(
                    entry.Name, entry.Value.GetProperty("granted").GetBoolean(), Enumeration<EntitlementReason>(entry.Value, "reason"),
                    entry.Value.TryGetProperty("capacityPlanRef", out var plan) ? plan.GetString() : null,
                    entry.Value.TryGetProperty("selectedGrantId", out var selected) ? selected.GetString() : null,
                    StringList(entry.Value, "supersededGrantIds")))],
                [.. Entries(root.GetProperty("features")).Select(entry => new FeatureResult(
                    entry.Name, entry.Value.GetProperty("available").GetBoolean(), Enumeration<EntitlementReason>(entry.Value, "reason")))],
                StringList(root, "unrecognizedGrantIds"),
                StringList(root, "ignoredTermIds"),
                columns.ValidUntil is { } validUntil ? new UtcMicros(validUntil) : null);
            return new EntitlementSnapshot(workspaceId, columns.Version, new UtcMicros(columns.ComputedAt), content);
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or NullReferenceException)
        {
            throw EntitlementRowCodec.Defect("The stored entitlement snapshot is malformed.");
        }
    }

    private static readonly JsonDocumentOptions Options = new() { AllowTrailingCommas = false, MaxDepth = 8 };

    /// <summary>The members of a keyed object in stored order; a repeated key is a defect (a keyed map never repeats).</summary>
    private static List<JsonProperty> Entries(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object) throw EntitlementRowCodec.Defect("A stored keyed map is not an object.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var entries = new List<JsonProperty>();
        foreach (var property in element.EnumerateObject())
        {
            if (!seen.Add(property.Name)) throw EntitlementRowCodec.Defect("A stored keyed map repeats a key.");
            entries.Add(property);
        }

        return entries;
    }

    private static string Write(Action<Utf8JsonWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer)) write(writer);
        return System.Text.Encoding.UTF8.GetString(buffer.WrittenSpan);
    }

    private static void Strings(Utf8JsonWriter writer, string name, ImmutableArray<string> values)
    {
        writer.WriteStartArray(name);
        foreach (var value in values) writer.WriteStringValue(value);
        writer.WriteEndArray();
    }

    private static UtcMicros? Optional(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) ? new UtcMicros(value.GetInt64()) : null;

    private static ImmutableArray<string> StringList(JsonElement element, string name) =>
        [.. element.GetProperty(name).EnumerateArray().Select(item => item.GetString()!)];

    private static T Enumeration<T>(JsonElement element, string name) where T : struct, Enum
    {
        var text = element.GetProperty(name).GetString();
        return Enum.TryParse<T>(text, ignoreCase: false, out var value) && Enum.IsDefined(value) && string.Equals(value.ToString(), text, StringComparison.Ordinal)
            ? value
            : throw EntitlementRowCodec.Defect("A stored " + typeof(T).Name + " value is not in the vocabulary.");
    }
}
