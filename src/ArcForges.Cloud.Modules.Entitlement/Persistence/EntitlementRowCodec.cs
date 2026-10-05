// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers;
using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;

/// <summary>
/// The exact mapping between the resolver's records and the physical columns of the entitlement tables: the JSON the commit plan
/// unpacks into rows, and the strict decoding of a loaded row. Enums use their registered numbers (listed order from 1), instants are
/// whole UTC microseconds carried as decimal text inside JSON and as exact integers in plan results, and no value goes through a
/// floating-point number.
/// </summary>
internal static class EntitlementRowCodec
{
    // ---------------------------------------------------------------------------------------------------------------------------------
    // Encoding: one JSON array per record kind, unpacked by the commit plan with json_each.
    // ---------------------------------------------------------------------------------------------------------------------------------

    public static string GrantsJson(IEnumerable<Grant> grants) => Array(grants, (writer, grant) =>
    {
        writer.WriteString("id", grant.GrantId);
        writer.WriteNumber("kind", Number(grant.Kind));
        writer.WriteString("subject", grant.Subject);
        writer.WritePropertyName("value");
        WriteValue(writer, grant.Value);
        writer.WriteNumber("source", Number(grant.Source));
        WriteOptional(writer, "sourceRef", grant.SourceRef);
        writer.WriteString("from", Micros(grant.EffectiveFrom));
        WriteOptional(writer, "until", grant.EffectiveUntil is { } until ? Micros(until) : null);
        writer.WriteString("actor", grant.IssuedByActor);
        writer.WriteString("createdAt", Micros(grant.CreatedAt));
        WriteOptional(writer, "reason", grant.Reason);
    });

    public static string RevocationsJson(IEnumerable<Revocation> revocations) => Array(revocations, (writer, revocation) =>
    {
        writer.WriteString("id", revocation.RevocationId);
        writer.WriteString("grantId", revocation.GrantId);
        writer.WriteString("reasonCode", revocation.ReasonCode);
        writer.WriteString("from", Micros(revocation.EffectiveFrom));
        writer.WriteString("actor", revocation.IssuedByActor);
        writer.WriteString("createdAt", Micros(revocation.CreatedAt));
    });

    public static string TermsJson(IEnumerable<ServiceTermRow> terms) => Array(terms, (writer, row) =>
    {
        var fact = row.Fact;
        writer.WriteString("id", fact.TermId);
        writer.WriteString("realmId", row.RealmId);
        writer.WriteNumber("kind", Number(fact.Kind));
        WriteOptional(writer, "subscriptionRef", row.SubscriptionRef);
        writer.WriteString("periodRef", row.PeriodRef);
        writer.WriteString("startsAt", Micros(fact.StartsAt));
        writer.WriteString("endsAt", Micros(fact.EndsAt));
        WriteOptional(writer, "graceEndsAt", fact.GraceEndsAt is { } grace ? Micros(grace) : null);
        WriteOptional(writer, "supersedesId", row.SupersedesId);
        writer.WriteString("offerId", row.OfferId);
        writer.WriteString("offerSnapshotId", row.OfferSnapshotId);
        writer.WriteString("authorizedAt", Micros(fact.AuthorizedAt));
        writer.WriteString("selectionPriority", row.SelectionPriority.ToString(CultureInfo.InvariantCulture));
        writer.WriteString("createdAt", Micros(fact.CreatedAt));
    });

    public static string TermActionsJson(IEnumerable<TermActionRow> actions) => Array(actions, (writer, row) =>
    {
        writer.WriteString("id", row.ActionId);
        writer.WriteString("termId", row.Fact.TermId);
        writer.WriteNumber("kind", Number(row.Fact.Kind));
        writer.WriteString("effectiveAt", Micros(row.Fact.EffectiveAt));
        writer.WriteString("recordedAt", Micros(row.Fact.RecordedAt));
        writer.WriteString("sourceRef", row.SourceRef);
        WriteOptional(writer, "replacementTermId", row.ReplacementTermId);
    });

    public static string ActivationsJson(IEnumerable<DefinitionsActivation> activations) => Array(activations, (writer, activation) =>
    {
        writer.WriteString("version", activation.Version);
        writer.WriteString("activatedAt", Micros(activation.ActivatedAt));
    });

    public static string StatusFactsJson(IEnumerable<StatusFactRow> facts) => Array(facts, (writer, row) =>
    {
        writer.WriteString("id", row.FactId);
        writer.WriteString("recordedAt", Micros(row.Fact.RecordedAt));
        writer.WriteNumber("status", Number(row.Fact.Status));
        writer.WriteNumber("autoRenew", row.Fact.AutoRenew ? 1 : 0);
        writer.WriteNumber("purchasePending", row.Fact.PurchasePending ? 1 : 0);
        writer.WriteString("sourceRef", row.SourceRef);
    });

    // ---------------------------------------------------------------------------------------------------------------------------------
    // Decoding: strict, a deviation is a defect.
    // ---------------------------------------------------------------------------------------------------------------------------------

    public static Grant ReadGrant(string workspaceId, IReadOnlyList<PlanValue> row)
    {
        Expect(row, 11);
        var kind = Enumeration<GrantKind>(row[1].AsInt64());
        return new Grant(
            row[0].AsText(), workspaceId, kind, row[2].AsText(), ReadValue(kind, row[3].AsText()), Enumeration<GrantSource>(row[4].AsInt64()),
            row[5].AsOptionalText(), new UtcMicros(row[6].AsInt64()), row[7].AsOptionalInt64() is { } until ? new UtcMicros(until) : null,
            row[8].AsText(), new UtcMicros(row[9].AsInt64()), row[10].AsOptionalText());
    }

    public static Revocation ReadRevocation(IReadOnlyList<PlanValue> row)
    {
        Expect(row, 6);
        return new Revocation(row[0].AsText(), row[1].AsText(), row[2].AsText(), new UtcMicros(row[3].AsInt64()), row[4].AsText(), new UtcMicros(row[5].AsInt64()));
    }

    public static ServiceTermFact ReadTerm(IReadOnlyList<PlanValue> row)
    {
        Expect(row, 7);
        return new ServiceTermFact(
            row[0].AsText(), Enumeration<ServiceTermKind>(row[1].AsInt64()), new UtcMicros(row[2].AsInt64()), new UtcMicros(row[3].AsInt64()),
            row[4].AsOptionalInt64() is { } grace ? new UtcMicros(grace) : null, new UtcMicros(row[5].AsInt64()), new UtcMicros(row[6].AsInt64()));
    }

    public static TermActionFact ReadTermAction(IReadOnlyList<PlanValue> row)
    {
        Expect(row, 5);
        return new TermActionFact(row[1].AsText(), Enumeration<ServiceTermActionKind>(row[2].AsInt64()), new UtcMicros(row[3].AsInt64()), new UtcMicros(row[4].AsInt64()));
    }

    public static WorkspaceStatusFact ReadStatusFact(IReadOnlyList<PlanValue> row)
    {
        Expect(row, 5);
        return new WorkspaceStatusFact(new UtcMicros(row[1].AsInt64()), Enumeration<WorkspaceStatus>(row[2].AsInt64()), Flag(row[3]), Flag(row[4]));
    }

    public static DefinitionsActivation ReadActivation(IReadOnlyList<PlanValue> row)
    {
        Expect(row, 2);
        return new DefinitionsActivation(row[0].AsText(), new UtcMicros(row[1].AsInt64()));
    }

    public static FeatureReleaseFact ReadRelease(IReadOnlyList<PlanValue> row)
    {
        Expect(row, 2);
        return new FeatureReleaseFact(row[0].AsText(), new UtcMicros(row[1].AsInt64()));
    }

    /// <summary>The registered number of an enum member: members are numbered from 1 in declaration order (the physical manifest registry).</summary>
    public static long Number<T>(T value) where T : struct, Enum => Convert.ToInt64(value, CultureInfo.InvariantCulture) + 1;

    private static T Enumeration<T>(long number) where T : struct, Enum
    {
        var raw = number - 1;
        if (raw is < 0 or > int.MaxValue) throw Defect("A stored " + typeof(T).Name + " number is not registered.");
        var value = (T)Enum.ToObject(typeof(T), (int)raw);
        return Enum.IsDefined(value) ? value : throw Defect("A stored " + typeof(T).Name + " number is not registered.");
    }

    private static bool Flag(PlanValue value) => value.AsInt64() switch
    {
        0 => false,
        1 => true,
        _ => throw Defect("A stored flag is neither 0 nor 1."),
    };

    private static void Expect(IReadOnlyList<PlanValue> row, int columns)
    {
        if (row.Count != columns) throw Defect("A plan row has " + row.Count + " columns, expected " + columns + ".");
    }

    internal static EntitlementStoreException Defect(string message) => new(EntitlementStoreFailure.Defect, message);

    private static string Micros(UtcMicros value) => value.Value.ToString(CultureInfo.InvariantCulture);

    private static void WriteOptional(Utf8JsonWriter writer, string name, string? value)
    {
        if (value is null) writer.WriteNull(name);
        else writer.WriteString(name, value);
    }

    private static void WriteValue(Utf8JsonWriter writer, GrantValue value)
    {
        writer.WriteStartObject();
        switch (value)
        {
            case CapabilityValue:
                break;
            case QuotaValue quota:
                writer.WriteNumber("limit", quota.Limit);
                writer.WriteNumber("priority", quota.Priority);
                break;
            case AllowanceValue allowance:
                writer.WriteString("capacityPlanRef", allowance.CapacityPlanRef);
                writer.WriteNumber("priority", allowance.Priority);
                break;
            default:
                throw new ArgumentException("A grant value of an unknown kind cannot be stored.", nameof(value));
        }

        writer.WriteEndObject();
    }

    private static GrantValue ReadValue(GrantKind kind, string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw Defect("A stored grant value is not an object.");
            var names = root.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray();
            switch (kind)
            {
                case GrantKind.Capability:
                    if (names.Length != 0) throw Defect("A stored capability grant value is not empty.");
                    return new CapabilityValue();
                case GrantKind.Quota:
                    if (!names.SequenceEqual(["limit", "priority"], StringComparer.Ordinal)) throw Defect("A stored quota grant value has the wrong members.");
                    return new QuotaValue(root.GetProperty("limit").GetInt64(), root.GetProperty("priority").GetInt64());
                case GrantKind.Allowance:
                    if (!names.SequenceEqual(["capacityPlanRef", "priority"], StringComparer.Ordinal)) throw Defect("A stored allowance grant value has the wrong members.");
                    return new AllowanceValue(root.GetProperty("capacityPlanRef").GetString()!, root.GetProperty("priority").GetInt64());
                default:
                    throw Defect("A stored grant has an unknown kind.");
            }
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException or KeyNotFoundException)
        {
            throw Defect("A stored grant value is malformed.");
        }
    }

    private static string Array<T>(IEnumerable<T> items, Action<Utf8JsonWriter, T> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartArray();
            foreach (var item in items)
            {
                writer.WriteStartObject();
                write(writer, item);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        }

        return System.Text.Encoding.UTF8.GetString(buffer.WrittenSpan);
    }
}
