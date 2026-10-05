// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using System.Text.Json;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using Xunit;
using static ArcForges.Cloud.Tests.Entitlement.Fixtures;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>
/// The exact mapping between the resolver's records and the physical columns (COM.16): the snapshot in its three json columns and the
/// record rows read back from plan answers. A stored value that does not read back exactly is a defect, never a guess.
/// </summary>
public sealed class PersistenceCodecTests
{
    private static string Id(int n) => D1EntitlementHarness.Uuid(n);

    private static EntitlementSnapshot Rich()
    {
        var workspace = Id(0xB1);
        var records = EntitlementRecordSet.Empty(workspace) with
        {
            Grants =
            [
                new Grant(Id(1), workspace, GrantKind.Capability, "cloud.sync", new CapabilityValue(), GrantSource.Subscription, "o1", T(0), null, "commerce", T(1)),
                new Grant(Id(2), workspace, GrantKind.Quota, "cloud.storage.bytes", new QuotaValue(100, 1), GrantSource.Subscription, "o2", T(0), null, "commerce", T(1)),
                new Grant(Id(3), workspace, GrantKind.Quota, "cloud.storage.bytes", new QuotaValue(50, 0), GrantSource.StorageAddOn, "o3", T(0), T(20 * Day), "commerce", T(1)),
                new Grant(Id(4), workspace, GrantKind.Allowance, "ai.capacity", new AllowanceValue(Id(0x44), 2), GrantSource.Subscription, "o4", T(0), null, "commerce", T(1)),
                new Grant(Id(5), workspace, GrantKind.Allowance, "ai.capacity", new AllowanceValue(Id(0x45), 1), GrantSource.Subscription, "o5", T(0), null, "commerce", T(1)),
                new Grant(Id(6), workspace, GrantKind.Capability, "unknown.capability", new CapabilityValue(), GrantSource.AdminGrant, "t6", T(0), null, "operator", T(1), "why"),
            ],
            Terms = [Term(Id(0x71), 0, 30 * Day, 33 * Day, createdSeconds: 1), Term(Id(0x72), 0, 30 * Day, kind: ServiceTermKind.SelfHostGrant, createdSeconds: 1)],
            Activations = [new DefinitionsActivation("bundle-1", T(1))],
        };
        return EntitlementResolver.Resolve(records, Definitions(), T(32 * Day));
    }

    [Fact]
    public void ASnapshotWritesToThreeJsonColumnsAndReadsBackExactly()
    {
        var snapshot = Rich();
        var columns = SnapshotMapper.ToColumns(snapshot);

        Assert.Equal(snapshot.Version, columns.Version);
        Assert.Equal(snapshot.ComputedAt.Value, columns.ComputedAt);
        Assert.Equal(snapshot.ValidUntil?.Value, columns.ValidUntil);
        using (var capabilities = JsonDocument.Parse(columns.Capabilities)) Assert.Equal(JsonValueKind.Object, capabilities.RootElement.ValueKind);
        using (var quotas = JsonDocument.Parse(columns.Quotas)) Assert.Equal(JsonValueKind.Object, quotas.RootElement.ValueKind);
        var back = SnapshotMapper.FromColumns(snapshot.WorkspaceId, columns);
        Assert.True(snapshot.SameAs(back));
        Assert.Equal(snapshot.Content.Canonical(), back.Content.Canonical());
        Assert.Equal(columns, SnapshotMapper.ToColumns(back));
        Assert.Contains(snapshot.Content.IgnoredTermIds, id => id == Id(0x72));
        Assert.Contains(Id(6), snapshot.Content.UnrecognizedGrantIds);
        Assert.NotEmpty(snapshot.Content.Allowances.Single().SupersededGrantIds);
    }

    [Fact]
    public void ASnapshotWithNoValidityAndNoPaidTermKeepsItsNulls()
    {
        var empty = EntitlementResolver.Resolve(EntitlementRecordSet.Empty(Id(0xB1)), Definitions(), T(1000));
        var columns = SnapshotMapper.ToColumns(empty);

        Assert.Null(columns.ValidUntil);
        var back = SnapshotMapper.FromColumns(Id(0xB1), columns);
        Assert.True(empty.SameAs(back));
        Assert.Null(back.ValidUntil);
    }

    public static TheoryData<string, string> Tampering() => new()
    {
        { "capabilities", "[]" },
        { "capabilities", "{\"cloud.sync\":{\"granted\":true,\"reason\":\"Maybe\",\"sourceGrantIds\":[]}}" },
        { "capabilities", "{\"cloud.sync\":{\"granted\":true,\"reason\":\"Available\",\"sourceGrantIds\":[]},\"cloud.sync\":{\"granted\":false,\"reason\":\"Available\",\"sourceGrantIds\":[]}}" },
        { "capabilities", "{\"cloud.sync\":{\"granted\":\"yes\",\"reason\":\"Available\",\"sourceGrantIds\":[]}}" },
        { "capabilities", "{\"cloud.sync\":{\"reason\":\"Available\",\"sourceGrantIds\":[]}}" },
        { "capabilities", "not json" },
        { "quotas", "{\"q\":{\"limit\":\"5\",\"reason\":\"Available\",\"contributions\":[]}}" },
        { "quotas", "{\"q\":{\"limit\":5,\"reason\":\"Available\",\"contributions\":[{\"grantId\":\"g\",\"source\":\"Nobody\",\"amount\":1}]}}" },
        { "quotas", "{\"q\":{\"limit\":5,\"reason\":\"Available\"}}" },
        { "features", "{}" },
        { "features", "{\"features\":{},\"service\":{\"state\":\"Bogus\",\"paidTermActive\":false},\"allowances\":{},\"definitionsVersion\":\"b\",\"unrecognizedGrantIds\":[],\"ignoredTermIds\":[]}" },
        { "features", "{\"features\":{},\"service\":{\"state\":\"None\",\"paidTermActive\":false},\"allowances\":{},\"definitionsVersion\":\"b\",\"unrecognizedGrantIds\":[],\"ignoredTermIds\":[],\"extra\":1}" },
        { "features", "{\"features\":[],\"service\":{\"state\":\"None\",\"paidTermActive\":false},\"allowances\":{},\"definitionsVersion\":\"b\",\"unrecognizedGrantIds\":[],\"ignoredTermIds\":[]}" },
    };

    [Theory]
    [MemberData(nameof(Tampering))]
    public void AStoredColumnThatDoesNotReadBackExactlyIsADefect(string column, string value)
    {
        var good = SnapshotMapper.ToColumns(EntitlementResolver.Resolve(EntitlementRecordSet.Empty(Id(0xB1)), Definitions(), T(1000)));
        var tampered = column switch
        {
            "capabilities" => good with { Capabilities = value },
            "quotas" => good with { Quotas = value },
            _ => good with { Features = value },
        };

        var thrown = Assert.Throws<EntitlementStoreException>(() => SnapshotMapper.FromColumns(Id(0xB1), tampered));
        Assert.Equal(EntitlementStoreFailure.Defect, thrown.Failure);
    }

    [Fact]
    public void RecordRowsReadBackTheirRegisteredNumbersAndRefuseAnythingElse()
    {
        var grant = EntitlementRowCodec.ReadGrant(Id(0xB1), Row(Text(Id(1)), Int(2), Text("cloud.storage.bytes"), Text("{\"limit\":5,\"priority\":3}"), Int(7), Text("t-1"), Int(10), PlanValue.Null, Text("operator"), Int(20), Text("goodwill")));
        Assert.Equal(GrantKind.Quota, grant.Kind);
        Assert.Equal(new QuotaValue(5, 3), grant.Value);
        Assert.Equal(GrantSource.Compensation, grant.Source);
        Assert.Equal("goodwill", grant.Reason);
        Assert.Null(grant.EffectiveUntil);

        foreach (var kind in new long[] { 0, 4, -1, long.MaxValue })
            Assert.Throws<EntitlementStoreException>(() => EntitlementRowCodec.ReadGrant(Id(0xB1), Row(Text(Id(1)), Int(kind), Text("s"), Text("{}"), Int(1), PlanValue.Null, Int(0), PlanValue.Null, Text("a"), Int(1), PlanValue.Null)));
        foreach (var source in new long[] { 0, 8 })
            Assert.Throws<EntitlementStoreException>(() => EntitlementRowCodec.ReadGrant(Id(0xB1), Row(Text(Id(1)), Int(1), Text("s"), Text("{}"), Int(source), PlanValue.Null, Int(0), PlanValue.Null, Text("a"), Int(1), PlanValue.Null)));
        foreach (var bad in new[] { "[]", "{\"limit\":5}", "{\"limit\":5,\"priority\":0,\"x\":1}", "{\"limit\":\"5\",\"priority\":0}", "nope" })
            Assert.Throws<EntitlementStoreException>(() => EntitlementRowCodec.ReadGrant(Id(0xB1), Row(Text(Id(1)), Int(2), Text("s"), Text(bad), Int(1), PlanValue.Null, Int(0), PlanValue.Null, Text("a"), Int(1), PlanValue.Null)));
        Assert.Throws<EntitlementStoreException>(() => EntitlementRowCodec.ReadGrant(Id(0xB1), Row(Text(Id(1)), Int(1), Text("s"), Text("{\"x\":1}"), Int(1), PlanValue.Null, Int(0), PlanValue.Null, Text("a"), Int(1), PlanValue.Null)));
        Assert.Throws<EntitlementStoreException>(() => EntitlementRowCodec.ReadGrant(Id(0xB1), Row(Text(Id(1)))));

        var fact = EntitlementRowCodec.ReadStatusFact(Row(Text(Id(2)), Int(5), Int(3), Int(0), Int(1)));
        Assert.Equal(new WorkspaceStatusFact(new UtcMicros(5), WorkspaceStatus.Suspended, false, true), fact);
        Assert.Throws<EntitlementStoreException>(() => EntitlementRowCodec.ReadStatusFact(Row(Text(Id(2)), Int(5), Int(3), Int(2), Int(1))));
        Assert.Throws<EntitlementStoreException>(() => EntitlementRowCodec.ReadStatusFact(Row(Text(Id(2)), Int(5), Int(4), Int(1), Int(1))));
        Assert.Equal(new TermActionFact(Id(3), ServiceTermActionKind.Revoke, new UtcMicros(9), new UtcMicros(8)), EntitlementRowCodec.ReadTermAction(Row(Text(Id(4)), Text(Id(3)), Int(2), Int(9), Int(8))));
        Assert.Throws<EntitlementStoreException>(() => EntitlementRowCodec.ReadTerm(Row(Text(Id(3)), Int(9), Int(1), Int(2), PlanValue.Null, Int(1), Int(1))));
    }

    [Fact]
    public void TheJsonOfARecordKindIsExactAndKeepsEveryRecordColumn()
    {
        var grant = new Grant(Id(1), Id(0xB1), GrantKind.Allowance, "ai.capacity", new AllowanceValue(Id(0x44), 9), GrantSource.Migration, "ref-1", T(1), T(2), "operator", T(3), "moved");
        using var document = JsonDocument.Parse(EntitlementRowCodec.GrantsJson([grant]));
        var item = document.RootElement.EnumerateArray().Single();

        Assert.Equal(3, item.GetProperty("kind").GetInt64());
        Assert.Equal(6, item.GetProperty("source").GetInt64());
        Assert.Equal("1000000", item.GetProperty("from").GetString());
        Assert.Equal("2000000", item.GetProperty("until").GetString());
        Assert.Equal("moved", item.GetProperty("reason").GetString());
        Assert.Equal(Id(0x44), item.GetProperty("value").GetProperty("capacityPlanRef").GetString());
        Assert.Equal(9, item.GetProperty("value").GetProperty("priority").GetInt64());
        using var none = JsonDocument.Parse(EntitlementRowCodec.GrantsJson([grant with { EffectiveUntil = null, Reason = null, SourceRef = null }]));
        Assert.Equal(JsonValueKind.Null, none.RootElement[0].GetProperty("until").ValueKind);
        Assert.Equal(JsonValueKind.Null, none.RootElement[0].GetProperty("reason").ValueKind);
        Assert.Equal("[]", EntitlementRowCodec.RevocationsJson([]));
        Assert.Equal("[]", EntitlementRowCodec.ActivationsJson([]));
    }

    private static PlanValue Text(string value) => PlanValue.FromText(value);

    private static PlanValue Int(long value) => PlanValue.FromInt64(value);

    private static IReadOnlyList<PlanValue> Row(params PlanValue[] values) => values;

    [Fact]
    public void TheResolverStillRefusesARecordSetBeyondItsBound()
    {
        var workspace = Id(0xB1);
        var grants = Enumerable.Range(0, InputRulesBound() + 1)
            .Select(i => new Grant(Id(0x4000 + i), workspace, GrantKind.Capability, "cloud.sync", new CapabilityValue(), GrantSource.Subscription, "r" + i, T(0), null, "commerce", T(1)))
            .ToImmutableArray();

        Assert.Throws<ResolverInputException>(() => EntitlementResolver.Resolve(EntitlementRecordSet.Empty(workspace) with { Grants = grants }, Definitions(), T(10)));
    }

    private static int InputRulesBound() => InputRules.MaxRecords;
}
