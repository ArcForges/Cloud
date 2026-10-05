// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using Xunit;
using static ArcForges.Cloud.Tests.Entitlement.Fixtures;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>
/// BR-06 over D1-stored records (COM.16): the COM.05 fixture accounts run through the real resolver service over the real durable store
/// (the production plans on the SQLite oracle), and a snapshot rebuilt from the records read back from D1 alone equals the snapshot read
/// back from D1, version included, however often it was evaluated in between and from a fresh service that holds nothing in memory.
/// </summary>
public sealed class D1RebuildEquivalenceTests
{
    public static TheoryData<string> AccountNames() => [.. RebuildEquivalenceTests.Accounts().Select(account => account.Name)];

    private static async Task<D1EntitlementHarness> Run(RebuildEquivalenceTests.Account account, long? tickSeconds)
    {
        var h = await D1EntitlementHarness.CreateAsync(account.SelfHost);
        long clock = 0;
        foreach (var step in account.Steps)
        {
            if (tickSeconds is { } tick)
            {
                for (var t = clock + tick; t < step.AtSeconds; t += tick)
                {
                    var before = (await h.Read()).Version;
                    var refreshed = await h.At(t).Refresh();
                    Assert.True(refreshed.Version >= before, "A snapshot version never decreases.");
                }
            }

            clock = step.AtSeconds;
            h.At(clock);
            await step.Run(h);
            await h.AssertRebuildEqual();
        }

        h.At(account.EndSeconds);
        await h.Refresh();
        return h;
    }

    [Theory]
    [MemberData(nameof(AccountNames))]
    public async Task ARebuildFromTheRecordsReadBackFromD1EqualsTheStoredSnapshot(string name)
    {
        var account = RebuildEquivalenceTests.Accounts().Single(candidate => candidate.Name == name);
        using var h = await Run(account, tickSeconds: null);
        await h.AssertRebuildEqual();
        var report = await h.Service.VerifyRebuildAsync(D1EntitlementHarness.Workspace, T.Ct);
        Assert.Equal(RebuildStatus.Equal, report.Status);
        var stored = report.Stored!;

        // An independent rebuild: the pure resolver over the records read back from D1, at the stored instant.
        var state = await h.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        Assert.True(stored.SameAs(EntitlementResolver.Resolve(state.Records, h.Definitions.Current(), stored.ComputedAt)));
        Assert.True(state.Snapshot!.SameAs(stored));

        // The stored columns read back to exactly the snapshot, and writing them again gives the same text.
        var columns = SnapshotMapper.ToColumns(stored);
        Assert.True(stored.SameAs(SnapshotMapper.FromColumns(stored.WorkspaceId, columns)));
        Assert.Equal(columns, SnapshotMapper.ToColumns(SnapshotMapper.FromColumns(stored.WorkspaceId, columns)));
        Assert.Equal(state.Records.Count, await RowCount(h));

    }

    [Theory]
    [MemberData(nameof(AccountNames))]
    public async Task AFreshServiceOverTheSameDatabaseReadsExactlyTheSameEntitlement(string name)
    {
        var account = RebuildEquivalenceTests.Accounts().Single(candidate => candidate.Name == name);
        using var h = await Run(account, tickSeconds: null);
        var written = await h.Read();

        // Nothing is held in memory: a new store and a new service over the same rows give the same answer and the same rebuild.
        var fresh = new EntitlementService(new D1EntitlementStore(h.Port), h.Definitions, new UuidIds(0x9000), h.Clock);
        var read = await fresh.ReadAsync(D1EntitlementHarness.Workspace, T.Ct);
        Assert.True(read.Succeeded, read.Detail);
        Assert.True(written.SameAs(read.Value!));
        Assert.Equal(RebuildStatus.Equal, (await fresh.VerifyRebuildAsync(D1EntitlementHarness.Workspace, T.Ct)).Status);
    }

    [Theory]
    [MemberData(nameof(AccountNames))]
    public async Task TheSnapshotIsIndependentOfHowOftenItWasEvaluatedOverD1(string name)
    {
        var account = RebuildEquivalenceTests.Accounts().Single(candidate => candidate.Name == name);
        using var rare = await Run(account, tickSeconds: null);
        using var frequent = await Run(account, tickSeconds: 3 * Day / 2);
        Assert.True((await rare.Read()).SameAs(await frequent.Read()), name);
    }

    [Fact]
    public async Task AGrantRevokedAtTheStaleVersionWritesNothingAndTheRevokedGrantEndsOverD1()
    {
        using var h = await D1EntitlementHarness.CreateAsync();
        h.At(10);
        var grant = await h.Issue(Capability("cloud.sync", 0, null, "pass1", GrantSource.CloudPass));
        await h.AddTerm(Term(D1EntitlementHarness.Uuid(0x71), 0, 60 * Day, createdSeconds: 5, kind: ServiceTermKind.Pass));
        var granted = await h.Read();
        Assert.True(Capability(granted, "cloud.sync").Granted);

        var stale = await h.Service.RevokeGrantAsync(
            new RevokeGrantRequest(D1EntitlementHarness.Workspace, grant.GrantId, "refund", null, "operator", granted.Version - 1), T.Ct);
        Assert.Equal(EntitlementError.StaleVersion, stale.Error);
        Assert.Equal(0, await h.Count("entitlement_revocation"));

        await h.Revoke(grant.GrantId, granted.Version);
        h.At(20);
        var revoked = await h.Refresh();
        Assert.False(Capability(revoked, "cloud.sync").Granted);
        Assert.True(revoked.Version > granted.Version);
        await h.AssertRebuildEqual();
    }

    private static async Task<long> RowCount(D1EntitlementHarness h)
    {
        long total = 0;
        foreach (var table in new[]
        {
            "entitlement_grant", "entitlement_revocation", "entitlement_service_term", "entitlement_service_term_action", "entitlement_workspace_status_fact",
            "entitlement_feature_release", "entitlement_definitions_activation",
        })
            total += await h.Count(table);
        return total;
    }
}
