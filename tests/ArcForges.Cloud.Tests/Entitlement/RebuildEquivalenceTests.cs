// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Infrastructure;
using Xunit;
using static ArcForges.Cloud.Tests.Entitlement.Fixtures;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>
/// BR-06, the core commerce invariant: a snapshot rebuilt from the grants, revocations and terms alone always equals the stored
/// snapshot, version included, for every fixture account and however often the snapshot was evaluated in between. The store is a
/// test-only substitute for D1; the equivalence proven here is of the resolver's logic against the store port's contract.
/// </summary>
public sealed class RebuildEquivalenceTests
{
    private sealed record Step(long AtSeconds, Func<EntitlementHarness, Task> Run);

    private sealed record Account(string Name, bool SelfHost, long EndSeconds, Step[] Steps);

    private static Step S(long at, Func<EntitlementHarness, Task> run) => new(at, run);

    private static Func<EntitlementHarness, Task> Issue(IssueGrantRequest request) => async h => await h.Issue(request);

    private static IEnumerable<Account> Accounts()
    {
        yield return new Account("empty", false, 100 * Day, []);
        yield return new Account("monthly-with-renewal-addon-and-cancel", false, 100 * Day,
        [
            S(0, Issue(Capability("cloud.sync", 0, null, "sub1-p1"))),
            S(0, Issue(Quota("cloud.storage.bytes", 50, 0, null, "base"))),
            S(0, Issue(Allowance("ai.capacity", "plan-basic", 0, null, "al1"))),
            S(0, h => h.AddTerm(Term("t1", Day, 31 * Day, graceSeconds: 38 * Day))),
            S(20 * Day, h => h.AddTerm(Term("t2", 31 * Day, 61 * Day, graceSeconds: 68 * Day, createdSeconds: 20 * Day))),
            S(24 * Day, Issue(Quota("cloud.storage.bytes", 100, 25 * Day, 50 * Day, "addon", GrantSource.StorageAddOn))),
            S(40 * Day, h => h.AddStatus(new WorkspaceStatusFact(T(40 * Day), WorkspaceStatus.Normal, AutoRenew: false, PurchasePending: false))),
        ]);
        yield return new Account("refunded-pass", false, 100 * Day,
        [
            S(0, Issue(Capability("cloud.sync", 0, null, "pass1", GrantSource.CloudPass))),
            S(0, h => h.AddTerm(Term("pass-t", 0, 60 * Day, kind: ServiceTermKind.Pass))),
            S(5 * Day, async h =>
            {
                var snapshot = await h.Read();
                await h.Revoke(Capability(snapshot, "cloud.sync").SourceGrantIds.Single(), snapshot.Version, effectiveSeconds: 0);
                await h.AddAction(new TermActionFact("pass-t", ServiceTermActionKind.Revoke, T(5 * Day), T(5 * Day)));
            }),
        ]);
        yield return new Account("grace-then-late-recovery", false, 100 * Day,
        [
            S(0, Issue(Capability("cloud.sync", 0, null, "sub1"))),
            S(0, h => h.AddTerm(Term("t1", 0, 30 * Day, graceSeconds: 37 * Day))),
            S(33 * Day, h => h.AddTerm(Term("t2", 30 * Day, 60 * Day, authorizedSeconds: 33 * Day, createdSeconds: 33 * Day))),
        ]);
        yield return new Account("late-issued-grant-with-earlier-start", false, 100 * Day,
        [
            S(0, h => h.AddTerm(Term("t1", 0, 100 * Day))),
            S(10 * Day, Issue(Capability("cloud.sync", 2 * Day, null, "late1"))),
        ]);
        yield return new Account("restricted-suspended-normal", false, 100 * Day,
        [
            S(0, Issue(Capability("cloud.sync", 0, null, "sub1"))),
            S(0, h => h.AddTerm(Term("t1", 0, 90 * Day))),
            S(10 * Day, h => h.AddStatus(new WorkspaceStatusFact(T(10 * Day), WorkspaceStatus.Restricted, true, false))),
            S(20 * Day, h => h.AddStatus(new WorkspaceStatusFact(T(20 * Day), WorkspaceStatus.Suspended, true, false))),
            S(30 * Day, h => h.AddStatus(new WorkspaceStatusFact(T(30 * Day), WorkspaceStatus.Normal, true, false))),
        ]);
        yield return new Account("feature-rollout", false, 100 * Day,
        [
            S(0, Issue(Capability("cloud.ai", 0, null, "ai1"))),
            S(0, h => h.AddTerm(Term("t1", 0, 90 * Day))),
            S(0, h => h.AddRelease(new FeatureReleaseFact("feature.ai", T(15 * Day)))),
        ]);
        yield return new Account("admin-and-compensation-grants", false, 100 * Day,
        [
            S(0, Issue(Capability("cloud.web_continuity", 0, 40 * Day, "ticket-9", GrantSource.AdminGrant, reason: "goodwill"))),
            S(0, Issue(Quota("cloud.devices.max", 4, 0, null, "mig-1", GrantSource.Migration, reason: "migration"))),
            S(0, h => h.AddTerm(Term("t1", 0, 20 * Day))),
            S(10 * Day, Issue(Capability("cloud.sync", 10 * Day, 30 * Day, "incident-3", GrantSource.Compensation, reason: "incident 3"))),
            S(15 * Day, h => h.AddTerm(Term("comp", 20 * Day, 27 * Day, kind: ServiceTermKind.Compensation, createdSeconds: 15 * Day))),
        ]);
        yield return new Account("self-host", true, 100 * Day,
        [
            S(0, Issue(Capability("cloud.sync", 0, null, "op-1", GrantSource.AdminGrant, reason: "operator funded"))),
            S(0, h => h.AddTerm(Term("sg", 0, 50 * Day, kind: ServiceTermKind.SelfHostGrant))),
        ]);
    }

    public static TheoryData<string> AccountNames()
    {
        return [.. Accounts().Select(account => account.Name)];
    }

    private static async Task<EntitlementHarness> Run(Account account, long? tickSeconds)
    {
        var h = new EntitlementHarness(account.SelfHost);
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
    public async Task RebuildingFromGrantsAndRevocationsAlwaysEqualsTheStoredSnapshot(string name)
    {
        var account = Accounts().Single(candidate => candidate.Name == name);
        var h = await Run(account, tickSeconds: null);
        await h.AssertRebuildEqual();
        var report = await h.Service.VerifyRebuildAsync(EntitlementHarness.Workspace, CancellationToken.None);
        Assert.Equal(RebuildStatus.Equal, report.Status);
        var stored = report.Stored!;

        // An independent rebuild: the pure function over the stored records only, at the stored instant.
        var again = EntitlementResolver.Resolve(h.Store.Records(EntitlementHarness.Workspace), h.Definitions.Current(), stored.ComputedAt);
        Assert.True(stored.SameAs(again));

        // The form that is actually stored reads back to exactly the same snapshot, and so does a rebuild of the read-back value.
        var json = SnapshotCodec.Serialize(stored);
        var roundTripped = SnapshotCodec.Deserialize(json);
        Assert.True(stored.SameAs(roundTripped));
        Assert.Equal(json, SnapshotCodec.Serialize(roundTripped));
    }

    [Theory]
    [MemberData(nameof(AccountNames))]
    public async Task TheSnapshotIsIndependentOfHowOftenItWasEvaluated(string name)
    {
        var account = Accounts().Single(candidate => candidate.Name == name);
        var rare = await Run(account, tickSeconds: null);
        var frequent = await Run(account, tickSeconds: 3 * Day / 2);
        var rareSnapshot = await rare.Read();
        var frequentSnapshot = await frequent.Read();
        Assert.True(rareSnapshot.SameAs(frequentSnapshot), name + ": " + rareSnapshot.Version + " vs " + frequentSnapshot.Version);
    }

    [Theory]
    [MemberData(nameof(AccountNames))]
    public async Task TheOrderOfTheInputRecordsNeverChangesTheResult(string name)
    {
        var account = Accounts().Single(candidate => candidate.Name == name);
        var h = await Run(account, tickSeconds: null);
        var records = h.Store.Records(EntitlementHarness.Workspace);
        var stored = (await h.Read());
        var reversed = records with
        {
            Grants = [.. records.Grants.Reverse()],
            Revocations = [.. records.Revocations.Reverse()],
            Terms = [.. records.Terms.Reverse()],
            TermActions = [.. records.TermActions.Reverse()],
            StatusFacts = [.. records.StatusFacts.Reverse()],
            FeatureReleases = [.. records.FeatureReleases.Reverse()],
            Activations = [.. records.Activations.Reverse()],
        };
        Assert.True(stored.SameAs(EntitlementResolver.Resolve(reversed, h.Definitions.Current(), stored.ComputedAt)));
    }

    [Fact]
    public async Task ALateGrantWithAnEarlierStartDoesNotRewriteWhatWasKnownEarlier()
    {
        var account = Accounts().Single(candidate => candidate.Name == "late-issued-grant-with-earlier-start");
        var h = await Run(account, tickSeconds: null);
        var records = h.Store.Records(EntitlementHarness.Workspace);
        var atFiveDays = EntitlementResolver.Resolve(records, h.Definitions.Current(), T(5 * Day));
        var atTwelveDays = EntitlementResolver.Resolve(records, h.Definitions.Current(), T(12 * Day));
        Assert.False(Capability(atFiveDays, "cloud.sync").Granted);
        Assert.True(Capability(atTwelveDays, "cloud.sync").Granted);
        Assert.True(atTwelveDays.Version > atFiveDays.Version);
    }

    [Fact]
    public async Task ATamperedSnapshotIsReportedAsADefectAndNeverOverwritten()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Capability("cloud.sync", 0, null, "s1"));
        await h.AddTerm(Term("t1", 0, 30 * Day));
        var snapshot = await h.At(Day).Refresh();

        var flipped = snapshot with
        {
            Content = snapshot.Content with
            {
                Capabilities = [.. snapshot.Content.Capabilities.Select(c => c.Key == "cloud.sync" ? c with { Granted = false, Reason = EntitlementReason.NoEntitlement } : c)],
            },
        };
        h.Store.ReplaceSnapshot(EntitlementHarness.Workspace, flipped);
        var report = await h.Service.VerifyRebuildAsync(EntitlementHarness.Workspace, CancellationToken.None);
        Assert.Equal(RebuildStatus.Mismatch, report.Status);
        Assert.NotEmpty(report.Differences);
        Assert.True(snapshot.SameAs(report.Rebuilt!));

        h.Store.ReplaceSnapshot(EntitlementHarness.Workspace, snapshot with { Version = snapshot.Version + 1 });
        Assert.Equal(RebuildStatus.Mismatch, (await h.Service.VerifyRebuildAsync(EntitlementHarness.Workspace, CancellationToken.None)).Status);
    }

    [Fact]
    public async Task ChangedDefinitionsAreDistinguishedFromADefectAndRefreshTheSnapshot()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Capability("cloud.sync", 0, null, "s1"));
        await h.AddTerm(Term("t1", 0, 30 * Day));
        await h.At(Day).Refresh();
        h.Definitions.Definitions = Definitions() with { Version = "bundle-2" };
        Assert.Equal(RebuildStatus.DefinitionsChanged, (await h.Service.VerifyRebuildAsync(EntitlementHarness.Workspace, CancellationToken.None)).Status);
        var refreshed = await h.Read();
        Assert.Equal("bundle-2", refreshed.Content.DefinitionsVersion);
        await h.AssertRebuildEqual();
    }

    [Fact]
    public async Task RefreshingAnUnchangedWorkspaceWritesNothing()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Capability("cloud.sync", 0, null, "s1"));
        var first = await h.Refresh();
        var commits = h.Store.CommitCount;
        var second = await h.Refresh();
        Assert.True(first.SameAs(second));
        Assert.Equal(commits, h.Store.CommitCount);
    }

    [Fact]
    public void AnEmptyHistoryResolvesToAVersionZeroSnapshotThatGrantsNothing()
    {
        var snapshot = EntitlementResolver.Resolve(EntitlementRecordSet.Empty("ws1"), Definitions(), T(1000));
        Assert.Equal(0, snapshot.Version);
        Assert.All(snapshot.Content.Capabilities, c => Assert.False(c.Granted));
        Assert.Equal(ServiceState.None, snapshot.Content.Service.State);
        Assert.Equal(ImmutableArray<string>.Empty, snapshot.Content.UnrecognizedGrantIds);
    }
}
