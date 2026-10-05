// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using Xunit;
using static ArcForges.Cloud.Tests.Entitlement.Fixtures;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>The grant interface (EO-03): admission, idempotency, stale-decision refusal, atomic commit with the snapshot, and fail-closed history.</summary>
public sealed class GrantInterfaceTests
{
    private static Dictionary<string, IssueGrantRequest> RefusalCases()
    {
        var good = Capability("cloud.sync", 0, null, "sub1");
        return new Dictionary<string, IssueGrantRequest>
        {
            ["malformed workspace"] = good with { WorkspaceId = "bad id" },
            ["undefined kind"] = good with { Kind = (GrantKind)7 },
            ["undefined source"] = good with { Source = (GrantSource)42 },
            ["malformed subject"] = good with { Subject = "Cloud Sync" },
            ["no source reference"] = good with { SourceRef = null },
            ["provider-payload-shaped reference"] = good with { SourceRef = "https://pay.example/evt?id=1" },
            ["capability with a quota value"] = good with { Value = new QuotaValue(5) },
            ["negative quota"] = Quota("cloud.storage.bytes", -1, 0, null, "q1"),
            ["quota above the bound"] = Quota("cloud.storage.bytes", InputRules.MaxQuotaLimit + 1, 0, null, "q1"),
            ["negative priority"] = Quota("support.level", 1, 0, null, "q1", priority: -1),
            ["allowance with a malformed plan"] = Allowance("ai.capacity", "plan one", 0, null, "a1"),
            ["ends before it starts"] = Capability("cloud.sync", 10, 5, "e1"),
            ["ends when it starts"] = Capability("cloud.sync", 10, 10, "e2"),
            ["no issuing actor"] = good with { IssuedByActor = " " },
            ["admin grant without reason"] = Capability("cloud.sync", 0, null, "t1", GrantSource.AdminGrant),
            ["compensation without reason"] = Capability("cloud.sync", 0, null, "t2", GrantSource.Compensation),
            ["migration without reason"] = Capability("cloud.sync", 0, null, "t3", GrantSource.Migration),
        };
    }

    public static TheoryData<string> RefusalNames() => [.. RefusalCases().Keys];

    [Theory]
    [MemberData(nameof(RefusalNames))]
    public async Task AnInadmissibleGrantIsRefusedWithATypedReasonAndWritesNothing(string why)
    {
        var request = RefusalCases()[why];
        var h = new EntitlementHarness().At(0);
        var result = await h.Service.IssueGrantAsync(request, CancellationToken.None);
        Assert.False(result.Succeeded, why);
        Assert.Equal(EntitlementError.InvalidRequest, result.Error);
        Assert.False(string.IsNullOrWhiteSpace(result.Detail));
        Assert.Equal(0, h.Store.CommitCount);
        Assert.Empty(h.Store.Records(EntitlementHarness.Workspace).Grants);
    }

    [Fact]
    public async Task AReplayedIssueWithTheSameSourceReferenceCreatesNothingTwice()
    {
        var h = new EntitlementHarness().At(0);
        var request = Capability("cloud.sync", 0, null, "order-1-period-1");
        var first = await h.Issue(request);
        var commits = h.Store.CommitCount;
        var replay = await h.Service.IssueGrantAsync(request, CancellationToken.None);
        Assert.True(replay.Succeeded);
        Assert.True(replay.Duplicate);
        Assert.Equal(first.GrantId, replay.Value!.GrantId);
        Assert.Equal(commits, h.Store.CommitCount);
        Assert.Single(h.Store.Records(EntitlementHarness.Workspace).Grants);
    }

    [Fact]
    public async Task ReusingASourceReferenceForADifferentGrantIsAConflict()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Capability("cloud.sync", 0, null, "order-1"));
        var result = await h.Service.IssueGrantAsync(Capability("cloud.web_continuity", 0, null, "order-1"), CancellationToken.None);
        Assert.Equal(EntitlementError.Conflict, result.Error);
        Assert.Single(h.Store.Records(EntitlementHarness.Workspace).Grants);
    }

    [Fact]
    public async Task AGrantAndTheSnapshotThatReflectsItCommitTogether()
    {
        var h = new EntitlementHarness().At(0);
        await h.AddTerm(Term("t1", 0, 30 * Day));
        var grant = await h.Issue(Capability("cloud.sync", 0, null, "sub1"));
        var snapshot = await h.Read();
        Assert.Equal([grant.GrantId], Capability(snapshot, "cloud.sync").SourceGrantIds);
        await h.AssertRebuildEqual();
    }

    [Fact]
    public async Task ARevocationDecidedAgainstAStaleVersionIsRefused()
    {
        var h = new EntitlementHarness().At(0);
        var grant = await h.Issue(Capability("cloud.sync", 0, null, "sub1"));
        await h.AddTerm(Term("t1", 0, 30 * Day));
        var current = await h.Read();
        var stale = await h.Service.RevokeGrantAsync(
            new RevokeGrantRequest(EntitlementHarness.Workspace, grant.GrantId, "refund", null, "operator", current.Version - 1), CancellationToken.None);
        Assert.Equal(EntitlementError.StaleVersion, stale.Error);
        Assert.Empty(h.Store.Records(EntitlementHarness.Workspace).Revocations);
    }

    [Fact]
    public async Task ARevocationNamesAnExactGrantInItsOwnWorkspace()
    {
        var h = new EntitlementHarness().At(0);
        var result = await h.Service.RevokeGrantAsync(
            new RevokeGrantRequest(EntitlementHarness.Workspace, "nope", "refund", null, "operator", 0), CancellationToken.None);
        Assert.Equal(EntitlementError.UnknownGrant, result.Error);
        var other = await h.Service.RevokeGrantAsync(
            new RevokeGrantRequest("another-workspace", "nope", "refund", null, "operator", 0), CancellationToken.None);
        Assert.Equal(EntitlementError.UnknownGrant, other.Error);
        var malformed = await h.Service.RevokeGrantAsync(
            new RevokeGrantRequest(EntitlementHarness.Workspace, "g", "Not A Code", null, "operator", 0), CancellationToken.None);
        Assert.Equal(EntitlementError.InvalidRequest, malformed.Error);
    }

    [Fact]
    public async Task AReplayedRevocationWritesNothing()
    {
        var h = new EntitlementHarness().At(0);
        var grant = await h.Issue(Capability("cloud.sync", 0, null, "sub1"));
        var version = (await h.Read()).Version;
        var first = await h.Revoke(grant.GrantId, version, effectiveSeconds: 0);
        var commits = h.Store.CommitCount;
        var newVersion = (await h.Read()).Version;
        var replay = await h.Service.RevokeGrantAsync(
            new RevokeGrantRequest(EntitlementHarness.Workspace, grant.GrantId, "refund", Fixtures.T(0), "operator", newVersion), CancellationToken.None);
        Assert.True(replay.Duplicate);
        Assert.Equal(first.RevocationId, replay.Value!.RevocationId);
        Assert.Equal(commits, h.Store.CommitCount);
    }

    [Fact]
    public async Task ARevokedGrantIsNeverDeletedOrEdited()
    {
        var h = new EntitlementHarness().At(0);
        var grant = await h.Issue(Capability("cloud.sync", 0, null, "sub1"));
        var version = (await h.Read()).Version;
        await h.Revoke(grant.GrantId, version, effectiveSeconds: 0);
        var stored = h.Store.Records(EntitlementHarness.Workspace);
        Assert.Equal(grant, stored.Grants.Single());
        Assert.Single(stored.Revocations);
    }

    [Fact]
    public async Task ConcurrentIssuersNeverLoseAGrantOrLeaveAStaleSnapshot()
    {
        var h = new EntitlementHarness().At(0);
        await h.AddTerm(Term("t1", 0, 30 * Day));
        var requests = Enumerable.Range(0, 3).Select(i => Capability("cloud.sync", 0, null, "ref" + i)).ToArray();
        var results = await Task.WhenAll(requests.Select(request => h.Service.IssueGrantAsync(request, CancellationToken.None).AsTask()));
        Assert.All(results, result => Assert.True(result.Succeeded, result.Detail));
        Assert.Equal(3, h.Store.Records(EntitlementHarness.Workspace).Grants.Length);
        Assert.Equal(3, Capability(await h.Read(), "cloud.sync").SourceGrantIds.Length);
        await h.AssertRebuildEqual();
    }

    [Fact]
    public async Task AWriterThatLosesTheRaceRederivesItsSnapshotFromTheNewHistory()
    {
        var h = new EntitlementHarness().At(0);
        await h.AddTerm(Term("t1", 0, 30 * Day));
        var interleaved = false;
        h.Store.BeforeNextCommit = async () =>
        {
            if (interleaved) return;
            interleaved = true;
            await h.Service.IssueGrantAsync(Capability("cloud.web_continuity", 0, null, "other"), CancellationToken.None);
        };
        var mine = await h.Issue(Capability("cloud.sync", 0, null, "mine"));
        var snapshot = await h.Read();
        Assert.Equal([mine.GrantId], Capability(snapshot, "cloud.sync").SourceGrantIds);
        Assert.True(Capability(snapshot, "cloud.web_continuity").Granted);
        await h.AssertRebuildEqual();
    }

    [Fact]
    public async Task AWriterThatNeverWinsTheRaceFailsClosedWithATypedError()
    {
        var h = new EntitlementHarness().At(0);
        var bump = 0;
        var store = h.Store;
        string Next() => "bump" + bump++;
        async Task Interfere()
        {
            await h.Service.IssueGrantAsync(Capability("cloud.web_continuity", 0, null, Next()), CancellationToken.None);
            store.BeforeNextCommit = Interfere;
        }

        store.BeforeNextCommit = Interfere;
        var result = await h.Service.IssueGrantAsync(Capability("cloud.sync", 0, null, "mine"), CancellationToken.None);
        Assert.Equal(EntitlementError.ConcurrentUpdate, result.Error);
        Assert.DoesNotContain(store.Records(EntitlementHarness.Workspace).Grants, grant => grant.SourceRef == "mine");
    }

    public static TheoryData<string> BrokenHistories() =>
        ["duplicate-grant-id", "foreign-workspace-grant", "orphan-revocation", "revocation-before-grant", "term-ends-before-start", "action-without-term", "too-many-records"];

    [Theory]
    [MemberData(nameof(BrokenHistories))]
    public async Task AHistoryTheResolverCannotInterpretYieldsNoSnapshotAndNoWrite(string kind)
    {
        var h = new EntitlementHarness().At(10);
        var grant = (await h.Issue(Capability("cloud.sync", 0, null, "sub1")));
        var commits = h.Store.CommitCount;
        h.Store.Insert(EntitlementHarness.Workspace, records => kind switch
        {
            "duplicate-grant-id" => records with { Grants = records.Grants.Add(grant) },
            "foreign-workspace-grant" => records with { Grants = records.Grants.Add(grant with { GrantId = "g2", WorkspaceId = "other", SourceRef = "x" }) },
            "orphan-revocation" => records with { Revocations = records.Revocations.Add(new Revocation("r1", "missing", "refund", T(0), "op", T(1))) },
            "revocation-before-grant" => records with { Revocations = records.Revocations.Add(new Revocation("r1", grant.GrantId, "refund", T(0), "op", T(-5))) },
            "term-ends-before-start" => records with { Terms = records.Terms.Add(new ServiceTermFact("t9", ServiceTermKind.Subscription, T(10), T(5), null, T(10), T(0))) },
            "action-without-term" => records with { TermActions = records.TermActions.Add(new TermActionFact("none", ServiceTermActionKind.Revoke, T(1), T(1))) },
            _ => records with
            {
                StatusFacts = [.. Enumerable.Range(0, InputRules.MaxRecords).Select(i => new WorkspaceStatusFact(T(i), WorkspaceStatus.Normal, true, false))],
            },
        });
        var refresh = await h.Service.RefreshAsync(EntitlementHarness.Workspace, CancellationToken.None);
        Assert.Equal(EntitlementError.InvalidHistory, refresh.Error);
        var issue = await h.Service.IssueGrantAsync(Capability("cloud.web_continuity", 0, null, "next"), CancellationToken.None);
        Assert.Equal(EntitlementError.InvalidHistory, issue.Error);
        Assert.Equal(commits, h.Store.CommitCount);
    }

    [Fact]
    public async Task AMalformedWorkspaceIdentifierIsRefusedBeforeAnyRead()
    {
        var h = new EntitlementHarness().At(0);
        Assert.Equal(EntitlementError.InvalidRequest, (await h.Service.ReadAsync("", CancellationToken.None)).Error);
        Assert.Equal(EntitlementError.InvalidRequest, (await h.Service.RefreshAsync("a b", CancellationToken.None)).Error);
    }

    [Fact]
    public void InputRulesAcceptOnlyBoundedOpaqueTokens()
    {
        Assert.True(InputRules.IsIdentifier("ws-1.A:b_c"));
        Assert.False(InputRules.IsIdentifier(new string('a', 65)));
        Assert.False(InputRules.IsKey("Upper"));
        Assert.True(InputRules.IsKey("cloud.storage.bytes"));
        Assert.False(InputRules.IsActor("bad\nactor"));
    }
}
