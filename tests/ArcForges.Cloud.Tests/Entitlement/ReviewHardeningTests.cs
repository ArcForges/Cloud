// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using Xunit;
using static ArcForges.Cloud.Tests.Entitlement.Fixtures;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>
/// Version and ordering guarantees an independent review found missing: a definitions change raises the version, same-instant facts
/// resolve by a total order, a later duplicate revocation never resurrects a grant, and a refresh never lowers a stored version.
/// </summary>
public sealed class ReviewHardeningTests
{
    private const string Ws = "ws1";

    private static Grant CapGrant(string id, long from = 0, long? until = null, long created = 0, string subject = "cloud.sync") =>
        new(id, Ws, GrantKind.Capability, subject, new CapabilityValue(), GrantSource.Subscription, "ref-" + id, T(from), until is { } u ? T(u) : null, "commerce", T(created));

    private static EntitlementRecordSet Records(params Grant[] grants) => EntitlementRecordSet.Empty(Ws) with { Grants = [.. grants] };

    private static CapabilityResult Sync(EntitlementSnapshot snapshot) => snapshot.Content.Capabilities.Single(c => c.Key == "cloud.sync");

    // ---- B1 -------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task ADefinitionsChangeThatAltersTheContentRaisesTheVersion()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Capability("cloud.new", 0, null, "n1"));
        await h.AddTerm(Term("t1", 0, 100 * Day));
        var before = await h.At(Day).Refresh();
        Assert.Equal([h.Store.Records(EntitlementHarness.Workspace).Grants.Single().GrantId], before.Content.UnrecognizedGrantIds);

        var changed = Definitions();
        h.Definitions.Definitions = changed with
        {
            Version = "bundle-2",
            Capabilities = changed.Capabilities.Add(new CapabilityDefinition("cloud.new", RequiresPaidTerm: true)),
        };
        var after = await h.At(2 * Day).Read();
        Assert.True(after.Content.Capabilities.Single(c => c.Key == "cloud.new").Granted);
        Assert.Equal("bundle-2", after.Content.DefinitionsVersion);
        Assert.True(after.Version > before.Version, "A client comparing versions must see the new entitlement.");
        await h.AssertRebuildEqual();
    }

    [Fact]
    public async Task EveryDefinitionsActivationRaisesTheVersionExactlyOnceEvenWhenTheContentIsEqual()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Capability("cloud.sync", 0, null, "s1"));
        var first = await h.Refresh();
        h.Definitions.Definitions = Definitions() with { Version = "bundle-2" };
        var second = await h.At(Day).Read();
        Assert.Equal(first.Version + 1, second.Version);
        Assert.Equal(second.Version, (await h.At(2 * Day).Read()).Version);
        h.Definitions.Definitions = Definitions() with { Version = "bundle-1" };
        var third = await h.At(3 * Day).Read();
        Assert.Equal(second.Version + 1, third.Version);
        await h.AssertRebuildEqual();
    }

    [Fact]
    public async Task DefinitionsThatHaveNoRecordedActivationAreNeverAppliedToARecordedHistory()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Capability("cloud.sync", 0, null, "s1"));
        h.Store.Insert(EntitlementHarness.Workspace, r => r with { Activations = r.Activations.Add(new DefinitionsActivation("bundle-9", T(5))) });
        var records = h.Store.Records(EntitlementHarness.Workspace);
        Assert.Throws<ResolverInputException>(() => EntitlementResolver.Resolve(records, Definitions(), T(10)));
    }

    // ---- B2 -------------------------------------------------------------------------------------------------------------

    public static TheoryData<int> TiePermutations() => [0, 1, 2, 3, 4, 5];

    [Theory]
    [MemberData(nameof(TiePermutations))]
    public void FactsRecordedAtTheSameInstantResolveByATotalOrderNeverByInputOrder(int permutation)
    {
        var facts = new[]
        {
            new WorkspaceStatusFact(T(5), WorkspaceStatus.Normal, true, false),
            new WorkspaceStatusFact(T(5), WorkspaceStatus.Suspended, true, false),
            new WorkspaceStatusFact(T(5), WorkspaceStatus.Restricted, true, false),
        };
        int[][] orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
        var records = (Records(CapGrant("g1")) with
        {
            Terms = [new ServiceTermFact("t1", ServiceTermKind.Subscription, T(0), T(100), null, T(0), T(0))],
            StatusFacts = [.. orders[permutation].Select(i => facts[i])],
        });
        var snapshot = EntitlementResolver.Resolve(records, Definitions(), T(10));
        Assert.Equal(ServiceState.Suspended, snapshot.Content.Service.State);
        Assert.Equal(EntitlementReason.WorkspaceSuspended, Sync(snapshot).Reason);
        var baseline = EntitlementResolver.Resolve(records with { StatusFacts = [.. facts] }, Definitions(), T(10));
        Assert.True(baseline.SameAs(snapshot));
    }

    [Fact]
    public void ATieOnStatusIsDecidedByCancelledRenewalThenNoPendingPurchase()
    {
        var renew = new WorkspaceStatusFact(T(5), WorkspaceStatus.Normal, AutoRenew: true, PurchasePending: false);
        var cancel = new WorkspaceStatusFact(T(5), WorkspaceStatus.Normal, AutoRenew: false, PurchasePending: false);
        var pending = new WorkspaceStatusFact(T(5), WorkspaceStatus.Normal, AutoRenew: true, PurchasePending: true);
        var records = Records(CapGrant("g1")) with { Terms = [new ServiceTermFact("t1", ServiceTermKind.Subscription, T(0), T(100), null, T(0), T(0))] };
        foreach (var order in new[] { new[] { renew, cancel }, new[] { cancel, renew } })
        {
            Assert.Equal(ServiceState.CancelScheduled, EntitlementResolver.Resolve(records with { StatusFacts = [.. order] }, Definitions(), T(10)).Content.Service.State);
        }

        var noTerm = Records(CapGrant("g1"));
        foreach (var order in new[] { new[] { renew, pending }, new[] { pending, renew } })
        {
            Assert.Equal(ServiceState.None, EntitlementResolver.Resolve(noTerm with { StatusFacts = [.. order] }, Definitions(), T(10)).Content.Service.State);
        }
    }

    [Fact]
    public void ALaterRecordedFactAlwaysWinsOverAnEarlierMoreRestrictiveOne()
    {
        var records = Records(CapGrant("g1")) with
        {
            Terms = [new ServiceTermFact("t1", ServiceTermKind.Subscription, T(0), T(100), null, T(0), T(0))],
            StatusFacts = [new WorkspaceStatusFact(T(6), WorkspaceStatus.Normal, true, false), new WorkspaceStatusFact(T(5), WorkspaceStatus.Suspended, true, false)],
        };
        Assert.Equal(ServiceState.Suspended, EntitlementResolver.Resolve(records, Definitions(), T(5)).Content.Service.State);
        Assert.Equal(ServiceState.Active, EntitlementResolver.Resolve(records, Definitions(), T(6)).Content.Service.State);
    }

    // ---- N1 -------------------------------------------------------------------------------------------------------------

    [Fact]
    public void ALaterDuplicateRevocationNeverResurrectsARevokedGrant()
    {
        var grant = CapGrant("g1");
        var term = new ServiceTermFact("t1", ServiceTermKind.Subscription, T(0), T(100), null, T(0), T(0));
        var early = new Revocation("r1", "g1", "refund", T(0), "op", T(1));
        var late = new Revocation("r2", "g1", "refund", T(50), "op", T(2));
        foreach (var order in new[] { new[] { early, late }, new[] { late, early } })
        {
            var records = Records(grant) with { Terms = [term], Revocations = [.. order] };
            Assert.False(Sync(EntitlementResolver.Resolve(records, Definitions(), T(10))).Granted);
            Assert.False(Sync(EntitlementResolver.Resolve(records, Definitions(), T(60))).Granted);
        }
    }

    [Fact]
    public void AStatusFactIsNotKnownBeforeItIsRecorded()
    {
        var records = Records(CapGrant("g1")) with
        {
            Terms = [new ServiceTermFact("t1", ServiceTermKind.Subscription, T(0), T(100), null, T(0), T(0))],
            StatusFacts = [new WorkspaceStatusFact(T(10), WorkspaceStatus.Suspended, true, false)],
        };
        Assert.Equal(ServiceState.Active, EntitlementResolver.Resolve(records, Definitions(), T(9)).Content.Service.State);
        Assert.Equal(ServiceState.Suspended, EntitlementResolver.Resolve(records, Definitions(), T(10)).Content.Service.State);
    }

    [Fact]
    public void ATamperedQuotaAboveTheBoundIsRefusedBeforeAnySumCanOverflow()
    {
        var grant = new Grant("g1", Ws, GrantKind.Quota, "cloud.storage.bytes", new QuotaValue(InputRules.MaxQuotaLimit + 1), GrantSource.Subscription, "r", T(0), null, "commerce", T(0));
        Assert.Throws<ResolverInputException>(() => EntitlementResolver.Resolve(Records(grant), Definitions(), T(10)));
        var atBound = grant with { Value = new QuotaValue(InputRules.MaxQuotaLimit) };
        Assert.Equal(InputRules.MaxQuotaLimit, EntitlementResolver.Resolve(Records(atBound), Definitions(), T(10)).Content.Quotas.First(q => q.Key == "cloud.storage.bytes").Limit);
    }

    [Fact]
    public void EqualPrioritiesAreDecidedByGrantIdentifierNotByInputOrder()
    {
        Grant Level(string id, long limit) => new(id, Ws, GrantKind.Quota, "support.level", new QuotaValue(limit, 2), GrantSource.Subscription, "r" + id, T(0), null, "commerce", T(0));
        foreach (var order in new[] { new[] { Level("a", 1), Level("b", 2) }, new[] { Level("b", 2), Level("a", 1) } })
        {
            var snapshot = EntitlementResolver.Resolve(Records(order), Definitions(), T(1));
            Assert.Equal(1, snapshot.Content.Quotas.Single(q => q.Key == "support.level").Limit);
        }
    }

    [Fact]
    public void ServiceNeverStartsBeforeItWasAuthorized()
    {
        var records = Records(CapGrant("g1")) with { Terms = [new ServiceTermFact("t1", ServiceTermKind.Subscription, T(0), T(100), null, T(50), T(0))] };
        Assert.False(Sync(EntitlementResolver.Resolve(records, Definitions(), T(10))).Granted);
        Assert.True(Sync(EntitlementResolver.Resolve(records, Definitions(), T(50))).Granted);
    }

    [Fact]
    public void AGrantThatLapsedWithItsTermReadsAsExpiredWhileARevokedOneReadsAsNoEntitlement()
    {
        var term = new ServiceTermFact("t1", ServiceTermKind.Subscription, T(0), T(30), T(37), T(0), T(0));
        var lapsed = Records(CapGrant("g1", 0, 30)) with { Terms = [term] };
        Assert.Equal(EntitlementReason.SubscriptionExpired, Sync(EntitlementResolver.Resolve(lapsed, Definitions(), T(40))).Reason);
        Assert.Equal(EntitlementReason.PaymentGrace, Sync(EntitlementResolver.Resolve(lapsed, Definitions(), T(33))).Reason);
        var revoked = lapsed with { Revocations = [new Revocation("r1", "g1", "refund", T(5), "op", T(6))] };
        Assert.Equal(EntitlementReason.NoEntitlement, Sync(EntitlementResolver.Resolve(revoked, Definitions(), T(40))).Reason);
    }

    // ---- N2 -------------------------------------------------------------------------------------------------------------

    [Fact]
    public void ASuspendedWorkspaceReportsNoQuotaLimitAndALapsedTermKeepsItBySpecification()
    {
        var quota = new Grant("q1", Ws, GrantKind.Quota, "cloud.storage.bytes", new QuotaValue(1000), GrantSource.Subscription, "q", T(0), null, "commerce", T(0));
        var term = new ServiceTermFact("t1", ServiceTermKind.Subscription, T(0), T(30), null, T(0), T(0));
        var records = Records(quota) with { Terms = [term] };
        var active = EntitlementResolver.Resolve(records, Definitions(), T(10)).Content.Quotas.Single(q => q.Key == "cloud.storage.bytes");
        Assert.Equal(1000, active.Limit);

        var expired = EntitlementResolver.Resolve(records, Definitions(), T(40)).Content.Quotas.Single(q => q.Key == "cloud.storage.bytes");
        Assert.Equal(1000, expired.Limit);
        Assert.Equal(EntitlementReason.Available, expired.Reason);

        var suspended = records with { StatusFacts = [new WorkspaceStatusFact(T(5), WorkspaceStatus.Suspended, true, false)] };
        var quotaEntry = EntitlementResolver.Resolve(suspended, Definitions(), T(10)).Content.Quotas.Single(q => q.Key == "cloud.storage.bytes");
        Assert.Equal(0, quotaEntry.Limit);
        Assert.Empty(quotaEntry.Contributions);
        Assert.Equal(EntitlementReason.WorkspaceSuspended, quotaEntry.Reason);
    }

    // ---- N3 / N6 --------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task ARecordAdmittedWithACreationTimeBeforeTheStoredComputationCannotLowerTheVersion()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Capability("cloud.sync", 0, null, "s1"));
        await h.AddTerm(Term("t1", Day, 100 * Day, createdSeconds: 0));
        var stored = await h.At(10 * Day).Refresh();
        Assert.True(stored.Version >= 2);

        // A term stamped with an old creation time and a start of zero would make the replay see service from the start, which collapses
        // two earlier changes into one and derives a lower version than the one clients may already hold.
        h.Store.Insert(EntitlementHarness.Workspace, r => r with { Terms = r.Terms.Add(Term("t2", 0, 100 * Day, createdSeconds: 0)) });
        var refresh = await h.Service.RefreshAsync(EntitlementHarness.Workspace, CancellationToken.None);
        Assert.Equal(EntitlementError.InvalidHistory, refresh.Error);
        Assert.Contains("fell below", refresh.Detail, StringComparison.Ordinal);
        var report = await h.Service.VerifyRebuildAsync(EntitlementHarness.Workspace, CancellationToken.None);
        Assert.Equal(stored.Version, report.Stored!.Version);
    }

    [Fact]
    public async Task AReplayedRevocationWithoutAnInstantWritesNothingAndAnUnchangedWorkspaceIsNotRewrittenLater()
    {
        var h = new EntitlementHarness().At(0);
        var grant = await h.Issue(Capability("cloud.sync", 0, null, "s1"));
        var version = (await h.Read()).Version;
        var first = await h.Service.RevokeGrantAsync(new RevokeGrantRequest(EntitlementHarness.Workspace, grant.GrantId, "refund", null, "op", version), CancellationToken.None);
        Assert.True(first.Succeeded);
        var after = (await h.Read()).Version;
        var commits = h.Store.CommitCount;
        h.At(Day);
        var replay = await h.Service.RevokeGrantAsync(new RevokeGrantRequest(EntitlementHarness.Workspace, grant.GrantId, "refund", null, "op", after), CancellationToken.None);
        Assert.True(replay.Duplicate);
        Assert.Single(h.Store.Records(EntitlementHarness.Workspace).Revocations);
        await h.At(2 * Day).Refresh();
        await h.At(3 * Day).Refresh();
        Assert.Equal(commits, h.Store.CommitCount);
        await h.AssertRebuildEqual();
        Assert.Equal(ImmutableArray<string>.Empty, (await h.Read()).Content.UnrecognizedGrantIds);
    }
}
