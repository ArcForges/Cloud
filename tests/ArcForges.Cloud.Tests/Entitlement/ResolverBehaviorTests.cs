// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using Xunit;
using static ArcForges.Cloud.Tests.Entitlement.Fixtures;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>
/// The resolver's rules, driven through the service with a test-only store and one settable clock: service state from paid-through,
/// the explicit combination rule of each of the four entitlement kinds, and the reason of every entry. These are offline logic
/// tests; they prove nothing about D1 persistence or about a real payment provider.
/// </summary>
public sealed class ResolverBehaviorTests
{
    private static async Task<EntitlementHarness> Subscriber()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Capability("cloud.sync", 0, null, "sub1-p1"));
        await h.Issue(Capability("account.manage", 0, null, "acct1"));
        await h.AddTerm(Term("t1", Day, 31 * Day, graceSeconds: 38 * Day));
        return h;
    }

    [Fact]
    public async Task ServiceStateFollowsPaidThroughAndNeverAProviderStatus()
    {
        var h = await Subscriber();
        var before = await h.Read();
        Assert.Equal(ServiceState.Pending, before.Content.Service.State);
        Assert.False(Capability(before, "cloud.sync").Granted);
        Assert.Equal(EntitlementReason.NoEntitlement, Capability(before, "cloud.sync").Reason);

        var active = await h.At(Day).Read();
        Assert.Equal(ServiceState.Active, active.Content.Service.State);
        Assert.Equal(T(31 * Day), active.Content.Service.PaidThrough);
        Assert.True(Capability(active, "cloud.sync").Granted);
        Assert.Equal(EntitlementReason.Available, Capability(active, "cloud.sync").Reason);
        Assert.True(active.Version > before.Version);

        var grace = await h.At(31 * Day).Read();
        Assert.Equal(ServiceState.Grace, grace.Content.Service.State);
        Assert.False(Capability(grace, "cloud.sync").Granted);
        Assert.Equal(EntitlementReason.PaymentGrace, Capability(grace, "cloud.sync").Reason);

        var ended = await h.At(38 * Day).Read();
        Assert.Equal(ServiceState.Ended, ended.Content.Service.State);
        Assert.Equal(EntitlementReason.SubscriptionExpired, Capability(ended, "cloud.sync").Reason);
        Assert.Equal(T(31 * Day), ended.Content.Service.PaidThrough);
    }

    [Fact]
    public async Task GraceProtectsAccessNotPaidServiceAndNeverExtendsAdmission()
    {
        var h = await Subscriber();
        var grace = await h.At(33 * Day).Read();
        Assert.Equal(EntitlementReason.PaymentGrace, Capability(grace, "cloud.sync").Reason);
        Assert.True(Capability(grace, "account.manage").Granted);
        Assert.False(grace.Content.Service.PaidTermActive);
        Assert.Equal(T(38 * Day), grace.Content.Service.GraceEndsAt);
    }

    [Fact]
    public async Task CancelScheduledKeepsEntitlementUntilPaidThrough()
    {
        var h = await Subscriber();
        await h.At(2 * Day).Refresh();
        await h.AddStatus(new WorkspaceStatusFact(T(2 * Day), WorkspaceStatus.Normal, AutoRenew: false, PurchasePending: false));
        var scheduled = await h.At(3 * Day).Read();
        Assert.Equal(ServiceState.CancelScheduled, scheduled.Content.Service.State);
        Assert.True(Capability(scheduled, "cloud.sync").Granted);
        Assert.True(scheduled.Content.Service.PaidTermActive);
        var ended = await h.At(40 * Day).Read();
        Assert.Equal(ServiceState.Ended, ended.Content.Service.State);
    }

    [Fact]
    public async Task AnAbuttingRenewalChangesNothingAtTheBoundary()
    {
        var h = await Subscriber();
        var first = await h.At(2 * Day).Read();
        h.At(20 * Day);
        await h.AddTerm(Term("t2", 31 * Day, 61 * Day, graceSeconds: 68 * Day, createdSeconds: 20 * Day));
        var renewed = await h.Refresh();
        Assert.Equal(T(61 * Day), renewed.Content.Service.PaidThrough);
        var across = await h.At(31 * Day).Read();
        Assert.Equal(ServiceState.Active, across.Content.Service.State);
        Assert.True(Capability(across, "cloud.sync").Granted);
        Assert.Equal(renewed.Version, across.Version);
        Assert.True(renewed.Version >= first.Version);
    }

    [Fact]
    public async Task ACapabilityNeedsAValidSourcedGrantAndAnActivePaidTerm()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Capability("cloud.sync", 0, null, "ticket-1", GrantSource.AdminGrant, reason: "support goodwill"));
        var noTerm = await h.At(Day).Refresh();
        Assert.False(Capability(noTerm, "cloud.sync").Granted);
        Assert.Equal(EntitlementReason.NoEntitlement, Capability(noTerm, "cloud.sync").Reason);

        await h.AddTerm(Term("t1", Day, 10 * Day));
        var withTerm = await h.At(2 * Day).Refresh();
        Assert.True(Capability(withTerm, "cloud.sync").Granted);

        var h2 = new EntitlementHarness().At(0);
        await h2.AddTerm(Term("t1", 0, 10 * Day));
        var termOnly = await h2.At(Day).Refresh();
        Assert.False(Capability(termOnly, "cloud.sync").Granted);
        Assert.Empty(Capability(termOnly, "cloud.sync").SourceGrantIds);
    }

    [Fact]
    public async Task ARefundRevocationEndsTheGrantWithoutEditingIt()
    {
        var h = await Subscriber();
        var active = await h.At(2 * Day).Read();
        var grantId = Capability(active, "cloud.sync").SourceGrantIds.Single();
        Assert.True(Capability(active, "cloud.sync").Granted);

        await h.Revoke(grantId, active.Version, effectiveSeconds: 0);
        var after = await h.At(2 * Day).Read();
        Assert.False(Capability(after, "cloud.sync").Granted);
        Assert.Equal(EntitlementReason.NoEntitlement, Capability(after, "cloud.sync").Reason);
        Assert.Empty(Capability(after, "cloud.sync").SourceGrantIds);
        Assert.True(after.Version > active.Version);
        var stored = h.Store.Records(EntitlementHarness.Workspace).Grants.Single(grant => grant.GrantId == grantId);
        Assert.Null(stored.EffectiveUntil);
    }

    [Fact]
    public async Task AFutureDatedRevocationLeavesTheGrantValidUntilItsDate()
    {
        var h = await Subscriber();
        var active = await h.At(2 * Day).Read();
        var grantId = Capability(active, "cloud.sync").SourceGrantIds.Single();
        await h.Revoke(grantId, active.Version, effectiveSeconds: 5 * Day);
        Assert.True(Capability(await h.At(3 * Day).Read(), "cloud.sync").Granted);
        Assert.False(Capability(await h.At(5 * Day).Read(), "cloud.sync").Granted);
    }

    [Fact]
    public async Task ATermActionTruncatesTheEffectiveIntervalButNeverRewritesIt()
    {
        var h = await Subscriber();
        await h.At(2 * Day).Refresh();
        await h.AddAction(new TermActionFact("t1", ServiceTermActionKind.Revoke, T(3 * Day), T(2 * Day)));
        var before = await h.At(2 * Day + 1).Read();
        Assert.True(Capability(before, "cloud.sync").Granted);
        var after = await h.At(3 * Day).Read();
        Assert.False(Capability(after, "cloud.sync").Granted);
        Assert.Equal(ServiceState.Ended, after.Content.Service.State);
        Assert.Equal(T(3 * Day), after.Content.Service.PaidThrough);
        Assert.Equal(T(31 * Day), h.Store.Records(EntitlementHarness.Workspace).Terms.Single().EndsAt);
    }

    [Fact]
    public async Task SuspensionAndRestrictionOverrideEverythingTheyShould()
    {
        var h = await Subscriber();
        await h.At(2 * Day).Refresh();
        await h.AddStatus(new WorkspaceStatusFact(T(2 * Day), WorkspaceStatus.Restricted, AutoRenew: true, PurchasePending: false));
        var restricted = await h.At(2 * Day + 1).Read();
        Assert.Equal(EntitlementReason.TemporarilyRestricted, Capability(restricted, "cloud.sync").Reason);
        Assert.True(Capability(restricted, "account.manage").Granted);

        h.At(3 * Day);
        await h.AddStatus(new WorkspaceStatusFact(T(3 * Day), WorkspaceStatus.Suspended, AutoRenew: true, PurchasePending: false));
        var suspended = await h.Read();
        Assert.Equal(ServiceState.Suspended, suspended.Content.Service.State);
        Assert.All(suspended.Content.Capabilities, capability =>
        {
            Assert.False(capability.Granted);
            Assert.Equal(EntitlementReason.WorkspaceSuspended, capability.Reason);
        });

        h.At(4 * Day);
        await h.AddStatus(new WorkspaceStatusFact(T(4 * Day), WorkspaceStatus.Normal, AutoRenew: true, PurchasePending: false));
        Assert.True(Capability(await h.Read(), "cloud.sync").Granted);
    }

    [Fact]
    public async Task AFeatureGateComposesWithEntitlementAndNeverReplacesIt()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Capability("cloud.ai", 0, null, "sub1-ai"));
        await h.AddTerm(Term("t1", 0, 100 * Day));
        var gated = await h.At(Day).Read();
        Assert.False(Capability(gated, "cloud.ai").Granted);
        Assert.Equal(EntitlementReason.FeatureUnavailable, Capability(gated, "cloud.ai").Reason);
        Assert.False(gated.Content.Features.Single().Available);

        await h.AddRelease(new FeatureReleaseFact("feature.ai", T(5 * Day)));
        Assert.False(Capability(await h.At(4 * Day).Read(), "cloud.ai").Granted);
        var released = await h.At(5 * Day).Read();
        Assert.True(Capability(released, "cloud.ai").Granted);
        Assert.True(released.Content.Features.Single().Available);
    }

    [Fact]
    public async Task QuotasCombineBySumMaxAndPriorityReplaceAndExplainTheirDerivation()
    {
        var h = new EntitlementHarness().At(0);
        await h.AddTerm(Term("t1", 0, 100 * Day));
        await h.Issue(Quota("cloud.storage.bytes", 50, 0, null, "base"));
        await h.Issue(Quota("cloud.storage.bytes", 100, 0, 10 * Day, "addon", GrantSource.StorageAddOn));
        await h.Issue(Quota("cloud.devices.max", 3, 0, null, "dev-a"));
        await h.Issue(Quota("cloud.devices.max", 5, 0, null, "dev-b", GrantSource.AdminGrant, reason: "goodwill"));
        await h.Issue(Quota("support.level", 1, 0, null, "sup-a", priority: 1));
        await h.Issue(Quota("support.level", 9, 0, null, "sup-b", priority: 2));
        await h.Issue(Quota("support.level", 7, 0, null, "sup-c", priority: 2));

        var snapshot = await h.At(Day).Refresh();
        var storage = Quota(snapshot, "cloud.storage.bytes");
        Assert.Equal(150, storage.Limit);
        Assert.Equal(150, storage.Contributions.Sum(c => c.Amount));
        Assert.Contains(storage.Contributions, c => c.Source == GrantSource.StorageAddOn && c.Amount == 100);
        Assert.Equal(5, Quota(snapshot, "cloud.devices.max").Limit);
        Assert.Equal(9, Quota(snapshot, "support.level").Limit);

        var downgraded = await h.At(10 * Day).Read();
        Assert.Equal(50, Quota(downgraded, "cloud.storage.bytes").Limit);
        Assert.Single(Quota(downgraded, "cloud.storage.bytes").Contributions);
    }

    [Fact]
    public async Task AnAllowanceResolvesToExactlyOneAccountSelectionWithoutDuplicateIssuance()
    {
        var h = new EntitlementHarness().At(0);
        await h.Issue(Allowance("ai.capacity", "plan-basic", 0, null, "al-1", priority: 1));
        await h.Issue(Allowance("ai.capacity", "plan-pro", 0, null, "al-2", priority: 2));
        var noTerm = await h.At(Day).Refresh();
        var allowance = noTerm.Content.Allowances.Single();
        Assert.False(allowance.Granted);
        Assert.Equal("plan-pro", allowance.CapacityPlanRef);

        await h.AddTerm(Term("t1", Day, 10 * Day));
        var active = (await h.At(2 * Day).Refresh()).Content.Allowances.Single();
        Assert.True(active.Granted);
        Assert.Equal("plan-pro", active.CapacityPlanRef);
        Assert.Single(active.SupersededGrantIds);
    }

    [Fact]
    public async Task AConsumableBalanceIsNotAGrantKindAndTheSnapshotCarriesNoBalance()
    {
        var h = new EntitlementHarness().At(0);
        var result = await h.Service.IssueGrantAsync(Capability("cloud.sync", 0, null, "x") with { Kind = (GrantKind)99 }, CancellationToken.None);
        Assert.Equal(EntitlementError.InvalidRequest, result.Error);
        var snapshot = await h.Refresh();
        Assert.DoesNotContain(snapshot.Content.Quotas, q => q.Key.Contains("credit", StringComparison.Ordinal));
        Assert.DoesNotContain(Enum.GetNames<GrantKind>(), name => name.Contains("Balance", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AGrantForAnUndefinedSubjectIsRecordedAsUnrecognizedAndNeverGranted()
    {
        var h = new EntitlementHarness().At(0);
        var grant = await h.Issue(Capability("cloud.unknown", 0, null, "u1"));
        await h.AddTerm(Term("t1", 0, 10 * Day));
        var snapshot = await h.At(Day).Refresh();
        Assert.Equal([grant.GrantId], snapshot.Content.UnrecognizedGrantIds);
        Assert.DoesNotContain(snapshot.Content.Capabilities, c => c.Key == "cloud.unknown");
    }

    [Fact]
    public async Task RealmsAreIsolatedInBothDirections()
    {
        var official = new EntitlementHarness().At(0);
        await official.Issue(Capability("cloud.sync", 0, null, "g1"));
        await official.AddTerm(Term("self", 0, 10 * Day, kind: ServiceTermKind.SelfHostGrant));
        var denied = await official.At(Day).Refresh();
        Assert.False(Capability(denied, "cloud.sync").Granted);
        Assert.Equal(["self"], denied.Content.IgnoredTermIds);

        var selfHost = new EntitlementHarness(selfHostRealm: true).At(0);
        await selfHost.Issue(Capability("cloud.sync", 0, null, "g1", GrantSource.AdminGrant, reason: "operator funded"));
        await selfHost.AddTerm(Term("sub", 0, 10 * Day));
        Assert.False(Capability(await selfHost.At(Day).Refresh(), "cloud.sync").Granted);
        await selfHost.AddTerm(Term("self", 0, 10 * Day, kind: ServiceTermKind.SelfHostGrant));
        Assert.True(Capability(await selfHost.At(2 * Day).Refresh(), "cloud.sync").Granted);
    }

    [Fact]
    public async Task EveryEntryCarriesAReasonAndEveryAssignableReasonIsReachable()
    {
        var seen = new HashSet<EntitlementReason>();
        void Collect(EntitlementSnapshot snapshot)
        {
            foreach (var capability in snapshot.Content.Capabilities)
            {
                Assert.True(Enum.IsDefined(capability.Reason));
                Assert.Equal(capability.Reason == EntitlementReason.Available, capability.Granted);
                seen.Add(capability.Reason);
            }

            foreach (var quota in snapshot.Content.Quotas) seen.Add(quota.Reason);
            foreach (var allowance in snapshot.Content.Allowances) seen.Add(allowance.Reason);
            foreach (var feature in snapshot.Content.Features) seen.Add(feature.Reason);
        }

        var h = await Subscriber();
        Collect(await h.At(0).Read());
        Collect(await h.At(Day).Read());
        Collect(await h.At(33 * Day).Read());
        Collect(await h.At(40 * Day).Read());
        await h.AddStatus(new WorkspaceStatusFact(T(40 * Day), WorkspaceStatus.Restricted, AutoRenew: true, PurchasePending: false));
        Collect(await h.At(41 * Day).Read());
        await h.AddStatus(new WorkspaceStatusFact(T(41 * Day), WorkspaceStatus.Suspended, AutoRenew: true, PurchasePending: false));
        Collect(await h.At(42 * Day).Read());
        var gated = new EntitlementHarness().At(0);
        await gated.Issue(Capability("cloud.ai", 0, null, "ai"));
        Collect(await gated.At(1).Refresh());

        var assignable = Enum.GetValues<EntitlementReason>().Where(reason => reason != EntitlementReason.QuotaExceeded).ToHashSet();
        Assert.Superset(assignable, seen);
        Assert.DoesNotContain(EntitlementReason.QuotaExceeded, seen);
    }
}
