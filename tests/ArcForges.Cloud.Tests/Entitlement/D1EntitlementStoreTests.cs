// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>
/// The durable Entitlement store (COM.16) against the production named plans on the SQLite oracle: atomic append and snapshot replace,
/// the revision write fence (including the first commit that creates the row), concurrent writers, the owner receipt and outbox row,
/// the GR-05 reason column, append-only enforcement and rebuild equivalence over the stored records. SQLite is not D1.
/// </summary>
public sealed class D1EntitlementStoreTests
{
    private static string Id(int n) => D1EntitlementHarness.Uuid(n);

    private static Grant AdminGrantWithReason(string id, string? reason, GrantSource source = GrantSource.AdminGrant) => new(
        id, D1EntitlementHarness.Workspace, GrantKind.Capability, "cloud.sync", new CapabilityValue(), source, "ticket-" + id[^4..],
        Fixtures.T(0), null, "operator", Fixtures.T(5), reason);

    private static EntitlementAppend Append(params Grant[] grants) => EntitlementAppend.None with { Grants = [.. grants] };

    [Fact]
    public async Task AGrantTheSnapshotAndTheVersionCommitTogetherAndReadBackExactly()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        harness.At(10);
        var capability = await harness.Issue(Fixtures.Capability("cloud.sync", 0, null, "order-1"));
        var quota = await harness.Issue(Fixtures.Quota("cloud.storage.bytes", 5_000_000_000, 0, null, "order-2", GrantSource.StorageAddOn));
        var allowance = await harness.Issue(Fixtures.Allowance("ai.capacity", "plan-1", 0, null, "order-3", priority: 4));
        await harness.AddTerm(Fixtures.Term(Id(0x71), 0, 90 * Fixtures.Day));
        var read = await harness.Read();

        var state = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        Assert.Equal([capability, quota, allowance], state.Records.Grants.OrderBy(g => g.CreatedAt));
        Assert.Equal(await harness.Count("entitlement_grant"), state.Records.Grants.Length);
        Assert.NotNull(state.Snapshot);
        Assert.True(state.Snapshot!.SameAs(read));
        Assert.Equal(read.Version, state.Snapshot.Version);
        Assert.True(Fixtures.Capability(read, "cloud.sync").Granted);
        Assert.Equal(4, state.Revision);
        await harness.AssertRebuildEqual();
    }

    [Fact]
    public async Task EveryCommitWritesItsReceiptOutboxRowAndChangeRecordWithTheRevision()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        harness.At(10);
        await harness.Issue(Fixtures.Capability("cloud.sync", 0, null, "order-1"));

        Assert.Equal(1, await harness.Count("platform_command", "operation = 'entitlement.commit' AND status = 2 AND result_rev = 1"));
        Assert.Equal(1, await harness.Count("platform_outbox", "event_type = 'entitlement.snapshot.changed' AND aggregate_id = '" + D1EntitlementHarness.Workspace + "' AND aggregate_rev = 1 AND state = 1"));
        Assert.Equal(1, await harness.Count("platform_outbox_position", "stream_key = '" + D1EntitlementHarness.Workspace + "' AND sequence = 1"));
        Assert.Equal(1, await harness.Count("platform_change_archive"));
        Assert.Equal(0, await harness.Count("platform_command_guard"));
        var revision = await harness.Bridge.QueryAsync("SELECT rev, updated_at FROM entitlement_revision", T.Ct);
        Assert.Equal(["1", await StoredComputedAt(harness)], revision.Single());
    }

    [Fact]
    public async Task AStaleRevisionCommitsNothing()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        harness.At(10);
        await harness.Issue(Fixtures.Capability("cloud.sync", 0, null, "order-1"));
        var stale = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        harness.At(20);
        await harness.Issue(Fixtures.Capability("cloud.ai", 0, null, "order-2"));
        var rowsBefore = await harness.Count("entitlement_grant");
        var receiptsBefore = await harness.Count("platform_command");

        var late = new Grant(Id(0x99), D1EntitlementHarness.Workspace, GrantKind.Capability, "cloud.sync", new CapabilityValue(), GrantSource.Subscription, "order-late",
            Fixtures.T(0), null, "commerce", Fixtures.T(30), null);
        var outcome = await harness.Store.CommitAsync(D1EntitlementHarness.Workspace, stale.Revision, Append(late), EntitlementResolver.Resolve(
            stale.Records with { Grants = stale.Records.Grants.Add(late) }, harness.Definitions.Current(), Fixtures.T(30)), T.Ct);

        Assert.Equal(CommitOutcome.RevisionConflict, outcome);
        Assert.Equal(rowsBefore, await harness.Count("entitlement_grant"));
        Assert.Equal(receiptsBefore, await harness.Count("platform_command"));
        Assert.Equal(0, await harness.Count("entitlement_grant", "grant_id = '" + late.GrantId + "'"));
        Assert.Equal(0, await harness.Count("platform_command_guard"));
    }

    [Fact]
    public async Task TheFirstCommitCreatesTheRevisionRowAndAConcurrentFirstCommitFailsItsGuard()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        var first = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        var second = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        Assert.Equal(0, first.Revision);
        Assert.Equal(0, await harness.Count("entitlement_revision"));

        var grantA = AdminGrantWithReason(Id(0x91), "first writer");
        var grantB = AdminGrantWithReason(Id(0x92), "second writer");
        var a = await harness.Store.CommitAsync(D1EntitlementHarness.Workspace, 0, Append(grantA), Snapshot(first, grantA, 6), T.Ct);
        var b = await harness.Store.CommitAsync(D1EntitlementHarness.Workspace, 0, Append(grantB), Snapshot(second, grantB, 6), T.Ct);

        Assert.Equal(CommitOutcome.Committed, a);
        Assert.Equal(CommitOutcome.RevisionConflict, b);
        Assert.Equal([["1"]], (await harness.Bridge.QueryAsync("SELECT rev FROM entitlement_revision", T.Ct)).Select(r => r.Cast<string>().ToArray()));
        Assert.Equal(1, await harness.Count("entitlement_grant"));
        Assert.Equal(0, await harness.Count("entitlement_grant", "grant_id = '" + grantB.GrantId + "'"));

        // A writer that believes a later revision exists when the row is absent is refused too: absent is revision zero and nothing else.
        var phantom = AdminGrantWithReason(Id(0x93), "phantom");
        using var other = await D1EntitlementHarness.CreateAsync();
        var emptyState = await other.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        Assert.Equal(CommitOutcome.RevisionConflict, await other.Store.CommitAsync(D1EntitlementHarness.Workspace, 5, Append(phantom), Snapshot(emptyState, phantom, 6), T.Ct));
        Assert.Equal(0, await other.Count("entitlement_revision"));
    }

    [Fact]
    public async Task ConcurrentWritersAreSerialisedByTheRevisionAndEveryGrantCommitsOnce()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        harness.At(100);
        var requests = Enumerable.Range(1, 4).Select(n => harness.ForWorkspace(Fixtures.Capability("cloud.sync", 0, null, "order-" + n))).ToArray();

        var results = await Task.WhenAll(requests.Select(request => harness.Service.IssueGrantAsync(request, T.Ct).AsTask()));

        Assert.All(results, result => Assert.True(result.Succeeded, result.Detail));
        Assert.Equal(4, await harness.Count("entitlement_grant"));
        Assert.Equal(4, results.Select(r => r.Value!.GrantId).Distinct().Count());
        var state = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        Assert.Equal(4, state.Revision);
        Assert.Equal(4, await harness.Count("platform_command"));
        Assert.Equal(4, await harness.Count("platform_outbox_position", "stream_key = '" + D1EntitlementHarness.Workspace + "'"));
        await harness.AssertRebuildEqual();
    }

    [Fact]
    public async Task ATrueCommitFailureRollsBackEveryRowOfTheBatch()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        var state = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        var grant = AdminGrantWithReason(Id(0x91), "valid");
        var orphan = new Revocation(Id(0x92), Id(0xDEAD), "refund", Fixtures.T(6), "operator", Fixtures.T(6));
        var append = EntitlementAppend.None with { Grants = [grant], Revocations = [orphan] };

        var thrown = await Assert.ThrowsAsync<EntitlementStoreException>(async () =>
            await harness.Store.CommitAsync(D1EntitlementHarness.Workspace, 0, append, Snapshot(state, grant, 6), T.Ct));

        Assert.Equal(EntitlementStoreFailure.Defect, thrown.Failure);
        foreach (var table in new[] { "entitlement_grant", "entitlement_revocation", "entitlement_snapshot", "entitlement_revision", "platform_command", "platform_outbox", "platform_change_archive", "platform_command_guard" })
            Assert.Equal(0, await harness.Count(table));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public async Task AnOperatorGrantWithoutAReasonIsRefusedByTheColumnRule(string? reason)
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        var state = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        foreach (var source in new[] { GrantSource.AdminGrant, GrantSource.Compensation, GrantSource.Migration })
        {
            var grant = AdminGrantWithReason(Id(0x91), reason, source);
            await Assert.ThrowsAsync<EntitlementStoreException>(async () =>
                await harness.Store.CommitAsync(D1EntitlementHarness.Workspace, 0, Append(grant), Snapshot(state, grant, 6), T.Ct));
        }

        Assert.Equal(0, await harness.Count("entitlement_grant"));
    }

    [Fact]
    public async Task AReasonOnAnOrdinarySourceOrOutOfShapeIsRefusedAndAnOperatorReasonRoundTrips()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        var state = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        var sample = AdminGrantWithReason(Id(0x91), "x", GrantSource.Subscription);
        foreach (var bad in new[] { sample, AdminGrantWithReason(Id(0x92), new string('r', 513)), AdminGrantWithReason(Id(0x93), "line\nbreak"), AdminGrantWithReason(Id(0x94), "nul\0byte") })
        {
            await Assert.ThrowsAsync<EntitlementStoreException>(async () =>
                await harness.Store.CommitAsync(D1EntitlementHarness.Workspace, 0, Append(bad), Snapshot(state, bad, 6), T.Ct));
        }

        Assert.Equal(0, await harness.Count("entitlement_grant"));

        harness.At(10);
        var reason = new string('é', 512);
        var issued = await harness.Issue(Fixtures.Capability("cloud.sync", 0, null, "TICKET-9", GrantSource.Compensation, reason));
        var loaded = (await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct)).Records.Grants.Single();
        Assert.Equal(reason, loaded.Reason);
        Assert.Equal(issued, loaded);
        Assert.Equal([[reason]], (await harness.Bridge.QueryAsync("SELECT reason FROM entitlement_grant", T.Ct)).Select(r => r.Cast<string>().ToArray()));
    }

    [Fact]
    public async Task TheStoreAppendsAndNeverUpdatesOrDeletesAGrantOrARevocation()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        harness.At(10);
        var grant = await harness.Issue(Fixtures.Capability("cloud.sync", 0, null, "order-1"));
        await harness.Revoke(grant.GrantId, (await harness.Read()).Version);

        foreach (var statement in new[]
        {
            "UPDATE entitlement_grant SET subject = 'x'", "DELETE FROM entitlement_grant", "UPDATE entitlement_revocation SET reason_code = 'x'", "DELETE FROM entitlement_revocation",
        })
        {
            Assert.Contains("af_immutable", await harness.Bridge.RefusalAsync(statement, T.Ct), StringComparison.Ordinal);
        }

        Assert.Equal(1, await harness.Count("entitlement_grant"));
        Assert.Equal(1, await harness.Count("entitlement_revocation"));
    }

    [Fact]
    public async Task TermsActionsStatusFactsActivationsAndReleasesCommitAtomicallyAndTheSnapshotRebuildsEqualFromStoredRecords()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        harness.At(10);
        await harness.Issue(Fixtures.Capability("cloud.sync", 0, null, "order-1"));
        await harness.Issue(Fixtures.Capability("cloud.ai", 0, null, "order-2"));
        await harness.Issue(Fixtures.Quota("cloud.storage.bytes", 100, 0, null, "order-3"));

        var first = Fixtures.Term(Id(0x71), 0, 30 * Fixtures.Day, 33 * Fixtures.Day, createdSeconds: 20);
        var renewal = Fixtures.Term(Id(0x72), 30 * Fixtures.Day, 60 * Fixtures.Day, null, createdSeconds: 20);
        await harness.AppendCommitted(D1EntitlementHarness.Terms(D1EntitlementHarness.TermRow(first, "period-1"), D1EntitlementHarness.TermRow(renewal, "period-2")), 20);
        await harness.AppendCommitted(EntitlementAppend.None with
        {
            TermActions = [new TermActionRow(Id(0x81), "action-1", new TermActionFact(Id(0x72), ServiceTermActionKind.Revoke, Fixtures.T(50 * Fixtures.Day), Fixtures.T(30)), null)],
            StatusFacts = [new StatusFactRow(Id(0x82), "status-1", new WorkspaceStatusFact(Fixtures.T(31), WorkspaceStatus.Restricted, AutoRenew: false, PurchasePending: true))],
        }, 31);
        Assert.Equal(FeatureReleaseOutcome.Released, await harness.Store.AppendFeatureReleaseAsync(new FeatureReleaseFact("feature.ai", Fixtures.T(32)), T.Ct));
        harness.At(40 * Fixtures.Day);
        harness.Definitions.Definitions = Fixtures.Definitions() with { Version = "bundle-2" };
        var refreshed = await harness.Refresh();

        var state = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        Assert.Equal(2, state.Records.Terms.Length);
        Assert.Single(state.Records.TermActions);
        Assert.Single(state.Records.StatusFacts);
        Assert.Single(state.Records.FeatureReleases);
        Assert.Equal("bundle-2", state.Records.Activations.Last().Version);
        Assert.True(state.Snapshot!.SameAs(refreshed));
        var report = await harness.Service.VerifyRebuildAsync(D1EntitlementHarness.Workspace, T.Ct);
        Assert.Equal(RebuildStatus.Equal, report.Status);
        Assert.Equal(WorkspaceStatus.Restricted, state.Records.StatusFacts.Single().Status);
        Assert.False(state.Records.StatusFacts.Single().AutoRenew);
        Assert.True(state.Records.StatusFacts.Single().PurchasePending);
        Assert.Equal(2, await harness.Count("entitlement_service_term"));
        Assert.Equal(["period-1", "period-2"], (await harness.Bridge.QueryAsync("SELECT period_ref FROM entitlement_service_term ORDER BY starts_at", T.Ct)).Select(r => r[0]!));
    }

    [Fact]
    public async Task ATamperedStoredSnapshotIsReportedAsAMismatchNeverRepaired()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        harness.At(10);
        var grant = await harness.Issue(Fixtures.Capability("cloud.sync", 0, null, "order-1"));
        await harness.AddTerm(Fixtures.Term(Id(0x71), 0, 30 * Fixtures.Day, createdSeconds: 5));
        Assert.True(Fixtures.Capability(await harness.Read(), "cloud.sync").Granted);
        await harness.AssertRebuildEqual();

        await harness.Bridge.ExecAsync("UPDATE entitlement_snapshot SET capabilities = json_replace(capabilities, '$.\"cloud.sync\".granted', json('false'))", T.Ct);

        var report = await harness.Service.VerifyRebuildAsync(D1EntitlementHarness.Workspace, T.Ct);
        Assert.Equal(RebuildStatus.Mismatch, report.Status);
        Assert.NotEmpty(report.Differences);
        Assert.Equal(1, await harness.Count("entitlement_grant", "grant_id = '" + grant.GrantId + "'"));
    }

    [Fact]
    public async Task ARepeatOfTheSameCommitIsRecognisedByItsReceiptAndNothingIsAppliedTwice()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        var state = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        var grant = AdminGrantWithReason(Id(0x91), "once");
        var snapshot = Snapshot(state, grant, 6);

        Assert.Equal(CommitOutcome.Committed, await harness.Store.CommitAsync(D1EntitlementHarness.Workspace, 0, Append(grant), snapshot, T.Ct));
        Assert.Equal(CommitOutcome.Committed, await harness.Store.CommitAsync(D1EntitlementHarness.Workspace, 0, Append(grant), snapshot, T.Ct));

        Assert.Equal(1, await harness.Count("entitlement_grant"));
        Assert.Equal(1, await harness.Count("platform_command"));
        Assert.Equal(1, await harness.Count("platform_outbox"));
        Assert.Equal([["1"]], (await harness.Bridge.QueryAsync("SELECT rev FROM entitlement_revision", T.Ct)).Select(r => r.Cast<string>().ToArray()));

        // The same revision with different content is a different command and loses to the first, as any stale writer does.
        var other = AdminGrantWithReason(Id(0x92), "other");
        Assert.Equal(CommitOutcome.RevisionConflict, await harness.Store.CommitAsync(D1EntitlementHarness.Workspace, 0, Append(other), Snapshot(state, other, 6), T.Ct));
    }

    [Fact]
    public async Task ALongHistoryIsReadInKeysetPagesWithoutSkippingOrRepeatingARow()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        var state = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        var expected = new List<string>();
        long revision = 0;
        foreach (var batch in new[] { 100, 100, 30 })
        {
            var start = expected.Count;
            var grants = Enumerable.Range(start, batch)
                .Select(i => AdminGrantWithReason(Id(0x2000 + i), "bulk", GrantSource.Migration) with { SourceRef = "bulk-" + i, EffectiveFrom = Fixtures.T(i) })
                .ToArray();
            expected.AddRange(grants.Select(g => g.GrantId));
            Assert.Equal(CommitOutcome.Committed, await harness.Store.CommitAsync(D1EntitlementHarness.Workspace, revision++, Append(grants), Snapshot(state, grants[0], 6), T.Ct));
        }

        var loaded = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        Assert.Equal(230, loaded.Records.Grants.Length);
        Assert.Equal(expected.Order(StringComparer.Ordinal), loaded.Records.Grants.Select(g => g.GrantId).Order(StringComparer.Ordinal));
        Assert.Equal(230, loaded.Records.Grants.Select(g => g.GrantId).Distinct().Count());
        Assert.Equal(3, loaded.Revision);
        Assert.True(harness.Bridge.Calls > 10);
    }

    [Fact]
    public async Task RecordsStampedAtTheEpochItselfAreReadBackLikeAnyOtherInstant()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        var state = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        var grant = AdminGrantWithReason(Id(0x91), "at zero") with { CreatedAt = Fixtures.T(0) };
        var append = EntitlementAppend.None with
        {
            Grants = [grant],
            Activations = [new DefinitionsActivation("bundle-1", Fixtures.T(0))],
            StatusFacts = [new StatusFactRow(Id(0x82), "status-0", new WorkspaceStatusFact(Fixtures.T(0), WorkspaceStatus.Normal, true, false))],
        };
        Assert.Equal(CommitOutcome.Committed, await harness.Store.CommitAsync(D1EntitlementHarness.Workspace, 0, append, Snapshot(state, grant, 0), T.Ct));

        var loaded = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);

        Assert.Equal(grant, loaded.Records.Grants.Single());
        Assert.Equal("bundle-1", loaded.Records.Activations.Single().Version);
        Assert.Equal(Fixtures.T(0), loaded.Records.StatusFacts.Single().RecordedAt);
        Assert.Equal(Fixtures.T(0), loaded.Snapshot!.ComputedAt);
    }

    [Fact]
    public async Task AWorkspaceNeverLoadsAnotherWorkspacesRecords()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        var second = D1EntitlementHarness.Uuid(0xB2);
        await harness.Bridge.SeedWorkspaceAsync(Guid.Parse(second), T.Ct);
        var workspaces = new List<(string Workspace, int Salt)> { (D1EntitlementHarness.Workspace, 0x100), (second, 0x200) };
        foreach (var (workspace, salt) in workspaces)
        {
            var state = await harness.Store.LoadAsync(workspace, T.Ct);
            var grant = new Grant(Id(salt + 1), workspace, GrantKind.Capability, "cloud.sync", new CapabilityValue(), GrantSource.AdminGrant, "ticket-" + salt,
                Fixtures.T(0), null, "operator", Fixtures.T(5), "isolation");
            var term = D1EntitlementHarness.TermRow(Fixtures.Term(Id(salt + 2), 0, 30 * Fixtures.Day, createdSeconds: 5), "period-" + salt) with { RealmId = Id(salt + 3) };
            var records = state.Records with { Grants = [grant], Terms = [term.Fact] };
            Assert.Equal(CommitOutcome.Committed, await harness.Store.CommitAsync(
                workspace, 0, EntitlementAppend.None with { Grants = [grant], Terms = [term] }, EntitlementResolver.Resolve(records, Fixtures.Definitions(), Fixtures.T(6)), T.Ct));
            var revocation = new Revocation(Id(salt + 4), grant.GrantId, "refund", Fixtures.T(7), "operator", Fixtures.T(7));
            var action = new TermActionRow(Id(salt + 5), "action-" + salt, new TermActionFact(term.Fact.TermId, ServiceTermActionKind.Revoke, Fixtures.T(8), Fixtures.T(8)), null);
            var after = records with { Revocations = [revocation], TermActions = [action.Fact] };
            Assert.Equal(CommitOutcome.Committed, await harness.Store.CommitAsync(
                workspace, 1, EntitlementAppend.None with { Revocations = [revocation], TermActions = [action] }, EntitlementResolver.Resolve(after, Fixtures.Definitions(), Fixtures.T(9)), T.Ct));
        }

        foreach (var (workspace, salt) in workspaces)
        {
            var loaded = (await harness.Store.LoadAsync(workspace, T.Ct)).Records;
            Assert.Equal([Id(salt + 1)], loaded.Grants.Select(g => g.GrantId));
            Assert.Equal([Id(salt + 4)], loaded.Revocations.Select(r => r.RevocationId));
            Assert.Equal([Id(salt + 2)], loaded.Terms.Select(x => x.TermId));
            Assert.Equal([Id(salt + 2)], loaded.TermActions.Select(x => x.TermId));
        }
    }

    [Fact]
    public async Task AReasonWithAnUnpairedSurrogateIsRefusedAndAPairedOneRoundTripsExactly()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        harness.At(10);
        var state = await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct);
        var broken = AdminGrantWithReason(Id(0x91), "bad \ud800 reason");
        await Assert.ThrowsAsync<ArgumentException>(async () => await harness.Store.CommitAsync(D1EntitlementHarness.Workspace, 0, Append(broken), Snapshot(state, broken, 6), T.Ct));
        Assert.Equal(0, await harness.Count("entitlement_grant"));

        var emoji = "ok \ud83d\ude00 reason";
        var issued = await harness.Issue(Fixtures.Capability("cloud.sync", 0, null, "TICKET-1", GrantSource.AdminGrant, emoji));
        Assert.Equal(emoji, issued.Reason);
        Assert.Equal(emoji, (await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct)).Records.Grants.Single().Reason);
    }

    [Fact]
    public async Task AFeatureReleaseIsAppendedOnceAndAReplayOrAConflictChangesNothing()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        var release = new FeatureReleaseFact("feature.ai", Fixtures.T(50));

        Assert.Equal(FeatureReleaseOutcome.Released, await harness.Store.AppendFeatureReleaseAsync(release, T.Ct));
        Assert.Equal(FeatureReleaseOutcome.AlreadyReleased, await harness.Store.AppendFeatureReleaseAsync(release, T.Ct));
        Assert.Equal(FeatureReleaseOutcome.Conflict, await harness.Store.AppendFeatureReleaseAsync(release with { ReleasedAt = Fixtures.T(60) }, T.Ct));

        Assert.Equal([["feature.ai", "50000000"]], (await harness.Bridge.QueryAsync("SELECT feature_key, released_at FROM entitlement_feature_release", T.Ct)).Select(r => r.Cast<string>().ToArray()));
        Assert.Contains("af_immutable", await harness.Bridge.RefusalAsync("UPDATE entitlement_feature_release SET released_at = 1", T.Ct), StringComparison.Ordinal);
        Assert.Throws<ArgumentException>(() => harness.Store.AppendFeatureReleaseAsync(new FeatureReleaseFact("Not A Key", Fixtures.T(1)), T.Ct).AsTask().GetAwaiter().GetResult());
    }

    [Fact]
    public async Task ARepeatedStatusFactReferenceOrAMissingWorkspaceTermIsRefusedAndNothingCommits()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        harness.At(10);
        await harness.Issue(Fixtures.Capability("cloud.sync", 0, null, "order-1"));
        var fact = new StatusFactRow(Id(0x82), "status-1", new WorkspaceStatusFact(Fixtures.T(30), WorkspaceStatus.Suspended, true, false));
        await harness.AppendCommitted(EntitlementAppend.None with { StatusFacts = [fact] }, 30);
        var before = await harness.Count("platform_command");

        var again = fact with { FactId = Id(0x83), Fact = fact.Fact with { RecordedAt = Fixtures.T(40) } };
        await Assert.ThrowsAsync<EntitlementStoreException>(async () => await harness.Append(EntitlementAppend.None with { StatusFacts = [again] }, 40));
        Assert.Equal(before, await harness.Count("platform_command"));
        Assert.Equal(1, await harness.Count("entitlement_workspace_status_fact"));

        // A term of a workspace that does not exist violates the foreign key of the model.
        var strangerTerm = D1EntitlementHarness.TermRow(Fixtures.Term(Id(0x71), 0, Fixtures.Day, createdSeconds: 41), "period-x");
        using var other = await D1EntitlementHarness.CreateAsync();
        await other.Bridge.ExecAsync("DELETE FROM workspace_workspace", T.Ct);
        await Assert.ThrowsAsync<EntitlementStoreException>(async () => await other.Append(D1EntitlementHarness.Terms(strangerTerm), 41));
        Assert.Equal(0, await other.Count("entitlement_service_term"));
        Assert.Equal(0, await other.Count("entitlement_revision"));
    }

    [Fact]
    public async Task AStoredValueThatDoesNotReadBackAsARecordIsADefectNotAGuess()
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        harness.At(10);
        await harness.Issue(Fixtures.Quota("cloud.storage.bytes", 5, 0, null, "order-1"));

        await harness.Bridge.ExecAsync("UPDATE entitlement_snapshot SET features = json_remove(features, '$.service')", T.Ct);
        var snapshotDefect = await Assert.ThrowsAsync<EntitlementStoreException>(async () => await harness.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct));
        Assert.Equal(EntitlementStoreFailure.Defect, snapshotDefect.Failure);

        using var second = await D1EntitlementHarness.CreateAsync();
        second.At(10);
        await second.Issue(Fixtures.Quota("cloud.storage.bytes", 5, 0, null, "order-1"));
        await second.Bridge.ExecAsync(
            "INSERT INTO entitlement_grant (grant_id, workspace_id, kind, subject, value, source, source_ref, effective_from, effective_until, issued_by_actor, created_at, reason) VALUES ('"
            + Id(0x501) + "', '" + D1EntitlementHarness.Workspace + "', 2, 'cloud.storage.bytes', '{\"limit\":5}', 1, 'tamper', 0, NULL, 'x', 1, NULL)", T.Ct);
        var valueDefect = await Assert.ThrowsAsync<EntitlementStoreException>(async () => await second.Store.LoadAsync(D1EntitlementHarness.Workspace, T.Ct));
        Assert.Equal(EntitlementStoreFailure.Defect, valueDefect.Failure);
    }

    [Theory]
    [InlineData("ws1")]
    [InlineData("00000000-0000-4000-8000-0000000000B1")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("")]
    public async Task AWorkspaceIdentifierThatIsNotACanonicalLowerCaseUuidNeverReachesStorage(string workspace)
    {
        using var harness = await D1EntitlementHarness.CreateAsync();
        var calls = harness.Bridge.Calls;

        await Assert.ThrowsAsync<ArgumentException>(async () => await harness.Store.LoadAsync(workspace, T.Ct));

        Assert.Equal(calls, harness.Bridge.Calls);
    }

    private async Task<string> StoredComputedAt(D1EntitlementHarness harness) =>
        (await harness.Bridge.QueryAsync("SELECT computed_at FROM entitlement_snapshot", T.Ct)).Single()[0]!;

    private static EntitlementSnapshot Snapshot(EntitlementState state, Grant grant, long atSeconds) =>
        EntitlementResolver.Resolve(state.Records with { Grants = state.Records.Grants.Add(grant) }, Fixtures.Definitions(), Fixtures.T(atSeconds));
}
