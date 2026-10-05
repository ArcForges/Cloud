// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>A settable time source: the single authoritative clock of a test, never the machine clock.</summary>
internal sealed class SettableTimeProvider(DateTimeOffset start) : TimeProvider
{
    private DateTimeOffset now = start;

    public override DateTimeOffset GetUtcNow() => now;

    public void SetSeconds(long seconds) => now = DateTimeOffset.UnixEpoch.AddSeconds(seconds);
}

/// <summary>
/// A test-only substitute for the D1-backed Entitlement store. It implements the store port's contract (append-only records, one
/// atomic commit of records and snapshot, a revision that refuses a stale writer) and nothing about D1: it proves the resolver's logic
/// against that contract and proves nothing about real persistence.
/// </summary>
internal sealed class InMemoryEntitlementStore : IEntitlementStore
{
    private readonly object gate = new();
    private readonly Dictionary<string, (EntitlementRecordSet Records, EntitlementSnapshot? Snapshot, long Revision)> rows = new(StringComparer.Ordinal);
    private readonly List<FeatureReleaseFact> releases = [];

    /// <summary>Runs after a load and before the commit decision, to interleave another writer deterministically.</summary>
    public Func<Task>? BeforeNextCommit { get; set; }

    public int CommitCount { get; private set; }

    public ValueTask<EntitlementState> LoadAsync(string workspaceId, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            var row = Row(workspaceId);
            return ValueTask.FromResult(new EntitlementState(row.Records with { FeatureReleases = row.Records.FeatureReleases.AddRange(releases) }, row.Snapshot, row.Revision));
        }
    }

    public async ValueTask<CommitOutcome> CommitAsync(
        string workspaceId, long expectedRevision, EntitlementAppend append, EntitlementSnapshot snapshot, CancellationToken cancellationToken)
    {
        var hook = BeforeNextCommit;
        BeforeNextCommit = null;
        if (hook is not null) await hook().ConfigureAwait(false);
        lock (gate)
        {
            var row = Row(workspaceId);
            if (row.Revision != expectedRevision) return CommitOutcome.RevisionConflict;
            var records = row.Records with
            {
                Grants = row.Records.Grants.AddRange(append.Grants),
                Revocations = row.Records.Revocations.AddRange(append.Revocations),
                Activations = row.Records.Activations.AddRange(append.Activations),
                Terms = row.Records.Terms.AddRange(append.Terms.Select(term => term.Fact)),
                TermActions = row.Records.TermActions.AddRange(append.TermActions.Select(action => action.Fact)),
                StatusFacts = row.Records.StatusFacts.AddRange(append.StatusFacts.Select(fact => fact.Fact)),
            };
            rows[workspaceId] = (records, snapshot, row.Revision + 1);
            CommitCount++;
            return CommitOutcome.Committed;
        }
    }

    public ValueTask<FeatureReleaseOutcome> AppendFeatureReleaseAsync(FeatureReleaseFact release, CancellationToken cancellationToken)
    {
        lock (gate)
        {
            var existing = releases.FirstOrDefault(candidate => candidate.Feature == release.Feature);
            if (existing is not null) return ValueTask.FromResult(existing == release ? FeatureReleaseOutcome.AlreadyReleased : FeatureReleaseOutcome.Conflict);
            releases.Add(release);
            return ValueTask.FromResult(FeatureReleaseOutcome.Released);
        }
    }

    /// <summary>Stands in for the owner admissions of other tasks (service terms, status facts, feature releases): it appends fact records directly.</summary>
    public void Insert(string workspaceId, Func<EntitlementRecordSet, EntitlementRecordSet> change)
    {
        lock (gate)
        {
            var row = Row(workspaceId);
            rows[workspaceId] = (change(row.Records), row.Snapshot, row.Revision + 1);
        }
    }

    /// <summary>Overwrites the stored snapshot, to simulate a defect or tampering that a rebuild must detect.</summary>
    public void ReplaceSnapshot(string workspaceId, EntitlementSnapshot snapshot)
    {
        lock (gate)
        {
            var row = Row(workspaceId);
            rows[workspaceId] = (row.Records, snapshot, row.Revision);
        }
    }

    public EntitlementRecordSet Records(string workspaceId)
    {
        lock (gate) return Row(workspaceId).Records;
    }

    private (EntitlementRecordSet Records, EntitlementSnapshot? Snapshot, long Revision) Row(string workspaceId) =>
        rows.TryGetValue(workspaceId, out var row) ? row : (EntitlementRecordSet.Empty(workspaceId), null, 0);
}

internal sealed class SequentialIds : IEntitlementIdSource
{
    private long next;

    public string NewId() => "id" + Interlocked.Increment(ref next);
}

internal sealed class FixedDefinitions(EntitlementDefinitions definitions) : IEntitlementDefinitionSource
{
    public EntitlementDefinitions Definitions { get; set; } = definitions;

    public EntitlementDefinitions Current() => Definitions;
}

/// <summary>
/// The operations a scenario of the rebuild-equivalence suite uses, so the same accounts run over the in-memory store of COM.05 and over
/// the durable D1 store (COM.16). Facts are appended the way their owner admissions would, in one unit with a snapshot refresh.
/// </summary>
internal interface IScenario
{
    EntitlementService Service { get; }

    FixedDefinitions Definitions { get; }

    string WorkspaceId { get; }

    IScenario AtSeconds(long seconds);

    Task<EntitlementSnapshot> Read();

    Task<EntitlementSnapshot> Refresh();

    Task<Grant> Issue(IssueGrantRequest request);

    Task<Revocation> Revoke(string grantId, long expectedVersion, long? effectiveSeconds = null, string reason = "refund");

    Task AddTermFact(ServiceTermFact term);

    Task AddActionFact(TermActionFact action);

    Task AddStatusFact(WorkspaceStatusFact fact);

    Task AddReleaseFact(FeatureReleaseFact release);

    Task AssertRebuildEqual();
}

/// <summary>Everything a scenario needs: the definitions, the store, the one clock and the service under test.</summary>
internal sealed class EntitlementHarness : IScenario
{
    public const string Workspace = "ws1";

    public EntitlementHarness(bool selfHostRealm = false)
    {
        Definitions = new FixedDefinitions(Fixtures.Definitions(selfHostRealm));
        Clock = new SettableTimeProvider(DateTimeOffset.UnixEpoch);
        Store = new InMemoryEntitlementStore();
        Service = new EntitlementService(Store, Definitions, new SequentialIds(), Clock);
    }

    public FixedDefinitions Definitions { get; }

    public SettableTimeProvider Clock { get; }

    public InMemoryEntitlementStore Store { get; }

    public EntitlementService Service { get; }

    public string WorkspaceId => Workspace;

    public EntitlementHarness At(long seconds)
    {
        Clock.SetSeconds(seconds);
        return this;
    }

    IScenario IScenario.AtSeconds(long seconds) => At(seconds);

    Task IScenario.AddTermFact(ServiceTermFact term) => AddTerm(term);

    Task IScenario.AddActionFact(TermActionFact action) => AddAction(action);

    Task IScenario.AddStatusFact(WorkspaceStatusFact fact) => AddStatus(fact);

    Task IScenario.AddReleaseFact(FeatureReleaseFact release) => AddRelease(release);

    public async Task<EntitlementSnapshot> Read()
    {
        var result = await Service.ReadAsync(Workspace, CancellationToken.None);
        Assert.True(result.Succeeded, result.Detail);
        return result.Value!;
    }

    public async Task<EntitlementSnapshot> Refresh()
    {
        var result = await Service.RefreshAsync(Workspace, CancellationToken.None);
        Assert.True(result.Succeeded, result.Detail);
        return result.Value!;
    }

    public async Task<Grant> Issue(IssueGrantRequest request)
    {
        var result = await Service.IssueGrantAsync(request, CancellationToken.None);
        Assert.True(result.Succeeded, result.Detail);
        return result.Value!;
    }

    public async Task<Revocation> Revoke(string grantId, long expectedVersion, long? effectiveSeconds = null, string reason = "refund")
    {
        var result = await Service.RevokeGrantAsync(
            new RevokeGrantRequest(Workspace, grantId, reason, effectiveSeconds is { } s ? Fixtures.T(s) : null, "operator", expectedVersion), CancellationToken.None);
        Assert.True(result.Succeeded, result.Detail);
        return result.Value!;
    }

    /// <summary>Appends a fact record the way its owner admission would, in one unit with a snapshot refresh at the current instant.</summary>
    public async Task AddFact(Func<EntitlementRecordSet, EntitlementRecordSet> change)
    {
        Store.Insert(Workspace, change);
        await Refresh();
    }

    public Task AddTerm(ServiceTermFact term) => AddFact(records => records with { Terms = records.Terms.Add(term) });

    public Task AddAction(TermActionFact action) => AddFact(records => records with { TermActions = records.TermActions.Add(action) });

    public Task AddStatus(WorkspaceStatusFact fact) => AddFact(records => records with { StatusFacts = records.StatusFacts.Add(fact) });

    public Task AddRelease(FeatureReleaseFact release) => AddFact(records => records with { FeatureReleases = records.FeatureReleases.Add(release) });

    public async Task AssertRebuildEqual()
    {
        var report = await Service.VerifyRebuildAsync(Workspace, CancellationToken.None);
        Assert.True(report.Status is RebuildStatus.Equal or RebuildStatus.NoSnapshot, string.Join("; ", report.Differences));
    }
}

internal static class Fixtures
{
    public const long Day = 86_400;

    public static UtcMicros T(long seconds) => new(seconds * 1_000_000);

    public static EntitlementDefinitions Definitions(bool selfHost = false) => new(
        "bundle-1",
        [
            new CapabilityDefinition("cloud.sync", RequiresPaidTerm: true),
            new CapabilityDefinition("cloud.ai", RequiresPaidTerm: true, FeatureGate: "feature.ai"),
            new CapabilityDefinition("cloud.web_continuity", RequiresPaidTerm: true),
            new CapabilityDefinition("account.manage", RequiresPaidTerm: false),
        ],
        [
            new QuotaDefinition("cloud.storage.bytes", QuotaCombination.Sum),
            new QuotaDefinition("cloud.devices.max", QuotaCombination.Max),
            new QuotaDefinition("support.level", QuotaCombination.PriorityReplace),
        ],
        [new AllowanceDefinition("ai.capacity")],
        selfHost);

    public static IssueGrantRequest Capability(string subject, long fromSeconds, long? untilSeconds, string sourceRef,
        GrantSource source = GrantSource.Subscription, string? reason = null) =>
        new(EntitlementHarness.Workspace, GrantKind.Capability, subject, new CapabilityValue(), source, sourceRef, T(fromSeconds),
            untilSeconds is { } until ? T(until) : null, "commerce", reason);

    public static IssueGrantRequest Quota(string subject, long limit, long fromSeconds, long? untilSeconds, string sourceRef,
        GrantSource source = GrantSource.Subscription, long priority = 0, string? reason = null) =>
        new(EntitlementHarness.Workspace, GrantKind.Quota, subject, new QuotaValue(limit, priority), source, sourceRef, T(fromSeconds),
            untilSeconds is { } until ? T(until) : null, "commerce", reason);

    public static IssueGrantRequest Allowance(string subject, string plan, long fromSeconds, long? untilSeconds, string sourceRef, long priority = 0) =>
        new(EntitlementHarness.Workspace, GrantKind.Allowance, subject, new AllowanceValue(plan, priority), GrantSource.Subscription, sourceRef,
            T(fromSeconds), untilSeconds is { } until ? T(until) : null, "commerce", null);

    public static ServiceTermFact Term(string id, long startSeconds, long endSeconds, long? graceSeconds = null, long? authorizedSeconds = null,
        long createdSeconds = 0, ServiceTermKind kind = ServiceTermKind.Subscription) =>
        new(id, kind, T(startSeconds), T(endSeconds), graceSeconds is { } grace ? T(grace) : null, T(authorizedSeconds ?? startSeconds), T(createdSeconds));

    public static CapabilityResult Capability(EntitlementSnapshot snapshot, string key) => snapshot.Content.Capabilities.Single(c => c.Key == key);

    public static QuotaResult Quota(EntitlementSnapshot snapshot, string key) => snapshot.Content.Quotas.Single(q => q.Key == key);

    public static ImmutableArray<T> Arr<T>(params T[] items) => [.. items];
}
