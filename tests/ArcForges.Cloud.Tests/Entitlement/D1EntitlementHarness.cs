// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement;
using ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using ArcForges.Cloud.Storage.ModuleBinding;
using Xunit;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>Allocates identifiers in the canonical lower-case UUID form the physical schema requires, deterministically.</summary>
internal sealed class UuidIds(int start = 0x1000) : IEntitlementIdSource
{
    private int next = start;

    public string NewId() => D1EntitlementHarness.Uuid(Interlocked.Increment(ref next));
}

/// <summary>
/// The real resolver service over the real durable store: the Entitlement service and the D1 store run the production named plans on the
/// SQLite oracle through the bridge (the same Worker plan code the signed executor reaches). One clock, one definitions source and one
/// workspace, like <see cref="EntitlementHarness"/>, so the COM.05 scenarios can be repeated over D1-stored records.
/// </summary>
internal sealed class D1EntitlementHarness : IScenario, IDisposable
{
    public static readonly string Workspace = Uuid(0xB1);

    private D1EntitlementHarness(bool selfHostRealm)
    {
        Bridge = new SqliteBridgeExecutor();
        Clock = new SettableTimeProvider(DateTimeOffset.UnixEpoch);
        Definitions = new FixedDefinitions(Fixtures.Definitions(selfHostRealm));
        Port = new ModulePlanPortFactory(Bridge, Bridge.Generation, Clock).For(EntitlementModule.Instance.Descriptor);
        Store = new D1EntitlementStore(Port);
        Service = new EntitlementService(Store, Definitions, new UuidIds(), Clock);
    }

    public SqliteBridgeExecutor Bridge { get; }

    public SettableTimeProvider Clock { get; }

    public FixedDefinitions Definitions { get; }

    public IModulePlanPort Port { get; }

    public D1EntitlementStore Store { get; }

    public EntitlementService Service { get; }

    public static string Uuid(int n) => $"00000000-0000-4000-8000-{n:x12}";

    public static async Task<D1EntitlementHarness> CreateAsync(bool selfHostRealm = false)
    {
        var harness = new D1EntitlementHarness(selfHostRealm);
        await harness.Bridge.SeedWorkspaceAsync(Guid.Parse(Workspace), T.Ct);
        return harness;
    }

    public D1EntitlementHarness At(long seconds)
    {
        Clock.SetSeconds(seconds);
        return this;
    }

    private readonly UuidIds rowIds = new(0x5000);
    private int references;

    public string WorkspaceId => Workspace;

    IScenario IScenario.AtSeconds(long seconds) => At(seconds);

    /// <summary>The scenarios name terms "t1" and "pass-t"; the physical schema needs canonical UUIDs, so a name maps to a stable one.</summary>
    public static string Mapped(string name)
    {
        if (Guid.TryParseExact(name, "D", out var parsed) && parsed.ToString("D") == name) return name;
        var bytes = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes("term:" + name));
        return new Guid(bytes.AsSpan(0, 16)).ToString("D");
    }

    Task IScenario.AddTermFact(ServiceTermFact term) => AddTerm(term with { TermId = Mapped(term.TermId) }, "period-" + term.TermId);

    async Task IScenario.AddActionFact(TermActionFact action)
    {
        var row = new TermActionRow(rowIds.NewId(), "action-" + Interlocked.Increment(ref references), action with { TermId = Mapped(action.TermId) }, null);
        await AppendCommitted(EntitlementAppend.None with { TermActions = [row] }, Clock.GetUtcNow().ToUnixTimeSeconds());
    }

    async Task IScenario.AddStatusFact(WorkspaceStatusFact fact)
    {
        var row = new StatusFactRow(rowIds.NewId(), "status-" + Interlocked.Increment(ref references), fact);
        await AppendCommitted(EntitlementAppend.None with { StatusFacts = [row] }, Clock.GetUtcNow().ToUnixTimeSeconds());
    }

    async Task IScenario.AddReleaseFact(FeatureReleaseFact release)
    {
        Assert.Equal(FeatureReleaseOutcome.Released, await Store.AppendFeatureReleaseAsync(release, T.Ct));
        await Refresh();
    }

    public IssueGrantRequest ForWorkspace(IssueGrantRequest request) => request with { WorkspaceId = Workspace };

    public async Task<EntitlementSnapshot> Read()
    {
        var result = await Service.ReadAsync(Workspace, T.Ct);
        Assert.True(result.Succeeded, result.Detail);
        return result.Value!;
    }

    public async Task<EntitlementSnapshot> Refresh()
    {
        var result = await Service.RefreshAsync(Workspace, T.Ct);
        Assert.True(result.Succeeded, result.Detail);
        return result.Value!;
    }

    public async Task<Grant> Issue(IssueGrantRequest request)
    {
        var result = await Service.IssueGrantAsync(ForWorkspace(request), T.Ct);
        Assert.True(result.Succeeded, result.Detail);
        return result.Value!;
    }

    public async Task<Revocation> Revoke(string grantId, long expectedVersion, long? effectiveSeconds = null, string reason = "refund")
    {
        var result = await Service.RevokeGrantAsync(
            new RevokeGrantRequest(Workspace, grantId, reason, effectiveSeconds is { } s ? Fixtures.T(s) : null, "operator", expectedVersion), T.Ct);
        Assert.True(result.Succeeded, result.Detail);
        return result.Value!;
    }

    /// <summary>
    /// Appends records through the store's own write path, the way an owner admission would: the resolver derives the snapshot over the
    /// stored records plus the append, and the store commits both under the revision it read.
    /// </summary>
    public async Task<CommitOutcome> Append(EntitlementAppend append, long atSeconds)
    {
        var state = await Store.LoadAsync(Workspace, T.Ct);
        var records = state.Records with
        {
            Grants = state.Records.Grants.AddRange(append.Grants),
            Revocations = state.Records.Revocations.AddRange(append.Revocations),
            Terms = state.Records.Terms.AddRange(append.Terms.Select(row => row.Fact)),
            TermActions = state.Records.TermActions.AddRange(append.TermActions.Select(row => row.Fact)),
            StatusFacts = state.Records.StatusFacts.AddRange(append.StatusFacts.Select(row => row.Fact)),
            Activations = state.Records.Activations.AddRange(append.Activations),
        };
        // Like the service, a write is stamped strictly after the stored computation, so the effective time never moves backwards.
        var at = state.Snapshot is { } stored ? UtcMicros.Max(Fixtures.T(atSeconds), new UtcMicros(stored.ComputedAt.Value + 1)) : Fixtures.T(atSeconds);
        var snapshot = EntitlementResolver.Resolve(records, Definitions.Current(), at);
        return await Store.CommitAsync(Workspace, state.Revision, append, snapshot, T.Ct);
    }

    public async Task AppendCommitted(EntitlementAppend append, long atSeconds) => Assert.Equal(CommitOutcome.Committed, await Append(append, atSeconds));

    /// <summary>Appends one term at the current instant of the clock, the way the term owner admission would.</summary>
    public Task AddTerm(ServiceTermFact fact, string? period = null) =>
        AppendCommitted(Terms(TermRow(fact, period ?? "period-" + fact.TermId[^4..])), Clock.GetUtcNow().ToUnixTimeSeconds());

    public static ServiceTermRow TermRow(ServiceTermFact fact, string period, string? subscription = "sub-1", string? supersedes = null) =>
        new(fact, Uuid(0xC1), fact.Kind == ServiceTermKind.Subscription ? subscription : null, period, supersedes, Uuid(0xC2), Uuid(0xC3), 0);

    public static EntitlementAppend Terms(params ServiceTermRow[] terms) => EntitlementAppend.None with { Terms = [.. terms] };

    public async Task AssertRebuildEqual()
    {
        var report = await Service.VerifyRebuildAsync(Workspace, T.Ct);
        Assert.True(report.Status is RebuildStatus.Equal or RebuildStatus.NoSnapshot, string.Join("; ", report.Differences));
    }

    public Task<long> Count(string table, string where = "1 = 1") => Bridge.CountAsync(table, where, T.Ct);

    public void Dispose() => Bridge.Dispose();

    public static ImmutableArray<T> Items<T>(params T[] items) => [.. items];
}
