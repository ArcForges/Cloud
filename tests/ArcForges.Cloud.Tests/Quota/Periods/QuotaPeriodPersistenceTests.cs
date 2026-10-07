// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement;
using ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Application;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Quota.Periods.Application;
using ArcForges.Cloud.Modules.Entitlement.Quota.Periods.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Entitlement;
using Xunit;

namespace ArcForges.Cloud.Tests.QuotaPeriods;

public sealed class QuotaPeriodPersistenceTests
{
    [Fact]
    public async Task ActualOwnerRowsYieldSelectedPaidPeriodPositiveSnapshotAndRestartedHistory()
    {
        using var h = await Harness.Create();
        var value = (await h.Source().ReadAsync(h.Realm, h.Workspace, T.Ct)).Value;
        Assert.NotNull(value); Assert.Equal(1, value.EntitlementRevision); Assert.Equal(1, value.SnapshotVersion);
        Assert.Equal("paid-original", value.SelectedPeriod!.Term.PeriodRef);
        Assert.Equal(QuotaDefinitionUnit.Count, Assert.Single(value.Quotas).Definition.Unit);
        Assert.Equal(100, Assert.Single(value.Quotas).Limit);
        Assert.Equal(value.SelectedPeriod.PeriodKey, Assert.Single(value.Quotas).PeriodKey);
        var restarted = (await h.Source().ReadAsync(h.Realm, h.Workspace, T.Ct)).Value!;
        Assert.Equal(value.SnapshotHash, restarted.SnapshotHash); Assert.Equal(value.SelectedPeriod.PeriodKey, restarted.SelectedPeriod!.PeriodKey);
        Assert.Equal(100_000_000, value.ValidUntilMicros);
    }

    [Fact]
    public async Task ActualKeysetReadsAllRowsAndRetainsActionReplacementSourceAndKnowledge()
    {
        using var h = await Harness.Create();
        for (var i = 0; i < 102; i++) await h.AddTerm(Guid.NewGuid(), "later-" + i, 200_000_000 + i, 300_000_000 + i, i, T.Ct);
        var replacement = Guid.NewGuid(); await h.AddTerm(replacement, "replacement", 50_000_000, 150_000_000, 7, T.Ct);
        await h.Bridge.ExecAsync($"INSERT INTO entitlement_service_term_action VALUES ('{Guid.NewGuid():D}','{h.Term:D}',1,50000000,4000000,'actual-action','{replacement:D}');", T.Ct);
        var read = await new D1QuotaPeriodStore(h.Port).ReadAsync(h.Realm, h.Workspace, T.Ct);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, read.Status);
        Assert.Equal(104, read.Value!.Terms.Length);
        var action = Assert.Single(read.Value.Actions); Assert.Equal(replacement, action.ReplacementTermId); Assert.Equal("actual-action", action.SourceRef);
        var source = await h.Source().ReadAsync(h.Realm, h.Workspace, T.Ct);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, source.Status); Assert.Equal(50_000_000, source.Value!.SelectedPeriod!.EligibleUntilMicros);
    }

    [Fact]
    public async Task CurrentConfigurationRaceAndElapsedSnapshotNeverReturnOldAuthority()
    {
        using var h = await Harness.Create();
        h.Authority.AfterFirstCurrent = () => h.Authority.Current = h.Association(Guid.NewGuid());
        Assert.Equal(QuotaDefinitionStatus.Stale, (await h.Source().ReadAsync(h.Realm, h.Workspace, T.Ct)).Status);
        h.Authority.AfterFirstCurrent = null; h.Authority.Current = h.Association(h.Revision);
        h.Clock.SetSeconds(100);
        Assert.Equal(QuotaDefinitionStatus.Stale, (await h.Source().ReadAsync(h.Realm, h.Workspace, T.Ct)).Status);
        Assert.Null((await h.Source().ReadAsync(h.Realm, h.Workspace, T.Ct)).Value);
    }

    [Fact]
    public async Task ActualRevisionRacesRestartBoundedlyAndCorruptOrCrossRealmRowsFailClosed()
    {
        using var h = await Harness.Create();
        var race = new ReadIntercept(h.Port, async read =>
        {
            if (read.PlanId == "entitlement.quota-period-terms") await h.Bridge.ExecAsync("UPDATE entitlement_revision SET rev=rev+1;", T.Ct);
        });
        Assert.Equal(QuotaDefinitionStatus.Unavailable, (await new D1QuotaPeriodStore(race).ReadAsync(h.Realm, h.Workspace, T.Ct)).Status);
        Assert.Equal(3, race.TermPages);
        Assert.Equal(QuotaDefinitionStatus.Defect, (await new D1QuotaPeriodStore(h.Port).ReadAsync(Guid.NewGuid(), h.Workspace, T.Ct)).Status);
        await h.Bridge.ExecAsync("UPDATE entitlement_revision SET rev=0;", T.Ct);
        Assert.Equal(QuotaDefinitionStatus.Defect, (await new D1QuotaPeriodStore(h.Port).ReadAsync(h.Realm, h.Workspace, T.Ct)).Status);
    }

    [Fact]
    public async Task CallerCancellationAfterActualReadAndMissingProducersRefuseWithoutValues()
    {
        using var h = await Harness.Create(); using var cancel = new CancellationTokenSource();
        var port = new ReadIntercept(h.Port, read => { cancel.Cancel(); return Task.CompletedTask; });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new D1QuotaPeriodStore(port).ReadAsync(h.Realm, h.Workspace, cancel.Token));
        var missing = new QuotaPeriodSource(new D1QuotaPeriodStore(h.Port), h.Profiles(), null, new QuotaDefinitionValidator(), h.Clock);
        Assert.Equal(QuotaDefinitionStatus.Unavailable, (await missing.ReadAsync(h.Realm, h.Workspace, T.Ct)).Status);
        Assert.Equal(QuotaDefinitionStatus.Invalid, (await missing.ReadAsync(Guid.Empty, h.Workspace, T.Ct)).Status);
        Assert.Equal(QuotaDefinitionStatus.NotFound, (await new D1QuotaPeriodStore(h.Port).ReadAsync(h.Realm, Guid.NewGuid(), T.Ct)).Status);
    }

    [Fact]
    public async Task InvalidCurrentArtifactMetadataRefusesBeforeAnySnapshotReads()
    {
        using var h = await Harness.Create(); var actual = h.Authority.Current!; var calls = h.Bridge.Calls;
        h.Authority.Current = new(actual.RealmId, actual.ConfigurationRevisionId, actual.DocumentHash, actual.ArtifactId,
            "unsupported-profile", actual.ArtifactHash, actual.VerifiedLength, actual.DefinitionsVersion, actual.RealmKind, actual.PublisherRef, actual.ResolverDefinitions);
        var result = await h.Source().ReadAsync(h.Realm, h.Workspace, T.Ct);
        Assert.Equal(QuotaDefinitionStatus.Defect, result.Status); Assert.Null(result.Value); Assert.Equal(calls, h.Bridge.Calls);
    }

    private sealed class Harness : IDisposable
    {
        internal Guid Realm { get; } = Guid.NewGuid(); internal Guid Workspace { get; } = Guid.NewGuid();
        internal Guid Revision { get; } = Guid.NewGuid(); internal Guid Term { get; } = Guid.NewGuid();
        internal SqliteBridgeExecutor Bridge { get; } = new();
        internal SettableTimeProvider Clock { get; } = new(DateTimeOffset.UnixEpoch.AddSeconds(10));
        internal IModulePlanPort Port { get; }
        internal Authority Authority { get; } = new();
        private readonly byte[] profile = QuotaDefinitionValidator.Encode("actual-definitions", [new("storage", QuotaDefinitionCombination.Sum, QuotaDefinitionUnit.Count, QuotaDefinitionMode.EntitlementPeriod)]);
        private Harness() => Port = new ModulePlanPortFactory(Bridge, Bridge.Generation, Clock).For(EntitlementModule.Instance.Descriptor);
        internal static async Task<Harness> Create()
        {
            var h = new Harness();
            try
            {
                var pending = Path.Combine(T.RepoRoot().FullName, "src", "ArcForges.Cloud.Storage.D1", "Migrations", "pending", "entitlement__quota-definition-profile.sql");
                if (File.Exists(pending)) await h.Bridge.ExecAsync(await File.ReadAllTextAsync(pending, T.Ct), T.Ct);
                await h.Bridge.SeedWorkspaceAsync(h.Workspace, T.Ct);
                await h.Bridge.ExecAsync($"UPDATE workspace_workspace SET realm_id='{h.Realm:D}' WHERE workspace_id='{h.Workspace:D}';", T.Ct);
                await h.AddTerm(h.Term, "paid-original", 1_000_000, 100_000_000, -1, T.Ct);
                var snapshot = new EntitlementSnapshot(h.Workspace.ToString("D"), 1, new(5_000_000), new("actual-definitions", new(ServiceState.Active, new(100_000_000), null, true), [],
                    [new("storage", 100, EntitlementReason.Available, [])], [], [], [], [], new(100_000_000)));
                var columns = SnapshotMapper.ToColumns(snapshot); var hash = Convert.ToHexStringLower(SHA256.HashData(h.profile));
                await h.Bridge.ExecAsync($"INSERT INTO entitlement_revision VALUES ('{h.Workspace:D}',1,5000000); INSERT INTO entitlement_snapshot VALUES ('{h.Workspace:D}',1,5000000,100000000,{Sql(columns.Capabilities)},{Sql(columns.Quotas)},{Sql(columns.Features)});" +
                    $"INSERT INTO entitlement_quota_definition_profile VALUES ('{h.Realm:D}','actual-definitions',X'{hash}',{Sql(Encoding.UTF8.GetString(h.profile))},'artifact:actual',X'{hash}',{h.profile.Length},1000000);", T.Ct);
                h.Authority.Current = h.Association(h.Revision); return h;
            }
            catch { h.Dispose(); throw; }
        }
        internal ApprovedQuotaConfiguration Association(Guid revision) => new(Realm, revision, new('a', 64), "artifact:actual", QuotaDefinitionValidator.ProfileName,
            Convert.ToHexStringLower(SHA256.HashData(profile)), profile.Length, "actual-definitions", "official", "config:publisher", [new("storage", QuotaDefinitionCombination.Sum)]);
        internal QuotaDefinitionService Profiles() => new(new D1QuotaDefinitionStore(Port), null, null, null, new QuotaDefinitionValidator(), Clock);
        internal QuotaPeriodSource Source() => new(new D1QuotaPeriodStore(Port), Profiles(), Authority, new QuotaDefinitionValidator(), Clock);
        internal Task AddTerm(Guid id, string reference, long start, long end, long priority, CancellationToken ct) => Bridge.ExecAsync(
            $"INSERT INTO entitlement_service_term VALUES ('{id:D}','{Workspace:D}','{Realm:D}',2,NULL,{Sql(reference)},{start},{end},NULL,NULL,'{Guid.NewGuid():D}','{Guid.NewGuid():D}',{start},{priority},1000000);", ct);
        public void Dispose() => Bridge.Dispose();
    }
    private static string Sql(string value) => "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
    // Only the unavailable signed Config producer is replaced; snapshot/profile/terms/actions and all reads execute actual owner plans.
    private sealed class Authority : IQuotaApprovedConfigurationSource
    {
        internal ApprovedQuotaConfiguration? Current; internal Action? AfterFirstCurrent; private int reads;
        public Task<QuotaConfigurationResult> ReadCurrentAsync(Guid realm, CancellationToken ct)
        {
            var value = Current; if (++reads == 1) AfterFirstCurrent?.Invoke(); return Task.FromResult(new QuotaConfigurationResult(QuotaDefinitionStatus.Succeeded, value));
        }
        public Task<QuotaConfigurationResult> ReadHistoricalAsync(Guid realm, Guid revision, string hash, CancellationToken ct) => throw new InvalidOperationException("Read-only period source does not publish.");
    }
    private sealed class ReadIntercept(IModulePlanPort inner, Func<ModulePlanRead, Task> afterRead) : IModulePlanPort
    {
        internal int TermPages;
        public async Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken ct)
        {
            var result = await inner.ReadAsync(read, ct); if (read.PlanId == "entitlement.quota-period-terms") TermPages++;
            await afterRead(read); return result;
        }
        public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken ct) => throw new InvalidOperationException("Read-only fixture must not write.");
    }
}
