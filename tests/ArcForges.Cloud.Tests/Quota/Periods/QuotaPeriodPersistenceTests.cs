// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
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
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Entitlement;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests.QuotaPeriods;

public sealed class QuotaPeriodPersistenceTests
{
    [Theory]
    [InlineData(128, false)]
    [InlineData(129, false)]
    [InlineData(256, false)]
    [InlineData(257, false)]
    [InlineData(128, true)]
    [InlineData(129, true)]
    [InlineData(256, true)]
    [InlineData(257, true)]
    public async Task CapturedMaterializerPublisherCurrentPeriodUsesSame256Utf8Bound(int byteLength, bool unicode)
    {
        using var h = await Harness.Create();
        var publisher = unicode ? new string('中', byteLength / 3) + new string('a', byteLength % 3) : new string('a', byteLength);
        Assert.Equal(byteLength, Encoding.UTF8.GetByteCount(publisher));
        var original = h.Authority.Current!;
        h.Authority.Current = new(original.RealmId, original.ConfigurationRevisionId, original.DocumentHash,
            original.ArtifactId, original.ArtifactProfile, original.ArtifactHash, original.VerifiedLength,
            original.DefinitionsVersion, original.RealmKind, publisher, original.ResolverDefinitions);
        var calls = h.Bridge.Calls;
        var result = await h.Source().ReadAsync(h.Realm, h.Workspace, T.Ct);
        if (byteLength > 256)
        {
            Assert.Equal(QuotaDefinitionStatus.Defect, result.Status);
            Assert.Null(result.Value);
            Assert.Equal(calls, h.Bridge.Calls);
            return;
        }
        Assert.Equal(QuotaDefinitionStatus.Succeeded, result.Status);
        Assert.Equal("paid-original", result.Value!.SelectedPeriod!.Term.PeriodRef);
        Assert.Equal(100, Assert.Single(result.Value.Quotas).Limit);
        Assert.Equal(1, result.Value.EntitlementRevision);
        Assert.Equal(1, result.Value.SnapshotVersion);
    }

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
        Assert.Equal(6, race.TermPages);
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
    public async Task ActualPublishedMaximumTextUsesBoundedPagesWithoutTruncatingHistory()
    {
        using var h = await Harness.Create();
        for (var i = 0; i < 3; i++)
        {
            var term = Guid.NewGuid(); var text = new string('x', 262143) + i;
            await h.AddTerm(term, text, 200_000_000 + i, 300_000_000 + i, i, T.Ct);
            await h.Bridge.ExecAsync($"INSERT INTO entitlement_service_term_action VALUES ('{Guid.NewGuid():D}','{term:D}',2,250000000,{1000001 + i},{Sql(text)},NULL);", T.Ct);
        }
        var pageCounts = new List<int>(); var rowBytes = new List<long>();
        var frames = new FrameObserver(h.Bridge);
        var actual = new ModulePlanPortFactory(frames, h.Bridge.Generation, h.Clock).For(EntitlementModule.Instance.Descriptor);
        var port = new PageObserver(actual, read =>
        {
            pageCounts.Add(read.Count);
            rowBytes.Add(read.Sum(r => 2048L + 6L * Encoding.UTF8.GetByteCount(r.Count == 11 ? r[4].AsOptionalText() ?? "" : r[5].AsOptionalText() ?? "")));
        });
        var result = await new D1QuotaPeriodStore(port).ReadAsync(h.Realm, h.Workspace, T.Ct);
        Assert.True(result.Status == QuotaDefinitionStatus.Succeeded, $"Status={result.Status}; pages={string.Join(",", pageCounts)}; bytes={string.Join(",", rowBytes)}"); Assert.Equal(4, result.Value!.Terms.Length); Assert.Equal(3, result.Value.Actions.Length);
        Assert.Equal(3, result.Value.Terms.Count(t => Encoding.UTF8.GetByteCount(t.PeriodRef) == 262144));
        Assert.All(result.Value.Actions, a => Assert.Equal(262144, Encoding.UTF8.GetByteCount(a.SourceRef)));
        Assert.All(rowBytes, size => Assert.InRange(size, 0, 196608));
        Assert.NotEmpty(frames.Lengths); Assert.All(frames.Lengths, length => Assert.InRange(length, 1, ExecutePlanResponseJson.MaxBytes));
        Assert.True(frames.Slices >= 6 * 16);
        Assert.Contains(4, pageCounts); Assert.Contains(3, pageCounts); Assert.Equal(2, pageCounts.Count(c => c == 0));
        Assert.Equal("paid-original", (await h.Source().ReadAsync(h.Realm, h.Workspace, T.Ct)).Value!.SelectedPeriod!.Term.PeriodRef);
    }

    [Fact]
    public async Task ActualUnicodeAndControlTextReconstructionPreservesPublishedBoundWithoutLargeFrames()
    {
        using var h = await Harness.Create(); var unicode = new string('中', 262143) + "0";
        var control = new string((char)1, 262143) + "1";
        await h.AddTerm(Guid.NewGuid(), unicode, 200_000_000, 300_000_000, 0, T.Ct);
        await h.AddTerm(Guid.NewGuid(), control, 200_000_001, 300_000_001, 0, T.Ct);
        var frames = new FrameObserver(h.Bridge);
        var actual = new ModulePlanPortFactory(frames, h.Bridge.Generation, h.Clock).For(EntitlementModule.Instance.Descriptor);
        var result = await new D1QuotaPeriodStore(actual).ReadAsync(h.Realm, h.Workspace, T.Ct);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, result.Status);
        Assert.True(result.Value!.Terms.Any(t => string.Equals(t.PeriodRef, unicode, StringComparison.Ordinal)));
        Assert.True(result.Value.Terms.Any(t => string.Equals(t.PeriodRef, control, StringComparison.Ordinal)));
        Assert.All(frames.Lengths, size => Assert.InRange(size, 1, ExecutePlanResponseJson.MaxBytes));
        var complete = new QuotaPeriodSource(new D1QuotaPeriodStore(actual), h.Profiles(), h.Authority, new QuotaDefinitionValidator(), h.Clock);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, (await complete.ReadAsync(h.Realm, h.Workspace, T.Ct)).Status);
    }

    [Fact]
    public async Task SliceTransportFailureOrBufferedCancellationNeverReturnsPartialHistory()
    {
        using var h = await Harness.Create();
        await h.AddTerm(Guid.NewGuid(), new string('x', 262144), 200_000_000, 300_000_000, 0, T.Ct);
        var unavailable = new SliceFailure(h.Bridge);
        var actual = new ModulePlanPortFactory(unavailable, h.Bridge.Generation, h.Clock).For(EntitlementModule.Instance.Descriptor);
        var result = await new D1QuotaPeriodStore(actual).ReadAsync(h.Realm, h.Workspace, T.Ct);
        Assert.Equal(QuotaDefinitionStatus.Unavailable, result.Status); Assert.Null(result.Value);
        using var cancel = new CancellationTokenSource();
        var port = new ReadIntercept(h.Port, read => { if (read.PlanId.EndsWith("-text", StringComparison.Ordinal)) cancel.Cancel(); return Task.CompletedTask; });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new D1QuotaPeriodStore(port).ReadAsync(h.Realm, h.Workspace, cancel.Token));
        Assert.Equal(QuotaDefinitionStatus.Succeeded, (await new D1QuotaPeriodStore(h.Port).ReadAsync(h.Realm, h.Workspace, T.Ct)).Status);
    }

    [Fact]
    public async Task ActualOversizedHistoryRefusesWithoutPartialProjectionAtPrivateWorkBudget()
    {
        using var h = await Harness.Create();
        await h.Bridge.ExecAsync($"WITH RECURSIVE cte_rows(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM cte_rows WHERE n<65) " +
            $"INSERT INTO entitlement_service_term SELECT '10000000-0000-0000-0000-' || printf('%012x',n),'{h.Workspace:D}','{h.Realm:D}',2,NULL," +
            $"replace(hex(zeroblob(131071)),'0','x') || printf('%02d',n),200000000+n,300000000,NULL,NULL,'{Guid.NewGuid():D}','{Guid.NewGuid():D}',200000000+n,0,1000000 FROM cte_rows;", T.Ct);
        var read = await new D1QuotaPeriodStore(h.Port).ReadAsync(h.Realm, h.Workspace, T.Ct);
        Assert.Equal(QuotaDefinitionStatus.Unavailable, read.Status); Assert.Null(read.Value);
        Assert.Equal(66, await h.Bridge.CountAsync("entitlement_service_term", cancellationToken: T.Ct));
    }

    [Fact]
    public async Task CompleteSnapshotColumnsAreReconstructedWithinActualGeneratedReplyBudget()
    {
        using var h = await Harness.Create(); var columns = await LargeSnapshot(h);
        Assert.True(columns.Capabilities.Length + columns.Quotas.Length + columns.Features.Length > ExecutePlanResponseJson.MaxBytes);
        Assert.All(new[] { columns.Capabilities, columns.Quotas, columns.Features }, text => Assert.InRange(text.Length, 1, 262144));
        var frames = new FrameObserver(h.Bridge);
        var actual = new ModulePlanPortFactory(frames, h.Bridge.Generation, h.Clock).For(EntitlementModule.Instance.Descriptor);
        var result = await new D1QuotaPeriodStore(actual).ReadAsync(h.Realm, h.Workspace, T.Ct);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, result.Status);
        Assert.Equal(2200, Assert.Single(result.Value!.Snapshot.Content.Quotas).Contributions.Length);
        Assert.Equal(1500, Assert.Single(result.Value.Snapshot.Content.Capabilities).SourceGrantIds.Length);
        Assert.Equal(1000, result.Value.Snapshot.Content.UnrecognizedGrantIds.Length);
        Assert.All(frames.Lengths, size => Assert.InRange(size, 1, ExecutePlanResponseJson.MaxBytes));
        Assert.True(frames.Slices > 30);
    }

    [Fact]
    public async Task MutableSnapshotChangingDuringSlicesNeverProducesMixedCurrentFacts()
    {
        using var h = await Harness.Create(); await LargeSnapshot(h); var changed = false;
        var port = new ReadIntercept(h.Port, async read =>
        {
            if (!changed && read.PlanId == "entitlement.quota-period-snapshot-text")
            {
                changed = true; await h.Bridge.ExecAsync("UPDATE entitlement_snapshot SET computed_at=computed_at+1; UPDATE entitlement_revision SET rev=rev+1;", T.Ct);
            }
        });
        var result = await new D1QuotaPeriodStore(port).ReadAsync(h.Realm, h.Workspace, T.Ct);
        Assert.True(changed); Assert.Equal(QuotaDefinitionStatus.Unavailable, result.Status); Assert.Null(result.Value);
    }

    private static async Task<SnapshotColumns> LargeSnapshot(Harness h)
    {
        static ImmutableArray<string> Ids(int count) => Enumerable.Range(0, count).Select(_ => Guid.NewGuid().ToString("D")).Order(StringComparer.Ordinal).ToImmutableArray();
        var contributors = Ids(2200).Select(id => new QuotaContribution(id, GrantSource.AdminGrant, 1)).ToImmutableArray();
        var snapshot = new EntitlementSnapshot(h.Workspace.ToString("D"), 1, new(5_000_000), new("actual-definitions",
            new(ServiceState.Active, new(100_000_000), null, true), [new("owner", true, EntitlementReason.Available, Ids(1500))],
            [new("storage", 2200, EntitlementReason.Available, contributors)], [], [], Ids(1000), [], new(100_000_000)));
        var columns = SnapshotMapper.ToColumns(snapshot);
        await h.Bridge.ExecAsync($"UPDATE entitlement_snapshot SET capabilities={Sql(columns.Capabilities)},quotas={Sql(columns.Quotas)},features={Sql(columns.Features)};", T.Ct);
        return columns;
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
    private sealed class SliceFailure(IPlanExecutor inner) : IPlanExecutor
    {
        public Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken ct) => call.Plan.Id.EndsWith("-text", StringComparison.Ordinal)
            ? throw new PlanFailureException(PlanFailureKind.Transport) : inner.ExecuteAsync(call, ct);
    }
    private sealed class FrameObserver(IPlanExecutor inner) : IPlanExecutor
    {
        internal readonly List<int> Lengths = []; internal int Slices;
        public async Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken ct)
        {
            var result = await inner.ExecuteAsync(call, ct);
            var frame = ExecutePlanResponseJson.Serialize(new ExecutePlanResponseExecutePlanSuccess(new ExecutePlanSuccess
            {
                RequestId = call.RequestId.ToString("D"),
                ManifestHash = PlanManifest.Hash,
                Rows = result.Rows.Select(r => r.ToArray()).ToArray(),
                Changes = result.Changes.ToString(System.Globalization.CultureInfo.InvariantCulture),
            }));
            Assert.InRange(frame.Length, 1, ExecutePlanResponseJson.MaxBytes); Lengths.Add(frame.Length);
            if (call.Plan.Id.EndsWith("-text", StringComparison.Ordinal)) Slices++;
            return result;
        }
    }
    private sealed class PageObserver(IModulePlanPort inner, Action<IReadOnlyList<IReadOnlyList<PlanValue>>> observe) : IModulePlanPort
    {
        public async Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken ct)
        {
            var result = await inner.ReadAsync(read, ct);
            if (read.PlanId is "entitlement.quota-period-terms" or "entitlement.quota-period-actions")
            {
                Assert.Equal(ModulePlanStatus.Succeeded, result.Status);
                observe(result.Rows);
            }
            return result;
        }
        public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken ct) => throw new InvalidOperationException("Read-only fixture must not write.");
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
