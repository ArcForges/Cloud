// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Application;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Domain;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Storage.Platform;
using ArcForges.Cloud.Tests.Entitlement;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.QuotaDefinitions;

public sealed class VersionedQuotaResolverDefinitionSourceTests
{
    [Fact]
    public async Task ActualIndexedCompatibilityDetectsMeaningDriftAndSameVersionChangesBeforeAnyPublication()
    {
        using var h = await Harness.Create();
        await h.Publish("v1", "official", ResolverDefinitionCombination.Sum);
        await h.PublishUnit();
        var check = h.Services.GetRequiredService<IQuotaDefinitionCompatibilityPort>();
        foreach (var changed in new[]
        {
            new QuotaSemanticDefinition("storage", QuotaDefinitionCombination.Sum, QuotaDefinitionUnit.Count, QuotaDefinitionMode.Gauge),
            new QuotaSemanticDefinition("storage", QuotaDefinitionCombination.Sum, QuotaDefinitionUnit.Bytes, QuotaDefinitionMode.EntitlementPeriod),
            new QuotaSemanticDefinition("storage", QuotaDefinitionCombination.Max, QuotaDefinitionUnit.Bytes, QuotaDefinitionMode.Gauge),
        }) Assert.Equal(QuotaDefinitionStatus.Conflict, await check.CheckAsync(h.Realm, Profile("next", [changed]), T.Ct));
        Assert.Equal(QuotaDefinitionStatus.Succeeded, await check.CheckAsync(h.Realm, Profile("removed", []), T.Ct));
        Assert.Equal(QuotaDefinitionStatus.Succeeded, await check.CheckAsync(h.Realm, Profile("reintroduced", [Unit()]), T.Ct));
        Assert.Equal(QuotaDefinitionStatus.Conflict, await check.CheckAsync(h.Realm, Profile("v1", [Unit(), Unit("zz.new")]), T.Ct));
        var restarted = new QuotaDefinitionCompatibilityPort(new D1QuotaDefinitionStore(h.Plans.For(EntitlementModule.Instance.Descriptor)),
            new QuotaDefinitionValidator(), h.Authority);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, await restarted.CheckAsync(h.Realm, Profile("reintroduced", [Unit()]), T.Ct));
        Assert.Equal(1, await h.Bridge.CountAsync("entitlement_quota_definition_profile", "1=1", T.Ct));
        Assert.Equal(1, await h.Bridge.CountAsync("entitlement_quota_definition_key", "1=1", T.Ct));
        Assert.Equal(2, await h.Bridge.CountAsync("platform_change_archive", "1=1", T.Ct));
    }

    [Fact]
    public async Task CompatibilityRejectsForgedDtoAndBoundsBeforeOwnerReadWithoutConferringApproval()
    {
        using var h = await Harness.Create();
        var store = new AfterCheck(new D1QuotaDefinitionStore(h.Plans.For(EntitlementModule.Instance.Descriptor)), () => Task.CompletedTask);
        var port = new QuotaDefinitionCompatibilityPort(store, new QuotaDefinitionValidator(), h.Authority);
        var original = Profile("candidate", [Unit()]);
        var forged = new QuotaSemanticProfile(original.DefinitionsVersion, original.Hash, original.CanonicalBytes,
            [Unit() with { Unit = QuotaDefinitionUnit.Count }]);
        Assert.Equal(QuotaDefinitionStatus.Invalid, await port.CheckAsync(h.Realm, forged, T.Ct));
        var excess = Enumerable.Range(0, 65).Select(n => Unit($"q{n:D3}")).ToArray();
        var tooMany = new QuotaSemanticProfile("candidate", original.Hash, original.CanonicalBytes, excess);
        Assert.Equal(QuotaDefinitionStatus.Invalid, await port.CheckAsync(h.Realm, tooMany, T.Ct));
        Assert.Equal(QuotaDefinitionStatus.Denied, await port.CheckAsync(Guid.NewGuid(), original, T.Ct));
        Assert.Equal(0, store.Checks);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, await port.CheckAsync(h.Realm, Profile("candidate", excess.Take(64).ToArray()), T.Ct));
        Assert.Equal(1, store.Checks);
        Assert.Equal(0, await h.Bridge.CountAsync("entitlement_quota_definition_profile", "1=1", T.Ct));
        Assert.Equal(0, await h.Bridge.CountAsync("platform_command", "1=1", T.Ct));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BufferedActualCompatibilityAnswerCannotOutliveCancellationOrRecoveryAuthority(bool cancel)
    {
        using var h = await Harness.Create();
        using var canceled = CancellationTokenSource.CreateLinkedTokenSource(T.Ct);
        var store = new AfterCheck(new D1QuotaDefinitionStore(h.Plans.For(EntitlementModule.Instance.Descriptor)), async () =>
        {
            if (cancel) canceled.Cancel();
            else await h.Bridge.ExecAsync("UPDATE platform_recovery_epoch SET state=1,rev=rev+1;", T.Ct);
        });
        var port = new QuotaDefinitionCompatibilityPort(store, new QuotaDefinitionValidator(), h.Authority);
        if (cancel) await Assert.ThrowsAnyAsync<OperationCanceledException>(() => port.CheckAsync(h.Realm, Profile("candidate", [Unit()]), canceled.Token));
        else Assert.Equal(QuotaDefinitionStatus.Unavailable, await port.CheckAsync(h.Realm, Profile("candidate", [Unit()]), canceled.Token));
        Assert.Equal(1, store.Checks);
        Assert.Equal(0, await h.Bridge.CountAsync("platform_command", "1=1", T.Ct));
    }

    private static QuotaSemanticDefinition Unit(string key = "storage") => new(key, QuotaDefinitionCombination.Sum, QuotaDefinitionUnit.Bytes, QuotaDefinitionMode.Gauge);
    private static QuotaSemanticProfile Profile(string version, QuotaSemanticDefinition[] definitions)
    {
        var bytes = QuotaDefinitionValidator.Encode(version, definitions);
        return new(version, Convert.ToHexStringLower(SHA256.HashData(bytes)), bytes, definitions);
    }
    [Fact]
    public async Task ActualProductionDIReadsAcceptedHistoricalAndCurrentVersionsWithoutLegacyResolverOrDefault()
    {
        using var h = await Harness.Create();
        await h.Publish("v1", "official", ResolverDefinitionCombination.Sum);
        await h.Publish("v2", "selfHosted", ResolverDefinitionCombination.Max);
        Assert.Null(h.Services.GetService<ArcForges.Cloud.Modules.Entitlement.Resolver.Application.IEntitlementDefinitionSource>());
        var source = h.Services.GetRequiredService<IQuotaResolverDefinitionSource>();
        Assert.IsType<VersionedQuotaResolverDefinitionSource>(source);
        var old = await source.ReadAsync(h.Realm, "v1", T.Ct);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, old.Status);
        Assert.Equal("official", old.Value!.RealmKind);
        Assert.Equal(QuotaDefinitionCombination.Sum, Assert.Single(old.Value.Quotas).Combination);
        var current = await source.ReadAsync(h.Realm, "v2", T.Ct);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, current.Status);
        Assert.Equal("selfHosted", current.Value!.RealmKind);
        Assert.Equal(QuotaDefinitionCombination.Max, Assert.Single(current.Value.Quotas).Combination);
        Assert.Equal(QuotaDefinitionStatus.NotFound, (await source.ReadAsync(h.Realm, "future", T.Ct)).Status);
        Assert.Equal(2, await h.Bridge.CountAsync("entitlement_resolver_definition_profile", "1=1", T.Ct));
    }

    [Fact]
    public async Task ClosingRealRecoveryAfterAnActualProfileReadRefusesItsFacts()
    {
        using var h = await Harness.Create();
        await h.Publish("v1", "official", ResolverDefinitionCombination.PriorityReplace);
        var observed = new AfterRead(h.Definitions, () => h.Bridge.ExecAsync("UPDATE platform_recovery_epoch SET state=1,rev=rev+1;", T.Ct));
        var result = await new VersionedQuotaResolverDefinitionSource(observed, h.Authority, new ResolverDefinitionValidator()).ReadAsync(h.Realm, "v1", T.Ct);
        Assert.Equal(QuotaDefinitionStatus.Unavailable, result.Status);
        Assert.Null(result.Value);
        Assert.Equal(1, observed.Reads);
        await h.Bridge.ExecAsync("UPDATE platform_recovery_epoch SET state=4,rev=rev+1;", T.Ct);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, (await h.Source.ReadAsync(h.Realm, "v1", T.Ct)).Status);
    }

    [Fact]
    public async Task CancellationAfterAnActualProfileReadCannotReleaseBufferedDefinitions()
    {
        using var h = await Harness.Create();
        await h.Publish("v1", "official", ResolverDefinitionCombination.Sum);
        using var canceled = CancellationTokenSource.CreateLinkedTokenSource(T.Ct);
        var observed = new AfterRead(h.Definitions, () => { canceled.Cancel(); return Task.CompletedTask; });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new VersionedQuotaResolverDefinitionSource(observed, h.Authority,
            new ResolverDefinitionValidator()).ReadAsync(h.Realm, "v1", canceled.Token));
        Assert.Equal(1, observed.Reads);
        Assert.Equal(1, await h.Bridge.CountAsync("entitlement_resolver_definition_profile", "1=1", T.Ct));
    }

    [Fact]
    public async Task ForeignRealmInvalidVersionAndMissingAuthorityCannotReadOrYieldDefinitions()
    {
        using var h = await Harness.Create();
        var observed = new AfterRead(h.Definitions, () => Task.CompletedTask);
        var source = new VersionedQuotaResolverDefinitionSource(observed, h.Authority, new ResolverDefinitionValidator());
        Assert.Equal(QuotaDefinitionStatus.Denied, (await source.ReadAsync(Guid.NewGuid(), "v1", T.Ct)).Status);
        Assert.Equal(QuotaDefinitionStatus.Invalid, (await source.ReadAsync(h.Realm, "bad version", T.Ct)).Status);
        Assert.Equal(QuotaDefinitionStatus.Unavailable, (await new VersionedQuotaResolverDefinitionSource(observed, null,
            new ResolverDefinitionValidator()).ReadAsync(h.Realm, "v1", T.Ct)).Status);
        Assert.Equal(0, observed.Reads);
    }

    private sealed class Harness : IDisposable
    {
        internal Guid Realm { get; } = Guid.NewGuid();
        internal SqliteBridgeExecutor Bridge { get; } = new(0);
        internal SettableTimeProvider Clock { get; } = new(DateTimeOffset.UnixEpoch.AddSeconds(10));
        internal ConfiguredRealmAuthority Authority { get; }
        internal ModulePlanPortFactory Plans { get; }
        internal ConfigFixture Config { get; } = new();
        internal ServiceProvider Services { get; }
        internal IResolverDefinitionPort Definitions => Services.GetRequiredService<IResolverDefinitionPort>();
        internal IQuotaResolverDefinitionSource Source => Services.GetRequiredService<IQuotaResolverDefinitionSource>();
        private Harness()
        {
            Plans = new ModulePlanPortFactory(Bridge, 0, Clock);
            Authority = new(name => name switch
            {
                "AF_REALM_ID" => Realm.ToString("D"), "AF_AUTH_EPOCH" => "7", "AF_RECOVERY_GENERATION" => "0", _ => null,
            }, _ => new RecoveryEpochReader(Plans, Clock));
            var services = new ServiceCollection();
            services.AddSingleton<TimeProvider>(Clock);
            services.AddSingleton<IModulePlanPortFactory>(Plans);
            services.AddSingleton<IRealmAuthorityPort>(Authority);
            services.AddSingleton<IResolverApprovedConfigurationSource>(Config);
            services.AddSingleton<IResolverDefinitionArtifactPort>(Config);
            services.AddSingleton<IQuotaApprovedConfigurationSource>(Config);
            services.AddSingleton<IQuotaDefinitionArtifactPort>(Config);
            ((IModuleBoundary)EntitlementModule.Instance).Register(services);
            Services = services.BuildServiceProvider();
        }
        internal static async Task<Harness> Create()
        {
            var h = new Harness();
            try
            {
                var pending = Path.Combine(T.RepoRoot().FullName, "src/ArcForges.Cloud.Storage.D1/Migrations/pending/entitlement__resolver-definition-profile.sql");
                if (File.Exists(pending)) await h.Bridge.ExecAsync(await File.ReadAllTextAsync(pending, T.Ct), T.Ct);
                var unitPending = Path.Combine(T.RepoRoot().FullName, "src/ArcForges.Cloud.Storage.D1/Migrations/pending/entitlement__quota-definition-profile.sql");
                if (File.Exists(unitPending)) await h.Bridge.ExecAsync(await File.ReadAllTextAsync(unitPending, T.Ct), T.Ct);
                await h.Bridge.ExecAsync($"INSERT INTO platform_recovery_epoch VALUES ('{h.Realm:D}',0,'fixture',zeroblob(32),4,1,1);", T.Ct);
                return h;
            }
            catch { h.Dispose(); throw; }
        }
        internal async Task Publish(string version, string kind, ResolverDefinitionCombination combination)
        {
            var revision = Guid.NewGuid();
            Config.Bytes = ResolverDefinitionValidator.Encode(version, [], [new("storage", combination)], []);
            var hash = Convert.ToHexStringLower(SHA256.HashData(Config.Bytes));
            Config.Approved = new(Realm, revision, new('a', 64), kind, version, "artifact:" + version,
                ResolverDefinitionValidator.ProfileName, hash, Config.Bytes.Length, "config:materializer");
            Assert.Equal(ResolverDefinitionStatus.Succeeded, (await Definitions.PublishAsync(new(Guid.NewGuid(), Realm, revision,
                Config.Approved.DocumentHash, Config.Approved.PublisherRef), T.Ct)).Status);
        }
        internal async Task PublishUnit()
        {
            var approved = Config.Approved;
            var profile = Profile(approved.DefinitionsVersion, [Unit()]);
            Config.UnitBytes = profile.CanonicalBytes.ToArray();
            var independent = await Source.ReadAsync(Realm, approved.DefinitionsVersion, T.Ct);
            Assert.Equal(QuotaDefinitionStatus.Succeeded, independent.Status);
            Config.QuotaApproved = new(Realm, approved.ConfigurationRevisionId, approved.DocumentHash, "unit:" + approved.DefinitionsVersion,
                QuotaDefinitionValidator.ProfileName, profile.Hash, Config.UnitBytes.Length, approved.DefinitionsVersion, approved.RealmKind,
                approved.PublisherRef, independent.Value!.Quotas);
            Assert.Equal(QuotaDefinitionStatus.Succeeded, (await Services.GetRequiredService<IQuotaDefinitionPort>().PublishAsync(
                new(Guid.NewGuid(), Realm, approved.ConfigurationRevisionId, approved.DocumentHash, approved.PublisherRef), T.Ct)).Status);
        }
        public void Dispose() { Services.Dispose(); Bridge.Dispose(); }
    }

    // Only unavailable signed Config/artifact authority is substituted; owner persistence, Worker and current recovery reads are real.
    private sealed class ConfigFixture : IResolverApprovedConfigurationSource, IResolverDefinitionArtifactPort, IQuotaApprovedConfigurationSource, IQuotaDefinitionArtifactPort
    {
        internal ApprovedResolverConfiguration Approved = null!;
        internal byte[] Bytes = [];
        internal byte[] UnitBytes = [];
        internal ApprovedQuotaConfiguration QuotaApproved = null!;
        public Task<ResolverConfigurationResult> ReadCurrentAsync(Guid realm, CancellationToken ct) => Task.FromResult(new ResolverConfigurationResult(ResolverDefinitionStatus.Succeeded, Approved));
        public Task<ResolverConfigurationResult> ReadHistoricalAsync(Guid realm, Guid revision, string hash, CancellationToken ct) => ReadCurrentAsync(realm, ct);
        public Task<ResolverDefinitionArtifactResult> ReadAsync(string id, string profile, string hash, CancellationToken ct) => Task.FromResult(new ResolverDefinitionArtifactResult(ResolverDefinitionStatus.Succeeded, Bytes));
        Task<QuotaConfigurationResult> IQuotaApprovedConfigurationSource.ReadCurrentAsync(Guid realm, CancellationToken ct) => Task.FromResult(new QuotaConfigurationResult(QuotaDefinitionStatus.Succeeded, QuotaApproved));
        Task<QuotaConfigurationResult> IQuotaApprovedConfigurationSource.ReadHistoricalAsync(Guid realm, Guid revision, string hash, CancellationToken ct) => Task.FromResult(new QuotaConfigurationResult(QuotaDefinitionStatus.Succeeded, QuotaApproved));
        Task<QuotaDefinitionArtifactResult> IQuotaDefinitionArtifactPort.ReadAsync(string id, string profile, string hash, CancellationToken ct) => Task.FromResult(new QuotaDefinitionArtifactResult(QuotaDefinitionStatus.Succeeded, UnitBytes));
    }
    private sealed class AfterRead(IResolverDefinitionPort inner, Func<Task> after) : IResolverDefinitionPort
    {
        internal int Reads;
        public Task<ResolverDefinitionResult> PublishAsync(ResolverDefinitionPublishRequest request, CancellationToken ct) => inner.PublishAsync(request, ct);
        public async Task<ResolverDefinitionResult> ReadAsync(Guid realm, string version, CancellationToken ct)
        {
            Reads++;
            var read = await inner.ReadAsync(realm, version, ct);
            await after();
            return read;
        }
    }
    private sealed class AfterCheck(IQuotaDefinitionStore inner, Func<Task> after) : IQuotaDefinitionStore
    {
        internal int Checks;
        public Task<QuotaDefinitionResult> ReadAsync(Guid realm, string version, CancellationToken ct) => inner.ReadAsync(realm, version, ct);
        public Task<QuotaDefinitionReceiptResult> ReceiptAsync(QuotaDefinitionPublishRequest request, CancellationToken ct) => inner.ReceiptAsync(request, ct);
        public Task<ModulePlanOutcome> PublishAsync(QuotaDefinitionPublishRequest request, ApprovedQuotaConfiguration approved,
            QuotaSemanticProfile profile, string hash, long now, CancellationToken ct) => inner.PublishAsync(request, approved, profile, hash, now, ct);
        public async Task<QuotaDefinitionStatus> CheckAsync(Guid realm, QuotaSemanticProfile profile, CancellationToken ct)
        {
            Checks++;
            var status = await inner.CheckAsync(realm, profile, ct);
            await after();
            return status;
        }
    }
}
