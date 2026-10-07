// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement;
using ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Infrastructure;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Storage.Platform;
using ArcForges.Cloud.Tests.Entitlement;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.ResolverDefinitionAuthority;

/// <summary>Real Entitlement DI/writer, C75 reads/guards, C82 capabilities and Worker SQLite. Only the unavailable signed Config/artifact authority is substituted.</summary>
public sealed class VersionedDefinitionCompositionTests
{
    [Fact]
    public async Task ProductionRevocationRetainsExistingExpectedVersionAndExactReplayRules()
    {
        using var h = await Harness.Create();
        var port = h.Services.GetRequiredService<IEntitlementGrantPort>();
        var grant = (await port.IssueGrantAsync(h.Command(), T.Ct)).Value!;
        var command = new RevokeGrantCommand(Harness.Workspace, grant.GrantId, "refunded", null, "commerce", 1);
        Assert.Equal(EntitlementPortStatus.StaleVersion, (await port.RevokeGrantAsync(command with { ExpectedEntitlementVersion = 0 }, T.Ct)).Status);
        Assert.Equal(0, await h.Count("entitlement_revocation"));
        Assert.Equal(EntitlementPortStatus.Succeeded, (await port.RevokeGrantAsync(command, T.Ct)).Status);
        var state = await h.Store.LoadAsync(Harness.Workspace, T.Ct);
        Assert.Equal(2, state.Revision);
        Assert.Single(state.Records.Revocations);
        Assert.Equal(EntitlementPortStatus.Duplicate, (await port.RevokeGrantAsync(command with { ExpectedEntitlementVersion = state.Snapshot!.Version }, T.Ct)).Status);
        Assert.Equal(1, await h.Count("entitlement_revocation"));
        Assert.Equal(2, await h.Count("platform_outbox"));
    }
    [Fact]
    public async Task MalformedGrantAndRevocationRefuseBeforeAnyAuthorityRead()
    {
        using var h = await Harness.Create();
        var port = h.Services.GetRequiredService<IEntitlementGrantPort>();
        var before = h.Bridge.Calls;
        foreach (var command in new[] { h.Command() with { Subject = "bad key" }, h.Command() with { Subject = "broken\ud800" },
            h.Command() with { Terms = new QuotaGrantTerms(-1) }, h.Command() with { EffectiveFrom = DateTimeOffset.UnixEpoch.AddTicks(1) } })
            Assert.Equal(EntitlementPortStatus.InvalidRequest, (await port.IssueGrantAsync(command, T.Ct)).Status);
        Assert.Equal(EntitlementPortStatus.InvalidRequest, (await port.RevokeGrantAsync(new(Harness.Workspace, "bad", "refunded", null, "commerce", 0), T.Ct)).Status);
        Assert.Equal(before, h.Bridge.Calls);
        Assert.Equal(0, await h.Count("entitlement_grant"));
    }
    [Fact]
    public async Task ProductionGrantBindingUsesCurrentAsyncDefinitionsAndHistoricalRebuildPinsStoredVersion()
    {
        using var h = await Harness.Create();
        Assert.Null(h.Services.GetService<IEntitlementDefinitionSource>());
        var port = Assert.IsType<VersionedEntitlementGrantPortAdapter>(h.Services.GetRequiredService<IEntitlementGrantPort>());
        var granted = await port.IssueGrantAsync(h.Command(), T.Ct);
        Assert.Equal(EntitlementPortStatus.Succeeded, granted.Status);
        var state = await h.Store.LoadAsync(Harness.Workspace, T.Ct);
        Assert.Equal(1, state.Revision);
        Assert.Single(state.Records.Grants);
        Assert.Equal("v1", state.Snapshot!.Content.DefinitionsVersion);
        Assert.Equal(1, await h.Count("entitlement_definitions_activation"));
        Assert.Equal(1, await h.Count("platform_outbox"));
        Assert.Equal(2, await h.Count("platform_change_archive"));
        var service = h.Services.GetRequiredService<VersionedEntitlementService>();
        await h.Publish("v2");
        Assert.Equal(RebuildStatus.Equal, (await service.VerifyRebuildAsync(Harness.Workspace, T.Ct)).Status);
        var refreshed = await service.ReadAsync(Harness.Workspace, true, T.Ct);
        Assert.True(refreshed.Succeeded);
        Assert.Equal("v2", refreshed.Value!.Content.DefinitionsVersion);
        Assert.Equal(2, (await h.Store.LoadAsync(Harness.Workspace, T.Ct)).Revision);
        Assert.Equal(RebuildStatus.Equal, (await service.VerifyRebuildAsync(Harness.Workspace, T.Ct)).Status);
        Assert.Equal(EntitlementPortStatus.Duplicate, (await port.IssueGrantAsync(h.Command(), T.Ct)).Status);
        Assert.Equal(1, await h.Count("entitlement_grant"));
    }

    [Theory]
    [InlineData("head")]
    [InlineData("recovery")]
    public async Task ARealAuthorityRaceAfterCapabilityPreparationRefusesEveryBatchWithoutAnyEffect(string change)
    {
        using var h = await Harness.Create();
        h.Participant.AfterSeal = () => h.Bridge.ExecAsync(change == "head"
            ? "UPDATE config_revision SET state=3;"
            : "UPDATE platform_recovery_epoch SET state=1,rev=rev+1;", T.Ct);
        var port = h.Services.GetRequiredService<IEntitlementGrantPort>();
        var result = await port.IssueGrantAsync(h.Command(), T.Ct);
        Assert.False(result.Status is EntitlementPortStatus.Succeeded or EntitlementPortStatus.Duplicate);
        Assert.Equal(0, await h.Count("entitlement_grant"));
        Assert.Equal(0, await h.Count("entitlement_revision"));
        Assert.Equal(0, await h.Count("entitlement_snapshot"));
        Assert.Equal(0, await h.Count("platform_outbox"));
        Assert.Equal(1, await h.Count("platform_command")); // Only the accepted immutable definition publication remains.
        Assert.Equal(0, await h.Count("platform_command_guard"));
    }

    [Theory]
    [InlineData("issuer")]
    [InlineData("scope")]
    [InlineData("unscoped")]
    public async Task ForeignIssuerWrongScopeAndLegacyUnscopedCapabilitiesNeverReachTheWriter(string misuse)
    {
        using var h = await Harness.Create();
        h.Participant.Misuse = misuse;
        await Assert.ThrowsAsync<InvalidOperationException>(() => h.Services.GetRequiredService<IEntitlementGrantPort>().IssueGrantAsync(h.Command(), T.Ct).AsTask());
        Assert.Equal(0, await h.Count("entitlement_grant"));
        Assert.Equal(0, await h.Count("platform_outbox"));
        Assert.Equal(1, await h.Count("platform_command"));
    }

    [Fact]
    public async Task MissingActualConfigParticipantFailsClosedDespiteMaterializedDefinitionsAndCurrentRecovery()
    {
        using var h = await Harness.Create();
        var source = h.Services.GetRequiredService<ICurrentResolverDefinitionSource>();
        var captured = (await source.ReadAsync(h.Realm, T.Ct)).Value!;
        var noAuthority = new CurrentDefinitionEntitlementStore(h.Store, h.Families.For(EntitlementModule.Instance.Descriptor), null,
            h.Recovery, source, captured);
        var snapshot = (await h.Store.LoadAsync(Harness.Workspace, T.Ct)).Records;
        var value = ArcForges.Cloud.Modules.Entitlement.Resolver.Domain.EntitlementResolver.Resolve(snapshot,
            ResolverDefinitionValidator.ToDefinitions(captured.Definitions.Profile, captured.Configuration.RealmKind),
            ArcForges.Cloud.Modules.Entitlement.Resolver.Domain.UtcMicros.FromDateTimeOffset(h.Clock.GetUtcNow()));
        Assert.Equal(EntitlementStoreFailure.Unavailable, (await Assert.ThrowsAsync<EntitlementStoreException>(() =>
            noAuthority.CommitAsync(Harness.Workspace, 0, EntitlementAppend.None, value, T.Ct).AsTask())).Failure);
        Assert.Equal(0, await h.Count("entitlement_revision"));
    }

    [Fact]
    public async Task CancellationAfterTheRealGrantCommitDoesNotReportSuccessOrUndoTheGrant()
    {
        using var h = await Harness.Create();
        using var cancelled = CancellationTokenSource.CreateLinkedTokenSource(T.Ct);
        var observing = new AfterWrite(h.Families.For(EntitlementModule.Instance.Descriptor), () => { cancelled.Cancel(); return Task.CompletedTask; });
        var port = new VersionedEntitlementGrantPortAdapter(h.Service(family: observing));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => port.IssueGrantAsync(h.Command(), cancelled.Token).AsTask());
        Assert.Equal(1, await h.Count("entitlement_grant"));
        Assert.Equal(1, await h.Count("entitlement_revision"));
        Assert.Equal(EntitlementPortStatus.Duplicate, (await h.Services.GetRequiredService<IEntitlementGrantPort>().IssueGrantAsync(h.Command(), T.Ct)).Status);
        Assert.Equal(1, await h.Count("platform_outbox"));
    }

    [Fact]
    public async Task RealRecoveryClosureAfterACommittedGrantRefusesResponseWithoutClaimingRollback()
    {
        using var h = await Harness.Create();
        var observing = new AfterWrite(h.Families.For(EntitlementModule.Instance.Descriptor),
            () => h.Bridge.ExecAsync("UPDATE platform_recovery_epoch SET state=1,rev=rev+1;", T.Ct));
        var result = await new VersionedEntitlementGrantPortAdapter(h.Service(family: observing)).IssueGrantAsync(h.Command(), T.Ct);
        Assert.Equal(EntitlementPortStatus.Unavailable, result.Status);
        Assert.Null(result.Value);
        Assert.Equal(1, await h.Count("entitlement_grant"));
        Assert.Equal(1, await h.Count("entitlement_snapshot"));
        Assert.Equal(1, await h.Count("platform_outbox"));
        Assert.Equal(2, await h.Count("platform_command"));
        await h.Bridge.ExecAsync("UPDATE platform_recovery_epoch SET state=4,rev=rev+1;", T.Ct);
        Assert.Equal(EntitlementPortStatus.Duplicate, (await h.Services.GetRequiredService<IEntitlementGrantPort>().IssueGrantAsync(h.Command(), T.Ct)).Status);
        Assert.Equal(1, await h.Count("entitlement_grant"));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ClosingRecoveryAfterARealHistoryReadCannotReleaseCurrentOrHistoricalFacts(bool historical)
    {
        using var h = await Harness.Create();
        Assert.Equal(EntitlementPortStatus.Succeeded, (await h.Services.GetRequiredService<IEntitlementGrantPort>().IssueGrantAsync(h.Command(), T.Ct)).Status);
        var store = new AfterLoad(h.Store, () => h.Bridge.ExecAsync("UPDATE platform_recovery_epoch SET state=1,rev=rev+1;", T.Ct));
        var service = h.Service(store: store);
        var failure = historical
            ? await Assert.ThrowsAsync<EntitlementStoreException>(() => service.VerifyRebuildAsync(Harness.Workspace, T.Ct).AsTask())
            : await Assert.ThrowsAsync<EntitlementStoreException>(() => service.ReadAsync(Harness.Workspace, false, T.Ct).AsTask());
        Assert.Equal(EntitlementStoreFailure.Unavailable, failure.Failure);
        Assert.Equal(1, await h.Count("entitlement_revision"));
    }

    private sealed class Harness : IDisposable
    {
        internal static readonly string Workspace = D1EntitlementHarness.Workspace;
        internal Guid Realm { get; } = Guid.NewGuid();
        internal SqliteBridgeExecutor Bridge { get; } = new(0);
        internal SettableTimeProvider Clock { get; } = new(DateTimeOffset.UnixEpoch.AddSeconds(10));
        internal ModulePlanPortFactory Plans { get; }
        internal ModuleFamilyPortFactory Families { get; }
        internal ConfiguredRealmAuthority Authority { get; }
        internal ConfiguredRealmAuthorityFamily Recovery { get; }
        internal ConfigFixture Config { get; } = new();
        internal Participant Participant { get; }
        internal ServiceProvider Services { get; }
        internal D1EntitlementStore Store => (D1EntitlementStore)Services.GetRequiredService<IEntitlementStore>();
        private Harness()
        {
            Plans = new(Bridge, 0, Clock);
            Families = new(Bridge, 0, Clock);
            Authority = new(name => name switch
            {
                "AF_REALM_ID" => Realm.ToString("D"), "AF_AUTH_EPOCH" => "7", "AF_RECOVERY_GENERATION" => "0", _ => null,
            }, _ => new RecoveryEpochReader(Plans, Clock));
            Recovery = new(Authority, () => Families);
            Participant = new(this);
            var services = new ServiceCollection();
            services.AddSingleton<TimeProvider>(Clock);
            services.AddSingleton<IModulePlanPortFactory>(Plans);
            services.AddSingleton<IModuleFamilyPortFactory>(Families);
            services.AddSingleton<IRealmAuthorityPort>(Authority);
            services.AddSingleton<IRealmAuthorityFamilyPort>(Recovery);
            services.AddSingleton<IResolverApprovedConfigurationSource>(Config);
            services.AddSingleton<IResolverDefinitionArtifactPort>(Config);
            services.AddSingleton<IResolverConfigurationParticipant>(Participant);
            ((IModuleBoundary)EntitlementModule.Instance).Register(services);
            Services = services.BuildServiceProvider();
        }
        internal static async Task<Harness> Create()
        {
            var h = new Harness();
            try
            {
                await h.Bridge.SeedWorkspaceAsync(Guid.Parse(Workspace), T.Ct);
                var pending = Path.Combine(T.RepoRoot().FullName, "src/ArcForges.Cloud.Storage.D1/Migrations/pending/entitlement__resolver-definition-profile.sql");
                if (File.Exists(pending)) await h.Bridge.ExecAsync(await File.ReadAllTextAsync(pending, T.Ct), T.Ct);
                await h.Bridge.ExecAsync($"INSERT INTO platform_recovery_epoch VALUES ('{h.Realm:D}',0,'fixture',zeroblob(32),4,1,1);", T.Ct);
                await h.Publish("v1");
                return h;
            }
            catch { h.Dispose(); throw; }
        }
        internal async Task Publish(string version)
        {
            var revision = Guid.NewGuid();
            Config.Bytes = ResolverDefinitionValidator.Encode(version, [new("cloud.sync", false, null)], [], []);
            var hash = Convert.ToHexStringLower(SHA256.HashData(Config.Bytes));
            Config.Approved = new(Realm, revision, new('a', 64), "official", version, "artifact:" + version,
                ResolverDefinitionValidator.ProfileName, hash, Config.Bytes.Length, "config:materializer");
            await Bridge.ExecAsync($"UPDATE config_revision SET state=3; INSERT INTO config_revision VALUES ('{revision:D}','fixture','fixture-head',X'{Config.Approved.DocumentHash}','fixture','{Realm:D}',1,1,2,'{{}}');", T.Ct);
            var result = await Services.GetRequiredService<IResolverDefinitionPort>().PublishAsync(new(Guid.NewGuid(), Realm, revision, Config.Approved.DocumentHash, Config.Approved.PublisherRef), T.Ct);
            Assert.Equal(ResolverDefinitionStatus.Succeeded, result.Status);
        }
        internal IssueGrantCommand Command() => new(Workspace, EntitlementGrantKind.Capability, "cloud.sync", new CapabilityGrantTerms(),
            EntitlementGrantSource.Subscription, "order:versioned", DateTimeOffset.UnixEpoch, null, "commerce", null);
        internal VersionedEntitlementService Service(IEntitlementStore? store = null, IModuleFamilyPort? family = null)
            => new(store ?? Store, Services.GetRequiredService<ICurrentResolverDefinitionSource>(), Services.GetRequiredService<IResolverDefinitionPort>(),
                Authority, family ?? Families.For(EntitlementModule.Instance.Descriptor), Participant, Recovery, new UuidIds(), Clock);
        internal Task<long> Count(string table) => Bridge.CountAsync(table, "1=1", T.Ct);
        public void Dispose() { Services.Dispose(); Bridge.Dispose(); }
    }
    // These boundary fixtures do not establish dual approval or Config signatures. The actual issuer/SQL/atomic fences are exercised.
    private sealed class ConfigFixture : IResolverApprovedConfigurationSource, IResolverDefinitionArtifactPort
    {
        internal ApprovedResolverConfiguration Approved = null!;
        internal byte[] Bytes = [];
        public Task<ResolverConfigurationResult> ReadCurrentAsync(Guid realm, CancellationToken ct) => Task.FromResult(new ResolverConfigurationResult(ResolverDefinitionStatus.Succeeded, Approved));
        public Task<ResolverConfigurationResult> ReadHistoricalAsync(Guid realm, Guid revision, string hash, CancellationToken ct) => ReadCurrentAsync(realm, ct);
        public Task<ResolverDefinitionArtifactResult> ReadAsync(string id, string profile, string hash, CancellationToken ct) => Task.FromResult(new ResolverDefinitionArtifactResult(ResolverDefinitionStatus.Succeeded, Bytes));
    }
    private sealed class Participant(Harness h) : IResolverConfigurationParticipant
    {
        internal Func<Task>? AfterSeal;
        internal string? Misuse;
        public async Task<ResolverDefinitionGuardResult> PrepareCurrentAsync(ResolverDefinitionGuardRequest request, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var factory = Misuse == "issuer" ? new ModuleFamilyPortFactory(h.Bridge, 0, h.Clock) : h.Families;
            var port = factory.For(ModuleDescriptor.Create("Config", "config"));
            ModuleFamilyContribution[] roles = [new("config", "policy", "current-definitions-head",
                [PlanValue.FromText(request.Configuration.RealmId.ToString("D")), PlanValue.FromText(request.Configuration.ConfigurationRevisionId.ToString("D")),
                 PlanValue.FromBytes(Convert.FromHexString(request.Configuration.DocumentHash))])];
            var guard = Misuse == "unscoped" ? port.Contribute(request.FamilyId, request.PlanId, roles)
                : port.ContributeScoped(request.FamilyId, request.PlanId, Misuse == "scope" ? Guid.NewGuid().ToString("D") : request.OwnerScope, roles);
            if (AfterSeal is { } mutation) await mutation();
            ct.ThrowIfCancellationRequested();
            return new(ResolverDefinitionStatus.Succeeded, guard);
        }
    }
    private sealed class AfterWrite(IModuleFamilyPort inner, Func<Task> after) : IModuleFamilyPort
    {
        public Task<ModulePlanOutcome> ReadAsync(string family, ModulePlanRead read, CancellationToken ct) => inner.ReadAsync(family, read, ct);
        public Task<ModulePlanOutcome> InspectAsync(string family, ModuleCommandIdentity identity, CancellationToken ct) => inner.InspectAsync(family, identity, ct);
        public IModuleFamilyContributionSet Contribute(string family, string plan, IReadOnlyList<ModuleFamilyContribution> contributions) => inner.Contribute(family, plan, contributions);
        public IModuleFamilyContributionSet ContributeScoped(string family, string plan, string scope, IReadOnlyList<ModuleFamilyContribution> contributions) => inner.ContributeScoped(family, plan, scope, contributions);
        public async Task<ModulePlanOutcome> WriteAsync(ModuleFamilyWrite write, CancellationToken ct)
        {
            var value = await inner.WriteAsync(write, ct);
            Assert.Equal(ModulePlanStatus.Succeeded, value.Status);
            await after();
            return value;
        }
    }
    private sealed class AfterLoad(IEntitlementStore inner, Func<Task> after) : IEntitlementStore
    {
        public async ValueTask<EntitlementState> LoadAsync(string workspace, CancellationToken ct)
        {
            var value = await inner.LoadAsync(workspace, ct);
            await after();
            return value;
        }
        public ValueTask<CommitOutcome> CommitAsync(string workspace, long expectedRevision, EntitlementAppend append,
            ArcForges.Cloud.Modules.Entitlement.Resolver.Domain.EntitlementSnapshot snapshot, CancellationToken ct)
            => inner.CommitAsync(workspace, expectedRevision, append, snapshot, ct);
        public ValueTask<FeatureReleaseOutcome> AppendFeatureReleaseAsync(ArcForges.Cloud.Modules.Entitlement.Resolver.Domain.FeatureReleaseFact fact, CancellationToken ct)
            => inner.AppendFeatureReleaseAsync(fact, ct);
    }
}
