// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using System.Security.Cryptography;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Application;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Infrastructure;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Entitlement;
using Xunit;

namespace ArcForges.Cloud.Tests.QuotaDefinitions;

public sealed class QuotaDefinitionPersistenceTests
{
    [Fact]
    public async Task ImmutableProfilesAndRemovedKeyMeaningsSurviveRestartAndReintroduction()
    {
        using var h = await Harness.Create();
        var original = h.Define("version-1", QuotaDefinitionUnit.Bytes);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, (await h.Publish(original)).Status);
        var removed = h.Define("removed-version", []);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, (await h.Publish(removed)).Status);
        Assert.Equal(1, await h.Count("entitlement_quota_definition_key"));
        var changed = h.Define("version-3", QuotaDefinitionUnit.Count);
        Assert.Equal(QuotaDefinitionStatus.Conflict, (await h.Publish(changed)).Status);
        var compatible = h.Define("version-4", QuotaDefinitionUnit.Bytes);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, (await h.Publish(compatible)).Status);
        var restarted = new D1QuotaDefinitionStore(h.Port);
        var retained = await restarted.ReadAsync(h.Realm, "version-1", T.Ct);
        Assert.Equal(QuotaDefinitionUnit.Bytes, Assert.Single(retained.Value!.Profile.Definitions).Unit);
        Assert.Equal(3, await h.Count("entitlement_quota_definition_profile"));
        Assert.Equal(3, await h.Count("platform_change_archive"));
        Assert.Contains("af_immutable", await h.Bridge.RefusalAsync("UPDATE entitlement_quota_definition_key SET unit=4;", T.Ct));
        Assert.Contains("af_immutable", await h.Bridge.RefusalAsync("DELETE FROM entitlement_quota_definition_profile;", T.Ct));
    }

    [Fact]
    public async Task ConcurrentDifferingVersionsCannotRedefineStableKeyOrLeavePartialProfile()
    {
        using var h = await Harness.Create();
        var a = h.Define("version-a", QuotaDefinitionUnit.Bytes);
        var aConfig = h.Authority.Approved!; var aBytes = h.Artifacts.Bytes; var aDefinitions = h.Resolver.Value!;
        var b = h.Define("version-b", QuotaDefinitionUnit.Count);
        var serviceA = h.Service(new Authority { Approved = aConfig }, new Artifacts { Bytes = aBytes }, new Resolver { Value = aDefinitions });
        var results = await Task.WhenAll(serviceA.PublishAsync(a, T.Ct), h.Publish(b));
        Assert.Single(results, r => r.Status == QuotaDefinitionStatus.Succeeded);
        Assert.Single(results, r => r.Status == QuotaDefinitionStatus.Conflict);
        Assert.Equal(1, await h.Count("entitlement_quota_definition_profile"));
        Assert.Equal(1, await h.Count("entitlement_quota_definition_key"));
        Assert.Equal(1, await h.Count("platform_command"));
        Assert.Equal(0, await h.Count("platform_command_guard"));
    }

    [Fact]
    public async Task ExactReplayPrecedesArtifactAndCurrentResolverButNeedsHistoricalApproval()
    {
        using var h = await Harness.Create(); var request = h.Define("version-1", QuotaDefinitionUnit.Bytes);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, (await h.Publish(request)).Status);
        h.Artifacts.Status = QuotaDefinitionStatus.Unavailable; h.Resolver.Status = QuotaDefinitionStatus.NotFound;
        Assert.Equal(QuotaDefinitionStatus.Replayed, (await h.Publish(request)).Status);
        Assert.Equal(1, h.Artifacts.Reads); Assert.Equal(1, h.Resolver.Reads);
        var changed = request with { DocumentHash = new('b', 64) };
        h.Authority.Approved = WithDocument(h.Authority.Approved!, changed);
        Assert.Equal(QuotaDefinitionStatus.ReusedIdentifier, (await h.Publish(changed)).Status);
        h.Authority.Status = QuotaDefinitionStatus.Unavailable;
        Assert.Equal(QuotaDefinitionStatus.Unavailable, (await h.Publish(request)).Status);
        h.Authority.Status = QuotaDefinitionStatus.Succeeded; h.Authority.Approved = WithDocument(h.Authority.Approved!, request);
        h.Clock.SetSeconds(8 * 86400);
        Assert.Equal(QuotaDefinitionStatus.ReceiptExpired, (await h.Publish(request)).Status);
        Assert.Equal(1, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task LostCommittedResponseReconcilesReceiptWithoutSecondEffect()
    {
        using var h = await Harness.Create(); var request = h.Define("version-1", QuotaDefinitionUnit.Bytes);
        var fault = new FaultPort(h.Port);
        Assert.Equal(QuotaDefinitionStatus.Replayed, (await h.Service(port: fault).PublishAsync(request, T.Ct)).Status);
        Assert.Equal(1, fault.Writes);
        Assert.Equal(1, await h.Count("platform_command")); Assert.Equal(1, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task CancellationAfterActualCommitDoesNotReturnSuccessOrRollbackAndReplayIsExact()
    {
        using var h = await Harness.Create(); var request = h.Define("version-1", QuotaDefinitionUnit.Bytes);
        using var cancel = new CancellationTokenSource(); var fault = new FaultPort(h.Port, cancel.Cancel);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Service(port: fault).PublishAsync(request, cancel.Token));
        Assert.Equal(1, await h.Count("entitlement_quota_definition_profile"));
        Assert.Equal(QuotaDefinitionStatus.Replayed, (await h.Publish(request)).Status);
    }

    [Fact]
    public async Task CandidateCannotSupplyItsOwnIndependentExpectedDefinitionsOrChangeApprovedBytes()
    {
        using var h = await Harness.Create(); var request = h.Define("version-1", QuotaDefinitionUnit.Bytes);
        h.Resolver.Value = new("version-1", "official", [new("different", QuotaDefinitionCombination.Sum)]);
        Assert.Equal(QuotaDefinitionStatus.Stale, (await h.Publish(request)).Status);
        Assert.Equal(0, h.Artifacts.Reads);
        h.Resolver.Value = new("version-1", "official", [new("storage", QuotaDefinitionCombination.Sum)]);
        h.Artifacts.Bytes = new byte[h.Artifacts.Bytes.Length];
        Assert.Equal(QuotaDefinitionStatus.Invalid, (await h.Publish(request)).Status);
        Assert.Equal(0, await h.Count("platform_command"));
    }

    [Fact]
    public async Task ModeAndCombinationCannotDriftAcrossApprovedDifferentVersions()
    {
        using var h = await Harness.Create(); var original = h.Define("original", QuotaDefinitionUnit.Bytes);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, (await h.Publish(original)).Status);
        var mode = h.Define("different-mode", [new("storage", QuotaDefinitionCombination.Sum, QuotaDefinitionUnit.Bytes, QuotaDefinitionMode.EntitlementPeriod)]);
        Assert.Equal(QuotaDefinitionStatus.Conflict, (await h.Publish(mode)).Status);
        var combination = h.Define("different-combination", [new("storage", QuotaDefinitionCombination.Max, QuotaDefinitionUnit.Bytes, QuotaDefinitionMode.Gauge)]);
        Assert.Equal(QuotaDefinitionStatus.Conflict, (await h.Publish(combination)).Status);
        Assert.Equal(1, await h.Count("entitlement_quota_definition_profile")); Assert.Equal(1, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task DefiniteTransportRefusalsRetryBoundedlyWithIdenticalCommandThenActualCommit()
    {
        using var h = await Harness.Create(); var request = h.Define("version-1", QuotaDefinitionUnit.Bytes);
        var retry = new RetryPort(h.Port);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, (await h.Service(port: retry).PublishAsync(request, T.Ct)).Status);
        Assert.Equal(3, retry.Writes.Count);
        Assert.Single(retry.Writes.Select(w => w.Commit!.CommandId).Distinct());
        Assert.Single(retry.Writes.Select(w => w.Commit!.RequestHash).Distinct());
        Assert.Equal(1, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task UnavailableReceiptAfterUnknownWriteNeverClaimsNoEffectOrBlindlyRetries()
    {
        using var h = await Harness.Create(); var request = h.Define("version-1", QuotaDefinitionUnit.Bytes);
        var unknown = new UnknownReceiptPort(h.Port);
        Assert.Equal(QuotaDefinitionStatus.UnknownOutcome, (await h.Service(port: unknown).PublishAsync(request, T.Ct)).Status);
        Assert.Equal(1, unknown.Writes); Assert.Equal(1, await h.Count("entitlement_quota_definition_profile"));
        Assert.Equal(QuotaDefinitionStatus.Replayed, (await h.Publish(request)).Status);
    }

    private static ApprovedQuotaConfiguration WithDocument(ApprovedQuotaConfiguration value, QuotaDefinitionPublishRequest request) => new(value.RealmId,
        value.ConfigurationRevisionId, request.DocumentHash, value.ArtifactId, value.ArtifactProfile, value.ArtifactHash, value.VerifiedLength,
        value.DefinitionsVersion, value.RealmKind, value.PublisherRef, value.ResolverDefinitions);

    private sealed class Harness : IDisposable
    {
        internal Guid Realm { get; } = Guid.NewGuid(); internal Guid Revision { get; } = Guid.NewGuid();
        internal SqliteBridgeExecutor Bridge { get; } = new();
        internal SettableTimeProvider Clock { get; } = new(DateTimeOffset.UnixEpoch.AddSeconds(10));
        internal IModulePlanPort Port { get; }
        internal Authority Authority { get; } = new(); internal Artifacts Artifacts { get; } = new(); internal Resolver Resolver { get; } = new();
        private Harness() => Port = new ModulePlanPortFactory(Bridge, Bridge.Generation, Clock).For(EntitlementModule.Instance.Descriptor);
        internal static async Task<Harness> Create()
        {
            var h = new Harness();
            try { await h.Bridge.ExecAsync(await File.ReadAllTextAsync(Path.Combine(T.RepoRoot().FullName, "src", "ArcForges.Cloud.Storage.D1", "Migrations", "pending", "entitlement__quota-definition-profile.sql"), T.Ct), T.Ct); return h; }
            catch { h.Dispose(); throw; }
        }
        internal QuotaDefinitionPublishRequest Request() => new(Guid.NewGuid(), Realm, Revision, new('a', 64), "config:trusted-materializer");
        internal QuotaDefinitionPublishRequest Define(string version, QuotaDefinitionUnit unit) => Define(version, [new("storage", QuotaDefinitionCombination.Sum, unit, QuotaDefinitionMode.Gauge)]);
        internal QuotaDefinitionPublishRequest Define(string version, QuotaSemanticDefinition[] definitions)
        {
            var request = Request() with { ConfigurationRevisionId = Guid.NewGuid() }; var bytes = QuotaDefinitionValidator.Encode(version, definitions); var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
            var expected = definitions.Select(d => new QuotaResolverDefinition(d.Key, d.Combination)).ToImmutableArray();
            Authority.Approved = new(Realm, request.ConfigurationRevisionId, request.DocumentHash, "artifact:" + version, QuotaDefinitionValidator.ProfileName, hash, bytes.Length, version, "official", request.PublisherRef, expected);
            Artifacts.Bytes = bytes; Resolver.Value = new(version, "official", expected); return request;
        }
        internal QuotaDefinitionService Service(Authority? authority = null, Artifacts? artifacts = null, Resolver? resolver = null, IModulePlanPort? port = null)
            => new(new D1QuotaDefinitionStore(port ?? Port), authority ?? Authority, artifacts ?? Artifacts, resolver ?? Resolver, new QuotaDefinitionValidator(), Clock);
        internal Task<QuotaDefinitionResult> Publish(QuotaDefinitionPublishRequest request) => Service().PublishAsync(request, T.Ct);
        internal Task<long> Count(string table) => Bridge.CountAsync(table, "1=1", T.Ct);
        public void Dispose() => Bridge.Dispose();
    }
    // Only absent Config/artifact/resolver producers are substituted; persistence, Worker execution and commit receipts execute actual code.
    private sealed class Authority : IQuotaApprovedConfigurationSource
    {
        internal ApprovedQuotaConfiguration? Approved; internal QuotaDefinitionStatus Status = QuotaDefinitionStatus.Succeeded;
        public Task<QuotaConfigurationResult> ReadHistoricalAsync(Guid realmId, Guid revision, string hash, CancellationToken ct) => Task.FromResult(new QuotaConfigurationResult(Status, Approved));
        public Task<QuotaConfigurationResult> ReadCurrentAsync(Guid realmId, CancellationToken ct) => Task.FromResult(new QuotaConfigurationResult(Status, Approved));
    }
    private sealed class Artifacts : IQuotaDefinitionArtifactPort
    {
        internal byte[] Bytes = []; internal QuotaDefinitionStatus Status = QuotaDefinitionStatus.Succeeded; internal int Reads;
        public Task<QuotaDefinitionArtifactResult> ReadAsync(string id, string profile, string hash, CancellationToken ct) { Reads++; return Task.FromResult(new QuotaDefinitionArtifactResult(Status, Bytes)); }
    }
    private sealed class Resolver : IQuotaResolverDefinitionSource
    {
        internal QuotaResolverDefinitionSet? Value; internal QuotaDefinitionStatus Status = QuotaDefinitionStatus.Succeeded; internal int Reads;
        public Task<QuotaResolverDefinitionResult> ReadAsync(Guid realm, string version, CancellationToken ct) { Reads++; return Task.FromResult(new QuotaResolverDefinitionResult(Status, Value)); }
    }
    private sealed class FaultPort(IModulePlanPort inner, Action? afterCommit = null) : IModulePlanPort
    {
        internal int Writes;
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken ct) => inner.ReadAsync(read, ct);
        public async Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken ct)
        {
            Writes++; Assert.Equal(ModulePlanStatus.Succeeded, (await inner.WriteAsync(write, ct)).Status);
            afterCommit?.Invoke(); return ModulePlanOutcome.Of(ModulePlanStatus.UnknownOutcome);
        }
    }
    private sealed class RetryPort(IModulePlanPort inner) : IModulePlanPort
    {
        internal List<ModulePlanWrite> Writes { get; } = [];
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken ct) => inner.ReadAsync(read, ct);
        public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken ct)
        {
            Writes.Add(write); return Writes.Count < 3 ? Task.FromResult(ModulePlanOutcome.Of(ModulePlanStatus.Unavailable)) : inner.WriteAsync(write, ct);
        }
    }
    private sealed class UnknownReceiptPort(IModulePlanPort inner) : IModulePlanPort
    {
        internal int Writes;
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken ct) => Writes > 0 && read.PlanId == "entitlement.quota-definition-command"
            ? Task.FromResult(ModulePlanOutcome.Of(ModulePlanStatus.Unavailable)) : inner.ReadAsync(read, ct);
        public async Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken ct)
        {
            Writes++; Assert.Equal(ModulePlanStatus.Succeeded, (await inner.WriteAsync(write, ct)).Status); return ModulePlanOutcome.Of(ModulePlanStatus.UnknownOutcome);
        }
    }
}
