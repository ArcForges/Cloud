// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Infrastructure;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Storage.Receipts;
using ArcForges.Cloud.Tests.Entitlement;
using Xunit;

namespace ArcForges.Cloud.Tests.ResolverDefinitionAuthority;

public sealed class ResolverDefinitionPersistenceTests
{
    [Fact]
    public async Task ArtifactReadThatSupersedesUnpublishedHeadCannotMaterializeTheEarlierVersion()
    {
        using var h = await Harness.Create();
        var old = h.Define("v1");
        var approved = h.Authority.Approved!;
        var bytes = h.Artifacts.Bytes;
        h.Define("v2");
        var later = h.Authority.Approved!;
        h.Authority.Approved = approved;
        h.Authority.CurrentApproved = approved;
        h.Artifacts.Bytes = bytes;
        h.Artifacts.AfterRead = () => h.Authority.CurrentApproved = later;
        Assert.Equal(ResolverDefinitionStatus.Stale, (await h.Publish(old)).Status);
        Assert.Equal(1, h.Artifacts.Reads);
        Assert.Equal(0, await h.Count("entitlement_resolver_definition_profile"));
        Assert.Equal(0, await h.Count("platform_command"));
    }

    [Theory]
    [InlineData(ResolverDefinitionStatus.NotFound)]
    [InlineData(ResolverDefinitionStatus.UnknownOutcome)]
    [InlineData(ResolverDefinitionStatus.Unavailable)]
    public async Task UnknownCurrentAuthorityCannotCreateAProfile(ResolverDefinitionStatus status)
    {
        using var h = await Harness.Create();
        var request = h.Define("v1");
        h.Authority.CurrentStatus = status;
        Assert.Equal(ResolverDefinitionStatus.Unavailable, (await h.Publish(request)).Status);
        Assert.Equal(0, h.Artifacts.Reads);
        Assert.Equal(0, await h.Count("platform_command"));
    }

    [Fact]
    public async Task StableReceiptCannotReplayAgainstADifferentRetainedArtifactAssociation()
    {
        using var h = await Harness.Create();
        var request = h.Define("v1");
        Assert.Equal(ResolverDefinitionStatus.Succeeded, (await h.Publish(request)).Status);
        h.Authority.Approved = h.Authority.Approved! with { ArtifactId = "different:artifact" };
        Assert.Equal(ResolverDefinitionStatus.Defect, (await h.Publish(request)).Status);
        Assert.Equal(1, h.Artifacts.Reads);
        Assert.Equal(1, await h.Count("platform_command"));
        Assert.Equal(1, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task SupersededUnpublishedDefinitionRefusesButExactAcceptedHistoricalRecoveryRetainsProvenance()
    {
        using var h = await Harness.Create();
        var old = h.Define("v1");
        var oldAssociation = h.Authority.Approved!;
        var oldBytes = h.Artifacts.Bytes;
        var later = h.Define("v2");
        var current = h.Authority.Approved!;
        Assert.Equal(ResolverDefinitionStatus.Succeeded, (await h.Publish(later)).Status);
        h.Authority.CurrentApproved = current;
        h.Authority.Approved = oldAssociation;
        h.Artifacts.Bytes = oldBytes;
        var before = h.Artifacts.Reads;
        Assert.Equal(ResolverDefinitionStatus.Stale, (await h.Publish(old)).Status);
        Assert.Equal(before, h.Artifacts.Reads);
        Assert.Equal(ResolverDefinitionStatus.NotFound, (await h.Publisher().ReadAsync(h.Realm, "v1", T.Ct)).Status);
        // A real current activation accepts v1 first; after later supersession only its exact accepted immutable recovery remains admissible.
        h.Authority.CurrentApproved = oldAssociation;
        Assert.Equal(ResolverDefinitionStatus.Succeeded, (await h.Publish(old)).Status);
        h.Authority.CurrentApproved = current;
        Assert.Equal(ResolverDefinitionStatus.Replayed, (await h.Publish(old)).Status);
        var recovery = await h.Publish(old with { CommandId = Guid.NewGuid() });
        Assert.Equal(ResolverDefinitionStatus.Succeeded, recovery.Status);
        Assert.Equal(old.ConfigurationRevisionId, recovery.Value!.FirstConfigurationRevisionId);
        Assert.Equal(2, await h.Count("entitlement_resolver_definition_profile"));
        Assert.Equal(3, await h.Count("platform_change_archive"));
    }
    [Fact]
    public async Task PersistedStableFailureWithNullPayloadReplaysOnlyItsExactAuthorizedRealmIdentity()
    {
        using var h = await Harness.Create();
        var request = h.Define("v1");
        var receipts = new CommandReceiptStore(h.Bridge, h.Bridge.Generation, h.Clock);
        Assert.True(await receipts.RecordFailureAsync(new(request.CommandId, null, request.PublisherRef,
            ResolverDefinitionOutcomes.Operation, ResolverDefinitionPublisher.RequestHash(request)),
            "validation.invalid_request", 10000000, 604810000000, T.Ct));
        Assert.Equal(ResolverDefinitionStatus.Conflict, (await h.Publish(request)).Status);
        Assert.Equal(0, h.Artifacts.Reads);
        var otherRealm = Guid.NewGuid();
        h.Authority.Approved = h.Authority.Approved! with { RealmId = otherRealm };
        Assert.Equal(ResolverDefinitionStatus.ReusedIdentifier, (await h.Publish(request with { RealmId = otherRealm })).Status);
        Assert.Equal(0, await h.Count("entitlement_resolver_definition_profile"));
        Assert.Equal(0, await h.Count("platform_change_archive"));
        Assert.Equal(1, await h.Count("platform_command"));
    }
    [Fact]
    public async Task LaterApprovedIdenticalReusePreservesFirstProvenanceAndHistoricalDefinitions()
    {
        using var h = await Harness.Create();
        var original = h.Define("v1");
        var first = await h.Publish(original);
        Assert.Equal(ResolverDefinitionStatus.Succeeded, first.Status);
        var later = h.Define("v1");
        Assert.NotEqual(original.ConfigurationRevisionId, later.ConfigurationRevisionId);
        var reused = await h.Publish(later);
        Assert.Equal(ResolverDefinitionStatus.Succeeded, reused.Status);
        Assert.Equal(original.ConfigurationRevisionId, reused.Value!.FirstConfigurationRevisionId);
        Assert.Equal(first.Value!.FirstDocumentHash, reused.Value.FirstDocumentHash);
        Assert.Equal(1, await h.Count("entitlement_resolver_definition_profile"));
        Assert.Equal(2, await h.Count("platform_change_archive"));
        var replacement = h.Define("v2", paid: false);
        Assert.Equal(ResolverDefinitionStatus.Succeeded, (await h.Publish(replacement)).Status);
        var reopened = await new D1ResolverDefinitionStore(h.Port).ReadAsync(h.Realm, "v1", T.Ct);
        Assert.True(Assert.Single(reopened.Value!.Profile.Capabilities).RequiresPaidTerm);
        Assert.Equal(ResolverDefinitionStatus.NotFound, (await h.Publisher().ReadAsync(h.Realm, "unknown", T.Ct)).Status);
        Assert.Contains("af_immutable", await h.Bridge.RefusalAsync("UPDATE entitlement_resolver_definition_profile SET realm_kind=2;", T.Ct));
        Assert.Contains("af_immutable", await h.Bridge.RefusalAsync("DELETE FROM entitlement_resolver_definition_profile;", T.Ct));
    }

    [Fact]
    public async Task AuthorizedPublisherRotationReusesExactArtifactWithoutChangingFirstPublisherOrAuthorizingOldIdentity()
    {
        using var h = await Harness.Create();
        var original = h.Define("v1");
        var first = await h.Publish(original);
        Assert.Equal(ResolverDefinitionStatus.Succeeded, first.Status);
        var oldAssociation = h.Authority.Approved!;
        var later = h.Define("v1") with { PublisherRef = "config:rotated-materializer" };
        h.Authority.Approved = h.Authority.Approved! with { PublisherRef = later.PublisherRef };
        var newAssociation = h.Authority.Approved;
        Assert.Equal(ResolverDefinitionStatus.Denied, (await h.Publish(later with { PublisherRef = original.PublisherRef })).Status);
        var reused = await h.Publish(later);
        Assert.Equal(ResolverDefinitionStatus.Succeeded, reused.Status);
        Assert.Equal(original.PublisherRef, reused.Value!.PublisherRef);
        Assert.Equal(original.ConfigurationRevisionId, reused.Value.FirstConfigurationRevisionId);
        var current = await new CurrentResolverDefinitionSource(h.Authority, h.Publisher()).ReadAsync(h.Realm, T.Ct);
        Assert.Equal(ResolverDefinitionStatus.Succeeded, current.Status);
        Assert.Equal(later.PublisherRef, current.Value!.Configuration.PublisherRef);
        Assert.Equal(original.PublisherRef, current.Value.Definitions.PublisherRef);
        h.Authority.CurrentApproved = newAssociation;
        h.Authority.Approved = oldAssociation;
        Assert.Equal(ResolverDefinitionStatus.Replayed, (await h.Publish(original)).Status);
        Assert.Equal(1, await h.Count("entitlement_resolver_definition_profile"));
        Assert.Equal(2, await h.Count("platform_command"));
        Assert.Equal(2, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task ConcurrentConflictingSameVersionRollsBackAllLosingEffects()
    {
        using var h = await Harness.Create();
        var a = h.Define("v1");
        var authorityA = new Authority { Approved = h.Authority.Approved };
        var artifactA = new Artifacts { Bytes = h.Artifacts.Bytes };
        var b = h.Define("v1", paid: false);
        var results = await Task.WhenAll(h.Publisher(authorityA, artifactA).PublishAsync(a, T.Ct), h.Publish(b));
        Assert.Single(results, r => r.Status == ResolverDefinitionStatus.Succeeded);
        Assert.Single(results, r => r.Status == ResolverDefinitionStatus.Conflict);
        Assert.Equal(1, await h.Count("entitlement_resolver_definition_profile"));
        Assert.Equal(1, await h.Count("platform_command"));
        Assert.Equal(1, await h.Count("platform_change_archive"));
        Assert.Equal(0, await h.Count("platform_command_guard"));
    }

    [Fact]
    public async Task ExactReceiptReplayRequiresHistoricalAuthorityButNotArtifactAvailability()
    {
        using var h = await Harness.Create(); var request = h.Define("v1");
        Assert.Equal(ResolverDefinitionStatus.Succeeded, (await h.Publish(request)).Status);
        h.Artifacts.Status = ResolverDefinitionStatus.Unavailable;
        Assert.Equal(ResolverDefinitionStatus.Replayed, (await h.Publish(request)).Status);
        Assert.Equal(1, h.Artifacts.Reads);
        var changed = request with { DocumentHash = new('b', 64) };
        h.Authority.Approved = h.Authority.Approved! with { DocumentHash = changed.DocumentHash };
        Assert.Equal(ResolverDefinitionStatus.ReusedIdentifier, (await h.Publish(changed)).Status);
        h.Authority.Status = ResolverDefinitionStatus.Unavailable;
        Assert.Equal(ResolverDefinitionStatus.Unavailable, (await h.Publish(request)).Status);
        h.Authority.Status = ResolverDefinitionStatus.Succeeded;
        h.Authority.Approved = h.Authority.Approved with { DocumentHash = request.DocumentHash };
        h.Clock.SetSeconds(8 * 86400);
        Assert.Equal(ResolverDefinitionStatus.ReceiptExpired, (await h.Publish(request)).Status);
        Assert.Equal(1, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task LostRealCommitResponseReconcilesWithoutRepeatingEffect()
    {
        using var h = await Harness.Create(); var request = h.Define("v1");
        var lost = new FaultPort(h.Port);
        Assert.Equal(ResolverDefinitionStatus.Replayed, (await h.Publisher(port: lost).PublishAsync(request, T.Ct)).Status);
        Assert.Equal(1, lost.Writes);
        Assert.Equal(1, await h.Count("platform_command"));
        Assert.Equal(1, await h.Count("entitlement_resolver_definition_profile"));
    }

    [Fact]
    public async Task CallerCancellationAfterRealCommitNeverReturnsSuccessOrClaimsRollback()
    {
        using var h = await Harness.Create(); var request = h.Define("v1");
        using var cancellation = CancellationTokenSource.CreateLinkedTokenSource(T.Ct);
        var lost = new FaultPort(h.Port, cancellation.Cancel);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Publisher(port: lost).PublishAsync(request, cancellation.Token));
        Assert.Equal(1, await h.Count("entitlement_resolver_definition_profile"));
        Assert.Equal(ResolverDefinitionStatus.Replayed, (await h.Publish(request)).Status);
        Assert.Equal(1, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task CurrentHeadChangedDuringReadCannotReturnEarlierDefinitions()
    {
        using var h = await Harness.Create(); var old = h.Define("v1"); await h.Publish(old);
        var oldHead = h.Authority.Approved!;
        var later = h.Define("v2", paid: false); await h.Publish(later);
        h.Authority.Sequence = new Queue<ApprovedResolverConfiguration>([oldHead, h.Authority.Approved!]);
        var current = new CurrentResolverDefinitionSource(h.Authority, h.Publisher());
        var read = await current.ReadAsync(h.Realm, T.Ct);
        Assert.Equal(ResolverDefinitionStatus.Succeeded, read.Status);
        Assert.Equal("v2", read.Value!.Definitions.Profile.DefinitionsVersion);
        Assert.False(Assert.Single(read.Value.Definitions.Profile.Capabilities).RequiresPaidTerm);
        h.Authority.Approved = oldHead;
        Assert.Equal(ResolverDefinitionStatus.Stale, await current.RevalidateAsync(read.Value, T.Ct));
        h.Define("not-materialized");
        Assert.Equal(ResolverDefinitionStatus.NotFound, (await current.ReadAsync(h.Realm, T.Ct)).Status);
        Assert.Equal(ResolverDefinitionStatus.Unavailable, (await new CurrentResolverDefinitionSource(null, h.Publisher()).ReadAsync(h.Realm, T.Ct)).Status);
    }

    [Fact]
    public async Task UnauthorizedOrAlteredArtifactCannotReachAnyWrite()
    {
        using var h = await Harness.Create(); var request = h.Define("v1");
        Assert.Equal(ResolverDefinitionStatus.Denied, (await h.Publish(request with { PublisherRef = "proposer" })).Status);
        Assert.Equal(0, h.Artifacts.Reads);
        h.Artifacts.Bytes = new byte[h.Artifacts.Bytes.Length];
        Assert.Equal(ResolverDefinitionStatus.Invalid, (await h.Publish(request)).Status);
        Assert.Equal(0, await h.Count("platform_command"));
        Assert.Equal(0, await h.Count("entitlement_resolver_definition_profile"));
    }

    [Fact]
    public async Task BoundedUnavailableRetriesReconcileThenResendTheExactCapturedCommit()
    {
        using var h = await Harness.Create(); var request = h.Define("v1");
        var retry = new RetryPort(h.Port, () => h.Clock.SetSeconds(100));
        Assert.Equal(ResolverDefinitionStatus.Succeeded, (await h.Publisher(port: retry).PublishAsync(request, T.Ct)).Status);
        Assert.Equal(3, retry.Writes.Count);
        Assert.All(retry.Writes, write =>
        {
            Assert.Empty(write.Commit!.Events);
            Assert.Equal(retry.Writes[0].Commit! with { Events = write.Commit.Events }, write.Commit);
        });
        Assert.All(retry.Writes, write => Assert.Equal(retry.Writes[0].OwnerArguments.SelectMany(a => a), write.OwnerArguments.SelectMany(a => a)));
        Assert.Equal(1, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task UnavailableReconciliationAfterRealCommitReturnsUnknownWithoutAnotherWrite()
    {
        using var h = await Harness.Create(); var request = h.Define("v1");
        var lost = new FaultPort(h.Port, receiptUnavailable: true);
        Assert.Equal(ResolverDefinitionStatus.UnknownOutcome, (await h.Publisher(port: lost).PublishAsync(request, T.Ct)).Status);
        Assert.Equal(1, lost.Writes);
        Assert.Equal(1, await h.Count("entitlement_resolver_definition_profile"));
        Assert.Equal(ResolverDefinitionStatus.Replayed, (await h.Publish(request)).Status);
    }

    private sealed class Harness : IDisposable
    {
        internal Guid Realm { get; } = Guid.NewGuid();
        internal SqliteBridgeExecutor Bridge { get; } = new();
        internal SettableTimeProvider Clock { get; } = new(DateTimeOffset.UnixEpoch.AddSeconds(10));
        internal IModulePlanPort Port { get; }
        internal Authority Authority { get; } = new();
        internal Artifacts Artifacts { get; } = new();
        private Harness() => Port = new ModulePlanPortFactory(Bridge, Bridge.Generation, Clock).For(EntitlementModule.Instance.Descriptor);
        internal static async Task<Harness> Create()
        {
            var h = new Harness();
            try
            {
                var pending = Path.Combine(T.RepoRoot().FullName, "src", "ArcForges.Cloud.Storage.D1", "Migrations", "pending", "entitlement__resolver-definition-profile.sql");
                if (File.Exists(pending)) await h.Bridge.ExecAsync(await File.ReadAllTextAsync(pending, T.Ct), T.Ct);
                return h;
            }
            catch { h.Dispose(); throw; }
        }
        internal ResolverDefinitionPublishRequest Define(string version, bool paid = true)
        {
            var request = new ResolverDefinitionPublishRequest(Guid.NewGuid(), Realm, Guid.NewGuid(), new('a', 64), "config:trusted-materializer");
            var bytes = ResolverDefinitionValidator.Encode(version, [new("assistant", paid, "released")], [new("bytes", ResolverDefinitionCombination.Sum)], [new("ai")]);
            var hash = Convert.ToHexStringLower(SHA256.HashData(bytes));
            Authority.Approved = new(Realm, request.ConfigurationRevisionId, request.DocumentHash, "official", version,
                "artifact:" + version, ResolverDefinitionValidator.ProfileName, hash, bytes.Length, request.PublisherRef);
            Artifacts.Bytes = bytes;
            return request;
        }
        internal ResolverDefinitionPublisher Publisher(Authority? authority = null, Artifacts? artifacts = null, IModulePlanPort? port = null)
            => new(new D1ResolverDefinitionStore(port ?? Port), authority ?? Authority, artifacts ?? Artifacts, new ResolverDefinitionValidator(), Clock);
        internal Task<ResolverDefinitionResult> Publish(ResolverDefinitionPublishRequest request) => Publisher().PublishAsync(request, T.Ct);
        internal Task<long> Count(string table) => Bridge.CountAsync(table, "1=1", T.Ct);
        public void Dispose() => Bridge.Dispose();
    }
    // Only unavailable signed Config/artifact boundaries are substituted. Named plans, Worker, SQLite and platform receipts execute real code.
    private sealed class Authority : IResolverApprovedConfigurationSource
    {
        internal ApprovedResolverConfiguration? Approved;
        internal ApprovedResolverConfiguration? CurrentApproved;
        internal ResolverDefinitionStatus Status = ResolverDefinitionStatus.Succeeded;
        internal ResolverDefinitionStatus? CurrentStatus;
        internal Queue<ApprovedResolverConfiguration>? Sequence;
        public Task<ResolverConfigurationResult> ReadHistoricalAsync(Guid realm, Guid revision, string hash, CancellationToken ct) => Task.FromResult(new ResolverConfigurationResult(Status, Approved));
        public Task<ResolverConfigurationResult> ReadCurrentAsync(Guid realm, CancellationToken ct)
            => Task.FromResult(new ResolverConfigurationResult(CurrentStatus ?? Status, Sequence is { Count: > 0 } ? Sequence.Dequeue() : CurrentApproved ?? Approved));
    }
    private sealed class Artifacts : IResolverDefinitionArtifactPort
    {
        internal byte[] Bytes = [];
        internal ResolverDefinitionStatus Status = ResolverDefinitionStatus.Succeeded;
        internal int Reads;
        internal Action? AfterRead;
        public Task<ResolverDefinitionArtifactResult> ReadAsync(string id, string profile, string hash, CancellationToken ct)
        { Reads++; AfterRead?.Invoke(); return Task.FromResult(new ResolverDefinitionArtifactResult(Status, Bytes)); }
    }
    private sealed class FaultPort(IModulePlanPort inner, Action? afterCommit = null, bool receiptUnavailable = false) : IModulePlanPort
    {
        internal int Writes;
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken ct) => receiptUnavailable && Writes > 0 && read.PlanId == "entitlement.resolver-definition-command"
            ? Task.FromResult(ModulePlanOutcome.Of(ModulePlanStatus.Unavailable)) : inner.ReadAsync(read, ct);
        public async Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken ct)
        {
            Writes++;
            Assert.Equal(ModulePlanStatus.Succeeded, (await inner.WriteAsync(write, ct)).Status);
            afterCommit?.Invoke();
            return ModulePlanOutcome.Of(ModulePlanStatus.UnknownOutcome);
        }
    }
    private sealed class RetryPort(IModulePlanPort inner, Action beforeRefusal) : IModulePlanPort
    {
        internal List<ModulePlanWrite> Writes { get; } = [];
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken ct) => inner.ReadAsync(read, ct);
        public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken ct)
        {
            Writes.Add(write);
            if (Writes.Count >= 3) return inner.WriteAsync(write, ct);
            beforeRefusal();
            return Task.FromResult(ModulePlanOutcome.Of(ModulePlanStatus.Unavailable));
        }
    }
}
