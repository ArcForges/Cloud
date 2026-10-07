// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.QuotaDefinitions;

public sealed class QuotaResolverDefinitionSourceTests
{
    private static readonly Guid Realm = Guid.Parse("20000000-0000-4000-8000-000000000001");

    [Fact]
    public async Task ActualInjectedResolverSetIsIndependentExactVersionAndRealmScoped()
    {
        var definitions = new Definitions();
        var source = new CurrentQuotaResolverDefinitionSource(definitions, new RealmPort());
        var result = await source.ReadAsync(Realm, "known-v1", TestContext.Current.CancellationToken);
        var value = Assert.IsType<QuotaResolverDefinitionSet>(result.Value);
        Assert.Equal(QuotaDefinitionStatus.Succeeded, result.Status);
        Assert.Equal("known-v1", value.DefinitionsVersion);
        Assert.Equal("official", value.RealmKind);
        Assert.Equal(QuotaDefinitionCombination.PriorityReplace, Assert.Single(value.Quotas).Combination);
        Assert.Equal("independent-key", Assert.Single(value.Quotas).Key);
        Assert.Equal(QuotaDefinitionStatus.NotFound, (await source.ReadAsync(Realm, "candidate-future", TestContext.Current.CancellationToken)).Status);
        Assert.Equal(QuotaDefinitionStatus.Denied, (await source.ReadAsync(Guid.NewGuid(), "known-v1", TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public async Task MissingProducerAndRealRealmRefusalNeverYieldDefaultDefinitions()
    {
        Assert.Equal(QuotaDefinitionStatus.Unavailable, (await new CurrentQuotaResolverDefinitionSource(null, new RealmPort())
            .ReadAsync(Realm, "known-v1", TestContext.Current.CancellationToken)).Status);
        Assert.Equal(QuotaDefinitionStatus.Unavailable, (await new CurrentQuotaResolverDefinitionSource(new Definitions(), null)
            .ReadAsync(Realm, "known-v1", TestContext.Current.CancellationToken)).Status);
        var definitions = new Definitions();
        var refused = await new CurrentQuotaResolverDefinitionSource(definitions, new RealmPort(RealmAuthorityFailure.ClosedRecovery))
            .ReadAsync(Realm, "known-v1", TestContext.Current.CancellationToken);
        Assert.Equal(QuotaDefinitionStatus.Unavailable, refused.Status);
        Assert.Null(refused.Value);
        Assert.Equal(0, definitions.Reads);
    }

    [Fact]
    public async Task BufferedRealmAnswerAfterCancellationNeverReadsOrReturnsDefinitions()
    {
        using var cancel = new CancellationTokenSource();
        var definitions = new Definitions();
        var source = new CurrentQuotaResolverDefinitionSource(definitions, new RealmPort(afterRead: cancel.Cancel));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => source.ReadAsync(Realm, "known-v1", cancel.Token));
        Assert.Equal(0, definitions.Reads);
    }

    [Fact]
    public async Task InvalidCurrentRowsAndTypedUnavailableSourceRefuseWithoutInventingDefinitions()
    {
        var definitions = new Definitions { Value = new("known-v1", [], default, [], false) };
        Assert.Equal(QuotaDefinitionStatus.Defect, (await new CurrentQuotaResolverDefinitionSource(definitions, new RealmPort()).ReadAsync(Realm, "known-v1", TestContext.Current.CancellationToken)).Status);
        definitions.Value = new("known-v1", [], [new("duplicate", QuotaCombination.Sum), new("duplicate", QuotaCombination.Max)], [], false);
        Assert.Equal(QuotaDefinitionStatus.Defect, (await new CurrentQuotaResolverDefinitionSource(definitions, new RealmPort()).ReadAsync(Realm, "known-v1", TestContext.Current.CancellationToken)).Status);
        definitions.Failure = EntitlementStoreFailure.Unavailable;
        Assert.Equal(QuotaDefinitionStatus.Unavailable, (await new CurrentQuotaResolverDefinitionSource(definitions, new RealmPort()).ReadAsync(Realm, "known-v1", TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public async Task BufferedCurrentSourceCancellationPrecedesEvenUnknownVersionRefusal()
    {
        using var cancel = new CancellationTokenSource();
        var definitions = new Definitions { AfterRead = cancel.Cancel };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => new CurrentQuotaResolverDefinitionSource(definitions, new RealmPort()).ReadAsync(Realm, "unknown", cancel.Token));
    }

    private sealed class Definitions : IEntitlementDefinitionSource
    {
        public int Reads { get; private set; }
        internal EntitlementDefinitions Value = new("known-v1", [], [new("independent-key", QuotaCombination.PriorityReplace)], [], false);
        internal EntitlementStoreFailure? Failure;
        internal Action? AfterRead;
        public EntitlementDefinitions Current()
        {
            Reads++;
            if (Failure is { } failure) throw new EntitlementStoreException(failure, "Unavailable definition producer fixture.");
            AfterRead?.Invoke(); return Value;
        }
    }
    private sealed class RealmPort(RealmAuthorityFailure? failure = null, Action? afterRead = null) : IRealmAuthorityPort
    {
        public Task<RealmAuthorityResult> ResolveAsync(CancellationToken cancellationToken)
        {
            afterRead?.Invoke();
            return Task.FromResult(failure is { } denied ? RealmAuthorityResult.Refused(denied)
                : RealmAuthorityResult.Available(new(Realm, 1, 0, 1)));
        }
    }
}
