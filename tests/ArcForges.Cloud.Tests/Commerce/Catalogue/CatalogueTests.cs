// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Commerce;
using ArcForges.Cloud.Modules.Commerce.Catalogue.Application;
using ArcForges.Cloud.Modules.Commerce.Catalogue.Infrastructure;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Entitlement;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.Commerce.Catalogue;

public sealed class CatalogueTests
{
    [Fact]
    public async Task PersistedPricesSupersedeAtStartAndExpiredNewestNeverResurrectsHistory()
    {
        using var h = new Harness();
        var first = h.Request();
        Assert.Equal(CataloguePublishStatus.Published, (await h.Publish(first)).Status);
        var next = h.Request(first.Publication with
        {
            ExpectedOfferRevision = 1,
            PriceVersionId = Id(21),
            PriceVersion = 3,
            Amount = "7.125",
            StartsAtMicros = 20_000_000,
            EndsAtMicros = 30_000_000,
            ConfigurationRevisionId = Id(22)
        });
        Assert.Equal(CataloguePublishStatus.Published, (await h.Publish(next)).Status);
        Assert.Equal(first.Publication.PriceVersionId, (await h.Reader.ReadEffectiveAsync(first.Publication.OfferId, T.Ct)).Value!.PriceVersionId);
        h.Clock.SetSeconds(20);
        Assert.Equal("7.125", (await h.Reader.ReadEffectiveAsync(first.Publication.OfferId, T.Ct)).Value!.Amount);
        h.Clock.SetSeconds(30);
        Assert.Equal(CatalogueReadStatus.NotFound, (await h.Reader.ReadEffectiveAsync(first.Publication.OfferId, T.Ct)).Status);
        var restarted = new CatalogueReader(new D1CatalogueStore(h.Port), h.Clock);
        var historical = (await restarted.ReadPriceAsync(first.Publication.PriceVersionId, T.Ct)).Value!;
        Assert.Equal(first.Publication.Amount, historical.Amount);
        Assert.Equal(first.Publication.Currency, historical.Currency);
        Assert.Equal(first.Publication.TermProfile, historical.TermProfile);
        Assert.Equal(first.Publication.ConfigurationRevisionId, historical.ConfigurationRevisionId);
        Assert.Null(historical.EndsAtMicros);
        Assert.Contains("af_immutable_commerce_price_version", await h.Bridge.RefusalAsync($"UPDATE commerce_price_version SET ends_at=20 WHERE price_version_id='{historical.PriceVersionId:D}';", T.Ct));
        Assert.Equal(2, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task GuardedRacesCommitExactlyOneAndStaleOrStructuralChangesLeaveNoPartialEffects()
    {
        using var h = new Harness();
        var first = h.Request();
        var other = h.Request(first.Publication with { PriceVersionId = Id(25), ConfigurationRevisionId = Id(26), Amount = "9" });
        var race = await System.Threading.Tasks.Task.WhenAll(h.Publish(first), h.Publish(other));
        Assert.Single(race, r => r.Status == CataloguePublishStatus.Published);
        Assert.Single(race, r => r.Status == CataloguePublishStatus.Conflict);
        Assert.Equal(1, await h.Count("commerce_offer"));
        Assert.Equal(1, await h.Count("commerce_price_version"));
        Assert.Equal(1, await h.Count("platform_command"));
        Assert.Equal(1, await h.Count("platform_change_archive"));
        Assert.Equal(0, await h.Count("platform_command_guard"));
        var structural = h.Request(first.Publication with
        {
            ExpectedOfferRevision = 1,
            Kind = 2,
            PriceVersion = 2,
            StartsAtMicros = 6_000_000,
            PriceVersionId = Id(27),
            ConfigurationRevisionId = Id(28)
        });
        Assert.Equal(CataloguePublishStatus.Conflict, (await h.Publish(structural)).Status);
        var state = (await h.Reader.ReadAsync(first.Publication.OfferId, T.Ct)).Value!;
        Assert.Equal(1, state.OfferRevision);
        Assert.Equal(1, state.LatestPriceVersion);
        Assert.Equal(1, state.Kind);
        Assert.Equal(1, await h.Count("platform_command"));
    }

    [Fact]
    public async Task SameCommandReplaysAndChangedContentOrPublisherCannotReuseIt()
    {
        using var h = new Harness();
        var request = h.Request();
        Assert.Equal(CataloguePublishStatus.Published, (await h.Publish(request)).Status);
        Assert.Equal(CataloguePublishStatus.Replayed, (await h.Publish(request)).Status);
        Assert.Equal(CataloguePublishStatus.ReusedIdentifier, (await h.Publish(request with { Publication = request.Publication with { Amount = "99" } })).Status);
        Assert.Equal(CataloguePublishStatus.ReusedIdentifier, (await h.Publish(request with { PublisherRef = "operator:other" })).Status);
        Assert.Equal(1, await h.Count("commerce_price_version"));
        Assert.Equal(1, await h.Count("platform_change_archive"));
        h.Clock.SetSeconds(8 * 86400);
        Assert.Equal(CataloguePublishStatus.ReceiptExpired, (await h.Publish(request)).Status);
    }

    [Fact]
    public async Task LostSuccessfulResponseRetriesSameReceiptAndTransientFailuresAreBounded()
    {
        using var h = new Harness();
        var lost = new FaultPort(h.Port, ModulePlanStatus.UnknownOutcome, applyFirst: true);
        var publisher = new CataloguePublisher(new D1CatalogueStore(lost), h.Authority, h.Clock, TimeSpan.FromDays(7));
        var request = h.Request();
        h.Authority.Approve(request);
        Assert.Equal(CataloguePublishStatus.Replayed, (await publisher.PublishAsync(request, T.Ct)).Status);
        Assert.Equal(2, lost.Writes.Count);
        Assert.Equal(lost.Writes[0].Commit, lost.Writes[1].Commit);
        Assert.Equal(1, await h.Count("commerce_price_version"));
        var unavailable = new FaultPort(h.Port, ModulePlanStatus.Unavailable);
        publisher = new(new D1CatalogueStore(unavailable), h.Authority, h.Clock, TimeSpan.FromDays(7));
        Assert.Equal(CataloguePublishStatus.Unavailable, (await publisher.PublishAsync(request, T.Ct)).Status);
        Assert.Equal(3, unavailable.Writes.Count);
        var refused = new FaultPort(h.Port, ModulePlanStatus.Rejected);
        publisher = new(new D1CatalogueStore(refused), h.Authority, h.Clock, TimeSpan.FromDays(7));
        Assert.Equal(CataloguePublishStatus.Rejected, (await publisher.PublishAsync(request, T.Ct)).Status);
        Assert.Single(refused.Writes);
    }

    [Fact]
    public async Task ActualEvidenceIsRequiredAndEveryBindingOrApprovalFailureRefusesBeforePersistence()
    {
        using var h = new Harness();
        var request = h.Request();
        h.Authority.Approve(request);
        var proof = h.Authority.Evidence!;
        CataloguePublicationEvidence[] invalid =
        [
            proof with { ContentHash = new string('0', 64) }, proof with { ContentHash = proof.ContentHash.ToUpperInvariant() },
            proof with { OfferId = Id(99) }, proof with { ConfigurationRevisionId = Id(99) }, proof with { PublisherRef = "operator:forged" },
            proof with { ApproverRef = proof.ProposerRef }, proof with { ApprovalId = proof.ProposalId }, proof with { ProposalId = Guid.Empty },
            proof with { EffectiveAtMicros = proof.EffectiveAtMicros + 1 }, proof with { ApprovedAtMicros = 6_000_000 }, proof with { ApprovedAtMicros = -1 },
        ];
        foreach (var evidence in invalid)
        {
            h.Authority.Evidence = evidence;
            Assert.Equal(CataloguePublishStatus.Denied, (await h.Publisher.PublishAsync(request, T.Ct)).Status);
        }
        foreach (var (source, status) in new[] { (CatalogueAuthorityStatus.Denied, CataloguePublishStatus.Denied),
                     (CatalogueAuthorityStatus.Stale, CataloguePublishStatus.StaleApproval), (CatalogueAuthorityStatus.Unavailable, CataloguePublishStatus.Unavailable) })
        {
            h.Authority.Status = source;
            Assert.Equal(status, (await h.Publisher.PublishAsync(request, T.Ct)).Status);
        }
        h.Authority.Status = CatalogueAuthorityStatus.Approved;
        h.Authority.Evidence = null;
        Assert.Equal(CataloguePublishStatus.Denied, (await h.Publisher.PublishAsync(request, T.Ct)).Status);
        Assert.Equal(0, await h.Count("commerce_offer"));
        Assert.Equal(0, await h.Count("platform_command"));
    }

    [Fact]
    public async Task InvalidMoneyIdentifiersUnicodeBoundsAndCurrencyNeverReachAuthority()
    {
        using var h = new Harness();
        var request = h.Request();
        foreach (var amount in new[] { "0", "-1", "01", "1.0", ".5", "1.", "1e2", "1,5", "NaN", "1.1234567891", new string('9', 29) })
            Assert.Equal(CataloguePublishStatus.Invalid, (await h.Publisher.PublishAsync(request with { Publication = request.Publication with { Amount = amount } }, T.Ct)).Status);
        foreach (var p in new[] { request.Publication with { Currency = "usd" }, request.Publication with { Currency = "US" },
                     request.Publication with { OfferId = Guid.Empty }, request.Publication with { Name = "broken\uD800" },
                     request.Publication with { Scope = " invalid" }, request.Publication with { TermProfile = "\n" },
                     request.Publication with { Active = true, Kind = 4 }, request.Publication with { EndsAtMicros = 5_000_000 },
                     request.Publication with { ExpectedOfferRevision = long.MaxValue } })
            Assert.Equal(CataloguePublishStatus.Invalid, (await h.Publisher.PublishAsync(request with { Publication = p }, T.Ct)).Status);
        Assert.Equal(0, h.Authority.Calls);
        Assert.Equal(0, await h.Count("commerce_price_version"));
        Assert.Equal(CatalogueReadStatus.Rejected, (await h.Reader.ReadAsync(Guid.Empty, T.Ct)).Status);
        Assert.Equal(CatalogueReadStatus.Rejected, (await h.Reader.ListAsync(null, 101, T.Ct)).Status);
    }

    [Fact]
    public async Task CancellationPropagatesThroughAuthorityAndRetryWithoutCommit()
    {
        using var h = new Harness();
        var request = h.Request();
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Publisher.PublishAsync(request, cancelled.Token));
        Assert.Equal(0, h.Authority.Calls);
        h.Authority.Block = true;
        using var duringSource = new CancellationTokenSource(TimeSpan.FromMilliseconds(25));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Publisher.PublishAsync(request, duringSource.Token));
        h.Authority.Block = false;
        h.Authority.Approve(request);
        var unavailable = new FaultPort(h.Port, ModulePlanStatus.Unavailable);
        var publisher = new CataloguePublisher(new D1CatalogueStore(unavailable), h.Authority, h.Clock, TimeSpan.FromDays(7));
        using var duringRetry = new CancellationTokenSource(TimeSpan.FromMilliseconds(10));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => publisher.PublishAsync(request, duringRetry.Token));
        Assert.Single(unavailable.Writes);
        Assert.Equal(0, await h.Count("platform_command"));
    }

    [Fact]
    public async Task CancellationAfterTheActualCommitDoesNotPretendRollbackAndRecoveryReplays()
    {
        using var h = new Harness();
        var request = h.Request();
        h.Authority.Approve(request);
        using var cancelledResponse = new CancellationTokenSource();
        var publisher = new CataloguePublisher(new D1CatalogueStore(new CancelledResponsePort(h.Port, cancelledResponse)), h.Authority, h.Clock, TimeSpan.FromDays(7));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => publisher.PublishAsync(request, cancelledResponse.Token));
        Assert.Equal(1, await h.Count("commerce_price_version"));
        Assert.Equal(1, await h.Count("platform_command"));
        Assert.Equal(CataloguePublishStatus.Replayed, (await h.Publish(request)).Status);
        Assert.Equal(1, await h.Count("platform_change_archive"));
    }

    [Fact]
    public async Task FutureMetadataChangeDefersUntilEffectiveTimeAndInactiveOfferKeepsHistoricalPrice()
    {
        using var h = new Harness();
        var first = h.Request();
        Assert.Equal(CataloguePublishStatus.Published, (await h.Publish(first)).Status);
        var deactivate = h.Request(first.Publication with
        {
            ExpectedOfferRevision = 1,
            PriceVersionId = Id(44),
            ConfigurationRevisionId = Id(45),
            PriceVersion = 2,
            StartsAtMicros = 20_000_000,
            Active = false,
            Name = "retired display"
        });
        Assert.Equal(CataloguePublishStatus.Conflict, (await h.Publish(deactivate)).Status);
        Assert.True((await h.Reader.ReadAsync(first.Publication.OfferId, T.Ct)).Value!.Active);
        h.Clock.SetSeconds(25); // Late materialization is valid because approval preceded its effective start.
        Assert.Equal(CataloguePublishStatus.Published, (await h.Publish(deactivate)).Status);
        Assert.Equal(CatalogueReadStatus.NotFound, (await h.Reader.ReadEffectiveAsync(first.Publication.OfferId, T.Ct)).Status);
        Assert.Equal("3.25", (await h.Reader.ReadPriceAsync(first.Publication.PriceVersionId, T.Ct)).Value!.Amount);
        Assert.Equal(CataloguePublishStatus.Replayed, (await h.Publish(first)).Status);
    }

    [Fact]
    public async Task CanonicalProjectionAndCompositionAreDeterministicAndFailClosed()
    {
        using var h = new Harness();
        var request = h.Request();
        var original = CatalogueCanonical.Create(request.Publication);
        Assert.Equal(original, CatalogueCanonical.Create(request.Publication with { }));
        Assert.NotEqual(original.Hash, CatalogueCanonical.Create(request.Publication with { Amount = "3.251" }).Hash);
        Assert.DoesNotContain("\"expectedOfferRevision\":0", original.Json, StringComparison.Ordinal);
        var services = new ServiceCollection();
        services.AddSingleton<IModulePlanPortFactory>(new ModulePlanPortFactory(h.Bridge, h.Bridge.Generation, h.Clock));
        services.AddSingleton<TimeProvider>(h.Clock);
        ((IModuleBoundary)CommerceModule.Instance).Register(services);
        using var withoutAuthority = services.BuildServiceProvider();
        Assert.NotNull(withoutAuthority.GetRequiredService<ICatalogueStatePort>());
        Assert.NotNull(withoutAuthority.GetRequiredService<ICatalogueQueryPort>());
        Assert.Throws<InvalidOperationException>(() => withoutAuthority.GetRequiredService<ICataloguePublicationPort>());
        services.AddSingleton<ICataloguePublicationAuthority>(h.Authority);
        using var composed = services.BuildServiceProvider();
        h.Authority.Approve(request);
        Assert.Equal(CataloguePublishStatus.Published, (await composed.GetRequiredService<ICataloguePublicationPort>().PublishAsync(request, T.Ct)).Status);
        Assert.Equal(CatalogueReadStatus.Found, (await composed.GetRequiredService<ICatalogueQueryPort>().ListAsync(null, 1, T.Ct)).Status);
    }

    [Fact]
    public async Task CompletedOrderAndCapturedPaymentRetainOriginalPriceAfterPublication()
    {
        using var h = new Harness();
        var first = h.Request();
        Assert.Equal(CataloguePublishStatus.Published, (await h.Publish(first)).Status);
        var workspace = Id(70);
        await h.Bridge.SeedWorkspaceAsync(workspace, T.Ct);
        // Fixture records model unavailable checkout/provider recognition. Catalogue operations below use the actual component and plans.
        await h.Bridge.ExecAsync($"""
            INSERT INTO commerce_billing_account VALUES ('{Id(71):D}','{Id(72):D}',1,1);
            INSERT INTO commerce_purchase_intent VALUES ('{Id(73):D}','{Id(71):D}','{workspace:D}','{first.Publication.OfferId:D}','{first.Publication.PriceVersionId:D}',3,1,100);
            INSERT INTO commerce_order VALUES ('{Id(74):D}','{Id(73):D}','{Id(71):D}','{workspace:D}','{first.Publication.OfferId:D}','{first.Publication.PriceVersionId:D}','3.25','EUR',2,1,2,1);
            INSERT INTO commerce_provider_event VALUES ('{Id(75):D}','fixture-provider','fixture-event','fixture-paid','[]',1,2,2,0,NULL);
            INSERT INTO commerce_payment VALUES ('{Id(76):D}','{Id(74):D}','fixture-provider','fixture-payment','3.25','EUR',2,'{Id(75):D}',1,2,1);
            """, T.Ct);
        var changed = h.Request(first.Publication with
        {
            ExpectedOfferRevision = 1,
            PriceVersion = 2,
            PriceVersionId = Id(77),
            ConfigurationRevisionId = Id(78),
            StartsAtMicros = 6_000_000,
            Amount = "98.75",
            Currency = "JPY",
            TaxCategory = "later-tax"
        });
        Assert.Equal(CataloguePublishStatus.Published, (await h.Publish(changed)).Status);
        var order = Assert.Single(await h.Bridge.QueryAsync("SELECT price_version_id,amount,amount_currency FROM commerce_order;", T.Ct));
        Assert.Equal(new[] { first.Publication.PriceVersionId.ToString("D"), "3.25", "EUR" }, order);
        var payment = Assert.Single(await h.Bridge.QueryAsync("SELECT amount,amount_currency FROM commerce_payment;", T.Ct));
        Assert.Equal(new[] { "3.25", "EUR" }, payment);
        Assert.Contains("FOREIGN KEY", await h.Bridge.RefusalAsync($"DELETE FROM commerce_price_version WHERE price_version_id='{first.Publication.PriceVersionId:D}';", T.Ct));
        Assert.Equal("3.25", (await h.Reader.ReadPriceAsync(first.Publication.PriceVersionId, T.Ct)).Value!.Amount);
    }

    [Fact]
    public async Task KeysetPagesAndReadFailuresHaveExplicitBoundedResults()
    {
        using var h = new Harness();
        for (var i = 0; i < 3; i++)
        {
            var request = h.Request();
            request = request with { Publication = request.Publication with { OfferId = Id(80 + i), PriceVersionId = Id(90 + i), ConfigurationRevisionId = Id(95 + i) } };
            Assert.Equal(CataloguePublishStatus.Published, (await h.Publish(request)).Status);
        }
        var page = await h.Reader.ListAsync(null, 2, T.Ct);
        Assert.Equal(2, page.Values.Count);
        Assert.Equal(Id(81), page.NextCursor);
        var last = await h.Reader.ListAsync(page.NextCursor, 2, T.Ct);
        Assert.Equal(Id(82), Assert.Single(last.Values).OfferId);
        Assert.Null(last.NextCursor);
        Assert.Equal(CatalogueReadStatus.NotFound, (await h.Reader.ReadPriceAsync(Id(999), T.Ct)).Status);
        var malformed = new ReadPort(new(ModulePlanStatus.Succeeded, [[PlanValue.FromText("wrong")]]));
        var store = new D1CatalogueStore(malformed);
        Assert.Equal(CatalogueReadStatus.Rejected, (await store.ReadPriceAsync(Id(1), T.Ct)).Status);
        Assert.Equal(CatalogueReadStatus.Rejected, (await store.ReadStateAsync(Id(1), T.Ct)).Status);
        Assert.Equal(CatalogueReadStatus.Unavailable, (await new D1CatalogueStore(new ReadPort(ModulePlanOutcome.Of(ModulePlanStatus.Unavailable))).ListAsync(null, 2, 10, T.Ct)).Status);
    }

    private static Guid Id(int n) => Guid.Parse(D1EntitlementHarness.Uuid(n));

    private sealed class Harness : IDisposable
    {
        private int next = 100;
        internal SqliteBridgeExecutor Bridge { get; } = new();
        internal SettableTimeProvider Clock { get; } = new(DateTimeOffset.UnixEpoch.AddSeconds(10));
        internal Authority Authority { get; } = new();
        internal IModulePlanPort Port { get; }
        internal CatalogueReader Reader { get; }
        internal CataloguePublisher Publisher { get; }
        internal Harness()
        {
            Port = new ModulePlanPortFactory(Bridge, Bridge.Generation, Clock).For(CommerceModule.Instance.Descriptor);
            var store = new D1CatalogueStore(Port);
            Reader = new(store, Clock);
            Publisher = new(store, Authority, Clock, TimeSpan.FromDays(7));
        }
        internal CataloguePublishRequest Request(CataloguePublication? publication = null) => new(Id(Interlocked.Increment(ref next)), "operator:publisher",
            publication ?? new(Id(1), 1, "configured test offer", "workspace", true, "approved-profile", 0, Id(2), 1, "3.25", "EUR", "configured-tax", 5_000_000, null, Id(3)));
        internal Task<CataloguePublishResult> Publish(CataloguePublishRequest request)
        {
            Authority.Approve(request);
            return Publisher.PublishAsync(request, T.Ct);
        }
        internal Task<long> Count(string table) => Bridge.CountAsync(table, "1=1", T.Ct);
        public void Dispose() => Bridge.Dispose();
    }

    // Configuration producer is the unavailable dependency. Each fake approval binds the complete real canonical projection, never an unconditional success flag.
    private sealed class Authority : ICataloguePublicationAuthority
    {
        internal int Calls;
        internal bool Block;
        internal CatalogueAuthorityStatus Status = CatalogueAuthorityStatus.Approved;
        internal CataloguePublicationEvidence? Evidence;
        internal void Approve(CataloguePublishRequest request) => Evidence = new(request.Publication.ConfigurationRevisionId, request.Publication.OfferId,
            CatalogueCanonical.Create(request.Publication).Hash, request.PublisherRef, "operator:proposer", "operator:approver", Id(50), Id(51), 1_000_000, request.Publication.StartsAtMicros);
        public async Task<CatalogueAuthorityResult> VerifyAsync(Guid configurationRevisionId, Guid offerId, string publisherRef, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref Calls);
            cancellationToken.ThrowIfCancellationRequested();
            if (Block) await System.Threading.Tasks.Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return new(Status, Evidence);
        }
    }

    // Fault injection only at unavailable transport/outcome boundary; all successful calls use the actual plans and receipt adapter.
    private sealed class FaultPort(IModulePlanPort inner, ModulePlanStatus fault, bool applyFirst = false) : IModulePlanPort
    {
        internal List<ModulePlanWrite> Writes { get; } = [];
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken) => inner.ReadAsync(read, cancellationToken);
        public async Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Writes.Add(write);
            if (!applyFirst) return ModulePlanOutcome.Of(fault);
            if (Writes.Count == 1)
            {
                Assert.Equal(ModulePlanStatus.Succeeded, (await inner.WriteAsync(write, cancellationToken)).Status);
                return ModulePlanOutcome.Of(fault);
            }
            return await inner.WriteAsync(write, cancellationToken);
        }
    }

    private sealed class ReadPort(ModulePlanOutcome result) : IModulePlanPort
    {
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken) => System.Threading.Tasks.Task.FromResult(result);
        public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken) => throw new InvalidOperationException("Read test must not write.");
    }

    private sealed class CancelledResponsePort(IModulePlanPort inner, CancellationTokenSource responseCancellation) : IModulePlanPort
    {
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken) => inner.ReadAsync(read, cancellationToken);
        public async Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken)
        {
            var result = await inner.WriteAsync(write, cancellationToken);
            Assert.Equal(ModulePlanStatus.Succeeded, result.Status);
            responseCancellation.Cancel();
            cancellationToken.ThrowIfCancellationRequested();
            return result;
        }
    }
}
