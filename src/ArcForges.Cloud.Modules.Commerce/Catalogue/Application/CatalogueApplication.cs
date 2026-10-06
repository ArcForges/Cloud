// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Cloud.Modules.Commerce.Catalogue.Domain;

namespace ArcForges.Cloud.Modules.Commerce.Catalogue.Application;


internal interface ICatalogueStore
{
    Task<CatalogueStateResult> ReadStateAsync(Guid offerId, CancellationToken cancellationToken);
    Task<CataloguePriceResult> ReadPriceAsync(Guid priceVersionId, CancellationToken cancellationToken);
    Task<CataloguePriceResult> ReadEffectiveAsync(Guid offerId, long atMicros, CancellationToken cancellationToken);
    Task<CataloguePageResult> ListAsync(Guid? afterOfferId, int limit, long atMicros, CancellationToken cancellationToken);
    Task<ModulePlanOutcome> PublishAsync(CataloguePublishRequest request, CatalogueContent content, CataloguePublicationEvidence evidence, long nowMicros, TimeSpan receiptLifetime, CancellationToken cancellationToken);
}

internal sealed class CatalogueReader(ICatalogueStore store, TimeProvider clock) : ICatalogueStatePort, ICatalogueQueryPort
{
    public Task<CatalogueStateResult> ReadAsync(Guid offerId, CancellationToken cancellationToken) =>
        offerId == Guid.Empty ? System.Threading.Tasks.Task.FromResult(new CatalogueStateResult(CatalogueReadStatus.Rejected)) : store.ReadStateAsync(offerId, cancellationToken);

    public Task<CataloguePriceResult> ReadPriceAsync(Guid priceVersionId, CancellationToken cancellationToken) =>
        priceVersionId == Guid.Empty ? System.Threading.Tasks.Task.FromResult(new CataloguePriceResult(CatalogueReadStatus.Rejected)) : store.ReadPriceAsync(priceVersionId, cancellationToken);

    public Task<CataloguePriceResult> ReadEffectiveAsync(Guid offerId, CancellationToken cancellationToken) =>
        offerId == Guid.Empty ? System.Threading.Tasks.Task.FromResult(new CataloguePriceResult(CatalogueReadStatus.Rejected)) : store.ReadEffectiveAsync(offerId, Now(), cancellationToken);

    public Task<CataloguePageResult> ListAsync(Guid? afterOfferId, int limit, CancellationToken cancellationToken) =>
        limit is < 1 or > 100 || afterOfferId == Guid.Empty ? System.Threading.Tasks.Task.FromResult(new CataloguePageResult(CatalogueReadStatus.Rejected, [])) : store.ListAsync(afterOfferId, limit, Now(), cancellationToken);

    private long Now() => (clock.GetUtcNow().UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;
}

/// <summary>Only a trusted host/configuration activation caller invokes publication; there is deliberately no public ingress route.</summary>
internal sealed class CataloguePublisher(ICatalogueStore store, ICataloguePublicationAuthority authority, TimeProvider clock, TimeSpan receiptLifetime) : ICataloguePublicationPort
{
    public async Task<CataloguePublishResult> PublishAsync(CataloguePublishRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request is null || request.Publication is null || request.CommandId == Guid.Empty || !CatalogueValidation.Text(request.PublisherRef, 256)
            || !CatalogueValidation.Valid(request.Publication) || receiptLifetime <= TimeSpan.Zero)
            return new(CataloguePublishStatus.Invalid);
        var now = (clock.GetUtcNow().UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10;
        if (now < 0 || receiptLifetime.Ticks / 10 > long.MaxValue - now) return new(CataloguePublishStatus.Invalid);
        var content = CatalogueCanonical.Create(request.Publication);
        var approval = await authority.VerifyAsync(request.Publication.ConfigurationRevisionId, request.Publication.OfferId, request.PublisherRef, cancellationToken).ConfigureAwait(false);
        if (approval.Status != CatalogueAuthorityStatus.Approved)
            return new(approval.Status switch
            {
                CatalogueAuthorityStatus.Unavailable => CataloguePublishStatus.Unavailable,
                CatalogueAuthorityStatus.Stale => CataloguePublishStatus.StaleApproval,
                _ => CataloguePublishStatus.Denied,
            });
        var proof = approval.Evidence;
        if (proof is null || proof.ConfigurationRevisionId != request.Publication.ConfigurationRevisionId || proof.OfferId != request.Publication.OfferId
            || proof.PublisherRef != request.PublisherRef || !CatalogueValidation.Text(proof.ProposerRef, 256) || !CatalogueValidation.Text(proof.ApproverRef, 256)
            || proof.ProposerRef == proof.ApproverRef || proof.ProposalId == Guid.Empty || proof.ApprovalId == Guid.Empty || proof.ProposalId == proof.ApprovalId
            || proof.ApprovedAtMicros < 0 || proof.ApprovedAtMicros > now || proof.ApprovedAtMicros > proof.EffectiveAtMicros
            || proof.EffectiveAtMicros != request.Publication.StartsAtMicros || !HashEquals(content.Hash, proof.ContentHash))
            return new(CataloguePublishStatus.Denied);

        // Every retry retains the identical command/content and time. The real plan adapter checks the durable receipt before any repeat.
        for (var attempt = 0; ; attempt++)
        {
            var outcome = await store.PublishAsync(request, content, proof, now, receiptLifetime, cancellationToken).ConfigureAwait(false);
            if (outcome.Status is ModulePlanStatus.Unavailable or ModulePlanStatus.UnknownOutcome && attempt < 2)
            {
                await System.Threading.Tasks.Task.Delay(TimeSpan.FromMilliseconds(25 * (1 << attempt)), clock, cancellationToken).ConfigureAwait(false);
                continue;
            }
            return new(outcome.Status switch
            {
                ModulePlanStatus.Succeeded => CataloguePublishStatus.Published,
                ModulePlanStatus.Replayed => CataloguePublishStatus.Replayed,
                ModulePlanStatus.GuardRefused or ModulePlanStatus.ConstraintRefused => CataloguePublishStatus.Conflict,
                ModulePlanStatus.ReusedIdentifier => CataloguePublishStatus.ReusedIdentifier,
                ModulePlanStatus.ReceiptExpired => CataloguePublishStatus.ReceiptExpired,
                ModulePlanStatus.UnknownOutcome or ModulePlanStatus.Unavailable => CataloguePublishStatus.Unavailable,
                _ => CataloguePublishStatus.Rejected,
            }, outcome.Status is ModulePlanStatus.Succeeded or ModulePlanStatus.Replayed ? request.Publication.ExpectedOfferRevision + 1 : null);
        }
    }

    private static bool HashEquals(string expected, string? actual) => actual is { Length: 64 } && actual.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f')
        && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expected), Encoding.ASCII.GetBytes(actual));
}
