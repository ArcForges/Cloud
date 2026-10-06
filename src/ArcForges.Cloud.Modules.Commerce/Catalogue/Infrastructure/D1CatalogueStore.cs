// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules.Commerce.Catalogue.Application;

namespace ArcForges.Cloud.Modules.Commerce.Catalogue.Infrastructure;

internal sealed class D1CatalogueStore(IModulePlanPort plans) : ICatalogueStore
{
    public async Task<CatalogueStateResult> ReadStateAsync(Guid offerId, CancellationToken cancellationToken)
    {
        var outcome = await plans.ReadAsync(new("commerce.catalogue-state", offerId.ToString("D"), [Id(offerId)]), cancellationToken).ConfigureAwait(false);
        if (outcome.Status != ModulePlanStatus.Succeeded) return new(ReadFailure(outcome.Status));
        if (outcome.Rows.Count == 0) return new(CatalogueReadStatus.NotFound);
        try
        {
            var r = outcome.Rows.Single();
            if (r.Count != 9) return new(CatalogueReadStatus.Rejected);
            return new(CatalogueReadStatus.Found, new(Guid.ParseExact(r[0].AsText(), "D"), checked((int)r[1].AsInt64()), r[2].AsText(), r[3].AsText(),
                r[4].AsBool(), r[5].AsText(), r[6].AsInt64(), r[7].AsInt64(), r[8].AsInt64()));
        }
        catch (Exception e) when (e is FormatException or InvalidOperationException or OverflowException) { return new(CatalogueReadStatus.Rejected); }
    }

    public async Task<CataloguePriceResult> ReadPriceAsync(Guid priceVersionId, CancellationToken cancellationToken) =>
        One(await plans.ReadAsync(new("commerce.catalogue-price", priceVersionId.ToString("D"), [Id(priceVersionId)]), cancellationToken).ConfigureAwait(false));

    public async Task<CataloguePriceResult> ReadEffectiveAsync(Guid offerId, long atMicros, CancellationToken cancellationToken) =>
        One(await plans.ReadAsync(new("commerce.catalogue-effective", offerId.ToString("D"), [Id(offerId), I(atMicros), I(atMicros)]), cancellationToken).ConfigureAwait(false));

    public async Task<CataloguePageResult> ListAsync(Guid? afterOfferId, int limit, long atMicros, CancellationToken cancellationToken)
    {
        var outcome = await plans.ReadAsync(new("commerce.catalogue-list", "commerce.catalogue",
            [T(afterOfferId?.ToString("D") ?? ""), I(atMicros), I(atMicros), I(limit + 1)]), cancellationToken).ConfigureAwait(false);
        if (outcome.Status != ModulePlanStatus.Succeeded) return new(ReadFailure(outcome.Status), []);
        try
        {
            var all = outcome.Rows.Select(Price).ToArray();
            var page = all.Take(limit).ToArray();
            return new(CatalogueReadStatus.Found, page, all.Length > limit ? page[^1].OfferId : null);
        }
        catch (Exception e) when (e is FormatException or InvalidOperationException or OverflowException) { return new(CatalogueReadStatus.Rejected, []); }
    }

    public Task<ModulePlanOutcome> PublishAsync(CataloguePublishRequest request, CatalogueContent content, CataloguePublicationEvidence evidence,
        long nowMicros, TimeSpan receiptLifetime, CancellationToken cancellationToken)
    {
        var p = request.Publication;
        var created = Math.Max(nowMicros, 1);
        var fingerprint = Json(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("publisher", request.PublisherRef);
            writer.WriteString("contentHash", content.Hash);
            writer.WriteEndObject();
        });
        var requestHash = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(fingerprint)));
        var archive = Json(writer =>
        {
            writer.WriteStartObject();
            writer.WriteString("kind", "commerce.catalogue-publication");
            writer.WriteString("publisher", evidence.PublisherRef);
            writer.WriteString("proposer", evidence.ProposerRef);
            writer.WriteString("approver", evidence.ApproverRef);
            writer.WriteString("proposalId", evidence.ProposalId.ToString("D"));
            writer.WriteString("approvalId", evidence.ApprovalId.ToString("D"));
            writer.WriteString("contentHash", content.Hash);
            writer.WritePropertyName("publication");
            writer.WriteRawValue(content.Json);
            writer.WriteEndObject();
        });
        var commit = new ModuleCommit(request.CommandId, null, request.PublisherRef, "commerce.catalogue-publish", requestHash, content.Json,
            p.ExpectedOfferRevision + 1, created, checked(created + receiptLifetime.Ticks / 10), [], 1, archive);
        IReadOnlyList<IReadOnlyList<PlanValue>> owner =
        [
            [Id(request.CommandId), Id(p.OfferId), I(p.Kind), T(p.Name), T(p.Scope), PlanValue.FromBool(p.Active), T(p.TermProfile),
                I(p.ExpectedOfferRevision), Id(p.PriceVersionId), I(p.PriceVersion), I(p.StartsAtMicros), I(nowMicros)],
            [Id(p.OfferId), I(p.Kind), T(p.Name), T(p.Scope), PlanValue.FromBool(p.Active), T(p.TermProfile), I(created), I(p.ExpectedOfferRevision)],
            [Id(p.PriceVersionId), Id(p.OfferId), I(p.PriceVersion), T(p.Amount), T(p.Currency), T(p.TaxCategory), I(p.StartsAtMicros), I(p.EndsAtMicros ?? -1), Id(p.ConfigurationRevisionId)],
        ];
        return plans.WriteAsync(new("commerce.catalogue-publish", p.OfferId.ToString("D"), owner, commit), cancellationToken);
    }

    private static CataloguePriceResult One(ModulePlanOutcome outcome)
    {
        if (outcome.Status != ModulePlanStatus.Succeeded) return new(ReadFailure(outcome.Status));
        if (outcome.Rows.Count == 0) return new(CatalogueReadStatus.NotFound);
        try { return new(CatalogueReadStatus.Found, Price(outcome.Rows.Single())); }
        catch (Exception e) when (e is FormatException or InvalidOperationException or OverflowException) { return new(CatalogueReadStatus.Rejected); }
    }

    private static CataloguePrice Price(IReadOnlyList<PlanValue> r)
    {
        if (r.Count != 15) throw new FormatException("Catalogue plan response shape differs from its reviewed contract.");
        return new(Guid.ParseExact(r[0].AsText(), "D"), checked((int)r[1].AsInt64()), r[2].AsText(), r[3].AsText(), r[4].AsBool(), r[5].AsText(), r[6].AsInt64(),
            Guid.ParseExact(r[7].AsText(), "D"), r[8].AsInt64(), r[9].AsText(), r[10].AsText(), r[11].AsText(), r[12].AsInt64(), r[13].AsOptionalInt64(), Guid.ParseExact(r[14].AsText(), "D"));
    }

    private static CatalogueReadStatus ReadFailure(ModulePlanStatus status) => status is ModulePlanStatus.Unavailable or ModulePlanStatus.UnknownOutcome or ModulePlanStatus.StaleGeneration
        ? CatalogueReadStatus.Unavailable : CatalogueReadStatus.Rejected;
    private static PlanValue Id(Guid value) => T(value.ToString("D"));
    private static PlanValue T(string value) => PlanValue.FromText(value);
    private static PlanValue I(long value) => PlanValue.FromInt64(value);
    private static string Json(Action<Utf8JsonWriter> write)
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream)) write(writer);
        return Encoding.UTF8.GetString(stream.ToArray());
    }
}
