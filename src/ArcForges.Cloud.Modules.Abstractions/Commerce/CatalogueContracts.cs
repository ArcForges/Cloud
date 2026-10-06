// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ArcForges.Cloud.Modules;

/// <summary>The complete server-approved commercial projection; no provider payload or default price crosses this port.</summary>
public sealed record CataloguePublication(
    Guid OfferId, int Kind, string Name, string Scope, bool Active, string TermProfile,
    long ExpectedOfferRevision, Guid PriceVersionId, long PriceVersion, string Amount, string Currency,
    string TaxCategory, long StartsAtMicros, long? EndsAtMicros, Guid ConfigurationRevisionId);

/// <summary>The canonical JSON and SHA-256 binding of a commercial projection.</summary>
public sealed record CatalogueContent(string Json, string Hash);

/// <summary>Shared deterministic framing, not an authorization decision. Configuration approves precisely these bytes.</summary>
public static class CatalogueCanonical
{
    public static CatalogueContent Create(CataloguePublication publication)
    {
        ArgumentNullException.ThrowIfNull(publication);
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("offerId", publication.OfferId.ToString("D"));
            writer.WriteNumber("kind", publication.Kind);
            writer.WriteString("name", publication.Name);
            writer.WriteString("scope", publication.Scope);
            writer.WriteBoolean("active", publication.Active);
            writer.WriteString("termProfile", publication.TermProfile);
            writer.WriteString("expectedOfferRevision", publication.ExpectedOfferRevision.ToString(CultureInfo.InvariantCulture));
            writer.WriteString("priceVersionId", publication.PriceVersionId.ToString("D"));
            writer.WriteString("priceVersion", publication.PriceVersion.ToString(CultureInfo.InvariantCulture));
            writer.WriteString("amount", publication.Amount);
            writer.WriteString("currency", publication.Currency);
            writer.WriteString("taxCategory", publication.TaxCategory);
            writer.WriteString("startsAtMicros", publication.StartsAtMicros.ToString(CultureInfo.InvariantCulture));
            if (publication.EndsAtMicros is { } ends) writer.WriteString("endsAtMicros", ends.ToString(CultureInfo.InvariantCulture));
            else writer.WriteNull("endsAtMicros");
            writer.WriteString("configurationRevisionId", publication.ConfigurationRevisionId.ToString("D"));
            writer.WriteEndObject();
        }
        var bytes = stream.ToArray();
        return new(Encoding.UTF8.GetString(bytes), Convert.ToHexStringLower(SHA256.HashData(bytes)));
    }
}

/// <summary>Only the authoritative Configuration implementation may produce this evidence after verifying actual stored activation and dual approval.</summary>
public sealed record CataloguePublicationEvidence(
    Guid ConfigurationRevisionId, Guid OfferId, string ContentHash, string PublisherRef,
    string ProposerRef, string ApproverRef, Guid ProposalId, Guid ApprovalId,
    long ApprovedAtMicros, long EffectiveAtMicros);

public enum CatalogueAuthorityStatus { Approved, Denied, Stale, Unavailable }

public sealed record CatalogueAuthorityResult(CatalogueAuthorityStatus Status, CataloguePublicationEvidence? Evidence = null);

/// <summary>A trusted source verifies canonical publication content and publisher against active configuration, never a caller-supplied permission flag.</summary>
public interface ICataloguePublicationAuthority
{
    Task<CatalogueAuthorityResult> VerifyAsync(Guid configurationRevisionId, Guid offerId, string publisherRef, CancellationToken cancellationToken);
}

/// <summary>The owner-bound state needed by Configuration to prepare an exact CAS projection without reading Commerce tables.</summary>
public sealed record CatalogueState(Guid OfferId, int Kind, string Name, string Scope, bool Active, string TermProfile,
    long OfferRevision, long LatestPriceVersion, long LatestStartsAtMicros);

public enum CatalogueReadStatus { Found, NotFound, Unavailable, Rejected }

public sealed record CatalogueStateResult(CatalogueReadStatus Status, CatalogueState? Value = null);

public interface ICatalogueStatePort
{
    Task<CatalogueStateResult> ReadAsync(Guid offerId, CancellationToken cancellationToken);
}

public enum CataloguePublishStatus { Published, Replayed, Invalid, Denied, StaleApproval, Unavailable, Conflict, ReusedIdentifier, ReceiptExpired, Rejected }

public sealed record CataloguePublishRequest(Guid CommandId, string PublisherRef, CataloguePublication Publication);
public sealed record CataloguePublishResult(CataloguePublishStatus Status, long? OfferRevision = null);

/// <summary>Trusted configuration activation materialization; this port neither registers ingress nor authorizes purchases.</summary>
public interface ICataloguePublicationPort
{
    Task<CataloguePublishResult> PublishAsync(CataloguePublishRequest request, CancellationToken cancellationToken);
}

/// <summary>Exact persisted price terms. Name and active state are current display metadata; amount, currency, tax, structural profile and version identity never reprice history.</summary>
public sealed record CataloguePrice(Guid OfferId, int Kind, string Name, string Scope, bool Active, string TermProfile, long OfferRevision,
    Guid PriceVersionId, long PriceVersion, string Amount, string Currency, string TaxCategory, long StartsAtMicros, long? EndsAtMicros, Guid ConfigurationRevisionId);

public sealed record CataloguePriceResult(CatalogueReadStatus Status, CataloguePrice? Value = null);
public sealed record CataloguePageResult(CatalogueReadStatus Status, IReadOnlyList<CataloguePrice> Values, Guid? NextCursor = null);

/// <summary>Owner reads for display and exact historical lookup; a purchase still requires current configuration and provider mapping authorization.</summary>
public interface ICatalogueQueryPort
{
    Task<CataloguePriceResult> ReadPriceAsync(Guid priceVersionId, CancellationToken cancellationToken);
    Task<CataloguePriceResult> ReadEffectiveAsync(Guid offerId, CancellationToken cancellationToken);
    Task<CataloguePageResult> ListAsync(Guid? afterOfferId, int limit, CancellationToken cancellationToken);
}
