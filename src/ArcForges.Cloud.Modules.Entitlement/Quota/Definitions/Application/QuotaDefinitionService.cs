// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Application;

internal sealed class QuotaDefinitionService(IQuotaDefinitionStore store, IQuotaApprovedConfigurationSource? configurations,
    IQuotaDefinitionArtifactPort? artifacts, IQuotaResolverDefinitionSource? resolver, IQuotaDefinitionValidator validator, TimeProvider clock) : IQuotaDefinitionPort
{
    public async Task<QuotaDefinitionResult> ReadAsync(Guid realmId, string definitionsVersion, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (realmId == Guid.Empty || !QuotaDefinitionValidator.Version(definitionsVersion)) return new(QuotaDefinitionStatus.Invalid);
        var result = await store.ReadAsync(realmId, definitionsVersion, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    public async Task<QuotaDefinitionResult> PublishAsync(QuotaDefinitionPublishRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request is null || request.CommandId == Guid.Empty || request.RealmId == Guid.Empty || request.ConfigurationRevisionId == Guid.Empty
            || !Hash(request.DocumentHash) || !QuotaDefinitionValidator.Version(request.PublisherRef)) return new(QuotaDefinitionStatus.Invalid);
        if (configurations is null || artifacts is null || resolver is null) return new(QuotaDefinitionStatus.Unavailable);
        // Historical approved source is necessary for retained materialization commands. It is not current purchase authorization.
        var association = await configurations.ReadHistoricalAsync(request.RealmId, request.ConfigurationRevisionId, request.DocumentHash, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (association.Status != QuotaDefinitionStatus.Succeeded || association.Value is not { } approved) return new(association.Status == QuotaDefinitionStatus.Succeeded ? QuotaDefinitionStatus.Defect : association.Status);
        if (approved.RealmId != request.RealmId || approved.ConfigurationRevisionId != request.ConfigurationRevisionId || approved.DocumentHash != request.DocumentHash
            || approved.PublisherRef != request.PublisherRef || approved.ArtifactProfile != QuotaDefinitionValidator.ProfileName || !Hash(approved.ArtifactHash)
            || approved.VerifiedLength is < 2 or > QuotaDefinitionValidator.MaximumBytes || !QuotaDefinitionValidator.Version(approved.DefinitionsVersion)
            || !QuotaDefinitionValidator.Version(approved.ArtifactId) || approved.RealmKind is not ("official" or "selfHosted")
            || approved.ResolverDefinitions.IsDefault || approved.ResolverDefinitions.Length > QuotaDefinitionValidator.MaximumDefinitions) return new(QuotaDefinitionStatus.Denied);
        var requestHash = RequestHash(request);
        var receipt = await ReplayAsync(request, requestHash, cancellationToken).ConfigureAwait(false);
        if (receipt.Status != QuotaDefinitionStatus.NotFound) return receipt;
        var definitionSet = await resolver.ReadAsync(request.RealmId, approved.DefinitionsVersion, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (definitionSet.Status != QuotaDefinitionStatus.Succeeded || definitionSet.Value is not { } expected)
            return new(definitionSet.Status == QuotaDefinitionStatus.Succeeded ? QuotaDefinitionStatus.Defect : definitionSet.Status);
        if (expected.DefinitionsVersion != approved.DefinitionsVersion || expected.RealmKind != approved.RealmKind || expected.Quotas.IsDefault || expected.Quotas.Any(q => q is null) || approved.ResolverDefinitions.Any(q => q is null)
            || !expected.Quotas.OrderBy(q => q.Key, StringComparer.Ordinal).SequenceEqual(approved.ResolverDefinitions.OrderBy(q => q.Key, StringComparer.Ordinal))) return new(QuotaDefinitionStatus.Stale);
        var artifact = await artifacts.ReadAsync(approved.ArtifactId, approved.ArtifactProfile, approved.ArtifactHash, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (artifact.Status != QuotaDefinitionStatus.Succeeded) return new(artifact.Status);
        var bytes = artifact.Bytes;
        if (bytes.Length != approved.VerifiedLength) return new(QuotaDefinitionStatus.Conflict);
        var validation = validator.Validate(bytes, approved.DefinitionsVersion, expected.Quotas, cancellationToken);
        if (validation.Status != QuotaDefinitionStatus.Succeeded || validation.Profile is not { } profile) return new(validation.Status == QuotaDefinitionStatus.Succeeded ? QuotaDefinitionStatus.Defect : validation.Status);
        if (profile.Hash != approved.ArtifactHash) return new(QuotaDefinitionStatus.Conflict);
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var outcome = await store.PublishAsync(request, approved, profile, requestHash, Now(), cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var status = QuotaDefinitionOutcomes.Status(outcome.Status);
            if (status == QuotaDefinitionStatus.Succeeded)
            {
                var read = await store.ReadAsync(request.RealmId, profile.DefinitionsVersion, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                return read.Status == QuotaDefinitionStatus.Succeeded ? read : new(QuotaDefinitionStatus.UnknownOutcome);
            }
            if (status is not (QuotaDefinitionStatus.Replayed or QuotaDefinitionStatus.UnknownOutcome or QuotaDefinitionStatus.Unavailable)) return new(status);
            // A lost response may have committed. Inspect the retained receipt before ever resending the identical command.
            receipt = await ReplayAsync(request, requestHash, cancellationToken).ConfigureAwait(false);
            if (receipt.Status != QuotaDefinitionStatus.NotFound)
                return status == QuotaDefinitionStatus.UnknownOutcome && receipt.Status == QuotaDefinitionStatus.Unavailable
                    ? new(QuotaDefinitionStatus.UnknownOutcome) : receipt;
            if (status == QuotaDefinitionStatus.Replayed) return new(QuotaDefinitionStatus.Defect);
            if (attempt == 2) return new(status);
            await Task.Delay(TimeSpan.FromMilliseconds(50 * (1 << attempt)), clock, cancellationToken).ConfigureAwait(false);
        }
        throw new InvalidOperationException("Bounded quota publication loop escaped.");
    }

    private async Task<QuotaDefinitionResult> ReplayAsync(QuotaDefinitionPublishRequest request, string hash, CancellationToken cancellationToken)
    {
        var receipt = await store.ReceiptAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (receipt.Status != QuotaDefinitionStatus.Succeeded || receipt.Value is not { } known) return new(receipt.Status);
        if (known.Actor != request.PublisherRef || known.Operation != QuotaDefinitionOutcomes.Operation || known.Hash != hash) return new(QuotaDefinitionStatus.ReusedIdentifier);
        if (Now() >= known.ExpiresAt) return new(QuotaDefinitionStatus.ReceiptExpired);
        if (known.Status == 3) return new(QuotaDefinitionStatus.Conflict);
        try
        {
            using var payload = JsonDocument.Parse(known.Payload ?? "", new() { MaxDepth = 2 });
            var root = payload.RootElement;
            if (root.GetProperty("realmId").GetString() != request.RealmId.ToString("D")) return new(QuotaDefinitionStatus.Defect);
            var read = await store.ReadAsync(request.RealmId, root.GetProperty("definitionsVersion").GetString()!, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (read.Status != QuotaDefinitionStatus.Succeeded || read.Value is not { } profile || profile.Profile.Hash != root.GetProperty("hash").GetString())
                return new(read.Status is QuotaDefinitionStatus.Unavailable ? QuotaDefinitionStatus.Unavailable : QuotaDefinitionStatus.Defect);
            return new(QuotaDefinitionStatus.Replayed, profile);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException) { cancellationToken.ThrowIfCancellationRequested(); return new(QuotaDefinitionStatus.Defect); }
    }
    private long Now() => checked((clock.GetUtcNow().UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10);
    private static bool Hash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static string RequestHash(QuotaDefinitionPublishRequest request)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> size = stackalloc byte[4];
        foreach (var field in new[] { "entitlement.quota-definition-command.v1", request.RealmId.ToString("D"), request.ConfigurationRevisionId.ToString("D"), request.DocumentHash, request.PublisherRef })
        {
            var bytes = Encoding.UTF8.GetBytes(field); BinaryPrimitives.WriteInt32BigEndian(size, bytes.Length); hash.AppendData(size); hash.AppendData(bytes);
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}
