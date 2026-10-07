// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Application;

internal sealed class ResolverDefinitionPublisher(IResolverDefinitionStore store, IResolverApprovedConfigurationSource? configurations,
    IResolverDefinitionArtifactPort? artifacts, IResolverDefinitionValidator validator, TimeProvider clock) : IResolverDefinitionPort
{
    public async Task<ResolverDefinitionResult> ReadAsync(Guid realmId, string definitionsVersion, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (realmId == Guid.Empty || !InputRules.IsOpaqueReference(definitionsVersion)) return new(ResolverDefinitionStatus.Invalid);
        var result = await store.ReadAsync(realmId, definitionsVersion, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        return result;
    }

    public async Task<ResolverDefinitionResult> PublishAsync(ResolverDefinitionPublishRequest request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (request is null || request.CommandId == Guid.Empty || request.RealmId == Guid.Empty || request.ConfigurationRevisionId == Guid.Empty
            || !CurrentResolverDefinitionSource.Hash(request.DocumentHash) || !CurrentResolverDefinitionSource.Publisher(request.PublisherRef)) return new(ResolverDefinitionStatus.Invalid);
        if (configurations is null || artifacts is null) return new(ResolverDefinitionStatus.Unavailable);
        var association = await configurations.ReadHistoricalAsync(request.RealmId, request.ConfigurationRevisionId, request.DocumentHash, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (association.Status != ResolverDefinitionStatus.Succeeded || association.Value is not { } approved)
            return new(association.Status == ResolverDefinitionStatus.Succeeded ? ResolverDefinitionStatus.Defect : association.Status);
        if (!CurrentResolverDefinitionSource.Valid(approved) || approved.RealmId != request.RealmId || approved.ConfigurationRevisionId != request.ConfigurationRevisionId
            || approved.DocumentHash != request.DocumentHash || approved.PublisherRef != request.PublisherRef) return new(ResolverDefinitionStatus.Denied);
        var requestHash = RequestHash(request);
        var replay = await ReplayAsync(request, requestHash, cancellationToken).ConfigureAwait(false);
        if (replay.Status != ResolverDefinitionStatus.NotFound) return replay;
        var artifact = await artifacts.ReadAsync(approved.ArtifactId, approved.ArtifactProfile, approved.ArtifactHash, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (artifact.Status != ResolverDefinitionStatus.Succeeded) return new(artifact.Status);
        var bytes = artifact.Bytes;
        if (bytes.Length != approved.VerifiedLength) return new(ResolverDefinitionStatus.Conflict);
        var validation = validator.Validate(bytes, approved.DefinitionsVersion, cancellationToken);
        if (validation.Status != ResolverDefinitionStatus.Succeeded || validation.Profile is not { } profile)
            return new(validation.Status == ResolverDefinitionStatus.Succeeded ? ResolverDefinitionStatus.Defect : validation.Status);
        if (profile.Hash != approved.ArtifactHash) return new(ResolverDefinitionStatus.Conflict);
        var publicationInstant = Now();
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var outcome = await store.PublishAsync(request, approved, profile, requestHash, publicationInstant, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            var status = ResolverDefinitionOutcomes.Status(outcome.Status);
            if (status == ResolverDefinitionStatus.Succeeded)
            {
                var read = await store.ReadAsync(request.RealmId, profile.DefinitionsVersion, cancellationToken).ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                return read.Status == ResolverDefinitionStatus.Succeeded ? read : new(ResolverDefinitionStatus.UnknownOutcome);
            }
            if (status is not (ResolverDefinitionStatus.Replayed or ResolverDefinitionStatus.UnknownOutcome or ResolverDefinitionStatus.Unavailable)) return new(status);
            replay = await ReplayAsync(request, requestHash, cancellationToken).ConfigureAwait(false);
            if (replay.Status != ResolverDefinitionStatus.NotFound)
                return status == ResolverDefinitionStatus.UnknownOutcome && replay.Status == ResolverDefinitionStatus.Unavailable
                    ? new(ResolverDefinitionStatus.UnknownOutcome) : replay;
            if (status == ResolverDefinitionStatus.Replayed) return new(ResolverDefinitionStatus.Defect);
            if (attempt == 2) return new(status);
            await Task.Delay(TimeSpan.FromMilliseconds(50 * (1 << attempt)), clock, cancellationToken).ConfigureAwait(false);
        }
        throw new InvalidOperationException("The bounded definition publication loop escaped.");
    }

    private async Task<ResolverDefinitionResult> ReplayAsync(ResolverDefinitionPublishRequest request, string hash, CancellationToken cancellationToken)
    {
        var receipt = await store.ReceiptAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (receipt.Status != ResolverDefinitionStatus.Succeeded || receipt.Value is not { } known) return new(receipt.Status);
        if (known.Actor != request.PublisherRef || known.Operation != ResolverDefinitionOutcomes.Operation || known.Hash != hash) return new(ResolverDefinitionStatus.ReusedIdentifier);
        if (Now() >= known.ExpiresAt) return new(ResolverDefinitionStatus.ReceiptExpired);
        if (known.Status == 3) return new(ResolverDefinitionStatus.Conflict);
        try
        {
            using var payload = JsonDocument.Parse(known.Payload ?? "", new() { MaxDepth = 2 });
            var root = payload.RootElement;
            if (root.GetProperty("realmId").GetString() != request.RealmId.ToString("D")) return new(ResolverDefinitionStatus.Defect);
            var read = await store.ReadAsync(request.RealmId, root.GetProperty("definitionsVersion").GetString()!, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (read.Status != ResolverDefinitionStatus.Succeeded || read.Value is not { } stored || stored.Profile.Hash != root.GetProperty("hash").GetString())
                return new(read.Status == ResolverDefinitionStatus.Unavailable ? ResolverDefinitionStatus.Unavailable : ResolverDefinitionStatus.Defect);
            return new(ResolverDefinitionStatus.Replayed, stored);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException)
        { cancellationToken.ThrowIfCancellationRequested(); return new(ResolverDefinitionStatus.Defect); }
    }
    private long Now() => checked((clock.GetUtcNow().UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks) / 10);
    internal static string RequestHash(ResolverDefinitionPublishRequest request)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> size = stackalloc byte[4];
        foreach (var field in new[] { "entitlement.resolver-definition-command.v1", request.RealmId.ToString("D"), request.ConfigurationRevisionId.ToString("D"), request.DocumentHash, request.PublisherRef })
        {
            var bytes = Encoding.UTF8.GetBytes(field); BinaryPrimitives.WriteInt32BigEndian(size, bytes.Length); hash.AppendData(size); hash.AppendData(bytes);
        }
        return Convert.ToHexStringLower(hash.GetHashAndReset());
    }
}
