// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Application;

internal sealed class CurrentResolverDefinitionSource(IResolverApprovedConfigurationSource? configurations,
    IResolverDefinitionPort profiles) : ICurrentResolverDefinitionSource
{
    public async Task<CurrentResolverDefinitionResult> ReadAsync(Guid realmId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (realmId == Guid.Empty) return new(ResolverDefinitionStatus.Invalid);
        if (configurations is null) return new(ResolverDefinitionStatus.Unavailable);
        for (var attempt = 0; attempt < 3; attempt++)
        {
            var head = await configurations.ReadCurrentAsync(realmId, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (head.Status != ResolverDefinitionStatus.Succeeded || head.Value is not { } approved)
                return new(head.Status == ResolverDefinitionStatus.Succeeded ? ResolverDefinitionStatus.Defect : head.Status);
            if (!Valid(approved) || approved.RealmId != realmId) return new(ResolverDefinitionStatus.Defect);
            var stored = await profiles.ReadAsync(realmId, approved.DefinitionsVersion, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (stored.Status != ResolverDefinitionStatus.Succeeded || stored.Value is not { } profile)
                return new(stored.Status == ResolverDefinitionStatus.Succeeded ? ResolverDefinitionStatus.Defect : stored.Status);
            if (!Matches(approved, profile)) return new(ResolverDefinitionStatus.Stale);
            var captured = new CurrentResolverDefinitions(approved, profile);
            var revalidated = await RevalidateAsync(captured, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (revalidated == ResolverDefinitionStatus.Succeeded) return new(revalidated, captured);
            if (revalidated != ResolverDefinitionStatus.Stale) return new(revalidated);
        }
        return new(ResolverDefinitionStatus.Stale);
    }

    public async Task<ResolverDefinitionStatus> RevalidateAsync(CurrentResolverDefinitions captured, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (captured is null || !Valid(captured.Configuration) || !Matches(captured.Configuration, captured.Definitions)) return ResolverDefinitionStatus.Invalid;
        if (configurations is null) return ResolverDefinitionStatus.Unavailable;
        var head = await configurations.ReadCurrentAsync(captured.Configuration.RealmId, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (head.Status != ResolverDefinitionStatus.Succeeded || head.Value is not { } current)
            return head.Status == ResolverDefinitionStatus.Succeeded ? ResolverDefinitionStatus.Defect : head.Status;
        return Valid(current) && current == captured.Configuration ? ResolverDefinitionStatus.Succeeded : ResolverDefinitionStatus.Stale;
    }

    internal static bool Valid(ApprovedResolverConfiguration? value)
        => value is not null && value.RealmId != Guid.Empty && value.ConfigurationRevisionId != Guid.Empty
            && Hash(value.DocumentHash) && value.RealmKind is "official" or "selfHosted"
            && ArcForges.Cloud.Modules.Entitlement.Resolver.Domain.InputRules.IsOpaqueReference(value.DefinitionsVersion)
            && Identifier(value.ArtifactId) && value.ArtifactProfile == ResolverDefinitionValidator.ProfileName
            && Hash(value.ArtifactHash) && value.VerifiedLength is >= 2 and <= ResolverDefinitionValidator.MaximumBytes
            && Publisher(value.PublisherRef);
    internal static bool Matches(ApprovedResolverConfiguration approved, StoredResolverDefinitionProfile? stored)
        => stored is not null && stored.RealmId == approved.RealmId && stored.Profile.DefinitionsVersion == approved.DefinitionsVersion
            && stored.Profile.Hash == approved.ArtifactHash && stored.ArtifactHash == approved.ArtifactHash
            && stored.ArtifactId == approved.ArtifactId && stored.ArtifactLength == approved.VerifiedLength
            && stored.Profile.CanonicalBytes.Length == approved.VerifiedLength && stored.RealmKind == approved.RealmKind;
    internal static bool Hash(string? value) => value is { Length: 64 } && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    internal static bool Identifier(string? value) => TextIdentifier(value, 128);
    internal static bool Publisher(string? value) => TextIdentifier(value, 256);
    private static bool TextIdentifier(string? value, int maximum) => value is { Length: > 0 } && value.Length <= maximum && !string.IsNullOrWhiteSpace(value)
        && !value.Any(char.IsControl) && Utf16.IsWellFormed(value) && System.Text.Encoding.UTF8.GetByteCount(value) <= maximum;
}
