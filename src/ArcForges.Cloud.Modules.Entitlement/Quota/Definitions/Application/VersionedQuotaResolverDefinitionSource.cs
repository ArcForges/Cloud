// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Application;

/// <summary>Reads an accepted exact immutable COM.20 version under the current real realm/recovery authority.
/// Historical definitions remain available after a later configuration activation; approval of a unit artifact is separate.</summary>
internal sealed class VersionedQuotaResolverDefinitionSource(IResolverDefinitionPort? definitions,
    IRealmAuthorityPort? realms, IResolverDefinitionValidator validator) : IQuotaResolverDefinitionSource
{
    public async Task<QuotaResolverDefinitionResult> ReadAsync(Guid realmId, string definitionsVersion, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (realmId == Guid.Empty || !QuotaDefinitionValidator.Version(definitionsVersion) || !InputRules.IsOpaqueReference(definitionsVersion))
            return new(QuotaDefinitionStatus.Invalid);
        if (definitions is null || realms is null) return new(QuotaDefinitionStatus.Unavailable);
        var realm = await realms.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (realm.Snapshot is not { } captured) return new(RealmStatus(realm.Failure));
        if (captured.RealmId != realmId) return new(QuotaDefinitionStatus.Denied);
        var read = await definitions.ReadAsync(realmId, definitionsVersion, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (read.Status != ResolverDefinitionStatus.Succeeded || read.Value is not { } stored)
            return new(read.Status == ResolverDefinitionStatus.Succeeded ? QuotaDefinitionStatus.Defect : Status(read.Status));
        if (stored.RealmId != realmId || stored.Profile.DefinitionsVersion != definitionsVersion || stored.RealmKind is not ("official" or "selfHosted")
            || stored.ArtifactHash != stored.Profile.Hash || stored.ArtifactLength != stored.Profile.CanonicalBytes.Length)
            return new(QuotaDefinitionStatus.Defect);
        var validation = validator.Validate(stored.Profile.CanonicalBytes, definitionsVersion, cancellationToken);
        if (validation.Status != ResolverDefinitionStatus.Succeeded || validation.Profile is not { } profile || profile.Hash != stored.Profile.Hash)
            return new(QuotaDefinitionStatus.Defect);
        var reopened = await realms.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (reopened.Snapshot is not { } current) return new(RealmStatus(reopened.Failure));
        if (current != captured) return new(QuotaDefinitionStatus.Unavailable);
        var quotas = profile.Quotas.Select(q => new QuotaResolverDefinition(q.Key, q.Combination switch
        {
            ResolverDefinitionCombination.Sum => QuotaDefinitionCombination.Sum,
            ResolverDefinitionCombination.Max => QuotaDefinitionCombination.Max,
            ResolverDefinitionCombination.PriorityReplace => QuotaDefinitionCombination.PriorityReplace,
            _ => throw new InvalidOperationException("The validated resolver combination is not mapped."),
        })).ToImmutableArray();
        cancellationToken.ThrowIfCancellationRequested();
        return new(QuotaDefinitionStatus.Succeeded, new(profile.DefinitionsVersion, stored.RealmKind, quotas));
    }

    private static QuotaDefinitionStatus RealmStatus(RealmAuthorityFailure? failure)
        => failure == RealmAuthorityFailure.Defect ? QuotaDefinitionStatus.Defect : QuotaDefinitionStatus.Unavailable;

    private static QuotaDefinitionStatus Status(ResolverDefinitionStatus status) => status switch
    {
        ResolverDefinitionStatus.Replayed => QuotaDefinitionStatus.Defect,
        ResolverDefinitionStatus.NotFound => QuotaDefinitionStatus.NotFound,
        ResolverDefinitionStatus.Invalid => QuotaDefinitionStatus.Invalid,
        ResolverDefinitionStatus.Conflict => QuotaDefinitionStatus.Conflict,
        ResolverDefinitionStatus.Stale => QuotaDefinitionStatus.Stale,
        ResolverDefinitionStatus.Denied => QuotaDefinitionStatus.Denied,
        ResolverDefinitionStatus.Unavailable => QuotaDefinitionStatus.Unavailable,
        ResolverDefinitionStatus.UnknownOutcome => QuotaDefinitionStatus.UnknownOutcome,
        ResolverDefinitionStatus.ReusedIdentifier => QuotaDefinitionStatus.ReusedIdentifier,
        ResolverDefinitionStatus.ReceiptExpired => QuotaDefinitionStatus.ReceiptExpired,
        _ => QuotaDefinitionStatus.Defect,
    };
}
