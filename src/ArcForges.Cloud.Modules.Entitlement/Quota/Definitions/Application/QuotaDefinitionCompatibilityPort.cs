// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Application;

internal sealed class QuotaDefinitionCompatibilityPort(IQuotaDefinitionStore store, IQuotaDefinitionValidator validator,
    IRealmAuthorityPort? realms) : IQuotaDefinitionCompatibilityPort
{
    public async Task<QuotaDefinitionStatus> CheckAsync(Guid realmId, QuotaSemanticProfile profile, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (realmId == Guid.Empty || profile is null || !InputRules.IsOpaqueReference(profile.DefinitionsVersion)
            || profile.Definitions.IsDefault || profile.Definitions.Length > QuotaDefinitionValidator.MaximumDefinitions
            || profile.Definitions.Any(d => d is null)) return QuotaDefinitionStatus.Invalid;
        // This reparse binds untrusted DTO fields to canonical bytes. Expected full resolver membership and signed approval are separate.
        var validated = validator.Validate(profile.CanonicalBytes, profile.DefinitionsVersion,
            profile.Definitions.Select(d => new QuotaResolverDefinition(d.Key, d.Combination)).ToArray(), cancellationToken);
        if (validated.Status != QuotaDefinitionStatus.Succeeded || validated.Profile is not { } captured
            || captured.Hash != profile.Hash || !captured.Definitions.SequenceEqual(profile.Definitions)) return QuotaDefinitionStatus.Invalid;
        if (realms is null) return QuotaDefinitionStatus.Unavailable;
        var realm = await realms.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (realm.Snapshot is not { } authority) return RealmStatus(realm.Failure);
        if (authority.RealmId != realmId) return QuotaDefinitionStatus.Denied;
        var result = await store.CheckAsync(realmId, captured, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var reopened = await realms.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (reopened.Snapshot is not { } current) return RealmStatus(reopened.Failure);
        return current == authority ? result : QuotaDefinitionStatus.Unavailable;
    }
    private static QuotaDefinitionStatus RealmStatus(RealmAuthorityFailure? failure)
        => failure == RealmAuthorityFailure.Defect ? QuotaDefinitionStatus.Defect : QuotaDefinitionStatus.Unavailable;
}
