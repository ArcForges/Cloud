// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Application;

/// <summary>Actual current resolver adapter, scoped by the real configured realm/recovery owner.
/// It does not invent future or historical definition sets; a versioned producer may supply this port instead.</summary>
internal sealed class CurrentQuotaResolverDefinitionSource(IEntitlementDefinitionSource? definitions, IRealmAuthorityPort? realms)
    : IQuotaResolverDefinitionSource
{
    public async Task<QuotaResolverDefinitionResult> ReadAsync(Guid realmId, string definitionsVersion, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (realmId == Guid.Empty || !QuotaDefinitionValidator.Version(definitionsVersion)) return new(QuotaDefinitionStatus.Invalid);
        if (definitions is null || realms is null) return new(QuotaDefinitionStatus.Unavailable);
        var realm = await realms.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (realm.Snapshot is not { } authority) return new(realm.Failure == RealmAuthorityFailure.Defect
            ? QuotaDefinitionStatus.Defect : QuotaDefinitionStatus.Unavailable);
        if (authority.RealmId != realmId) return new(QuotaDefinitionStatus.Denied);
        var current = definitions.Current();
        try { RecordSetValidator.Validate(EntitlementRecordSet.Empty(realmId.ToString("D")), current); }
        catch (ResolverInputException) { return new(QuotaDefinitionStatus.Defect); }
        if (current.Version != definitionsVersion) return new(QuotaDefinitionStatus.NotFound);
        if (current.Quotas.Length > QuotaDefinitionValidator.MaximumDefinitions) return new(QuotaDefinitionStatus.Invalid);
        var quotas = current.Quotas.Select(q => new QuotaResolverDefinition(q.Key, q.Combination switch
        {
            QuotaCombination.Sum => QuotaDefinitionCombination.Sum,
            QuotaCombination.Max => QuotaDefinitionCombination.Max,
            QuotaCombination.PriorityReplace => QuotaDefinitionCombination.PriorityReplace,
            _ => throw new InvalidOperationException("A validated resolver combination is not mapped."),
        })).ToImmutableArray();
        cancellationToken.ThrowIfCancellationRequested();
        return new(QuotaDefinitionStatus.Succeeded, new(current.Version, current.IsSelfHostRealm ? "selfHosted" : "official", quotas));
    }
}

