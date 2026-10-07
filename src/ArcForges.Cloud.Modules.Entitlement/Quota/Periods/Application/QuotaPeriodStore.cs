// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Periods.Application;

internal sealed record QuotaPeriodStoredState(long Revision, EntitlementSnapshot Snapshot, string SnapshotHash,
    ImmutableArray<QuotaServiceTerm> Terms, ImmutableArray<QuotaServiceTermAction> Actions);
internal sealed record QuotaPeriodStoredResult(QuotaDefinitionStatus Status, QuotaPeriodStoredState? Value = null);
internal interface IQuotaPeriodStore
{
    Task<QuotaPeriodStoredResult> ReadAsync(Guid realmId, Guid workspaceId, CancellationToken cancellationToken);
}
