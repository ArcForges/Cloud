// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;

namespace ArcForges.Cloud.Modules;

public enum QuotaServiceTermKind { Subscription, Pass, Compensation, SelfHostGrant }
public enum QuotaTermActionKind { Supersede, Revoke }
public enum QuotaResolvedReason { Available, NoEntitlement, SubscriptionExpired, PaymentGrace, QuotaExceeded, TemporarilyRestricted, WorkspaceSuspended, FeatureUnavailable }

/// <summary>Immutable paid interval and actual pinned selection priority. Actions affect eligibility, never its period identity.</summary>
public sealed record QuotaServiceTerm(Guid TermId, Guid RealmId, Guid WorkspaceId, QuotaServiceTermKind Kind, string PeriodRef,
    long StartsAtMicros, long EndsAtMicros, long AuthorizedAtMicros, long SelectionPriority, long CreatedAtMicros);
public sealed record QuotaServiceTermAction(Guid ActionId, Guid TermId, QuotaTermActionKind Kind, long EffectiveAtMicros,
    long RecordedAtMicros, string SourceRef, Guid? ReplacementTermId);
public sealed record QuotaSelectedPeriod(string PeriodKey, QuotaServiceTerm Term, long EligibleFromMicros, long EligibleUntilMicros);
public sealed record QuotaResolvedDefinition(QuotaSemanticDefinition Definition, long Limit, QuotaResolvedReason Reason, string? PeriodKey);

/// <summary>Actual owned read provenance; this is not a permission capability or a same-batch authorization contribution.</summary>
public sealed record QuotaPeriodSnapshot(Guid RealmId, Guid WorkspaceId, ApprovedQuotaConfiguration Configuration,
    long EntitlementRevision, long SnapshotVersion, string SnapshotHash, long ComputedAtMicros, long ObservedAtMicros,
    long? ValidUntilMicros, bool PaidTermActive, QuotaSelectedPeriod? SelectedPeriod,
    ImmutableArray<QuotaResolvedDefinition> Quotas, ImmutableArray<QuotaServiceTerm> Terms,
    ImmutableArray<QuotaServiceTermAction> Actions);
public sealed record QuotaPeriodResult(QuotaDefinitionStatus Status, QuotaPeriodSnapshot? Value = null);

/// <summary>Reopens real current Config association and persistent positive Entitlement revision/snapshot/normalized terms.
/// The operation owner must still authorize the workspace and join real current owner guards before any new work.</summary>
public interface IQuotaPeriodSource
{
    Task<QuotaPeriodResult> ReadAsync(Guid realmId, Guid workspaceId, CancellationToken cancellationToken);
}
