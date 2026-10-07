// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Application;

/// <summary>What one workspace holds in the Entitlement store: every record, the stored snapshot, and the revision of the store row group.</summary>
/// <param name="Records">Every grant, revocation, term, action and fact of the workspace.</param>
/// <param name="Snapshot">The stored derived snapshot, or null before the first one was computed.</param>
/// <param name="Revision">
/// A count that advances on every commit of this workspace, including a commit that does not change the snapshot version. A commit that
/// names a stale revision is refused, so two writers can never each derive a snapshot from a history the other has already changed.
/// </param>
internal sealed record EntitlementState(EntitlementRecordSet Records, EntitlementSnapshot? Snapshot, long Revision);

/// <summary>
/// A service term as its owner admission appends it: the interval the resolver reads (<see cref="Fact"/>) with every other column of the
/// term row (model 01). The row is immutable once appended; renewal, supersession and revocation are new rows and actions (TM-04).
/// </summary>
internal sealed record ServiceTermRow(
    ServiceTermFact Fact,
    string RealmId,
    string? SubscriptionRef,
    string PeriodRef,
    string? SupersedesId,
    string OfferId,
    string OfferSnapshotId,
    long SelectionPriority);

/// <summary>An append-only supersede or revoke of a term with its idempotency reference (one append per source reference).</summary>
internal sealed record TermActionRow(string ActionId, string SourceRef, TermActionFact Fact, string? ReplacementTermId);

/// <summary>A workspace status fact with its identifier and the reference of the admission that decided it (one append per reference).</summary>
internal sealed record StatusFactRow(string FactId, string SourceRef, WorkspaceStatusFact Fact);

/// <summary>
/// Records to append in one commit. The store only ever appends: no row is updated or deleted (GR-06, TM-04). Grants, revocations,
/// definitions activations, service terms, term actions and workspace status facts travel through this port and commit atomically with
/// the snapshot that reflects them. A feature release is global, takes no workspace revision and has its own append on the store.
/// </summary>
internal sealed record EntitlementAppend(
    ImmutableArray<Grant> Grants, ImmutableArray<Revocation> Revocations, ImmutableArray<DefinitionsActivation> Activations)
{
    public static EntitlementAppend None { get; } = new([], [], []);

    public ImmutableArray<ServiceTermRow> Terms { get; init; } = [];

    public ImmutableArray<TermActionRow> TermActions { get; init; } = [];

    public ImmutableArray<StatusFactRow> StatusFacts { get; init; } = [];

    public bool IsEmpty => Grants.IsEmpty && Revocations.IsEmpty && Activations.IsEmpty && Terms.IsEmpty && TermActions.IsEmpty && StatusFacts.IsEmpty;
}

internal enum CommitOutcome
{
    Committed,
    RevisionConflict,

    /// <summary>The store could not tell whether the commit happened. Nothing may be assumed; the same request may be sent again.</summary>
    UnknownOutcome,
}

internal enum FeatureReleaseOutcome
{
    Released,

    /// <summary>The feature already had this release: nothing was written.</summary>
    AlreadyReleased,

    /// <summary>The feature already has a different release instant: nothing was written.</summary>
    Conflict,
}

/// <summary>
/// The persistence port of the resolver. One call appends the new records and replaces the snapshot as one atomic unit of work, so a
/// grant never exists without the snapshot that reflects it. The D1 implementation is the module's own persistence (COM.16); the
/// resolver owns only this contract.
/// </summary>
internal interface IEntitlementStore
{
    ValueTask<EntitlementState> LoadAsync(string workspaceId, CancellationToken cancellationToken);

    /// <summary>Commits atomically, or returns <see cref="CommitOutcome.RevisionConflict"/> and changes nothing.</summary>
    ValueTask<CommitOutcome> CommitAsync(
        string workspaceId, long expectedRevision, EntitlementAppend append, EntitlementSnapshot snapshot, CancellationToken cancellationToken);

    /// <summary>
    /// Appends one global feature release (idempotent by feature). It takes no workspace revision: a snapshot learns of it at its next refresh,
    /// because a release is known only from its own instant and a snapshot computed earlier is unchanged by it.
    /// </summary>
    ValueTask<FeatureReleaseOutcome> AppendFeatureReleaseAsync(FeatureReleaseFact release, CancellationToken cancellationToken);
}

/// <summary>The existing owner's complete prepared mutation, reused by the closed current-definition family without another writer.</summary>
internal interface IEntitlementPreparedStore : IEntitlementStore
{
    ModulePlanWrite Prepare(string workspaceId, long expectedRevision, EntitlementAppend append, EntitlementSnapshot snapshot);
    CommitOutcome Classify(ModulePlanOutcome outcome);
}

/// <summary>Supplies the active definition set. The configuration module's activated revision stands behind it; the resolver never loads or validates configuration (CG-01).</summary>
internal interface IEntitlementDefinitionSource
{
    EntitlementDefinitions Current();
}

/// <summary>Allocates identifiers of new grants and revocations. The identifier source is a port so that the resolver stays deterministic under test.</summary>
internal interface IEntitlementIdSource
{
    string NewId();
}

/// <summary>Why the D1 store refused to answer. A stored value that does not read back as a record is a defect, never a guess. The store raises it; the service does not catch it.</summary>
internal enum EntitlementStoreFailure
{
    /// <summary>The store is overloaded or unreachable, or the history changed under a read on every attempt. Nothing was committed; retry later.</summary>
    Unavailable,

    /// <summary>A stored value or a plan answer is not what the physical schema and the plans promise, or a commit was refused by a constraint: a defect or a deployment skew.</summary>
    Defect,
}

internal sealed class EntitlementStoreException(EntitlementStoreFailure failure, string message) : Exception(message)
{
    public EntitlementStoreFailure Failure { get; } = failure;
}

internal enum EntitlementError
{
    InvalidRequest,
    InvalidHistory,
    Conflict,
    StaleVersion,
    UnknownGrant,
    ConcurrentUpdate,

    /// <summary>The store could not tell whether the commit happened; only the same request may be sent again.</summary>
    OutcomeUnknown,
}

/// <summary>The outcome of a service call: a value, or a typed refusal with a reason a caller or operator can read.</summary>
internal sealed record EntitlementResult<T>
{
    private EntitlementResult()
    {
    }

    public T? Value { get; private init; }

    public EntitlementError? Error { get; private init; }

    public string? Detail { get; private init; }

    /// <summary>True when an equal grant or revocation already existed and nothing was written.</summary>
    public bool Duplicate { get; private init; }

    public bool Succeeded => Error is null;

    public static EntitlementResult<T> Success(T value, bool duplicate = false) => new() { Value = value, Duplicate = duplicate };

    public static EntitlementResult<T> Failure(EntitlementError error, string detail) => new() { Error = error, Detail = detail };
}
