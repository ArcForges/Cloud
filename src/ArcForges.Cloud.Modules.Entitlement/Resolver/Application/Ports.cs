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
/// Records to append in one commit. The store only ever appends: no grant or revocation is updated or deleted (GR-06). Only grants,
/// revocations and definitions activations travel through this port: service terms, status facts and feature releases are appended
/// by their own owner admissions, which must extend the port (or share the unit of work) before they can commit atomically with a snapshot.
/// </summary>
internal sealed record EntitlementAppend(
    ImmutableArray<Grant> Grants, ImmutableArray<Revocation> Revocations, ImmutableArray<DefinitionsActivation> Activations)
{
    public static EntitlementAppend None { get; } = new([], [], []);
}

internal enum CommitOutcome
{
    Committed,
    RevisionConflict,
}

/// <summary>
/// The persistence port of the resolver. One call appends the new records and replaces the snapshot as one atomic unit of work, so a
/// grant never exists without the snapshot that reflects it. The D1 implementation belongs to the migration and plan tasks; the
/// resolver owns only this contract.
/// </summary>
internal interface IEntitlementStore
{
    ValueTask<EntitlementState> LoadAsync(string workspaceId, CancellationToken cancellationToken);

    /// <summary>Commits atomically, or returns <see cref="CommitOutcome.RevisionConflict"/> and changes nothing.</summary>
    ValueTask<CommitOutcome> CommitAsync(
        string workspaceId, long expectedRevision, EntitlementAppend append, EntitlementSnapshot snapshot, CancellationToken cancellationToken);
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

internal enum EntitlementError
{
    InvalidRequest,
    InvalidHistory,
    Conflict,
    StaleVersion,
    UnknownGrant,
    ConcurrentUpdate,
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
