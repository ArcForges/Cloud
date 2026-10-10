// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

/// <summary>The stored lifecycle state of a workspace, exactly the closed values of the data model (<c>workspace_workspace.state</c>).</summary>
public enum WorkspaceRecordState
{
    Active = 1,
    Suspended = 2,
    PendingDeletion = 3,
}

/// <summary>
/// A stored workspace as the directory reports it: primitives only, no Workspace module type. The identifiers are canonical lower-case
/// UUID text, the instant is whole UTC microseconds and <see cref="Revision"/> is the workspace row's revision guard. A workspace has
/// exactly one owner user and no member, role or seat (WS-01 to WS-05).
/// </summary>
public sealed record WorkspaceRecord(
    string WorkspaceId,
    string RealmId,
    string OwnerUserId,
    string Name,
    string DataRegion,
    long ProtectionProfile,
    WorkspaceRecordState State,
    long CreatedAtMicros,
    long Revision);

/// <summary>The typed answers of a directory read. Nothing is coerced and no refusal carries a value of the request.</summary>
public enum WorkspaceDirectoryStatus
{
    /// <summary>The workspace exists in the realm (and, for a read by owner, belongs to that owner); it is returned with its state.</summary>
    Found,

    /// <summary>No workspace with that identity exists in the realm. A workspace of another realm is never visible.</summary>
    NotFound,

    /// <summary>An argument is not a canonical lower-case UUID; nothing was read.</summary>
    InvalidRequest,

    /// <summary>The store was overloaded, unreachable or at another recovery generation; nothing is known, and the same read may be sent again later.</summary>
    Unavailable,

    /// <summary>The plan was refused or the stored row cannot be interpreted: a defect or a deployment skew, never a retry and never a value.</summary>
    Defect,
}

/// <summary>The outcome of a directory read: the record when <see cref="Status"/> is <see cref="WorkspaceDirectoryStatus.Found"/>, otherwise none.</summary>
public sealed record WorkspaceDirectoryResult(WorkspaceDirectoryStatus Status, WorkspaceRecord? Workspace, string? Detail);

/// <summary>
/// The read side of the Workspace module for other modules (S54(1)): a workspace by its identifier or by its one owner, always scoped by
/// realm. It lives in the shared boundary project so that no module references the Workspace project, and it is implemented by the
/// Workspace module over its own named plans; each module reads only its own tables (the grant-port precedent).
/// </summary>
public interface IWorkspaceDirectory
{
    /// <summary>The workspace with this identifier in this realm.</summary>
    ValueTask<WorkspaceDirectoryResult> FindAsync(string realmId, string workspaceId, CancellationToken cancellationToken);

    /// <summary>The one workspace this user owns in this realm (the schema keeps at most one per owner and realm).</summary>
    ValueTask<WorkspaceDirectoryResult> FindByOwnerAsync(string realmId, string ownerUserId, CancellationToken cancellationToken);
}
