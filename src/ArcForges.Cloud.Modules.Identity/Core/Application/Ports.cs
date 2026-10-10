// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Domain;

namespace ArcForges.Cloud.Modules.Identity.Core.Application;

/// <summary>A credential together with the user it belongs to, read in one lookup so a decision never mixes two moments.</summary>
internal sealed record CredentialLookup(AuthIdentity Credential, User User);

internal enum CommitOutcome
{
    Committed,

    /// <summary>A guard was false: nothing was written, so the caller rereads and recalculates (the guarded-batch contract of CLOUD.06).</summary>
    Refused,

    /// <summary>
    /// The command's receipt matches this commit (identifier, workspace, actor, operation and request hash) inside its replay window: the
    /// original commit took effect and nothing was executed again.
    /// </summary>
    Replayed,

    /// <summary>The command identifier is recorded with different content (<c>command.reused_identifier</c>): nothing was executed.</summary>
    IdentifierConflict,

    /// <summary>The command's receipt matches but its replay window has passed (<c>command.receipt_expired</c>): nothing was executed.</summary>
    ReceiptExpired,

    /// <summary>
    /// The store could not establish whether the commit took effect (a lost response, an unavailable or overloaded database). The caller
    /// resends the identical commit under the same command identifier, which either commits once or replays; it never allocates a new command.
    /// </summary>
    Unknown,
}

/// <summary>
/// One change of the core model, decided by the service and applied atomically by the store. Each variant corresponds to one named plan
/// (enrollment is the family <c>account-enrollment</c>) and carries the revisions the decision read, so a writer that lost a race is
/// refused instead of overwriting.
/// </summary>
internal abstract record IdentityCommit(string CommandId, WorkspaceId Scope)
{
    /// <summary>Creates the user, its first credential and its personal workspace in one commit (WS-02).</summary>
    internal sealed record Enroll(string CommandId, User User, AuthIdentity Credential, Workspace Workspace)
        : IdentityCommit(CommandId, Workspace.Id);

    internal sealed record AddCredential(string CommandId, WorkspaceId Scope, Principal Caller, long ExpectedUserRevision, AuthIdentity Credential)
        : IdentityCommit(CommandId, Scope);

    internal sealed record RevokeCredential(
        string CommandId, WorkspaceId Scope, Principal Caller, AuthIdentityId Target, long ExpectedCredentialRevision, long ExpectedUserRevision, UtcMicros At)
        : IdentityCommit(CommandId, Scope);

    internal sealed record RelabelCredential(
        string CommandId, WorkspaceId Scope, Principal Caller, AuthIdentityId Target, long ExpectedCredentialRevision, string? Label)
        : IdentityCommit(CommandId, Scope);

    internal sealed record RenameUser(string CommandId, WorkspaceId Scope, Principal Caller, long ExpectedUserRevision, string DisplayName)
        : IdentityCommit(CommandId, Scope);
}

/// <summary>
/// The persistence port of the core model. Every read is scoped by realm, so a row of another realm is never returned; one commit
/// applies a whole <see cref="IdentityCommit"/> atomically or returns <see cref="CommitOutcome.Refused"/> and changes nothing. The D1
/// implementation (Persistence, CLOUD.72) runs the named plans under <c>storage/plans/identity</c> through the Abstractions plan port, the
/// family <c>account-enrollment</c> through the Abstractions family port, and reads workspaces through the Workspace module's published
/// directory. A store that cannot serve a call throws <see cref="IdentityStoreException"/>; it never returns a partial or guessed value.
/// </summary>
internal interface IIdentityStore
{
    ValueTask<User?> FindUserAsync(RealmId realm, UserId id, CancellationToken cancellationToken);

    ValueTask<CredentialLookup?> FindCredentialAsync(RealmId realm, string providerId, string subject, CancellationToken cancellationToken);

    ValueTask<IReadOnlyList<AuthIdentity>> ListCredentialsAsync(RealmId realm, UserId id, CancellationToken cancellationToken);

    ValueTask<Workspace?> FindWorkspaceAsync(RealmId realm, WorkspaceId id, CancellationToken cancellationToken);

    ValueTask<Workspace?> FindWorkspaceByOwnerAsync(RealmId realm, UserId owner, CancellationToken cancellationToken);

    /// <summary>
    /// Whether the user of this realm has a live recovery-code set (an active recovery path that lets the last credential be removed). A
    /// user that is not in the realm has none.
    /// </summary>
    ValueTask<bool> HasActiveRecoveryPathAsync(RealmId realm, UserId id, CancellationToken cancellationToken);

    ValueTask<CommitOutcome> CommitAsync(IdentityCommit commit, CancellationToken cancellationToken);
}

/// <summary>Why a store call could not be served. Neither carries a value of the request or of a stored row.</summary>
internal enum IdentityStoreFailure
{
    /// <summary>The database was overloaded, unreachable or at another recovery generation: nothing was executed, so the same call may be sent again later.</summary>
    Unavailable,

    /// <summary>A plan was refused, or a stored row or a plan answer is not what the physical schema and the plans promise: a defect or a deployment skew, never a retry.</summary>
    Defect,
}

/// <summary>A store call that could not be served (<see cref="IdentityStoreFailure"/>). The message names the plan and the reason, never a value.</summary>
internal sealed class IdentityStoreException(IdentityStoreFailure failure, string message) : Exception(message)
{
    public IdentityStoreFailure Failure { get; } = failure;
}

/// <summary>Allocates identifiers. A port so that the service stays deterministic under test; every value is a canonical lower-case UUID.</summary>
internal interface IIdentityIdSource
{
    string NewId();
}

/// <summary>The outcome of a service call: a value, or a typed refusal naming a rule and never a value or another user.</summary>
internal sealed record IdentityResult<T>
{
    private IdentityResult()
    {
    }

    public T? Value { get; private init; }

    public IdentityError? Error { get; private init; }

    public bool IsSuccess => Error is null;

    public static IdentityResult<T> Success(T value) => new() { Value = value };

    public static IdentityResult<T> Failure(IdentityError error) => new() { Error = error };
}
