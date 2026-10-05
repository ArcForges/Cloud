// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;

namespace ArcForges.Cloud.Modules.Identity.Core.Domain;

/// <summary>Whether a realm is the official ArcForges Cloud or a self-hosted deployment (ID-12, ID-13). The two never share an identity (ID-11, ID-14).</summary>
internal enum RealmKind
{
    Official = 1,
    SelfHost = 2,
}

/// <summary>
/// A realm: an independent identity and data authority (requirements 02, section 2.1). It is deployment configuration and not a table
/// (one D1 authority database serves one realm), so the model carries it as a value that every user, credential and workspace names.
/// </summary>
internal sealed record Realm(RealmId Id, RealmKind Kind);

/// <summary>The stored numbers are the one-based positions of the physical enum (model 01 section 3, never renumbered).</summary>
internal enum AuthMethod
{
    Passkey = 1,
    EmailCode = 2,
    Password = 3,
    Oidc = 4,
}

internal enum UserState
{
    Active = 1,
    Restricted = 2,
    Suspended = 3,
    PendingDeletion = 4,
    Deleted = 5,
}

internal enum WorkspaceState
{
    Active = 1,
    Suspended = 2,
    PendingDeletion = 3,
}

/// <summary>A user: who the owner is. A user is never an email address and never an authentication identity (BR-04, ID-01).</summary>
/// <param name="Revision">The profile and credential-lifecycle guard: every change of the user or of the set of its credentials advances it.</param>
internal sealed record User(
    UserId Id,
    RealmId Realm,
    string DisplayName,
    UserState State,
    UtcMicros CreatedAt,
    UtcMicros? DeletionRequestedAt,
    long Revision);

/// <summary>The passkey-only part of a credential (model 01: COSE public key, WebAuthn user handle, BE/BS flags, counter).</summary>
internal sealed record PasskeyMaterial(
    ImmutableArray<byte> PublicKey,
    ImmutableArray<byte> UserHandle,
    bool? BackupEligible,
    bool? BackupState,
    string? TransportsJson,
    long? SignCount);

/// <summary>
/// One authentication identity: a credential of exactly one user, unique by realm, provider and subject. Adding, revoking or relabelling
/// it never changes the user, the user identifier or the workspace the user owns (BR-04).
/// </summary>
/// <param name="Password">A versioned salted verifier, only for the password method.</param>
internal sealed record AuthIdentity(
    AuthIdentityId Id,
    UserId UserId,
    RealmId Realm,
    string ProviderId,
    AuthMethod Method,
    string Subject,
    string? Label,
    PasskeyMaterial? Passkey,
    string? Password,
    UtcMicros CreatedAt,
    UtcMicros? LastUsedAt,
    UtcMicros? RevokedAt,
    long Revision)
{
    public bool IsRevoked => RevokedAt is not null;
}

/// <summary>
/// The single-owner workspace (WS-01 to WS-05): <see cref="OwnerUserId"/> is the one and only relation between a user and a workspace.
/// There is no member, role or seat, and ownership never changes (WO-01, WO-03).
/// </summary>
internal sealed record Workspace(
    WorkspaceId Id,
    RealmId Realm,
    UserId OwnerUserId,
    string Name,
    string DataRegion,
    WorkspaceState State,
    UtcMicros CreatedAt,
    long Revision);

/// <summary>The authenticated caller as the identity core sees it: a realm and a user, never a credential (ID-10).</summary>
internal readonly record struct Principal(RealmId Realm, UserId User);
