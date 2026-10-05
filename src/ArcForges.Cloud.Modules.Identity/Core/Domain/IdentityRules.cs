// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.Modules.Identity.Core.Domain;

/// <summary>Why a request was refused. A reason names a rule and never a value, a subject or another user.</summary>
internal enum IdentityError
{
    InvalidRequest,
    NotFound,
    CredentialUnavailable,
    LastCredential,
    NotPermitted,
    Conflict,
}

/// <summary>
/// The pure rules of the core model. They read no clock, no store and no randomness. Each rule is also written as the guard of a named
/// plan (storage/plans/identity, storage/plans/families), and the shared vectors hold both to the same outcomes.
/// </summary>
internal static partial class IdentityRules
{
    public const int DisplayNameMaxLength = 128;
    public const int SubjectMaxLength = 512;
    public const int LabelMaxLength = 64;
    public const string PersonalWorkspaceName = "Personal";
    public const string DefaultDataRegion = "Automatic";

    [GeneratedRegex("^[a-z][a-z0-9._-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex ProviderPattern();

    public static bool IsValidProvider(string? providerId) => providerId is not null && ProviderPattern().IsMatch(providerId);

    /// <summary>Non-empty, at most 128 UTF-16 units, no control character and no unpaired surrogate.</summary>
    public static bool IsValidDisplayName(string? text) => IsPlainText(text, DisplayNameMaxLength) && !string.IsNullOrWhiteSpace(text);

    public static bool IsValidSubject(string? text) => IsPlainText(text, SubjectMaxLength);

    public static bool IsValidLabel(string? text) => text is null || (IsPlainText(text, LabelMaxLength) && !string.IsNullOrWhiteSpace(text));

    private static bool IsPlainText(string? text, int maxLength)
    {
        if (string.IsNullOrEmpty(text) || text.Length > maxLength) return false;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (char.IsControl(c)) return false;
            if (char.IsHighSurrogate(c))
            {
                if (i + 1 >= text.Length || !char.IsLowSurrogate(text[i + 1])) return false;
                i++;
            }
            else if (char.IsLowSurrogate(c))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>The method-specific shape of a credential, as the physical checks require it (a passkey has a user handle, only a password has a verifier).</summary>
    public static bool HasValidShape(AuthIdentity credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        if (!IsValidProvider(credential.ProviderId) || !IsValidSubject(credential.Subject) || !IsValidLabel(credential.Label)) return false;
        var passkey = credential.Passkey;
        if (credential.Method == AuthMethod.Passkey)
        {
            if (passkey is null || passkey.UserHandle.IsDefaultOrEmpty || passkey.PublicKey.IsDefaultOrEmpty) return false;
            if (passkey.BackupState is not null && passkey.BackupEligible is null) return false;
            if (passkey.SignCount is < 0) return false;
        }
        else if (passkey is not null)
        {
            return false;
        }

        return credential.Method == AuthMethod.Password
            ? !string.IsNullOrEmpty(credential.Password)
            : credential.Password is null;
    }

    /// <summary>A new credential or a new enrollment is admitted only for an active user.</summary>
    public static bool MayAddCredential(User user) => user.State == UserState.Active;

    /// <summary>Changing or removing a credential is admitted for an active or restricted user, so a restricted user can still remove a compromised credential.</summary>
    public static bool MayChangeCredentials(User user) => user.State is UserState.Active or UserState.Restricted;

    /// <summary>
    /// The last-credential rule (model 01 <c>identity.last_credential</c>): a user keeps at least one usable authentication identity or
    /// an active recovery path.
    /// </summary>
    public static IdentityError? CheckRevocation(User user, IReadOnlyCollection<AuthIdentity> credentials, AuthIdentityId target, bool hasActiveRecoveryPath)
    {
        ArgumentNullException.ThrowIfNull(user);
        ArgumentNullException.ThrowIfNull(credentials);
        if (!MayChangeCredentials(user)) return IdentityError.NotPermitted;
        var found = credentials.FirstOrDefault(c => c.Id == target && c.UserId == user.Id && c.Realm == user.Realm && !c.IsRevoked);
        if (found is null) return IdentityError.NotFound;
        var remaining = credentials.Any(c => c.Id != target && c.UserId == user.Id && c.Realm == user.Realm && !c.IsRevoked);
        return remaining || hasActiveRecoveryPath ? null : IdentityError.LastCredential;
    }

    /// <summary>
    /// The direct ownership check (WO-02): the caller owns the workspace when the realm and the owner user are the caller's. There is no
    /// membership to consult, and knowing a workspace identifier grants nothing (WS-07).
    /// </summary>
    public static bool Owns(Principal caller, Workspace workspace)
    {
        ArgumentNullException.ThrowIfNull(workspace);
        return workspace.Realm == caller.Realm && workspace.OwnerUserId == caller.User;
    }

    /// <summary>Builds the personal workspace of a new user (WS-02, WS-04, WS-09).</summary>
    public static Workspace NewPersonalWorkspace(WorkspaceId id, User owner) =>
        new(id, owner.Realm, owner.Id, PersonalWorkspaceName, DefaultDataRegion, WorkspaceState.Active, owner.CreatedAt, 1);
}
