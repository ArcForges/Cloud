// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Domain;

namespace ArcForges.Cloud.Modules.Identity.Core.Application;

/// <summary>
/// The use cases of the core model: enrollment with its personal workspace, credential linking, revocation and relabelling, and the
/// direct ownership check. It decides, the store applies; a write names the revisions it read, and a refused commit is reread and
/// recalculated a bounded number of times before the caller is told of the conflict.
/// </summary>
internal sealed class IdentityService(IIdentityStore store, IIdentityIdSource ids, TimeProvider time)
{
    /// <summary>Attempts of one write before a conflict is reported; each refusal rereads everything the decision used.</summary>
    public const int MaxAttempts = 4;

    private UtcMicros Now() => UtcMicros.FromDateTimeOffset(time.GetUtcNow());

    /// <summary>
    /// Completes an authentication whose proof was verified: creates the user, the credential and the personal workspace in one commit, or
    /// finds the existing user of that credential. The result never says whose credential a refusal concerned.
    /// </summary>
    public async ValueTask<IdentityResult<EnrollmentOutcome>> CompleteEnrollmentAsync(EnrollmentRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!IdentifierText.IsCanonical(request.CommandId) || !IdentityRules.IsValidDisplayName(request.DisplayName)
            || request.Realm == default || !IsValid(request.Credential))
            return Fail<EnrollmentOutcome>(IdentityError.InvalidRequest);
        var credential = request.Credential;
        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            var existing = await store.FindCredentialAsync(request.Realm, credential.ProviderId, credential.Subject, cancellationToken).ConfigureAwait(false);
            if (existing is not null)
            {
                // The credential of an existing user signs that user in; a revoked credential or an unusable user is the same refusal as an unknown one.
                if (existing.Credential.IsRevoked || existing.User.State is UserState.Suspended or UserState.Deleted)
                    return Fail<EnrollmentOutcome>(IdentityError.CredentialUnavailable);
                var home = await store.FindWorkspaceByOwnerAsync(request.Realm, existing.User.Id, cancellationToken).ConfigureAwait(false);
                return home is null
                    ? Fail<EnrollmentOutcome>(IdentityError.NotFound)
                    : IdentityResult<EnrollmentOutcome>.Success(new EnrollmentOutcome(existing.User, existing.Credential, home, false));
            }

            var now = Now();
            var user = new User(UserId.Parse(ids.NewId()), request.Realm, request.DisplayName, UserState.Active, now, null, 1);
            var created = Build(ids.NewId(), user.Id, request.Realm, credential, now);
            var workspace = IdentityRules.NewPersonalWorkspace(WorkspaceId.Parse(ids.NewId()), user);
            var outcome = await store.CommitAsync(new IdentityCommit.Enroll(request.CommandId, user, created, workspace), cancellationToken).ConfigureAwait(false);
            if (outcome == CommitOutcome.Committed)
                return IdentityResult<EnrollmentOutcome>.Success(new EnrollmentOutcome(user, created, workspace, true));
        }

        return Fail<EnrollmentOutcome>(IdentityError.Conflict);
    }

    /// <summary>
    /// Resolves a verified provider subject to its user. An unknown subject, a revoked credential, a credential of another realm and an
    /// unusable user are the same refusal, so the call is no oracle for which subjects exist.
    /// </summary>
    public async ValueTask<IdentityResult<CredentialResolution>> ResolveCredentialAsync(
        RealmId realm, string providerId, string subject, CancellationToken cancellationToken)
    {
        if (realm == default || !IdentityRules.IsValidProvider(providerId) || !IdentityRules.IsValidSubject(subject))
            return Fail<CredentialResolution>(IdentityError.CredentialUnavailable);
        var found = await store.FindCredentialAsync(realm, providerId, subject, cancellationToken).ConfigureAwait(false);
        return found is null || found.Credential.IsRevoked || found.User.State is UserState.Suspended or UserState.Deleted
            ? Fail<CredentialResolution>(IdentityError.CredentialUnavailable)
            : IdentityResult<CredentialResolution>.Success(new CredentialResolution(found.User, found.Credential));
    }

    /// <summary>Links one more authentication identity to the caller. The user, its identifier and its workspace do not change (BR-04).</summary>
    public async ValueTask<IdentityResult<AuthIdentity>> AddCredentialAsync(
        Principal caller, string commandId, NewCredential credential, CancellationToken cancellationToken)
    {
        if (!IdentifierText.IsCanonical(commandId) || !IsValid(credential)) return Fail<AuthIdentity>(IdentityError.InvalidRequest);
        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            var user = await store.FindUserAsync(caller.Realm, caller.User, cancellationToken).ConfigureAwait(false);
            var home = await store.FindWorkspaceByOwnerAsync(caller.Realm, caller.User, cancellationToken).ConfigureAwait(false);
            if (user is null || home is null) return Fail<AuthIdentity>(IdentityError.NotFound);
            if (!IdentityRules.MayAddCredential(user)) return Fail<AuthIdentity>(IdentityError.NotPermitted);
            if (await store.FindCredentialAsync(caller.Realm, credential.ProviderId, credential.Subject, cancellationToken).ConfigureAwait(false) is not null)
                return Fail<AuthIdentity>(IdentityError.CredentialUnavailable);
            var added = Build(ids.NewId(), user.Id, caller.Realm, credential, Now());
            var commit = new IdentityCommit.AddCredential(commandId, home.Id, caller, user.Revision, added);
            if (await store.CommitAsync(commit, cancellationToken).ConfigureAwait(false) == CommitOutcome.Committed)
                return IdentityResult<AuthIdentity>.Success(added);
        }

        return Fail<AuthIdentity>(IdentityError.Conflict);
    }

    /// <summary>Revokes one of the caller's credentials unless it is the last usable one and no recovery path is active.</summary>
    public async ValueTask<IdentityResult<AuthIdentity>> RevokeCredentialAsync(
        Principal caller, string commandId, AuthIdentityId target, CancellationToken cancellationToken)
    {
        if (!IdentifierText.IsCanonical(commandId) || target == default) return Fail<AuthIdentity>(IdentityError.InvalidRequest);
        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            var user = await store.FindUserAsync(caller.Realm, caller.User, cancellationToken).ConfigureAwait(false);
            var home = await store.FindWorkspaceByOwnerAsync(caller.Realm, caller.User, cancellationToken).ConfigureAwait(false);
            if (user is null || home is null) return Fail<AuthIdentity>(IdentityError.NotFound);
            var credentials = await store.ListCredentialsAsync(caller.Realm, caller.User, cancellationToken).ConfigureAwait(false);
            var recovery = await store.HasActiveRecoveryPathAsync(caller.User, cancellationToken).ConfigureAwait(false);
            if (IdentityRules.CheckRevocation(user, credentials, target, recovery) is { } refusal) return Fail<AuthIdentity>(refusal);
            var current = credentials.First(c => c.Id == target);
            var at = Now();
            var commit = new IdentityCommit.RevokeCredential(commandId, home.Id, caller, target, current.Revision, user.Revision, at);
            if (await store.CommitAsync(commit, cancellationToken).ConfigureAwait(false) == CommitOutcome.Committed)
                return IdentityResult<AuthIdentity>.Success(current with { RevokedAt = at, Revision = current.Revision + 1 });
        }

        return Fail<AuthIdentity>(IdentityError.Conflict);
    }

    public async ValueTask<IdentityResult<AuthIdentity>> RelabelCredentialAsync(
        Principal caller, string commandId, AuthIdentityId target, string? label, CancellationToken cancellationToken)
    {
        if (!IdentifierText.IsCanonical(commandId) || target == default || !IdentityRules.IsValidLabel(label)) return Fail<AuthIdentity>(IdentityError.InvalidRequest);
        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            var user = await store.FindUserAsync(caller.Realm, caller.User, cancellationToken).ConfigureAwait(false);
            var home = await store.FindWorkspaceByOwnerAsync(caller.Realm, caller.User, cancellationToken).ConfigureAwait(false);
            if (user is null || home is null) return Fail<AuthIdentity>(IdentityError.NotFound);
            if (!IdentityRules.MayChangeCredentials(user)) return Fail<AuthIdentity>(IdentityError.NotPermitted);
            var credentials = await store.ListCredentialsAsync(caller.Realm, caller.User, cancellationToken).ConfigureAwait(false);
            var current = credentials.FirstOrDefault(c => c.Id == target && !c.IsRevoked);
            if (current is null) return Fail<AuthIdentity>(IdentityError.NotFound);
            var commit = new IdentityCommit.RelabelCredential(commandId, home.Id, caller, target, current.Revision, label);
            if (await store.CommitAsync(commit, cancellationToken).ConfigureAwait(false) == CommitOutcome.Committed)
                return IdentityResult<AuthIdentity>.Success(current with { Label = label, Revision = current.Revision + 1 });
        }

        return Fail<AuthIdentity>(IdentityError.Conflict);
    }

    public async ValueTask<IdentityResult<User>> RenameUserAsync(Principal caller, string commandId, string displayName, CancellationToken cancellationToken)
    {
        if (!IdentifierText.IsCanonical(commandId) || !IdentityRules.IsValidDisplayName(displayName)) return Fail<User>(IdentityError.InvalidRequest);
        for (var attempt = 0; attempt < MaxAttempts; attempt++)
        {
            var user = await store.FindUserAsync(caller.Realm, caller.User, cancellationToken).ConfigureAwait(false);
            var home = await store.FindWorkspaceByOwnerAsync(caller.Realm, caller.User, cancellationToken).ConfigureAwait(false);
            if (user is null || home is null) return Fail<User>(IdentityError.NotFound);
            if (!IdentityRules.MayChangeCredentials(user)) return Fail<User>(IdentityError.NotPermitted);
            var commit = new IdentityCommit.RenameUser(commandId, home.Id, caller, user.Revision, displayName);
            if (await store.CommitAsync(commit, cancellationToken).ConfigureAwait(false) == CommitOutcome.Committed)
                return IdentityResult<User>.Success(user with { DisplayName = displayName, Revision = user.Revision + 1 });
        }

        return Fail<User>(IdentityError.Conflict);
    }

    /// <summary>
    /// The direct ownership check (WO-02, WS-07): the workspace of the caller's realm whose owner is the caller. A workspace that does not
    /// exist, one of another owner and one of another realm are the same refusal, so knowing an identifier discloses nothing.
    /// </summary>
    public async ValueTask<IdentityResult<Workspace>> AuthorizeWorkspaceAsync(Principal caller, WorkspaceId id, CancellationToken cancellationToken)
    {
        if (id == default) return Fail<Workspace>(IdentityError.NotFound);
        var workspace = await store.FindWorkspaceAsync(caller.Realm, id, cancellationToken).ConfigureAwait(false);
        return workspace is not null && IdentityRules.Owns(caller, workspace)
            ? IdentityResult<Workspace>.Success(workspace)
            : Fail<Workspace>(IdentityError.NotFound);
    }

    public async ValueTask<IdentityResult<Workspace>> GetPersonalWorkspaceAsync(Principal caller, CancellationToken cancellationToken)
    {
        var workspace = await store.FindWorkspaceByOwnerAsync(caller.Realm, caller.User, cancellationToken).ConfigureAwait(false);
        return workspace is not null && IdentityRules.Owns(caller, workspace)
            ? IdentityResult<Workspace>.Success(workspace)
            : Fail<Workspace>(IdentityError.NotFound);
    }

    private static bool IsValid(NewCredential credential) =>
        credential is not null && IdentityRules.HasValidShape(Build("00000000-0000-4000-8000-000000000000", UserIdPlaceholder, default, credential, default));

    private static readonly UserId UserIdPlaceholder = UserId.Parse("00000000-0000-4000-8000-000000000001");

    private static AuthIdentity Build(string id, UserId user, RealmId realm, NewCredential credential, UtcMicros now) =>
        new(AuthIdentityId.Parse(id), user, realm, credential.ProviderId, credential.Method, credential.Subject, credential.Label,
            credential.Passkey, credential.Password, now, null, null, 1);

    private static IdentityResult<T> Fail<T>(IdentityError error) => IdentityResult<T>.Failure(error);
}
