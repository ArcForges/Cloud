// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Domain;

namespace ArcForges.Cloud.Modules.Identity.Core.Application;

/// <summary>A credential a verified proof established. The proof itself (passkey ceremony, email code, provider callback) is CLOUD.12.</summary>
internal sealed record NewCredential(
    string ProviderId, AuthMethod Method, string Subject, string? Label, PasskeyMaterial? Passkey, string? Password);

/// <summary>Completion of an authentication that may create the user (the first enrollment) or find the existing one.</summary>
internal sealed record EnrollmentRequest(RealmId Realm, string CommandId, string DisplayName, NewCredential Credential);

/// <summary>
/// What an enrollment completion did. <see cref="CreatedUser"/> is true only when the commit created the user and the workspace, and it
/// is the only case in which configured initial grants apply (an existing user's login never issues them).
/// </summary>
internal sealed record EnrollmentOutcome(User User, AuthIdentity Credential, Workspace Workspace, bool CreatedUser);

internal sealed record CredentialResolution(User User, AuthIdentity Credential);