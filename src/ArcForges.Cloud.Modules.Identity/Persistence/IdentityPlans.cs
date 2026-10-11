// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Identity.Persistence.Infrastructure;

/// <summary>
/// The named read plans of the Identity owner (<c>storage/plans/identity</c>) and the family the store runs; with the write plan ids of
/// IdentityStatements these are the only strings the module hands to the plan and family ports. Nothing here names SQL or a table.
/// </summary>
internal static class IdentityPlans
{
    public const string UserLoad = "identity.user-load";
    public const string CredentialGet = "identity.credential-get";
    public const string CredentialRows = "identity.credential-rows";
    public const string RecoveryActive = "identity.recovery-active";

    /// <summary>The registered shared family of an enrollment (<c>storage/plans/families.json</c>).</summary>
    public const string EnrollmentFamily = "account-enrollment";

    /// <summary>The columns of <see cref="UserLoad"/>: user, display name, state, created, deletion requested, revision.</summary>
    public const int UserColumns = 6;

    /// <summary>The credential columns <see cref="CredentialRows"/> returns and <see cref="CredentialGet"/> starts with.</summary>
    public const int CredentialColumns = 18;

    /// <summary>The user columns <see cref="CredentialGet"/> appends: display name, state, created, deletion requested, revision.</summary>
    public const int JoinedUserColumns = 5;

    /// <summary>The upper bound of the credential rows of one user (the plan's maxRows); a larger set is refused by the plan, never truncated.</summary>
    public const int MaxCredentialRows = 64;
}
