// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using ArcForges.Cloud.Modules.Identity.Core.Application;

namespace ArcForges.Cloud.Modules.Identity.Core.Infrastructure;

/// <summary>Enrollment replay binds caller content, never identifiers allocated by an attempt. Base64 fields distinguish null/empty and prevent separator ambiguity.</summary>
internal static class EnrollmentReceiptIdentity
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

    public static ModuleCommandIdentity For(IdentityCommit.Enroll commit) => For(new EnrollmentRequest(
        commit.User.Realm, commit.CommandId, commit.User.DisplayName,
        new NewCredential(commit.Credential.ProviderId, commit.Credential.Method, commit.Credential.Subject,
            commit.Credential.Label, commit.Credential.Passkey, commit.Credential.Password)));

    public static ModuleCommandIdentity For(EnrollmentRequest request)
    {
        var credential = request.Credential;
        var passkey = credential.Passkey;
        var actor = "enrollment:" + Hash([request.Realm.Value, credential.ProviderId, credential.Subject]);
        var hash = Hash([
            "identity.account.enroll.v1", request.Realm.Value, request.DisplayName, credential.ProviderId,
            ((int)credential.Method).ToString(CultureInfo.InvariantCulture), credential.Subject, credential.Label, credential.Password,
            passkey is null ? null : Convert.ToBase64String(passkey.PublicKey.AsSpan()),
            passkey is null ? null : Convert.ToBase64String(passkey.UserHandle.AsSpan()),
            passkey?.BackupEligible?.ToString(), passkey?.BackupState?.ToString(), passkey?.TransportsJson,
            passkey?.SignCount?.ToString(CultureInfo.InvariantCulture),
        ]);
        return new ModuleCommandIdentity(Guid.Parse(request.CommandId), null, actor, "identity.account.enroll", hash);
    }

    private static string Hash(IReadOnlyList<string?> fields)
    {
        var content = string.Join('\n', fields.Select(value => value is null ? "~" : Convert.ToBase64String(Utf8.GetBytes(value))));
        return Convert.ToHexString(SHA256.HashData(Utf8.GetBytes(content))).ToLowerInvariant();
    }
}
