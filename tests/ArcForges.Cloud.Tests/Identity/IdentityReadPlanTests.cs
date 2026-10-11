// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Entitlement;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

/// <summary>
/// The CLOUD.72 identity read plans (<c>identity.credential-get</c>, <c>identity.credential-rows</c>, <c>identity.recovery-active</c>;
/// S54(1)) through the Identity module's plan port, executed by the production Worker plan code over SQLite with every committed
/// migration. They prove that the full credential row (subject, passkey material, password verifier) and the user row come back exactly,
/// that every read is scoped by realm, that the recovery predicate is the one the revoke guard uses, and that the port refuses another
/// module's plan before the executor. SQLite is not D1.
/// </summary>
public sealed class IdentityReadPlanTests : IDisposable
{
    internal const string RealmA = "00000000-0000-4000-8000-0000000000a1";
    internal const string RealmB = "00000000-0000-4000-8000-0000000000b2";
    internal const string UserA = "10000000-0000-4000-8000-000000000001";
    internal const string UserB = "10000000-0000-4000-8000-000000000002";
    internal const string UserC = "10000000-0000-4000-8000-000000000003";
    private const string Passkey = "20000000-0000-4000-8000-000000000001";
    private const string Password = "20000000-0000-4000-8000-000000000002";
    private const string EmailCode = "20000000-0000-4000-8000-000000000003";
    private const string OidcA = "20000000-0000-4000-8000-000000000004";
    private const string OidcC = "20000000-0000-4000-8000-000000000005";
    private const string SetId = "30000000-0000-4000-8000-000000000001";

    private static readonly ModuleDescriptor IdentityModule = ModuleDescriptor.Create("Identity", "identity");
    private static readonly ModuleDescriptor WorkspaceModule = ModuleDescriptor.Create("Workspace", "workspace");

    /// <summary>The credential columns both credential reads return, in this order, for the passkey of user A.</summary>
    private static readonly string?[] PasskeyColumns =
    [
        Passkey, UserA, "1", "passkey-subject", "hex:0102a0ff", "hex:aa55", "1", "0", "[\"usb\",\"nfc\"]", "7", "Laptop", "100", "150", null,
        RealmA, "webauthn", null, "2",
    ];

    private static readonly string?[] PasswordColumns =
    [
        Password, UserA, "3", "password-subject", null, null, null, null, null, null, null, "120", null, null, RealmA, "password",
        "verifier-v1:fixture", "1",
    ];

    private static readonly string?[] EmailCodeColumns =
    [
        EmailCode, UserA, "2", "email-subject", null, null, null, null, null, null, null, "90", "95", "300", RealmA, "email", null, "3",
    ];

    /// <summary>The user columns <c>identity.credential-get</c> appends: display name, state, created, deletion requested, revision.</summary>
    private static readonly string?[] UserAColumns = ["Ada", "1", "10", null, "6"];

    private readonly SqliteBridgeExecutor bridge = new(recoveryGeneration: 1);
    private readonly FakeTime time = new(DateTimeOffset.FromUnixTimeSeconds(1_790_000_000));

    public void Dispose() => bridge.Dispose();

    private IModulePlanPort Port(ModuleDescriptor module) => new ModulePlanPortFactory(bridge, 1, time).For(module);

    /// <summary>Users A and B in realm A and user C in realm B; three credentials of A (one revoked) and one OIDC subject held in both realms.</summary>
    internal static async Task SeedAsync(SqliteBridgeExecutor bridge)
    {
        await bridge.ExecAsync(
            "INSERT INTO identity_user (user_id, realm_id, display_name, state, created_at, deletion_requested_at, rev) VALUES "
            + "('" + UserA + "', '" + RealmA + "', 'Ada', 1, 10, NULL, 6), "
            + "('" + UserB + "', '" + RealmA + "', 'Grace', 4, 11, 400, 1), "
            + "('" + UserC + "', '" + RealmB + "', 'Edsger', 1, 12, NULL, 1);",
            T.Ct);
        await bridge.ExecAsync(
            "INSERT INTO identity_auth_identity (auth_identity_id, user_id, method, subject, public_key, user_handle, backup_eligible, backup_state, transports, sign_count, label, created_at, last_used_at, revoked_at, realm_id, provider_id, password_hash, rev) VALUES "
            + "('" + Passkey + "', '" + UserA + "', 1, 'passkey-subject', X'0102A0FF', X'AA55', 1, 0, '[\"usb\",\"nfc\"]', 7, 'Laptop', 100, 150, NULL, '" + RealmA + "', 'webauthn', NULL, 2), "
            + "('" + Password + "', '" + UserA + "', 3, 'password-subject', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 120, NULL, NULL, '" + RealmA + "', 'password', 'verifier-v1:fixture', 1), "
            + "('" + EmailCode + "', '" + UserA + "', 2, 'email-subject', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 90, 95, 300, '" + RealmA + "', 'email', NULL, 3), "
            + "('" + OidcA + "', '" + UserB + "', 4, 'shared-subject', NULL, NULL, NULL, NULL, NULL, NULL, 'Work', 130, NULL, NULL, '" + RealmA + "', 'oidc-a', NULL, 1), "
            + "('" + OidcC + "', '" + UserC + "', 4, 'shared-subject', NULL, NULL, NULL, NULL, NULL, NULL, NULL, 140, NULL, NULL, '" + RealmB + "', 'oidc-a', NULL, 1);",
            T.Ct);
    }

    internal static string? Render(PlanValue value) => value.Kind switch
    {
        PlanValueKind.Null => null,
        PlanValueKind.Int64 => value.AsInt64().ToString(CultureInfo.InvariantCulture),
        PlanValueKind.Text => value.AsText(),
        PlanValueKind.Bytes => "hex:" + Convert.ToHexStringLower(value.AsBytes()),
        PlanValueKind.Bool => value.AsBool() ? "true" : "false",
        _ => throw new ArgumentOutOfRangeException(nameof(value)),
    };

    internal static List<string?[]> Rows(ModulePlanOutcome outcome)
    {
        Assert.Equal(ModulePlanStatus.Succeeded, outcome.Status);
        return [.. outcome.Rows.Select(row => row.Select(Render).ToArray())];
    }

    private static PlanValue Text(string value) => PlanValue.FromText(value);

    private Task<ModulePlanOutcome> GetAsync(string realm, string provider, string subject) =>
        Port(IdentityModule).ReadAsync(new ModulePlanRead("identity.credential-get", realm, [Text(realm), Text(provider), Text(subject)]), T.Ct);

    private Task<ModulePlanOutcome> RowsAsync(string realm, string user) =>
        Port(IdentityModule).ReadAsync(new ModulePlanRead("identity.credential-rows", realm, [Text(realm), Text(user)]), T.Ct);

    private Task<ModulePlanOutcome> RecoveryAsync(string realm, string user) =>
        Port(IdentityModule).ReadAsync(new ModulePlanRead("identity.recovery-active", realm, [Text(realm), Text(user)]), T.Ct);

    private Task AddRecoveryCodeAsync(string user, byte fill, string consumed = "NULL", string invalidated = "NULL") => bridge.ExecAsync(
        "INSERT INTO identity_recovery_code (code_hash, set_id, user_id, issued_at, consumed_at, invalidated_at) VALUES (X'"
        + Convert.ToHexString(Enumerable.Repeat(fill, 32).ToArray()) + "', '" + SetId + "', '" + user + "', 50, " + consumed + ", " + invalidated + ");",
        T.Ct);

    [Fact]
    public async Task CredentialGetReturnsTheFullCredentialRowAndItsUserInOneRow()
    {
        await SeedAsync(bridge);

        var passkey = Assert.Single(Rows(await GetAsync(RealmA, "webauthn", "passkey-subject")));
        Assert.Equal([.. PasskeyColumns, .. UserAColumns], passkey);

        var password = Assert.Single(Rows(await GetAsync(RealmA, "password", "password-subject")));
        Assert.Equal([.. PasswordColumns, .. UserAColumns], password);

        // A user pending deletion is returned with its state and deletion instant: the service, not the read, decides what it may do.
        var pending = Assert.Single(Rows(await GetAsync(RealmA, "oidc-a", "shared-subject")));
        Assert.Equal([OidcA, UserB, "4", "shared-subject"], pending[..4]);
        Assert.Equal(["Grace", "4", "11", "400", "1"], pending[18..]);
    }

    [Fact]
    public async Task CredentialGetReturnsARevokedCredentialWithItsRevocationInstant()
    {
        await SeedAsync(bridge);

        var revoked = Assert.Single(Rows(await GetAsync(RealmA, "email", "email-subject")));

        Assert.Equal([.. EmailCodeColumns, .. UserAColumns], revoked);
    }

    [Fact]
    public async Task CredentialGetIsScopedByRealmProviderAndSubject()
    {
        await SeedAsync(bridge);

        // The same provider and subject in realm B is another identity of another user.
        var other = Assert.Single(Rows(await GetAsync(RealmB, "oidc-a", "shared-subject")));
        Assert.Equal([OidcC, UserC], other[..2]);
        Assert.Equal(RealmB, other[14]);

        Assert.Empty(Rows(await GetAsync(RealmB, "webauthn", "passkey-subject")));
        Assert.Empty(Rows(await GetAsync(RealmA, "oidc-b", "shared-subject")));
        Assert.Empty(Rows(await GetAsync(RealmA, "webauthn", "PASSKEY-SUBJECT")));
        Assert.Empty(Rows(await GetAsync(RealmA, "webauthn", "unknown-subject")));
    }

    [Fact]
    public async Task CredentialRowsReturnEveryCredentialOfTheUserWithItsSubjectAndMaterialOrderedByCreation()
    {
        await SeedAsync(bridge);

        var rows = Rows(await RowsAsync(RealmA, UserA));

        Assert.Equal(3, rows.Count);
        Assert.Equal(EmailCodeColumns, rows[0]);
        Assert.Equal(PasskeyColumns, rows[1]);
        Assert.Equal(PasswordColumns, rows[2]);
    }

    [Fact]
    public async Task BothCredentialReadsReturnTheSameCredentialColumnsSoOneCodecDecodesThem()
    {
        await SeedAsync(bridge);

        var get = Assert.Single(Rows(await GetAsync(RealmA, "webauthn", "passkey-subject")));
        var listed = Rows(await RowsAsync(RealmA, UserA)).Single(row => row[0] == Passkey);

        Assert.Equal(PlanManifest.Identity.CredentialRows.Statements[0].Returns!.Count, listed.Length);
        Assert.Equal(listed, get[..listed.Length]);
        Assert.Equal(
            PlanManifest.Identity.CredentialRows.Statements[0].Returns,
            PlanManifest.Identity.CredentialGet.Statements[0].Returns!.Take(listed.Length));
    }

    [Fact]
    public async Task CredentialRowsAreScopedByRealmAndUser()
    {
        await SeedAsync(bridge);

        Assert.Equal([OidcA], Rows(await RowsAsync(RealmA, UserB)).Select(row => row[0]));
        Assert.Equal([OidcC], Rows(await RowsAsync(RealmB, UserC)).Select(row => row[0]));

        // A user is found only in its own realm.
        Assert.Empty(Rows(await RowsAsync(RealmB, UserA)));
        Assert.Empty(Rows(await RowsAsync(RealmA, UserC)));
        Assert.Empty(Rows(await RowsAsync(RealmA, "10000000-0000-4000-8000-0000000000ff")));
    }

    [Fact]
    public async Task CredentialRowsAboveTheDeclaredBoundAreRefusedAsOverloadedAndNeverTruncated()
    {
        await SeedAsync(bridge);
        Assert.Equal(64, PlanManifest.Identity.CredentialRows.MaxRows);
        await bridge.ExecAsync(
            "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 61) "
            + "INSERT INTO identity_auth_identity (auth_identity_id, user_id, method, subject, created_at, realm_id, provider_id, rev) "
            + "SELECT printf('21000000-0000-4000-8000-%012d', i), '" + UserA + "', 2, 'bulk-' || i, 200 + i, '" + RealmA + "', 'email', 1 FROM n;",
            T.Ct);

        // 3 + 61 = 64 rows are read whole; one more is a bounded refusal, never a silently shortened list.
        Assert.Equal(64, Rows(await RowsAsync(RealmA, UserA)).Count);
        await bridge.ExecAsync(
            "INSERT INTO identity_auth_identity (auth_identity_id, user_id, method, subject, created_at, realm_id, provider_id, rev) VALUES "
            + "('21000000-0000-4000-8000-000000000062', '" + UserA + "', 2, 'bulk-62', 262, '" + RealmA + "', 'email', 1);",
            T.Ct);

        var outcome = await RowsAsync(RealmA, UserA);

        Assert.Equal(ModulePlanStatus.Unavailable, outcome.Status);
        Assert.Empty(outcome.Rows);
    }

    [Fact]
    public async Task RecoveryActiveIsTrueOnlyForAnUnconsumedAndUninvalidatedCodeOfTheUser()
    {
        await SeedAsync(bridge);

        Assert.Equal(["false"], Assert.Single(Rows(await RecoveryAsync(RealmA, UserA))));

        await AddRecoveryCodeAsync(UserA, 0x01, consumed: "60");
        await AddRecoveryCodeAsync(UserA, 0x02, invalidated: "70");
        await AddRecoveryCodeAsync(UserA, 0x03, consumed: "60", invalidated: "70");
        await AddRecoveryCodeAsync(UserB, 0x04);
        Assert.Equal(["false"], Assert.Single(Rows(await RecoveryAsync(RealmA, UserA))));
        Assert.Equal(["true"], Assert.Single(Rows(await RecoveryAsync(RealmA, UserB))));

        await AddRecoveryCodeAsync(UserA, 0x05);
        Assert.Equal(["true"], Assert.Single(Rows(await RecoveryAsync(RealmA, UserA))));
    }

    [Fact]
    public async Task RecoveryActiveAnswersOnlyForAUserOfTheRealm()
    {
        await SeedAsync(bridge);
        await AddRecoveryCodeAsync(UserA, 0x06);

        // No row means the user is not in this realm: the read never answers for another realm's user.
        Assert.Empty(Rows(await RecoveryAsync(RealmB, UserA)));
        Assert.Empty(Rows(await RecoveryAsync(RealmA, "10000000-0000-4000-8000-0000000000ff")));
        Assert.Equal(["false"], Assert.Single(Rows(await RecoveryAsync(RealmB, UserC))));
    }

    [Fact]
    public async Task RecoveryActiveUsesTheSamePredicateAsTheRevokeGuard()
    {
        var root = T.RepoRoot().FullName;
        var read = await File.ReadAllTextAsync(Path.Combine(root, "storage", "plans", "identity", "recovery-active.sql"), T.Ct);
        var guard = await File.ReadAllTextAsync(Path.Combine(root, "storage", "plans", "identity", "credential-revoke.sql"), T.Ct);

        Assert.Contains("FROM identity_recovery_code WHERE user_id = ? AND consumed_at IS NULL AND invalidated_at IS NULL", guard, StringComparison.Ordinal);
        Assert.Contains("FROM identity_recovery_code r WHERE r.user_id = u.user_id AND r.consumed_at IS NULL AND r.invalidated_at IS NULL", read, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheIdentityPortRefusesAWorkspacePlanAndTheWorkspacePortAnIdentityPlanBeforeTheExecutor()
    {
        await SeedAsync(bridge);
        var calls = bridge.Calls;

        await Assert.ThrowsAsync<InvalidOperationException>(() => Port(IdentityModule).ReadAsync(
            new ModulePlanRead("workspace.workspace-by-owner", RealmA, [Text(RealmA), Text(UserA)]), T.Ct));
        await Assert.ThrowsAsync<InvalidOperationException>(() => Port(WorkspaceModule).ReadAsync(
            new ModulePlanRead("identity.credential-get", RealmA, [Text(RealmA), Text("webauthn"), Text("passkey-subject")]), T.Ct));

        Assert.Equal(calls, bridge.Calls);
    }

    [Fact]
    public async Task AWrongArgumentKindIsRejectedBeforeTheExecutor()
    {
        await SeedAsync(bridge);
        var calls = bridge.Calls;

        var outcome = await Port(IdentityModule).ReadAsync(
            new ModulePlanRead("identity.recovery-active", RealmA, [Text(RealmA), PlanValue.FromInt64(1)]), T.Ct);

        Assert.Equal(ModulePlanStatus.Rejected, outcome.Status);
        Assert.Equal(calls, bridge.Calls);
    }
}
