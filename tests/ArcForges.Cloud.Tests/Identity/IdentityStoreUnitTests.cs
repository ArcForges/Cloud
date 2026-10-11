// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Core.Infrastructure;
using ArcForges.Cloud.Modules.Identity.Persistence.Infrastructure;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Storage.ModuleBinding;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

/// <summary>
/// The D1 identity store against scripted Abstractions ports: the exact plan ids, owner scopes and arguments of every read and commit,
/// the strict decoding of every row (a malformed or foreign row is a defect, never a value), the mapping of every plan status, and the
/// store's commits held byte for byte to the shared vector through the real plan and family ports with a recording executor.
/// </summary>
public sealed class IdentityStoreUnitTests
{
    private static readonly RealmId Realm = RealmId.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    private static readonly RealmId OtherRealm = RealmId.Parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    private static readonly UserId User = UserId.Parse("10000000-0000-4000-8000-000000000001");
    private static readonly UserId OtherUser = UserId.Parse("10000000-0000-4000-8000-000000000002");
    private static readonly AuthIdentityId Credential = AuthIdentityId.Parse("20000000-0000-4000-8000-000000000001");
    private static readonly WorkspaceId Home = WorkspaceId.Parse("40000000-0000-4000-8000-000000000001");
    private static readonly DateTimeOffset Start = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);
    private const string Command = "50000000-0000-4000-8000-000000000001";

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed class Rig
    {
        public ScriptedPlans Plans { get; } = new();

        public ScriptedFamilies Families { get; } = new();

        public ScriptedDirectory Directory { get; } = new();

        public SequentialIdentityIds Ids { get; } = new();

        public IdentityClock Clock { get; } = new(Start);

        public D1IdentityStore Store => new(Plans, Families, Directory, Ids, Clock);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Rows
    // ------------------------------------------------------------------------------------------------------------------------

    private static PlanValue T(string value) => PlanValue.FromText(value);

    private static PlanValue I(long value) => PlanValue.FromInt64(value);

    private static readonly PlanValue N = PlanValue.Null;

    /// <summary>The 18 credential columns of an email-code credential of <see cref="User"/>.</summary>
    private static PlanValue[] EmailRow(string subject = "ada@example.test", string? realm = null, string? user = null, long? revokedAt = null) =>
    [
        T(Credential.Value), T(user ?? User.Value), I(2), T(subject), N, N, N, N, N, N, T("Mail"), I(100), I(150), revokedAt is { } r ? I(r) : N,
        T(realm ?? Realm.Value), T("official-email"), N, I(3),
    ];

    private static PlanValue[] PasskeyRow() =>
    [
        T(Credential.Value), T(User.Value), I(1), T("passkey-subject"), PlanValue.FromBytes([1, 2, 160, 255]), PlanValue.FromBytes([170, 85]), I(1), I(0),
        T("[\"usb\"]"), I(7), N, I(100), N, N, T(Realm.Value), T("official-passkey"), N, I(2),
    ];

    private static PlanValue[] UserTail(long state = 1) => [T("Ada"), I(state), I(10), N, I(6)];

    private static PlanValue[] UserRow(long state = 1) => [T(User.Value), .. UserTail(state)];

    private static ModulePlanOutcome Rows(params PlanValue[][] rows) => new(ModulePlanStatus.Succeeded, rows);

    private static WorkspaceRecord Record(string? realm = null, string? owner = null, string? id = null) =>
        new(id ?? Home.Value, realm ?? Realm.Value, owner ?? User.Value, "Personal", "Automatic", 1, WorkspaceRecordState.Active, 10, 1);

    // ------------------------------------------------------------------------------------------------------------------------
    // Reads: plan, scope, arguments and decoding
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task AUserIsReadWithTheUserLoadPlanScopedByRealm()
    {
        var rig = new Rig();
        rig.Plans.Answer = _ => Rows(UserRow());

        var user = await rig.Store.FindUserAsync(Realm, User, Ct);

        Assert.Equal(new User(User, Realm, "Ada", UserState.Active, new UtcMicros(10), null, 6), user);
        var read = Assert.Single(rig.Plans.Reads);
        Assert.Equal("identity.user-load", read.PlanId);
        Assert.Equal(Realm.Value, read.OwnerScope);
        Assert.Equal([T(Realm.Value), T(User.Value)], read.Arguments);
    }

    [Fact]
    public async Task NoRowIsNoUserAndNoCredential()
    {
        var rig = new Rig();
        rig.Plans.Answer = _ => Rows();

        Assert.Null(await rig.Store.FindUserAsync(Realm, User, Ct));
        Assert.Null(await rig.Store.FindCredentialAsync(Realm, "official-email", "ada@example.test", Ct));
        Assert.Empty(await rig.Store.ListCredentialsAsync(Realm, User, Ct));
        Assert.False(await rig.Store.HasActiveRecoveryPathAsync(Realm, User, Ct));
    }

    [Fact]
    public async Task ACredentialAndItsUserAreReadInOneStatementWithEveryColumn()
    {
        var rig = new Rig();
        rig.Plans.Answer = _ => Rows([.. PasskeyRow(), .. UserTail()]);

        var found = await rig.Store.FindCredentialAsync(Realm, "official-passkey", "passkey-subject", Ct);

        var read = Assert.Single(rig.Plans.Reads);
        Assert.Equal("identity.credential-get", read.PlanId);
        Assert.Equal(Realm.Value, read.OwnerScope);
        Assert.Equal([T(Realm.Value), T("official-passkey"), T("passkey-subject")], read.Arguments);
        Assert.NotNull(found);
        var credential = found.Credential;
        Assert.Equal((Credential, User, Realm, "official-passkey", AuthMethod.Passkey, "passkey-subject"), (credential.Id, credential.UserId, credential.Realm, credential.ProviderId, credential.Method, credential.Subject));
        Assert.Equal(((string?)null, (string?)null, new UtcMicros(100), (UtcMicros?)null, (UtcMicros?)null, 2L), (credential.Label, credential.Password, credential.CreatedAt, credential.LastUsedAt, credential.RevokedAt, credential.Revision));
        var passkey = Assert.IsType<PasskeyMaterial>(credential.Passkey);
        Assert.Equal(new byte[] { 1, 2, 160, 255 }, passkey.PublicKey.ToArray());
        Assert.Equal(new byte[] { 170, 85 }, passkey.UserHandle.ToArray());
        Assert.Equal((true, false, "[\"usb\"]", 7L), (passkey.BackupEligible!.Value, passkey.BackupState!.Value, passkey.TransportsJson, passkey.SignCount!.Value));
        Assert.Equal(new User(User, Realm, "Ada", UserState.Active, new UtcMicros(10), null, 6), found.User);
    }

    [Fact]
    public async Task ARevokedCredentialAndAPasswordVerifierAreReturnedAsStored()
    {
        var rig = new Rig();
        PlanValue[] password = [T(Credential.Value), T(User.Value), I(3), T("ada"), N, N, N, N, N, N, N, I(100), N, N, T(Realm.Value), T("self-host-password"), T("verifier-v1"), I(1)];
        rig.Plans.Answer = read => read.PlanId == "identity.credential-rows" ? Rows(EmailRow(revokedAt: 300), password) : Rows();

        var listed = await rig.Store.ListCredentialsAsync(Realm, User, Ct);

        Assert.Equal(2, listed.Count);
        Assert.Equal(new UtcMicros(300), listed[0].RevokedAt);
        Assert.True(listed[0].IsRevoked);
        Assert.Equal(new UtcMicros(150), listed[0].LastUsedAt);
        Assert.Equal("Mail", listed[0].Label);
        Assert.Equal("verifier-v1", listed[1].Password);
        Assert.Null(listed[1].Passkey);
        var read = Assert.Single(rig.Plans.Reads);
        Assert.Equal(("identity.credential-rows", Realm.Value), (read.PlanId, read.OwnerScope));
        Assert.Equal([T(Realm.Value), T(User.Value)], read.Arguments);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task TheRecoveryPathIsTheRealmScopedFlag(bool active)
    {
        var rig = new Rig();
        rig.Plans.Answer = _ => Rows([PlanValue.FromBool(active)]);

        Assert.Equal(active, await rig.Store.HasActiveRecoveryPathAsync(Realm, User, Ct));
        var read = Assert.Single(rig.Plans.Reads);
        Assert.Equal(("identity.recovery-active", Realm.Value), (read.PlanId, read.OwnerScope));
        Assert.Equal([T(Realm.Value), T(User.Value)], read.Arguments);
    }

    [Fact]
    public async Task WorkspacesAreReadThroughTheDirectoryByRealmAndIdentifierOrOwner()
    {
        var rig = new Rig();
        rig.Directory.Answer = (_, _) => new WorkspaceDirectoryResult(WorkspaceDirectoryStatus.Found, Record(), null);

        var expected = new Workspace(Home, Realm, User, "Personal", "Automatic", WorkspaceState.Active, new UtcMicros(10), 1);
        Assert.Equal(expected, await rig.Store.FindWorkspaceAsync(Realm, Home, Ct));
        Assert.Equal(expected, await rig.Store.FindWorkspaceByOwnerAsync(Realm, User, Ct));
        Assert.Equal([("id", Realm.Value, Home.Value), ("owner", Realm.Value, User.Value)], rig.Directory.Calls);
        Assert.Empty(rig.Plans.Reads);

        rig.Directory.Answer = (_, _) => new WorkspaceDirectoryResult(WorkspaceDirectoryStatus.NotFound, null, null);
        Assert.Null(await rig.Store.FindWorkspaceAsync(Realm, Home, Ct));
        Assert.Null(await rig.Store.FindWorkspaceByOwnerAsync(Realm, User, Ct));
    }

    [Theory]
    [InlineData(WorkspaceRecordState.Suspended, "Suspended")]
    [InlineData(WorkspaceRecordState.PendingDeletion, "PendingDeletion")]
    public async Task AWorkspaceKeepsItsStoredState(WorkspaceRecordState stored, string expected)
    {
        var rig = new Rig();
        rig.Directory.Answer = (_, _) => new WorkspaceDirectoryResult(WorkspaceDirectoryStatus.Found, Record() with { State = stored }, null);

        Assert.Equal(Enum.Parse<WorkspaceState>(expected), (await rig.Store.FindWorkspaceAsync(Realm, Home, Ct))!.State);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Reads: defects and unavailability
    // ------------------------------------------------------------------------------------------------------------------------

    public static TheoryData<string> MalformedCredentialRows() =>
    [
        "short", "id-not-canonical", "id-upper-case", "user-kind", "method-zero", "method-five", "method-text", "subject-null", "provider-null",
        "public-key-text", "flag-two", "flag-text", "sign-count-text", "transports-int", "created-null", "revision-negative", "realm-not-canonical",
        "passkey-without-handle", "passkey-material-on-email", "password-on-email", "provider-invalid", "label-empty", "foreign-realm",
        "foreign-subject", "two-rows", "user-state-zero", "user-state-six", "user-created-negative", "user-name-int", "user-revision-null", "wide",
    ];

    private static PlanValue[][] Malformed(string variant)
    {
        PlanValue[] With(PlanValue[] row, int index, PlanValue value)
        {
            var copy = row.ToArray();
            copy[index] = value;
            return copy;
        }

        var email = EmailRow();
        var user = UserTail();
        return variant switch
        {
            "short" => [[.. email[..17], .. user]],
            "id-not-canonical" => [[.. With(email, 0, T("not-an-id")), .. user]],
            "id-upper-case" => [[.. With(email, 0, T("2000000A-0000-4000-8000-00000000000B")), .. user]],
            "user-kind" => [[.. With(email, 1, I(1)), .. user]],
            "method-zero" => [[.. With(email, 2, I(0)), .. user]],
            "method-five" => [[.. With(email, 2, I(5)), .. user]],
            "method-text" => [[.. With(email, 2, T("2")), .. user]],
            "subject-null" => [[.. With(email, 3, N), .. user]],
            "provider-null" => [[.. With(email, 15, N), .. user]],
            "public-key-text" => [[.. With(PasskeyRow(), 4, T("AQI")), .. user]],
            "flag-two" => [[.. With(PasskeyRow(), 6, I(2)), .. user]],
            "flag-text" => [[.. With(PasskeyRow(), 7, T("0")), .. user]],
            "sign-count-text" => [[.. With(PasskeyRow(), 9, T("7")), .. user]],
            "transports-int" => [[.. With(PasskeyRow(), 8, I(1)), .. user]],
            "created-null" => [[.. With(email, 11, N), .. user]],
            "revision-negative" => [[.. With(email, 17, I(-1)), .. user]],
            "realm-not-canonical" => [[.. With(email, 14, T("realm")), .. user]],
            "passkey-without-handle" => [[.. With(PasskeyRow(), 5, N), .. user]],
            "passkey-material-on-email" => [[.. With(email, 9, I(0)), .. user]],
            "password-on-email" => [[.. With(email, 16, T("verifier")), .. user]],
            "provider-invalid" => [[.. With(email, 15, T("Official Email")), .. user]],
            "label-empty" => [[.. With(email, 10, T(" ")), .. user]],
            "foreign-realm" => [[.. EmailRow(realm: OtherRealm.Value), .. user]],
            "foreign-subject" => [[.. EmailRow(subject: "other@example.test"), .. user]],
            "two-rows" => [[.. email, .. user], [.. email, .. user]],
            "user-state-zero" => [[.. email, .. UserTail(state: 0)]],
            "user-state-six" => [[.. email, .. UserTail(state: 6)]],
            "user-created-negative" => [[.. email, .. With(user, 2, I(-1))]],
            "user-name-int" => [[.. email, .. With(user, 0, I(1))]],
            "user-revision-null" => [[.. email, .. With(user, 4, N)]],
            "wide" => [[.. email, .. user, N]],
            _ => throw new ArgumentOutOfRangeException(nameof(variant)),
        };
    }

    [Theory]
    [MemberData(nameof(MalformedCredentialRows))]
    public async Task AMalformedOrForeignCredentialRowIsADefectAndNeverACredential(string variant)
    {
        var rig = new Rig();
        var rows = Malformed(variant);
        rig.Plans.Answer = _ => Rows(rows);

        // A passkey variant asks for the passkey, so only the malformed column can make the answer a defect.
        var passkey = rows[0].Length > 15 && rows[0][15] == T("official-passkey");
        var (provider, subject) = passkey ? ("official-passkey", "passkey-subject") : ("official-email", "ada@example.test");
        var failure = await Assert.ThrowsAsync<IdentityStoreException>(async () => await rig.Store.FindCredentialAsync(Realm, provider, subject, Ct));

        Assert.Equal(IdentityStoreFailure.Defect, failure.Failure);
        Assert.DoesNotContain("ada@example.test", failure.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheBaselineRowsOfTheDefectTableDecode()
    {
        var rig = new Rig();
        rig.Plans.Answer = read => read.Arguments[1] == T("official-passkey") ? Rows([.. PasskeyRow(), .. UserTail()]) : Rows([.. EmailRow(), .. UserTail()]);

        Assert.Equal(AuthMethod.EmailCode, (await rig.Store.FindCredentialAsync(Realm, "official-email", "ada@example.test", Ct))!.Credential.Method);
        Assert.Equal(AuthMethod.Passkey, (await rig.Store.FindCredentialAsync(Realm, "official-passkey", "passkey-subject", Ct))!.Credential.Method);
    }

    [Fact]
    public async Task ACredentialRowOfAnotherUserOrRealmInTheListIsADefect()
    {
        var rig = new Rig();
        PlanValue[][] bad = [EmailRow(user: OtherUser.Value), EmailRow(realm: OtherRealm.Value), EmailRow()[..17], [.. EmailRow(), N]];
        foreach (var row in bad)
        {
            rig.Plans.Answer = _ => Rows(row);
            var failure = await Assert.ThrowsAsync<IdentityStoreException>(async () => await rig.Store.ListCredentialsAsync(Realm, User, Ct));
            Assert.Equal(IdentityStoreFailure.Defect, failure.Failure);
        }
    }

    [Fact]
    public async Task AUserRowThatIsNotTheUserAskedForOrCannotBeReadIsADefect()
    {
        var rig = new Rig();
        PlanValue[][] bad =
        [
            [T(OtherUser.Value), .. UserTail()],
            [I(1), .. UserTail()],
            [.. UserRow()[..5]],
            [.. UserRow(), N],
            [T(User.Value), T("Ada"), I(9), I(10), N, I(6)],
            [T(User.Value), T("Ada"), I(1), I(10), I(-5), I(6)],
            [T(User.Value), T("Ada"), I(1), I(10), N, I(-1)],
        ];
        foreach (var row in bad)
        {
            rig.Plans.Answer = _ => Rows(row);
            Assert.Equal(IdentityStoreFailure.Defect, (await Assert.ThrowsAsync<IdentityStoreException>(async () => await rig.Store.FindUserAsync(Realm, User, Ct))).Failure);
        }

        rig.Plans.Answer = _ => Rows(UserRow(), UserRow());
        Assert.Equal(IdentityStoreFailure.Defect, (await Assert.ThrowsAsync<IdentityStoreException>(async () => await rig.Store.FindUserAsync(Realm, User, Ct))).Failure);
    }

    [Fact]
    public async Task ARecoveryAnswerThatIsNotOneFlagIsADefect()
    {
        var rig = new Rig();
        PlanValue[][][] answers = [[[I(1)]], [[T("true")]], [[PlanValue.FromBool(true), PlanValue.FromBool(true)]], [[PlanValue.FromBool(true)], [PlanValue.FromBool(false)]]];
        foreach (var rows in answers)
        {
            rig.Plans.Answer = _ => Rows(rows);
            Assert.Equal(IdentityStoreFailure.Defect, (await Assert.ThrowsAsync<IdentityStoreException>(async () => await rig.Store.HasActiveRecoveryPathAsync(Realm, User, Ct))).Failure);
        }
    }

    [Fact]
    public async Task ADirectoryAnswerIsMappedAndAForeignWorkspaceIsADefect()
    {
        var rig = new Rig();
        (WorkspaceDirectoryResult Result, IdentityStoreFailure Failure)[] cases =
        [
            (new(WorkspaceDirectoryStatus.Unavailable, null, "x"), IdentityStoreFailure.Unavailable),
            (new(WorkspaceDirectoryStatus.Defect, null, "x"), IdentityStoreFailure.Defect),
            (new(WorkspaceDirectoryStatus.InvalidRequest, null, "x"), IdentityStoreFailure.Defect),
            (new(WorkspaceDirectoryStatus.Found, null, null), IdentityStoreFailure.Defect),
            (new(WorkspaceDirectoryStatus.Found, Record(realm: OtherRealm.Value), null), IdentityStoreFailure.Defect),
            (new(WorkspaceDirectoryStatus.Found, Record(owner: OtherUser.Value, id: "40000000-0000-4000-8000-000000000009"), null), IdentityStoreFailure.Defect),
            (new(WorkspaceDirectoryStatus.Found, Record() with { State = (WorkspaceRecordState)9 }, null), IdentityStoreFailure.Defect),
            (new(WorkspaceDirectoryStatus.Found, Record() with { Revision = -1 }, null), IdentityStoreFailure.Defect),
            (new(WorkspaceDirectoryStatus.Found, Record(id: "not-an-id"), null), IdentityStoreFailure.Defect),
        ];
        foreach (var (result, failure) in cases)
        {
            rig.Directory.Answer = (_, _) => result;
            Assert.Equal(failure, (await Assert.ThrowsAsync<IdentityStoreException>(async () => await rig.Store.FindWorkspaceAsync(Realm, Home, Ct))).Failure);
            Assert.Equal(failure, (await Assert.ThrowsAsync<IdentityStoreException>(async () => await rig.Store.FindWorkspaceByOwnerAsync(Realm, User, Ct))).Failure);
        }
    }

    public static TheoryData<ModulePlanStatus> NonSuccessStatuses()
    {
        var data = new TheoryData<ModulePlanStatus>();
        foreach (var status in Enum.GetValues<ModulePlanStatus>().Where(status => status != ModulePlanStatus.Succeeded)) data.Add(status);
        return data;
    }

    [Theory]
    [MemberData(nameof(NonSuccessStatuses))]
    public async Task EveryReadStatusOtherThanSuccessIsUnavailableOrADefectAndNeverAnEmptyAnswer(ModulePlanStatus status)
    {
        var rig = new Rig();
        rig.Plans.Answer = _ => ModulePlanOutcome.Of(status);
        var expected = status is ModulePlanStatus.Unavailable or ModulePlanStatus.StaleGeneration ? IdentityStoreFailure.Unavailable : IdentityStoreFailure.Defect;

        Func<Task>[] reads =
        [
            async () => await rig.Store.FindUserAsync(Realm, User, Ct),
            async () => await rig.Store.FindCredentialAsync(Realm, "official-email", "ada@example.test", Ct),
            async () => await rig.Store.ListCredentialsAsync(Realm, User, Ct),
            async () => await rig.Store.HasActiveRecoveryPathAsync(Realm, User, Ct),
        ];
        foreach (var read in reads) Assert.Equal(expected, (await Assert.ThrowsAsync<IdentityStoreException>(read)).Failure);
    }

    [Fact]
    public async Task CancellationReachesThePortsAndIsNotSwallowed()
    {
        var rig = new Rig();
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        rig.Plans.Answer = _ => throw new OperationCanceledException(cancelled.Token);
        rig.Plans.WriteAnswer = _ => throw new OperationCanceledException(cancelled.Token);
        rig.Families.Answer = _ => throw new OperationCanceledException(cancelled.Token);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await rig.Store.FindUserAsync(Realm, User, cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await rig.Store.CommitAsync(Rename(), cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await rig.Store.CommitAsync(Enroll(), cancelled.Token));
        Assert.Equal(cancelled.Token, rig.Plans.Tokens[0]);
        Assert.Equal(cancelled.Token, rig.Families.Tokens[0]);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Commits: call shape
    // ------------------------------------------------------------------------------------------------------------------------

    private static IdentityCommit.RenameUser Rename() => new(Command, Home, new Principal(Realm, User), 6, "Ada L.");

    private static IdentityCommit.Enroll Enroll()
    {
        var user = new User(User, Realm, "Ada", UserState.Active, new UtcMicros(10), null, 1);
        var credential = new AuthIdentity(Credential, User, Realm, "official-email", AuthMethod.EmailCode, "ada@example.test", null, null, null, new UtcMicros(10), null, null, 1);
        return new IdentityCommit.Enroll(Command, user, credential, IdentityRules.NewPersonalWorkspace(Home, user));
    }

    [Fact]
    public async Task AModuleCommitIsTheNamedWritePlanWithTheStatementArgumentsAndTheTailOfIdentityStatements()
    {
        var rig = new Rig();
        rig.Plans.WriteAnswer = _ => ModulePlanOutcome.Of(ModulePlanStatus.Succeeded);
        var commit = Rename();

        Assert.Equal(CommitOutcome.Committed, await rig.Store.CommitAsync(commit, Ct));

        var write = Assert.Single(rig.Plans.Writes);
        var now = UtcMicros.FromDateTimeOffset(Start);
        var outbox = "00000000-0000-4000-8000-000000000101";
        var expected = IdentityStatements.UserRename(commit, new CommitContext(now, outbox, Command, null, 1));
        Assert.Equal("identity.user-rename", write.PlanId);
        Assert.Equal(Home.Value, write.OwnerScope);
        Assert.Equal(expected.OwnerStatements.Select(statement => statement.Select(IdentityRowCodec.ToValue).ToArray()).ToArray(), write.OwnerArguments.Select(statement => statement.ToArray()).ToArray());
        var tail = Assert.IsType<ModuleCommit>(write.Commit);
        Assert.Equal(Guid.Parse(Command), tail.CommandId);
        Assert.Equal(Guid.Parse(Home.Value), tail.WorkspaceId);
        Assert.Equal(("user:" + User.Value, "identity.user.rename", expected.Tail.RequestHash, "{\"ok\":true}", 7L), (tail.ActorRef, tail.Operation, tail.RequestHash, tail.ResultPayloadJson, tail.ResultRevision!.Value));
        Assert.Equal((now.Value, now.Value + CommitContext.ReceiptRetentionMicros, 1L, expected.Tail.ChangeRecordJson), (tail.CreatedAtMicros, tail.ExpiresAtMicros, tail.ChangeSchemaVersion, tail.ChangeRecordJson));
        var e = Assert.Single(tail.Events);
        Assert.Equal(new ModuleOutboxEvent(Guid.Parse(outbox), "identity.user", Guid.Parse(User.Value), 7, "identity.user.renamed", expected.Tail.Events[0].PayloadJson, Guid.Parse(Home.Value), Guid.Parse(Command), null), e);
        Assert.Empty(rig.Families.Calls);
    }

    [Fact]
    public async Task EveryModuleCommitVariantUsesItsOwnPlan()
    {
        var rig = new Rig();
        rig.Plans.WriteAnswer = _ => ModulePlanOutcome.Of(ModulePlanStatus.Succeeded);
        var caller = new Principal(Realm, User);
        var added = new AuthIdentity(Credential, User, Realm, "official-email", AuthMethod.EmailCode, "second@example.test", null, null, null, new UtcMicros(10), null, null, 1);
        IdentityCommit[] commits =
        [
            new IdentityCommit.AddCredential(Command, Home, caller, 6, added),
            new IdentityCommit.RevokeCredential(Command, Home, caller, Credential, 3, 6, new UtcMicros(20)),
            new IdentityCommit.RelabelCredential(Command, Home, caller, Credential, 3, "Work"),
            Rename(),
        ];
        foreach (var commit in commits) Assert.Equal(CommitOutcome.Committed, await rig.Store.CommitAsync(commit, Ct));

        Assert.Equal(["identity.credential-add", "identity.credential-revoke", "identity.credential-relabel", "identity.user-rename"], rig.Plans.Writes.Select(write => write.PlanId));
        Assert.All(rig.Plans.Writes, write => Assert.Equal(Home.Value, write.OwnerScope));
        // Every commit gets a fresh outbox identifier from the identifier source.
        Assert.Equal(4, rig.Plans.Writes.Select(write => write.Commit!.Events[0].OutboxId).Distinct().Count());
    }

    [Fact]
    public async Task AnEnrollmentIsTheAccountEnrollmentFamilyWithTheIdentityAndWorkspaceContributions()
    {
        var rig = new Rig();
        rig.Families.Answer = _ => ModulePlanOutcome.Of(ModulePlanStatus.Succeeded);
        var commit = Enroll();

        Assert.Equal(CommitOutcome.Committed, await rig.Store.CommitAsync(commit, Ct));

        var call = Assert.Single(rig.Families.Calls);
        var expected = IdentityStatements.Enroll(commit, new CommitContext(UtcMicros.FromDateTimeOffset(Start), "00000000-0000-4000-8000-000000000101", Command, null, 1));
        Assert.Equal(("account-enrollment", "families.account-enrollment.create-user", Home.Value), (call.Family, call.PlanId, call.OwnerScope));
        Assert.Equal(
            expected.Contributions.Select(c => (c.Module, c.Kind == "revision" ? FamilyStatementClass.Revision : FamilyStatementClass.Record, c.Key)).ToArray(),
            call.Statements.Select(s => (s.Module, s.Class, s.Key)).ToArray());
        Assert.Equal(
            expected.Contributions.Select(c => c.Arguments.Select(IdentityRowCodec.ToValue).ToArray()).ToArray(),
            call.Statements.Select(s => s.Arguments.ToArray()).ToArray());
        Assert.Equal(("user:" + User.Value, "identity.account.enroll", expected.Tail.RequestHash), (call.Commit.ActorRef, call.Commit.Operation, call.Commit.RequestHash));
        Assert.Empty(rig.Plans.Writes);
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Commits: the status table
    // ------------------------------------------------------------------------------------------------------------------------

    /// <summary>Every plan status and the outcome (or failure) it maps to; a constraint is a collision only for an enrollment (and an added credential).</summary>
    private static readonly (ModulePlanStatus Status, string Module, string Enroll)[] CommitTable =
    [
        (ModulePlanStatus.Succeeded, "Committed", "Committed"),
        (ModulePlanStatus.Replayed, "Replayed", "Replayed"),
        (ModulePlanStatus.GuardRefused, "Refused", "Refused"),
        (ModulePlanStatus.ConstraintRefused, "Defect", "Refused"),
        (ModulePlanStatus.ReusedIdentifier, "IdentifierConflict", "IdentifierConflict"),
        (ModulePlanStatus.ReceiptExpired, "ReceiptExpired", "ReceiptExpired"),
        (ModulePlanStatus.UnknownOutcome, "Unknown", "Unknown"),
        (ModulePlanStatus.Unavailable, "Unavailable", "Unavailable"),
        (ModulePlanStatus.StaleGeneration, "Unavailable", "Unavailable"),
        (ModulePlanStatus.Rejected, "Defect", "Defect"),
        (ModulePlanStatus.ReplayedFailure, "Defect", "Defect"),
        (ModulePlanStatus.DuplicateMessage, "Defect", "Defect"),
    ];

    public static TheoryData<ModulePlanStatus, bool, string> CommitStatusTable()
    {
        var data = new TheoryData<ModulePlanStatus, bool, string>();
        foreach (var (status, module, enroll) in CommitTable)
        {
            data.Add(status, false, module);
            data.Add(status, true, enroll);
        }

        return data;
    }

    [Theory]
    [MemberData(nameof(CommitStatusTable))]
    public async Task EveryCommitStatusMapsToOneOutcomeOrATypedFailure(ModulePlanStatus status, bool enroll, string expected)
    {
        var rig = new Rig();
        rig.Plans.WriteAnswer = _ => ModulePlanOutcome.Of(status);
        rig.Families.Answer = _ => ModulePlanOutcome.Of(status);
        IdentityCommit commit = enroll ? Enroll() : Rename();

        if (expected is "Unavailable" or "Defect")
        {
            var failure = await Assert.ThrowsAsync<IdentityStoreException>(async () => await rig.Store.CommitAsync(commit, Ct));
            Assert.Equal(Enum.Parse<IdentityStoreFailure>(expected), failure.Failure);
        }
        else
        {
            Assert.Equal(Enum.Parse<CommitOutcome>(expected), await rig.Store.CommitAsync(commit, Ct));
        }
    }

    [Fact]
    public void TheStatusTableCoversEveryPlanStatus()
    {
        Assert.Equal(Enum.GetValues<ModulePlanStatus>().Order(), CommitTable.Select(row => row.Status).Order());
    }

    [Fact]
    public void AConstraintRefusalIsARetryableCollisionOnlyForTheCommitsThatInsertRandomIdentifiers()
    {
        var caller = new Principal(Realm, User);
        var added = new AuthIdentity(Credential, User, Realm, "official-email", AuthMethod.EmailCode, "b@example.test", null, null, null, new UtcMicros(10), null, null, 1);
        Assert.Equal(CommitOutcome.Refused, D1IdentityStore.Map(Enroll(), ModulePlanStatus.ConstraintRefused, "p"));
        Assert.Equal(CommitOutcome.Refused, D1IdentityStore.Map(new IdentityCommit.AddCredential(Command, Home, caller, 6, added), ModulePlanStatus.ConstraintRefused, "p"));
        foreach (IdentityCommit commit in new IdentityCommit[]
        {
            new IdentityCommit.RevokeCredential(Command, Home, caller, Credential, 3, 6, new UtcMicros(20)),
            new IdentityCommit.RelabelCredential(Command, Home, caller, Credential, 3, "Work"),
            Rename(),
        })
        {
            Assert.Equal(IdentityStoreFailure.Defect, Assert.Throws<IdentityStoreException>(() => D1IdentityStore.Map(commit, ModulePlanStatus.ConstraintRefused, "p")).Failure);
        }
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // The shared vector through the real ports
    // ------------------------------------------------------------------------------------------------------------------------

    public static TheoryData<int> VectorSteps()
    {
        var data = new TheoryData<int>();
        for (var i = 0; i < IdentityStatementTests.Vector.GetProperty("steps").GetArrayLength(); i++) data.Add(i);
        return data;
    }

    [Theory]
    [MemberData(nameof(VectorSteps))]
    public async Task TheStoreSendsExactlyTheSharedVectorArgumentsThroughTheRealPorts(int index)
    {
        var step = IdentityStatementTests.Vector.GetProperty("steps")[index];
        var (commit, context) = IdentityStatementTests.Commit(step.GetProperty("op").GetString()!, step.GetProperty("input"));
        var recorder = new RecordingExecutor();
        var time = new IdentityClock(Start);
        var module = ModuleDescriptor.Create("Identity", "identity");
        var store = new D1IdentityStore(
            new ModulePlanPortFactory(recorder, 0, time).For(module), new ModuleFamilyPortFactory(recorder, 0, time).For(module), new ScriptedDirectory(), _ => context);

        Assert.Equal(CommitOutcome.Committed, await store.CommitAsync(commit, Ct));

        var call = Assert.Single(recorder.Calls);
        Assert.Equal(step.GetProperty("plan").GetString(), call.Plan.Id);
        Assert.Equal(step.GetProperty("scope").GetString(), call.OwnerScope);
        Assert.Equal(IdentityStatementTests.Expected(step), call.Arguments.Select(statement => statement.Select(IdentityStatementTests.Describe).ToArray()).ToArray());
    }

    [Fact]
    public void ArgumentConversionIsExact()
    {
        Assert.Equal(PlanValue.FromInt64(long.MinValue), IdentityRowCodec.ToValue(PlanArgument.Int64(long.MinValue)));
        Assert.Equal(PlanValue.FromInt64(-1), IdentityRowCodec.ToValue(PlanArgument.OptionalInt64(null)));
        Assert.Equal(PlanValue.FromBytes([1, 2, 3, 251, 255]), IdentityRowCodec.ToValue(PlanArgument.Bytes([1, 2, 3, 251, 255])));
        Assert.Equal(PlanValue.Null, IdentityRowCodec.ToValue(PlanArgument.Null));
        Assert.Equal(PlanValue.FromText("x"), IdentityRowCodec.ToValue(PlanArgument.Text("x")));
        Assert.Throws<ArgumentOutOfRangeException>(() => IdentityRowCodec.ToClass("authorization"));
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Scripted ports
    // ------------------------------------------------------------------------------------------------------------------------

    private sealed class ScriptedPlans : IModulePlanPort
    {
        public Func<ModulePlanRead, ModulePlanOutcome> Answer { get; set; } = _ => throw new InvalidOperationException("No read answer scripted.");

        public Func<ModulePlanWrite, ModulePlanOutcome> WriteAnswer { get; set; } = _ => throw new InvalidOperationException("No write answer scripted.");

        public List<ModulePlanRead> Reads { get; } = [];

        public List<ModulePlanWrite> Writes { get; } = [];

        public List<CancellationToken> Tokens { get; } = [];

        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken)
        {
            Reads.Add(read);
            Tokens.Add(cancellationToken);
            return Task.FromResult(Answer(read));
        }

        public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken)
        {
            Writes.Add(write);
            Tokens.Add(cancellationToken);
            return Task.FromResult(WriteAnswer(write));
        }
    }

    private sealed class ScriptedFamilies : IModuleFamilyPort
    {
        public Func<ModuleFamilyCall, ModulePlanOutcome> Answer { get; set; } = _ => throw new InvalidOperationException("No family answer scripted.");

        public List<ModuleFamilyCall> Calls { get; } = [];

        public List<CancellationToken> Tokens { get; } = [];

        public Task<ModulePlanOutcome> ExecuteAsync(ModuleFamilyCall call, CancellationToken cancellationToken)
        {
            Calls.Add(call);
            Tokens.Add(cancellationToken);
            return Task.FromResult(Answer(call));
        }
    }

    private sealed class ScriptedDirectory : IWorkspaceDirectory
    {
        public Func<string, string, WorkspaceDirectoryResult> Answer { get; set; } = (_, _) => throw new InvalidOperationException("No directory answer scripted.");

        public List<(string By, string Realm, string Key)> Calls { get; } = [];

        public ValueTask<WorkspaceDirectoryResult> FindAsync(string realmId, string workspaceId, CancellationToken cancellationToken)
        {
            Calls.Add(("id", realmId, workspaceId));
            return ValueTask.FromResult(Answer(realmId, workspaceId));
        }

        public ValueTask<WorkspaceDirectoryResult> FindByOwnerAsync(string realmId, string ownerUserId, CancellationToken cancellationToken)
        {
            Calls.Add(("owner", realmId, ownerUserId));
            return ValueTask.FromResult(Answer(realmId, ownerUserId));
        }
    }

    /// <summary>Records every plan call and answers it as committed, so the sealed arguments of the real ports can be compared.</summary>
    private sealed class RecordingExecutor : IPlanExecutor
    {
        public List<PlanCall> Calls { get; } = [];

        public Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken)
        {
            PlanArguments.Validate(call);
            Calls.Add(call);
            return Task.FromResult(new PlanResult([], 1));
        }
    }
}
