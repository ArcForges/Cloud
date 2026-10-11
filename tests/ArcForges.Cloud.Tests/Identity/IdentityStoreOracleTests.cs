// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Identity;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Persistence.Infrastructure;
using ArcForges.Cloud.Modules.Workspace;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Entitlement;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

/// <summary>
/// The identity service over its production D1 store, composed exactly as the Identity and Workspace modules register themselves, on the
/// real plan and family ports and the production Worker plan code over SQLite with every committed migration (the COM.16 bridge). It
/// proves the whole path: every read is realm-scoped, every commit variant writes its rows with the receipt, outbox row and change
/// record, a false guard writes nothing, concurrent enrollments of one credential commit once, a colliding random identifier is refused
/// whole and retried with fresh identifiers, and replay, reused identifier, expired receipt and unknown outcome are answered from real
/// receipts. SQLite is not D1 (the opt-in workerd run repeats the engine-dependent cases).
/// </summary>
public sealed class IdentityStoreOracleTests : IDisposable
{
    private static readonly RealmId RealmA = IdentityHarness.RealmA;
    private static readonly RealmId RealmB = IdentityHarness.RealmB;
    private static readonly DateTimeOffset Start = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);

    private static readonly string[] Tables =
    [
        "identity_user", "identity_auth_identity", "workspace_workspace", "platform_command", "platform_outbox", "platform_change_archive", "platform_command_guard",
    ];

    private readonly SqliteBridgeExecutor bridge = new(recoveryGeneration: 1);
    private readonly FakeTime time = new(Start);
    private readonly List<ServiceProvider> providers = [];

    public void Dispose()
    {
        foreach (var provider in providers) provider.Dispose();
        bridge.Dispose();
    }

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private sealed record Composition(IdentityService Service, IIdentityStore Store);

    /// <summary>The service and store as the modules register them, over the real ports on the given executor (the bridge by default).</summary>
    private Composition Compose(IPlanExecutor? executor = null, IIdentityIdSource? ids = null, ulong generation = 1)
    {
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(time);
        services.AddSingleton<IModulePlanPortFactory>(new ModulePlanPortFactory(executor ?? bridge, generation, time));
        services.AddSingleton<IModuleFamilyPortFactory>(new ModuleFamilyPortFactory(executor ?? bridge, generation, time));
        if (ids is not null) services.AddSingleton(ids);
        ((IModuleBoundary)WorkspaceModule.Instance).Register(services);
        ((IModuleBoundary)IdentityModule.Instance).Register(services);
        var provider = services.BuildServiceProvider();
        providers.Add(provider);
        return new Composition(provider.GetRequiredService<IdentityService>(), provider.GetRequiredService<IIdentityStore>());
    }

    private async Task<long[]> CountsAsync()
    {
        var counts = new long[Tables.Length];
        for (var index = 0; index < Tables.Length; index++) counts[index] = await bridge.CountAsync(Tables[index], cancellationToken: Ct);
        return counts;
    }

    private static long[] Counts(long users, long credentials, long workspaces, long commits) => [users, credentials, workspaces, commits, commits, commits, 0];

    private static string NewCommand() => Guid.NewGuid().ToString("D");

    private static EnrollmentRequest Request(string subject, RealmId? realm = null, string? command = null, NewCredential? credential = null) =>
        new(realm ?? RealmA, command ?? NewCommand(), "Ada", credential ?? IdentityHarness.Email(subject));

    private static async Task<EnrollmentOutcome> EnrollAsync(IdentityService service, string subject, RealmId? realm = null)
    {
        var result = await service.CompleteEnrollmentAsync(Request(subject, realm), Ct);
        Assert.True(result.IsSuccess, "enrollment failed: " + result.Error);
        return result.Value!;
    }

    private Task AddRecoveryCodeAsync(UserId user) => bridge.ExecAsync(
        "INSERT INTO identity_recovery_code (code_hash, set_id, user_id, issued_at, consumed_at, invalidated_at) VALUES (X'"
        + Convert.ToHexString(Enumerable.Repeat((byte)0x5a, 32).ToArray()) + "', '30000000-0000-4000-8000-000000000001', '" + user.Value + "', 50, NULL, NULL);",
        Ct);

    // ------------------------------------------------------------------------------------------------------------------------
    // Reads and commits
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task AnEnrollmentCommitsItsRecordsWithTheTailAndEveryReadReturnsThemOnlyInTheirRealm()
    {
        var (service, store) = Compose();
        var command = NewCommand();

        var result = await service.CompleteEnrollmentAsync(Request("ada@example.test", command: command), Ct);

        Assert.True(result.IsSuccess);
        var account = result.Value!;
        Assert.True(account.CreatedUser);
        Assert.Equal(Counts(1, 1, 1, 1), await CountsAsync());
        Assert.Equal(account.User, await store.FindUserAsync(RealmA, account.User.Id, Ct));
        Assert.Equal(new CredentialLookup(account.Credential, account.User), await store.FindCredentialAsync(RealmA, "official-email", "ada@example.test", Ct));
        Assert.Equal(new[] { account.Credential }, await store.ListCredentialsAsync(RealmA, account.User.Id, Ct));
        Assert.Equal(account.Workspace, await store.FindWorkspaceAsync(RealmA, account.Workspace.Id, Ct));
        Assert.Equal(account.Workspace, await store.FindWorkspaceByOwnerAsync(RealmA, account.User.Id, Ct));
        Assert.False(await store.HasActiveRecoveryPathAsync(RealmA, account.User.Id, Ct));

        // Realm B sees none of it.
        Assert.Null(await store.FindUserAsync(RealmB, account.User.Id, Ct));
        Assert.Null(await store.FindCredentialAsync(RealmB, "official-email", "ada@example.test", Ct));
        Assert.Empty(await store.ListCredentialsAsync(RealmB, account.User.Id, Ct));
        Assert.Null(await store.FindWorkspaceAsync(RealmB, account.Workspace.Id, Ct));
        Assert.Null(await store.FindWorkspaceByOwnerAsync(RealmB, account.User.Id, Ct));
        Assert.False((await service.AuthorizeWorkspaceAsync(new Principal(RealmB, account.User.Id), account.Workspace.Id, Ct)).IsSuccess);
        Assert.True((await service.AuthorizeWorkspaceAsync(IdentityHarness.Caller(account), account.Workspace.Id, Ct)).IsSuccess);

        // The tail: the receipt of this command, the outbox row correlated to it and an Identity change record of schema version 1.
        var receipt = Assert.Single(await bridge.QueryAsync("SELECT command_id, workspace_id, actor_ref, operation, status FROM platform_command", Ct));
        Assert.Equal([command, account.Workspace.Id.Value, "user:" + account.User.Id.Value, "identity.account.enroll", "2"], receipt);
        var outbox = Assert.Single(await bridge.QueryAsync("SELECT event_type, aggregate_id, workspace_id, correlation_id, causation_id FROM platform_outbox", Ct));
        Assert.Equal(["identity.user.enrolled", account.User.Id.Value, account.Workspace.Id.Value, command, null], outbox);
        Assert.Equal(["1"], Assert.Single(await bridge.QueryAsync("SELECT schema_version FROM platform_change_archive", Ct)));
    }

    [Fact]
    public async Task ASecondEnrollmentOfTheCredentialSignsTheUserInAndWritesNothing()
    {
        var (service, _) = Compose();
        var first = await EnrollAsync(service, "ada@example.test");
        var before = await CountsAsync();

        var again = await EnrollAsync(service, "ada@example.test");

        Assert.False(again.CreatedUser);
        Assert.Equal(first.User, again.User);
        Assert.Equal(first.Workspace, again.Workspace);
        Assert.Equal(before, await CountsAsync());
    }

    [Fact]
    public async Task PasskeyAndPasswordCredentialsRoundTripWithTheirMaterial()
    {
        var (service, store) = Compose();
        var account = await EnrollAsync(service, "ada@example.test");
        var caller = IdentityHarness.Caller(account);

        var passkey = await service.AddCredentialAsync(caller, NewCommand(), IdentityHarness.Passkey("passkey-subject"), Ct);
        var password = await service.AddCredentialAsync(caller, NewCommand(), IdentityHarness.Password("ada"), Ct);

        Assert.True(passkey.IsSuccess && password.IsSuccess);
        var stored = (await store.FindCredentialAsync(RealmA, "official-passkey", "passkey-subject", Ct))!;
        Assert.Equal(passkey.Value!.Id, stored.Credential.Id);
        var material = stored.Credential.Passkey!;
        Assert.Equal(new byte[] { 1, 2, 3 }, material.PublicKey.ToArray());
        Assert.Equal(new byte[] { 9, 8, 7 }, material.UserHandle.ToArray());
        Assert.Equal((true, false, "[\"internal\"]", 0L), (material.BackupEligible!.Value, material.BackupState!.Value, material.TransportsJson, material.SignCount!.Value));
        Assert.Equal("Phone", stored.Credential.Label);
        Assert.Equal(3, stored.User.Revision);
        Assert.Equal(password.Value, (await store.FindCredentialAsync(RealmA, "self-host-password", "ada", Ct))!.Credential);
        Assert.Equal("verifier-example", password.Value!.Password);
        Assert.Equal(3, (await store.ListCredentialsAsync(RealmA, account.User.Id, Ct)).Count);
        var resolved = await service.ResolveCredentialAsync(RealmA, "official-passkey", "passkey-subject", Ct);
        Assert.Equal(account.User.Id, resolved.Value!.User.Id);
        Assert.Equal(Counts(1, 3, 1, 3), await CountsAsync());
    }

    [Fact]
    public async Task RelabelRenameAndRevokeCommitWithTheirRevisionsAndTheLastCredentialNeedsARecoveryPath()
    {
        var (service, store) = Compose();
        var account = await EnrollAsync(service, "ada@example.test");
        var caller = IdentityHarness.Caller(account);
        var passkey = (await service.AddCredentialAsync(caller, NewCommand(), IdentityHarness.Passkey("passkey-subject"), Ct)).Value!;

        var relabeled = await service.RelabelCredentialAsync(caller, NewCommand(), passkey.Id, "Laptop", Ct);
        var renamed = await service.RenameUserAsync(caller, NewCommand(), "Ada L.", Ct);
        var revoked = await service.RevokeCredentialAsync(caller, NewCommand(), account.Credential.Id, Ct);

        Assert.True(relabeled.IsSuccess && renamed.IsSuccess && revoked.IsSuccess);
        var rows = await store.ListCredentialsAsync(RealmA, account.User.Id, Ct);
        Assert.Equal(("Laptop", 2L), (rows.Single(c => c.Id == passkey.Id).Label, rows.Single(c => c.Id == passkey.Id).Revision));
        var email = rows.Single(c => c.Id == account.Credential.Id);
        Assert.Equal((revoked.Value!.RevokedAt, 2L), (email.RevokedAt, email.Revision));
        var user = (await store.FindUserAsync(RealmA, account.User.Id, Ct))!;
        Assert.Equal(("Ada L.", 4L), (user.DisplayName, user.Revision));

        // The passkey is now the last usable credential: refused without a recovery path, admitted with one (the real recovery read).
        Assert.Equal(IdentityError.LastCredential, (await service.RevokeCredentialAsync(caller, NewCommand(), passkey.Id, Ct)).Error);
        await AddRecoveryCodeAsync(account.User.Id);
        Assert.True(await store.HasActiveRecoveryPathAsync(RealmA, account.User.Id, Ct));
        Assert.False(await store.HasActiveRecoveryPathAsync(RealmB, account.User.Id, Ct));
        Assert.True((await service.RevokeCredentialAsync(caller, NewCommand(), passkey.Id, Ct)).IsSuccess);
        Assert.All(await store.ListCredentialsAsync(RealmA, account.User.Id, Ct), credential => Assert.True(credential.IsRevoked));
        Assert.Equal(Counts(1, 2, 1, 6), await CountsAsync());
    }

    [Fact]
    public async Task ARefusedGuardCommitsNothingNotEvenAReceipt()
    {
        var (service, store) = Compose();
        var account = await EnrollAsync(service, "ada@example.test");
        var caller = IdentityHarness.Caller(account);
        var before = await CountsAsync();

        IdentityCommit[] stale =
        [
            new IdentityCommit.RenameUser(NewCommand(), account.Workspace.Id, caller, 0, "Stale"),
            new IdentityCommit.RelabelCredential(NewCommand(), account.Workspace.Id, caller, account.Credential.Id, 9, "Stale"),
            new IdentityCommit.RevokeCredential(NewCommand(), account.Workspace.Id, caller, account.Credential.Id, 1, 1, new UtcMicros(5)),
            new IdentityCommit.AddCredential(NewCommand(), account.Workspace.Id, caller, 7, account.Credential with { Id = AuthIdentityId.Parse(Guid.NewGuid().ToString("D")), Subject = "x@example.test" }),
            new IdentityCommit.Enroll(NewCommand(), account.User, account.Credential, account.Workspace),
        ];
        foreach (var commit in stale) Assert.Equal(CommitOutcome.Refused, await store.CommitAsync(commit, Ct));

        Assert.Equal(before, await CountsAsync());
        Assert.Equal("Ada", (await store.FindUserAsync(RealmA, account.User.Id, Ct))!.DisplayName);
    }

    [Fact]
    public async Task TwentyFiveConcurrentEnrollmentsOfOneCredentialCommitOnce()
    {
        var (service, _) = Compose();

        var results = await Task.WhenAll(Enumerable.Range(0, 25).Select(_ => service.CompleteEnrollmentAsync(Request("contended@example.test"), Ct).AsTask()));

        Assert.All(results, result => Assert.True(result.IsSuccess, "enrollment failed: " + result.Error));
        Assert.Single(results, result => result.Value!.CreatedUser);
        Assert.Single(results.Select(result => result.Value!.User.Id).Distinct());
        Assert.Equal(Counts(1, 1, 1, 1), await CountsAsync());
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Colliding random identifiers
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task AnEnrollmentWhoseRandomUserIdentifierExistsIsRefusedWholeAndRetriedWithFreshIdentifiers()
    {
        var (seed, store) = Compose();
        var existing = await EnrollAsync(seed, "first@example.test");
        var discarded = "20000000-0000-4000-8000-0000000000d1";
        var ids = new ScriptedIds(existing.User.Id.Value, discarded, "40000000-0000-4000-8000-0000000000d2");
        var (service, _) = Compose(ids: ids);

        var account = await EnrollAsync(service, "second@example.test");

        Assert.True(account.CreatedUser);
        Assert.NotEqual(existing.User.Id, account.User.Id);
        Assert.NotEqual(discarded, account.Credential.Id.Value);
        Assert.Equal(existing.User, await store.FindUserAsync(RealmA, existing.User.Id, Ct));
        Assert.Equal(Counts(2, 2, 2, 2), await CountsAsync());
    }

    [Fact]
    public async Task AUserIdentifierHeldInAnotherRealmMeetsThePrimaryKeyAndIsRetriedWithFreshIdentifiers()
    {
        var (seed, store) = Compose();
        var other = await EnrollAsync(seed, "b@example.test", RealmB);
        var (service, _) = Compose(ids: new ScriptedIds(other.User.Id.Value));

        var account = await EnrollAsync(service, "a@example.test", RealmA);

        Assert.True(account.CreatedUser);
        Assert.NotEqual(other.User.Id, account.User.Id);
        Assert.Equal(other.User, await store.FindUserAsync(RealmB, other.User.Id, Ct));
        Assert.Null(await store.FindUserAsync(RealmA, other.User.Id, Ct));
        Assert.Equal(Counts(2, 2, 2, 2), await CountsAsync());
    }

    [Fact]
    public async Task AnAddedCredentialWhoseRandomIdentifierExistsIsRetriedWithAFreshOne()
    {
        var (seed, store) = Compose();
        var account = await EnrollAsync(seed, "ada@example.test");
        var (service, _) = Compose(ids: new ScriptedIds(account.Credential.Id.Value));

        var added = await service.AddCredentialAsync(IdentityHarness.Caller(account), NewCommand(), IdentityHarness.Email("second@example.test"), Ct);

        Assert.True(added.IsSuccess);
        Assert.NotEqual(account.Credential.Id, added.Value!.Id);
        Assert.Equal(account.Credential, (await store.FindCredentialAsync(RealmA, "official-email", "ada@example.test", Ct))!.Credential);
        Assert.Equal(2, (await store.FindUserAsync(RealmA, account.User.Id, Ct))!.Revision);
        Assert.Equal(Counts(1, 2, 1, 2), await CountsAsync());
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Receipts: replay, reused identifier, expired receipt, unknown outcome, unavailability
    // ------------------------------------------------------------------------------------------------------------------------

    [Fact]
    public async Task ACommitWhoseResponseAndReconciliationWereLostIsResentIdenticallyAndReplaysFromItsReceipt()
    {
        var (seed, store) = Compose();
        var account = await EnrollAsync(seed, "ada@example.test");
        var lossy = new LossyExecutor(bridge, "identity.user-rename", executeFirst: true, loseReconciliation: true);
        var (service, _) = Compose(lossy);

        var renamed = await service.RenameUserAsync(IdentityHarness.Caller(account), NewCommand(), "Ada L.", Ct);

        Assert.True(renamed.IsSuccess);
        Assert.Equal(2, lossy.Sends);
        var user = (await store.FindUserAsync(RealmA, account.User.Id, Ct))!;
        Assert.Equal(("Ada L.", 2L), (user.DisplayName, user.Revision));
        Assert.Equal(renamed.Value, user);
        Assert.Equal(Counts(1, 1, 1, 2), await CountsAsync());
    }

    [Fact]
    public async Task AnUnknownEnrollmentThatNeverRanIsResentIdenticallyAndCommitsOnce()
    {
        var lossy = new LossyExecutor(bridge, "families.account-enrollment.create-user", executeFirst: false, loseReconciliation: false);
        var (service, store) = Compose(lossy);

        var account = await EnrollAsync(service, "ada@example.test");

        Assert.True(account.CreatedUser);
        Assert.Equal(2, lossy.Sends);
        Assert.Equal(account.User, await store.FindUserAsync(RealmA, account.User.Id, Ct));
        Assert.Equal(Counts(1, 1, 1, 1), await CountsAsync());
    }

    [Fact]
    public async Task AReceiptWhoseWindowPassedBeforeTheResendIsAnExpiredRefusalAndNothingRunsAgain()
    {
        var (seed, store) = Compose();
        var account = await EnrollAsync(seed, "ada@example.test");
        var lossy = new LossyExecutor(bridge, "identity.user-rename", executeFirst: true, loseReconciliation: true, onLoss: () => time.Advance(TimeSpan.FromDays(7)));
        var (service, _) = Compose(lossy);

        var renamed = await service.RenameUserAsync(IdentityHarness.Caller(account), NewCommand(), "Ada L.", Ct);

        Assert.Equal(IdentityError.ReceiptExpired, renamed.Error);
        Assert.Equal(2, lossy.Sends);
        Assert.Equal(2, (await store.FindUserAsync(RealmA, account.User.Id, Ct))!.Revision);
        Assert.Equal(Counts(1, 1, 1, 2), await CountsAsync());
    }

    [Fact]
    public async Task ACommandIdentifierReusedForAnotherRequestIsAConflictAndWritesNothing()
    {
        var (service, _) = Compose();
        var command = NewCommand();
        var account = (await service.CompleteEnrollmentAsync(Request("ada@example.test", command: command), Ct)).Value!;
        var before = await CountsAsync();

        var otherEnrollment = await service.CompleteEnrollmentAsync(Request("grace@example.test", command: command), Ct);
        var otherWrite = await service.RenameUserAsync(IdentityHarness.Caller(account), command, "Ada L.", Ct);

        Assert.Equal(IdentityError.IdentifierConflict, otherEnrollment.Error);
        Assert.Equal(IdentityError.IdentifierConflict, otherWrite.Error);
        Assert.Equal(before, await CountsAsync());
    }

    [Fact]
    public async Task AnEnrollmentThatMeetsItsOwnCommandWithOtherIdentifiersProbesTheReceiptAndSignsInWithoutWriting()
    {
        var (first, store) = Compose();
        var request = Request("ada@example.test");
        EnrollmentOutcome? original = null;
        var recorder = new HookedStore(store, async () => original = (await first.CompleteEnrollmentAsync(request, Ct)).Value);
        var racing = new IdentityService(recorder, new RandomIdentityIdSource(), time);

        var result = await racing.CompleteEnrollmentAsync(request, Ct);

        Assert.True(result.IsSuccess, "enrollment failed: " + result.Error);
        Assert.NotNull(original);
        Assert.True(original.CreatedUser);
        Assert.False(result.Value!.CreatedUser);
        Assert.Equal(original.User, result.Value.User);
        Assert.Equal(original.Credential, result.Value.Credential);
        Assert.Equal(original.Workspace, result.Value.Workspace);
        Assert.Equal([CommitOutcome.IdentifierConflict, CommitOutcome.Replayed], recorder.Outcomes);
        Assert.Equal(Counts(1, 1, 1, 1), await CountsAsync());
    }

    [Fact]
    public async Task AnUnavailableOrStaleStoreIsATypedFailureAndWritesNothing()
    {
        var (seed, _) = Compose();
        var account = await EnrollAsync(seed, "ada@example.test");
        var before = await CountsAsync();

        var (down, _) = Compose(new FailingExecutor(bridge, "identity.user-rename", PlanFailureKind.Unavailable));
        var failure = await Assert.ThrowsAsync<IdentityStoreException>(async () => await down.RenameUserAsync(IdentityHarness.Caller(account), NewCommand(), "Ada L.", Ct));
        Assert.Equal(IdentityStoreFailure.Unavailable, failure.Failure);

        var (stale, staleStore) = Compose(generation: 2);
        Assert.Equal(IdentityStoreFailure.Unavailable, (await Assert.ThrowsAsync<IdentityStoreException>(async () => await staleStore.FindUserAsync(RealmA, account.User.Id, Ct))).Failure);
        Assert.Equal(IdentityStoreFailure.Unavailable, (await Assert.ThrowsAsync<IdentityStoreException>(async () => await stale.CompleteEnrollmentAsync(Request("x@example.test"), Ct))).Failure);

        Assert.Equal(before, await CountsAsync());
    }

    // ------------------------------------------------------------------------------------------------------------------------
    // Test doubles (external failures only; the plans, ports and store are the production code)
    // ------------------------------------------------------------------------------------------------------------------------

    /// <summary>Returns the scripted identifiers first, then fresh random ones.</summary>
    private sealed class ScriptedIds(params string[] first) : IIdentityIdSource
    {
        private readonly Queue<string> queue = new(first);
        private readonly RandomIdentityIdSource random = new();

        public string NewId()
        {
            lock (queue) return queue.TryDequeue(out var id) ? id : random.NewId();
        }
    }

    /// <summary>
    /// Loses the first send of one plan: after executing it (a lost response) or before (a lost request). With
    /// <paramref name="loseReconciliation"/> the receipt read that follows is lost too, so the port cannot resolve the outcome.
    /// </summary>
    private sealed class LossyExecutor(IPlanExecutor inner, string planId, bool executeFirst, bool loseReconciliation, Action? onLoss = null) : IPlanExecutor
    {
        private bool lost;
        private bool reconciliationLost;

        public int Sends { get; private set; }

        public async Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken)
        {
            if (call.Plan.Id == planId)
            {
                Sends++;
                if (!lost)
                {
                    lost = true;
                    if (executeFirst) await inner.ExecuteAsync(call, cancellationToken);
                    throw new PlanFailureException(PlanFailureKind.UnknownOutcome);
                }
            }
            else if (loseReconciliation && lost && !reconciliationLost && call.Plan.Id == PlanManifest.Platform.CommandLoad.Id)
            {
                reconciliationLost = true;
                onLoss?.Invoke();
                throw new PlanFailureException(PlanFailureKind.UnknownOutcome);
            }

            return await inner.ExecuteAsync(call, cancellationToken);
        }
    }

    /// <summary>Fails every send of one plan with a failure that executed nothing.</summary>
    private sealed class FailingExecutor(IPlanExecutor inner, string planId, PlanFailureKind kind) : IPlanExecutor
    {
        public Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken) =>
            call.Plan.Id == planId ? throw new PlanFailureException(kind) : inner.ExecuteAsync(call, cancellationToken);
    }

    /// <summary>Runs an action before the first commit (another request winning the race) and records every commit outcome of the real store.</summary>
    private sealed class HookedStore(IIdentityStore inner, Func<Task> beforeFirstCommit) : IIdentityStore
    {
        private Func<Task>? hook = beforeFirstCommit;

        public List<CommitOutcome> Outcomes { get; } = [];

        public ValueTask<User?> FindUserAsync(RealmId realm, UserId id, CancellationToken cancellationToken) => inner.FindUserAsync(realm, id, cancellationToken);

        public ValueTask<CredentialLookup?> FindCredentialAsync(RealmId realm, string providerId, string subject, CancellationToken cancellationToken) =>
            inner.FindCredentialAsync(realm, providerId, subject, cancellationToken);

        public ValueTask<IReadOnlyList<AuthIdentity>> ListCredentialsAsync(RealmId realm, UserId id, CancellationToken cancellationToken) => inner.ListCredentialsAsync(realm, id, cancellationToken);

        public ValueTask<Workspace?> FindWorkspaceAsync(RealmId realm, WorkspaceId id, CancellationToken cancellationToken) => inner.FindWorkspaceAsync(realm, id, cancellationToken);

        public ValueTask<Workspace?> FindWorkspaceByOwnerAsync(RealmId realm, UserId owner, CancellationToken cancellationToken) => inner.FindWorkspaceByOwnerAsync(realm, owner, cancellationToken);

        public ValueTask<bool> HasActiveRecoveryPathAsync(RealmId realm, UserId id, CancellationToken cancellationToken) => inner.HasActiveRecoveryPathAsync(realm, id, cancellationToken);

        public async ValueTask<CommitOutcome> CommitAsync(IdentityCommit commit, CancellationToken cancellationToken)
        {
            if (hook is { } run)
            {
                hook = null;
                await run();
            }

            var outcome = await inner.CommitAsync(commit, cancellationToken);
            Outcomes.Add(outcome);
            return outcome;
        }
    }
}
