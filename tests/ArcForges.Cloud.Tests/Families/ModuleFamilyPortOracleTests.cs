// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Tests.Entitlement;
using Xunit;

namespace ArcForges.Cloud.Tests.Families;

/// <summary>
/// The family port on the real family plan <c>families.account-enrollment.create-user</c>, executed by the production Worker plan code over
/// SQLite with every committed migration (the COM.16 bridge). It proves what the batch does: the records, the receipt, the outbox row and
/// the change record commit together; a false guard commits nothing; and the receipt answers a replay, a reused identifier, an expired
/// receipt and an outcome lost after the commit. SQLite is not D1 (the opt-in workerd run repeats the engine-dependent cases).
/// </summary>
public sealed class ModuleFamilyPortOracleTests : IDisposable
{
    private static readonly ModuleDescriptor Identity = ModuleDescriptor.Create("Identity", "identity");
    private static readonly DateTimeOffset Created = DateTimeOffset.FromUnixTimeMilliseconds(Enrollment.CreatedAt / 1000);

    private static readonly string[] Tables =
    [
        "identity_user", "identity_auth_identity", "workspace_workspace", "platform_command", "platform_outbox", "platform_outbox_position",
        "platform_change_archive", "platform_command_guard",
    ];

    /// <summary>One user, credential, workspace, receipt, outbox row, outbox position and change record, and no guard row left behind.</summary>
    private static readonly long[] OneEnrollment = [1, 1, 1, 1, 1, 1, 1, 0];

    private readonly SqliteBridgeExecutor bridge = new(recoveryGeneration: 1);
    private readonly FakeTime time = new(Created);

    public void Dispose() => bridge.Dispose();

    private IModuleFamilyPort Port(IPlanExecutor? executor = null) => new ModuleFamilyPortFactory(executor ?? bridge, 1, time).For(Identity);

    private async Task<long[]> CountsAsync()
    {
        var counts = new long[Tables.Length];
        for (var index = 0; index < Tables.Length; index++) counts[index] = await bridge.CountAsync(Tables[index], cancellationToken: T.Ct);
        return counts;
    }

    [Fact]
    public async Task AnEnrollmentCommitsTheRecordsTheReceiptTheOutboxAndTheChangeRecordTogetherAndReleasesItsGuards()
    {
        var enrollment = Enrollment.New();

        var outcome = await Port().ExecuteAsync(enrollment.Call(), T.Ct);

        Assert.Equal(ModulePlanStatus.Succeeded, outcome.Status);
        Assert.Equal(OneEnrollment, await CountsAsync());
        var user = Assert.Single(await bridge.QueryAsync("SELECT user_id, realm_id, display_name, rev FROM identity_user", T.Ct));
        Assert.Equal([enrollment.User.ToString("D"), enrollment.Realm.ToString("D"), "Ada", "1"], user);
        var workspace = Assert.Single(await bridge.QueryAsync("SELECT workspace_id, realm_id, owner_user_id, rev FROM workspace_workspace", T.Ct));
        Assert.Equal([enrollment.Workspace.ToString("D"), enrollment.Realm.ToString("D"), enrollment.User.ToString("D"), "1"], workspace);
        var receipt = Assert.Single(await bridge.QueryAsync("SELECT command_id, workspace_id, actor_ref, request_hash, status, result_payload FROM platform_command", T.Ct));
        Assert.Equal([enrollment.Command.ToString("D"), enrollment.Scope, "user:" + enrollment.User.ToString("D"), enrollment.RequestHash, "2", enrollment.ResultJson], receipt);
        var outbox = Assert.Single(await bridge.QueryAsync("SELECT o.outbox_id, p.stream_key FROM platform_outbox o JOIN platform_outbox_position p ON p.outbox_id = o.outbox_id", T.Ct));
        Assert.Equal([enrollment.Outbox.ToString("D"), enrollment.Scope], outbox);
    }

    [Fact]
    public async Task ASecondEnrollmentOfTheSameCredentialIsRefusedWholeAndCommitsNothing()
    {
        var first = Enrollment.New("shared-subject");
        Assert.Equal(ModulePlanStatus.Succeeded, (await Port().ExecuteAsync(first.Call(), T.Ct)).Status);
        var before = await CountsAsync();

        // Fresh user, credential and workspace identifiers under a new command: only the credential subject collides.
        var second = Enrollment.New("shared-subject");
        var outcome = await Port().ExecuteAsync(second.Call(), T.Ct);

        Assert.Equal(ModulePlanStatus.GuardRefused, outcome.Status);
        Assert.Null(outcome.StoredResultJson);
        Assert.Equal(before, await CountsAsync());
        Assert.Empty(await bridge.QueryAsync("SELECT user_id FROM identity_user WHERE user_id = '" + second.User.ToString("D") + "'", T.Ct));
    }

    [Fact]
    public async Task ACollidingIdentifierIsRefusedWholeNeverOverwritten()
    {
        var first = Enrollment.New("subject-a");
        Assert.Equal(ModulePlanStatus.Succeeded, (await Port().ExecuteAsync(first.Call(), T.Ct)).Status);
        var before = await CountsAsync();

        // A new enrollment whose random user identifier happens to equal an existing one: the revision-zero guard refuses the whole batch.
        var colliding = Enrollment.New("subject-b") with { User = first.User };
        Assert.Equal(ModulePlanStatus.GuardRefused, (await Port().ExecuteAsync(colliding.Call(), T.Ct)).Status);
        var collidingWorkspace = Enrollment.New("subject-c") with { Workspace = first.Workspace };
        Assert.Equal(ModulePlanStatus.GuardRefused, (await Port().ExecuteAsync(collidingWorkspace.Call(), T.Ct)).Status);

        Assert.Equal(before, await CountsAsync());
        Assert.Equal("Ada", (await bridge.QueryAsync("SELECT display_name FROM identity_user", T.Ct))[0][0]);
    }

    [Fact]
    public async Task TheSameSubjectInAnotherRealmIsAnotherCredential()
    {
        Assert.Equal(ModulePlanStatus.Succeeded, (await Port().ExecuteAsync(Enrollment.New("same").Call(), T.Ct)).Status);
        Assert.Equal(ModulePlanStatus.Succeeded, (await Port().ExecuteAsync(Enrollment.New("same", realm: Guid.NewGuid()).Call(), T.Ct)).Status);
        Assert.Equal(2, await bridge.CountAsync("identity_auth_identity", cancellationToken: T.Ct));
    }

    [Fact]
    public async Task AReplayOfTheSameCommandIsAnsweredFromItsReceiptAndExecutesNothing()
    {
        var enrollment = Enrollment.New();
        var call = enrollment.Call();
        Assert.Equal(ModulePlanStatus.Succeeded, (await Port().ExecuteAsync(call, T.Ct)).Status);
        var before = await CountsAsync();

        var replay = await Port().ExecuteAsync(call, T.Ct);

        Assert.Equal(ModulePlanStatus.Replayed, replay.Status);
        Assert.Equal(enrollment.ResultJson, replay.StoredResultJson);
        Assert.Equal(before, await CountsAsync());
    }

    [Fact]
    public async Task ACommandIdentifierReusedWithDifferentContentIsRefusedAndWritesNothing()
    {
        var enrollment = Enrollment.New();
        Assert.Equal(ModulePlanStatus.Succeeded, (await Port().ExecuteAsync(enrollment.Call(), T.Ct)).Status);
        var before = await CountsAsync();

        // The same command identifier for another enrollment: every guard holds, the receipt key refuses the batch, the receipt names the conflict.
        var reused = Enrollment.New("another-subject", command: enrollment.Command);
        var outcome = await Port().ExecuteAsync(reused.Call(), T.Ct);

        Assert.Equal(ModulePlanStatus.ReusedIdentifier, outcome.Status);
        Assert.Null(outcome.StoredResultJson);
        Assert.Equal(before, await CountsAsync());
    }

    [Fact]
    public async Task AnExpiredReceiptIsNeverExecutedAsANewCommand()
    {
        var enrollment = Enrollment.New();
        var call = enrollment.Call();
        Assert.Equal(ModulePlanStatus.Succeeded, (await Port().ExecuteAsync(call, T.Ct)).Status);
        var before = await CountsAsync();

        time.Advance(TimeSpan.FromDays(7));
        var outcome = await Port().ExecuteAsync(call, T.Ct);

        Assert.Equal(ModulePlanStatus.ReceiptExpired, outcome.Status);
        Assert.Null(outcome.StoredResultJson);
        Assert.Equal(before, await CountsAsync());
    }

    [Fact]
    public async Task AnOutcomeLostAfterTheCommitIsResolvedByTheCallsOwnReceipt()
    {
        var enrollment = Enrollment.New();
        var lost = new LosingExecutor(bridge, executeFirst: true);

        var outcome = await Port(lost).ExecuteAsync(enrollment.Call(), T.Ct);

        Assert.Equal(ModulePlanStatus.Succeeded, outcome.Status);
        Assert.Equal(enrollment.ResultJson, outcome.StoredResultJson);
        Assert.Equal(1, lost.Lost);
        Assert.Equal(OneEnrollment, await CountsAsync());
    }

    [Fact]
    public async Task AnUnknownOutcomeWithoutAReceiptIsUnknownAndOnlyTheSameCommandIsSentAgain()
    {
        var enrollment = Enrollment.New();
        var call = enrollment.Call();
        var lost = new LosingExecutor(bridge, executeFirst: false);

        Assert.Equal(ModulePlanStatus.UnknownOutcome, (await Port(lost).ExecuteAsync(call, T.Ct)).Status);
        Assert.Equal(0, await bridge.CountAsync("platform_command", cancellationToken: T.Ct));

        // The same call (same command, same identifiers) is the only safe resend; it commits exactly once.
        Assert.Equal(ModulePlanStatus.Succeeded, (await Port().ExecuteAsync(call, T.Ct)).Status);
        Assert.Equal(ModulePlanStatus.Replayed, (await Port().ExecuteAsync(call, T.Ct)).Status);
        Assert.Equal(OneEnrollment, await CountsAsync());
    }

    [Fact]
    public async Task ConcurrentEnrollmentsOfOneCredentialCommitOnce()
    {
        var enrollments = Enumerable.Range(0, 12).Select(_ => Enrollment.New("contended")).ToArray();

        var outcomes = await Task.WhenAll(enrollments.Select(enrollment => Port().ExecuteAsync(enrollment.Call(), T.Ct)));

        Assert.Equal(1, outcomes.Count(outcome => outcome.Status == ModulePlanStatus.Succeeded));
        Assert.All(outcomes.Where(outcome => outcome.Status != ModulePlanStatus.Succeeded), outcome => Assert.Equal(ModulePlanStatus.GuardRefused, outcome.Status));
        Assert.Equal(OneEnrollment, await CountsAsync());
    }

    [Fact]
    public async Task AStaleRecoveryGenerationCommitsNothing()
    {
        var enrollment = Enrollment.New();
        var outcome = await new ModuleFamilyPortFactory(bridge, 2, time).For(Identity).ExecuteAsync(enrollment.Call(), T.Ct);

        Assert.Equal(ModulePlanStatus.StaleGeneration, outcome.Status);
        Assert.Equal(new long[Tables.Length], await CountsAsync());
    }

    /// <summary>Loses the answer of the first family batch: after executing it (a lost response) or before sending it (a lost request).</summary>
    private sealed class LosingExecutor(IPlanExecutor inner, bool executeFirst) : IPlanExecutor
    {
        public int Lost { get; private set; }

        public async Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken)
        {
            if (Lost == 0 && call.Plan.Id == Enrollment.Plan)
            {
                Lost++;
                if (executeFirst) await inner.ExecuteAsync(call, cancellationToken);
                throw new PlanFailureException(PlanFailureKind.UnknownOutcome);
            }

            return await inner.ExecuteAsync(call, cancellationToken);
        }
    }
}
