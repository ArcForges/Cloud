// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Storage.Receipts;
using ArcForges.Cloud.Storage.SharedFamilies;
using ArcForges.Cloud.Tests.Receipts;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests.Families;

/// <summary>
/// The family-execution port (CLOUD.72) around the shared-family engine: who may contribute what (each refusal happens before anything is
/// sent), how the sealed call is built from the contributions and the commit tail, and how every executor and receipt outcome becomes a
/// typed status. The SQL itself runs in <see cref="ModuleFamilyPortOracleTests"/>.
/// </summary>
public sealed class ModuleFamilyPortTests
{
    private static readonly ModuleDescriptor Identity = ModuleDescriptor.Create("Identity", "identity");
    private static readonly ModuleDescriptor Workspace = ModuleDescriptor.Create("Workspace", "workspace");
    private static readonly ModuleDescriptor Devices = ModuleDescriptor.Create("Devices", "device");
    private static readonly ModuleDescriptor Entitlement = ModuleDescriptor.Create("Entitlement", "entitlement");

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    /// <summary>The instant of the fixture commits; their receipts expire seven days later.</summary>
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeMilliseconds(Enrollment.CreatedAt / 1000);

    private static (IModuleFamilyPortFactory Factory, ScriptedExecutor Storage) Create(ulong generation = 5, DateTimeOffset? now = null)
    {
        var storage = new ScriptedExecutor();
        return (new ModuleFamilyPortFactory(storage, generation, new FixedTime(now ?? Now)), storage);
    }

    private static List<FamilyStatement> Replace(List<FamilyStatement> statements, string key, Func<FamilyStatement, FamilyStatement> change)
    {
        var index = statements.FindIndex(statement => statement.Key == key);
        statements[index] = change(statements[index]);
        return statements;
    }

    [Theory]
    [InlineData("no-such-family", Enrollment.Plan)]
    [InlineData("Account-Enrollment", Enrollment.Plan)]
    [InlineData("account-enrollment", "families.account-enrollment.no-such-plan")]
    [InlineData("account-enrollment", "identity.credential-add")]
    [InlineData("account-enrollment", "families.other-family.create-user")]
    public async Task AnUnknownFamilyOrAPlanOfAnotherFamilyIsRefusedBeforeTheExecutor(string family, string plan)
    {
        var (factory, storage) = Create();
        var enrollment = Enrollment.New();

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await factory.For(Identity).ExecuteAsync(enrollment.Call(family: family, plan: plan), T.Ct));

        Assert.Empty(storage.Calls);
    }

    [Theory]
    [InlineData("Commerce", "commerce")]
    [InlineData("Support", "support")]
    [InlineData("TrustSafety", "trustsafety")]
    [InlineData("Audit", "audit")]
    [InlineData("Platform", "platform")]
    [InlineData("Foundation", "foundation")]
    public async Task ACallerThatIsNotAParticipantIsRefusedBeforeTheExecutor(string name, string schema)
    {
        var (factory, storage) = Create();
        var enrollment = Enrollment.New();

        var refused = await Assert.ThrowsAsync<InvalidOperationException>(async () => await factory.For(ModuleDescriptor.Create(name, schema)).ExecuteAsync(enrollment.Call(), T.Ct));

        Assert.Contains("not a participant", refused.Message, StringComparison.Ordinal);
        Assert.Empty(storage.Calls);
    }

    [Fact]
    public async Task AStatementOfAnotherModuleIsRefusedForEveryCallerOtherThanTheOneReviewedException()
    {
        var (factory, storage) = Create();
        var enrollment = Enrollment.New();

        // Workspace is a participant, but the identity statements are not its own (the exception names the other direction only).
        var workspaceCaller = await Assert.ThrowsAsync<InvalidOperationException>(async () => await factory.For(Workspace).ExecuteAsync(enrollment.Call(), T.Ct));
        Assert.Contains("may not contribute the identity.", workspaceCaller.Message, StringComparison.Ordinal);

        // Device and Entitlement are conditional participants: neither may contribute an identity or workspace statement.
        var workspaceOnly = enrollment.Statements().Where(statement => statement.Module == "workspace").ToList();
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await factory.For(Devices).ExecuteAsync(enrollment.Call(workspaceOnly), T.Ct));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await factory.For(Entitlement).ExecuteAsync(enrollment.Call(), T.Ct));

        // Identity may contribute its own statements and the workspace statements of this family, but no statement of another module.
        var withDevice = enrollment.Statements();
        withDevice.Add(new FamilyStatement("device", FamilyStatementClass.Record, "installation", [Enrollment.T("x")]));
        var identityCaller = await Assert.ThrowsAsync<InvalidOperationException>(async () => await factory.For(Identity).ExecuteAsync(enrollment.Call(withDevice), T.Ct));
        Assert.Contains("may not contribute the device.installation", identityCaller.Message, StringComparison.Ordinal);

        Assert.Empty(storage.Calls);
    }

    [Theory]
    [InlineData("platform", "a-receipt")]
    [InlineData("platform", "release")]
    [InlineData("platform", "job-lease")]
    public async Task APlatformStatementIsNeverContributedByAModule(string module, string key)
    {
        var (factory, storage) = Create();
        var enrollment = Enrollment.New();
        var statements = enrollment.Statements();
        statements.Add(new FamilyStatement(module, FamilyStatementClass.Record, key, [Enrollment.T(enrollment.Command)]));

        var refused = await Assert.ThrowsAsync<InvalidOperationException>(async () => await factory.For(Identity).ExecuteAsync(enrollment.Call(statements), T.Ct));

        Assert.Contains("platform statement", refused.Message, StringComparison.Ordinal);
        Assert.Empty(storage.Calls);
    }

    [Theory]
    [InlineData("Identity")]
    [InlineData("identity ")]
    [InlineData("")]
    [InlineData("support")]
    [InlineData("identity_user")]
    public async Task AStatementOwnerOutsideTheLockOrderIsRefused(string module)
    {
        var (factory, storage) = Create();
        var enrollment = Enrollment.New();
        var statements = Replace(enrollment.Statements(), "user", statement => statement with { Module = module });

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await factory.For(Identity).ExecuteAsync(enrollment.Call(statements), T.Ct));

        Assert.Empty(storage.Calls);
    }

    [Fact]
    public void TheReviewedExceptionIsOneRowForIdentityContributingWorkspaceInAccountEnrollmentOnly()
    {
        var row = Assert.Single(FamilyContributionPolicy.Exceptions);
        Assert.Equal(("account-enrollment", FamilyModule.Identity, FamilyModule.Workspace), (row.Family, row.Caller, row.Statement));
        Assert.True(FamilyContributionPolicy.MayContribute("account-enrollment", FamilyModule.Identity, FamilyModule.Workspace));
        Assert.True(FamilyContributionPolicy.MayContribute("account-enrollment", FamilyModule.Identity, FamilyModule.Identity));
        Assert.True(FamilyContributionPolicy.MayContribute("account-enrollment", FamilyModule.Workspace, FamilyModule.Workspace));
        Assert.False(FamilyContributionPolicy.MayContribute("account-enrollment", FamilyModule.Workspace, FamilyModule.Identity));
        Assert.False(FamilyContributionPolicy.MayContribute("account-enrollment", FamilyModule.Device, FamilyModule.Workspace));
        Assert.False(FamilyContributionPolicy.MayContribute("account-enrollment", FamilyModule.Identity, FamilyModule.Device));
        Assert.False(FamilyContributionPolicy.MayContribute("account-enrollment", FamilyModule.Identity, FamilyModule.Platform));
        Assert.False(FamilyContributionPolicy.MayContribute("account-enrollment", FamilyModule.Platform, FamilyModule.Platform));
        Assert.False(FamilyContributionPolicy.MayContribute("other-family", FamilyModule.Identity, FamilyModule.Workspace));
        Assert.False(FamilyContributionPolicy.MayContribute("Account-Enrollment", FamilyModule.Identity, FamilyModule.Workspace));
    }

    [Fact]
    public async Task TheExceptionDoesNotHoldInAnotherFamilyWithTheSameParticipantsAndShape()
    {
        var storage = new ScriptedExecutor { Handler = _ => ScriptedExecutor.Changed() };
        var (catalog, plans) = FamilyPortCatalog.OtherFamily();
        var factory = new ModuleFamilyPortFactory(storage, 5, new FixedTime(Now), catalog, plans);
        var enrollment = Enrollment.New();

        var refused = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
            await factory.For(Identity).ExecuteAsync(enrollment.Call(family: "other-family", plan: "families.other-family.create-user"), T.Ct));
        Assert.Contains("may not contribute the workspace.", refused.Message, StringComparison.Ordinal);
        Assert.Empty(storage.Calls);

        // The same call in account-enrollment, through the same factory, passes the policy and is sent once.
        Assert.Equal(ModulePlanStatus.Succeeded, (await factory.For(Identity).ExecuteAsync(enrollment.Call(), T.Ct)).Status);
        Assert.Equal([Enrollment.Plan], storage.PlanIds);
    }

    [Fact]
    public async Task ADuplicatedMissingUnknownOrMisclassifiedStatementIsRefused()
    {
        var (factory, storage) = Create();
        var enrollment = Enrollment.New();
        var port = factory.For(Identity);

        var duplicated = enrollment.Statements();
        duplicated.Add(duplicated[0]);
        var missing = enrollment.Statements().Where(statement => statement.Key != "owner").ToList();
        var unknown = Replace(enrollment.Statements(), "user", statement => statement with { Key = "user-x" });
        var misclassified = Replace(enrollment.Statements(), "credential-id", statement => statement with { Class = FamilyStatementClass.Authorization });
        var undefined = Replace(enrollment.Statements(), "credential-id", statement => statement with { Class = (FamilyStatementClass)99 });

        Assert.Contains("DuplicateContribution", (await Assert.ThrowsAsync<InvalidOperationException>(async () => await port.ExecuteAsync(enrollment.Call(duplicated), T.Ct))).Message, StringComparison.Ordinal);
        Assert.Contains("MissingContribution", (await Assert.ThrowsAsync<InvalidOperationException>(async () => await port.ExecuteAsync(enrollment.Call(missing), T.Ct))).Message, StringComparison.Ordinal);
        Assert.Contains("NotInPlan", (await Assert.ThrowsAsync<InvalidOperationException>(async () => await port.ExecuteAsync(enrollment.Call(unknown), T.Ct))).Message, StringComparison.Ordinal);
        Assert.Contains("NotInPlan", (await Assert.ThrowsAsync<InvalidOperationException>(async () => await port.ExecuteAsync(enrollment.Call(misclassified), T.Ct))).Message, StringComparison.Ordinal);
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await port.ExecuteAsync(enrollment.Call(undefined), T.Ct));

        Assert.Empty(storage.Calls);
    }

    [Fact]
    public async Task ArgumentsOfTheWrongKindCountOrScopeAreRejectedWithoutReachingTheExecutor()
    {
        var (factory, storage) = Create();
        var enrollment = Enrollment.New();
        var port = factory.For(Identity);

        var kind = Replace(enrollment.Statements(), "credential-id", statement => statement with { Arguments = [Enrollment.I(1), Enrollment.I(0)] });
        var count = Replace(enrollment.Statements(), "user", statement => statement with { Arguments = [Enrollment.T(enrollment.Realm), Enrollment.I(0)] });
        // The workspace guard and record bind the owner scope: a workspace other than the scope of the call is refused.
        var scope = Replace(enrollment.Statements(), "workspace", statement => statement.Class == FamilyStatementClass.Revision
            ? statement with { Arguments = [Enrollment.T(Guid.NewGuid()), Enrollment.I(0)] }
            : statement);
        var nullKey = Replace(enrollment.Statements(), "account", statement => statement with { Arguments = [PlanValue.Null, Enrollment.T(enrollment.Realm), Enrollment.T("Ada"), Enrollment.I(1)] });

        foreach (var statements in new[] { kind, count, scope, nullKey })
            Assert.Equal(ModulePlanStatus.Rejected, (await port.ExecuteAsync(enrollment.Call(statements), T.Ct)).Status);

        Assert.Empty(storage.Calls);
    }

    [Fact]
    public async Task ACommitThatDoesNotFitThePlanOrIsMalformedIsRefusedBeforeTheExecutor()
    {
        var (factory, storage) = Create();
        var enrollment = Enrollment.New();
        var port = factory.For(Identity);

        // The plan carries exactly one outbox event: a commit of none or two cannot be bound onto its platform statements.
        Assert.Contains("do not fit", (await Assert.ThrowsAsync<InvalidOperationException>(async () => await port.ExecuteAsync(enrollment.Call(commit: enrollment.Commit(events: 0)), T.Ct))).Message, StringComparison.Ordinal);
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await port.ExecuteAsync(enrollment.Call(commit: enrollment.Commit(events: 2)), T.Ct));

        // A malformed commit is refused by the commit-tail types, exactly as through the module plan port.
        await Assert.ThrowsAsync<ArgumentException>(async () => await port.ExecuteAsync(enrollment.Call(commit: enrollment.Commit() with { CommandId = Guid.Empty }), T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(async () => await port.ExecuteAsync(enrollment.Call(commit: enrollment.Commit() with { ResultPayloadJson = "{" }), T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(async () => await port.ExecuteAsync(enrollment.Call(commit: enrollment.Commit() with { ChangeRecordJson = "[]" }), T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(async () => await port.ExecuteAsync(enrollment.Call(commit: enrollment.Commit() with { ExpiresAtMicros = Enrollment.CreatedAt }), T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(async () => await port.ExecuteAsync(enrollment.Call(scope: "platform:change-archive"), T.Ct));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await port.ExecuteAsync(enrollment.Call() with { Commit = null! }, T.Ct));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await port.ExecuteAsync(null!, T.Ct));

        Assert.Empty(storage.Calls);
    }

    [Fact]
    public async Task TheSealedCallIsTheEnginesUnitOfWorkWithTheCommandInFrontOfEveryGuardAndTheTailInPlanOrder()
    {
        var (factory, storage) = Create(generation: 9);
        storage.Handler = _ => ScriptedExecutor.Changed(9);
        var enrollment = Enrollment.New();

        var outcome = await factory.For(Identity).ExecuteAsync(enrollment.Call(), T.Ct);

        Assert.Equal(ModulePlanStatus.Succeeded, outcome.Status);
        var call = Assert.Single(storage.Calls);
        Assert.Equal(Enrollment.Plan, call.Plan.Id);
        Assert.Equal(enrollment.Scope, call.OwnerScope);
        Assert.Equal(9UL, call.RecoveryGeneration);

        // The expected arguments: the same contributions and commit tail assembled directly on the engine.
        var family = FamilyPortCatalog.EnrollmentPlan;
        var unit = FamilyUnitOfWork.Begin(family, enrollment.Command, enrollment.Scope, 9, PlanManifest.FamilyCatalog.Single(entry => entry.Id == Enrollment.Family));
        foreach (var statement in enrollment.Statements())
        {
            unit.Contribute(new FamilyContribution(
                statement.Module == "identity" ? FamilyModule.Identity : FamilyModule.Workspace,
                Enum.Parse<FamilyClass>(statement.Class.ToString()),
                statement.Key,
                [.. statement.Arguments.Select(Scalar)]));
        }

        var commit = enrollment.Commit();
        var receipt = new CommandReceipt(new CommandIdentity(commit.CommandId, commit.WorkspaceId, commit.ActorRef, commit.Operation, commit.RequestHash), commit.ResultPayloadJson, commit.ResultRevision, commit.CreatedAtMicros, commit.ExpiresAtMicros);
        var events = commit.Events.Select(e => new ArcForges.Cloud.Storage.Outbox.OutboxEvent(e.OutboxId, e.AggregateKind, e.AggregateId, e.AggregateRevision, e.EventType, e.PayloadJson, e.WorkspaceId, e.CorrelationId, e.CausationId)).ToList();
        var tail = CommitTail.Arguments(enrollment.Scope, new CommitTailValues(receipt, events, new ArcForges.Cloud.Storage.Archive.ChangeRecord(commit.ChangeSchemaVersion, commit.ChangeRecordJson)));
        string[] keys = ["a-receipt", "b-stream", "c-outbox", "d-position", "e-archive-stream", "f-archive"];
        for (var index = 0; index < keys.Length; index++) unit.For(FamilyModule.Platform).Mutation(FamilyClass.Record, keys[index], tail[index]);
        var expected = unit.Seal().Arguments;

        Assert.Equal(Render(expected), Render(call.Arguments));
        var command = "text:" + enrollment.Command.ToString("D");
        for (var index = 0; index < family.Roles.Count; index++)
        {
            if (family.Roles[index].Phase != FamilyPhase.Mutation) Assert.Equal(command, FamilyFixtureRender(call.Arguments[index][0]));
        }
    }

    /// <summary>Every executor failure and receipt answer, and the typed status the port returns. Exactly one batch is sent in every case.</summary>
    public static TheoryData<string, string?, string?, ModulePlanStatus, bool> Outcomes => new()
    {
        { "committed", null, null, ModulePlanStatus.Succeeded, false },
        { "stale guard, no receipt", "Precondition", "none", ModulePlanStatus.GuardRefused, false },
        { "constraint, no receipt", "Constraint", "none", ModulePlanStatus.ConstraintRefused, false },
        { "stale guard, same command committed", "Precondition", "same", ModulePlanStatus.Replayed, true },
        { "constraint, same command committed", "Constraint", "same", ModulePlanStatus.Replayed, true },
        { "stale guard, same command failed", "Precondition", "failed", ModulePlanStatus.ReplayedFailure, false },
        { "constraint, identifier reused", "Constraint", "other-hash", ModulePlanStatus.ReusedIdentifier, false },
        { "constraint, identifier reused by another actor", "Constraint", "other-actor", ModulePlanStatus.ReusedIdentifier, false },
        { "stale guard, receipt expired", "Precondition", "expired", ModulePlanStatus.ReceiptExpired, false },
        { "stale guard, receipt in progress", "Precondition", "in-progress", ModulePlanStatus.UnknownOutcome, false },
        { "stale guard, receipt unreadable", "Precondition", "unavailable", ModulePlanStatus.Unavailable, false },
        { "unknown, no receipt", "UnknownOutcome", "none", ModulePlanStatus.UnknownOutcome, false },
        { "unknown, own receipt", "UnknownOutcome", "same", ModulePlanStatus.Succeeded, true },
        { "unknown, identifier reused", "UnknownOutcome", "other-hash", ModulePlanStatus.ReusedIdentifier, false },
        { "unknown, receipt expired", "UnknownOutcome", "expired", ModulePlanStatus.ReceiptExpired, false },
        { "unknown, receipt unreadable", "UnknownOutcome", "unavailable", ModulePlanStatus.UnknownOutcome, false },
        { "unknown, receipt malformed", "UnknownOutcome", "malformed", ModulePlanStatus.UnknownOutcome, false },
        { "stale generation", "StaleGeneration", null, ModulePlanStatus.StaleGeneration, false },
        { "overloaded", "Overloaded", null, ModulePlanStatus.Unavailable, false },
        { "unavailable", "Unavailable", null, ModulePlanStatus.Unavailable, false },
        { "signature refused", "Transport", null, ModulePlanStatus.Unavailable, false },
        { "invalid plan", "InvalidPlan", null, ModulePlanStatus.Rejected, false },
        { "manifest skew", "ManifestMismatch", null, ModulePlanStatus.Rejected, false },
    };

    [Theory]
    [MemberData(nameof(Outcomes))]
    public async Task EveryExecutorAndReceiptOutcomeBecomesATypedStatusAndNothingIsRetried(string name, string? failure, string? receipt, ModulePlanStatus expected, bool stored)
    {
        Assert.NotEmpty(name);
        var (factory, storage) = Create();
        var enrollment = Enrollment.New();
        var commit = enrollment.Commit();
        storage.Handler = call =>
        {
            if (call.Plan.Id == Enrollment.Plan) return failure is { } kind ? throw ScriptedExecutor.Fail(Enum.Parse<PlanFailureKind>(kind)) : ScriptedExecutor.Changed(9);
            Assert.Equal("platform.command-load", call.Plan.Id);
            Assert.Equal(enrollment.Command.ToString("D"), ScriptedExecutor.Text(call.Arguments[0][0]));
            return receipt switch
            {
                "none" => ScriptedExecutor.Rows(),
                "same" => Receipt(commit, status: 2),
                "failed" => Receipt(commit, status: 3),
                "in-progress" => Receipt(commit, status: 1),
                "other-hash" => Receipt(commit with { RequestHash = "another-hash" }, status: 2),
                "other-actor" => Receipt(commit with { ActorRef = "user:" + Guid.NewGuid().ToString("D") }, status: 2),
                "expired" => Receipt(commit with { ExpiresAtMicros = Enrollment.CreatedAt - 1 }, status: 2),
                "unavailable" => throw ScriptedExecutor.Fail(PlanFailureKind.Unavailable),
                "malformed" => ScriptedExecutor.Rows([D1Values.Text("h"), D1Values.Int64(9), D1Values.Null(), D1Values.Null(), D1Values.Null(), D1Values.Int64(1), D1Values.Text("a"), D1Values.Text("o"), D1Values.Null()]),
                _ => throw new InvalidOperationException("Unscripted receipt."),
            };
        };

        var outcome = await factory.For(Identity).ExecuteAsync(enrollment.Call(commit: commit), T.Ct);

        Assert.Equal(expected, outcome.Status);
        Assert.Empty(outcome.Rows);
        Assert.Equal(stored ? commit.ResultPayloadJson : null, outcome.StoredResultJson);
        Assert.Equal(1, storage.PlanIds.Count(id => id == Enrollment.Plan));
        Assert.Equal(receipt is null ? 0 : 1, storage.PlanIds.Count(id => id == "platform.command-load"));
    }

    [Fact]
    public async Task ACancelledCallerDoesNotTurnIntoAStatus()
    {
        var (factory, storage) = Create();
        storage.Handler = _ => throw new OperationCanceledException();
        var enrollment = Enrollment.New();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await factory.For(Identity).ExecuteAsync(enrollment.Call(), T.Ct));
        Assert.Single(storage.Calls);
    }

    private static PlanResult Receipt(ModuleCommit commit, long status) => ScriptedExecutor.Rows(
    [
        D1Values.Text(commit.RequestHash),
        D1Values.Int64(status),
        status == 2 ? D1Values.Text(commit.ResultPayloadJson) : D1Values.Null(),
        ScriptedExecutor.OptInt(commit.ResultRevision),
        status == 3 ? D1Values.Text("identity.refused") : D1Values.Null(),
        D1Values.Int64(commit.ExpiresAtMicros),
        D1Values.Text(commit.ActorRef),
        D1Values.Text(commit.Operation),
        ScriptedExecutor.Opt(commit.WorkspaceId?.ToString("D")),
    ]);

    private static D1Scalar Scalar(PlanValue value) => value.Kind switch
    {
        PlanValueKind.Null => D1Values.Null(),
        PlanValueKind.Int64 => D1Values.Int64(value.AsInt64()),
        PlanValueKind.Text => D1Values.Text(value.AsText()),
        PlanValueKind.Bytes => D1Values.Bytes(value.AsBytes()),
        _ => D1Values.Bool(value.AsBool()),
    };

    private static string FamilyFixtureRender(D1Scalar scalar) => ArcForges.Cloud.Tests.SharedFamilies.FamilyFixture.Render(scalar);

    private static string[][] Render(D1Scalar[][] arguments) => [.. arguments.Select(statement => statement.Select(FamilyFixtureRender).ToArray())];
}
