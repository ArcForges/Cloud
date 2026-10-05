// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.Receipts;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;
using static ArcForges.Cloud.Tests.Receipts.Samples;
using static ArcForges.Cloud.Tests.Receipts.ScriptedExecutor;

namespace ArcForges.Cloud.Tests.Receipts;

/// <summary>
/// What the host does with the answers of a guarded write: every non-success is reconciled with the receipt (or the inbox), which is the only
/// proof of a commit (D1 profile section 4). The SQL that produces these answers is proved by tests/worker/d1-receipts.test.ts.
/// </summary>
public sealed class CommitExecutorTests
{
    private const string Scope = "workspace:fixture-a";

    private static readonly PlanDefinition WritePlan = new(
        "entitlement.fixture-store",
        1,
        PlanAccess.Write,
        0,
        [new([new PlanParam(PlanKind.Text), new PlanParam(PlanKind.Scope)], null), new([new PlanParam(PlanKind.Scope), new PlanParam(PlanKind.Text)], null), .. CommitTail.Kinds(1, false).Select(k => new PlanStatement([.. k.Params], null)), new PlanStatement([.. CommitTail.ReleaseKinds.Params], null)]);

    private static (CommitExecutor Executor, ScriptedExecutor Storage, CommitTailValues Values, PlanCall Call) Arrange(bool inbox = false)
    {
        var storage = new ScriptedExecutor();
        var time = new FixedTime();
        var values = new CommitTailValues(Receipt(), [Event(1)], Change(), inbox ? new InboxKey("consumer", "evt", 0) : null, inbox ? NowMicros + InboxRetention.MinimumMicros : 0);
        var plan = inbox ? WithInbox() : WritePlan;
        var owner = new D1Scalar[][] { [D1Values.Text(values.Receipt.Identity.CommandId.ToString("D")), D1Values.Text(Scope)], [D1Values.Text(Scope), D1Values.Text("x")] };
        var call = PlanCall.New(plan, Scope, 0, CommitTail.Bind(plan, Scope, owner, values));
        var executor = new CommitExecutor(storage, new CommandReceiptStore(storage, 0, time), new InboxStore(storage, 0));
        return (executor, storage, values, call);
    }

    private static PlanDefinition WithInbox() =>
        new("entitlement.fixture-consume", 1, PlanAccess.Write, 0,
            [new([new PlanParam(PlanKind.Text), new PlanParam(PlanKind.Scope)], null), new([new PlanParam(PlanKind.Scope), new PlanParam(PlanKind.Text)], null), .. CommitTail.Kinds(1, true).Select(k => new PlanStatement([.. k.Params], null)), new PlanStatement([.. CommitTail.ReleaseKinds.Params], null)]);

    private sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    /// <summary>A stored receipt row as platform.command-load returns it.</summary>
    private static D1Scalar[] ReceiptRow(CommitTailValues values, int status = 2, string? hash = null, long? expires = null, string actor = "actor-1", string operation = "fixture.store", Guid? workspace = null) =>
        [
            D1Values.Text(hash ?? values.Receipt.Identity.RequestHash),
            D1Values.Int64(status),
            status == 3 ? D1Values.Null() : D1Values.Text(values.Receipt.ResultPayloadJson),
            status == 3 ? D1Values.Null() : D1Values.Int64(values.Receipt.ResultRevision!.Value),
            status == 3 ? D1Values.Text("validation.invalid_request") : D1Values.Null(),
            D1Values.Int64(expires ?? values.Receipt.ExpiresAtMicros),
            D1Values.Text(actor),
            D1Values.Text(operation),
            workspace is { } w ? D1Values.Text(w.ToString("D")) : D1Values.Null(),
        ];

    private static PlanResult WriteThrows(PlanCall call, PlanFailureKind kind) => call.Plan.Access == PlanAccess.Write ? throw Fail(kind) : throw new InvalidOperationException();

    [Fact]
    public async Task ASuccessfulBatchIsCommittedAndReadsNothingBack()
    {
        var (executor, storage, values, call) = Arrange();
        storage.Handler = _ => Changed(12);
        var outcome = await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken);
        Assert.Equal(CommitKind.Committed, outcome.Kind);
        Assert.Equal(["entitlement.fixture-store"], storage.PlanIds);
    }

    [Fact]
    public async Task AFailedGuardWithoutAReceiptIsADefiniteRollbackTheCallerRecalculatesUnderTheSameCommandId()
    {
        var (executor, storage, values, call) = Arrange();
        storage.Handler = c => c.Plan.Id == "platform.command-load" ? Rows() : WriteThrows(c, PlanFailureKind.Precondition);
        var outcome = await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken);
        Assert.Equal(CommitKind.GuardFailed, outcome.Kind);
        Assert.Equal(["entitlement.fixture-store", "platform.command-load"], storage.PlanIds);
        // The receipt was read by the command id of the batch, and nothing was written but the batch.
        Assert.Equal(values.Receipt.Identity.CommandId.ToString("D"), Text(storage.Calls[1].Arguments[0][0]));
    }

    [Fact]
    public async Task AGuardThatFailsBecauseTheSameCommandAlreadyCommittedReturnsItsOriginalResult()
    {
        var (executor, storage, values, call) = Arrange();
        storage.Handler = c => c.Plan.Id == "platform.command-load" ? Rows(ReceiptRow(values)) : WriteThrows(c, PlanFailureKind.Precondition);
        var outcome = await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken);
        Assert.Equal(CommitKind.Replayed, outcome.Kind);
        Assert.Equal("{\"ok\":true}", outcome.Stored!.ResultPayloadJson);
        Assert.Equal(3, outcome.Stored.ResultRevision);
    }

    [Fact]
    public async Task ADuplicateReceiptKeyIsAReplayOrAReusedIdentifierNeverASecondExecution()
    {
        var (executor, storage, values, call) = Arrange();
        storage.Handler = c => c.Plan.Id == "platform.command-load" ? Rows(ReceiptRow(values)) : WriteThrows(c, PlanFailureKind.Constraint);
        Assert.Equal(CommitKind.Replayed, (await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken)).Kind);

        storage.Handler = c => c.Plan.Id == "platform.command-load" ? Rows(ReceiptRow(values, hash: "another-request")) : WriteThrows(c, PlanFailureKind.Constraint);
        var reused = await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken);
        Assert.Equal(CommitKind.ReusedIdentifier, reused.Kind);
        Assert.Null(reused.Stored);

        // The id of the same request presented by another actor, operation or workspace is also reused and reveals nothing.
        foreach (var row in new[] { ReceiptRow(values, actor: "someone-else"), ReceiptRow(values, operation: "other.operation"), ReceiptRow(values, workspace: Id(5)) })
        {
            storage.Handler = c => c.Plan.Id == "platform.command-load" ? Rows(row) : WriteThrows(c, PlanFailureKind.Constraint);
            var outcome = await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken);
            Assert.Equal(CommitKind.ReusedIdentifier, outcome.Kind);
            Assert.Null(outcome.Stored);
        }
    }

    [Fact]
    public async Task ARefusalThatWasRecordedIsReplayedAndAnExpiredReceiptIsNeverExecutedAgain()
    {
        var (executor, storage, values, call) = Arrange();
        storage.Handler = c => c.Plan.Id == "platform.command-load" ? Rows(ReceiptRow(values, status: 3)) : WriteThrows(c, PlanFailureKind.Constraint);
        var failure = await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken);
        Assert.Equal(CommitKind.ReplayedFailure, failure.Kind);
        Assert.Equal("validation.invalid_request", failure.Stored!.ErrorCode);

        storage.Handler = c => c.Plan.Id == "platform.command-load" ? Rows(ReceiptRow(values, expires: NowMicros)) : WriteThrows(c, PlanFailureKind.Constraint);
        Assert.Equal(CommitKind.ReceiptExpired, (await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken)).Kind);
        storage.Handler = c => c.Plan.Id == "platform.command-load" ? Rows(ReceiptRow(values, expires: NowMicros + 1)) : WriteThrows(c, PlanFailureKind.Constraint);
        Assert.Equal(CommitKind.Replayed, (await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken)).Kind);
    }

    [Fact]
    public async Task ARedeliveredInboxMessageIsADuplicateAndAConstraintWithNoCauseIsNotHidden()
    {
        var (executor, storage, values, call) = Arrange(inbox: true);
        // The inbox row is shaped as the plan returns it: int64 outcome and processed_at.
        storage.Handler = c => c.Plan.Id switch
        {
            "platform.command-load" => Rows(),
            "platform.inbox-load" => Rows([D1Values.Int64(1), D1Values.Int64(1000)]),
            _ => WriteThrows(c, PlanFailureKind.Constraint),
        };
        var duplicate = await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken);
        Assert.Equal(CommitKind.DuplicateMessage, duplicate.Kind);
        Assert.Equal("consumer", Text(storage.Calls.Single(c => c.Plan.Id == "platform.inbox-load").Arguments[0][0]));
        Assert.Equal("evt@0", Text(storage.Calls.Single(c => c.Plan.Id == "platform.inbox-load").Arguments[0][1]));

        storage.Calls.Clear();
        storage.Handler = c => c.Plan.Id is "platform.command-load" or "platform.inbox-load" ? Rows() : WriteThrows(c, PlanFailureKind.Constraint);
        var failure = await Assert.ThrowsAsync<PlanFailureException>(() => executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken));
        Assert.Equal(PlanFailureKind.Constraint, failure.Kind);
    }

    [Fact]
    public async Task AnUnknownOutcomeIsResolvedByTheReceiptAndOtherwiseOnlyTheSameCommandIdMayBeSentAgain()
    {
        var (executor, storage, values, call) = Arrange();
        storage.Handler = c => c.Plan.Id == "platform.command-load" ? Rows(ReceiptRow(values)) : WriteThrows(c, PlanFailureKind.UnknownOutcome);
        var committed = await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken);
        Assert.Equal(CommitKind.Committed, committed.Kind);
        Assert.Equal(3, committed.Stored!.ResultRevision);

        storage.Handler = c => c.Plan.Id == "platform.command-load" ? Rows() : WriteThrows(c, PlanFailureKind.UnknownOutcome);
        var unknown = await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken);
        Assert.Equal(CommitKind.Unknown, unknown.Kind);

        storage.Handler = c => c.Plan.Id == "platform.command-load" ? Rows(ReceiptRow(values, hash: "different")) : WriteThrows(c, PlanFailureKind.UnknownOutcome);
        Assert.Equal(CommitKind.ReusedIdentifier, (await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken)).Kind);

        // A receipt that is still in progress is not a result either.
        storage.Handler = c => c.Plan.Id == "platform.command-load" ? Rows(ReceiptRow(values, status: 1)) : WriteThrows(c, PlanFailureKind.UnknownOutcome);
        Assert.Equal(CommitKind.Unknown, (await executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken)).Kind);
    }

    [Theory]
    [InlineData("Overloaded")]
    [InlineData("Unavailable")]
    [InlineData("StaleGeneration")]
    [InlineData("InvalidPlan")]
    [InlineData("ManifestMismatch")]
    [InlineData("Transport")]
    public async Task EveryOtherFailureCommittedNothingAndPropagatesWithoutAReceiptRead(string kindName)
    {
        var kind = Enum.Parse<PlanFailureKind>(kindName);
        var (executor, storage, values, call) = Arrange();
        storage.Handler = c => WriteThrows(c, kind);
        var failure = await Assert.ThrowsAsync<PlanFailureException>(() => executor.ExecuteAsync(call, values, TestContext.Current.CancellationToken));
        Assert.Equal(kind, failure.Kind);
        Assert.Equal(["entitlement.fixture-store"], storage.PlanIds);
    }
}
