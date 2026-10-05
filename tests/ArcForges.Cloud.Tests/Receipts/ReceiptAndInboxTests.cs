// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.Receipts;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;
using static ArcForges.Cloud.Tests.Receipts.Samples;
using static ArcForges.Cloud.Tests.Receipts.ScriptedExecutor;

namespace ArcForges.Cloud.Tests.Receipts;

public sealed class ReceiptAndInboxTests
{
    private sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static StoredCommand Stored(CommandReceiptStatus status = CommandReceiptStatus.Succeeded, long? expires = null, Guid? workspace = null, string hash = "hash-1", string actor = "actor-1", string operation = "fixture.store") =>
        new(Id(1), workspace, actor, operation, hash, status, status == CommandReceiptStatus.Failed ? null : "{}", 1, status == CommandReceiptStatus.Failed ? "x.y" : null, expires ?? NowMicros + 1000);

    [Fact]
    public void ReplayClassificationFollowsTheReceiptRulesInOrder()
    {
        var request = Identity();
        Assert.Equal(ReplayKind.NotSeen, CommandReplay.Classify(null, request, NowMicros).Kind);
        Assert.Equal(ReplayKind.Replay, CommandReplay.Classify(Stored(), request, NowMicros).Kind);
        Assert.Equal(ReplayKind.ReplayOfFailure, CommandReplay.Classify(Stored(CommandReceiptStatus.Failed), request, NowMicros).Kind);
        Assert.Equal(ReplayKind.InProgress, CommandReplay.Classify(Stored(CommandReceiptStatus.InProgress), request, NowMicros).Kind);
        // The replay window ends at expires_at, inclusive of the instant itself, and an expired id is never treated as new.
        Assert.Equal(ReplayKind.Replay, CommandReplay.Classify(Stored(expires: NowMicros + 1), request, NowMicros).Kind);
        Assert.Equal(ReplayKind.Expired, CommandReplay.Classify(Stored(expires: NowMicros), request, NowMicros).Kind);
        Assert.Equal(ReplayKind.Expired, CommandReplay.Classify(Stored(expires: NowMicros - 1), request, NowMicros).Kind);
        // Content, actor, operation and workspace each make the id reused, before the window is considered, and the stored result is not returned.
        foreach (var other in new[] { Stored(hash: "different"), Stored(actor: "someone-else"), Stored(operation: "other"), Stored(workspace: Id(8)) })
        {
            var decision = CommandReplay.Classify(other, request, NowMicros);
            Assert.Equal(ReplayKind.ReusedIdentifier, decision.Kind);
            Assert.Null(decision.Stored);
        }

        Assert.Equal(ReplayKind.ReusedIdentifier, CommandReplay.Classify(Stored(hash: "different", expires: NowMicros - 5), request, NowMicros).Kind);
        Assert.Equal(ReplayKind.Replay, CommandReplay.Classify(Stored(workspace: Id(8)), Identity(workspace: Id(8)), NowMicros).Kind);
    }

    [Fact]
    public async Task TheStoreReadsAReceiptRowIntoItsTypedForm()
    {
        var storage = new ScriptedExecutor();
        var workspace = Id(9);
        storage.Handler = _ => Rows(
        [
            D1Values.Text("hash-1"), D1Values.Int64(2), D1Values.Text("{\"a\":1}"), D1Values.Int64(7), D1Values.Null(), D1Values.Int64(NowMicros + 5), D1Values.Text("actor-1"), D1Values.Text("fixture.store"), D1Values.Text(workspace.ToString("D")),
        ]);
        var store = new CommandReceiptStore(storage, 3, new FixedTime());
        var stored = await store.LoadAsync(Id(1), TestContext.Current.CancellationToken);
        Assert.Equal(new StoredCommand(Id(1), workspace, "actor-1", "fixture.store", "hash-1", CommandReceiptStatus.Succeeded, "{\"a\":1}", 7, null, NowMicros + 5), stored);
        var call = Assert.Single(storage.Calls);
        Assert.Equal("platform.command-load", call.Plan.Id);
        Assert.Equal(3UL, call.RecoveryGeneration);
        Assert.Equal(CommandReceiptStore.PlatformScope, call.OwnerScope);
        Assert.Equal(Id(1).ToString("D"), Text(call.Arguments[0][0]));

        storage.Handler = _ => Rows();
        Assert.Null(await store.LoadAsync(Id(2), TestContext.Current.CancellationToken));
        var decision = await store.ClassifyAsync(Identity(2), TestContext.Current.CancellationToken);
        Assert.Equal(ReplayKind.NotSeen, decision.Kind);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    [InlineData(-1)]
    public async Task AStatusThatIsNotARegisteredNumberIsADefectNeverAGuess(int status)
    {
        var storage = new ScriptedExecutor
        {
            Handler = _ => Rows([D1Values.Text("h"), D1Values.Int64(status), D1Values.Null(), D1Values.Null(), D1Values.Null(), D1Values.Int64(1), D1Values.Text("a"), D1Values.Text("o"), D1Values.Null()]),
        };
        var failure = await Assert.ThrowsAsync<PlanFailureException>(() => new CommandReceiptStore(storage, 0, new FixedTime()).LoadAsync(Id(1), TestContext.Current.CancellationToken));
        Assert.Equal(PlanFailureKind.InvalidPlan, failure.Kind);
    }

    [Fact]
    public async Task ARefusalIsRecordedOnceUnderItsCommandId()
    {
        var storage = new ScriptedExecutor { Handler = _ => Changed() };
        var store = new CommandReceiptStore(storage, 0, new FixedTime());
        Assert.True(await store.RecordFailureAsync(Identity(workspace: Id(4)), "validation.invalid_request", NowMicros, NowMicros + 100, TestContext.Current.CancellationToken));
        var call = Assert.Single(storage.Calls);
        Assert.Equal("platform.command-record-failure", call.Plan.Id);
        Assert.Equal(["actor-1", "fixture.store", "hash-1", "validation.invalid_request"], new[] { Text(call.Arguments[0][2]), Text(call.Arguments[0][3]), Text(call.Arguments[0][4]), Text(call.Arguments[0][5]) });
        Assert.Equal(Id(4).ToString("D"), Text(call.Arguments[0][1]));

        storage.Handler = _ => throw Fail(PlanFailureKind.Constraint);
        Assert.False(await store.RecordFailureAsync(Identity(), "validation.invalid_request", NowMicros, NowMicros + 100, TestContext.Current.CancellationToken));
        storage.Handler = _ => throw Fail(PlanFailureKind.Overloaded);
        await Assert.ThrowsAsync<PlanFailureException>(() => store.RecordFailureAsync(Identity(), "validation.invalid_request", NowMicros, NowMicros + 100, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => store.RecordFailureAsync(Identity(), "", NowMicros, NowMicros + 100, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => store.RecordFailureAsync(Identity(), "x", NowMicros, NowMicros, TestContext.Current.CancellationToken));
    }

    [Fact]
    public void TheInboxKeyCarriesTheRecoveryGenerationInTheStoredMessageId()
    {
        var key = new InboxKey("billing-consumer", "evt-1", 0);
        Assert.Equal("evt-1@0", key.StoredMessageId);
        Assert.Equal("evt-1@18446744073709551615", new InboxKey("c", "evt-1", ulong.MaxValue).StoredMessageId);
        // The same event under another generation, or another consumer, is a different message.
        Assert.NotEqual(key.StoredMessageId, new InboxKey("billing-consumer", "evt-1", 1).StoredMessageId);
        Assert.Throws<ArgumentException>(() => new InboxKey("", "evt", 0));
        Assert.Throws<ArgumentException>(() => new InboxKey("c", "", 0));
        Assert.Throws<ArgumentException>(() => new InboxKey("c", new string('m', 255), 0));
    }

    [Fact]
    public async Task TheInboxStoreReadsAnEntryAndRecordsARejectedMessageOnce()
    {
        var storage = new ScriptedExecutor { Handler = _ => Rows([D1Values.Int64(3), D1Values.Int64(55)]) };
        var store = new InboxStore(storage, 2);
        var key = new InboxKey("provider-events", "evt-bad", 2);
        Assert.Equal(new InboxEntry(InboxOutcome.Rejected, 55), await store.LoadAsync(key, TestContext.Current.CancellationToken));
        var load = Assert.Single(storage.Calls);
        Assert.Equal(["provider-events", "evt-bad@2"], new[] { Text(load.Arguments[0][0]), Text(load.Arguments[0][1]) });
        Assert.Equal(2UL, load.RecoveryGeneration);

        storage.Handler = _ => Rows([D1Values.Null(), D1Values.Null()]);
        Assert.Equal(new InboxEntry(null, null), await store.LoadAsync(key, TestContext.Current.CancellationToken));
        storage.Handler = _ => Rows();
        Assert.Null(await store.LoadAsync(key, TestContext.Current.CancellationToken));
        storage.Handler = _ => Rows([D1Values.Int64(9), D1Values.Int64(1)]);
        await Assert.ThrowsAsync<PlanFailureException>(() => store.LoadAsync(key, TestContext.Current.CancellationToken));

        storage.Handler = _ => Changed();
        Assert.True(await store.RecordRejectedAsync(key, NowMicros, NowMicros + InboxRetention.MinimumMicros, TestContext.Current.CancellationToken));
        var record = storage.Calls[^1];
        Assert.Equal("platform.inbox-record", record.Plan.Id);
        Assert.Equal(3, Int(record.Arguments[0][4]));
        storage.Handler = _ => throw Fail(PlanFailureKind.Constraint);
        Assert.False(await store.RecordRejectedAsync(key, NowMicros, NowMicros + InboxRetention.MinimumMicros, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => store.RecordRejectedAsync(key, NowMicros, NowMicros, TestContext.Current.CancellationToken));
    }
}
