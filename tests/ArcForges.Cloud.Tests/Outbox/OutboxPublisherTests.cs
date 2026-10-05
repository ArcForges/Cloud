// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.Outbox;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;
using static ArcForges.Cloud.Tests.Receipts.Samples;
using static ArcForges.Cloud.Tests.Receipts.ScriptedExecutor;
using ScriptedExecutor = ArcForges.Cloud.Tests.Receipts.ScriptedExecutor;

namespace ArcForges.Cloud.Tests.Outbox;

/// <summary>
/// The contiguous publisher's host side: what it selects, the guarded acknowledgement it binds and how a failed or lost acknowledgement is reconciled with
/// the stream. The SQL (guards, contention, dead letters, fences) is proved by tests/worker/d1-receipts.test.ts.
/// </summary>
public sealed class OutboxPublisherTests
{
    private const string Key = "workspace:fixture-a";

    private sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static D1Scalar[] StreamRow(long last, long watermark, long revision = 0, long fence = 0, string? receipt = null) =>
        [D1Values.Int64(last), D1Values.Int64(watermark), D1Values.Int64(revision), D1Values.Int64(fence), Opt(receipt)];

    private static D1Scalar[] StoredRow(long sequence, int state = 1, int attempts = 0, string? payload = null) =>
    [
        D1Values.Int64(sequence),
        D1Values.Text(Id(100 + (int)sequence).ToString("D")),
        D1Values.Text("fixture"),
        D1Values.Text(Id(200 + (int)sequence).ToString("D")),
        D1Values.Int64(4),
        D1Values.Text("fixture.changed"),
        D1Values.Text(payload ?? "{\"n\":1}"),
        D1Values.Null(),
        D1Values.Text(Id(300 + (int)sequence).ToString("D")),
        D1Values.Null(),
        D1Values.Int64(state),
        D1Values.Int64(attempts),
        D1Values.Int64(NowMicros),
    ];

    private static OutboxPublisher PublisherOver(ScriptedExecutor storage) => new(storage, 5, new FixedTime());

    [Fact]
    public async Task NothingIsSelectedFromAMissingStreamOrOneWithoutUnpublishedRows()
    {
        var storage = new ScriptedExecutor { Handler = _ => Rows() };
        var publisher = PublisherOver(storage);
        Assert.Null(await publisher.LoadStreamAsync(Key, TestContext.Current.CancellationToken));
        Assert.Null(await publisher.SelectAsync(Key, 10, TestContext.Current.CancellationToken));
        storage.Handler = _ => Rows(StreamRow(7, 7));
        Assert.Null(await publisher.SelectAsync(Key, 10, TestContext.Current.CancellationToken));
        Assert.All(storage.Calls, call => Assert.Equal(Key, call.OwnerScope));
        Assert.All(storage.Calls, call => Assert.Equal(5UL, call.RecoveryGeneration));
    }

    [Fact]
    public async Task TheSelectionIsTheContiguousPendingRowsAfterTheWatermarkBoundedByTheCaller()
    {
        var storage = new ScriptedExecutor();
        storage.Handler = c => c.Plan.Id == "platform.stream-load" ? Rows(StreamRow(10, 4, 2, 1)) : Rows(StoredRow(5), StoredRow(6), StoredRow(7));
        var selection = await PublisherOver(storage).SelectAsync(Key, 3, TestContext.Current.CancellationToken);
        Assert.NotNull(selection);
        Assert.Equal([5L, 6L, 7L], selection.Rows.Select(r => r.Sequence).ToArray());
        Assert.Equal((4L, 7L, 2L, 1L), (selection.After, selection.Through, selection.PublishRevision, selection.Fence));
        Assert.Null(selection.Blocked);
        var select = storage.Calls.Single(c => c.Plan.Id == "platform.outbox-select");
        // The range is (watermark, watermark + bound], never beyond the allocation counter.
        Assert.Equal([4L, 7L], new[] { Int(select.Arguments[0][1]), Int(select.Arguments[0][2]) });
        Assert.Equal(Id(105), selection.Rows[0].OutboxId);
        Assert.Equal(OutboxState.Pending, selection.Rows[0].State);

        storage.Handler = c => c.Plan.Id == "platform.stream-load" ? Rows(StreamRow(6, 4)) : Rows(StoredRow(5), StoredRow(6));
        await PublisherOver(storage).SelectAsync(Key, 50, TestContext.Current.CancellationToken);
        Assert.Equal(6, Int(storage.Calls.Last(c => c.Plan.Id == "platform.outbox-select").Arguments[0][2]));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PublisherOver(storage).SelectAsync(Key, 0, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => PublisherOver(storage).SelectAsync(Key, 51, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task APayloadBoundSelectionThatReturnsFewerRowsIsStillAContiguousPrefix()
    {
        var storage = new ScriptedExecutor { Handler = c => c.Plan.Id == "platform.stream-load" ? Rows(StreamRow(30, 0)) : Rows(StoredRow(1), StoredRow(2)) };
        var selection = await PublisherOver(storage).SelectAsync(Key, 25, TestContext.Current.CancellationToken);
        Assert.Equal(2, selection!.Rows.Count);
        Assert.Equal(2, selection.Through);
    }

    [Fact]
    public async Task AGapARepeatAnOutOfOrderRowADispatchedRowAboveTheWatermarkOrUnreadableSequencesStopPublication()
    {
        foreach (var script in new D1Scalar[][][]
        {
            [StoredRow(5), StoredRow(7)],          // gap
            [StoredRow(5), StoredRow(5)],          // repeat
            [StoredRow(6), StoredRow(5)],          // out of order
            [StoredRow(5), StoredRow(6, state: 2)], // dispatched above the watermark
            [StoredRow(6)],                         // the first row after the watermark is missing
            [],                                     // allocated sequences that cannot be read at all
        })
        {
            var storage = new ScriptedExecutor { Handler = c => c.Plan.Id == "platform.stream-load" ? Rows(StreamRow(8, 4)) : Rows(script) };
            await Assert.ThrowsAsync<OutboxIntegrityException>(() => PublisherOver(storage).SelectAsync(Key, 10, TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task ADeadLetteredRowEndsTheSelectionAndBlocksTheStream()
    {
        var storage = new ScriptedExecutor { Handler = c => c.Plan.Id == "platform.stream-load" ? Rows(StreamRow(8, 4)) : Rows(StoredRow(5), StoredRow(6, state: 3, attempts: 5), StoredRow(7)) };
        var selection = await PublisherOver(storage).SelectAsync(Key, 10, TestContext.Current.CancellationToken);
        Assert.Equal([5L], selection!.Rows.Select(r => r.Sequence).ToArray());
        Assert.Equal(5, selection.Through);
        Assert.Equal(6, selection.Blocked!.Sequence);
        Assert.Equal(5, selection.Blocked.Attempts);

        storage.Handler = c => c.Plan.Id == "platform.stream-load" ? Rows(StreamRow(8, 4)) : Rows(StoredRow(5, state: 3));
        var blockedFirst = await PublisherOver(storage).SelectAsync(Key, 10, TestContext.Current.CancellationToken);
        Assert.Empty(blockedFirst!.Rows);
        Assert.Equal(4, blockedFirst.Through);
        Assert.NotNull(blockedFirst.Blocked);
        await Assert.ThrowsAsync<ArgumentException>(() => PublisherOver(storage).AcknowledgeAsync(blockedFirst, "run", TestContext.Current.CancellationToken));
    }

    private static OutboxSelection SelectionOf(long after, long through, long revision = 2, long fence = 1) =>
        new(Key, after, through, Enumerable.Range((int)after + 1, (int)(through - after)).Select(s => Row(s)).ToArray(), revision, fence, null);

    private static OutboxRow Row(long sequence, int attempts = 0, OutboxState state = OutboxState.Pending) =>
        new(sequence, Id(100 + (int)sequence), "fixture", Id(200 + (int)sequence), 4, "fixture.changed", "{}", null, Id(300 + (int)sequence), null, state, attempts, NowMicros);

    [Fact]
    public async Task TheAcknowledgementBindsTheGuardTheDispatchAndTheWatermarkAdvanceFromTheSelectionAndRecordsTheReceipt()
    {
        var storage = new ScriptedExecutor { Handler = _ => Changed(4) };
        var selection = SelectionOf(4, 7);
        Assert.Equal(AckOutcome.Applied, await PublisherOver(storage).AcknowledgeAsync(selection, "run-1", TestContext.Current.CancellationToken));
        var call = Assert.Single(storage.Calls);
        Assert.Equal("platform.outbox-ack", call.Plan.Id);
        Assert.Equal(Key, call.OwnerScope);
        var guard = call.Arguments[0];
        // guard: command id, stream, watermark, revision, fence, through, stream, watermark, through, row count
        Assert.Equal(Key, Text(guard[1]));
        Assert.Equal([4L, 2L, 1L, 7L], new[] { Int(guard[2]), Int(guard[3]), Int(guard[4]), Int(guard[5]) });
        Assert.Equal([4L, 7L, 3L], new[] { Int(guard[7]), Int(guard[8]), Int(guard[9]) });
        var advance = call.Arguments[2];
        Assert.Equal([7L, 4L, 2L, 1L], new[] { Int(advance[0]), Int(advance[4]), Int(advance[5]), Int(advance[6]) });
        Assert.Equal("run-1", Text(advance[1]));
        Assert.Equal(Text(guard[0]), Text(call.Arguments[3][0]));
        Assert.Equal(StorageTime(), Int(call.Arguments[1][0]));
    }

    private static long StorageTime() => NowMicros;

    [Theory]
    [InlineData("Precondition")]
    [InlineData("UnknownOutcome")]
    public async Task AFailedOrLostAcknowledgementIsReconciledByRereadingTheStreamAndNeverNumbersOrMarksAnythingAgain(string kindName)
    {
        var kind = Enum.Parse<PlanFailureKind>(kindName);
        var selection = SelectionOf(4, 7);
        async Task<AckOutcome> Run(D1Scalar[] state)
        {
            var storage = new ScriptedExecutor { Handler = c => c.Plan.Id == "platform.stream-load" ? Rows(state) : throw Fail(kind) };
            var outcome = await PublisherOver(storage).AcknowledgeAsync(selection, "run-1", TestContext.Current.CancellationToken);
            Assert.Equal(["platform.outbox-ack", "platform.stream-load"], storage.PlanIds);
            return outcome;
        }

        // The batch did apply (the response was lost): the watermark is at the range's end and the receipt is this run's.
        Assert.Equal(AckOutcome.Applied, await Run(StreamRow(9, 7, 3, 1, "run-1")));
        // Another publisher acknowledged it, or went beyond it.
        Assert.Equal(AckOutcome.Acknowledged, await Run(StreamRow(9, 7, 3, 1, "run-other")));
        Assert.Equal(AckOutcome.Acknowledged, await Run(StreamRow(9, 9, 4, 1, "run-1")));
        // Nothing moved: a row left the pending state (or the batch never ran): select again.
        Assert.Equal(AckOutcome.NotApplied, await Run(StreamRow(9, 4, 2, 1)));
        // The stream moved some other way: a lower acknowledgement, a revision or a fence change.
        Assert.Equal(AckOutcome.Superseded, await Run(StreamRow(9, 5, 3, 1, "run-other")));
        Assert.Equal(AckOutcome.Superseded, await Run(StreamRow(9, 4, 3, 1)));
        Assert.Equal(AckOutcome.Superseded, await Run(StreamRow(9, 4, 2, 2)));
    }

    [Theory]
    [InlineData("Overloaded")]
    [InlineData("StaleGeneration")]
    [InlineData("Constraint")]
    public async Task OtherFailuresOfTheAcknowledgementPropagate(string kindName)
    {
        var kind = Enum.Parse<PlanFailureKind>(kindName);
        var storage = new ScriptedExecutor { Handler = _ => throw Fail(kind) };
        var failure = await Assert.ThrowsAsync<PlanFailureException>(() => PublisherOver(storage).AcknowledgeAsync(SelectionOf(0, 1), "run", TestContext.Current.CancellationToken));
        Assert.Equal(kind, failure.Kind);
        Assert.Single(storage.Calls);
    }

    [Fact]
    public async Task AttemptsDeadLettersRequeuesAndFenceChangesAreGuardedByTheRowAndTheFenceTheCallerRead()
    {
        var storage = new ScriptedExecutor { Handler = _ => Changed(3) };
        var publisher = PublisherOver(storage);
        var row = Row(5, attempts: 2);
        Assert.True(await publisher.RecordAttemptAsync(Key, row, 1, TestContext.Current.CancellationToken));
        var attempt = storage.Calls[^1];
        Assert.Equal("platform.outbox-attempt", attempt.Plan.Id);
        Assert.Equal([row.OutboxId.ToString("D"), Key], new[] { Text(attempt.Arguments[0][1]), Text(attempt.Arguments[0][2]) });
        Assert.Equal([2L, 1L], new[] { Int(attempt.Arguments[0][3]), Int(attempt.Arguments[0][4]) });
        Assert.Equal(Text(attempt.Arguments[0][0]), Text(attempt.Arguments[2][0]));

        Assert.True(await publisher.DeadLetterAsync(Key, row, 1, TestContext.Current.CancellationToken));
        Assert.Equal("platform.outbox-dead-letter", storage.Calls[^1].Plan.Id);
        Assert.True(await publisher.RequeueAsync(Key, Row(5, 5, OutboxState.DeadLettered), 1, TestContext.Current.CancellationToken));
        var requeue = storage.Calls[^1];
        Assert.Equal("platform.outbox-requeue", requeue.Plan.Id);
        Assert.Equal(1, Int(requeue.Arguments[0][3]));
        Assert.True(await publisher.AdvanceFenceAsync(Key, 1, TestContext.Current.CancellationToken));
        var fence = storage.Calls[^1];
        Assert.Equal("platform.stream-fence", fence.Plan.Id);
        Assert.Equal(1, Int(fence.Arguments[0][2]));
        Assert.Equal(1, Int(fence.Arguments[1][2]));

        // A guard that no longer holds is a plain false, never an exception: the caller rereads.
        storage.Handler = _ => throw Fail(PlanFailureKind.Precondition);
        Assert.False(await publisher.RecordAttemptAsync(Key, row, 1, TestContext.Current.CancellationToken));
        Assert.False(await publisher.DeadLetterAsync(Key, row, 1, TestContext.Current.CancellationToken));
        Assert.False(await publisher.RequeueAsync(Key, row, 1, TestContext.Current.CancellationToken));
        Assert.False(await publisher.AdvanceFenceAsync(Key, 1, TestContext.Current.CancellationToken));
        storage.Handler = _ => throw Fail(PlanFailureKind.UnknownOutcome);
        await Assert.ThrowsAsync<PlanFailureException>(() => publisher.RecordAttemptAsync(Key, row, 1, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RetentionPurgesPositionsBeforeOutboxRowsUnderTheWatermarkGuardAndRefusesWhenItIsBelow()
    {
        var storage = new ScriptedExecutor { Handler = _ => Changed(2) };
        var publisher = PublisherOver(storage);
        Assert.True(await publisher.PurgeAsync(Key, 40, NowMicros, TestContext.Current.CancellationToken));
        var call = Assert.Single(storage.Calls);
        Assert.Equal("platform.outbox-purge", call.Plan.Id);
        Assert.Equal([40L, 40L, NowMicros], new[] { Int(call.Arguments[0][2]), Int(call.Arguments[1][1]), Int(call.Arguments[1][2]) });
        Assert.Equal(NowMicros, Int(call.Arguments[2][0]));
        Assert.Equal(Text(call.Arguments[0][0]), Text(call.Arguments[3][0]));
        storage.Handler = _ => throw Fail(PlanFailureKind.Precondition);
        Assert.False(await publisher.PurgeAsync(Key, 40, NowMicros, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => publisher.PurgeAsync(Key, 0, NowMicros, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => publisher.PurgeAsync("platform:change-archive", 1, NowMicros, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("platform:change-archive")]
    [InlineData("platform:other")]
    [InlineData("")]
    [InlineData("with space")]
    public async Task APlatformStreamOrAMalformedKeyIsNeverAnOutboxStream(string key)
    {
        var storage = new ScriptedExecutor { Handler = _ => Rows() };
        var publisher = PublisherOver(storage);
        await Assert.ThrowsAsync<ArgumentException>(() => publisher.LoadStreamAsync(key, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => publisher.SelectAsync(key, 5, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => publisher.AdvanceFenceAsync(key, 0, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => publisher.AcknowledgeAsync(SelectionOf(0, 1) with { StreamKey = key }, "r", TestContext.Current.CancellationToken));
        Assert.Empty(storage.Calls);
    }

    [Fact]
    public void AStreamStateThatBreaksItsOwnRulesIsRefused()
    {
        foreach (var bad in new[] { StreamRow(3, 4), StreamRow(-1, 0), StreamRow(3, -1), StreamRow(3, 1, -1), StreamRow(3, 1, 0, -1) })
            Assert.Throws<PlanFailureException>(() => StreamState.FromRows([bad]));
        Assert.Null(StreamState.FromRows([]));
        var state = StreamState.FromRows([StreamRow(9, 4, 1, 2, "r")])!;
        Assert.Equal(5, state.Unpublished);
    }
}
