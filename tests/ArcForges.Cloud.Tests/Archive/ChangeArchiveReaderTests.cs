// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.Archive;
using ArcForges.Cloud.Storage.Outbox;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;
using static ArcForges.Cloud.Tests.Receipts.Samples;
using static ArcForges.Cloud.Tests.Receipts.ScriptedExecutor;
using ScriptedExecutor = ArcForges.Cloud.Tests.Receipts.ScriptedExecutor;

namespace ArcForges.Cloud.Tests.Archive;

public sealed class ChangeArchiveReaderTests
{
    private sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static D1Scalar[] StateRow(long last, long watermark, long revision = 0, long fence = 0, string? receipt = null) =>
        [D1Values.Int64(last), D1Values.Int64(watermark), D1Values.Int64(revision), D1Values.Int64(fence), Opt(receipt)];

    private static D1Scalar[] Record(long sequence, string? json = null, byte[]? hash = null)
    {
        json ??= $"{{\"row\":{sequence}}}";
        return
        [
            D1Values.Int64(sequence),
            D1Values.Text(Id((int)sequence).ToString("D")),
            D1Values.Int64(23),
            D1Values.Text(json),
            D1Values.Bytes(hash ?? ChangeRecord.HashOf(json)),
            D1Values.Int64(NowMicros),
        ];
    }

    private static ChangeArchiveReader ReaderOver(ScriptedExecutor storage) => new(storage, 5, new FixedTime());

    [Fact]
    public void TheHashIsTheSha256OfTheUtf8RecordText()
    {
        var record = new ChangeRecord(23, "{\"name\":\"Zoë\"}");
        Assert.Equal(32, record.Hash().Length);
        Assert.Equal(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes("{\"name\":\"Zoë\"}")), record.Hash());
        Assert.NotEqual(record.Hash(), new ChangeRecord(23, "{\"name\":\"Zoe\"}").Hash());
    }

    [Fact]
    public async Task NothingIsReadWhenEverythingCommittedIsAcknowledged()
    {
        var storage = new ScriptedExecutor { Handler = _ => Rows() };
        Assert.Null(await ReaderOver(storage).LoadStateAsync(TestContext.Current.CancellationToken));
        Assert.Null(await ReaderOver(storage).SelectAsync(10, TestContext.Current.CancellationToken));
        storage.Handler = _ => Rows(StateRow(6, 6));
        Assert.Null(await ReaderOver(storage).SelectAsync(10, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => ReaderOver(storage).SelectAsync(0, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => ReaderOver(storage).SelectAsync(101, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task TheBatchIsTheVerifiedContiguousRecordsAfterTheAcknowledgedWatermark()
    {
        var storage = new ScriptedExecutor { Handler = c => c.Plan.Id == "platform.archive-state" ? Rows(StateRow(9, 2, 3, 1)) : Rows(Record(3), Record(4), Record(5)) };
        var batch = await ReaderOver(storage).SelectAsync(3, TestContext.Current.CancellationToken);
        Assert.Equal([3L, 4L, 5L], batch!.Records.Select(r => r.Sequence).ToArray());
        Assert.Equal((2L, 5L, 3L, 1L), (batch.After, batch.Through, batch.PublishRevision, batch.Fence));
        var select = storage.Calls.Single(c => c.Plan.Id == "platform.archive-select");
        Assert.Equal([2L, 5L], new[] { Int(select.Arguments[0][0]), Int(select.Arguments[0][1]) });
        Assert.Equal(5UL, select.RecoveryGeneration);
        // A byte-bounded page may hold fewer records than asked for; the prefix is still contiguous.
        storage.Handler = c => c.Plan.Id == "platform.archive-state" ? Rows(StateRow(30, 0)) : Rows(Record(1), Record(2));
        Assert.Equal(2, (await ReaderOver(storage).SelectAsync(100, TestContext.Current.CancellationToken))!.Through);
    }

    [Fact]
    public async Task AGapARepeatAMissingFirstRecordOrNothingReadableStopsTheCopy()
    {
        foreach (var script in new D1Scalar[][][] { [Record(3), Record(5)], [Record(3), Record(3)], [Record(4)], [Record(4), Record(3)], [] })
        {
            var storage = new ScriptedExecutor { Handler = c => c.Plan.Id == "platform.archive-state" ? Rows(StateRow(9, 2)) : Rows(script) };
            await Assert.ThrowsAsync<ArchiveIntegrityException>(() => ReaderOver(storage).SelectAsync(5, TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task ARecordThatDoesNotMatchItsHashIsRefusedBeforeItIsHandedOver()
    {
        var storage = new ScriptedExecutor { Handler = c => c.Plan.Id == "platform.archive-state" ? Rows(StateRow(9, 2)) : Rows(Record(3), Record(4, "{\"row\":99}", ChangeRecord.HashOf("{\"row\":4}"))) };
        var failure = await Assert.ThrowsAsync<ArchiveIntegrityException>(() => ReaderOver(storage).SelectAsync(5, TestContext.Current.CancellationToken));
        Assert.Contains("sequence 4", failure.Message, StringComparison.Ordinal);

        // A flipped bit in the stored hash is the same failure, and so is a hash of the wrong length (the table refuses it, a reader does too).
        var flipped = ChangeRecord.HashOf("{\"row\":3}");
        flipped[0] ^= 1;
        storage.Handler = c => c.Plan.Id == "platform.archive-state" ? Rows(StateRow(9, 2)) : Rows(Record(3, "{\"row\":3}", flipped));
        await Assert.ThrowsAsync<ArchiveIntegrityException>(() => ReaderOver(storage).SelectAsync(5, TestContext.Current.CancellationToken));
        storage.Handler = c => c.Plan.Id == "platform.archive-state" ? Rows(StateRow(9, 2)) : Rows(Record(3, "{\"row\":3}", new byte[31]));
        await Assert.ThrowsAsync<PlanFailureException>(() => ReaderOver(storage).SelectAsync(5, TestContext.Current.CancellationToken));
    }

    private static ArchiveBatch BatchOf(long after, long through, long revision = 2, long fence = 1) =>
        new(after, through, Enumerable.Range((int)after + 1, (int)(through - after)).Select(s => new ArchivedChange(s, Id((int)s), 23, "{}", ChangeRecord.HashOf("{}"), NowMicros)).ToArray(), revision, fence);

    [Fact]
    public async Task TheWatermarkAdvancesOnlyWithTheIndependentStoragesReceiptUnderTheGuardOfTheBatchItRead()
    {
        var storage = new ScriptedExecutor { Handler = _ => Changed(3) };
        Assert.Equal(AckOutcome.Applied, await ReaderOver(storage).AcknowledgeAsync(BatchOf(2, 5), "s3-receipt", TestContext.Current.CancellationToken));
        var call = Assert.Single(storage.Calls);
        Assert.Equal("platform.archive-ack", call.Plan.Id);
        var guard = call.Arguments[0];
        Assert.Equal([2L, 2L, 1L, 5L, 2L, 5L, 3L], new[] { Int(guard[1]), Int(guard[2]), Int(guard[3]), Int(guard[4]), Int(guard[5]), Int(guard[6]), Int(guard[7]) });
        var advance = call.Arguments[1];
        Assert.Equal([5L, 2L, 2L, 1L], new[] { Int(advance[0]), Int(advance[3]), Int(advance[4]), Int(advance[5]) });
        Assert.Equal("s3-receipt", Text(advance[1]));
        Assert.Equal(Text(guard[0]), Text(call.Arguments[2][0]));

        await Assert.ThrowsAsync<ArgumentException>(() => ReaderOver(storage).AcknowledgeAsync(BatchOf(2, 5), "", TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentException>(() => ReaderOver(storage).AcknowledgeAsync(BatchOf(2, 2), "r", TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RetentionPurgesOnlyAcknowledgedRecordsPastTheBackupCutoff()
    {
        var storage = new ScriptedExecutor { Handler = _ => Changed(2) };
        Assert.True(await ReaderOver(storage).PurgeAsync(7, NowMicros, TestContext.Current.CancellationToken));
        var call = Assert.Single(storage.Calls);
        Assert.Equal("platform.archive-purge", call.Plan.Id);
        Assert.Equal([7L, 7L, NowMicros], new[] { Int(call.Arguments[0][1]), Int(call.Arguments[1][0]), Int(call.Arguments[1][1]) });
        storage.Handler = _ => throw Fail(PlanFailureKind.Precondition);
        Assert.False(await ReaderOver(storage).PurgeAsync(7, NowMicros, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() => ReaderOver(storage).PurgeAsync(0, NowMicros, TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData("Precondition")]
    [InlineData("UnknownOutcome")]
    public async Task AFailedOrLostArchiveAcknowledgementIsReconciledFromTheStream(string kindName)
    {
        var kind = Enum.Parse<PlanFailureKind>(kindName);
        async Task<AckOutcome> Run(D1Scalar[] state)
        {
            var storage = new ScriptedExecutor { Handler = c => c.Plan.Id == "platform.archive-state" ? Rows(state) : throw Fail(kind) };
            var outcome = await ReaderOver(storage).AcknowledgeAsync(BatchOf(2, 5), "s3-receipt", TestContext.Current.CancellationToken);
            Assert.Equal(["platform.archive-ack", "platform.archive-state"], storage.PlanIds);
            return outcome;
        }

        Assert.Equal(AckOutcome.Applied, await Run(StateRow(9, 5, 3, 1, "s3-receipt")));
        Assert.Equal(AckOutcome.Acknowledged, await Run(StateRow(9, 7, 4, 1, "other")));
        Assert.Equal(AckOutcome.NotApplied, await Run(StateRow(9, 2, 2, 1)));
        Assert.Equal(AckOutcome.Superseded, await Run(StateRow(9, 3, 3, 1, "other")));
        Assert.Equal(AckOutcome.Superseded, await Run(StateRow(9, 2, 2, 2)));
    }
}
