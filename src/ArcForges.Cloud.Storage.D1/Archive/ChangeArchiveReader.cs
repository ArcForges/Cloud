// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using ArcForges.Cloud.Storage.Outbox;
using ArcForges.Cloud.Storage.Receipts;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.Archive;

/// <summary>A change record as stored: its sequence, the command that committed it, its schema version, its text and the hash recorded with it.</summary>
internal sealed record ArchivedChange(long Sequence, Guid CommandId, long SchemaVersion, string RecordJson, byte[] RecordHash, long CreatedAtMicros);

/// <summary>The contiguous archived records after the acknowledged watermark, each verified against its hash, with the stream state they were read under.</summary>
internal sealed record ArchiveBatch(long After, long Through, IReadOnlyList<ArchivedChange> Records, long PublishRevision, long Fence);

/// <summary>A record that does not hash to the value stored with it, a gap, a repeat or a record out of order: the archive is not copied past it.</summary>
internal sealed class ArchiveIntegrityException(string message) : Exception(message);

/// <summary>
/// The reader of the change archive (D1 profile section 7). It reads the contiguous committed records after the acknowledged watermark, verifies every
/// record's SHA-256 before it is handed to the archive worker, and advances the watermark only when the independent storage has acknowledged the range
/// and gave a receipt. The copy to independent storage and the signed backup watermark belong to the backup tasks (WP-46); this is the D1 side of both.
/// </summary>
internal sealed class ChangeArchiveReader(IPlanExecutor executor, ulong recoveryGeneration, TimeProvider time)
{
    public const int MaxBatch = 100;

    public async Task<StreamState?> LoadStateAsync(CancellationToken cancellationToken)
    {
        var call = PlanCall.New(PlanManifest.Platform.ArchiveState, CommandReceiptStore.PlatformScope, recoveryGeneration, [[]]);
        var result = await executor.ExecuteAsync(call, cancellationToken);
        return StreamState.FromRows(result.Rows);
    }

    /// <summary>The next verified records, or null when everything committed is acknowledged. A gap, a repeat or a hash mismatch throws <see cref="ArchiveIntegrityException"/>.</summary>
    public async Task<ArchiveBatch?> SelectAsync(int maxRecords, CancellationToken cancellationToken)
    {
        if (maxRecords is < 1 or > MaxBatch) throw new ArgumentOutOfRangeException(nameof(maxRecords));
        var state = await LoadStateAsync(cancellationToken);
        if (state is null || state.Unpublished == 0) return null;
        var after = state.PublishedWatermark;
        var through = Math.Min(state.LastSequence, after + maxRecords);
        var call = PlanCall.New(PlanManifest.Platform.ArchiveSelect, CommandReceiptStore.PlatformScope, recoveryGeneration, [[D1Values.Int64(after), D1Values.Int64(through)]]);
        var result = await executor.ExecuteAsync(call, cancellationToken);
        if (result.Rows.Count == 0) throw new ArchiveIntegrityException($"Archive sequences {after + 1} to {through} are allocated but cannot be read.");
        var records = new List<ArchivedChange>(result.Rows.Count);
        for (var index = 0; index < result.Rows.Count; index++)
        {
            var record = Parse(result.Rows[index]);
            if (record.Sequence != after + 1 + index) throw new ArchiveIntegrityException($"Archive: expected sequence {after + 1 + index} but read {record.Sequence}.");
            if (!CryptographicOperations.FixedTimeEquals(ChangeRecord.HashOf(record.RecordJson), record.RecordHash)) throw new ArchiveIntegrityException($"Archive sequence {record.Sequence} does not match its recorded hash.");
            records.Add(record);
        }

        return new ArchiveBatch(after, after + records.Count, records, state.PublishRevision, state.Fence);
    }

    /// <summary>Advances the acknowledged watermark over the batch after the independent storage returned <paramref name="independentReceipt"/>.</summary>
    public async Task<AckOutcome> AcknowledgeAsync(ArchiveBatch batch, string independentReceipt, CancellationToken cancellationToken)
    {
        if (batch.Records.Count == 0) throw new ArgumentException("There is nothing to acknowledge.", nameof(batch));
        StorageFormats.ShortText(independentReceipt, nameof(independentReceipt));
        var guard = D1Values.Text(StorageFormats.Id(Guid.NewGuid()));
        var now = D1Values.Int64(StorageFormats.Micros(time.GetUtcNow()));
        var (after, through) = (D1Values.Int64(batch.After), D1Values.Int64(batch.Through));
        var (revision, fence) = (D1Values.Int64(batch.PublishRevision), D1Values.Int64(batch.Fence));
        D1Scalar[][] arguments =
        [
            [guard, after, revision, fence, through, after, through, D1Values.Int64(batch.Through - batch.After)],
            [through, D1Values.Text(independentReceipt), now, after, revision, fence],
            [guard],
        ];
        try
        {
            await executor.ExecuteAsync(PlanCall.New(PlanManifest.Platform.ArchiveAck, CommandReceiptStore.PlatformScope, recoveryGeneration, arguments), cancellationToken);
            return AckOutcome.Applied;
        }
        catch (PlanFailureException exception) when (exception.Kind is PlanFailureKind.Precondition or PlanFailureKind.UnknownOutcome)
        {
            return await ReconcileAsync(batch, independentReceipt, cancellationToken);
        }
    }

    public async Task<AckOutcome> ReconcileAsync(ArchiveBatch batch, string independentReceipt, CancellationToken cancellationToken)
    {
        var state = await LoadStateAsync(cancellationToken) ?? throw new ArchiveIntegrityException("The archive stream disappeared.");
        if (state.PublishedWatermark >= batch.Through)
            return state.PublishedWatermark == batch.Through && string.Equals(state.AckReceipt, independentReceipt, StringComparison.Ordinal) ? AckOutcome.Applied : AckOutcome.Acknowledged;
        if (state.PublishedWatermark == batch.After && state.PublishRevision == batch.PublishRevision && state.Fence == batch.Fence) return AckOutcome.NotApplied;
        return AckOutcome.Superseded;
    }

    /// <summary>
    /// Retention: deletes change records at or below the acknowledged watermark that were created before <paramref name="cutoffMicros"/>, the instant after which no
    /// dependent backup needs them (the caller decides it). False when the watermark is below <paramref name="through"/>.
    /// </summary>
    public async Task<bool> PurgeAsync(long through, long cutoffMicros, CancellationToken cancellationToken)
    {
        if (through < 1 || cutoffMicros <= 0) throw new ArgumentOutOfRangeException(nameof(through));
        var guard = D1Values.Text(StorageFormats.Id(Guid.NewGuid()));
        D1Scalar[][] arguments = [[guard, D1Values.Int64(through)], [D1Values.Int64(through), D1Values.Int64(cutoffMicros)], [guard]];
        try
        {
            await executor.ExecuteAsync(PlanCall.New(PlanManifest.Platform.ArchivePurge, CommandReceiptStore.PlatformScope, recoveryGeneration, arguments), cancellationToken);
            return true;
        }
        catch (PlanFailureException exception) when (exception.Kind == PlanFailureKind.Precondition)
        {
            return false;
        }
    }

    private static ArchivedChange Parse(IReadOnlyList<D1Scalar> row)
    {
        if (!D1Values.TryGetInt64(row[0], out var sequence)
            || !D1Values.TryGetText(row[1], out var command)
            || !Guid.TryParseExact(command, "D", out var commandId)
            || !D1Values.TryGetInt64(row[2], out var version)
            || !D1Values.TryGetText(row[3], out var record)
            || !D1Values.TryGetBytes(row[4], out var hash)
            || !D1Values.TryGetInt64(row[5], out var created)
            || sequence < 1
            || hash.Length != 32)
            throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        return new ArchivedChange(sequence, commandId, version, record, hash, created);
    }
}
