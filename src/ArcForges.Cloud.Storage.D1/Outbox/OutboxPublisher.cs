// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage.Receipts;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.Outbox;

/// <summary>A committed outbox row as a publisher reads it, with the sequence its commit allocated in the stream.</summary>
internal sealed record OutboxRow(
    long Sequence,
    Guid OutboxId,
    string AggregateKind,
    Guid AggregateId,
    long AggregateRevision,
    string EventType,
    string PayloadJson,
    Guid? WorkspaceId,
    Guid CorrelationId,
    Guid? CausationId,
    OutboxState State,
    int Attempts,
    long CreatedAtMicros);

/// <summary>
/// The pending rows that follow the watermark without a gap, the stream state they were selected under, and the dead-lettered row that stops the stream
/// when there is one. <see cref="Rows"/> may be empty: nothing to publish, or the first row after the watermark is blocked.
/// </summary>
internal sealed record OutboxSelection(string StreamKey, long After, long Through, IReadOnlyList<OutboxRow> Rows, long PublishRevision, long Fence, OutboxRow? Blocked);

/// <summary>
/// The contiguous publisher mechanics of the generic outbox (D1 profile section 5). It selects committed rows in sequence order, marks exactly that range
/// dispatched and advances the watermark in one guarded batch, and reconciles a lost acknowledgement by rereading the stream. It publishes nothing itself:
/// the Durable Object feed (WP-24.04) and the Sync publisher (WP-25.02) deliver the rows and call the acknowledgement afterwards (dispatch is at-least-once, OB-03).
/// </summary>
internal sealed class OutboxPublisher(IPlanExecutor executor, ulong recoveryGeneration, TimeProvider time)
{
    public const int MaxSelection = 50;
    public const int DefaultSelection = 25;

    public async Task<StreamState?> LoadStreamAsync(string streamKey, CancellationToken cancellationToken)
    {
        RequireStream(streamKey);
        var result = await executor.ExecuteAsync(PlanCall.New(PlanManifest.Platform.StreamLoad, streamKey, recoveryGeneration, [[D1Values.Text(streamKey)]]), cancellationToken);
        return StreamState.FromRows(result.Rows);
    }

    /// <summary>
    /// The next rows to publish, or null when the stream has none. A missing, repeated or out-of-order sequence, and a dispatched row above the watermark,
    /// throw <see cref="OutboxIntegrityException"/>: the stream is not published past something unexplained.
    /// </summary>
    public async Task<OutboxSelection?> SelectAsync(string streamKey, int maxRows, CancellationToken cancellationToken)
    {
        if (maxRows is < 1 or > MaxSelection) throw new ArgumentOutOfRangeException(nameof(maxRows));
        var state = await LoadStreamAsync(streamKey, cancellationToken);
        if (state is null || state.Unpublished == 0) return null;
        var after = state.PublishedWatermark;
        var through = Math.Min(state.LastSequence, after + maxRows);
        var call = PlanCall.New(PlanManifest.Platform.OutboxSelect, streamKey, recoveryGeneration, [[D1Values.Text(streamKey), D1Values.Int64(after), D1Values.Int64(through)]]);
        var result = await executor.ExecuteAsync(call, cancellationToken);
        var rows = new List<OutboxRow>(result.Rows.Count);
        OutboxRow? blocked = null;
        for (var index = 0; index < result.Rows.Count; index++)
        {
            var row = Parse(result.Rows[index]);
            if (row.Sequence != after + 1 + index) throw new OutboxIntegrityException($"Stream {streamKey}: expected sequence {after + 1 + index} but read {row.Sequence}.");
            if (row.State == OutboxState.Dispatched) throw new OutboxIntegrityException($"Stream {streamKey}: sequence {row.Sequence} is dispatched above the watermark {after}.");
            if (row.State == OutboxState.DeadLettered)
            {
                blocked = row;
                break;
            }

            rows.Add(row);
        }

        // A committed sequence that cannot be read (no position or no outbox row) is not the end of the stream: it is a defect.
        if (blocked is null && result.Rows.Count == 0) throw new OutboxIntegrityException($"Stream {streamKey}: sequences {after + 1} to {through} are allocated but cannot be read.");
        return new OutboxSelection(streamKey, after, after + rows.Count, rows, state.PublishRevision, state.Fence, blocked);
    }

    /// <summary>
    /// Marks the selected range dispatched and advances the watermark under the guard of the watermark, the revision, the fence and a count proving every
    /// row of the range exists and is still pending. <paramref name="receipt"/> identifies this publisher run (recorded on the stream).
    /// </summary>
    public async Task<AckOutcome> AcknowledgeAsync(OutboxSelection selection, string receipt, CancellationToken cancellationToken)
    {
        if (selection.Rows.Count == 0) throw new ArgumentException("There is nothing to acknowledge.", nameof(selection));
        StorageFormats.ShortText(receipt, nameof(receipt));
        RequireStream(selection.StreamKey);
        var guard = StorageFormats.Id(Guid.NewGuid());
        var now = StorageFormats.Micros(time.GetUtcNow());
        var key = D1Values.Text(selection.StreamKey);
        var (after, through) = (D1Values.Int64(selection.After), D1Values.Int64(selection.Through));
        D1Scalar[][] arguments =
        [
            [D1Values.Text(guard), key, after, D1Values.Int64(selection.PublishRevision), D1Values.Int64(selection.Fence), through, key, after, through, D1Values.Int64(selection.Through - selection.After)],
            [D1Values.Int64(now), key, after, through],
            [through, D1Values.Text(receipt), D1Values.Int64(now), key, after, D1Values.Int64(selection.PublishRevision), D1Values.Int64(selection.Fence)],
            [D1Values.Text(guard)],
        ];
        try
        {
            await executor.ExecuteAsync(PlanCall.New(PlanManifest.Platform.OutboxAck, selection.StreamKey, recoveryGeneration, arguments), cancellationToken);
            return AckOutcome.Applied;
        }
        catch (PlanFailureException exception) when (exception.Kind is PlanFailureKind.Precondition or PlanFailureKind.UnknownOutcome)
        {
            return await ReconcileAsync(selection, receipt, cancellationToken);
        }
    }

    /// <summary>Rereads the stream after a failed or lost acknowledgement; it never numbers or marks anything again (D1 profile section 5, lost acknowledgement).</summary>
    public async Task<AckOutcome> ReconcileAsync(OutboxSelection selection, string receipt, CancellationToken cancellationToken)
    {
        var state = await LoadStreamAsync(selection.StreamKey, cancellationToken) ?? throw new OutboxIntegrityException($"Stream {selection.StreamKey} disappeared.");
        if (state.PublishedWatermark >= selection.Through)
            return state.PublishedWatermark == selection.Through && string.Equals(state.AckReceipt, receipt, StringComparison.Ordinal) ? AckOutcome.Applied : AckOutcome.Acknowledged;
        if (state.PublishedWatermark == selection.After && state.PublishRevision == selection.PublishRevision && state.Fence == selection.Fence) return AckOutcome.NotApplied;
        return AckOutcome.Superseded;
    }

    /// <summary>Counts one failed delivery of a pending row. False when the row, its attempts or the stream fence are no longer as read.</summary>
    public Task<bool> RecordAttemptAsync(string streamKey, OutboxRow row, long fence, CancellationToken cancellationToken) =>
        TransitionAsync(PlanManifest.Platform.OutboxAttempt, streamKey, row, fence, withAttempts: true, cancellationToken);

    /// <summary>Stops the stream at a row that cannot be delivered. The watermark never passes a dead-lettered row until it is requeued.</summary>
    public Task<bool> DeadLetterAsync(string streamKey, OutboxRow row, long fence, CancellationToken cancellationToken) =>
        TransitionAsync(PlanManifest.Platform.OutboxDeadLetter, streamKey, row, fence, withAttempts: true, cancellationToken);

    /// <summary>The operator's decision to deliver a dead-lettered row again; its attempts restart from zero.</summary>
    public Task<bool> RequeueAsync(string streamKey, OutboxRow row, long fence, CancellationToken cancellationToken) =>
        TransitionAsync(PlanManifest.Platform.OutboxRequeue, streamKey, row, fence, withAttempts: false, cancellationToken);

    /// <summary>Makes every earlier selection of the stream fail its guard (a takeover or a recovery generation change). False when the fence moved already.</summary>
    public async Task<bool> AdvanceFenceAsync(string streamKey, long expectedFence, CancellationToken cancellationToken)
    {
        RequireStream(streamKey);
        var guard = D1Values.Text(StorageFormats.Id(Guid.NewGuid()));
        var key = D1Values.Text(streamKey);
        D1Scalar[][] arguments =
        [
            [guard, key, D1Values.Int64(expectedFence)],
            [D1Values.Int64(StorageFormats.Micros(time.GetUtcNow())), key, D1Values.Int64(expectedFence)],
            [guard],
        ];
        return await GuardedAsync(PlanCall.New(PlanManifest.Platform.StreamFence, streamKey, recoveryGeneration, arguments), cancellationToken);
    }

    /// <summary>
    /// Retention: deletes the positions at or below the stream's acknowledged watermark of rows dispatched before <paramref name="cutoffMicros"/>, then those outbox
    /// rows (a position first, so the foreign key never blocks). False when the watermark is below <paramref name="through"/>.
    /// </summary>
    public async Task<bool> PurgeAsync(string streamKey, long through, long cutoffMicros, CancellationToken cancellationToken)
    {
        RequireStream(streamKey);
        if (through < 1 || cutoffMicros <= 0) throw new ArgumentOutOfRangeException(nameof(through));
        var guard = D1Values.Text(StorageFormats.Id(Guid.NewGuid()));
        var key = D1Values.Text(streamKey);
        D1Scalar[][] arguments = [[guard, key, D1Values.Int64(through)], [key, D1Values.Int64(through), key, D1Values.Int64(cutoffMicros)], [D1Values.Int64(cutoffMicros)], [guard]];
        return await GuardedAsync(PlanCall.New(PlanManifest.Platform.OutboxPurge, streamKey, recoveryGeneration, arguments), cancellationToken);
    }

    private async Task<bool> TransitionAsync(PlanDefinition plan, string streamKey, OutboxRow row, long fence, bool withAttempts, CancellationToken cancellationToken)
    {
        RequireStream(streamKey);
        var guard = D1Values.Text(StorageFormats.Id(Guid.NewGuid()));
        var key = D1Values.Text(streamKey);
        var outbox = D1Values.Text(StorageFormats.Id(row.OutboxId));
        var attempts = D1Values.Int64(row.Attempts);
        D1Scalar[][] arguments = withAttempts
            ? [[guard, outbox, key, attempts, D1Values.Int64(fence)], [outbox, attempts], [guard]]
            : [[guard, outbox, key, D1Values.Int64(fence)], [outbox], [guard]];
        return await GuardedAsync(PlanCall.New(plan, streamKey, recoveryGeneration, arguments), cancellationToken);
    }

    private async Task<bool> GuardedAsync(PlanCall call, CancellationToken cancellationToken)
    {
        try
        {
            await executor.ExecuteAsync(call, cancellationToken);
            return true;
        }
        catch (PlanFailureException exception) when (exception.Kind == PlanFailureKind.Precondition)
        {
            return false;
        }
    }

    private static void RequireStream(string streamKey)
    {
        if (!StorageFormats.IsOwnerStreamScope(streamKey)) throw new ArgumentException("The stream key is not an owner scope.", nameof(streamKey));
    }

    private static OutboxRow Parse(IReadOnlyList<D1Scalar> row)
    {
        if (!D1Values.TryGetInt64(row[0], out var sequence)
            || !D1Values.TryGetText(row[1], out var id)
            || !D1Values.TryGetText(row[2], out var kind)
            || !D1Values.TryGetText(row[3], out var aggregate)
            || !D1Values.TryGetInt64(row[4], out var revision)
            || !D1Values.TryGetText(row[5], out var eventType)
            || !D1Values.TryGetText(row[6], out var payload)
            || !D1Values.TryGetText(row[8], out var correlation)
            || !D1Values.TryGetInt64(row[10], out var state)
            || !D1Values.TryGetInt64(row[11], out var attempts)
            || !D1Values.TryGetInt64(row[12], out var created)
            || state is < 1 or > 3
            || attempts is < 0 or > int.MaxValue
            || sequence < 1)
            throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        return new OutboxRow(
            sequence,
            Id(id),
            kind,
            Id(aggregate),
            revision,
            eventType,
            payload,
            D1Values.TryGetText(row[7], out var workspace) ? Id(workspace) : null,
            Id(correlation),
            D1Values.TryGetText(row[9], out var causation) ? Id(causation) : null,
            (OutboxState)state,
            (int)attempts,
            created);
    }

    private static Guid Id(string text) => Guid.TryParseExact(text, "D", out var id) && id != Guid.Empty ? id : throw new PlanFailureException(PlanFailureKind.InvalidPlan);
}
