// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.Outbox;

/// <summary>
/// The state of one publication stream (<c>platform_sequence_stream</c>): the allocation counter, the contiguous published watermark, the revision
/// that only an acknowledgement or a fence change advances (so unrelated commits never invalidate a selection), the fence and the last receipt.
/// </summary>
internal sealed record StreamState(long LastSequence, long PublishedWatermark, long PublishRevision, long Fence, string? AckReceipt)
{
    /// <summary>The rows above the watermark that were committed and are not yet acknowledged.</summary>
    public long Unpublished => LastSequence - PublishedWatermark;

    internal static StreamState? FromRows(IReadOnlyList<IReadOnlyList<D1Scalar>> rows)
    {
        if (rows.Count == 0) return null;
        var row = rows[0];
        if (!D1Values.TryGetInt64(row[0], out var last)
            || !D1Values.TryGetInt64(row[1], out var watermark)
            || !D1Values.TryGetInt64(row[2], out var revision)
            || !D1Values.TryGetInt64(row[3], out var fence)
            || last < 0
            || watermark < 0
            || watermark > last
            || revision < 0
            || fence < 0)
            throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        return new StreamState(last, watermark, revision, fence, D1Values.TryGetText(row[4], out var receipt) ? receipt : null);
    }
}

/// <summary>A stored sequence that is not what the allocation rule guarantees: a missing, repeated or out-of-order row. Publication stops; nothing is skipped.</summary>
internal sealed class OutboxIntegrityException(string message) : Exception(message);

/// <summary>The result of a guarded acknowledgement, reconciled with the stream when the batch's response is not a plain success.</summary>
internal enum AckOutcome
{
    /// <summary>This call's batch acknowledged the range.</summary>
    Applied,

    /// <summary>The range was already acknowledged (this call's lost response, or another publisher): the watermark is at or beyond it.</summary>
    Acknowledged,

    /// <summary>The batch did not apply and the stream is as selected (a row left the pending state): select again.</summary>
    NotApplied,

    /// <summary>Another publisher, a fence change or an acknowledgement moved the stream: select again from the new state.</summary>
    Superseded,
}
