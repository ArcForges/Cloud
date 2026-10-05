// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.Receipts;

/// <summary>Stored form of <c>platform_inbox.outcome</c> (model 01 section 2; numbers from 1 in listed order).</summary>
internal enum InboxOutcome
{
    Applied = 1,
    DuplicateIgnored = 2,
    Rejected = 3,
}

/// <summary>
/// The deduplication key of one inbound message: the producing system (OB-04; <c>&lt;producing system&gt;/&lt;handler&gt;</c> when two handlers apply the same
/// message), the message id and the recovery generation under which it is applied (D1 profile section 5). The stored message id is
/// <c>&lt;message id&gt;@&lt;generation&gt;</c>, so a message delivered again after a restore under a new generation applies again.
/// </summary>
internal sealed record InboxKey
{
    public InboxKey(string source, string messageId, ulong generation)
    {
        Source = StorageFormats.ShortText(source, nameof(source));
        MessageId = StorageFormats.ShortText(messageId, nameof(messageId));
        Generation = generation;
        if (StoredMessageId.Length > StorageFormats.MaxShortTextLength) throw new ArgumentException("The message id is too long.", nameof(messageId));
    }

    public string Source { get; }

    public string MessageId { get; }

    public ulong Generation { get; }

    public string StoredMessageId => string.Create(CultureInfo.InvariantCulture, $"{MessageId}@{Generation}");
}

/// <summary>The declared inbox retention (model 01 section 2): a row lives at least 30 days, so it outlasts redelivery, reconciliation and the recovery window.</summary>
internal static class InboxRetention
{
    public const long MinimumMicros = 30L * 86_400_000_000;

    public static void Require(long receivedAtMicros, long expiresAtMicros)
    {
        if (receivedAtMicros <= 0 || expiresAtMicros < receivedAtMicros + MinimumMicros) throw new ArgumentException("An inbox row expires at least 30 days after it is received.", nameof(expiresAtMicros));
    }
}

internal sealed record InboxEntry(InboxOutcome? Outcome, long? ProcessedAtMicros);

/// <summary>Reads the inbox and records a terminal outcome that has no effects of its own (the applied claim is part of the commit tail).</summary>
internal sealed class InboxStore(IPlanExecutor executor, ulong recoveryGeneration)
{
    public async Task<InboxEntry?> LoadAsync(InboxKey key, CancellationToken cancellationToken)
    {
        var call = PlanCall.New(
            PlanManifest.Platform.InboxLoad,
            CommandReceiptStore.PlatformScope,
            recoveryGeneration,
            [[D1Values.Text(key.Source), D1Values.Text(key.StoredMessageId)]]);
        var result = await executor.ExecuteAsync(call, cancellationToken);
        if (result.Rows.Count == 0) return null;
        var row = result.Rows[0];
        InboxOutcome? outcome = null;
        if (D1Values.TryGetInt64(row[0], out var number))
        {
            if (number is < 1 or > 3) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
            outcome = (InboxOutcome)number;
        }

        return new InboxEntry(outcome, D1Values.TryGetInt64(row[1], out var processed) ? processed : null);
    }

    /// <summary>
    /// Records that a message was seen and refused (for example a poison message), so that its redelivery is a no-op. Returns false when the
    /// key already exists: the message was already applied or refused and nothing is written.
    /// </summary>
    public async Task<bool> RecordRejectedAsync(InboxKey key, long nowMicros, long expiresAtMicros, CancellationToken cancellationToken)
    {
        InboxRetention.Require(nowMicros, expiresAtMicros);
        var arguments = new[]
        {
            new[]
            {
                D1Values.Text(key.Source),
                D1Values.Text(key.StoredMessageId),
                D1Values.Int64(nowMicros),
                D1Values.Int64(nowMicros),
                D1Values.Int64((long)InboxOutcome.Rejected),
                D1Values.Int64(expiresAtMicros),
            },
        };
        try
        {
            await executor.ExecuteAsync(PlanCall.New(PlanManifest.Platform.InboxRecord, CommandReceiptStore.PlatformScope, recoveryGeneration, arguments), cancellationToken);
            return true;
        }
        catch (PlanFailureException exception) when (exception.Kind == PlanFailureKind.Constraint)
        {
            return false;
        }
    }
}
