// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Storage.Receipts;

internal enum CommitKind
{
    /// <summary>This call's batch committed: the effect, its receipt, outbox rows and change record exist.</summary>
    Committed,

    /// <summary>The same command had already committed (a replay, or a response lost after the commit): the stored original result is returned and nothing was executed.</summary>
    Replayed,

    /// <summary>The same command had already been refused for a stable reason (a failed receipt).</summary>
    ReplayedFailure,

    /// <summary>The inbox key was already applied: the redelivered message changed nothing.</summary>
    DuplicateMessage,

    /// <summary>The command id exists with different content: <c>command.reused_identifier</c>.</summary>
    ReusedIdentifier,

    /// <summary>The id is known but its replay window ended: <c>command.receipt_expired</c>; it is never executed as a new command.</summary>
    ReceiptExpired,

    /// <summary>The guard was false (a stale revision, lease or fence): the batch rolled back completely and nothing was committed. The caller rereads and recalculates under the same command id.</summary>
    GuardFailed,

    /// <summary>The outcome is unknown and no receipt exists yet: the batch may still commit. Only the same command id may be sent again, never a new one.</summary>
    Unknown,
}

internal sealed record CommitOutcome(CommitKind Kind, StoredCommand? Stored);

/// <summary>
/// Runs one guarded write that carries the commit tail and reconciles every non-success with the receipt, which is the only proof of a commit (D1 profile
/// section 4). A guard that fails, a duplicate command id, a duplicate inbox key and an unknown outcome all end in a receipt (or inbox) read, never a blind retry.
/// </summary>
internal sealed class CommitExecutor(IPlanExecutor executor, CommandReceiptStore receipts, InboxStore inbox)
{
    public async Task<CommitOutcome> ExecuteAsync(PlanCall call, CommitTailValues values, CancellationToken cancellationToken)
    {
        var identity = values.Receipt.Identity;
        try
        {
            await executor.ExecuteAsync(call, cancellationToken);
            return new CommitOutcome(CommitKind.Committed, null);
        }
        catch (PlanFailureException exception) when (exception.Kind is PlanFailureKind.Precondition or PlanFailureKind.Constraint)
        {
            // The batch rolled back as a whole. Why: a stale guard, or a duplicate of a command or message that already committed.
            var decision = await receipts.ClassifyAsync(identity, cancellationToken);
            if (decision.Kind != ReplayKind.NotSeen) return FromReplay(decision);
            if (values.Inbox is { } key && await inbox.LoadAsync(key, cancellationToken) is not null) return new CommitOutcome(CommitKind.DuplicateMessage, null);
            if (exception.Kind == PlanFailureKind.Precondition) return new CommitOutcome(CommitKind.GuardFailed, null);
            // A constraint with no receipt and no inbox row is a defect (a value the column refuses), not a replay: it is not hidden.
            throw;
        }
        catch (PlanFailureException exception) when (exception.Kind == PlanFailureKind.UnknownOutcome)
        {
            var decision = await receipts.ClassifyAsync(identity, cancellationToken);
            return decision.Kind == ReplayKind.NotSeen ? new CommitOutcome(CommitKind.Unknown, null) : FromReplay(decision, committedByThisCall: true);
        }
    }

    private static CommitOutcome FromReplay(ReplayDecision decision, bool committedByThisCall = false) => decision.Kind switch
    {
        // After an unknown outcome the receipt is this call's own commit; after a refused batch it is an earlier one.
        ReplayKind.Replay => new CommitOutcome(committedByThisCall ? CommitKind.Committed : CommitKind.Replayed, decision.Stored),
        ReplayKind.ReplayOfFailure => new CommitOutcome(CommitKind.ReplayedFailure, decision.Stored),
        ReplayKind.ReusedIdentifier => new CommitOutcome(CommitKind.ReusedIdentifier, null),
        ReplayKind.Expired => new CommitOutcome(CommitKind.ReceiptExpired, null),
        _ => new CommitOutcome(CommitKind.Unknown, decision.Stored),
    };

    /// <summary>A read of the current receipt before executing, for callers that want to answer a replay without running the plan.</summary>
    public async Task<ReplayDecision> PreflightAsync(CommandIdentity identity, CancellationToken cancellationToken) =>
        await receipts.ClassifyAsync(identity, cancellationToken);
}
