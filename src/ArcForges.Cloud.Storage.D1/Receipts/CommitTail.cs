// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage.Archive;
using ArcForges.Cloud.Storage.Outbox;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.Receipts;

/// <summary>Everything one guarded commit stores beside its own mutations: the receipt, the outbox events, the change record and, for a consumer, the inbox claim.</summary>
internal sealed record CommitTailValues
{
    public CommitTailValues(CommandReceipt receipt, IReadOnlyList<OutboxEvent> events, ChangeRecord change, InboxKey? inbox = null, long inboxExpiresAtMicros = 0)
    {
        Receipt = receipt ?? throw new ArgumentNullException(nameof(receipt));
        Events = events ?? throw new ArgumentNullException(nameof(events));
        Change = change ?? throw new ArgumentNullException(nameof(change));
        if (events.Count > CommitTail.MaxEvents) throw new ArgumentException($"A commit carries at most {CommitTail.MaxEvents} outbox events.", nameof(events));
        if (events.Select(e => e.OutboxId).Distinct().Count() != events.Count) throw new ArgumentException("Outbox ids are distinct.", nameof(events));
        if (inbox is not null) InboxRetention.Require(receipt.CreatedAtMicros, inboxExpiresAtMicros);
        Inbox = inbox;
        InboxExpiresAtMicros = inboxExpiresAtMicros;
    }

    public CommandReceipt Receipt { get; }

    public IReadOnlyList<OutboxEvent> Events { get; }

    public ChangeRecord Change { get; }

    public InboxKey? Inbox { get; }

    public long InboxExpiresAtMicros { get; }
}

internal readonly record struct TailStatementKinds(string Role, IReadOnlyList<PlanParam> Params);

/// <summary>
/// The commit tail (D1 profile section 4): the canonical statements that follow a plan's own mutations, then the guard release that ends every plan
/// that uses guard rows. The SQL is fixed text that the plan generator verifies in every module write plan (eng/verification/commit-tail.ts); this
/// class builds the matching arguments and refuses a plan whose trailing statements do not have the canonical parameter kinds, before anything is sent.
/// The guard statements that open a plan, and the release when a family plan generates it, belong to the guarded-batch engine.
/// </summary>
internal static class CommitTail
{
    public const int MaxEvents = 16;

    private static readonly PlanParam TextParam = new(PlanKind.Text);
    private static readonly PlanParam NullableText = new(PlanKind.Text, true);
    private static readonly PlanParam Int64Param = new(PlanKind.Int64);
    private static readonly PlanParam ScopeParam = new(PlanKind.Scope);
    private static readonly PlanParam BytesParam = new(PlanKind.Bytes);

    /// <summary>The tail statements, without the release.</summary>
    public static int StatementCount(int events, bool inbox) => (inbox ? 1 : 0) + 1 + (3 * events) + 2;

    /// <summary>The guard release, the last statement of every plan that uses guard rows.</summary>
    public static TailStatementKinds ReleaseKinds { get; } = new("guard-release", [TextParam]);

    /// <summary>The canonical statements, in order, with their parameter kinds (shared with the plan generator through Vectors/commit-tail.json).</summary>
    public static IReadOnlyList<TailStatementKinds> Kinds(int events, bool inbox)
    {
        if (events is < 0 or > MaxEvents) throw new ArgumentOutOfRangeException(nameof(events));
        var list = new List<TailStatementKinds>(StatementCount(events, inbox));
        if (inbox) list.Add(new("inbox", [TextParam, TextParam, Int64Param, Int64Param, Int64Param]));
        list.Add(new("receipt", [TextParam, NullableText, TextParam, TextParam, TextParam, TextParam, Int64Param, Int64Param, Int64Param]));
        for (var index = 0; index < events; index++)
        {
            list.Add(new("stream", [ScopeParam, Int64Param]));
            list.Add(new("outbox", [TextParam, TextParam, TextParam, Int64Param, TextParam, TextParam, NullableText, TextParam, NullableText, Int64Param]));
            list.Add(new("position", [TextParam, ScopeParam, ScopeParam]));
        }

        list.Add(new("archive-stream", [Int64Param]));
        list.Add(new("archive", [TextParam, Int64Param, TextParam, BytesParam, Int64Param]));
        return list;
    }

    /// <summary>The arguments of the tail statements. The outbox stream is the owner scope of the call.</summary>
    public static D1Scalar[][] Arguments(string ownerScope, CommitTailValues values)
    {
        if (!StorageFormats.IsOwnerStreamScope(ownerScope)) throw new ArgumentException("The owner scope is not a valid outbox stream key.", nameof(ownerScope));
        var identity = values.Receipt.Identity;
        var commandId = StorageFormats.Id(identity.CommandId);
        var now = values.Receipt.CreatedAtMicros;
        var list = new List<D1Scalar[]>(StatementCount(values.Events.Count, values.Inbox is not null));
        if (values.Inbox is { } inbox)
            list.Add([D1Values.Text(inbox.Source), D1Values.Text(inbox.StoredMessageId), D1Values.Int64(now), D1Values.Int64(now), D1Values.Int64(values.InboxExpiresAtMicros)]);
        list.Add(
        [
            D1Values.Text(commandId),
            Nullable(StorageFormats.Id(identity.WorkspaceId)),
            D1Values.Text(identity.ActorRef),
            D1Values.Text(identity.Operation),
            D1Values.Text(identity.RequestHash),
            D1Values.Text(values.Receipt.ResultPayloadJson),
            // A null resulting revision is the sentinel -1 (a revision is never negative); the SQL turns it back into NULL.
            D1Values.Int64(values.Receipt.ResultRevision ?? -1),
            D1Values.Int64(now),
            D1Values.Int64(values.Receipt.ExpiresAtMicros),
        ]);
        foreach (var e in values.Events)
        {
            var outboxId = StorageFormats.Id(e.OutboxId);
            list.Add([D1Values.Text(ownerScope), D1Values.Int64(now)]);
            list.Add(
            [
                D1Values.Text(outboxId),
                D1Values.Text(e.AggregateKind),
                D1Values.Text(StorageFormats.Id(e.AggregateId)),
                D1Values.Int64(e.AggregateRevision),
                D1Values.Text(e.EventType),
                D1Values.Text(e.PayloadJson),
                Nullable(StorageFormats.Id(e.WorkspaceId)),
                D1Values.Text(StorageFormats.Id(e.CorrelationId)),
                Nullable(StorageFormats.Id(e.CausationId)),
                D1Values.Int64(now),
            ]);
            list.Add([D1Values.Text(outboxId), D1Values.Text(ownerScope), D1Values.Text(ownerScope)]);
        }

        list.Add([D1Values.Int64(now)]);
        list.Add([D1Values.Text(commandId), D1Values.Int64(values.Change.SchemaVersion), D1Values.Text(values.Change.RecordJson), D1Values.Bytes(values.Change.Hash()), D1Values.Int64(now)]);
        return [.. list];
    }

    /// <summary>The arguments of the guard release for a command.</summary>
    public static D1Scalar[] Release(Guid commandId) => [D1Values.Text(StorageFormats.Id(commandId))];

    /// <summary>
    /// The complete argument list of a module write plan: the guard statements and the module's own mutations (<paramref name="ownerArguments"/>) followed by the
    /// tail and the guard release. The plan must be exactly that many statements with the canonical kinds at its end, and its first guard must carry the
    /// receipt's command id.
    /// </summary>
    public static D1Scalar[][] Bind(PlanDefinition plan, string ownerScope, D1Scalar[][] ownerArguments, CommitTailValues values)
    {
        if (plan.Access != PlanAccess.Write || ownerArguments.Length < 2) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        var kinds = Kinds(values.Events.Count, values.Inbox is not null);
        if (plan.Statements.Count != ownerArguments.Length + kinds.Count + 1) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        for (var index = 0; index < kinds.Count; index++)
        {
            var actual = plan.Statements[ownerArguments.Length + index];
            if (!SameKinds(actual.Params, kinds[index].Params)) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        }

        if (!SameKinds(plan.Statements[^1].Params, ReleaseKinds.Params)) throw new PlanFailureException(PlanFailureKind.InvalidPlan);

        if (ownerArguments[0].Length == 0 || !D1Values.TryGetText(ownerArguments[0][0], out var guardId) || guardId != StorageFormats.Id(values.Receipt.Identity.CommandId))
            throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        return [.. ownerArguments, .. Arguments(ownerScope, values), Release(values.Receipt.Identity.CommandId)];
    }

    private static D1Scalar Nullable(string? value) => value is null ? D1Values.Null() : D1Values.Text(value);

    private static bool SameKinds(IReadOnlyList<PlanParam> left, IReadOnlyList<PlanParam> right)
    {
        if (left.Count != right.Count) return false;
        for (var index = 0; index < left.Count; index++)
        {
            if (left[index] != right[index]) return false;
        }

        return true;
    }
}
