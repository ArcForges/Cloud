// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.Receipts;

/// <summary>Stored form of <c>platform_command.status</c> (model 01 section 2; numbers from 1 in listed order).</summary>
internal enum CommandReceiptStatus
{
    InProgress = 1,
    Succeeded = 2,
    Failed = 3,
}

/// <summary>
/// What identifies a command for replay: the caller-allocated id and the fingerprint of its content. A second call
/// with the same id and a different fingerprint, actor, operation or workspace is a reused identifier, never executed.
/// </summary>
internal sealed record CommandIdentity
{
    public CommandIdentity(Guid commandId, Guid? workspaceId, string actorRef, string operation, string requestHash)
    {
        CommandId = commandId == Guid.Empty ? throw new ArgumentException("A command id is never nil.", nameof(commandId)) : commandId;
        WorkspaceId = workspaceId == Guid.Empty ? throw new ArgumentException("A workspace id is never nil.", nameof(workspaceId)) : workspaceId;
        ActorRef = StorageFormats.ShortText(actorRef, nameof(actorRef));
        Operation = StorageFormats.ShortText(operation, nameof(operation));
        RequestHash = StorageFormats.ShortText(requestHash, nameof(requestHash));
    }

    public Guid CommandId { get; }

    public Guid? WorkspaceId { get; }

    public string ActorRef { get; }

    public string Operation { get; }

    public string RequestHash { get; }
}

/// <summary>The receipt a successful guarded write stores with its effect (TX-02): the original response and its resulting revision.</summary>
internal sealed record CommandReceipt
{
    public CommandReceipt(CommandIdentity identity, string resultPayloadJson, long? resultRevision, long createdAtMicros, long expiresAtMicros)
    {
        Identity = identity ?? throw new ArgumentNullException(nameof(identity));
        if (!StorageFormats.IsJson(resultPayloadJson, StorageFormats.MaxJsonBytes, objectRoot: false)) throw new ArgumentException("The result payload is not well-formed JSON within its bound.", nameof(resultPayloadJson));
        if (resultRevision is < 0) throw new ArgumentOutOfRangeException(nameof(resultRevision), "A revision is never negative.");
        if (createdAtMicros <= 0 || expiresAtMicros <= createdAtMicros) throw new ArgumentException("A receipt expires after it is created.", nameof(expiresAtMicros));
        ResultPayloadJson = resultPayloadJson;
        ResultRevision = resultRevision;
        CreatedAtMicros = createdAtMicros;
        ExpiresAtMicros = expiresAtMicros;
    }

    public CommandIdentity Identity { get; }

    public string ResultPayloadJson { get; }

    public long? ResultRevision { get; }

    public long CreatedAtMicros { get; }

    public long ExpiresAtMicros { get; }
}

/// <summary>A receipt as it was read back.</summary>
internal sealed record StoredCommand(
    Guid CommandId,
    Guid? WorkspaceId,
    string ActorRef,
    string Operation,
    string RequestHash,
    CommandReceiptStatus Status,
    string? ResultPayloadJson,
    long? ResultRevision,
    string? ErrorCode,
    long ExpiresAtMicros);

internal enum ReplayKind
{
    /// <summary>No receipt exists: the command has not committed.</summary>
    NotSeen,

    /// <summary>The same command committed: its original result is returned and nothing is executed (TX-03).</summary>
    Replay,

    /// <summary>The same command was refused for a stable reason: the original refusal is returned.</summary>
    ReplayOfFailure,

    /// <summary>The id exists with different content: <c>command.reused_identifier</c>, never executed.</summary>
    ReusedIdentifier,

    /// <summary>The id is known but its replay window has passed: <c>command.receipt_expired</c>, never executed as new.</summary>
    Expired,

    /// <summary>The id is recorded as in progress (never written by an atomic family): the caller waits or reconciles with its owner.</summary>
    InProgress,
}

internal sealed record ReplayDecision(ReplayKind Kind, StoredCommand? Stored);

/// <summary>The replay rules of the command receipt (model 01 section 2, TX-03 to TX-05, command replay retention profile).</summary>
internal static class CommandReplay
{
    public static ReplayDecision Classify(StoredCommand? stored, CommandIdentity request, long nowMicros)
    {
        if (stored is null) return new ReplayDecision(ReplayKind.NotSeen, null);
        // The fingerprint, the actor, the operation and the workspace must all be those of the request. A mismatch of any of them
        // never reveals the stored result: a different actor presenting a known id learns nothing but that it is reused.
        var same = stored.CommandId == request.CommandId
            && stored.WorkspaceId == request.WorkspaceId
            && string.Equals(stored.ActorRef, request.ActorRef, StringComparison.Ordinal)
            && string.Equals(stored.Operation, request.Operation, StringComparison.Ordinal)
            && string.Equals(stored.RequestHash, request.RequestHash, StringComparison.Ordinal);
        if (!same) return new ReplayDecision(ReplayKind.ReusedIdentifier, null);
        if (nowMicros >= stored.ExpiresAtMicros) return new ReplayDecision(ReplayKind.Expired, null);
        return stored.Status switch
        {
            CommandReceiptStatus.Succeeded => new ReplayDecision(ReplayKind.Replay, stored),
            CommandReceiptStatus.Failed => new ReplayDecision(ReplayKind.ReplayOfFailure, stored),
            _ => new ReplayDecision(ReplayKind.InProgress, stored),
        };
    }
}

/// <summary>Reads command receipts and records definite refusals (the success receipt is part of the commit tail).</summary>
internal sealed class CommandReceiptStore(IPlanExecutor executor, ulong recoveryGeneration, TimeProvider time)
{
    /// <summary>Scope of the realm-level platform plans, which key their rows by command id and not by an owner scope.</summary>
    public const string PlatformScope = "platform";

    public async Task<StoredCommand?> LoadAsync(Guid commandId, CancellationToken cancellationToken)
    {
        var call = PlanCall.New(PlanManifest.Platform.CommandLoad, PlatformScope, recoveryGeneration, [[D1Values.Text(StorageFormats.Id(commandId))]]);
        var result = await executor.ExecuteAsync(call, cancellationToken);
        if (result.Rows.Count == 0) return null;
        var row = result.Rows[0];
        if (!D1Values.TryGetText(row[0], out var hash)
            || !D1Values.TryGetInt64(row[1], out var status)
            || status is < 1 or > 3
            || !D1Values.TryGetInt64(row[5], out var expires)
            || !D1Values.TryGetText(row[6], out var actor)
            || !D1Values.TryGetText(row[7], out var operation))
            throw new PlanFailureException(PlanFailureKind.InvalidPlan);
        var payload = D1Values.TryGetText(row[2], out var payloadText) ? payloadText : null;
        var revision = D1Values.TryGetInt64(row[3], out var revisionValue) ? revisionValue : (long?)null;
        var error = D1Values.TryGetText(row[4], out var errorText) ? errorText : null;
        Guid? workspace = null;
        if (D1Values.TryGetText(row[8], out var workspaceText))
        {
            if (!Guid.TryParseExact(workspaceText, "D", out var parsed)) throw new PlanFailureException(PlanFailureKind.InvalidPlan);
            workspace = parsed;
        }

        return new StoredCommand(commandId, workspace, actor, operation, hash, (CommandReceiptStatus)status, payload, revision, error, expires);
    }

    /// <summary>The replay decision for a request, from the stored receipt and the current instant.</summary>
    public async Task<ReplayDecision> ClassifyAsync(CommandIdentity request, CancellationToken cancellationToken) =>
        CommandReplay.Classify(await LoadAsync(request.CommandId, cancellationToken), request, StorageFormats.Micros(time.GetUtcNow()));

    /// <summary>
    /// Records a definite refusal under its command id so that a retry returns the same refusal. Returns false when a receipt already
    /// exists (nothing is written); the caller then classifies the stored receipt.
    /// </summary>
    public async Task<bool> RecordFailureAsync(CommandIdentity identity, string errorCode, long createdAtMicros, long expiresAtMicros, CancellationToken cancellationToken)
    {
        StorageFormats.ShortText(errorCode, nameof(errorCode));
        if (createdAtMicros <= 0 || expiresAtMicros <= createdAtMicros) throw new ArgumentException("A receipt expires after it is created.", nameof(expiresAtMicros));
        var arguments = new[]
        {
            new[]
            {
                D1Values.Text(StorageFormats.Id(identity.CommandId)),
                identity.WorkspaceId is { } workspace ? D1Values.Text(StorageFormats.Id(workspace)) : D1Values.Null(),
                D1Values.Text(identity.ActorRef),
                D1Values.Text(identity.Operation),
                D1Values.Text(identity.RequestHash),
                D1Values.Text(errorCode),
                D1Values.Int64(createdAtMicros),
                D1Values.Int64(expiresAtMicros),
            },
        };
        try
        {
            await executor.ExecuteAsync(PlanCall.New(PlanManifest.Platform.CommandRecordFailure, PlatformScope, recoveryGeneration, arguments), cancellationToken);
            return true;
        }
        catch (PlanFailureException exception) when (exception.Kind == PlanFailureKind.Constraint)
        {
            return false;
        }
    }
}
