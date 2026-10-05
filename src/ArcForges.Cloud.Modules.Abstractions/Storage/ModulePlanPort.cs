// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

/// <summary>
/// One outbox event a guarded commit writes with its effect (OB-01, OB-02). The payload is one JSON object of at most 4 KiB; the
/// outbox sequence is allocated by the commit itself, never by the caller.
/// </summary>
public sealed record ModuleOutboxEvent(
    Guid OutboxId,
    string AggregateKind,
    Guid AggregateId,
    long AggregateRevision,
    string EventType,
    string PayloadJson,
    Guid? WorkspaceId,
    Guid CorrelationId,
    Guid? CausationId);

/// <summary>
/// What a guarded commit stores beside the module's own mutations: the owner receipt that makes a replay answer with the original result,
/// the outbox events and the change-archive record (D1 profile section 4, the commit tail). The instants are whole UTC microseconds.
/// </summary>
public sealed record ModuleCommit(
    Guid CommandId,
    Guid? WorkspaceId,
    string ActorRef,
    string Operation,
    string RequestHash,
    string ResultPayloadJson,
    long? ResultRevision,
    long CreatedAtMicros,
    long ExpiresAtMicros,
    IReadOnlyList<ModuleOutboxEvent> Events,
    long ChangeSchemaVersion,
    string ChangeRecordJson);

/// <summary>A read of one named plan of the calling module: exact typed arguments for its single statement.</summary>
public sealed record ModulePlanRead(string PlanId, string OwnerScope, IReadOnlyList<PlanValue> Arguments);

/// <summary>
/// A write of one named plan of the calling module. <see cref="OwnerArguments"/> are the arguments of every statement of the plan that
/// precedes its commit tail (its guards and its own mutations), in plan order; <see cref="Commit"/> supplies the tail and the guard
/// release when the plan declares one, and is null for a plan whose header states that it has none.
/// </summary>
public sealed record ModulePlanWrite(string PlanId, string OwnerScope, IReadOnlyList<IReadOnlyList<PlanValue>> OwnerArguments, ModuleCommit? Commit);

/// <summary>What happened to a plan call. Only <see cref="Succeeded"/> means the effect (or the read) happened in this call.</summary>
public enum ModulePlanStatus
{
    /// <summary>The read returned its rows, or the batch committed this call's effect.</summary>
    Succeeded,

    /// <summary>The same command had already committed (a replay, or a response lost after the commit); nothing was executed again and the stored original result is returned.</summary>
    Replayed,

    /// <summary>The same command had already been refused for a stable reason.</summary>
    ReplayedFailure,

    /// <summary>The inbox message was already applied.</summary>
    DuplicateMessage,

    /// <summary>The command identifier exists with different content.</summary>
    ReusedIdentifier,

    /// <summary>The identifier is known but its replay window ended; it is never executed as a new command.</summary>
    ReceiptExpired,

    /// <summary>A guard was false (a stale revision, lease or fence): everything rolled back. Reread, recalculate and send again.</summary>
    GuardRefused,

    /// <summary>A database constraint refused the batch (for example a primary key): everything rolled back.</summary>
    ConstraintRefused,

    /// <summary>The outcome is unknown and no receipt proves a commit: only the same command may be sent again.</summary>
    UnknownOutcome,

    /// <summary>Nothing was executed; the store is overloaded or unreachable. Retry later with the same command.</summary>
    Unavailable,

    /// <summary>The recovery generation of the call is not the current one.</summary>
    StaleGeneration,

    /// <summary>The plan or its arguments were refused before or at execution: a defect or a deployment skew, never a retry.</summary>
    Rejected,
}

/// <summary>The typed result of a plan call. Rows are present only for a read.</summary>
public sealed record ModulePlanOutcome(ModulePlanStatus Status, IReadOnlyList<IReadOnlyList<PlanValue>> Rows, string? StoredResultJson = null)
{
    public static ModulePlanOutcome Of(ModulePlanStatus status) => new(status, []);
}

/// <summary>
/// The one way a module reaches D1: a named, versioned, reviewed plan of its own owner, exact typed arguments in, typed rows or a typed
/// status out. It names no table and no SQL, and the implementation refuses a plan whose owner is not the module it was created for.
/// </summary>
public interface IModulePlanPort
{
    Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken);

    Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken);
}

/// <summary>Creates the plan port of one module. The composition binds it once; a module asks for its own port and no other.</summary>
public interface IModulePlanPortFactory
{
    IModulePlanPort For(ModuleDescriptor module);
}
