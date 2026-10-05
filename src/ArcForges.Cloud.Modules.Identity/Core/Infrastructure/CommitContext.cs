// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;
using ArcForges.Cloud.Modules.Identity.Core.Domain;

namespace ArcForges.Cloud.Modules.Identity.Core.Infrastructure;

/// <summary>What the coordinator supplies to one commit: the instant, the identifiers of the outbox row and of the correlation, and the schema version of the release.</summary>
internal sealed record CommitContext(UtcMicros Now, string OutboxId, string CorrelationId, string? CausationId, long SchemaVersion)
{
    /// <summary>A receipt is kept for seven days, the command replay retention profile.</summary>
    public const long ReceiptRetentionMicros = 7L * 24 * 60 * 60 * 1_000_000;
}

internal sealed record OutboxEventContent(
    string OutboxId, string AggregateKind, string AggregateId, long AggregateRevision, string EventType, string PayloadJson, string CorrelationId, string? CausationId);

/// <summary>
/// The values of the commit tail (D1 profile section 4): the receipt, the outbox events and the change record of one commit. They carry
/// identifiers, numbers and operation names only: no subject, no secret, no display name and no label.
/// </summary>
internal sealed record TailContent(
    string CommandId,
    string? WorkspaceId,
    string ActorRef,
    string Operation,
    string RequestHash,
    string ResultPayloadJson,
    long? ResultRevision,
    long CreatedAt,
    long ExpiresAt,
    ImmutableArray<OutboxEventContent> Events,
    long SchemaVersion,
    string ChangeRecordJson);

/// <summary>A module write plan call: the plan, the owner scope, the arguments of the plan's own statements in order, and the tail.</summary>
internal sealed record IdentityPlanCall(string PlanId, WorkspaceId Scope, ImmutableArray<ImmutableArray<PlanArgument>> OwnerStatements, TailContent Tail);

/// <summary>The call of the shared family <c>account-enrollment</c>: contributions by module in the guarded-batch grammar, and the tail.</summary>
internal sealed record EnrollmentPlanCall(WorkspaceId Scope, ImmutableArray<StatementContribution> Contributions, TailContent Tail);
