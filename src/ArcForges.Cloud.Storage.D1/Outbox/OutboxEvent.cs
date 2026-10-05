// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage.Receipts;

namespace ArcForges.Cloud.Storage.Outbox;

/// <summary>Stored form of <c>platform_outbox.state</c> (model 01 section 2; numbers from 1 in listed order).</summary>
internal enum OutboxState
{
    Pending = 1,
    Dispatched = 2,
    DeadLettered = 3,
}

/// <summary>
/// One outbox row written by the commit tail (OB-01, OB-02): the aggregate it concerns, the aggregate revision after the change, the event,
/// its payload and the correlation and causation identifiers. The payload is bounded (4 KiB) because a publisher reads it back in pages.
/// </summary>
internal sealed record OutboxEvent
{
    public OutboxEvent(Guid outboxId, string aggregateKind, Guid aggregateId, long aggregateRevision, string eventType, string payloadJson, Guid? workspaceId, Guid correlationId, Guid? causationId)
    {
        OutboxId = outboxId == Guid.Empty ? throw new ArgumentException("An outbox id is never nil.", nameof(outboxId)) : outboxId;
        AggregateId = aggregateId == Guid.Empty ? throw new ArgumentException("An aggregate id is never nil.", nameof(aggregateId)) : aggregateId;
        CorrelationId = correlationId == Guid.Empty ? throw new ArgumentException("A correlation id is never nil.", nameof(correlationId)) : correlationId;
        WorkspaceId = workspaceId == Guid.Empty ? throw new ArgumentException("A workspace id is never nil.", nameof(workspaceId)) : workspaceId;
        CausationId = causationId == Guid.Empty ? throw new ArgumentException("A causation id is never nil.", nameof(causationId)) : causationId;
        if (aggregateRevision < 0) throw new ArgumentOutOfRangeException(nameof(aggregateRevision), "A revision is never negative.");
        AggregateKind = StorageFormats.ShortText(aggregateKind, nameof(aggregateKind));
        EventType = StorageFormats.ShortText(eventType, nameof(eventType));
        if (!StorageFormats.IsJson(payloadJson, StorageFormats.MaxEventPayloadBytes, objectRoot: true)) throw new ArgumentException("An outbox payload is one well-formed JSON object of at most 4 KiB.", nameof(payloadJson));
        AggregateRevision = aggregateRevision;
        PayloadJson = payloadJson;
    }

    public Guid OutboxId { get; }

    public string AggregateKind { get; }

    public Guid AggregateId { get; }

    public long AggregateRevision { get; }

    public string EventType { get; }

    public string PayloadJson { get; }

    public Guid? WorkspaceId { get; }

    public Guid CorrelationId { get; }

    public Guid? CausationId { get; }
}
