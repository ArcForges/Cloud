// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Application;

/// <summary>The single durable accounting writer. Current authorization precedes replay; measurement
/// and current policy are required for new effects. Unknown writes retain the exact original command.</summary>
internal sealed class QuotaKernel(IQuotaKernelStore store, IQuotaKernelAuthority authority,
    IQuotaMeasurementAuthority measurements, TimeProvider time) : IQuotaKernelPort
{
    public async Task<QuotaReadResult<QuotaBudgetState>> ReadBudgetAsync(QuotaOwnerContext context, QuotaBudgetKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!QuotaRules.Context(context) || !QuotaRules.Key(key) || !QuotaRules.Owns(context, key)) return new(QuotaKernelStatus.Invalid, null);
        var permission = await authority.AuthorizeReadAsync(context, key, null, cancellationToken).ConfigureAwait(false);
        return permission != QuotaAuthorityStatus.Authorized ? new(Auth(permission), null)
            : await store.BudgetAsync(key, cancellationToken).ConfigureAwait(false);
    }

    public async Task<QuotaReadResult<QuotaReservation>> ReadReservationAsync(QuotaOwnerContext context, Guid reservationId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!QuotaRules.Context(context) || reservationId == Guid.Empty) return new(QuotaKernelStatus.Invalid, null);
        var permission = await authority.AuthorizeReadAsync(context, null, reservationId, cancellationToken).ConfigureAwait(false);
        return permission != QuotaAuthorityStatus.Authorized ? new(Auth(permission), null)
            : await store.ReservationAsync(context, reservationId, cancellationToken).ConfigureAwait(false);
    }

    public async Task<QuotaKernelResult> PublishBudgetAsync(QuotaBudgetCommand command, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (command is null || !QuotaRules.Budget(command)) return new(QuotaKernelStatus.Invalid);
        const string operation = "entitlement.quota-budget";
        var change = command.Change;
        var content = QuotaRules.Canonical(operation, command.Context, writer =>
        {
            QuotaRules.WriteKey(writer, change.Key); writer.WriteString("unit", change.Unit);
            N(writer, "limit", change.Limit); N(writer, "policyVersion", change.PolicyVersion); N(writer, "revision", change.ExpectedRevision);
        });
        var prior = await Begin(command.Context, command.CommandId, QuotaKernelOperation.PublishBudget, operation, content.Hash, cancellationToken).ConfigureAwait(false);
        if (prior is not null) return prior;
        var permission = await authority.AuthorizeBudgetAsync(command, cancellationToken).ConfigureAwait(false);
        if (permission != QuotaAuthorityStatus.Authorized) return new(Auth(permission));
        var loaded = await store.BudgetAsync(change.Key, cancellationToken).ConfigureAwait(false);
        if (loaded.Status is not (QuotaKernelStatus.Succeeded or QuotaKernelStatus.NotFound)) return new(loaded.Status);
        var old = loaded.Value;
        if (old is null ? change.ExpectedRevision != 0
            : old.Revision != change.ExpectedRevision || old.Unit != change.Unit || change.PolicyVersion < old.PolicyVersion
              || change.PolicyVersion == old.PolicyVersion && change.Limit != old.Limit) return new(QuotaKernelStatus.Conflict);
        var state = new QuotaBudgetState(change.Key, change.Unit, change.Limit, old?.Used ?? 0, old?.Held ?? 0, change.PolicyVersion, change.ExpectedRevision + 1);
        IReadOnlyList<PlanValue> values = [I((int)change.Key.ScopeKind), T(change.Key.ScopeId), T(change.Key.QuotaKey), T(change.Key.PeriodKey),
            T(change.Unit), I(change.Limit), I(change.PolicyVersion), I(change.ExpectedRevision)];
        return await Commit(command.Context, command.CommandId, operation, content, "entitlement.quota-kernel-publish", change.Key.ScopeId,
            [[T(command.CommandId.ToString("D")), .. values], values], new(QuotaKernelStatus.Succeeded, [state]), cancellationToken).ConfigureAwait(false);
    }

    public async Task<QuotaKernelResult> ReserveAsync(QuotaAdmissionCommand command, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Structural validation precedes replay, but elapsed admission/lease times cannot turn a known
        // successful identifier into a fresh write or prevent recovery of its original receipt.
        if (command?.Items is null || command.Items.Count is <= 0 or > 8) return new(QuotaKernelStatus.Invalid);
        // A read-only interface may wrap a mutable caller list. Capture one immutable command
        // before hashing or awaiting authority; the approved items and committed items must agree.
        command = command with { Items = Array.AsReadOnly(command.Items.ToArray()) };
        if (!QuotaRules.Admission(command, 0)) return new(QuotaKernelStatus.Invalid);
        const string operation = "entitlement.quota-reserve";
        var ordered = command.Items.OrderBy(item => QuotaRules.SortKey(item.Key), StringComparer.Ordinal).ToArray();
        var items = Json(writer =>
        {
            writer.WriteStartArray();
            foreach (var item in ordered)
            {
                writer.WriteStartObject(); QuotaRules.WriteKey(writer, item.Key); writer.WriteString("reservationId", item.ReservationId.ToString("D"));
                N(writer, "bound", item.Bound); N(writer, "policyVersion", item.PolicyVersion); N(writer, "revision", item.ExpectedRevision);
                N(writer, "admissionCeiling", item.AdmissionCeiling); writer.WriteEndObject();
            }
            writer.WriteEndArray();
        });
        var content = QuotaRules.Canonical(operation, command.Context, writer =>
        {
            writer.WriteString("operationId", command.OperationId.ToString("D")); N(writer, "expiresAt", command.ExpiresAtMicros);
            QuotaRules.WriteLease(writer, command.JobLease);
            writer.WritePropertyName("items"); writer.WriteRawValue(items);
        });
        var prior = await Begin(command.Context, command.CommandId, QuotaKernelOperation.Reserve, operation, content.Hash, cancellationToken).ConfigureAwait(false);
        if (prior is not null) return prior;
        var now = QuotaRules.Now(time);
        if (!QuotaRules.Admission(command, now)) return new(QuotaKernelStatus.Invalid, Reason: "admission_expired");
        var permission = await authority.AuthorizeAdmissionAsync(command, cancellationToken).ConfigureAwait(false);
        if (permission != QuotaAuthorityStatus.Authorized) return new(Auth(permission));
        var budgets = new List<QuotaBudgetState>();
        var reservations = new List<QuotaReservation>();
        foreach (var item in ordered)
        {
            var read = await store.BudgetAsync(item.Key, cancellationToken).ConfigureAwait(false);
            if (read.Status != QuotaKernelStatus.Succeeded) return new(read.Status);
            var budget = read.Value!;
            if (budget.Revision != item.ExpectedRevision || budget.PolicyVersion != item.PolicyVersion) return new(QuotaKernelStatus.Conflict);
            var ceiling = Math.Min(budget.Limit, item.AdmissionCeiling ?? budget.Limit);
            if (ceiling < item.Bound || budget.Used > ceiling - item.Bound || budget.Held > ceiling - item.Bound - budget.Used)
                return new(QuotaKernelStatus.LimitExceeded);
            budgets.Add(budget with { Held = budget.Held + item.Bound, Revision = budget.Revision + 1 });
            reservations.Add(new(item.ReservationId, command.OperationId, item.Key, command.Context.OwnerKind, command.Context.OwnerId,
                item.Bound, 0, QuotaReservationState.Held, command.ExpiresAtMicros, command.JobLease?.LeasedUntilMicros, command.JobLease?.Fence));
        }
        var guard = Json(writer =>
        {
            writer.WriteStartObject(); writer.WritePropertyName("items"); writer.WriteRawValue(items);
            QuotaRules.WriteOwnerBinding(writer, command.Context);
            QuotaRules.WriteLease(writer, command.JobLease); N(writer, "now", now); writer.WriteEndObject();
        });
        IReadOnlyList<IReadOnlyList<PlanValue>> arguments =
        [
            [T(command.CommandId.ToString("D")), T(guard), T(QuotaRules.Scope(command.Context))], [T(items), T(items)],
            [T(command.OperationId.ToString("D")), T(command.Context.OwnerKind), T(command.Context.OwnerId.ToString("D")), I(command.ExpiresAtMicros),
                I(command.JobLease?.LeasedUntilMicros ?? -1), I(command.JobLease?.Fence ?? -1), T(items)],
        ];
        return await Commit(command.Context, command.CommandId, operation, content, "entitlement.quota-kernel-reserve", QuotaRules.Scope(command.Context),
            arguments, new(QuotaKernelStatus.Succeeded, budgets, reservations), cancellationToken).ConfigureAwait(false);
    }

    public async Task<QuotaKernelResult> ApplyAsync(QuotaEffectCommand command, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (command is null || !QuotaRules.Effect(command)) return new(QuotaKernelStatus.Invalid);
        const string operation = "entitlement.quota-effect";
        var measure = command.Measurement;
        var content = QuotaRules.Canonical(operation, command.Context, writer =>
        {
            writer.WriteString("reservationId", command.ReservationId.ToString("D")); N(writer, "revision", command.ExpectedBudgetRevision);
            QuotaRules.WriteLease(writer, command.JobLease); writer.WriteBoolean("complete", command.Complete);
            writer.WriteString("effectId", measure.EffectId.ToString("D")); N(writer, "kind", (int)measure.Kind); N(writer, "quantity", measure.Quantity);
            QuotaRules.Id(writer, "objectId", measure.SourceObjectId); QuotaRules.Id(writer, "segmentId", measure.SourceSegmentId);
            QuotaRules.Id(writer, "deletionId", measure.DeletionReceiptId);
        });
        var prior = await Begin(command.Context, command.CommandId, QuotaKernelOperation.ApplyEffect, operation, content.Hash, cancellationToken).ConfigureAwait(false);
        if (prior is not null) return prior;
        var read = await store.ReservationAsync(command.Context, command.ReservationId, cancellationToken).ConfigureAwait(false);
        if (read.Status != QuotaKernelStatus.Succeeded) return new(read.Status);
        var reservation = read.Value!;
        var permission = await authority.AuthorizeEffectAsync(command, reservation, cancellationToken).ConfigureAwait(false);
        if (permission != QuotaAuthorityStatus.Authorized) return new(Auth(permission));
        permission = await measurements.VerifyAsync(command.Context, reservation, measure, cancellationToken).ConfigureAwait(false);
        if (permission != QuotaAuthorityStatus.Authorized) return new(Auth(permission));
        var loaded = await store.BudgetAsync(reservation.Key, cancellationToken).ConfigureAwait(false);
        if (loaded.Status != QuotaKernelStatus.Succeeded) return new(loaded.Status);
        var budget = loaded.Value!;
        var now = QuotaRules.Now(time);
        if (budget.Revision != command.ExpectedBudgetRevision || budget.Revision == long.MaxValue || !CurrentLease(reservation, command.JobLease, now))
            return new(QuotaKernelStatus.Conflict);
        var remaining = reservation.Bound - reservation.Consumed;
        QuotaBudgetState nextBudget;
        QuotaReservation nextReservation;
        if (measure.Kind == QuotaEffectKind.Consume)
        {
            if (reservation.State != QuotaReservationState.Held || reservation.ExpiresAtMicros <= now
                || measure.Quantity > remaining || budget.Used > long.MaxValue - measure.Quantity)
                return new(QuotaKernelStatus.Conflict);
            var heldDebit = command.Complete ? remaining : measure.Quantity;
            if (budget.Held < heldDebit) return new(QuotaKernelStatus.Conflict);
            nextBudget = budget with { Used = budget.Used + measure.Quantity, Held = budget.Held - heldDebit, Revision = budget.Revision + 1 };
            nextReservation = reservation with
            {
                Consumed = reservation.Consumed + measure.Quantity,
                State = command.Complete || measure.Quantity == remaining ? QuotaReservationState.Settled : QuotaReservationState.Held
            };
        }
        else if (measure.Kind == QuotaEffectKind.Release)
        {
            if (reservation.State is not (QuotaReservationState.Held or QuotaReservationState.Releasing) || !command.Complete
                || measure.Quantity != remaining || budget.Held < remaining) return new(QuotaKernelStatus.Conflict);
            nextBudget = budget with { Held = budget.Held - remaining, Revision = budget.Revision + 1 };
            nextReservation = reservation with { State = QuotaReservationState.Released };
        }
        else
        {
            if (measure.Quantity < 0 ? budget.Used < -measure.Quantity : budget.Used > long.MaxValue - measure.Quantity)
                return new(QuotaKernelStatus.Conflict);
            nextBudget = budget with { Used = budget.Used + measure.Quantity, Revision = budget.Revision + 1 };
            nextReservation = reservation;
        }
        nextReservation = nextReservation with { LeaseUntilMicros = command.JobLease?.LeasedUntilMicros, Fence = command.JobLease?.Fence };
        var payload = MutationPayload(command.Context, reservation, budget, nextReservation, nextBudget, command.JobLease, now, writer =>
        {
            writer.WriteString("effectId", measure.EffectId.ToString("D")); N(writer, "kind", (int)measure.Kind); N(writer, "quantity", measure.Quantity);
            QuotaRules.Id(writer, "objectId", measure.SourceObjectId); QuotaRules.Id(writer, "segmentId", measure.SourceSegmentId);
            QuotaRules.Id(writer, "deletionId", measure.DeletionReceiptId); writer.WriteBoolean("complete", command.Complete);
        });
        return await Commit(command.Context, command.CommandId, operation, content, "entitlement.quota-kernel-effect", reservation.Key.ScopeId,
            [[T(command.CommandId.ToString("D")), T(payload), T(reservation.Key.ScopeId)], [T(payload)], [T(payload)], [T(payload)]],
            new(QuotaKernelStatus.Succeeded, [nextBudget], [nextReservation]), cancellationToken).ConfigureAwait(false);
    }

    public async Task<QuotaKernelResult> RequestCleanupAsync(QuotaCleanupCommand command, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (command is null || !QuotaRules.Cleanup(command)) return new(QuotaKernelStatus.Invalid);
        const string operation = "entitlement.quota-cleanup";
        var content = QuotaRules.Canonical(operation, command.Context, writer =>
        {
            writer.WriteString("reservationId", command.ReservationId.ToString("D")); N(writer, "revision", command.ExpectedBudgetRevision); QuotaRules.WriteLease(writer, command.JobLease);
        });
        var prior = await Begin(command.Context, command.CommandId, QuotaKernelOperation.RequestCleanup, operation, content.Hash, cancellationToken).ConfigureAwait(false);
        if (prior is not null) return prior;
        var read = await store.ReservationAsync(command.Context, command.ReservationId, cancellationToken).ConfigureAwait(false);
        if (read.Status != QuotaKernelStatus.Succeeded) return new(read.Status);
        var reservation = read.Value!;
        var permission = await authority.AuthorizeCleanupAsync(command, reservation, cancellationToken).ConfigureAwait(false);
        if (permission != QuotaAuthorityStatus.Authorized) return new(Auth(permission));
        var loaded = await store.BudgetAsync(reservation.Key, cancellationToken).ConfigureAwait(false);
        if (loaded.Status != QuotaKernelStatus.Succeeded) return new(loaded.Status);
        var budget = loaded.Value!;
        var now = QuotaRules.Now(time);
        if (budget.Revision != command.ExpectedBudgetRevision || budget.Revision == long.MaxValue || !CurrentLease(reservation, command.JobLease, now)
            || reservation.State is not (QuotaReservationState.Held or QuotaReservationState.Releasing)) return new(QuotaKernelStatus.Conflict);
        // Moving to Releasing is durable intent only. Physical Used and admission Held remain charged
        // until verified owner termination/deletion evidence arrives through ApplyAsync.
        var nextBudget = budget with { Revision = budget.Revision + 1 };
        var nextReservation = reservation with { State = QuotaReservationState.Releasing, LeaseUntilMicros = command.JobLease?.LeasedUntilMicros, Fence = command.JobLease?.Fence };
        var payload = MutationPayload(command.Context, reservation, budget, nextReservation, nextBudget, command.JobLease, now, _ => { });
        return await Commit(command.Context, command.CommandId, operation, content, "entitlement.quota-kernel-cleanup", reservation.Key.ScopeId,
            [[T(command.CommandId.ToString("D")), T(payload), T(reservation.Key.ScopeId)], [T(payload)], [T(payload)]],
            new(QuotaKernelStatus.Succeeded, [nextBudget], [nextReservation]), cancellationToken).ConfigureAwait(false);
    }

    private async Task<QuotaKernelResult?> Begin(QuotaOwnerContext context, Guid commandId, QuotaKernelOperation kind, string operation,
        string hash, CancellationToken cancellationToken)
    {
        var permission = await authority.AuthorizeCommandAsync(context, kind, cancellationToken).ConfigureAwait(false);
        if (permission != QuotaAuthorityStatus.Authorized) return new(Auth(permission));
        var read = await store.ReceiptAsync(context, commandId, cancellationToken).ConfigureAwait(false);
        if (read.Status == QuotaKernelStatus.NotFound) return null;
        if (read.Status != QuotaKernelStatus.Succeeded) return new(read.Status);
        var receipt = read.Value!;
        if (receipt.ActorRef != context.ActorRef || receipt.Operation != operation || receipt.RequestHash != hash) return new(QuotaKernelStatus.ReusedIdentifier);
        if (receipt.ExpiresAtMicros <= QuotaRules.Now(time)) return new(QuotaKernelStatus.ReceiptExpired);
        if (receipt.Status == 3) return new(QuotaKernelStatus.Conflict);
        var decoded = QuotaResultCodec.Decode(receipt.ResultJson);
        return decoded.Status == QuotaKernelStatus.Succeeded ? decoded with { Status = QuotaKernelStatus.Replayed } : new(QuotaKernelStatus.Conflict);
    }

    private async Task<QuotaKernelResult> Commit(QuotaOwnerContext context, Guid commandId, string operation, (string Json, string Hash) content,
        string plan, string scope, IReadOnlyList<IReadOnlyList<PlanValue>> arguments, QuotaKernelResult result, CancellationToken cancellationToken)
    {
        var now = Math.Max(QuotaRules.Now(time), 1);
        var archive = Json(writer =>
        {
            writer.WriteStartObject(); writer.WriteString("kind", operation); writer.WritePropertyName("command"); writer.WriteRawValue(content.Json);
            writer.WritePropertyName("result"); writer.WriteRawValue(QuotaResultCodec.Encode(result)); writer.WriteEndObject();
        });
        var commit = new ModuleCommit(commandId, context.WorkspaceId, context.ActorRef, operation, content.Hash, QuotaResultCodec.Encode(result),
            null, now, checked(now + 604800000000), [], 1, archive);
        for (var attempt = 0; ; attempt++)
        {
            var outcome = await store.WriteAsync(plan, scope, arguments, commit, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (outcome.Status == ModulePlanStatus.Succeeded) return result;
            if (outcome.Status == ModulePlanStatus.Replayed)
            {
                var decoded = QuotaResultCodec.Decode(outcome.StoredResultJson);
                return decoded.Status == QuotaKernelStatus.Succeeded ? decoded with { Status = QuotaKernelStatus.Replayed } : new(QuotaKernelStatus.Conflict);
            }
            if (attempt >= 2 || outcome.Status is not (ModulePlanStatus.Unavailable or ModulePlanStatus.UnknownOutcome))
                return new(QuotaRules.Status(outcome.Status));
            // The shared signed adapter reconciles the receipt before UnknownOutcome. Retry only the
            // same immutable batch; never choose a new identifier or remeasure after an ambiguous write.
            await Task.Delay(TimeSpan.FromMilliseconds(25 * (1 << attempt)), time, cancellationToken).ConfigureAwait(false);
        }
    }

    private static string MutationPayload(QuotaOwnerContext context, QuotaReservation oldReservation, QuotaBudgetState oldBudget,
        QuotaReservation nextReservation, QuotaBudgetState nextBudget, CapacityJobLease? jobLease, long now, Action<Utf8JsonWriter> extra) => Json(writer =>
    {
        writer.WriteStartObject(); QuotaRules.WriteKey(writer, oldBudget.Key);
        writer.WriteString("reservationId", oldReservation.ReservationId.ToString("D")); QuotaRules.WriteOwnerBinding(writer, context);
        N(writer, "revision", oldBudget.Revision);
        N(writer, "oldUsed", oldBudget.Used); N(writer, "oldHeld", oldBudget.Held); N(writer, "oldConsumed", oldReservation.Consumed);
        N(writer, "oldState", (int)oldReservation.State); N(writer, "bound", oldReservation.Bound); N(writer, "oldFence", oldReservation.Fence);
        QuotaRules.WriteLease(writer, jobLease);
        N(writer, "used", nextBudget.Used); N(writer, "held", nextBudget.Held); N(writer, "consumed", nextReservation.Consumed);
        N(writer, "state", (int)nextReservation.State); N(writer, "now", now); extra(writer); writer.WriteEndObject();
    });
    private static bool CurrentLease(QuotaReservation reservation, CapacityJobLease? lease, long now) => reservation.Fence is null
        ? lease is null : lease is not null && QuotaRules.Lease(lease, long.MaxValue, now) && lease.Fence >= reservation.Fence;
    private static QuotaKernelStatus Auth(QuotaAuthorityStatus status) => status switch
    {
        QuotaAuthorityStatus.Unavailable => QuotaKernelStatus.Unavailable,
        QuotaAuthorityStatus.Stale => QuotaKernelStatus.StaleGeneration,
        _ => QuotaKernelStatus.Denied,
    };
    private static PlanValue T(string value) => PlanValue.FromText(value);
    private static PlanValue I(long value) => PlanValue.FromInt64(value);
    private static void N(Utf8JsonWriter writer, string name, long value) => QuotaRules.Number(writer, name, value);
    private static void N(Utf8JsonWriter writer, string name, long? value) => QuotaRules.Number(writer, name, value);
    private static string Json(Action<Utf8JsonWriter> write)
    {
        using var bytes = new MemoryStream();
        using (var writer = new Utf8JsonWriter(bytes)) write(writer);
        return System.Text.Encoding.UTF8.GetString(bytes.ToArray());
    }
}
