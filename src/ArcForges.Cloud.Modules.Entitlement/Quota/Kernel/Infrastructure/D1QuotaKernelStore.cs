// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Application;
using ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Infrastructure;

internal sealed class D1QuotaKernelStore(IModulePlanPort plans) : IQuotaKernelStore
{
    public Task<QuotaReadResult<QuotaBudgetState>> BudgetAsync(QuotaBudgetKey key, CancellationToken cancellationToken) =>
        ReadAsync(new("entitlement.quota-kernel-budget", key.ScopeId,
            [I((int)key.ScopeKind), T(key.ScopeId), T(key.QuotaKey), T(key.PeriodKey)]), row =>
        {
            if (row.Count != 10) throw new FormatException();
            var value = new QuotaBudgetState(new((QuotaScopeKind)row[0].AsInt64(), row[1].AsText(), row[2].AsText(), row[3].AsText()),
                row[4].AsText(), row[5].AsInt64(), row[6].AsInt64(), row[7].AsInt64(), row[8].AsInt64(), row[9].AsInt64());
            if (!QuotaRules.State(value) || value.Key != key) throw new FormatException();
            return value;
        }, cancellationToken);

    public Task<QuotaReadResult<QuotaReservation>> ReservationAsync(QuotaOwnerContext context, Guid reservationId, CancellationToken cancellationToken) =>
        ReadAsync(new("entitlement.quota-kernel-reservation", QuotaRules.Scope(context),
            [T(reservationId.ToString("D")), T(context.OwnerKind), T(context.OwnerId.ToString("D")), T(QuotaRules.Scope(context))]), row =>
        {
            if (row.Count != 14) throw new FormatException();
            var value = new QuotaReservation(Guid.ParseExact(row[0].AsText(), "D"), Guid.ParseExact(row[1].AsText(), "D"),
                new((QuotaScopeKind)row[2].AsInt64(), row[3].AsText(), row[4].AsText(), row[5].AsText()), row[6].AsText(), Guid.ParseExact(row[7].AsText(), "D"),
                row[8].AsInt64(), row[9].AsInt64(), (QuotaReservationState)row[10].AsInt64(), row[11].AsInt64(), row[12].AsOptionalInt64(), row[13].AsOptionalInt64());
            if (!QuotaRules.State(value) || value.ReservationId != reservationId || !QuotaRules.Matches(context, value)) throw new FormatException();
            return value;
        }, cancellationToken);

    public Task<QuotaReadResult<QuotaCommandReceipt>> ReceiptAsync(QuotaOwnerContext context, Guid commandId, CancellationToken cancellationToken) =>
        ReadAsync(new("entitlement.quota-kernel-command", QuotaRules.Scope(context),
            [T(commandId.ToString("D")), T(QuotaRules.Scope(context)), T(context.ActorRef)]), row =>
        {
            if (row.Count != 6 || row[3].AsInt64() is not (2 or 3) || row[5].AsInt64() < 0) throw new FormatException();
            return new QuotaCommandReceipt(row[0].AsText(), row[1].AsText(), row[2].AsText(), row[3].AsInt64(), row[4].AsOptionalText(), row[5].AsInt64());
        }, cancellationToken);

    public Task<ModulePlanOutcome> WriteAsync(string plan, string scope, IReadOnlyList<IReadOnlyList<PlanValue>> arguments,
        ModuleCommit commit, CancellationToken cancellationToken) => plans.WriteAsync(new(plan, scope, arguments, commit), cancellationToken);

    private async Task<QuotaReadResult<TValue>> ReadAsync<TValue>(ModulePlanRead read, Func<IReadOnlyList<PlanValue>, TValue> decode, CancellationToken cancellationToken)
    {
        var outcome = await plans.ReadAsync(read, cancellationToken).ConfigureAwait(false);
        if (outcome.Status != ModulePlanStatus.Succeeded) return new(QuotaRules.Status(outcome.Status), default);
        if (outcome.Rows.Count == 0) return new(QuotaKernelStatus.NotFound, default);
        try { return new(QuotaKernelStatus.Succeeded, decode(outcome.Rows.Single())); }
        catch (Exception error) when (error is FormatException or InvalidOperationException or OverflowException) { return new(QuotaKernelStatus.Conflict, default); }
    }

    private static PlanValue T(string value) => PlanValue.FromText(value);
    private static PlanValue I(long value) => PlanValue.FromInt64(value);
}
