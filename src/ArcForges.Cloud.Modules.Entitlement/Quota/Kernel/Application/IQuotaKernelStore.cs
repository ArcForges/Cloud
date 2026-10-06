// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Application;

internal sealed record QuotaCommandReceipt(string ActorRef, string Operation, string RequestHash, long Status, string? ResultJson, long ExpiresAtMicros);
internal interface IQuotaKernelStore
{
    Task<QuotaReadResult<QuotaBudgetState>> BudgetAsync(QuotaBudgetKey key, CancellationToken cancellationToken);
    Task<QuotaReadResult<QuotaReservation>> ReservationAsync(QuotaOwnerContext context, Guid reservationId, CancellationToken cancellationToken);
    Task<QuotaReadResult<QuotaCommandReceipt>> ReceiptAsync(QuotaOwnerContext context, Guid commandId, CancellationToken cancellationToken);
    Task<ModulePlanOutcome> WriteAsync(string plan, string scope, IReadOnlyList<IReadOnlyList<PlanValue>> arguments,
        ModuleCommit commit, CancellationToken cancellationToken);
}
