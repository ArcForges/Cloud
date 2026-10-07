// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Application;

internal sealed record QuotaDefinitionReceipt(string Actor, string Operation, string Hash, long Status, string? Payload, long ExpiresAt);
internal sealed record QuotaDefinitionReceiptResult(QuotaDefinitionStatus Status, QuotaDefinitionReceipt? Value = null);
internal interface IQuotaDefinitionStore
{
    Task<QuotaDefinitionResult> ReadAsync(Guid realmId, string version, CancellationToken cancellationToken);
    Task<QuotaDefinitionReceiptResult> ReceiptAsync(QuotaDefinitionPublishRequest request, CancellationToken cancellationToken);
    Task<ModulePlanOutcome> PublishAsync(QuotaDefinitionPublishRequest request, ApprovedQuotaConfiguration approved,
        QuotaSemanticProfile profile, string requestHash, long nowMicros, CancellationToken cancellationToken);
}
