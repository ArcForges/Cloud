// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;

internal static class QuotaDefinitionOutcomes
{
    internal const string Operation = "entitlement.quota-definition-publish";
    internal static QuotaDefinitionStatus Status(ModulePlanStatus status) => status switch
    {
        ModulePlanStatus.Succeeded => QuotaDefinitionStatus.Succeeded,
        ModulePlanStatus.Replayed => QuotaDefinitionStatus.Replayed,
        ModulePlanStatus.ReusedIdentifier => QuotaDefinitionStatus.ReusedIdentifier,
        ModulePlanStatus.ReceiptExpired => QuotaDefinitionStatus.ReceiptExpired,
        ModulePlanStatus.GuardRefused or ModulePlanStatus.ConstraintRefused or ModulePlanStatus.ReplayedFailure => QuotaDefinitionStatus.Conflict,
        ModulePlanStatus.UnknownOutcome => QuotaDefinitionStatus.UnknownOutcome,
        ModulePlanStatus.Unavailable or ModulePlanStatus.StaleGeneration => QuotaDefinitionStatus.Unavailable,
        _ => QuotaDefinitionStatus.Defect,
    };
}
