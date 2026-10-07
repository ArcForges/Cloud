// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Definitions.Application;

internal sealed record ResolverDefinitionReceipt(string Actor, string Operation, string Hash, long Status, string? Payload, long ExpiresAt);
internal sealed record ResolverDefinitionReceiptResult(ResolverDefinitionStatus Status, ResolverDefinitionReceipt? Value = null);
internal interface IResolverDefinitionStore
{
    Task<ResolverDefinitionResult> ReadAsync(Guid realmId, string version, CancellationToken cancellationToken);
    Task<ResolverDefinitionReceiptResult> ReceiptAsync(ResolverDefinitionPublishRequest request, CancellationToken cancellationToken);
    Task<ModulePlanOutcome> PublishAsync(ResolverDefinitionPublishRequest request, ApprovedResolverConfiguration approved,
        ResolverDefinitionProfile profile, string requestHash, long nowMicros, CancellationToken cancellationToken);
}

internal static class ResolverDefinitionOutcomes
{
    public const string Operation = "entitlement.resolver-definition-publish";
    public static ResolverDefinitionStatus Status(ModulePlanStatus value) => value switch
    {
        ModulePlanStatus.Succeeded => ResolverDefinitionStatus.Succeeded,
        ModulePlanStatus.Replayed => ResolverDefinitionStatus.Replayed,
        ModulePlanStatus.ReplayedFailure or ModulePlanStatus.GuardRefused or ModulePlanStatus.ConstraintRefused => ResolverDefinitionStatus.Conflict,
        ModulePlanStatus.ReusedIdentifier => ResolverDefinitionStatus.ReusedIdentifier,
        ModulePlanStatus.ReceiptExpired => ResolverDefinitionStatus.ReceiptExpired,
        ModulePlanStatus.UnknownOutcome => ResolverDefinitionStatus.UnknownOutcome,
        ModulePlanStatus.Unavailable => ResolverDefinitionStatus.Unavailable,
        ModulePlanStatus.StaleGeneration => ResolverDefinitionStatus.Stale,
        _ => ResolverDefinitionStatus.Defect,
    };
}
