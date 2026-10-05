// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Application;

/// <summary>A request to issue one grant. The grant identifier and creation time are assigned by the service, never by the caller.</summary>
internal sealed record IssueGrantRequest(
    string WorkspaceId,
    GrantKind Kind,
    string Subject,
    GrantValue Value,
    GrantSource Source,
    string? SourceRef,
    UtcMicros EffectiveFrom,
    UtcMicros? EffectiveUntil,
    string IssuedByActor,
    string? Reason);

/// <summary>A request to revoke one exact grant. <see cref="ExpectedSnapshotVersion"/> guards the entitlement version the caller decided against.</summary>
internal sealed record RevokeGrantRequest(
    string WorkspaceId,
    string GrantId,
    string ReasonCode,
    UtcMicros? EffectiveFrom,
    string IssuedByActor,
    long ExpectedSnapshotVersion);

/// <summary>
/// Admission of a grant: the rules that make the grant interface the only way in (EO-03). Every refusal is typed and explained; nothing
/// is coerced. A credit balance, trial flag or operator edit cannot become a grant of a kind the model does not define (SV-03).
/// </summary>
internal static class GrantAdmission
{
    public static string? Validate(IssueGrantRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!InputRules.IsIdentifier(request.WorkspaceId)) return "The workspace identifier is malformed.";
        if (!Enum.IsDefined(request.Kind)) return "The grant kind is not one of capability, quota or allowance.";
        if (!Enum.IsDefined(request.Source)) return "The grant source is not in the closed source vocabulary.";
        if (!InputRules.IsKey(request.Subject)) return "The grant subject is malformed.";
        if (request.Value is null || !ValueMatchesKind(request)) return "The grant value does not match its kind or is out of range.";
        if (!InputRules.IsActor(request.IssuedByActor)) return "A grant must name the actor or audited action that issued it.";
        if (request.EffectiveUntil is { } until && until <= request.EffectiveFrom) return "A grant must end after it starts.";
        if (request.SourceRef is not null && !InputRules.IsOpaqueReference(request.SourceRef))
        {
            return "The source reference must be an opaque reference of lower-case, upper-case, digit and . _ - : characters, not a provider payload.";
        }

        // Every source names its originating transaction or audited action (GR-02). Administrative, compensation and migration grants also
        // carry a reason and, through the source reference, the ticket or incident (GR-04, GR-05).
        if (request.SourceRef is null) return "Every grant names the transaction or audited action that originated it.";
        var administrative = request.Source is GrantSource.AdminGrant or GrantSource.Compensation or GrantSource.Migration;
        if (administrative && !InputRules.IsReason(request.Reason)) return "An administrative, compensation or migration grant requires a reason.";
        if (!administrative && request.Reason is not null && !InputRules.IsReason(request.Reason)) return "The reason is malformed.";
        return null;
    }

    private static bool ValueMatchesKind(IssueGrantRequest request) => request.Kind switch
    {
        GrantKind.Capability => request.Value is CapabilityValue,
        GrantKind.Quota => request.Value is QuotaValue { Limit: >= 0 and <= InputRules.MaxQuotaLimit, Priority: >= 0 },
        GrantKind.Allowance => request.Value is AllowanceValue { Priority: >= 0 } allowance && InputRules.IsIdentifier(allowance.CapacityPlanRef),
        _ => false,
    };

    /// <summary>True when a stored grant is the same issuance as the request, which is what makes a replayed request idempotent.</summary>
    public static bool IsSameIssuance(Grant existing, IssueGrantRequest request) =>
        existing.WorkspaceId == request.WorkspaceId && existing.Kind == request.Kind && existing.Subject == request.Subject
        && existing.Value == request.Value && existing.Source == request.Source && existing.SourceRef == request.SourceRef
        && existing.EffectiveFrom == request.EffectiveFrom && existing.EffectiveUntil == request.EffectiveUntil
        && existing.IssuedByActor == request.IssuedByActor;
}
