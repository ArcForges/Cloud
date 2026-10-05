// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Immutable;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

/// <summary>How the grants of one quota combine (requirements section 6.1): the base plus add-ons sum, device-style limits take the maximum, a support level replaces by priority.</summary>
internal enum QuotaCombination
{
    Sum,
    Max,
    PriorityReplace,
}

/// <summary>A capability the resolver may grant. Which capabilities need an active paid term is data, never code (BN-01).</summary>
internal sealed record CapabilityDefinition(string Key, bool RequiresPaidTerm, string? FeatureGate = null);

internal sealed record QuotaDefinition(string Key, QuotaCombination Combination);

/// <summary>An allowance subject. An allowance always requires an active paid term: included capacity only recovers during eligible service.</summary>
internal sealed record AllowanceDefinition(string Key);

/// <summary>
/// The versioned definition set the resolver evaluates against (a bundle version, BN-02). <see cref="IsSelfHostRealm"/> decides which
/// term kinds count: an official realm ignores a self-host service grant and a self-host realm ignores every official term (SV-04).
/// </summary>
internal sealed record EntitlementDefinitions(
    string Version,
    ImmutableArray<CapabilityDefinition> Capabilities,
    ImmutableArray<QuotaDefinition> Quotas,
    ImmutableArray<AllowanceDefinition> Allowances,
    bool IsSelfHostRealm);
