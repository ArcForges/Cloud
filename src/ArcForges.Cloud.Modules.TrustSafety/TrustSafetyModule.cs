// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.TrustSafety;

/// <summary>
/// Boundary of the TrustSafety module, the only owner of the <c>trustsafety_*</c> tables and of the plans under
/// <c>storage/plans/trustsafety</c>. It owns reports and enforcement actions. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class TrustSafetyModule : IModuleBoundary
{
    public static TrustSafetyModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("TrustSafety", "trustsafety");
}
