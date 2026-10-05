// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Policy;

/// <summary>
/// Boundary of the Policy module, the only owner of the <c>policy_*</c> tables and of the plans under
/// <c>storage/plans/policy</c>. It owns policy bundles. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class PolicyModule : IModuleBoundary
{
    public static PolicyModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Policy", "policy");
}
