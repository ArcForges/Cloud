// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Entitlement;

/// <summary>
/// Boundary of the Entitlement module, the only owner of the <c>entitlement_*</c> tables and of the plans under
/// <c>storage/plans/entitlement</c>. It owns grants, snapshots, usage counters, service terms and capacity buckets, policy periods and reservations. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class EntitlementModule : IModuleBoundary
{
    public static EntitlementModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Entitlement", "entitlement");
}
