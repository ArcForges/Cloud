// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Resource;

/// <summary>
/// Boundary of the Resource module, the only owner of the <c>resource_*</c> tables and of the plans under
/// <c>storage/plans/resource</c>. It owns cloud objects and upload sessions. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class ResourceModule : IModuleBoundary
{
    public static ResourceModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Resource", "resource");
}
