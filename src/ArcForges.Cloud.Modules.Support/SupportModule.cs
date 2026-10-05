// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Support;

/// <summary>
/// Boundary of the Support module, the only owner of the <c>support_*</c> tables and of the plans under
/// <c>storage/plans/support</c>. It owns support cases and access grants. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class SupportModule : IModuleBoundary
{
    public static SupportModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Support", "support");
}
