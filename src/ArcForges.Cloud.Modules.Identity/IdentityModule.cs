// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Identity;

/// <summary>
/// Boundary of the Identity module, the only owner of the <c>identity_*</c> tables and of the plans under
/// <c>storage/plans/identity</c>. It owns user, authentication identity and session records. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class IdentityModule : IModuleBoundary
{
    public static IdentityModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Identity", "identity");
}
