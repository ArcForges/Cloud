// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.PackageCatalog;

/// <summary>
/// Boundary of the PackageCatalog module, the only owner of the <c>package_catalog_*</c> tables and of the plans under
/// <c>storage/plans/package-catalog</c>. It owns publishers, packages, versions, reviews and revocations. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class PackageCatalogModule : IModuleBoundary
{
    public static PackageCatalogModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("PackageCatalog", "package_catalog");
}
