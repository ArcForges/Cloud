// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Search;

/// <summary>
/// Boundary of the Search module, the only owner of the <c>search_*</c> tables and of the plans under
/// <c>storage/plans/search</c>. It owns inference-job receipts (derived indexes are separately rebuildable). Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class SearchModule : IModuleBoundary
{
    public static SearchModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Search", "search");
}
