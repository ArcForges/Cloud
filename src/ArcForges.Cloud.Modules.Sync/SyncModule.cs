// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Sync;

/// <summary>
/// Boundary of the Sync module, the only owner of the <c>sync_*</c> tables and of the plans under
/// <c>storage/plans/sync</c>. It owns sync scopes and the change feed. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class SyncModule : IModuleBoundary
{
    public static SyncModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Sync", "sync");
}
