// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Workspace;

/// <summary>
/// Boundary of the Workspace module, the only owner of the <c>workspace_*</c> tables and of the plans under
/// <c>storage/plans/workspace</c>. It owns workspace records (ownership is a direct owner-user check; there is no membership table). Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class WorkspaceModule : IModuleBoundary
{
    public static WorkspaceModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Workspace", "workspace");
}
