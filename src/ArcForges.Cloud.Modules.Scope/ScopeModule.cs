// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Scope;

/// <summary>
/// Boundary of the Scope module, the only owner of the <c>scope_*</c> tables and of the plans under
/// <c>storage/plans/scope</c>. It owns ArcScope Cloud simulation definitions, runs and segments. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class ScopeModule : IModuleBoundary
{
    public static ScopeModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Scope", "scope");
}
