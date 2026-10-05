// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Agent;

/// <summary>
/// Boundary of the Agent module, the only owner of the <c>agent_*</c> tables and of the plans under
/// <c>storage/plans/agent</c>. It owns agent profiles, model descriptors, and tariff and supplier price versions. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class AgentModule : IModuleBoundary
{
    public static AgentModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Agent", "agent");
}
