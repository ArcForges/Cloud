// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Configuration;

/// <summary>
/// Boundary of the Configuration module, the only owner of the <c>config_*</c> tables and of the plans under
/// <c>storage/plans/config</c>. It owns activated deployment-policy revisions. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class ConfigurationModule : IModuleBoundary
{
    public static ConfigurationModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Configuration", "config");
}
