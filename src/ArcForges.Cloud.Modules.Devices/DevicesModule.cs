// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Devices;

/// <summary>
/// Boundary of the Devices module, the only owner of the <c>device_*</c> tables and of the plans under
/// <c>storage/plans/device</c>. It owns device and installation records. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class DevicesModule : IModuleBoundary
{
    public static DevicesModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Devices", "device");
}
