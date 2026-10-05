// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Notification;

/// <summary>
/// Boundary of the Notification module, the only owner of the <c>notification_*</c> tables and of the plans under
/// <c>storage/plans/notification</c>. It owns notifications and push registrations. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class NotificationModule : IModuleBoundary
{
    public static NotificationModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Notification", "notification");
}
