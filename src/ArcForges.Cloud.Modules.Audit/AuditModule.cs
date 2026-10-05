// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Audit;

/// <summary>
/// Boundary of the Audit module, the only owner of the <c>audit_*</c> tables and of the plans under
/// <c>storage/plans/audit</c>. It owns audit events, operator proposals and operator approvals. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class AuditModule : IModuleBoundary
{
    public static AuditModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Audit", "audit");
}
