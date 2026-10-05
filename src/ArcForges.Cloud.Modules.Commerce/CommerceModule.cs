// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Commerce;

/// <summary>
/// Boundary of the Commerce module, the only owner of the <c>commerce_*</c> tables and of the plans under
/// <c>storage/plans/commerce</c>. It owns billing accounts, orders, subscriptions, credit lots, provider events, AI request, attempt, usage and settlement records, refunds and adjustments. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class CommerceModule : IModuleBoundary
{
    public static CommerceModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Commerce", "commerce");
}
