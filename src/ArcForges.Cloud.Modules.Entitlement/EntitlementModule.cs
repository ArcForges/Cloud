// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ArcForges.Cloud.Modules.Entitlement;

/// <summary>
/// Boundary of the Entitlement module, the only owner of the <c>entitlement_*</c> tables and of the plans under
/// <c>storage/plans/entitlement</c>. It owns grants, snapshots, usage counters, service terms and capacity buckets, policy periods and reservations. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class EntitlementModule : IModuleBoundary
{
    public static EntitlementModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Entitlement", "entitlement");

    /// <summary>
    /// Lists the resolver service (COM.05). It is created only when something asks for it, and it needs the store, definition and
    /// identifier ports, which no composition supplies until the persistence task adds them: listing it serves no method and reads
    /// no table.
    /// </summary>
    void IModuleBoundary.Register(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(provider => new EntitlementService(
            provider.GetRequiredService<IEntitlementStore>(),
            provider.GetRequiredService<IEntitlementDefinitionSource>(),
            provider.GetRequiredService<IEntitlementIdSource>(),
            provider.GetRequiredService<TimeProvider>()));
    }
}
