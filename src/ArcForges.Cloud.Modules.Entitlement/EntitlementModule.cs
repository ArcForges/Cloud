// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;
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
    /// Lists the resolver service (COM.05), its production D1 store and the published grant port (COM.16). Every service is created only when
    /// something asks for it, and none opens a route or a method policy. The store needs the host's plan port factory, which a composition binds
    /// to the signed Worker executor; the service also needs the active definitions source, which the configuration activation task supplies,
    /// so until a composition supplies both nothing here is resolved.
    /// </summary>
    void IModuleBoundary.Register(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IEntitlementIdSource, GuidEntitlementIdSource>();
        services.TryAddSingleton<IEntitlementStore>(provider => new D1EntitlementStore(provider.GetRequiredService<IModulePlanPortFactory>().For(Descriptor)));
        services.TryAddSingleton(provider => new EntitlementService(
            provider.GetRequiredService<IEntitlementStore>(),
            provider.GetRequiredService<IEntitlementDefinitionSource>(),
            provider.GetRequiredService<IEntitlementIdSource>(),
            provider.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton<IEntitlementGrantPort>(provider => new EntitlementGrantPortAdapter(provider.GetRequiredService<EntitlementService>()));
    }
}
