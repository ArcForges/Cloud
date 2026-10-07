// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Application;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Domain;
using ArcForges.Cloud.Modules.Entitlement.Quota.Definitions.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Quota.Periods.Application;
using ArcForges.Cloud.Modules.Entitlement.Quota.Periods.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Application;
using ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Infrastructure;
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
        services.TryAddSingleton<IQuotaKernelStore>(provider => new D1QuotaKernelStore(provider.GetRequiredService<IModulePlanPortFactory>().For(Descriptor)));
        services.TryAddSingleton<IQuotaKernelPort>(provider => new QuotaKernel(
            provider.GetRequiredService<IQuotaKernelStore>(), provider.GetRequiredService<IQuotaKernelAuthority>(),
            provider.GetRequiredService<IQuotaMeasurementAuthority>(), provider.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton<IQuotaDefinitionValidator, QuotaDefinitionValidator>();
        services.TryAddSingleton<IQuotaResolverDefinitionSource>(provider => new CurrentQuotaResolverDefinitionSource(
            provider.GetService<IEntitlementDefinitionSource>(), provider.GetService<IRealmAuthorityPort>()));
        services.TryAddSingleton<IQuotaDefinitionStore>(provider => new D1QuotaDefinitionStore(provider.GetRequiredService<IModulePlanPortFactory>().For(Descriptor)));
        services.TryAddSingleton<IQuotaDefinitionPort>(provider => new QuotaDefinitionService(provider.GetRequiredService<IQuotaDefinitionStore>(),
            provider.GetService<IQuotaApprovedConfigurationSource>(), provider.GetService<IQuotaDefinitionArtifactPort>(),
            provider.GetService<IQuotaResolverDefinitionSource>(), provider.GetRequiredService<IQuotaDefinitionValidator>(), provider.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton<IQuotaPeriodStore>(provider => new D1QuotaPeriodStore(provider.GetRequiredService<IModulePlanPortFactory>().For(Descriptor)));
        services.TryAddSingleton<IQuotaPeriodSource>(provider => new QuotaPeriodSource(provider.GetRequiredService<IQuotaPeriodStore>(), provider.GetRequiredService<IQuotaDefinitionPort>(),
            provider.GetService<IQuotaApprovedConfigurationSource>(), provider.GetRequiredService<IQuotaDefinitionValidator>(), provider.GetRequiredService<TimeProvider>()));
    }
}
