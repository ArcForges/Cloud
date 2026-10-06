// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Commerce.Catalogue.Application;
using ArcForges.Cloud.Modules.Commerce.Catalogue.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

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

    void IModuleBoundary.Register(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ICatalogueStore>(provider => new D1CatalogueStore(provider.GetRequiredService<IModulePlanPortFactory>().For(Descriptor)));
        services.TryAddSingleton<CatalogueReader>();
        services.TryAddSingleton<ICatalogueStatePort>(provider => provider.GetRequiredService<CatalogueReader>());
        services.TryAddSingleton<ICatalogueQueryPort>(provider => provider.GetRequiredService<CatalogueReader>());
        // No permissive authority is installed here. POL.02 binds the actual dual-approved Configuration source.
        services.TryAddSingleton<ICataloguePublicationPort>(provider => new CataloguePublisher(provider.GetRequiredService<ICatalogueStore>(),
            provider.GetRequiredService<ICataloguePublicationAuthority>(), provider.GetRequiredService<TimeProvider>(), TimeSpan.FromDays(7)));
    }
}
