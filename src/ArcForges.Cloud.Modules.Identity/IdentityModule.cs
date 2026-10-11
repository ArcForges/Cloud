// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Persistence.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ArcForges.Cloud.Modules.Identity;

/// <summary>
/// Boundary of the Identity module, the only owner of the <c>identity_*</c> tables and of the plans under
/// <c>storage/plans/identity</c>. It owns user, authentication identity and session records. Its Domain, Application and Infrastructure layers
/// are folders and namespaces of this project; no other module may reference this assembly or touch its tables, and the host
/// only lists it.
/// </summary>
public sealed class IdentityModule : IModuleBoundary
{
    public static IdentityModule Instance { get; } = new();

    public ModuleDescriptor Descriptor { get; } = ModuleDescriptor.Create("Identity", "identity");

    /// <summary>
    /// Lists the core identity service (CLOUD.11) and its production D1 store and identifier source (CLOUD.72). Every service is created only
    /// when something asks for it, and none opens a route or a method policy. The store needs the host's plan port and family port factories,
    /// which a composition binds to the signed Worker executor, and the Workspace module's published directory; until a composition supplies
    /// the executor (production binds none today) nothing here is resolved and no table is read.
    /// </summary>
    void IModuleBoundary.Register(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IIdentityIdSource, RandomIdentityIdSource>();
        services.TryAddSingleton<IIdentityStore>(provider => new D1IdentityStore(
            provider.GetRequiredService<IModulePlanPortFactory>().For(Descriptor),
            provider.GetRequiredService<IModuleFamilyPortFactory>().For(Descriptor),
            provider.GetRequiredService<IWorkspaceDirectory>(),
            provider.GetRequiredService<IIdentityIdSource>(),
            provider.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton(provider => new IdentityService(
            provider.GetRequiredService<IIdentityStore>(),
            provider.GetRequiredService<IIdentityIdSource>(),
            provider.GetRequiredService<TimeProvider>()));
    }
}
