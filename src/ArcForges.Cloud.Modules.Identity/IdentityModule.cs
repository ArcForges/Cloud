// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Persistence;
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
    /// Binds the core service to the owner plan and family ports. The host supplies the executor and its generation configuration.
    /// </summary>
    void IModuleBoundary.Register(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IIdentityIdSource, IdentityIdSource>();
        services.TryAddSingleton<IIdentityStore>(provider => new D1IdentityStore(
            provider.GetRequiredService<IModulePlanPortFactory>().For(Descriptor),
            provider.GetRequiredService<IModuleFamilyPortFactory>().For(Descriptor),
            provider.GetRequiredService<IIdentityIdSource>(), provider.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton(provider => new IdentityService(
            provider.GetRequiredService<IIdentityStore>(),
            provider.GetRequiredService<IIdentityIdSource>(),
            provider.GetRequiredService<TimeProvider>()));
    }
}
