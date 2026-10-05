// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Application;
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
    /// Lists the core identity service (CLOUD.11). It is created only when something asks for it, and it needs the store and the
    /// identifier port, which no composition supplies until the plan-execution port exists: listing it serves no method and reads no table.
    /// </summary>
    void IModuleBoundary.Register(IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(provider => new IdentityService(
            provider.GetRequiredService<IIdentityStore>(),
            provider.GetRequiredService<IIdentityIdSource>(),
            provider.GetRequiredService<TimeProvider>()));
    }
}