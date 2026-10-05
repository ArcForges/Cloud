// SPDX-License-Identifier: AGPL-3.0-only
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace ArcForges.Cloud.Modules;

/// <summary>
/// The entry point of one module. The host lists the boundaries and calls these members; it never reaches into a module's
/// persistence, and a module never reaches into another module or into the host (Design CM-01 to CM-04). A module registers its
/// own services and its own route fragment here, and the deny-by-default ingress pipeline still refuses every method that has no
/// policy, so listing a boundary adds no reachable behavior by itself.
/// </summary>
public interface IModuleBoundary
{
    ModuleDescriptor Descriptor { get; }

    /// <summary>Registers the module's services. The default registers nothing.</summary>
    void Register(IServiceCollection services)
    {
    }

    /// <summary>Maps the module's route fragment. The default maps nothing.</summary>
    void Map(IEndpointRouteBuilder endpoints)
    {
    }
}
