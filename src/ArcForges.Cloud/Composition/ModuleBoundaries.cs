// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Agent;
using ArcForges.Cloud.Modules.Audit;
using ArcForges.Cloud.Modules.Chat;
using ArcForges.Cloud.Modules.Commerce;
using ArcForges.Cloud.Modules.Configuration;
using ArcForges.Cloud.Modules.Devices;
using ArcForges.Cloud.Modules.Entitlement;
using ArcForges.Cloud.Modules.Identity;
using ArcForges.Cloud.Modules.Notification;
using ArcForges.Cloud.Modules.PackageCatalog;
using ArcForges.Cloud.Modules.Policy;
using ArcForges.Cloud.Modules.Resource;
using ArcForges.Cloud.Modules.Scope;
using ArcForges.Cloud.Modules.Search;
using ArcForges.Cloud.Modules.Support;
using ArcForges.Cloud.Modules.Sync;
using ArcForges.Cloud.Modules.TrustSafety;
using ArcForges.Cloud.Modules.Workspace;
using TaskModule = ArcForges.Cloud.Modules.Task.TaskModule;

namespace ArcForges.Cloud.Composition;

/// <summary>
/// The 19 module boundaries of the Cloud schema map, listed explicitly (nothing is scanned). The host only lists them; each module
/// registers its own services and route fragment through its boundary, and appends here when it is added (RES-cloud-host-composition).
/// </summary>
internal static class ModuleBoundaries
{
    public static IReadOnlyList<IModuleBoundary> All { get; } =
    [
        IdentityModule.Instance,
        WorkspaceModule.Instance,
        DevicesModule.Instance,
        EntitlementModule.Instance,
        CommerceModule.Instance,
        ChatModule.Instance,
        TaskModule.Instance,
        AgentModule.Instance,
        SyncModule.Instance,
        ResourceModule.Instance,
        SearchModule.Instance,
        NotificationModule.Instance,
        PolicyModule.Instance,
        AuditModule.Instance,
        SupportModule.Instance,
        TrustSafetyModule.Instance,
        ScopeModule.Instance,
        ConfigurationModule.Instance,
        PackageCatalogModule.Instance,
    ];
}

/// <summary>Lists one module boundary in the host composition. It serves no public method and no plain route of its own: those are
/// declared by the module's own policies when it implements them, and an undeclared path stays refused by the ingress pipeline.</summary>
internal sealed class ModuleBoundaryHost(IModuleBoundary boundary) : IHostModule
{
    public IModuleBoundary Boundary { get; } = boundary;

    public void Register(WebApplicationBuilder builder) => Boundary.Register(builder.Services);

    public void Map(WebApplication app) => Boundary.Map(app);
}
