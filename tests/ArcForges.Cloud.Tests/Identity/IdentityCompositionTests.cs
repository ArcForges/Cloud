// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Identity;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Persistence.Infrastructure;
using ArcForges.Cloud.Modules.Workspace;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Tests.Entitlement;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

/// <summary>
/// Where the identity service resolves (S54(3)). A composition that binds the plan executor (the foundation configuration of the host,
/// here over the SQLite bridge) resolves the service over its production D1 store, the random identifier source, the real plan and family
/// bindings and the Workspace directory, and serves an enrollment end to end. Without that configuration nothing resolves. Production
/// binds no plan executor today, so production resolution is blocked on the production plan-executor composition, not proven.
/// </summary>
public sealed class IdentityCompositionTests : IDisposable
{
    private readonly SqliteBridgeExecutor bridge = new(recoveryGeneration: 1);

    public void Dispose() => bridge.Dispose();

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    private static void RegisterHostModules(WebApplicationBuilder builder, FoundationModule foundation)
    {
        foundation.Register(builder);
        new ModulePlanBindingModule().Register(builder);
        new ModuleFamilyBindingModule().Register(builder);
        new ModuleBoundaryHost(WorkspaceModule.Instance).Register(builder);
        new ModuleBoundaryHost(IdentityModule.Instance).Register(builder);
    }

    [Fact]
    public async Task UnderTheFoundationConfigurationTheHostResolvesTheServiceOverTheD1StoreAndServesAnEnrollment()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.Services.AddSingleton<IPlanExecutor>(bridge);
        RegisterHostModules(builder, new FoundationModule(T.Options(generation: 1)));
        await using var app = builder.Build();

        var service = app.Services.GetRequiredService<IdentityService>();

        Assert.IsType<D1IdentityStore>(app.Services.GetRequiredService<IIdentityStore>());
        Assert.IsType<RandomIdentityIdSource>(app.Services.GetRequiredService<IIdentityIdSource>());
        Assert.Same(service, app.Services.GetRequiredService<IdentityService>());
        var enrolled = await service.CompleteEnrollmentAsync(new EnrollmentRequest(IdentityHarness.RealmA, Guid.NewGuid().ToString("D"), "Ada", IdentityHarness.Email("ada@example.test")), Ct);
        Assert.True(enrolled.IsSuccess, "enrollment failed: " + enrolled.Error);
        Assert.True(enrolled.Value!.CreatedUser);
        var caller = IdentityHarness.Caller(enrolled.Value);
        Assert.Equal(enrolled.Value.Workspace, (await service.AuthorizeWorkspaceAsync(caller, enrolled.Value.Workspace.Id, Ct)).Value);
        Assert.Equal(enrolled.Value.User.Id, (await service.ResolveCredentialAsync(IdentityHarness.RealmA, "official-email", "ada@example.test", Ct)).Value!.User.Id);
        Assert.Equal(1, await bridge.CountAsync("identity_user", cancellationToken: Ct));
        Assert.Equal(1, await bridge.CountAsync("workspace_workspace", cancellationToken: Ct));
        Assert.Equal(1, await bridge.CountAsync("platform_command", cancellationToken: Ct));
    }

    [Fact]
    public async Task WithoutTheFoundationConfigurationTheServiceIsListedButNothingResolvesIt()
    {
        // Production binds no plan executor today (the COM.16 gap; owner to be assigned by planning repair fix8).
        var builder = WebApplication.CreateSlimBuilder();
        RegisterHostModules(builder, new FoundationModule(_ => null));
        await using var app = builder.Build();

        Assert.Contains(builder.Services, descriptor => descriptor.ServiceType == typeof(IdentityService));
        Assert.Contains(builder.Services, descriptor => descriptor.ServiceType == typeof(IIdentityStore));
        Assert.Throws<InvalidOperationException>(() => app.Services.GetRequiredService<IdentityService>());
        Assert.Throws<InvalidOperationException>(() => app.Services.GetRequiredService<IIdentityStore>());
    }

    [Fact]
    public void TheStoreAsksEachFactoryForTheIdentityDescriptorOnly()
    {
        var plans = new RecordingPlanFactory();
        var families = new RecordingFamilyFactory();
        var services = new ServiceCollection();
        services.AddSingleton<IModulePlanPortFactory>(plans);
        services.AddSingleton<IModuleFamilyPortFactory>(families);
        ((IModuleBoundary)WorkspaceModule.Instance).Register(services);
        ((IModuleBoundary)IdentityModule.Instance).Register(services);
        ((IModuleBoundary)IdentityModule.Instance).Register(services);
        using var provider = services.BuildServiceProvider();

        Assert.Same(provider.GetRequiredService<IIdentityStore>(), provider.GetRequiredService<IIdentityStore>());
        Assert.Single(services, descriptor => descriptor.ServiceType == typeof(IIdentityStore));
        Assert.Single(services, descriptor => descriptor.ServiceType == typeof(IIdentityIdSource));
        Assert.Equal(new[] { "identity", "workspace" }, plans.Requested.Select(module => module.PlanOwner).Order(StringComparer.Ordinal));
        Assert.Equal(new[] { IdentityModule.Instance.Descriptor }, families.Requested);
    }

    [Fact]
    public void TheStoreNeedsTheWorkspaceDirectory()
    {
        var services = new ServiceCollection();
        services.AddSingleton<IModulePlanPortFactory>(new RecordingPlanFactory());
        services.AddSingleton<IModuleFamilyPortFactory>(new RecordingFamilyFactory());
        ((IModuleBoundary)IdentityModule.Instance).Register(services);
        using var provider = services.BuildServiceProvider();

        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<IIdentityStore>());
    }

    private sealed class RecordingPlanFactory : IModulePlanPortFactory
    {
        public List<ModuleDescriptor> Requested { get; } = [];

        public IModulePlanPort For(ModuleDescriptor module)
        {
            Requested.Add(module);
            return new NoPlans();
        }
    }

    private sealed class RecordingFamilyFactory : IModuleFamilyPortFactory
    {
        public List<ModuleDescriptor> Requested { get; } = [];

        public IModuleFamilyPort For(ModuleDescriptor module)
        {
            Requested.Add(module);
            return new NoFamilies();
        }
    }

    private sealed class NoPlans : IModulePlanPort
    {
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken) => throw new InvalidOperationException("Not used.");

        public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken) => throw new InvalidOperationException("Not used.");
    }

    private sealed class NoFamilies : IModuleFamilyPort
    {
        public Task<ModulePlanOutcome> ExecuteAsync(ModuleFamilyCall call, CancellationToken cancellationToken) => throw new InvalidOperationException("Not used.");
    }
}
