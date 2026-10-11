// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Tests.Receipts;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.Families;

/// <summary>
/// The host composition append (RES-cloud-host-composition): the family port is bound beside the plan-execution port, resolves when the
/// foundation configuration supplies the executor and the recovery generation, and resolves to nothing usable without it (production today).
/// </summary>
public sealed class ModuleFamilyBindingTests
{
    [Fact]
    public void TheHostListsTheFamilyBindingOnceRightAfterThePlanBinding()
    {
        var modules = HostModules.All(BuildIdentity.FromAssembly(typeof(HelloEndpoint).Assembly));
        var plan = modules.Select((module, index) => (module, index)).Single(item => item.module is ModulePlanBindingModule).index;
        var family = modules.Select((module, index) => (module, index)).Single(item => item.module is ModuleFamilyBindingModule).index;
        Assert.Equal(plan + 1, family);
    }

    [Fact]
    public async Task UnderTheFoundationConfigurationTheFactoryResolvesWithItsExecutorAndGeneration()
    {
        var builder = WebApplication.CreateSlimBuilder();
        var storage = new ScriptedExecutor { Handler = _ => ScriptedExecutor.Changed() };
        builder.Services.AddSingleton<IPlanExecutor>(storage);
        new FoundationModule(T.Options(generation: 4)).Register(builder);
        new ModuleFamilyBindingModule().Register(builder);
        await using var app = builder.Build();

        var factory = app.Services.GetRequiredService<IModuleFamilyPortFactory>();

        Assert.IsType<ModuleFamilyPortFactory>(factory);
        Assert.Same(factory, app.Services.GetRequiredService<IModuleFamilyPortFactory>());
        var enrollment = Enrollment.New();
        var outcome = await factory.For(ModuleDescriptor.Create("Identity", "identity")).ExecuteAsync(enrollment.Call(), T.Ct);
        Assert.Equal(ModulePlanStatus.Succeeded, outcome.Status);
        var call = Assert.Single(storage.Calls);
        Assert.Equal(4UL, call.RecoveryGeneration);
        Assert.Equal(Enrollment.Plan, call.Plan.Id);
    }

    [Fact]
    public async Task WithoutTheFoundationConfigurationNothingResolvesTheFactory()
    {
        var builder = WebApplication.CreateSlimBuilder();
        new FoundationModule(_ => null).Register(builder);
        new ModuleFamilyBindingModule().Register(builder);
        await using var app = builder.Build();

        Assert.Throws<InvalidOperationException>(() => app.Services.GetRequiredService<IModuleFamilyPortFactory>());
    }

    [Fact]
    public async Task ATestHostSubstituteRegisteredFirstIsKept()
    {
        var builder = WebApplication.CreateSlimBuilder();
        var substitute = new SubstituteFactory();
        builder.Services.AddSingleton<IModuleFamilyPortFactory>(substitute);
        new ModuleFamilyBindingModule().Register(builder);
        await using var app = builder.Build();

        Assert.Same(substitute, app.Services.GetRequiredService<IModuleFamilyPortFactory>());
    }

    private sealed class SubstituteFactory : IModuleFamilyPortFactory
    {
        public IModuleFamilyPort For(ModuleDescriptor module) => throw new NotSupportedException();
    }
}
