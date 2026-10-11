// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Hmac;
using ArcForges.Cloud.Ingress;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Task.Harness.Wake;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Storage.ModuleBinding;
using Microsoft.Extensions.DependencyInjection.Extensions;
using TaskModule = ArcForges.Cloud.Modules.Task.TaskModule;

namespace ArcForges.Cloud.Composition;

/// <summary>One independently registered part of the host; the host lists its modules explicitly, nothing is scanned.</summary>
internal interface IHostModule
{
    void Register(WebApplicationBuilder builder);

    void Map(WebApplication app);

    /// <summary>The public gRPC-Web methods this module serves, each with its ingress policy. A method without a policy is refused.</summary>
    IEnumerable<RpcPolicy> RpcPolicies => [];

    /// <summary>Exact plain HTTP routes this module serves (they carry their own checks). Any path not declared is refused by the ingress pipeline.</summary>
    IEnumerable<string> PlainPaths => [];

    /// <summary>Path prefixes of plain HTTP routes this module serves; a path strictly under a prefix is admitted to its endpoint.</summary>
    IEnumerable<string> PlainPrefixes => [];
}

internal static class HostModules
{
    /// <summary>The ingress module comes first so its pipeline runs before the gRPC-Web adapter; it reads the other modules' policies when mapping.</summary>
    public static IReadOnlyList<IHostModule> All(JsonObject identity)
    {
        IHostModule[] served = [new HelloModule(identity), new FoundationModule(), new ModulePlanBindingModule(), new ModuleFamilyBindingModule(), .. ModuleBoundaries.All.Select(boundary => new ModuleBoundaryHost(boundary)), new HarnessWakeModule(identity)];
        return [new IngressModule(served), .. served];
    }
}

/// <summary>
/// The harness wake port of the Task module, appended to the host composition (HAR.40, RES-cloud-host-composition). It is registered and its
/// private path declared only when the foundation configuration is present, because the W2C verifier keys come from it. Without that
/// configuration no wake port is registered, the Task module maps no route and the ingress pipeline refuses the path. The alarm arming port
/// (the outbound harness.internal client) is registered under the same condition.
/// </summary>
internal sealed class HarnessWakeModule(JsonObject identity) : IHostModule
{
    private bool enabled;

    public void Register(WebApplicationBuilder builder)
    {
        enabled = builder.Services.Any(descriptor => descriptor.ServiceType == typeof(FoundationOptions));
        if (!enabled) return;
        // The alarm port (HAR.40 alarm arming) is registered with the wake route and nowhere else; production registers nothing new.
        builder.Services.TryAddSingleton<IHarnessAlarmPort>(_ => new HarnessAlarmClient(FoundationModule.NewClient(), TimeSpan.FromSeconds(5)));
        builder.Services.TryAddSingleton<IHarnessWakePort>(provider =>
        {
            var configured = provider.GetRequiredService<FoundationOptions>();
            var time = provider.GetRequiredService<TimeProvider>();
            var build = identity["build"]!.AsObject();
            var cloudBuild = build["sourceCommit"]!.GetValue<string>() + (build["dirty"]!.GetValue<bool>() ? "-dirty" : "");
            var plans = new ModulePlanPortFactory(provider.GetRequiredService<IPlanExecutor>(), configured.RecoveryGeneration, time).For(TaskModule.Instance.Descriptor);
            return new HarnessWakeService(
                plans,
                cloudBuild,
                checked((long)configured.RecoveryGeneration),
                time,
                (method, target, bodyHash, header) => PrivateRequestVerifier.Verify(method, target, bodyHash, header, configured.VerifyKeys, time.GetUtcNow(), out _));
        });
    }

    public IEnumerable<string> PlainPaths => enabled ? [HarnessWakeRoute.Path] : [];

    public void Map(WebApplication app)
    {
    }
}

/// <summary>
/// The public ingress pipeline of the host: it composes the method policies of the listed modules into the deny-by-default table and
/// installs the pipeline ahead of the gRPC-Web adapter. It serves no method of its own.
/// </summary>
internal sealed class IngressModule(IReadOnlyList<IHostModule> served) : IHostModule
{
    public void Register(WebApplicationBuilder builder)
    {
    }

    public void Map(WebApplication app)
    {
        var routes = new IngressRoutes(RpcPolicyRegistry.Create(served.SelectMany(module => module.RpcPolicies)),
            served.SelectMany(module => module.PlainPaths), served.SelectMany(module => module.PlainPrefixes));
        app.Use((context, next) => IngressPipeline.InvokeAsync(context, next, routes));
    }
}

/// <summary>The anonymous Hello gRPC service, its gRPC-Web adapter and the health route, unchanged from the bootstrap host.</summary>
internal sealed class HelloModule(JsonObject identity) : IHostModule
{
    public void Register(WebApplicationBuilder builder) =>
        builder.Services.AddGrpc(options =>
        {
            options.EnableDetailedErrors = false;
            options.MaxReceiveMessageSize = 4091;
            options.MaxSendMessageSize = 4091;
        });

    public IEnumerable<RpcPolicy> RpcPolicies { get; } =
        [RpcPolicy.Unary("/arcforges.hello.v1.HelloService/SayHello", RpcAuthentication.Anonymous, RpcScope.None)];

    public IEnumerable<string> PlainPaths { get; } = ["/healthz"];

    public void Map(WebApplication app)
    {
        app.UseGrpcWeb();
        app.MapGrpcService<HelloEndpoint>().EnableGrpcWeb();

        var build = identity["build"]!.AsObject();
        var revision = build["sourceCommit"]!.GetValue<string>() + (build["dirty"]!.GetValue<bool>() ? "-dirty" : "");
        var health = new HealthStatus("arcforges-cloud", revision, !RuntimeFeature.IsDynamicCodeSupported,
            identity["artifact"]!.AsObject(), build);
        app.MapGet("/healthz", () => Results.Json(health, HealthJsonContext.Default.HealthStatus));
    }
}

/// <summary>
/// Binds the generic plan-execution port of the Abstractions project to the signed Worker executor (COM.16): a module project asks the
/// factory for the port of its own descriptor and reaches D1 only through named plans of its own owner. The binding is created only
/// when a module asks for it, and it needs the executor and the recovery generation of the foundation configuration, so without that
/// configuration (production today) nothing resolves it and no route, method or request changes.
/// </summary>
internal sealed class ModulePlanBindingModule : IHostModule
{
    public void Register(WebApplicationBuilder builder) =>
        builder.Services.TryAddSingleton<IModulePlanPortFactory>(provider => new ModulePlanPortFactory(
            provider.GetRequiredService<IPlanExecutor>(), provider.GetRequiredService<FoundationOptions>().RecoveryGeneration, provider.GetRequiredService<TimeProvider>()));

    public void Map(WebApplication app)
    {
    }
}

/// <summary>
/// Binds the generic family-execution port of the Abstractions project to the shared-family engine over the signed Worker executor
/// (CLOUD.72), beside the plan-execution binding: a module asks the factory for the port of its own descriptor and runs a registered
/// shared family only with its own statements (and the one reviewed exception of the FamilyBinding policy). Like the plan binding it is
/// created only when a module asks for it and needs the executor and the recovery generation of the foundation configuration, so without
/// that configuration (production today) nothing resolves it and no route, method or request changes.
/// </summary>
internal sealed class ModuleFamilyBindingModule : IHostModule
{
    public void Register(WebApplicationBuilder builder) =>
        builder.Services.TryAddSingleton<IModuleFamilyPortFactory>(provider => new ModuleFamilyPortFactory(
            provider.GetRequiredService<IPlanExecutor>(), provider.GetRequiredService<FoundationOptions>().RecoveryGeneration, provider.GetRequiredService<TimeProvider>()));

    public void Map(WebApplication app)
    {
    }
}

/// <summary>
/// The PRF.07 foundation proof. Registers nothing unless <c>ARCFORGES_FOUNDATION_PROOF</c> is exactly <c>enabled</c>; when enabled,
/// an invalid configuration throws during startup. Services are added with TryAdd so a test host can substitute them first.
/// </summary>
internal sealed class FoundationModule : IHostModule
{
    private readonly Func<string, string?> environment;
    private FoundationOptions? options;

    public FoundationModule() : this(Environment.GetEnvironmentVariable)
    {
    }

    public FoundationModule(Func<string, string?> environment) => this.environment = environment;

    public FoundationModule(FoundationOptions options)
    {
        environment = _ => null;
        this.options = options;
    }

    public void Register(WebApplicationBuilder builder)
    {
        options ??= FoundationOptions.IsEnabled(environment) ? FoundationOptions.Parse(environment) : null;
        if (options is not { } configured) return;
        var services = builder.Services;
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(configured);
        services.TryAddSingleton<IPlanExecutor>(provider => new WorkerPlanExecutor(NewClient(), configured.StorageBaseUrl, configured.SigningKeyC2w, provider.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton(provider => new ObjectsClient(NewClient(), configured.ObjectsBaseUrl, configured.SigningKeyC2w, provider.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton(provider => new SessionService(provider.GetRequiredService<IPlanExecutor>(), configured, provider.GetRequiredService<TimeProvider>()));
        services.TryAddSingleton(provider => new JobSliceService(provider.GetRequiredService<IPlanExecutor>(), provider.GetRequiredService<TimeProvider>(), configured.RecoveryGeneration));
        services.TryAddSingleton(provider => new EgressProbe(NewClient, EgressProbe.PublicTargets, provider.GetRequiredService<SessionService>().IsReadyAsync));
        services.TryAddSingleton<FoundationOperations>();
        services.TryAddSingleton(new PipelineProbeState());
        services.TryAddSingleton<IBrowserSessionVerifier>(provider =>
            new BrowserSessionVerifier(provider.GetRequiredService<SessionService>(), configured));
    }

    public IEnumerable<RpcPolicy> RpcPolicies => options is null ? Array.Empty<RpcPolicy>() : PipelineProbe.Policies;

    public IEnumerable<string> PlainPaths => options is null ? Array.Empty<string>() : [BrowserSessionEndpoints.BootstrapPath, BrowserSessionEndpoints.LogoutPath];

    public IEnumerable<string> PlainPrefixes => options is null ? Array.Empty<string>() : [FoundationEndpoints.Prefix];

    public void Map(WebApplication app)
    {
        if (options is null) return;
        BrowserSessionEndpoints.Map(app);
        FoundationEndpoints.Map(app);
        PipelineProbe.Map(app);
    }

    /// <summary>No redirects (a signed request must never follow one), no automatic decompression; time limits are applied per call.</summary>
    internal static HttpClient NewClient() =>
        new(new SocketsHttpHandler { AllowAutoRedirect = false, AutomaticDecompression = System.Net.DecompressionMethods.None }) { Timeout = Timeout.InfiniteTimeSpan };
}
