// SPDX-License-Identifier: AGPL-3.0-only
using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Storage;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ArcForges.Cloud.Composition;

/// <summary>One independently registered part of the host; the host lists its modules explicitly, nothing is scanned.</summary>
internal interface IHostModule
{
    void Register(WebApplicationBuilder builder);

    void Map(WebApplication app);
}

internal static class HostModules
{
    public static IReadOnlyList<IHostModule> All(JsonObject identity) => [new HelloModule(identity), new FoundationModule()];
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
        services.TryAddSingleton<FoundationOperations>();
    }

    public void Map(WebApplication app)
    {
        if (options is null) return;
        BrowserSessionEndpoints.Map(app);
        FoundationEndpoints.Map(app);
    }

    /// <summary>No redirects (a signed request must never follow one), no automatic decompression; time limits are applied per call.</summary>
    private static HttpClient NewClient() =>
        new(new SocketsHttpHandler { AllowAutoRedirect = false, AutomaticDecompression = System.Net.DecompressionMethods.None }) { Timeout = Timeout.InfiniteTimeSpan };
}
