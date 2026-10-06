// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Capacity;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.Capacity;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ArcForges.Cloud.Composition;

/// <summary>Supplied by the actual production storage/recovery composition owner. It is not sourced
/// from FoundationOptions or a caller hint; the signed Worker executor also enforces its generation.</summary>
internal sealed record CapacityStorageBinding(IPlanExecutor Executor, ulong RecoveryGeneration);

internal sealed class CapacityModule(Func<string, string?> environment) : IHostModule
{
    private bool enabled;
    public CapacityModule() : this(Environment.GetEnvironmentVariable) { }
    public void Register(WebApplicationBuilder builder)
    {
        enabled = environment("ARCFORGES_CAPACITY") == "enabled";
        if (!enabled) return;
        builder.Services.TryAddSingleton(CapacityIngressOptions.Parse(environment));
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.TryAddSingleton<ICapacityJobPort>(provider =>
        {
            var storage = provider.GetRequiredService<CapacityStorageBinding>();
            return new CapacityJobPortFactory(storage.Executor, storage.RecoveryGeneration,
                provider.GetRequiredService<TimeProvider>(), provider.GetRequiredService<ICapacityJobAuthority>()).Create();
        });
        builder.Services.TryAddSingleton<CapacityDispatcher>();
        builder.Services.TryAddSingleton<ICapacityJobRecoveryPort>(provider =>
        {
            var storage = provider.GetRequiredService<CapacityStorageBinding>();
            return new CapacityJobRecoveryPort(storage.Executor, storage.RecoveryGeneration,
                provider.GetRequiredService<TimeProvider>(), provider.GetRequiredService<ICapacityJobRecoveryAuthority>(),
                provider.GetServices<ICapacityJobProcessor>().Select(processor => processor.JobType));
        });
        builder.Services.TryAddSingleton<CapacityRecoveryService>();
        builder.Services.TryAddSingleton<CapacityMeasurementHarness>();
        // The operator run owner supplies a retained artifact journal and actual operation adapters.
        // The harness refuses absent full-system producers before dispatching any workload.
        builder.Services.TryAddSingleton<CapacityLoadHarness>(provider => new(
            provider.GetServices<ICapacityLoadOperation>(), provider.GetRequiredService<TimeProvider>(),
            provider.GetRequiredService<CapacityLoadJournal>(), provider.GetRequiredService<ICapacityLoadRunAuthority>()));
        builder.Services.TryAddSingleton<CapacityAdmission>();
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<ICapacityJobProcessor, CapacityMeasurementProcessor>());
        builder.Services.TryAddSingleton<ICapacityWakeScheduler>(provider => new CapacityWakeScheduler(
            new HttpClient(new SocketsHttpHandler
            {
                AllowAutoRedirect = false,
                UseProxy = false,
                UseCookies = false,
                AutomaticDecompression = System.Net.DecompressionMethods.None,
            })
            { Timeout = Timeout.InfiniteTimeSpan },
            provider.GetRequiredService<CapacityIngressOptions>().ScheduleSigner,
            provider.GetRequiredService<ICapacityJobPort>(), provider.GetRequiredService<TimeProvider>()));
    }
    public IEnumerable<string> PlainPaths => enabled ? [CapacityEndpoints.Path, CapacityEndpoints.RecoveryPath] : [];
    public void Map(WebApplication app)
    {
        if (!enabled) return;
        // An enabled production service must fail at startup rather than serve a fake job API when
        // actual storage/recovery/owner authority is missing. Processors have explicit type ownership.
        _ = app.Services.GetRequiredService<CapacityDispatcher>();
        _ = app.Services.GetRequiredService<CapacityRecoveryService>();
        CapacityEndpoints.Map(app);
    }
}
