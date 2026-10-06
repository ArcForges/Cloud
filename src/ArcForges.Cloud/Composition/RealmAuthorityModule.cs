// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Storage.Platform;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace ArcForges.Cloud.Composition;

/// <summary>Registers the real lazy security authority; requesting no authority preserves existing anonymous health and routes.</summary>
internal sealed class RealmAuthorityModule : IHostModule
{
    public void Register(WebApplicationBuilder builder)
    {
        builder.Services.TryAddSingleton(TimeProvider.System);
        builder.Services.TryAddSingleton<IRealmAuthorityPort>(provider => new ConfiguredRealmAuthority(Environment.GetEnvironmentVariable,
            generation => provider.GetService<IPlanExecutor>() is { } executor
                ? new RecoveryEpochReader(new ModulePlanPortFactory(executor, checked((ulong)generation), provider.GetRequiredService<TimeProvider>()),
                    provider.GetRequiredService<TimeProvider>())
                : null));
    }

    public void Map(WebApplication app)
    {
    }
}

/// <summary>
/// Required environment identity is captured once, lazily, and never silently follows a changed database generation. The production
/// reader factory is independent of Foundation proof configuration and carries this deployment's required expected generation.
/// </summary>
internal sealed class ConfiguredRealmAuthority : IRealmAuthorityPort
{
    private readonly Lazy<Configuration> configuration;
    private readonly Func<long, IRecoveryEpochPort?> recoveryFactory;

    public ConfiguredRealmAuthority(Func<string, string?> environment, Func<long, IRecoveryEpochPort?> recoveryFactory)
    {
        ArgumentNullException.ThrowIfNull(environment);
        this.recoveryFactory = recoveryFactory ?? throw new ArgumentNullException(nameof(recoveryFactory));
        configuration = new Lazy<Configuration>(() => Parse(environment), LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public async Task<RealmAuthorityResult> ResolveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var configured = configuration.Value;
        if (configured.Failure is { } failure) return RealmAuthorityResult.Refused(failure);
        var recovery = recoveryFactory(configured.Generation);
        if (recovery is null) return RealmAuthorityResult.Refused(RealmAuthorityFailure.Unavailable);
        var result = await recovery.ReadAsync(configured.Realm, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (result.Snapshot is not { } current) return RealmAuthorityResult.Refused(result.Failure switch
        {
            RecoveryEpochFailure.Missing => RealmAuthorityFailure.MissingRecovery,
            RecoveryEpochFailure.Closed => RealmAuthorityFailure.ClosedRecovery,
            RecoveryEpochFailure.StaleGeneration => RealmAuthorityFailure.StaleGeneration,
            RecoveryEpochFailure.Unavailable => RealmAuthorityFailure.Unavailable,
            _ => RealmAuthorityFailure.Defect,
        });
        if (current.RealmId != configured.Realm || current.Generation < 0 || current.Revision <= 0) return RealmAuthorityResult.Refused(RealmAuthorityFailure.Defect);
        if (current.Generation != configured.Generation) return RealmAuthorityResult.Refused(RealmAuthorityFailure.StaleGeneration);
        return RealmAuthorityResult.Available(new RealmAuthoritySnapshot(configured.Realm, configured.AuthEpoch, current.Generation, current.Revision));
    }

    private static Configuration Parse(Func<string, string?> environment)
    {
        var realm = environment("AF_REALM_ID");
        var epoch = environment("AF_AUTH_EPOCH");
        var generation = environment("AF_RECOVERY_GENERATION");
        if (realm is null || epoch is null || generation is null) return new(Guid.Empty, 0, 0, RealmAuthorityFailure.MissingConfiguration);
        if (!Guid.TryParseExact(realm, "D", out var realmId) || realmId == Guid.Empty || realm != realmId.ToString("D")
            || !CanonicalInteger(epoch, 1, out var authEpoch) || !CanonicalInteger(generation, 0, out var expectedGeneration))
            return new(Guid.Empty, 0, 0, RealmAuthorityFailure.InvalidConfiguration);
        return new(realmId, authEpoch, expectedGeneration, null);
    }

    private static bool CanonicalInteger(string text, long minimum, out long value) =>
        long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value) && value >= minimum
        && string.Equals(text, value.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal);

    private sealed record Configuration(Guid Realm, long AuthEpoch, long Generation, RealmAuthorityFailure? Failure);
}
