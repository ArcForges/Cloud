// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
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
        builder.Services.TryAddSingleton(_ => new ConfiguredRealmOptionsCapture(Environment.GetEnvironmentVariable));
        builder.Services.TryAddSingleton<IRealmAuthorityPort>(provider => new ConfiguredRealmAuthority(provider.GetRequiredService<ConfiguredRealmOptionsCapture>(),
            generation => provider.GetService<IPlanExecutor>() is { } executor
                ? new RecoveryEpochReader(new ModulePlanPortFactory(executor, checked((ulong)generation), provider.GetRequiredService<TimeProvider>()),
                    provider.GetRequiredService<TimeProvider>())
                : null));
        builder.Services.TryAddSingleton<IRealmAuthorityFamilyPort>(provider => new ConfiguredRealmAuthorityFamily(
            provider.GetRequiredService<IRealmAuthorityPort>(), () => provider.GetService<IModuleFamilyPortFactory>() as ModuleFamilyPortFactory));
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
    private readonly ConfiguredRealmOptionsCapture configuration;
    private readonly Func<long, IRecoveryEpochPort?> recoveryFactory;

    public ConfiguredRealmAuthority(Func<string, string?> environment, Func<long, IRecoveryEpochPort?> recoveryFactory)
        : this(new ConfiguredRealmOptionsCapture(environment), recoveryFactory)
    {
    }

    public ConfiguredRealmAuthority(ConfiguredRealmOptionsCapture configuration, Func<long, IRecoveryEpochPort?> recoveryFactory)
    {
        this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        this.recoveryFactory = recoveryFactory ?? throw new ArgumentNullException(nameof(recoveryFactory));
    }

    public async Task<RealmAuthorityResult> ResolveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var configured = configuration.Capture();
        if (configured.Failure is { } failure) return RealmAuthorityResult.Refused(failure);
        var recovery = recoveryFactory(configured.ExpectedRecoveryGeneration);
        if (recovery is null) return RealmAuthorityResult.Refused(RealmAuthorityFailure.Unavailable);
        var result = await recovery.ReadAsync(configured.RealmId, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (result.Snapshot is not { } current) return RealmAuthorityResult.Refused(result.Failure switch
        {
            RecoveryEpochFailure.Missing => RealmAuthorityFailure.MissingRecovery,
            RecoveryEpochFailure.Closed => RealmAuthorityFailure.ClosedRecovery,
            RecoveryEpochFailure.StaleGeneration => RealmAuthorityFailure.StaleGeneration,
            RecoveryEpochFailure.Unavailable => RealmAuthorityFailure.Unavailable,
            _ => RealmAuthorityFailure.Defect,
        });
        if (current.RealmId != configured.RealmId || current.Generation < 0 || current.Revision <= 0) return RealmAuthorityResult.Refused(RealmAuthorityFailure.Defect);
        if (current.Generation != configured.ExpectedRecoveryGeneration) return RealmAuthorityResult.Refused(RealmAuthorityFailure.StaleGeneration);
        return RealmAuthorityResult.Available(new RealmAuthoritySnapshot(configured.RealmId, configured.AuthEpoch, current.Generation, current.Revision));
    }

}

/// <summary>One lazy immutable deployment capture shared by authority reads and production transport composition.</summary>
internal sealed record ConfiguredRealmOptions(Guid RealmId, long AuthEpoch, long ExpectedRecoveryGeneration, RealmAuthorityFailure? Failure);

internal sealed class ConfiguredRealmOptionsCapture
{
    private readonly Lazy<ConfiguredRealmOptions> configuration;

    public ConfiguredRealmOptionsCapture(Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        configuration = new Lazy<ConfiguredRealmOptions>(() => Parse(environment), LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public ConfiguredRealmOptions Capture() => configuration.Value;

    public bool TryGetConfigured(out ConfiguredRealmOptions options)
    {
        options = Capture();
        return options.Failure is null;
    }

    private static ConfiguredRealmOptions Parse(Func<string, string?> environment)
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

}

/// <summary>The real configured reader supplies facts; only the exact shared Storage factory can mint a bound capability.</summary>
internal sealed class ConfiguredRealmAuthorityFamily(IRealmAuthorityPort authority, Func<ModuleFamilyPortFactory?> factory) : IRealmAuthorityFamilyPort
{
    public async Task<RealmAuthorityFamilyResult> PrepareAsync(string familyId, string planId, string ownerScope, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var current = await authority.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (current.Snapshot is not { } snapshot) return RealmAuthorityFamilyResult.Refused(current.Failure ?? RealmAuthorityFailure.Defect);
        ModuleFamilyPortFactory? shared;
        try
        {
            shared = factory();
        }
        catch (InvalidOperationException)
        {
            // Microsoft's lazy DI factory reports absent required executor/options this way. Never fall back to a private issuer.
            return RealmAuthorityFamilyResult.Refused(RealmAuthorityFailure.Unavailable);
        }
        if (shared is null) return RealmAuthorityFamilyResult.Refused(RealmAuthorityFailure.Unavailable);
        cancellationToken.ThrowIfCancellationRequested();
        return shared.PrepareRecoveryGuard(snapshot, familyId, planId, ownerScope);
    }
}
