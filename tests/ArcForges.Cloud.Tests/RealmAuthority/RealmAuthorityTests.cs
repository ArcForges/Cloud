// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Platform;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Storage.Platform;
using ArcForges.Cloud.Tests.Entitlement;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.RealmAuthority;

public sealed class RealmAuthorityTests
{
    private static readonly Guid Realm = Guid.Parse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");

    [Fact]
    public async Task ActualOwnerReadAndConfiguredAuthorityFollowDurableCurrentStateWithoutAdoptingNewGeneration()
    {
        using var database = new SqliteBridgeExecutor(0);
        var reader = new RecoveryEpochReader(new ModulePlanPortFactory(database, 0, TimeProvider.System), TimeProvider.System);
        var authority = Authority(reader);
        Assert.Equal(RealmAuthorityFailure.MissingRecovery, (await authority.ResolveAsync(TestContext.Current.CancellationToken)).Failure);
        await Seed(database);
        var current = Assert.IsType<RealmAuthoritySnapshot>((await authority.ResolveAsync(TestContext.Current.CancellationToken)).Snapshot);
        Assert.Equal(new RealmAuthoritySnapshot(Realm, 7, 0, 1), current);
        await database.ExecAsync("UPDATE platform_recovery_epoch SET state=1, rev=2", TestContext.Current.CancellationToken);
        Assert.Equal(RealmAuthorityFailure.ClosedRecovery, (await authority.ResolveAsync(TestContext.Current.CancellationToken)).Failure);
        await database.ExecAsync("UPDATE platform_recovery_epoch SET state=4, recovery_generation=1, rev=3", TestContext.Current.CancellationToken);
        Assert.Equal(RealmAuthorityFailure.StaleGeneration, (await authority.ResolveAsync(TestContext.Current.CancellationToken)).Failure);
        Assert.Equal(4, database.Calls);
    }

    [Fact]
    public async Task ActualReadKeepsRealmsIsolatedAndConcurrentResolutionsRereadEachCurrentVersion()
    {
        using var database = new SqliteBridgeExecutor(0);
        await Seed(database);
        var reader = new RecoveryEpochReader(new ModulePlanPortFactory(database, 0, TimeProvider.System), TimeProvider.System);
        Assert.Equal(RecoveryEpochFailure.Missing, (await reader.ReadAsync(Guid.Parse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), TestContext.Current.CancellationToken)).Failure);
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Authority(reader).ResolveAsync(TestContext.Current.CancellationToken)));
        Assert.All(results, result => Assert.Equal(1, Assert.IsType<RealmAuthoritySnapshot>(result.Snapshot).RecoveryRevision));
        await database.ExecAsync("UPDATE platform_recovery_epoch SET rev=2", TestContext.Current.CancellationToken);
        Assert.Equal(2, Assert.IsType<RecoveryEpochSnapshot>((await reader.ReadAsync(Realm, TestContext.Current.CancellationToken)).Snapshot).Revision);
        Assert.Equal(10, database.Calls);
    }

    [Theory]
    [InlineData("AF_REALM_ID", null, RealmAuthorityFailure.MissingConfiguration)]
    [InlineData("AF_AUTH_EPOCH", null, RealmAuthorityFailure.MissingConfiguration)]
    [InlineData("AF_RECOVERY_GENERATION", null, RealmAuthorityFailure.MissingConfiguration)]
    [InlineData("AF_REALM_ID", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", RealmAuthorityFailure.InvalidConfiguration)]
    [InlineData("AF_REALM_ID", "00000000-0000-0000-0000-000000000000", RealmAuthorityFailure.InvalidConfiguration)]
    [InlineData("AF_REALM_ID", "", RealmAuthorityFailure.InvalidConfiguration)]
    [InlineData("AF_AUTH_EPOCH", "0", RealmAuthorityFailure.InvalidConfiguration)]
    [InlineData("AF_AUTH_EPOCH", "01", RealmAuthorityFailure.InvalidConfiguration)]
    [InlineData("AF_AUTH_EPOCH", "+1", RealmAuthorityFailure.InvalidConfiguration)]
    [InlineData("AF_AUTH_EPOCH", " 1", RealmAuthorityFailure.InvalidConfiguration)]
    [InlineData("AF_AUTH_EPOCH", "9223372036854775808", RealmAuthorityFailure.InvalidConfiguration)]
    [InlineData("AF_RECOVERY_GENERATION", "-1", RealmAuthorityFailure.InvalidConfiguration)]
    [InlineData("AF_RECOVERY_GENERATION", "00", RealmAuthorityFailure.InvalidConfiguration)]
    [InlineData("AF_RECOVERY_GENERATION", "1.0", RealmAuthorityFailure.InvalidConfiguration)]
    public async Task MissingInvalidOrNoncanonicalConfigurationRefusesBeforeStorage(string key, string? value, RealmAuthorityFailure failure)
    {
        var environment = ValidEnvironment();
        environment[key] = value;
        var factoryCalls = 0;
        var authority = new ConfiguredRealmAuthority(name => environment.GetValueOrDefault(name), _ => { factoryCalls++; return null; });
        Assert.Equal(failure, (await authority.ResolveAsync(TestContext.Current.CancellationToken)).Failure);
        Assert.Equal(0, factoryCalls);
    }

    [Fact]
    public async Task LazyImmutableConfigurationNeverUsesProofDefaultsAndUnavailableExecutorRefuses()
    {
        var environment = ValidEnvironment();
        var reads = 0;
        var authority = new ConfiguredRealmAuthority(name => { reads++; return environment.GetValueOrDefault(name); }, _ => null);
        Assert.Equal(0, reads);
        Assert.Equal(RealmAuthorityFailure.Unavailable, (await authority.ResolveAsync(TestContext.Current.CancellationToken)).Failure);
        environment["AF_REALM_ID"] = "invalid";
        Assert.Equal(RealmAuthorityFailure.Unavailable, (await authority.ResolveAsync(TestContext.Current.CancellationToken)).Failure);
        Assert.Equal(3, reads);
    }

    [Fact]
    public async Task RealHostModuleRegistrationAddsNoRouteAndKeepsMissingConfigurationLazy()
    {
        var builder = WebApplication.CreateBuilder();
        var module = new RealmAuthorityModule();
        module.Register(builder);
        Assert.Empty(((IHostModule)module).RpcPolicies);
        Assert.Empty(((IHostModule)module).PlainPaths);
        Assert.Empty(((IHostModule)module).PlainPrefixes);
        using var services = builder.Services.BuildServiceProvider();
        var authority = services.GetRequiredService<IRealmAuthorityPort>();
        // The real environment need not contain this task's configuration, and no executor is configured in this fixture.
        Assert.Null((await authority.ResolveAsync(TestContext.Current.CancellationToken)).Snapshot);
        Assert.Null(services.GetService<ArcForges.Cloud.Storage.IPlanExecutor>());
    }

    [Theory]
    [InlineData(ModulePlanStatus.Rejected, RecoveryEpochFailure.Defect)]
    [InlineData(ModulePlanStatus.GuardRefused, RecoveryEpochFailure.Defect)]
    [InlineData(ModulePlanStatus.StaleGeneration, RecoveryEpochFailure.StaleGeneration)]
    public async Task PermanentReadFailuresDoNotBecomeMissingOrRetry(ModulePlanStatus status, RecoveryEpochFailure failure)
    {
        var plans = new FakePlans(ModulePlanOutcome.Of(status));
        Assert.Equal(failure, (await Reader(plans).ReadAsync(Realm, TestContext.Current.CancellationToken)).Failure);
        Assert.Equal(1, plans.Calls);
    }

    [Fact]
    public async Task TransientReadsRetryBoundedlyAndCallerCancellationStopsBackoff()
    {
        var plans = new FakePlans(ModulePlanOutcome.Of(ModulePlanStatus.UnknownOutcome), ModulePlanOutcome.Of(ModulePlanStatus.Unavailable), Row());
        Assert.NotNull((await Reader(plans).ReadAsync(Realm, TestContext.Current.CancellationToken)).Snapshot);
        Assert.Equal(3, plans.Calls);
        var exhausted = new FakePlans(ModulePlanOutcome.Of(ModulePlanStatus.Unavailable));
        Assert.Equal(RecoveryEpochFailure.Unavailable, (await Reader(exhausted).ReadAsync(Realm, TestContext.Current.CancellationToken)).Failure);
        Assert.Equal(3, exhausted.Calls);
        using var cancel = new CancellationTokenSource();
        var cancelling = new FakePlans(ModulePlanOutcome.Of(ModulePlanStatus.Unavailable)) { AfterRead = cancel.Cancel };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Reader(cancelling).ReadAsync(Realm, cancel.Token));
        Assert.Equal(1, cancelling.Calls);
        var unused = new FakePlans(Row());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Reader(unused).ReadAsync(Realm, cancel.Token));
        Assert.Equal(0, unused.Calls);
    }

    [Fact]
    public async Task ReadDeadlineIsBoundedAndInFlightCallerCancellationIsPropagated()
    {
        var hanging = new FakePlans(Row()) { DuringRead = async token => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Row(); } };
        var reader = new RecoveryEpochReader(hanging, new FastDeadlineTime());
        Assert.Equal(RecoveryEpochFailure.Unavailable, (await reader.ReadAsync(Realm, TestContext.Current.CancellationToken)).Failure);
        Assert.Equal(3, hanging.Calls);
        using var caller = new CancellationTokenSource(TimeSpan.FromMilliseconds(20));
        var cancelled = new FakePlans(Row()) { DuringRead = async token => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Row(); } };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Reader(cancelled).ReadAsync(Realm, caller.Token));
        Assert.Equal(1, cancelled.Calls);
    }

    [Fact]
    public async Task MalformedRowsInvalidRealmAndClosedStatesFailClosed()
    {
        var invalid = new FakePlans(Row());
        Assert.Equal(RecoveryEpochFailure.InvalidRealm, (await Reader(invalid).ReadAsync(Guid.Empty, TestContext.Current.CancellationToken)).Failure);
        Assert.Equal(0, invalid.Calls);
        var malformed = new[]
        {
            new ModulePlanOutcome(ModulePlanStatus.Succeeded, [[], []]),
            new ModulePlanOutcome(ModulePlanStatus.Succeeded, [[PlanValue.FromText("wrong")]]),
            Row(generation: -1), Row(revision: 0), Row(state: 0), Row(state: 5),
            new ModulePlanOutcome(ModulePlanStatus.Succeeded, [[PlanValue.FromText(Realm.ToString("D")), PlanValue.FromText("0"), PlanValue.FromInt64(4), PlanValue.FromInt64(1)]]),
            new ModulePlanOutcome(ModulePlanStatus.Succeeded, [[PlanValue.FromText(Guid.Empty.ToString("D")), PlanValue.FromInt64(0), PlanValue.FromInt64(4), PlanValue.FromInt64(1)]]),
        };
        foreach (var outcome in malformed) Assert.Equal(RecoveryEpochFailure.Defect, (await Reader(new FakePlans(outcome)).ReadAsync(Realm, TestContext.Current.CancellationToken)).Failure);
        foreach (var state in new[] { 1, 2, 3 }) Assert.Equal(RecoveryEpochFailure.Closed, (await Reader(new FakePlans(Row(state: state))).ReadAsync(Realm, TestContext.Current.CancellationToken)).Failure);
    }

    [Fact]
    public async Task SharedPortValidatesDependencySnapshotAndClosedResultContracts()
    {
        Assert.Throws<ArgumentNullException>(() => RealmAuthorityResult.Available(null!));
        Assert.Throws<ArgumentNullException>(() => RecoveryEpochResult.Available(null!));
        Assert.Null(RealmAuthorityResult.Refused(RealmAuthorityFailure.Defect).Snapshot);
        Assert.Null(RecoveryEpochResult.Refused(RecoveryEpochFailure.Defect).Snapshot);
        var mismatched = new SnapshotPort(new RecoveryEpochSnapshot(Guid.Empty, 0, 1));
        Assert.Equal(RealmAuthorityFailure.Defect, (await Authority(mismatched).ResolveAsync(TestContext.Current.CancellationToken)).Failure);
        var maximum = ValidEnvironment();
        maximum["AF_AUTH_EPOCH"] = long.MaxValue.ToString(System.Globalization.CultureInfo.InvariantCulture);
        maximum["AF_RECOVERY_GENERATION"] = long.MaxValue.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var authority = new ConfiguredRealmAuthority(maximum.GetValueOrDefault, generation => new SnapshotPort(new RecoveryEpochSnapshot(Realm, generation, 1)));
        Assert.Equal(long.MaxValue, Assert.IsType<RealmAuthoritySnapshot>((await authority.ResolveAsync(TestContext.Current.CancellationToken)).Snapshot).AuthEpoch);
    }

    [Theory]
    [InlineData(RecoveryEpochFailure.InvalidRealm, RealmAuthorityFailure.Defect)]
    [InlineData(RecoveryEpochFailure.Missing, RealmAuthorityFailure.MissingRecovery)]
    [InlineData(RecoveryEpochFailure.Closed, RealmAuthorityFailure.ClosedRecovery)]
    [InlineData(RecoveryEpochFailure.StaleGeneration, RealmAuthorityFailure.StaleGeneration)]
    [InlineData(RecoveryEpochFailure.Unavailable, RealmAuthorityFailure.Unavailable)]
    [InlineData(RecoveryEpochFailure.Defect, RealmAuthorityFailure.Defect)]
    public async Task DependencyFailureRemainsExplicitAndNeverReturnsAuthority(RecoveryEpochFailure dependency, RealmAuthorityFailure expected)
    {
        var authority = Authority(new FailedRecoveryPort(dependency));
        var result = await authority.ResolveAsync(TestContext.Current.CancellationToken);
        Assert.Equal(expected, result.Failure);
        Assert.Null(result.Snapshot);
    }

    private static Task Seed(SqliteBridgeExecutor database) => database.ExecAsync(
        "INSERT INTO platform_recovery_epoch VALUES ('" + Realm.ToString("D") + "',0,'fixture',zeroblob(32),4,1,1)", TestContext.Current.CancellationToken);

    private static Dictionary<string, string?> ValidEnvironment() => new(StringComparer.Ordinal)
    {
        ["AF_REALM_ID"] = Realm.ToString("D"),
        ["AF_AUTH_EPOCH"] = "7",
        ["AF_RECOVERY_GENERATION"] = "0",
    };

    private static ConfiguredRealmAuthority Authority(IRecoveryEpochPort reader) => new(ValidEnvironment().GetValueOrDefault, _ => reader);

    private static RecoveryEpochReader Reader(FakePlans plans) => new(plans, TimeProvider.System);

    private static ModulePlanOutcome Row(long generation = 0, long state = 4, long revision = 1) => new(ModulePlanStatus.Succeeded,
        [[PlanValue.FromText(Realm.ToString("D")), PlanValue.FromInt64(generation), PlanValue.FromInt64(state), PlanValue.FromInt64(revision)]]);

    private sealed class SnapshotPort(RecoveryEpochSnapshot snapshot) : IRecoveryEpochPort
    {
        public Task<RecoveryEpochResult> ReadAsync(Guid realmId, CancellationToken cancellationToken) => Task.FromResult(RecoveryEpochResult.Available(snapshot));
    }

    private sealed class FailedRecoveryPort(RecoveryEpochFailure failure) : IRecoveryEpochPort
    {
        public Task<RecoveryEpochResult> ReadAsync(Guid realmId, CancellationToken cancellationToken) => Task.FromResult(RecoveryEpochResult.Refused(failure));
    }

    private sealed class FakePlans(params ModulePlanOutcome[] outcomes) : IModulePlanPortFactory, IModulePlanPort
    {
        public int Calls { get; private set; }

        public Action? AfterRead { get; init; }

        public Func<CancellationToken, Task<ModulePlanOutcome>>? DuringRead { get; init; }

        public IModulePlanPort For(ModuleDescriptor module)
        {
            Assert.Equal("platform", module.PlanOwner);
            return this;
        }

        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken)
        {
            Assert.Equal("platform.recovery-current", read.PlanId);
            Assert.Equal("platform", read.OwnerScope);
            Assert.Single(read.Arguments);
            var result = outcomes[Math.Min(Calls++, outcomes.Length - 1)];
            AfterRead?.Invoke();
            return DuringRead?.Invoke(cancellationToken) ?? Task.FromResult(result);
        }

        public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken) => throw new InvalidOperationException("Authority never writes.");
    }

    private sealed class FastDeadlineTime : TimeProvider
    {
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) =>
            TimeProvider.System.CreateTimer(callback, state, dueTime == TimeSpan.FromSeconds(8) ? TimeSpan.FromMilliseconds(1) : dueTime, period);
    }
}
