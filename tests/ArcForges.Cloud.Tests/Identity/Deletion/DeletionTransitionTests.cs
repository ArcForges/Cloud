// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Identity;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Recovery.Application;
using ArcForges.Cloud.Modules.Identity.Recovery.Configuration;
using ArcForges.Cloud.Modules.Identity.Recovery.Domain;
using ArcForges.Cloud.Modules.Identity.Recovery.Infrastructure;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Storage.SharedFamilies;
using ArcForges.Cloud.Tests.Receipts;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.Deletion;

public sealed class DeletionTransitionTests
{
    private static readonly Guid Realm = Samples.Id(10), User = Samples.Id(11), Deletion = Samples.Id(12), Workspace = Samples.Id(13);
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;
    private static DeletionTransitionTarget Target(DeletionTransition transition) => new(transition, Realm, User, Deletion, Workspace.ToString("D"));
    private static DeletionLifecycle Pending => new(Deletion, Realm, User, 100, 1_000_100, "original.v1", 1, UserState.Suspended, DeletionState.Pending, null, null, 2);

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task RequestCapturesActualUserAndOneImmutablePolicy(int stateValue)
    {
        var state = (UserState)stateValue;
        var store = new Store { User = new(new(state, 7, null), null) };
        var fixture = new Fixture();
        var service = Service(store, fixture, policy: new(new IdentityDeletionPolicyInput("new.v2", "5")));
        var result = await service.PrepareAsync(Target(DeletionTransition.Request), Cancellation);
        var prepared = Assert.IsType<DeletionTransitionPreparation>(result.Value);
        Assert.Null(result.Failure);
        Assert.Equal(state, prepared.Lifecycle.PreviousUserState);
        Assert.Equal("new.v2", prepared.Lifecycle.PolicyVersion);
        Assert.Equal(500, prepared.Lifecycle.RequestedAtMicros);
        Assert.Equal(5_000_500, prepared.Lifecycle.GraceEndsAtMicros);
        Assert.Equal(7, prepared.UserRevision);
        Assert.Equal(1, prepared.Lifecycle.Revision);
        Assert.NotNull(prepared.Contribution);
        Assert.Equal("families.account-security.request-deletion", fixture.Plan);
        Assert.Equal(7, fixture.Items!.Single(item => item.Key == "deletion-request-user").Arguments[3].AsInt64());
        Assert.Equal(5_000_500, fixture.Items!.Single(item => item.Key == "deletion-lifecycle").Arguments[4].AsInt64());
        Assert.Equal(1, store.UserReads);
        Assert.Equal(0, store.LifecycleReads);
        Assert.Empty(fixture.Executor.Calls); // Preparation never commits an incomplete security family.
    }

    [Fact]
    public async Task CancelUsesOriginalStateAndDeadlineWithoutResolvingNewPolicy()
    {
        var fixture = new Fixture();
        var policy = new DeletionPolicy(_ => throw new InvalidOperationException("Existing requests do not read new-request policy."));
        var result = await Service(new Store(), fixture, policy: policy).PrepareAsync(Target(DeletionTransition.Cancel), Cancellation);
        Assert.Equal(Pending, Assert.IsType<DeletionTransitionPreparation>(result.Value).Lifecycle);
        Assert.Equal("families.account-security.cancel-deletion", fixture.Plan);
        Assert.Equal((long)UserState.Suspended, fixture.Items!.Single(item => item.Key == "deletion-user" && item.Class == "record").Arguments[0].AsInt64());
        Assert.Equal("original.v1", fixture.Items!.Single(item => item.Key == "deletion-current").Arguments[4].AsText());
        Assert.Empty(fixture.Executor.Calls);
    }

    [Theory]
    [InlineData(1, 1, 100, null)]
    [InlineData(1, 1, 1_000_099, null)]
    [InlineData(1, 1, 1_000_100, IdentityDeletionFailure.Expired)]
    [InlineData(1, 3, 500, IdentityDeletionFailure.NotPending)]
    [InlineData(2, 1, 1_000_099, IdentityDeletionFailure.NotPending)]
    [InlineData(2, 1, 1_000_100, null)]
    [InlineData(3, 1, 1_000_100, IdentityDeletionFailure.NotPending)]
    [InlineData(3, 3, 1_000_100, null)]
    public async Task ExactLifecycleWindowsAndStatesAreRequired(int transitionValue, int stateValue, long at, IdentityDeletionFailure? expected)
    {
        var transition = (DeletionTransition)transitionValue;
        var state = (DeletionState)stateValue;
        var fixture = new Fixture();
        var store = new Store { Lifecycle = new(new(Pending with { State = state }, UserState.PendingDeletion, 7, 100), null) };
        var result = await Service(store, fixture, new Clock { At = at }).PrepareAsync(Target(transition), Cancellation);
        Assert.Equal(expected, result.Failure);
        Assert.Equal(expected is null, result.Value is not null);
        Assert.Equal(expected is null ? 1 : 0, fixture.Seals);
        if (expected is null)
            Assert.Equal(transition == DeletionTransition.Cancel ? 7 : 6, fixture.Items!.Single(item => item.Key is "deletion-current" or "deletion-due" or "deletion-purging").Arguments.Count);
        Assert.Empty(fixture.Executor.Calls);
        // These are request-time preparation checks, not a claim of transaction-time expiry/purge fencing.
    }

    [Fact]
    public async Task MissingPolicyAndInvalidPersistedAuthorityNeverSeal()
    {
        var fixture = new Fixture();
        var store = new Store();
        Assert.Equal(IdentityDeletionFailure.Unavailable,
            (await Service(store, fixture, policy: new(new IdentityDeletionPolicyInput(null, null))).PrepareAsync(Target(DeletionTransition.Request), Cancellation)).Failure);
        foreach (var stored in new[]
        {
            new DeletionUserAuthority(UserState.PendingDeletion, 7, null), new(UserState.Active, 7, 10),
            new(UserState.Active, 0, null), new(UserState.Active, long.MaxValue, null),
        })
        {
            store.User = new(stored, null);
            var result = await Service(store, fixture).PrepareAsync(Target(DeletionTransition.Request), Cancellation);
            Assert.Null(result.Value);
            Assert.NotNull(result.Failure);
        }
        foreach (var stored in new[]
        {
            new StoredDeletionAuthority(Pending, UserState.Active, 7), new(Pending, UserState.PendingDeletion, 0),
            new(Pending with { RealmId = Guid.NewGuid() }, UserState.PendingDeletion, 7),
            new(Pending with { GraceEndsAtMicros = 1_000_101 }, UserState.PendingDeletion, 7),
            new(Pending with { Revision = long.MaxValue }, UserState.PendingDeletion, 7),
        })
        {
            store.Lifecycle = new(stored, null);
            Assert.Null((await Service(store, fixture).PrepareAsync(Target(DeletionTransition.Cancel), Cancellation)).Value);
        }
        Assert.Equal(0, fixture.Seals);
    }

    [Fact]
    public async Task AuthorityRefusalsAndWrongScopeStopBeforeStorage()
    {
        var fixture = new Fixture();
        var store = new Store();
        foreach (var (failure, expected) in new[]
        {
            (RealmAuthorityFailure.MissingConfiguration, IdentityDeletionFailure.Unavailable),
            (RealmAuthorityFailure.InvalidConfiguration, IdentityDeletionFailure.Unavailable),
            (RealmAuthorityFailure.Unavailable, IdentityDeletionFailure.Unavailable),
            (RealmAuthorityFailure.StaleGeneration, IdentityDeletionFailure.StaleAuthority),
            (RealmAuthorityFailure.Defect, IdentityDeletionFailure.Defect),
        })
            Assert.Equal(expected, (await Service(store, fixture, authority: new(RealmAuthorityResult.Refused(failure)))
                .PrepareAsync(Target(DeletionTransition.Request), Cancellation)).Failure);
        Assert.Equal(IdentityDeletionFailure.StaleAuthority, (await Service(store, fixture)
            .PrepareAsync(Target(DeletionTransition.Request) with { OwnerScope = "caller-scope" }, Cancellation)).Failure);
        Assert.Equal(IdentityDeletionFailure.StaleAuthority, (await Service(store, fixture, authority: new(RealmAuthorityResult.Available(new(Guid.NewGuid(), 1, 0, 1))))
            .PrepareAsync(Target(DeletionTransition.Request), Cancellation)).Failure);
        Assert.Equal(0, store.UserReads + store.LifecycleReads);
        Assert.Equal(0, fixture.Seals);
    }

    [Fact]
    public async Task CancellationAndReadFailuresCannotBecomePreparedAuthority()
    {
        var fixture = new Fixture();
        var store = new Store { User = new(null, IdentityDeletionFailure.Unavailable) };
        Assert.Equal(IdentityDeletionFailure.Unavailable, (await Service(store, fixture).PrepareAsync(Target(DeletionTransition.Request), Cancellation)).Failure);
        store.User = new(null, null);
        Assert.Equal(IdentityDeletionFailure.Defect, (await Service(store, fixture).PrepareAsync(Target(DeletionTransition.Request), Cancellation)).Failure);
        using var cancellation = new CancellationTokenSource();
        store.AfterRead = cancellation.Cancel;
        store.User = new(new(UserState.Active, 7, null), null);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Service(store, fixture).PrepareAsync(Target(DeletionTransition.Request), cancellation.Token));
        var reads = store.UserReads;
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Service(store, fixture).PrepareAsync(Target(DeletionTransition.Request), cancellation.Token));
        Assert.Equal(reads, store.UserReads);
        Assert.Equal(0, fixture.Seals);
    }

    [Fact]
    public async Task DifferentCurrentUserRequestCannotReuseOriginalLifecycleAuthority()
    {
        var fixture = new Fixture();
        foreach (var timestamp in new long?[] { null, 99, 101 })
        {
            var store = new Store { Lifecycle = new(new(Pending, UserState.PendingDeletion, 7, timestamp), null) };
            Assert.Equal(IdentityDeletionFailure.StaleAuthority, (await Service(store, fixture).PrepareAsync(Target(DeletionTransition.Cancel), Cancellation)).Failure);
        }
        Assert.Equal(0, fixture.Seals);
    }

    [Fact]
    public async Task ClockIsSampledAfterPersistenceAndCannotTravelBeforeRequest()
    {
        var fixture = new Fixture();
        var clock = new Clock();
        var store = new Store { AfterRead = () => clock.At = 1_000_100 };
        Assert.Equal(IdentityDeletionFailure.Expired, (await Service(store, fixture, clock).PrepareAsync(Target(DeletionTransition.Cancel), Cancellation)).Failure);
        store.AfterRead = () => clock.At = 99;
        Assert.Equal(IdentityDeletionFailure.StaleAuthority, (await Service(store, fixture, clock).PrepareAsync(Target(DeletionTransition.Cancel), Cancellation)).Failure);
        Assert.Equal(0, fixture.Seals);
    }

    [Fact]
    public async Task PersistedDeadlineCapabilityUsesActualOwnerFactoryAndFreshRevisionWithoutWriting()
    {
        var fixture = new Fixture();
        fixture.Executor.Handler = call => call.Plan.Id == "identity.deletion-current"
            ? ScriptedExecutor.Rows([D1Values.Text(Deletion.ToString("D")), D1Values.Text(Realm.ToString("D")), D1Values.Text(User.ToString("D")),
                D1Values.Int64(100), D1Values.Int64(1_000_100), D1Values.Text("original.v1"), D1Values.Int64(1), D1Values.Int64(3),
                D1Values.Int64(1), D1Values.Null(), D1Values.Null(), D1Values.Int64(2), D1Values.Int64(4), D1Values.Int64(7), D1Values.Int64(100)])
            : throw new InvalidOperationException("Preparation must never write.");
        var reader = new DeletionLifecyclePort(new ModulePlanPortFactory(fixture.Executor, 0, new Clock()).For(IdentityModule.Instance.Descriptor),
            fixture, new Authority(RealmAuthorityResult.Available(new(Realm, 3, 0, 2))), new Clock());
        var result = await reader.PrepareAsync(Realm, User, "account-security", "families.account-security.cancel-deletion", Workspace.ToString("D"), Cancellation);
        Assert.NotNull(result.Snapshot);
        Assert.NotNull(result.Contribution);
        Assert.Null(result.Failure);
        Assert.Equal(2, fixture.Items!.Single(item => item.Key == "deletion-revision").Arguments[1].AsInt64());
        Assert.Equal(1, fixture.Items!.Single(item => item.Key == "deletion-current").Arguments[5].AsInt64());
        Assert.Equal(7, fixture.Items!.Single(item => item.Key == "deletion-user" && item.Class == "authorization").Arguments[4].AsInt64());
        Assert.Single(fixture.Executor.Calls);
        Assert.Equal(PlanAccess.Read, fixture.Executor.Calls[0].Plan.Access);
        await Assert.ThrowsAsync<InvalidOperationException>(() => reader.PrepareAsync(Realm, User, "account-security", "families.account-security.unknown", Workspace.ToString("D"), Cancellation));
        Assert.Equal(1, fixture.Seals);
    }

    [Fact]
    public async Task PublicResultContractsRejectNullOrUndefinedAndMaintainExclusiveOutcomes()
    {
        var fixture = new Fixture();
        var prepared = Assert.IsType<DeletionTransitionPreparation>((await Service(new Store(), fixture).PrepareAsync(Target(DeletionTransition.Request), Cancellation)).Value);
        var value = prepared.Lifecycle;
        var snapshot = new IdentityDeletionSnapshot(value.DeletionId, value.RealmId, value.UserId, value.RequestedAtMicros, value.GraceEndsAtMicros,
            value.PolicyVersion, value.GraceSeconds, (IdentityDeletionPreviousState)value.PreviousUserState, value.Revision, prepared.UserRevision);
        Assert.Throws<ArgumentNullException>(() => IdentityDeletionResult.Available(null!));
        Assert.Throws<ArgumentNullException>(() => IdentityDeletionFamilyResult.Available(null!, prepared.Contribution));
        Assert.Throws<ArgumentNullException>(() => IdentityDeletionFamilyResult.Available(snapshot, null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => IdentityDeletionResult.Refused((IdentityDeletionFailure)999));
        Assert.Throws<ArgumentOutOfRangeException>(() => IdentityDeletionFamilyResult.Refused((IdentityDeletionFailure)999));
        var available = IdentityDeletionResult.Available(snapshot);
        Assert.Same(snapshot, available.Snapshot); Assert.Null(available.Failure);
        var capability = IdentityDeletionFamilyResult.Available(snapshot, prepared.Contribution);
        Assert.Same(snapshot, capability.Snapshot); Assert.Same(prepared.Contribution, capability.Contribution); Assert.Null(capability.Failure);
        foreach (var failure in Enum.GetValues<IdentityDeletionFailure>())
        {
            var refused = IdentityDeletionResult.Refused(failure);
            Assert.Null(refused.Snapshot); Assert.Equal(failure, refused.Failure);
            var refusedFamily = IdentityDeletionFamilyResult.Refused(failure);
            Assert.Null(refusedFamily.Snapshot); Assert.Null(refusedFamily.Contribution); Assert.Equal(failure, refusedFamily.Failure);
        }
    }

    [Fact]
    public async Task ModuleCompositionUsesSameRealReaderAndLazyRequiredPolicyWithoutBootstrapWrite()
    {
        var fixture = new Fixture();
        var services = new ServiceCollection();
        services.AddSingleton<IModulePlanPortFactory>(new ModulePlanPortFactory(fixture.Executor, 0, new Clock()));
        services.AddSingleton<IModuleFamilyPortFactory>(fixture.Factory);
        services.AddSingleton<IRealmAuthorityPort>(new Authority(RealmAuthorityResult.Available(new(Realm, 3, 0, 2))));
        services.AddSingleton<TimeProvider>(new Clock());
        services.AddSingleton(new IdentityDeletionPolicyInput(null, null));
        ((IModuleBoundary)IdentityModule.Instance).Register(services);
        using var provider = services.BuildServiceProvider();
        var reader = provider.GetRequiredService<IIdentityDeletionLifecyclePort>();
        Assert.Same(reader, provider.GetRequiredService<IDeletionTransitionStore>());
        fixture.Executor.Handler = _ => ScriptedExecutor.Rows([D1Values.Text(Realm.ToString("D")), D1Values.Text(User.ToString("D")), D1Values.Int64(1), D1Values.Null(), D1Values.Int64(7)]);
        var result = await provider.GetRequiredService<DeletionLifecycleService>().PrepareAsync(Target(DeletionTransition.Request), Cancellation);
        Assert.Equal(IdentityDeletionFailure.Unavailable, result.Failure);
        Assert.Single(fixture.Executor.Calls);
        Assert.Equal(PlanAccess.Read, fixture.Executor.Calls[0].Plan.Access);
    }

    private static DeletionLifecycleService Service(Store store, Fixture fixture, Clock? clock = null, DeletionPolicy? policy = null, Authority? authority = null)
        => new(store, policy ?? new(new IdentityDeletionPolicyInput("new.v2", "5")), authority ?? new(RealmAuthorityResult.Available(new(Realm, 3, 0, 2))), fixture, clock ?? new Clock());

    private sealed class Store : IDeletionTransitionStore
    {
        public DeletionStoredResult<DeletionUserAuthority> User { get; set; } = new(new(UserState.Active, 7, null), null);
        public DeletionStoredResult<StoredDeletionAuthority> Lifecycle { get; set; } = new(new(Pending, UserState.PendingDeletion, 7, 100), null);
        public int UserReads { get; private set; }
        public int LifecycleReads { get; private set; }
        public Action? AfterRead { get; set; }
        public Task<DeletionStoredResult<DeletionUserAuthority>> UserAsync(Guid realmId, Guid userId, CancellationToken cancellationToken)
        { Assert.Equal(Realm, realmId); Assert.Equal(DeletionTransitionTests.User, userId); UserReads++; AfterRead?.Invoke(); return Task.FromResult(User); }
        public Task<DeletionStoredResult<StoredDeletionAuthority>> LifecycleAsync(Guid realmId, Guid userId, Guid deletionId, CancellationToken cancellationToken)
        { Assert.Equal(Realm, realmId); Assert.Equal(DeletionTransitionTests.User, userId); Assert.Equal(Deletion, deletionId); LifecycleReads++; AfterRead?.Invoke(); return Task.FromResult(Lifecycle); }
    }

    private sealed class Clock : TimeProvider
    {
        public long At { get; set; } = 500;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddTicks(At * 10);
    }
    private sealed class Authority(RealmAuthorityResult result) : IRealmAuthorityPort
    { public Task<RealmAuthorityResult> ResolveAsync(CancellationToken cancellationToken) => Task.FromResult(result); }

    // Closed test-owned future consumer catalogue: real production factory seals and validates roles/argument counts.
    // There is no production catalogue activation and no invented successful executor/foreign participant.
    private sealed class Fixture : IModuleFamilyPort
    {
        public ScriptedExecutor Executor { get; } = new();
        public ModuleFamilyPortFactory Factory { get; }
        private readonly IModuleFamilyPort port;
        public string? Plan { get; private set; }
        public IReadOnlyList<ModuleFamilyContribution>? Items { get; private set; }
        public int Seals { get; private set; }
        public Fixture()
        {
            var catalog = new[] { new FamilyDefinition("account-security", "Deletion fixture", "CLOUD79 test-owned future consumer", [new(FamilyModule.Identity, true, null)]) };
            FamilyPlanDefinition[] plans =
            [
                PlanFor("request-deletion", [("authorization", "deletion-request-user", "ttii"), ("revision", "deletion-pending-empty", "tii"), ("revision", "deletion-purging-empty", "tii"), ("revision", "deletion-revision", "ti"), ("record", "deletion-lifecycle", "tttiitii"), ("record", "deletion-user", "iti")]),
                PlanFor("cancel-deletion", [("authorization", "deletion-current", "tttitii"), ("authorization", "deletion-user", "ttiii"), ("revision", "deletion-revision", "ti"), ("record", "deletion-lifecycle", "iti"), ("record", "deletion-user", "iti")]),
                PlanFor("begin-deletion-purge", [("authorization", "deletion-due", "tttiti"), ("authorization", "deletion-user", "ttiii"), ("revision", "deletion-revision", "ti"), ("record", "deletion-lifecycle", "ti")]),
                PlanFor("complete-deletion-purge", [("authorization", "deletion-purging", "tttiti"), ("authorization", "deletion-user", "ttiii"), ("revision", "deletion-revision", "ti"), ("record", "deletion-lifecycle", "iti"), ("record", "deletion-user", "ti")]),
            ];
            Factory = new ModuleFamilyPortFactory(Executor, 0, new Clock(), catalog, plans);
            port = Factory.For(IdentityModule.Instance.Descriptor);
        }
        private static FamilyPlanDefinition PlanFor(string name, (string Class, string Key, string Types)[] own)
        {
            var roles = own.Select(item => new FamilyStatementRole(FamilyModule.Identity, item.Class == "record" ? FamilyPhase.Mutation : FamilyPhase.Guard,
                item.Class == "record" ? FamilyClass.Record : item.Class == "revision" ? FamilyClass.Revision : FamilyClass.Authorization, item.Key)).ToArray();
            var statements = own.Select(item => new PlanStatement([.. (item.Class == "record" ? "" : "t").Concat(item.Types).Select(type => new PlanParam(type == 't' ? PlanKind.Text : PlanKind.Int64))], null)).ToArray();
            return new(new("families.account-security." + name, 1, PlanAccess.Write, 0,
                [.. statements, new PlanStatement([new(PlanKind.Text)], null)]), "account-security",
                [.. roles, new(FamilyModule.Platform, FamilyPhase.Release, FamilyClass.Release, "release")]);
        }
        public IModuleFamilyContributionSet Contribute(string familyId, string planId, IReadOnlyList<ModuleFamilyContribution> contributions)
        { var sealedSet = port.Contribute(familyId, planId, contributions); Plan = planId; Items = contributions; Seals++; return sealedSet; }
        public Task<ModulePlanOutcome> ReadAsync(string familyId, ModulePlanRead read, CancellationToken cancellationToken) => throw new InvalidOperationException("No foreign reads in preparation.");
        public Task<ModulePlanOutcome> InspectAsync(string familyId, ModuleCommandIdentity identity, CancellationToken cancellationToken) => throw new InvalidOperationException("No commit preflight in preparation.");
        public Task<ModulePlanOutcome> WriteAsync(ModuleFamilyWrite write, CancellationToken cancellationToken) => throw new InvalidOperationException("Only CLOUD17 can assemble full deletion writes.");
    }
}
