// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Identity.Recovery.Infrastructure;
using Xunit;

namespace ArcForges.Cloud.Tests.Deletion;

public sealed class DeletionReaderTests
{
    private static readonly Guid Realm = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    private static readonly Guid User = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    private static readonly Guid Deletion = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ExistingDisclosureIsIndependentOfNewRequestConfiguration()
    {
        var plans = new Plans(Row());
        var value = await Reader(plans).ReadAsync(Realm, User, Cancellation);
        var snapshot = Assert.IsType<IdentityDeletionSnapshot>(value.Snapshot);
        Assert.Equal("policy.v1", snapshot.PolicyVersion);
        Assert.Equal(1_000_100, snapshot.GraceEndsAtMicros);
        Assert.Equal(IdentityDeletionPreviousState.Suspended, snapshot.PreviousUserState);
        Assert.Equal(2, snapshot.LifecycleRevision);
        Assert.Equal(7, snapshot.UserRevision);
        Assert.Equal(1, plans.Calls);
        Assert.Null(value.Failure);
    }

    [Theory]
    [InlineData(ModulePlanStatus.Rejected, IdentityDeletionFailure.Defect)]
    [InlineData(ModulePlanStatus.StaleGeneration, IdentityDeletionFailure.StaleAuthority)]
    [InlineData(ModulePlanStatus.GuardRefused, IdentityDeletionFailure.StaleAuthority)]
    [InlineData(ModulePlanStatus.Replayed, IdentityDeletionFailure.Defect)]
    public async Task PermanentFailuresDoNotBecomeMissingOrRetry(ModulePlanStatus status, IdentityDeletionFailure expected)
    {
        var plans = new Plans(ModulePlanOutcome.Of(status));
        Assert.Equal(expected, (await Reader(plans).ReadAsync(Realm, User, Cancellation)).Failure);
        Assert.Equal(1, plans.Calls);
    }

    [Fact]
    public async Task RetryIsBoundedAndCancellationStopsBeforeAnotherDispatch()
    {
        var plans = new Plans(ModulePlanOutcome.Of(ModulePlanStatus.Unavailable), ModulePlanOutcome.Of(ModulePlanStatus.UnknownOutcome), Row());
        Assert.NotNull((await Reader(plans).ReadAsync(Realm, User, Cancellation)).Snapshot);
        Assert.Equal(3, plans.Calls);
        var exhausted = new Plans(ModulePlanOutcome.Of(ModulePlanStatus.Unavailable));
        Assert.Equal(IdentityDeletionFailure.Unavailable, (await Reader(exhausted).ReadAsync(Realm, User, Cancellation)).Failure);
        Assert.Equal(3, exhausted.Calls);
        using var cancelled = new CancellationTokenSource();
        var first = new Plans(ModulePlanOutcome.Of(ModulePlanStatus.Unavailable)) { AfterRead = cancelled.Cancel };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Reader(first).ReadAsync(Realm, User, cancelled.Token));
        Assert.Equal(1, first.Calls);
        var never = new Plans(Row());
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Reader(never).ReadAsync(Realm, User, cancelled.Token));
        Assert.Equal(0, never.Calls);
    }

    [Fact]
    public async Task ReadDeadlineRemainsUnavailableAndCallerCancellationPropagates()
    {
        var hanging = new Plans(Row()) { DuringRead = async token => { await Task.Delay(Timeout.InfiniteTimeSpan, token); return Row(); } };
        Assert.Equal(IdentityDeletionFailure.Unavailable, (await Reader(hanging, new FastDeadline()).ReadAsync(Realm, User, Cancellation)).Failure);
        Assert.Equal(3, hanging.Calls);
        using var cancelled = new CancellationTokenSource();
        var first = new Plans(Row()) { DuringRead = token => { cancelled.Cancel(); return Task.FromCanceled<ModulePlanOutcome>(token); } };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Reader(first).ReadAsync(Realm, User, cancelled.Token));
        Assert.Equal(1, first.Calls);
    }

    [Fact]
    public async Task RealmAuthorityAndInvalidIdentifiersRefuseBeforeStorage()
    {
        foreach (var failure in new[] { RealmAuthorityFailure.MissingConfiguration, RealmAuthorityFailure.InvalidConfiguration, RealmAuthorityFailure.Unavailable })
        {
            var plans = new Plans(Row());
            var reader = Reader(plans, authority: new Authority(RealmAuthorityResult.Refused(failure)));
            Assert.Equal(IdentityDeletionFailure.Unavailable, (await reader.ReadAsync(Realm, User, Cancellation)).Failure);
            Assert.Equal(0, plans.Calls);
        }
        var untouched = new Plans(Row());
        Assert.Equal(IdentityDeletionFailure.StaleAuthority, (await Reader(untouched).ReadAsync(Guid.Empty, User, Cancellation)).Failure);
        Assert.Equal(0, untouched.Calls);
        var wrong = new Authority(RealmAuthorityResult.Available(new(Guid.NewGuid(), 1, 0, 1)));
        Assert.Equal(IdentityDeletionFailure.StaleAuthority, (await Reader(untouched, authority: wrong).ReadAsync(Realm, User, Cancellation)).Failure);
        Assert.Equal(0, untouched.Calls);
    }

    [Fact]
    public async Task MalformedShapeAndEnumOverflowNeverBecomeAuthority()
    {
        var row = Row().Rows[0];
        var malformed = new List<ModulePlanOutcome>
        {
            new(ModulePlanStatus.Succeeded, [[], []]),
            new(ModulePlanStatus.Succeeded, [[PlanValue.FromText("malformed")]]),
        };
        foreach (var (index, value) in new (int, PlanValue)[]
        {
            (0, T(Deletion.ToString("D").ToUpperInvariant())), (1, T(Guid.NewGuid().ToString("D"))),
            (4, I(1_000_101)), (6, I(long.MaxValue)), (7, I(4_294_967_297)), (8, I(4_294_967_297)),
            (9, I(500)), (11, I(0)), (13, I(0)), (4, T("1000100")),
        })
        {
            var copy = row.ToArray();
            copy[index] = value;
            malformed.Add(new(ModulePlanStatus.Succeeded, [copy]));
        }
        foreach (var outcome in malformed)
            Assert.Equal(IdentityDeletionFailure.Defect, (await Reader(new Plans(outcome)).ReadAsync(Realm, User, Cancellation)).Failure);
        Assert.Equal(IdentityDeletionFailure.NotPending, (await Reader(new Plans(new ModulePlanOutcome(ModulePlanStatus.Succeeded, []))).ReadAsync(Realm, User, Cancellation)).Failure);
    }

    [Fact]
    public async Task SampleAfterReadsEnforcesExactDeadlineAndCurrentUserState()
    {
        var time = new Clock();
        var delayed = new Plans(Row()) { AfterRead = () => time.At = 1_000_100 };
        Assert.Equal(IdentityDeletionFailure.Expired, (await Reader(delayed, time).ReadAsync(Realm, User, Cancellation)).Failure);
        time.At = 99;
        Assert.Equal(IdentityDeletionFailure.StaleAuthority, (await Reader(new Plans(Row()), time).ReadAsync(Realm, User, Cancellation)).Failure);
        var row = Row().Rows[0].ToArray();
        row[12] = I(1);
        Assert.Equal(IdentityDeletionFailure.StaleAuthority, (await Reader(new Plans(new ModulePlanOutcome(ModulePlanStatus.Succeeded, [row]))).ReadAsync(Realm, User, Cancellation)).Failure);
    }

    [Fact]
    public async Task PendingLifecycleMustMatchActualUserDeletionRequestTimestamp()
    {
        foreach (var timestamp in new[] { PlanValue.Null, I(99), I(101) })
        {
            var row = Row().Rows[0].ToArray();
            row[14] = timestamp;
            var result = await Reader(new Plans(new ModulePlanOutcome(ModulePlanStatus.Succeeded, [row]))).ReadAsync(Realm, User, Cancellation);
            Assert.Equal(IdentityDeletionFailure.StaleAuthority, result.Failure);
            Assert.Null(result.Snapshot);
        }
    }

    private static DeletionLifecyclePort Reader(Plans plans, TimeProvider? time = null, IRealmAuthorityPort? authority = null)
        => new(plans, new NoFamily(), authority ?? new Authority(RealmAuthorityResult.Available(new(Realm, 1, 0, 1))), time ?? new Clock());

    private static ModulePlanOutcome Row() => new(ModulePlanStatus.Succeeded,
        [[T(Deletion.ToString("D")), T(Realm.ToString("D")), T(User.ToString("D")), I(100), I(1_000_100), T("policy.v1"), I(1), I(3), I(1), PlanValue.Null, PlanValue.Null, I(2), I(4), I(7), I(100)]]);

    private static PlanValue T(string value) => PlanValue.FromText(value);
    private static PlanValue I(long value) => PlanValue.FromInt64(value);

    private sealed class Authority(RealmAuthorityResult result) : IRealmAuthorityPort
    {
        public Task<RealmAuthorityResult> ResolveAsync(CancellationToken cancellationToken) => Task.FromResult(result);
    }

    private class Clock : TimeProvider
    {
        public long At { get; set; } = 500;
        public override DateTimeOffset GetUtcNow() => DateTimeOffset.UnixEpoch.AddTicks(At * 10);
    }

    private sealed class FastDeadline : Clock
    {
        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
            => TimeProvider.System.CreateTimer(callback, state, dueTime == TimeSpan.FromSeconds(2) ? TimeSpan.FromMilliseconds(1) : dueTime, period);
    }

    private sealed class Plans(params ModulePlanOutcome[] outcomes) : IModulePlanPort
    {
        public int Calls { get; private set; }
        public Action? AfterRead { get; init; }
        public Func<CancellationToken, Task<ModulePlanOutcome>>? DuringRead { get; init; }
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken)
        {
            Assert.Equal("identity.deletion-current", read.PlanId);
            Assert.Equal(Realm.ToString("D"), read.OwnerScope);
            Assert.Equal(Realm.ToString("D"), read.Arguments[0].AsText());
            Assert.Equal(User.ToString("D"), read.Arguments[1].AsText());
            var result = outcomes[Math.Min(Calls++, outcomes.Length - 1)];
            AfterRead?.Invoke();
            return DuringRead?.Invoke(cancellationToken) ?? Task.FromResult(result);
        }
        public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken) => throw new InvalidOperationException("Reader never writes.");
    }

    private sealed class NoFamily : IModuleFamilyPort
    {
        public IModuleFamilyContributionSet Contribute(string familyId, string planId, IReadOnlyList<ModuleFamilyContribution> contributions) => throw new InvalidOperationException("Reader never seals.");
        public Task<ModulePlanOutcome> ReadAsync(string familyId, ModulePlanRead read, CancellationToken cancellationToken) => throw new InvalidOperationException();
        public Task<ModulePlanOutcome> InspectAsync(string familyId, ModuleCommandIdentity identity, CancellationToken cancellationToken) => throw new InvalidOperationException();
        public Task<ModulePlanOutcome> WriteAsync(ModuleFamilyWrite write, CancellationToken cancellationToken) => throw new InvalidOperationException("Reader never commits.");
    }
}
