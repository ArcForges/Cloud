// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Identity;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Recovery.Application;
using ArcForges.Cloud.Modules.Identity.Recovery.Domain;
using ArcForges.Cloud.Modules.Identity.Recovery.Infrastructure;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Receipts;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests.Deletion;

public sealed class DeletionStoreTests
{
    private static readonly Guid Realm = Samples.Id(10), User = Samples.Id(11), Deletion = Samples.Id(12);
    private static CancellationToken Cancellation => TestContext.Current.CancellationToken;

    [Fact]
    public async Task ActualNamedPlansCaptureOwnedCurrentRevisionsAndTerminalHistory()
    {
        var executor = new ScriptedExecutor
        {
            Handler = call => call.Plan.Id switch
            {
                "identity.deletion-user" => ScriptedExecutor.Rows([T(Realm), T(User), I(3), D1Values.Null(), I(9)]),
                "identity.deletion-state" => ScriptedExecutor.Rows(LifecycleRow()),
                _ => throw new InvalidOperationException("Unexpected plan."),
            },
        };
        var store = Store(executor);
        Assert.Equal(new DeletionUserAuthority(UserState.Suspended, 9, null), (await store.UserAsync(Realm, User, Cancellation)).Value);
        var stored = Assert.IsType<StoredDeletionAuthority>((await store.LifecycleAsync(Realm, User, Deletion, Cancellation)).Value);
        Assert.Equal(DeletionState.Cancelled, stored.Lifecycle.State);
        Assert.Equal(500, stored.Lifecycle.CancelledAtMicros);
        Assert.Equal(UserState.Suspended, stored.UserState);
        Assert.Equal(9, stored.UserRevision);
        Assert.All(executor.Calls, call =>
        {
            Assert.Equal(Realm.ToString("D"), call.OwnerScope);
            Assert.Equal(Realm.ToString("D"), ScriptedExecutor.Text(call.Arguments[0][0]));
            Assert.Equal(0UL, call.RecoveryGeneration);
            Assert.Equal(PlanAccess.Read, call.Plan.Access);
        });
    }

    [Fact]
    public async Task MissingMalformedOrForeignStoredRowsNeverBecomeAuthority()
    {
        var executor = new ScriptedExecutor { Handler = _ => ScriptedExecutor.Rows() };
        var store = Store(executor);
        Assert.Equal(IdentityDeletionFailure.StaleAuthority, (await store.UserAsync(Realm, User, Cancellation)).Failure);
        Assert.Equal(IdentityDeletionFailure.NotPending, (await store.LifecycleAsync(Realm, User, Deletion, Cancellation)).Failure);
        foreach (var row in new D1Scalar[][]
        {
            [T(Realm), T(User), I(4_294_967_297), D1Values.Null(), I(9)],
            [T(Guid.NewGuid()), T(User), I(1), D1Values.Null(), I(9)],
            [T(Realm), T(User), I(1), D1Values.Null(), I(0)],
            [T(Realm), T(User), I(1), D1Values.Text("wrong"), I(9)],
            [T(Realm)],
        })
        {
            executor.Handler = _ => ScriptedExecutor.Rows(row);
            Assert.Equal(IdentityDeletionFailure.Defect, (await store.UserAsync(Realm, User, Cancellation)).Failure);
        }
        foreach (var (index, value) in new (int, D1Scalar)[]
        {
            (0, T(Guid.NewGuid())), (1, T(Guid.NewGuid())), (2, T(Guid.NewGuid())), (4, I(1_000_101)),
            (7, I(4_294_967_297)), (8, I(4_294_967_298)), (9, I(1_000_100)), (11, I(0)), (12, I(6)), (13, I(0)),
        })
        {
            var row = LifecycleRow(); row[index] = value;
            executor.Handler = _ => ScriptedExecutor.Rows(row);
            Assert.Equal(IdentityDeletionFailure.Defect, (await store.LifecycleAsync(Realm, User, Deletion, Cancellation)).Failure);
        }
        executor.Handler = _ => ScriptedExecutor.Rows(LifecycleRow(), LifecycleRow());
        Assert.Equal(IdentityDeletionFailure.Defect, (await store.LifecycleAsync(Realm, User, Deletion, Cancellation)).Failure);
    }

    [Theory]
    [InlineData(2, IdentityDeletionFailure.StaleAuthority)]
    [InlineData(1, IdentityDeletionFailure.StaleAuthority)]
    [InlineData(7, IdentityDeletionFailure.Defect)]
    [InlineData(0, IdentityDeletionFailure.Defect)]
    public async Task RealAdapterFailuresRemainClosedAndDoNotRetryPermanentFailures(int failureValue, IdentityDeletionFailure expected)
    {
        var failure = (PlanFailureKind)failureValue;
        var executor = new ScriptedExecutor { Handler = _ => throw new PlanFailureException(failure) };
        var store = Store(executor);
        Assert.Equal(expected, (await store.UserAsync(Realm, User, Cancellation)).Failure);
        Assert.Equal(expected, (await store.LifecycleAsync(Realm, User, Deletion, Cancellation)).Failure);
        Assert.Equal(2, executor.Calls.Count);
    }

    [Fact]
    public async Task LostReadResponsesRetryBoundedlyWhileCallerCancellationStopsImmediately()
    {
        var attempts = 0;
        var executor = new ScriptedExecutor
        {
            Handler = _ => ++attempts < 3 ? throw new PlanFailureException(PlanFailureKind.UnknownOutcome) : ScriptedExecutor.Rows(LifecycleRow()),
        };
        Assert.NotNull((await Store(executor).LifecycleAsync(Realm, User, Deletion, Cancellation)).Value);
        Assert.Equal(3, attempts);
        using var cancelled = new CancellationTokenSource();
        executor.Handler = _ => { cancelled.Cancel(); throw new PlanFailureException(PlanFailureKind.Unavailable); };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Store(executor).UserAsync(Realm, User, cancelled.Token));
        Assert.Equal(4, executor.Calls.Count);
    }

    private static DeletionLifecyclePort Store(ScriptedExecutor executor)
    {
        var descriptor = IdentityModule.Instance.Descriptor;
        return new(new ModulePlanPortFactory(executor, 0, TimeProvider.System).For(descriptor),
            new ModuleFamilyPortFactory(executor, 0, TimeProvider.System).For(descriptor), new NoAuthority(), TimeProvider.System);
    }
    private sealed class NoAuthority : IRealmAuthorityPort
    { public Task<RealmAuthorityResult> ResolveAsync(CancellationToken cancellationToken) => throw new InvalidOperationException("Internal store facts are not a standalone authorization decision."); }
    private static D1Scalar[] LifecycleRow() => [T(Deletion), T(Realm), T(User), I(100), I(1_000_100), D1Values.Text("original.v1"), I(1), I(3), I(2), I(500), D1Values.Null(), I(3), I(3), I(9)];
    private static D1Scalar T(Guid value) => D1Values.Text(value.ToString("D"));
    private static D1Scalar I(long value) => D1Values.Int64(value);
}
