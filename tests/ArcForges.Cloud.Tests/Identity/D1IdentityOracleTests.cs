// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Identity;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Persistence;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Entitlement;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

/// <summary>Actual store, family coordinator, owner ports, Worker executor and all migrations. SQLite replaces D1; no provider or network acceptance is claimed.</summary>
public sealed class D1IdentityOracleTests
{
    private sealed class Fixture : IDisposable
    {
        public readonly SqliteBridgeExecutor Executor = new();
        public readonly IdentityClock Clock = new(new DateTimeOffset(2026, 10, 6, 17, 0, 0, TimeSpan.Zero));
        public readonly SequentialIdentityIds Ids = new();
        public readonly D1IdentityStore Store;
        public readonly IdentityService Service;
        public Fixture()
        {
            var descriptor = IdentityModule.Instance.Descriptor;
            Store = new D1IdentityStore(new ModulePlanPortFactory(Executor, Executor.Generation, Clock).For(descriptor),
                new ModuleFamilyPortFactory(Executor, Executor.Generation, Clock).For(descriptor), Ids, Clock);
            Service = new IdentityService(Store, Ids, Clock);
        }
        public void Dispose() => Executor.Dispose();
    }

    private sealed class UncertainExecutor(SqliteBridgeExecutor storage, bool commitBeforeFailure) : IPlanExecutor
    {
        private int writes;
        public async Task<PlanResult> ExecuteAsync(PlanCall call, CancellationToken cancellationToken)
        {
            if (call.Plan.Access == PlanAccess.Write && Interlocked.Increment(ref writes) == 1)
            {
                if (commitBeforeFailure) _ = await storage.ExecuteAsync(call, cancellationToken);
                throw new PlanFailureException(PlanFailureKind.UnknownOutcome);
            }
            return await storage.ExecuteAsync(call, cancellationToken);
        }
    }

    private sealed class CollisionIds(string collision, SequentialIdentityIds remainder) : IIdentityIdSource
    {
        private int count;
        public string NewId() => Interlocked.Increment(ref count) == 1 ? collision : remainder.NewId();
    }

    [Fact]
    public async Task AForcedIdentifierCollisionRollsBackAndRetriesWithFreshIdentifiers()
    {
        using var fixture = new Fixture();
        var ct = TestContext.Current.CancellationToken;
        var first = (await fixture.Service.CompleteEnrollmentAsync(new EnrollmentRequest(IdentityHarness.RealmA, fixture.Ids.NewId(), "Ada", IdentityHarness.Email("first@example.test")), ct)).Value!;
        var request = new EnrollmentRequest(IdentityHarness.RealmA, fixture.Ids.NewId(), "Grace", IdentityHarness.Email("second@example.test"));
        var service = new IdentityService(fixture.Store, new CollisionIds(first.User.Id.Value, fixture.Ids), fixture.Clock);
        var second = (await service.CompleteEnrollmentAsync(request, ct)).Value!;
        Assert.NotEqual(first.User.Id, second.User.Id);
        Assert.Equal(2, await fixture.Executor.CountAsync("identity_user", cancellationToken: ct));
        Assert.Equal(2, await fixture.Executor.CountAsync("platform_command", cancellationToken: ct));
        Assert.Equal(2, await fixture.Executor.CountAsync("platform_outbox", cancellationToken: ct));
        Assert.Equal(0, await fixture.Executor.CountAsync("platform_command_guard", cancellationToken: ct));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task UncertainEnrollmentReconcilesTheSameCommandAndNeverDuplicatesEffects(bool commitBeforeFailure)
    {
        using var storage = new SqliteBridgeExecutor();
        var executor = new UncertainExecutor(storage, commitBeforeFailure);
        var ids = new SequentialIdentityIds();
        var clock = TimeProvider.System;
        var descriptor = IdentityModule.Instance.Descriptor;
        var store = new D1IdentityStore(new ModulePlanPortFactory(executor, storage.Generation, clock).For(descriptor),
            new ModuleFamilyPortFactory(executor, storage.Generation, clock).For(descriptor), ids, clock);
        var service = new IdentityService(store, ids, clock);
        var ct = TestContext.Current.CancellationToken;
        var request = new EnrollmentRequest(IdentityHarness.RealmA, ids.NewId(), "Ada", IdentityHarness.Email("lost-response@example.test"));
        Assert.True((await service.CompleteEnrollmentAsync(request, ct)).IsSuccess);
        Assert.Equal(1, await storage.CountAsync("identity_user", cancellationToken: ct));
        Assert.Equal(1, await storage.CountAsync("platform_command", cancellationToken: ct));
        Assert.Equal(1, await storage.CountAsync("platform_outbox", cancellationToken: ct));
        var receipt = Assert.Single(await storage.QueryAsync("SELECT command_id FROM platform_command", ct));
        Assert.Equal(request.CommandId, receipt[0]);
    }

    [Fact]
    public async Task EnrollmentReplayReuseExpiryAndAuthorizationUsePersistedOriginalResults()
    {
        using var fixture = new Fixture();
        var ct = TestContext.Current.CancellationToken;
        var request = new EnrollmentRequest(IdentityHarness.RealmA, fixture.Ids.NewId(), "Ada", IdentityHarness.Passkey("verified-key"));
        var created = (await fixture.Service.CompleteEnrollmentAsync(request, ct)).Value!;
        Assert.True(created.CreatedUser);
        var replay = (await fixture.Service.CompleteEnrollmentAsync(request, ct)).Value!;
        Assert.False(replay.CreatedUser);
        Assert.Equal(created.User, replay.User);
        Assert.Equal(created.Credential.Passkey!.PublicKey, replay.Credential.Passkey!.PublicKey);
        Assert.Equal(created.Workspace, replay.Workspace);
        Assert.Equal(IdentityError.Conflict, (await fixture.Service.CompleteEnrollmentAsync(request with { DisplayName = "Grace" }, ct)).Error);
        Assert.Equal(IdentityError.NotFound, (await fixture.Service.AuthorizeWorkspaceAsync(new Principal(IdentityHarness.RealmB, created.User.Id), created.Workspace.Id, ct)).Error);
        fixture.Clock.Advance(TimeSpan.FromDays(8));
        Assert.Equal(IdentityError.Conflict, (await fixture.Service.CompleteEnrollmentAsync(request, ct)).Error);
        Assert.Equal(1, await fixture.Executor.CountAsync("identity_user", cancellationToken: ct));
        Assert.Equal(1, await fixture.Executor.CountAsync("platform_outbox", cancellationToken: ct));
    }

    [Fact]
    public async Task EveryMutationAndLastCredentialGuardRunThroughTheRealStore()
    {
        using var fixture = new Fixture();
        var ct = TestContext.Current.CancellationToken;
        var account = (await fixture.Service.CompleteEnrollmentAsync(new EnrollmentRequest(IdentityHarness.RealmA, fixture.Ids.NewId(), "Ada", IdentityHarness.Email("ada@example.test")), ct)).Value!;
        var principal = IdentityHarness.Caller(account);
        var added = (await fixture.Service.AddCredentialAsync(principal, fixture.Ids.NewId(), IdentityHarness.Password("password-subject"), ct)).Value!;
        Assert.Equal("verifier-example", (await fixture.Store.FindCredentialAsync(principal.Realm, "self-host-password", "password-subject", ct))!.Credential.Password);
        Assert.True((await fixture.Service.RelabelCredentialAsync(principal, fixture.Ids.NewId(), added.Id, "Laptop", ct)).IsSuccess);
        Assert.Equal("Laptop", (await fixture.Store.ListCredentialsAsync(principal.Realm, principal.User, ct)).Single(c => c.Id == added.Id).Label);
        Assert.Equal("Grace", (await fixture.Service.RenameUserAsync(principal, fixture.Ids.NewId(), "Grace", ct)).Value!.DisplayName);
        Assert.True((await fixture.Service.RevokeCredentialAsync(principal, fixture.Ids.NewId(), account.Credential.Id, ct)).IsSuccess);
        Assert.Equal(IdentityError.LastCredential, (await fixture.Service.RevokeCredentialAsync(principal, fixture.Ids.NewId(), added.Id, ct)).Error);
        Assert.Equal(IdentityError.CredentialUnavailable, (await fixture.Service.ResolveCredentialAsync(principal.Realm, "official-email", "ada@example.test", ct)).Error);
        Assert.Equal(5, await fixture.Executor.CountAsync("platform_command", cancellationToken: ct));
        await fixture.Executor.ExecAsync($"INSERT INTO identity_recovery_code(code_hash,set_id,user_id,issued_at) VALUES(zeroblob(32),'{fixture.Ids.NewId()}','{principal.User.Value}',1)", ct);
        Assert.True(await fixture.Store.HasActiveRecoveryPathAsync(principal.Realm, principal.User, ct));
        Assert.False(await fixture.Store.HasActiveRecoveryPathAsync(IdentityHarness.RealmB, principal.User, ct));
        Assert.True((await fixture.Service.RevokeCredentialAsync(principal, fixture.Ids.NewId(), added.Id, ct)).IsSuccess);
        Assert.Equal(0, await fixture.Executor.CountAsync("platform_command_guard", cancellationToken: ct));
    }

    [Fact]
    public async Task ConcurrentEnrollmentWithOneCommandHasOnePersistedAccount()
    {
        using var fixture = new Fixture();
        var ct = TestContext.Current.CancellationToken;
        var request = new EnrollmentRequest(IdentityHarness.RealmA, fixture.Ids.NewId(), "Ada", IdentityHarness.Email("same@example.test"));
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => fixture.Service.CompleteEnrollmentAsync(request, ct).AsTask()));
        Assert.All(results, result => Assert.True(result.IsSuccess));
        Assert.Single(results.Select(result => result.Value!.User.Id).Distinct());
        Assert.Equal(1, results.Count(result => result.Value!.CreatedUser));
        Assert.Equal(1, await fixture.Executor.CountAsync("workspace_workspace", cancellationToken: ct));
        Assert.Equal(1, await fixture.Executor.CountAsync("platform_change_archive", cancellationToken: ct));
    }

    [Fact]
    public async Task ModuleCompositionResolvesTheStoreAndPerformsAnActualEnrollment()
    {
        using var executor = new SqliteBridgeExecutor();
        var clock = new IdentityClock(DateTimeOffset.UtcNow);
        var services = new ServiceCollection();
        services.AddSingleton<TimeProvider>(clock);
        services.AddSingleton<IModulePlanPortFactory>(new ModulePlanPortFactory(executor, executor.Generation, clock));
        services.AddSingleton<IModuleFamilyPortFactory>(new ModuleFamilyPortFactory(executor, executor.Generation, clock));
        ((IModuleBoundary)IdentityModule.Instance).Register(services);
        using var provider = services.BuildServiceProvider();
        var request = new EnrollmentRequest(IdentityHarness.RealmA, Guid.NewGuid().ToString("D"), "Ada", IdentityHarness.Email("composition@example.test"));
        Assert.True((await provider.GetRequiredService<IdentityService>().CompleteEnrollmentAsync(request, TestContext.Current.CancellationToken)).IsSuccess);
        Assert.IsType<D1IdentityStore>(provider.GetRequiredService<IIdentityStore>());
    }
}
