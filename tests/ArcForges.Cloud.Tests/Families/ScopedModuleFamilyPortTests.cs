// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Storage.SharedFamilies;
using ArcForges.Cloud.Tests.Platform;
using ArcForges.Cloud.Tests.Receipts;
using Xunit;

namespace ArcForges.Cloud.Tests.Families;

/// <summary>Real factory and migrated SQLite/Worker future-consumer tests, not a production registration or deployment.</summary>
public sealed class ScopedModuleFamilyPortTests
{
    private static readonly ModuleDescriptor Identity = ModuleDescriptor.Create("Identity", "identity");
    private static readonly ModuleDescriptor Workspace = ModuleDescriptor.Create("Workspace", "workspace");
    private static FamilyPlanDefinition Fixture() => RecoveryFamilyGuardTests.Fixture() with { RequiresScopedContributions = true };
    private static ModuleFamilyPortFactory Factory(IPlanExecutor executor) => RecoveryFamilyGuardTests.Factory(executor, fixture: Fixture());
    private static IReadOnlyList<ModuleFamilyContribution> WorkspaceRoles() => FamilyPortFixture.Enrollment().Contributions.Where(item => item.Owner == "workspace").ToArray();
    private static Task Seed(RecoveryBridgeExecutor database) => database.ExecAsync(
        "INSERT INTO platform_recovery_epoch VALUES ('" + Samples.Id(10).ToString("D") + "',0,'fixture',zeroblob(32),4,1,1)", TestContext.Current.CancellationToken);

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")]
    [InlineData("aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa")]
    [InlineData("arbitrary-scope")]
    public void NonCanonicalOrEmptyScopeCannotMintACapability(string? scope)
    {
        var executor = new ScriptedExecutor();
        var factory = Factory(executor);
        var failure = Assert.Throws<ModuleFamilyContributionException>(() => factory.For(Workspace).ContributeScoped(
            "account-enrollment", RecoveryFamilyGuardTests.PlanId, scope!, WorkspaceRoles()));
        Assert.Equal(ModuleFamilyContributionFailure.Rejected, failure.Failure);
        Assert.Empty(executor.Calls);
    }

    [Theory]
    [InlineData("wrong-scope")]
    [InlineData("legacy")]
    [InlineData("issuer")]
    [InlineData("forged")]
    [InlineData("duplicate")]
    public async Task InvalidScopedCapabilityNeverReadsAReceiptOrMutates(string variant)
    {
        using var database = new RecoveryBridgeExecutor(0);
        await Seed(database);
        var factory = Factory(database);
        var write = RecoveryFamilyGuardTests.Write();
        var authority = await RecoveryFamilyGuardTests.Authority(database, factory).PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        var issuing = variant == "issuer" ? Factory(database) : factory;
        var capability = variant == "legacy"
            ? issuing.For(Workspace).Contribute(write.FamilyId, write.PlanId, WorkspaceRoles())
            : issuing.For(Workspace).ContributeScoped(write.FamilyId, write.PlanId,
                variant == "wrong-scope" ? Samples.Id(99).ToString("D") : write.OwnerScope, WorkspaceRoles());
        var participants = variant switch
        {
            "forged" => new IModuleFamilyContributionSet[] { new Forged(), authority.Contribution! },
            "duplicate" => [capability, capability, authority.Contribution!],
            _ => [capability, authority.Contribution!],
        };
        var calls = database.Calls;
        if (variant == "duplicate")
            Assert.Equal(FamilyViolation.DuplicateContribution, (await Assert.ThrowsAsync<FamilyViolationException>(() => factory.For(Identity).WriteAsync(write with { Participants = participants }, TestContext.Current.CancellationToken))).Violation);
        else
            await Assert.ThrowsAsync<InvalidOperationException>(() => factory.For(Identity).WriteAsync(write with { Participants = participants }, TestContext.Current.CancellationToken));
        Assert.Equal(calls, database.Calls);
        await EmptyEffects(database);
    }

    [Fact]
    public async Task CorrectScopedCapabilityCommitsOnceAndConcurrentRetriesReplay()
    {
        using var database = new RecoveryBridgeExecutor(0);
        await Seed(database);
        var factory = Factory(database);
        var write = RecoveryFamilyGuardTests.Write();
        var authority = await RecoveryFamilyGuardTests.Authority(database, factory).PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        var roles = WorkspaceRoles().ToArray();
        var arguments = roles[0].Arguments.ToArray();
        roles[0] = roles[0] with { Arguments = arguments };
        var capability = factory.For(Workspace).ContributeScoped(write.FamilyId, write.PlanId, write.OwnerScope, roles);
        // Neither a caller's mutable collection nor scalar array can change the sealed capability.
        arguments[0] = PlanValue.FromText("changed-after-sealing");
        Array.Clear(roles);
        var complete = write with { Participants = [capability, authority.Contribution!] };
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => factory.For(Identity).WriteAsync(complete, TestContext.Current.CancellationToken)));
        Assert.Equal(1, outcomes.Count(item => item.Status == ModulePlanStatus.Succeeded));
        Assert.Equal(7, outcomes.Count(item => item.Status == ModulePlanStatus.Replayed));
        foreach (var table in EffectTables) Assert.Equal(1, await database.CountAsync(table, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(0, await database.CountAsync("platform_command_guard", cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task RecoveryRaceRollsBackThenFreshAuthorityAndTheSameScopedCapabilityCommit()
    {
        using var database = new RecoveryBridgeExecutor(0);
        await Seed(database);
        var factory = Factory(database);
        var write = RecoveryFamilyGuardTests.Write();
        var capability = factory.For(Workspace).ContributeScoped(write.FamilyId, write.PlanId, write.OwnerScope, WorkspaceRoles());
        var source = RecoveryFamilyGuardTests.Authority(database, factory);
        var before = await source.PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        await database.ExecAsync("UPDATE platform_recovery_epoch SET rev=2", TestContext.Current.CancellationToken);
        Assert.Equal(ModulePlanStatus.GuardRefused, (await factory.For(Identity).WriteAsync(write with { Participants = [capability, before.Contribution!] }, TestContext.Current.CancellationToken)).Status);
        await EmptyEffects(database);
        var after = await source.PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        Assert.Equal(ModulePlanStatus.Succeeded, (await factory.For(Identity).WriteAsync(write with { Participants = [capability, after.Contribution!] }, TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public async Task LateArchiveFailureRollsBackAllBusinessAndReceiptEffects()
    {
        using var database = new RecoveryBridgeExecutor(0);
        await Seed(database);
        var factory = Factory(database);
        var write = RecoveryFamilyGuardTests.Write();
        var authority = await RecoveryFamilyGuardTests.Authority(database, factory).PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        var capability = factory.For(Workspace).ContributeScoped(write.FamilyId, write.PlanId, write.OwnerScope, WorkspaceRoles());
        await database.ExecAsync("CREATE TRIGGER fixture_scoped_archive BEFORE INSERT ON platform_change_archive BEGIN SELECT RAISE(ABORT,'scoped-tail'); END;", TestContext.Current.CancellationToken);
        var result = await factory.For(Identity).WriteAsync(write with { Participants = [capability, authority.Contribution!] }, TestContext.Current.CancellationToken);
        Assert.Equal(ModulePlanStatus.UnknownOutcome, result.Status);
        await EmptyEffects(database);
    }

    [Fact]
    public async Task ScopedCapabilityCannotMoveToAnotherOtherwiseRegisteredPlan()
    {
        var executor = new ScriptedExecutor();
        var original = Fixture();
        var other = original with { Plan = original.Plan with { Id = "families.account-enrollment.another-scoped-fixture" } };
        var factory = new ModuleFamilyPortFactory(executor, 0, TimeProvider.System, PlanManifest.FamilyCatalog, [original, other]);
        var write = RecoveryFamilyGuardTests.Write();
        var capability = factory.For(Workspace).ContributeScoped(write.FamilyId, write.PlanId, write.OwnerScope, WorkspaceRoles());
        await Assert.ThrowsAsync<InvalidOperationException>(() => factory.For(Identity).WriteAsync(write with { PlanId = other.Plan.Id, Participants = [capability] }, TestContext.Current.CancellationToken));
        Assert.Empty(executor.Calls);
    }

    [Fact]
    public async Task CancellationBeforeDispatchLeavesNoEffectsAndLegacyCreateUserStillCommits()
    {
        using var database = new RecoveryBridgeExecutor(0);
        var factory = new ModuleFamilyPortFactory(database, 0, TimeProvider.System);
        var enrollment = FamilyPortFixture.Enrollment();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => factory.For(Identity).WriteAsync(enrollment, cancellation.Token));
        Assert.Equal(0, database.Calls);
        await EmptyEffects(database);
        Assert.Equal(ModulePlanStatus.Succeeded, (await factory.For(Identity).WriteAsync(enrollment, TestContext.Current.CancellationToken)).Status);
        Assert.Equal(ModulePlanStatus.Replayed, (await factory.For(Identity).WriteAsync(enrollment, TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public void AcceptedCreateUserCannotBeRetrofittedToRequireScopedContributions()
    {
        var accepted = PlanManifest.FamilyPlans.Single(item => item.Plan.Id == "families.account-enrollment.create-user");
        Assert.False(accepted.RequiresScopedContributions);
        var forbidden = accepted with { RequiresScopedContributions = true };
        Assert.NotEmpty(FamilyPlanVerifier.Problems(forbidden, PlanManifest.FamilyCatalog.Single()));
        Assert.Throws<InvalidOperationException>(() => RecoveryFamilyGuardTests.Factory(new ScriptedExecutor(), fixture: forbidden));
    }

    private static readonly string[] EffectTables = ["identity_user", "identity_auth_identity", "workspace_workspace", "platform_command", "platform_outbox", "platform_change_archive"];
    private static async Task EmptyEffects(RecoveryBridgeExecutor database)
    {
        foreach (var table in EffectTables.Concat(["platform_command_guard", "platform_sequence_stream"]))
            Assert.Equal(0, await database.CountAsync(table, cancellationToken: TestContext.Current.CancellationToken));
    }
    private sealed class Forged : IModuleFamilyContributionSet;
}
