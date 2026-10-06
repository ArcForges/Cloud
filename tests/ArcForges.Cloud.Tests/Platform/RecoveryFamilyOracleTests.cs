// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Tests.Receipts;
using Xunit;

namespace ArcForges.Cloud.Tests.Platform;

/// <summary>The actual issuer, family composer, named predicate generator and Worker batch run over all SQLite migrations, not provider deployment.</summary>
public sealed class RecoveryFamilyOracleTests
{
    private static Task Seed(RecoveryBridgeExecutor database) => database.ExecAsync(
        "INSERT INTO platform_recovery_epoch VALUES ('" + Samples.Id(10).ToString("D") + "',0,'fixture',zeroblob(32),4,1,1)", TestContext.Current.CancellationToken);

    [Theory]
    [InlineData("state=1,rev=2")]
    [InlineData("state=2,rev=2")]
    [InlineData("state=3,rev=2")]
    [InlineData("recovery_generation=1,rev=2")]
    [InlineData("rev=2")]
    [InlineData("realm_id='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'")]
    public async Task ActualRecoveryTransitionAfterReadRollsBackEveryEffect(string transition)
    {
        using var database = new RecoveryBridgeExecutor(0);
        await Seed(database);
        var factory = RecoveryFamilyGuardTests.Factory(database);
        var write = RecoveryFamilyGuardTests.Write();
        var prepared = await RecoveryFamilyGuardTests.Authority(database, factory).PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        var guard = Assert.IsAssignableFrom<IModuleFamilyContributionSet>(prepared.Contribution);
        await database.ExecAsync("UPDATE platform_recovery_epoch SET " + transition, TestContext.Current.CancellationToken);
        var result = await factory.For(ModuleDescriptor.Create("Identity", "identity")).WriteAsync(
            write with { Participants = [RecoveryFamilyGuardTests.Workspace(factory), guard] }, TestContext.Current.CancellationToken);
        Assert.Equal(ModulePlanStatus.GuardRefused, result.Status);
        await EmptyEffects(database);
    }

    [Fact]
    public async Task FreshRereadAfterRevisionRefusalCommitsOnceAndThenReplays()
    {
        using var database = new RecoveryBridgeExecutor(0);
        await Seed(database);
        var factory = RecoveryFamilyGuardTests.Factory(database);
        var authority = RecoveryFamilyGuardTests.Authority(database, factory);
        var write = RecoveryFamilyGuardTests.Write();
        var port = factory.For(ModuleDescriptor.Create("Identity", "identity"));
        var first = await authority.PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        await database.ExecAsync("UPDATE platform_recovery_epoch SET rev=2", TestContext.Current.CancellationToken);
        Assert.Equal(ModulePlanStatus.GuardRefused, (await port.WriteAsync(write with
        {
            Participants = [RecoveryFamilyGuardTests.Workspace(factory), Assert.IsAssignableFrom<IModuleFamilyContributionSet>(first.Contribution)],
        }, TestContext.Current.CancellationToken)).Status);
        await EmptyEffects(database);
        var second = await authority.PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        Assert.Equal(2, second.Snapshot?.RecoveryRevision);
        var complete = write with { Participants = [RecoveryFamilyGuardTests.Workspace(factory), Assert.IsAssignableFrom<IModuleFamilyContributionSet>(second.Contribution)] };
        Assert.Equal(ModulePlanStatus.Succeeded, (await port.WriteAsync(complete, TestContext.Current.CancellationToken)).Status);
        Assert.Equal(ModulePlanStatus.Replayed, (await port.WriteAsync(complete, TestContext.Current.CancellationToken)).Status);
        foreach (var table in new[] { "identity_user", "identity_auth_identity", "workspace_workspace", "platform_command", "platform_outbox", "platform_change_archive" })
            Assert.Equal(1, await database.CountAsync(table, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(0, await database.CountAsync("platform_command_guard", cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ActualConcurrentSameCommandHasOneEffectAndRemainingCallsReplay()
    {
        using var database = new RecoveryBridgeExecutor(0);
        await Seed(database);
        var factory = RecoveryFamilyGuardTests.Factory(database);
        var write = RecoveryFamilyGuardTests.Write();
        var prepared = await RecoveryFamilyGuardTests.Authority(database, factory).PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        var complete = write with { Participants = [RecoveryFamilyGuardTests.Workspace(factory), Assert.IsAssignableFrom<IModuleFamilyContributionSet>(prepared.Contribution)] };
        var outcomes = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => factory.For(ModuleDescriptor.Create("Identity", "identity")).WriteAsync(complete, TestContext.Current.CancellationToken)));
        Assert.Equal(1, outcomes.Count(item => item.Status == ModulePlanStatus.Succeeded));
        Assert.Equal(7, outcomes.Count(item => item.Status == ModulePlanStatus.Replayed));
        Assert.Equal(1, await database.CountAsync("identity_user", cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal(1, await database.CountAsync("platform_command", cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task LateTailUnknownFailureRollsBackOwnerRecordsAndRecoveryGuardWithoutUnsafeRetry()
    {
        using var database = new RecoveryBridgeExecutor(0);
        await Seed(database);
        var factory = RecoveryFamilyGuardTests.Factory(database);
        var write = RecoveryFamilyGuardTests.Write();
        var prepared = await RecoveryFamilyGuardTests.Authority(database, factory).PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        await database.ExecAsync("CREATE TRIGGER fixture_fail_archive BEFORE INSERT ON platform_change_archive BEGIN SELECT RAISE(ABORT,'fixture-tail'); END;", TestContext.Current.CancellationToken);
        var result = await factory.For(ModuleDescriptor.Create("Identity", "identity")).WriteAsync(write with
        {
            Participants = [RecoveryFamilyGuardTests.Workspace(factory), Assert.IsAssignableFrom<IModuleFamilyContributionSet>(prepared.Contribution)],
        }, TestContext.Current.CancellationToken);
        Assert.Equal(ModulePlanStatus.UnknownOutcome, result.Status);
        await EmptyEffects(database);
        Assert.Equal(4, database.Calls); // real recovery read, receipt preflight, one batch and reconciliation; no mutation retry.
    }

    private static async Task EmptyEffects(RecoveryBridgeExecutor database)
    {
        foreach (var table in new[] { "identity_user", "identity_auth_identity", "workspace_workspace", "platform_command", "platform_outbox", "platform_change_archive", "platform_command_guard", "platform_sequence_stream" })
            Assert.Equal(0, await database.CountAsync(table, cancellationToken: TestContext.Current.CancellationToken));
    }
}
