// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Tests.Entitlement;
using ArcForges.Cloud.Tests.Receipts;
using Xunit;

namespace ArcForges.Cloud.Tests.Families;

/// <summary>The production family binding and Worker executor run every committed migration on SQLite; the provider and HMAC network remain outside this evidence.</summary>
public sealed class FamilyPortOracleTests
{
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = Samples.Now;

        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public async Task RealFamilyBindingCommitsOnceThenReplaysRefusesReuseAndExpiryWithoutMutations()
    {
        using var executor = new SqliteBridgeExecutor();
        var clock = new Clock();
        var port = new ModuleFamilyPortFactory(executor, executor.Generation, clock).For(ModuleDescriptor.Create("Identity", "identity"));
        var write = FamilyPortFixture.Enrollment();
        var cancellation = TestContext.Current.CancellationToken;
        Assert.Equal(ModulePlanStatus.Succeeded, (await port.WriteAsync(write, cancellation)).Status);
        Assert.Equal(1, await executor.CountAsync("identity_user", cancellationToken: cancellation));
        Assert.Equal(1, await executor.CountAsync("identity_auth_identity", cancellationToken: cancellation));
        Assert.Equal(1, await executor.CountAsync("workspace_workspace", cancellationToken: cancellation));
        Assert.Equal(1, await executor.CountAsync("platform_command", cancellationToken: cancellation));
        Assert.Equal(1, await executor.CountAsync("platform_outbox", cancellationToken: cancellation));
        Assert.Equal(0, await executor.CountAsync("platform_command_guard", cancellationToken: cancellation));

        Assert.Equal(ModulePlanStatus.Replayed, (await port.WriteAsync(write, cancellation)).Status);
        Assert.Equal(ModulePlanStatus.ReusedIdentifier, (await port.WriteAsync(write with { Commit = write.Commit with { RequestHash = "different" } }, cancellation)).Status);
        clock.Now = clock.Now.AddDays(8);
        Assert.Equal(ModulePlanStatus.ReceiptExpired, (await port.WriteAsync(write, cancellation)).Status);
        Assert.Equal(1, await executor.CountAsync("platform_outbox", cancellationToken: cancellation));
        Assert.Equal(1, await executor.CountAsync("platform_change_archive", cancellationToken: cancellation));
    }

    [Fact]
    public async Task RefusedRevisionZeroGuardRollsBackEveryNewRecordAndReceipt()
    {
        using var executor = new SqliteBridgeExecutor();
        var port = new ModuleFamilyPortFactory(executor, executor.Generation, new Clock()).For(ModuleDescriptor.Create("Identity", "identity"));
        var write = FamilyPortFixture.Enrollment();
        var cancellation = TestContext.Current.CancellationToken;
        Assert.Equal(ModulePlanStatus.Succeeded, (await port.WriteAsync(write, cancellation)).Status);
        var command = Samples.Id(99);
        var conflicting = write with { Commit = write.Commit with { CommandId = command } };
        Assert.Equal(ModulePlanStatus.GuardRefused, (await port.WriteAsync(conflicting, cancellation)).Status);
        Assert.Equal(1, await executor.CountAsync("identity_user", cancellationToken: cancellation));
        Assert.Equal(1, await executor.CountAsync("platform_command", cancellationToken: cancellation));
        Assert.Equal(0, await executor.CountAsync("platform_command_guard", cancellationToken: cancellation));
    }

    [Fact]
    public async Task ConcurrentSameCommandHasOneCommittedEffectAndEveryOtherWriterReplays()
    {
        using var executor = new SqliteBridgeExecutor();
        var factory = new ModuleFamilyPortFactory(executor, executor.Generation, new Clock());
        var write = FamilyPortFixture.Enrollment();
        var cancellation = TestContext.Current.CancellationToken;
        var results = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            factory.For(ModuleDescriptor.Create("Identity", "identity")).WriteAsync(write, cancellation)));
        Assert.Equal(1, results.Count(result => result.Status == ModulePlanStatus.Succeeded));
        Assert.Equal(7, results.Count(result => result.Status == ModulePlanStatus.Replayed));
        Assert.Equal(1, await executor.CountAsync("identity_user", cancellationToken: cancellation));
        Assert.Equal(1, await executor.CountAsync("platform_outbox", cancellationToken: cancellation));
        Assert.Equal(1, await executor.CountAsync("platform_change_archive", cancellationToken: cancellation));
        Assert.Equal(0, await executor.CountAsync("platform_command_guard", cancellationToken: cancellation));
    }
}
