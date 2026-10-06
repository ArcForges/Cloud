// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Tests.Receipts;
using Xunit;

namespace ArcForges.Cloud.Tests.Families;

public sealed class ModuleFamilyPortTests
{
    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Samples.Now;
    }

    private static readonly ModuleCommandIdentity Identity = new(Samples.Id(1), null, "actor", "identity.account.enroll", "hash");

    [Theory]
    [InlineData("identity", "unknown")]
    [InlineData("commerce", "account-enrollment")]
    [InlineData("platform", "account-enrollment")]
    public async Task UnknownFamiliesAndNonParticipantsNeverReachStorage(string owner, string family)
    {
        var executor = new ScriptedExecutor();
        var port = new ModuleFamilyPortFactory(executor, 1, new Clock()).For(ModuleDescriptor.Create("Caller", owner));
        await Assert.ThrowsAsync<InvalidOperationException>(() => port.InspectAsync(family, Identity, TestContext.Current.CancellationToken));
        Assert.Empty(executor.Calls);
    }

    [Fact]
    public async Task ForeignContributionsAreRejectedBeforeAnyReceiptRead()
    {
        var executor = new ScriptedExecutor();
        var port = new ModuleFamilyPortFactory(executor, 1, new Clock()).For(ModuleDescriptor.Create("Identity", "identity"));
        var commit = new ModuleCommit(Identity.CommandId, null, Identity.ActorRef, Identity.Operation, Identity.RequestHash, "{}", 1,
            Samples.NowMicros, Samples.NowMicros + 1000, [], 1, "{}");
        await Assert.ThrowsAsync<InvalidOperationException>(() => port.WriteAsync(new ModuleFamilyWrite("account-enrollment", "families.account-enrollment.create-user", "identity:enrollment",
            [new("device", "record", "foreign", [])], commit), TestContext.Current.CancellationToken));
        Assert.Empty(executor.Calls);
    }

    [Fact]
    public async Task InspectionReturnsNotSeenAndPreservesTypedStorageFailures()
    {
        var executor = new ScriptedExecutor { Handler = _ => ScriptedExecutor.Rows() };
        var port = new ModuleFamilyPortFactory(executor, 9, new Clock()).For(ModuleDescriptor.Create("Identity", "identity"));
        Assert.Equal(ModulePlanStatus.Succeeded, (await port.InspectAsync("account-enrollment", Identity, TestContext.Current.CancellationToken)).Status);
        Assert.Equal("platform.command-load", Assert.Single(executor.Calls).Plan.Id);
        executor.Handler = _ => throw new PlanFailureException(PlanFailureKind.Unavailable);
        Assert.Equal(ModulePlanStatus.Unavailable, (await port.InspectAsync("account-enrollment", Identity, TestContext.Current.CancellationToken)).Status);
    }
}
