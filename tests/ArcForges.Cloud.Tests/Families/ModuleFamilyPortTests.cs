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

    [Theory]
    [InlineData("hash", 2, 1000, ModulePlanStatus.Replayed)]
    [InlineData("different", 2, 1000, ModulePlanStatus.ReusedIdentifier)]
    [InlineData("hash", 2, 0, ModulePlanStatus.ReceiptExpired)]
    [InlineData("hash", 3, 1000, ModulePlanStatus.ReplayedFailure)]
    [InlineData("hash", 1, 1000, ModulePlanStatus.UnknownOutcome)]
    public async Task EveryReceiptOutcomeIsTypedAndRefusalsNeverExposeStoredResults(string hash, int status, long expiresAfter, ModulePlanStatus expected)
    {
        var executor = new ScriptedExecutor
        {
            Handler = _ => ScriptedExecutor.Rows([
                D1Values.Text(hash), D1Values.Int64(status), D1Values.Text("{\"original\":true}"), D1Values.Int64(1), D1Values.Null(),
                D1Values.Int64(Samples.NowMicros + expiresAfter), D1Values.Text(Identity.ActorRef), D1Values.Text(Identity.Operation), D1Values.Null(),
            ]),
        };
        var port = new ModuleFamilyPortFactory(executor, 9, new Clock()).For(ModuleDescriptor.Create("Identity", "identity"));
        var outcome = await port.InspectAsync("account-enrollment", Identity, TestContext.Current.CancellationToken);
        Assert.Equal(expected, outcome.Status);
        if (expected is ModulePlanStatus.ReusedIdentifier or ModulePlanStatus.ReceiptExpired) Assert.Null(outcome.StoredResultJson);
        Assert.Single(executor.Calls);
    }

    [Fact]
    public async Task CancellationBeforeInspectionNeverCallsAnExecutor()
    {
        var executor = new ScriptedExecutor();
        var port = new ModuleFamilyPortFactory(executor, 9, new Clock()).For(ModuleDescriptor.Create("Identity", "identity"));
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => port.InspectAsync("account-enrollment", Identity, cancellation.Token));
        Assert.Empty(executor.Calls);
    }

    [Fact]
    public async Task OwnerCapabilitiesCombineAcrossModulesAndCannotBeForgedOrCrossFactories()
    {
        var storage = new ScriptedExecutor { Handler = call => call.Plan.Access == PlanAccess.Read ? ScriptedExecutor.Rows() : ScriptedExecutor.Changed() };
        var factory = new ModuleFamilyPortFactory(storage, 1, new Clock());
        var identity = factory.For(ModuleDescriptor.Create("Identity", "identity"));
        var workspace = factory.For(ModuleDescriptor.Create("Workspace", "workspace"));
        var write = FamilyPortFixture.Enrollment();
        var workspaceItems = write.Contributions.Where(item => item.Owner == "workspace").ToArray();
        var combined = write with
        {
            Contributions = write.Contributions.Where(item => item.Owner == "identity").ToArray(),
            Participants = [workspace.Contribute(write.FamilyId, write.PlanId, workspaceItems)],
        };
        Assert.Equal(ModulePlanStatus.Succeeded, (await identity.WriteAsync(combined, TestContext.Current.CancellationToken)).Status);
        Assert.Equal(["platform.command-load", write.PlanId], storage.PlanIds);

        storage.Calls.Clear();
        var another = new ModuleFamilyPortFactory(storage, 1, new Clock()).For(ModuleDescriptor.Create("Workspace", "workspace"));
        await Assert.ThrowsAsync<InvalidOperationException>(() => identity.WriteAsync(combined with { Participants = [another.Contribute(write.FamilyId, write.PlanId, workspaceItems)] }, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<InvalidOperationException>(() => identity.WriteAsync(combined with { Participants = [new ForgedSet()] }, TestContext.Current.CancellationToken));
        Assert.Empty(storage.Calls);
    }

    private sealed class ForgedSet : IModuleFamilyContributionSet;

    [Fact]
    public async Task UnknownFamilyOutcomeReconcilesReceiptsAndNeverRetriesTheBatch()
    {
        var storage = new ScriptedExecutor
        {
            Handler = call => call.Plan.Access == PlanAccess.Read ? ScriptedExecutor.Rows() : throw new PlanFailureException(PlanFailureKind.UnknownOutcome),
        };
        var port = new ModuleFamilyPortFactory(storage, 1, new Clock()).For(ModuleDescriptor.Create("Identity", "identity"));
        var write = FamilyPortFixture.Enrollment();
        Assert.Equal(ModulePlanStatus.UnknownOutcome, (await port.WriteAsync(write, TestContext.Current.CancellationToken)).Status);
        Assert.Equal(["platform.command-load", write.PlanId, "platform.command-load"], storage.PlanIds);
    }

    [Theory]
    [InlineData(ModulePlanStatus.Replayed)]
    [InlineData(ModulePlanStatus.ReceiptExpired)]
    [InlineData(ModulePlanStatus.ReusedIdentifier)]
    public async Task ExistingReceiptPreventsEveryMutationAndUnsafeResultDisclosure(ModulePlanStatus expected)
    {
        var write = FamilyPortFixture.Enrollment();
        var commit = write.Commit;
        var storage = new ScriptedExecutor
        {
            Handler = _ => ScriptedExecutor.Rows([
                D1Values.Text(expected == ModulePlanStatus.ReusedIdentifier ? "different" : commit.RequestHash), D1Values.Int64(2), D1Values.Text("{\"original\":true}"),
                D1Values.Int64(1), D1Values.Null(), D1Values.Int64(expected == ModulePlanStatus.ReceiptExpired ? Samples.NowMicros : commit.ExpiresAtMicros),
                D1Values.Text(commit.ActorRef), D1Values.Text(commit.Operation), commit.WorkspaceId is { } workspace ? D1Values.Text(workspace.ToString("D")) : D1Values.Null(),
            ]),
        };
        var port = new ModuleFamilyPortFactory(storage, 1, new Clock()).For(ModuleDescriptor.Create("Identity", "identity"));
        var result = await port.WriteAsync(write, TestContext.Current.CancellationToken);
        Assert.Equal(expected, result.Status);
        if (expected != ModulePlanStatus.Replayed) Assert.Null(result.StoredResultJson);
        Assert.Equal(["platform.command-load"], storage.PlanIds);
    }

    [Fact]
    public async Task MalformedMissingAndDuplicateContributionsCannotTriggerAReceiptRead()
    {
        var write = FamilyPortFixture.Enrollment();
        var storage = new ScriptedExecutor();
        var port = new ModuleFamilyPortFactory(storage, 1, new Clock()).For(ModuleDescriptor.Create("Identity", "identity"));
        var first = write.Contributions[0];
        await Assert.ThrowsAnyAsync<Exception>(() => port.WriteAsync(write with { Contributions = [] }, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<InvalidOperationException>(() => port.WriteAsync(write with { Contributions = [first, first] }, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<InvalidOperationException>(() => port.WriteAsync(write with { Contributions = [first with { Arguments = [] }] }, TestContext.Current.CancellationToken));
        await Assert.ThrowsAsync<InvalidOperationException>(() => port.WriteAsync(write with { Contributions = [first with { Class = "unregistered" }] }, TestContext.Current.CancellationToken));
        Assert.Empty(storage.Calls);
    }
}
