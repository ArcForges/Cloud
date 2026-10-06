// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Identity.Core.Application;
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Persistence;
using Xunit;

namespace ArcForges.Cloud.Tests.IdentityCore;

public sealed class D1IdentityStoreTests
{
    private sealed class Ports : IModulePlanPort, IModuleFamilyPort
    {
        public readonly List<ModulePlanRead> Reads = [];
        public Func<ModulePlanRead, ModulePlanOutcome> Read = _ => ModulePlanOutcome.Of(ModulePlanStatus.Succeeded);
        public ModulePlanStatus WriteStatus = ModulePlanStatus.Succeeded;
        public int Writes;
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Reads.Add(read); return Task.FromResult(Read(read));
        }
        public Task<ModulePlanOutcome> ReadAsync(string familyId, ModulePlanRead read, CancellationToken cancellationToken) => ReadAsync(read, cancellationToken);
        public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); Writes++; return Task.FromResult(ModulePlanOutcome.Of(WriteStatus)); }
        public Task<ModulePlanOutcome> WriteAsync(ModuleFamilyWrite write, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); Writes++; return Task.FromResult(ModulePlanOutcome.Of(WriteStatus)); }
        public Task<ModulePlanOutcome> InspectAsync(string familyId, ModuleCommandIdentity identity, CancellationToken cancellationToken) => Task.FromResult(ModulePlanOutcome.Of(WriteStatus));
        public IModuleFamilyContributionSet Contribute(string familyId, string planId, IReadOnlyList<ModuleFamilyContribution> contributions) => throw new NotSupportedException();
    }
    private static readonly RealmId Realm = IdentityHarness.RealmA;
    private static readonly UserId User = UserId.Parse("00000000-0000-4000-8000-000000000001");
    private static D1IdentityStore Store(Ports ports) => new(ports, ports, new SequentialIdentityIds(), TimeProvider.System);
    private static IReadOnlyList<PlanValue> Row(int index, long created = 1) =>
    [
        PlanValue.FromText($"00000000-0000-4000-8000-{index:x12}"), PlanValue.FromInt64(2), PlanValue.FromText("official-email"), PlanValue.Null,
        PlanValue.FromInt64(created), PlanValue.Null, PlanValue.Null, PlanValue.FromInt64(1), PlanValue.FromText(User.Value), PlanValue.FromText(Realm.Value),
        PlanValue.FromText($"subject-{index}"), PlanValue.Null, PlanValue.Null, PlanValue.Null, PlanValue.Null, PlanValue.Null, PlanValue.Null, PlanValue.Null,
    ];

    [Fact]
    public async Task KeysetPagingReturnsEveryCredentialAndPassesExactCursor()
    {
        var ports = new Ports();
        ports.Read = read => new ModulePlanOutcome(ModulePlanStatus.Succeeded,
            read.Arguments[3].AsText() == "" ? [.. Enumerable.Range(1, 64).Select(index => Row(index))] : [Row(65, 2)]);
        var result = await Store(ports).ListCredentialsAsync(Realm, User, TestContext.Current.CancellationToken);
        Assert.Equal(65, result.Count);
        Assert.Equal(2, ports.Reads.Count);
        Assert.Equal(long.MinValue, ports.Reads[0].Arguments[2].AsInt64());
        Assert.Equal(result[63].Id.Value, ports.Reads[1].Arguments[3].AsText());
        Assert.Equal(1, ports.Reads[1].Arguments[2].AsInt64());
        Assert.All(ports.Reads, read => Assert.Equal(Realm.Value, read.OwnerScope));
    }

    [Theory]
    [InlineData("foreignRealm")]
    [InlineData("wrongKind")]
    [InlineData("invalidMethod")]
    [InlineData("duplicate")]
    [InlineData("oversize")]
    public async Task InvalidRowsCannotBecomeAUserOrCredential(string malformed)
    {
        var values = Row(1).ToArray();
        if (malformed == "foreignRealm") values[9] = PlanValue.FromText(IdentityHarness.RealmB.Value);
        if (malformed == "wrongKind") values[4] = PlanValue.FromText("1");
        if (malformed == "invalidMethod") values[1] = PlanValue.FromInt64(99);
        var rows = malformed == "duplicate" ? new IReadOnlyList<PlanValue>[] { values, values }
            : malformed == "oversize" ? Enumerable.Repeat<IReadOnlyList<PlanValue>>(values, 65).ToArray() : [values];
        var ports = new Ports { Read = _ => new ModulePlanOutcome(ModulePlanStatus.Succeeded, rows) };
        var failure = await Assert.ThrowsAsync<IdentityStorageException>(() => Store(ports).ListCredentialsAsync(Realm, User, TestContext.Current.CancellationToken).AsTask());
        Assert.Equal(IdentityStorageFailure.InvalidPlan, failure.Failure);
    }

    [Theory]
    [InlineData(ModulePlanStatus.Unavailable, (int)IdentityStorageFailure.Unavailable, 3)]
    [InlineData(ModulePlanStatus.UnknownOutcome, (int)IdentityStorageFailure.OutcomeUnknown, 3)]
    [InlineData(ModulePlanStatus.StaleGeneration, (int)IdentityStorageFailure.StaleGeneration, 1)]
    [InlineData(ModulePlanStatus.Rejected, (int)IdentityStorageFailure.InvalidPlan, 1)]
    public async Task ReadRetryIsBoundedAndTyped(ModulePlanStatus status, int expected, int attempts)
    {
        var ports = new Ports { Read = _ => ModulePlanOutcome.Of(status) };
        var failure = await Assert.ThrowsAsync<IdentityStorageException>(() => Store(ports).FindUserAsync(Realm, User, TestContext.Current.CancellationToken).AsTask());
        Assert.Equal((IdentityStorageFailure)expected, failure.Failure);
        Assert.Equal(attempts, ports.Reads.Count);
        Assert.Equal(0, ports.Writes);
    }

    [Fact]
    public async Task CancelledBackoffStopsReadRetriesAndNeverWrites()
    {
        using var cancellation = new CancellationTokenSource();
        var ports = new Ports { Read = _ => { cancellation.Cancel(); return ModulePlanOutcome.Of(ModulePlanStatus.Unavailable); } };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Store(ports).FindUserAsync(Realm, User, cancellation.Token).AsTask());
        Assert.Single(ports.Reads);
        Assert.Equal(0, ports.Writes);
    }

    [Fact]
    public async Task UnknownWriteOutcomeIsNeverBlindlyRetriedByTheStore()
    {
        var ports = new Ports { WriteStatus = ModulePlanStatus.UnknownOutcome };
        var commit = new IdentityCommit.RenameUser("00000000-0000-4000-8000-000000000002", WorkspaceId.Parse("00000000-0000-4000-8000-000000000003"), new Principal(Realm, User), 1, "Ada");
        var failure = await Assert.ThrowsAsync<IdentityStorageException>(() => Store(ports).CommitAsync(commit, TestContext.Current.CancellationToken).AsTask());
        Assert.Equal(IdentityStorageFailure.OutcomeUnknown, failure.Failure);
        Assert.Equal(1, ports.Writes);
    }
}
