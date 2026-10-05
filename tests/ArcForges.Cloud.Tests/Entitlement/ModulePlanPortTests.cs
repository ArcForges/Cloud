// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Receipts;
using Xunit;
using static ArcForges.Cloud.Tests.Receipts.ScriptedExecutor;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>
/// The generic plan-execution port (COM.16): a module reaches D1 only through named plans of its own owner, with exact typed arguments, and
/// every plan failure becomes a typed status. The SQL itself is proved by the oracle tests; this is what the adapter does around it.
/// </summary>
public sealed class ModulePlanPortTests
{
    private static readonly ModuleDescriptor Entitlement = EntitlementModule.Instance.Descriptor;
    private static readonly ModuleDescriptor Commerce = ModuleDescriptor.Create("Commerce", "commerce");

    private sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Samples.Now;
    }

    private static (IModulePlanPortFactory Factory, ScriptedExecutor Storage) Create(ulong generation = 7)
    {
        var storage = new ScriptedExecutor();
        return (new ModulePlanPortFactory(storage, generation, new FixedTime()), storage);
    }

    [Theory]
    [InlineData("entitlement.revision-load")]
    [InlineData("platform.command-load")]
    [InlineData("foundation.readiness")]
    [InlineData("commerce.anything")]
    public async Task APlanOfAnotherOwnerIsRefusedBeforeAnythingIsSent(string planId)
    {
        var (factory, storage) = Create();
        var port = factory.For(planId.StartsWith("commerce.", StringComparison.Ordinal) ? Entitlement : Commerce);

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await port.ReadAsync(new ModulePlanRead(planId, "scope", [PlanValue.FromText("x")]), T.Ct));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await port.WriteAsync(new ModulePlanWrite(planId, "scope", [[PlanValue.FromText("x")]], null), T.Ct));

        Assert.Empty(storage.Calls);
    }

    [Fact]
    public async Task AnUnknownPlanAndAnAccessMismatchAreCallerDefectsThatNeverReachTheExecutor()
    {
        var (factory, storage) = Create();
        var port = factory.For(Entitlement);

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await port.ReadAsync(new ModulePlanRead("entitlement.no-such-plan", "s", []), T.Ct));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await port.ReadAsync(new ModulePlanRead("entitlement.commit", "s", []), T.Ct));
        await Assert.ThrowsAsync<InvalidOperationException>(async () => await port.WriteAsync(new ModulePlanWrite("entitlement.revision-load", "s", [], null), T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(async () => await port.ReadAsync(new ModulePlanRead("", "s", []), T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(async () => await port.WriteAsync(new ModulePlanWrite("entitlement.feature-release-append", "s", [[], []], null), T.Ct));

        Assert.Empty(storage.Calls);
    }

    [Fact]
    public async Task ARoundTripCarriesExactTypedValuesTheScopeAndTheRecoveryGeneration()
    {
        var (factory, storage) = Create(generation: 9);
        storage.Handler = _ => Rows([D1Values.Int64(long.MaxValue)]);

        var outcome = await factory.For(Entitlement).ReadAsync(new ModulePlanRead("entitlement.revision-load", "00000000-0000-4000-8000-0000000000b1", [PlanValue.FromText("00000000-0000-4000-8000-0000000000b1")]), T.Ct);

        Assert.Equal(ModulePlanStatus.Succeeded, outcome.Status);
        Assert.Equal(long.MaxValue, outcome.Rows.Single().Single().AsInt64());
        var call = storage.Calls.Single();
        Assert.Equal(9UL, call.RecoveryGeneration);
        Assert.Equal("00000000-0000-4000-8000-0000000000b1", call.OwnerScope);
        Assert.Equal("entitlement.revision-load", call.Plan.Id);
    }

    [Fact]
    public async Task AnArgumentThatDoesNotMatchTheStatementKindsIsRejectedByTheSharedValidationBeforeExecution()
    {
        var (factory, storage) = Create();

        var outcome = await factory.For(Entitlement).ReadAsync(new ModulePlanRead("entitlement.revision-load", "s", [PlanValue.FromInt64(1)]), T.Ct);

        Assert.Equal(ModulePlanStatus.Rejected, outcome.Status);
        Assert.Empty(storage.Calls);
    }

    [Theory]
    [InlineData((int)PlanFailureKind.Precondition, ModulePlanStatus.GuardRefused)]
    [InlineData((int)PlanFailureKind.Constraint, ModulePlanStatus.ConstraintRefused)]
    [InlineData((int)PlanFailureKind.UnknownOutcome, ModulePlanStatus.UnknownOutcome)]
    [InlineData((int)PlanFailureKind.StaleGeneration, ModulePlanStatus.StaleGeneration)]
    [InlineData((int)PlanFailureKind.Overloaded, ModulePlanStatus.Unavailable)]
    [InlineData((int)PlanFailureKind.Unavailable, ModulePlanStatus.Unavailable)]
    [InlineData((int)PlanFailureKind.Transport, ModulePlanStatus.Unavailable)]
    [InlineData((int)PlanFailureKind.InvalidPlan, ModulePlanStatus.Rejected)]
    [InlineData((int)PlanFailureKind.ManifestMismatch, ModulePlanStatus.Rejected)]
    public async Task EveryPlanFailureBecomesATypedStatus(int failure, ModulePlanStatus expected)
    {
        var kind = (PlanFailureKind)failure;
        var (factory, storage) = Create();
        storage.Handler = _ => throw Fail(kind);
        var port = factory.For(Entitlement);

        var read = await port.ReadAsync(new ModulePlanRead("entitlement.revision-load", "w", [PlanValue.FromText("w")]), T.Ct);
        var write = await port.WriteAsync(new ModulePlanWrite("entitlement.feature-release-append", "feature.ai", [[PlanValue.FromText("feature.ai"), PlanValue.FromInt64(5)]], null), T.Ct);

        Assert.Equal(expected, read.Status);
        Assert.Equal(expected, write.Status);
        Assert.Empty(read.Rows);
    }

    [Fact]
    public async Task AReadThatReturnsAScalarTheModulePortDoesNotCarryIsRejected()
    {
        var (factory, storage) = Create();
        storage.Handler = _ => Rows([D1Values.Uint64(5)]);

        var outcome = await factory.For(Entitlement).ReadAsync(new ModulePlanRead("entitlement.revision-load", "w", [PlanValue.FromText("w")]), T.Ct);

        Assert.Equal(ModulePlanStatus.Rejected, outcome.Status);
    }

    [Fact]
    public async Task ACommitForAPlanThatDeclaresNoTailIsRejected()
    {
        var (factory, storage) = Create();
        var commit = new ModuleCommit(Samples.Id(1), null, "actor", "op", "hash", "{}", 1, Samples.NowMicros, Samples.NowMicros + 1000, [], 1, "{}");

        var outcome = await factory.For(Entitlement).WriteAsync(
            new ModulePlanWrite("entitlement.feature-release-append", "feature.ai", [[PlanValue.FromText("feature.ai"), PlanValue.FromInt64(5)]], commit), T.Ct);

        Assert.Equal(ModulePlanStatus.Rejected, outcome.Status);
        Assert.Empty(storage.Calls);
    }

    [Fact]
    public void PlanValuesAreExactAndNeverDescribeTheirContent()
    {
        Assert.Equal(PlanValue.FromInt64(long.MinValue), PlanValue.FromInt64(long.MinValue));
        Assert.NotEqual(PlanValue.FromInt64(1), PlanValue.FromBool(true));
        Assert.Equal(PlanValue.FromBytes([1, 2, 3]), PlanValue.FromBytes([1, 2, 3]));
        Assert.NotEqual(PlanValue.FromText("a"), PlanValue.FromText("b"));
        Assert.Equal(PlanValue.Null, PlanValue.FromOptionalText(null));
        Assert.Throws<InvalidOperationException>(() => PlanValue.FromText("x").AsInt64());
        Assert.Null(PlanValue.Null.AsOptionalInt64());
        Assert.DoesNotContain("secret", PlanValue.FromText("secret").ToString(), StringComparison.Ordinal);
        Assert.Throws<ArgumentNullException>(() => PlanValue.FromText(null!));
    }
}
