// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.FamilyBinding;
using ArcForges.Cloud.Storage.SharedFamilies;
using ArcForges.Cloud.Tests.Families;
using ArcForges.Cloud.Tests.Receipts;
using Xunit;

namespace ArcForges.Cloud.Tests.Platform;

public sealed class RecoveryFamilyGuardTests
{
    internal const string PlanId = "families.account-enrollment.recovery-fixture";

    internal static FamilyPlanDefinition Fixture()
    {
        var enrolled = PlanManifest.FamilyPlans.Single(item => item.Plan.Id == "families.account-enrollment.create-user");
        return enrolled with
        {
            Roles = [new(FamilyModule.Platform, FamilyPhase.Guard, FamilyClass.Authorization, "recovery-current"), .. enrolled.Roles],
            Plan = enrolled.Plan with
            {
                Id = PlanId,
                Statements = [new PlanStatement([new(PlanKind.Text), new(PlanKind.Text), new(PlanKind.Int64), new(PlanKind.Int64), new(PlanKind.Int64)], null), .. enrolled.Plan.Statements],
            },
        };
    }

    internal static ModuleFamilyPortFactory Factory(IPlanExecutor storage, ulong generation = 0, FamilyPlanDefinition? fixture = null) =>
        new(storage, generation, new Clock(), PlanManifest.FamilyCatalog, [fixture ?? Fixture()]);

    private sealed class Clock : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Samples.Now;
    }

    internal static ModuleFamilyWrite Write() => FamilyPortFixture.Enrollment() with { PlanId = PlanId, Contributions = FamilyPortFixture.Enrollment().Contributions.Where(item => item.Owner == "identity").ToArray() };

    internal static ConfiguredRealmAuthorityFamily Authority(IPlanExecutor storage, ModuleFamilyPortFactory? factory) => new(
        new ConfiguredRealmAuthority(key => key switch
        {
            "AF_REALM_ID" => Samples.Id(10).ToString("D"),
            "AF_AUTH_EPOCH" => "7",
            "AF_RECOVERY_GENERATION" => "0",
            _ => null,
        }, generation => new ArcForges.Cloud.Storage.Platform.RecoveryEpochReader(
            new ArcForges.Cloud.Storage.ModuleBinding.ModulePlanPortFactory(storage, checked((ulong)generation), TimeProvider.System), TimeProvider.System)), () => factory);

    internal static IModuleFamilyContributionSet Workspace(ModuleFamilyPortFactory factory) => factory.For(ModuleDescriptor.Create("Workspace", "workspace"))
        .Contribute("account-enrollment", PlanId, FamilyPortFixture.Enrollment().Contributions.Where(item => item.Owner == "workspace").ToArray());

    private static ScriptedExecutor Storage() => new()
    {
        Handler = call => call.Plan.Id == "platform.recovery-current"
            ? ScriptedExecutor.Rows([D1Values.Text(Samples.Id(10).ToString("D")), D1Values.Int64(0), D1Values.Int64(4), D1Values.Int64(1)])
            : call.Plan.Access == PlanAccess.Read ? ScriptedExecutor.Rows() : ScriptedExecutor.Changed(),
    };

    [Fact]
    public async Task RealReaderAndSameIssuerComposeExactRecoveryArgumentsWithoutPlatformPrivilege()
    {
        var storage = Storage();
        var factory = Factory(storage);
        var write = Write();
        var prepared = await Authority(storage, factory).PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        Assert.Equal(1, prepared.Snapshot?.RecoveryRevision);
        var capability = Assert.IsAssignableFrom<IModuleFamilyContributionSet>(prepared.Contribution);
        var port = factory.For(ModuleDescriptor.Create("Identity", "identity"));
        Assert.Equal(ModulePlanStatus.Succeeded, (await port.WriteAsync(write with { Participants = [Workspace(factory), capability] }, TestContext.Current.CancellationToken)).Status);
        var mutation = storage.Calls.Single(call => call.Plan.Id == PlanId);
        Assert.Equal(5, mutation.Arguments[0].Length);
        Assert.True(D1Values.TryGetInt64(mutation.Arguments[0][3], out var state));
        Assert.Equal(4, state);
        Assert.True(D1Values.TryGetInt64(mutation.Arguments[0][4], out var revision));
        Assert.Equal(1, revision);
        Assert.Throws<InvalidOperationException>(() => factory.For(ModuleDescriptor.Create("Platform", "platform")).Contribute(write.FamilyId, write.PlanId, []));
        Assert.Throws<InvalidOperationException>(() => port.Contribute(write.FamilyId, write.PlanId, [new("platform", "authorization", "recovery-current", [])]));
    }

    [Theory]
    [InlineData("forged")]
    [InlineData("issuer")]
    [InlineData("scope")]
    [InlineData("missing")]
    [InlineData("duplicate")]
    public async Task InvalidCapabilitiesNeverReadAReceiptOrMutate(string variant)
    {
        var storage = Storage();
        var factory = Factory(storage);
        var write = Write();
        var issuing = variant == "issuer" ? Factory(storage) : factory;
        var prepared = await Authority(storage, issuing).PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        var capability = Assert.IsAssignableFrom<IModuleFamilyContributionSet>(prepared.Contribution);
        var participants = variant switch
        {
            "forged" => new IModuleFamilyContributionSet[] { Workspace(factory), new Forged() },
            "missing" => [Workspace(factory)],
            "duplicate" => [Workspace(factory), capability, capability],
            _ => [Workspace(factory), capability],
        };
        if (variant == "scope") write = write with { OwnerScope = "different" };
        await Assert.ThrowsAnyAsync<Exception>(() => factory.For(ModuleDescriptor.Create("Identity", "identity")).WriteAsync(
            write with { Participants = participants }, TestContext.Current.CancellationToken));
        Assert.Equal(["platform.recovery-current"], storage.PlanIds);
    }

    [Theory]
    [InlineData("generation", RealmAuthorityFailure.StaleGeneration)]
    [InlineData("unavailable", RealmAuthorityFailure.Unavailable)]
    [InlineData("unregistered", RealmAuthorityFailure.Defect)]
    [InlineData("role", RealmAuthorityFailure.Defect)]
    [InlineData("shape", RealmAuthorityFailure.Defect)]
    public async Task UnavailableStaleOrUnregisteredIssuerCannotProduceASuccessfulCapability(string variant, RealmAuthorityFailure expected)
    {
        var storage = Storage();
        var fixture = Fixture();
        if (variant == "role") fixture = fixture with { Roles = [fixture.Roles[0] with { Key = "other" }, .. fixture.Roles.Skip(1)] };
        if (variant == "shape") fixture = fixture with { Plan = fixture.Plan with { Statements = [new PlanStatement([new(PlanKind.Text), new(PlanKind.Text)], null), .. fixture.Plan.Statements.Skip(1)] } };
        var factory = variant == "unavailable" ? null : Factory(storage, variant == "generation" ? 1UL : 0UL, fixture);
        var write = Write();
        var result = await Authority(storage, factory).PrepareAsync(write.FamilyId, variant == "unregistered" ? "families.account-enrollment.unknown" : write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        Assert.Equal(expected, result.Failure);
        Assert.Null(result.Snapshot);
        Assert.Null(result.Contribution);
        Assert.Equal(["platform.recovery-current"], storage.PlanIds);
    }

    [Fact]
    public async Task CancellationBeforePrepareNeverCallsStorage()
    {
        var storage = Storage();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Authority(storage, Factory(storage)).PrepareAsync("account-enrollment", PlanId, "scope", cancellation.Token));
        Assert.Empty(storage.Calls);
    }

    [Fact]
    public async Task MutableFixtureInputsAreCopiedAndCannotReplaceRolesOrParametersAfterFactoryCreation()
    {
        var storage = Storage();
        var fixture = Fixture();
        var roles = fixture.Roles.ToArray();
        var parameters = fixture.Plan.Statements[0].Params.ToArray();
        var statements = fixture.Plan.Statements.ToArray();
        statements[0] = statements[0] with { Params = parameters };
        var original = fixture with { Roles = roles, Plan = fixture.Plan with { Statements = statements } };
        FamilyPlanDefinition[] plans = [original];
        var factory = new ModuleFamilyPortFactory(storage, 0, new Clock(), PlanManifest.FamilyCatalog, plans);
        roles[0] = roles[0] with { Key = "forged" };
        parameters[1] = new PlanParam(PlanKind.Bytes);
        statements[0] = new PlanStatement([], null);
        plans[0] = original with { Family = "foreign" };
        var write = Write();
        var result = await Authority(storage, factory).PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        Assert.Null(result.Failure);
        Assert.Equal(ModulePlanStatus.Succeeded, (await factory.For(ModuleDescriptor.Create("Identity", "identity")).WriteAsync(write with
        {
            Participants = [Workspace(factory), Assert.IsAssignableFrom<IModuleFamilyContributionSet>(result.Contribution)],
        }, TestContext.Current.CancellationToken)).Status);
    }

    [Fact]
    public async Task CapabilityCannotMoveToAnotherOtherwiseRegisteredPlan()
    {
        var storage = Storage();
        var fixture = Fixture();
        var other = fixture with { Plan = fixture.Plan with { Id = "families.account-enrollment.other-fixture" } };
        var factory = new ModuleFamilyPortFactory(storage, 0, new Clock(), PlanManifest.FamilyCatalog, [fixture, other]);
        var write = Write();
        var prepared = await Authority(storage, factory).PrepareAsync(write.FamilyId, write.PlanId, write.OwnerScope, TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<InvalidOperationException>(() => factory.For(ModuleDescriptor.Create("Identity", "identity")).WriteAsync(write with
        {
            PlanId = other.Plan.Id,
            Participants = [Assert.IsAssignableFrom<IModuleFamilyContributionSet>(prepared.Contribution)],
        }, TestContext.Current.CancellationToken));
        Assert.Equal(["platform.recovery-current"], storage.PlanIds);
    }

    private sealed class Forged : IModuleFamilyContributionSet;
}
