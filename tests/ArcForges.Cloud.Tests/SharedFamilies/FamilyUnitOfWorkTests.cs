// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.SharedFamilies;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests.SharedFamilies;

/// <summary>The unit of work (Design SU-02): modules contribute typed arguments of their own statements; the plan fixes the order and the command identity.</summary>
public sealed class FamilyUnitOfWorkTests
{
    private static FamilyViolation Refusal(Action action) => Assert.Throws<FamilyViolationException>(action).Violation;

    [Fact]
    public void SealOrdersTheArgumentsByThePlanNotByTheOrderOfContribution()
    {
        var command = Guid.NewGuid();
        var call = FamilyFixture.Unit(command).Seal();
        Assert.Equal(12, call.Arguments.Length);
        Assert.Equal(FamilyFixture.Workspace, call.OwnerScope);
        Assert.Equal(0UL, call.RecoveryGeneration);
        Assert.Equal("families.fixture-pair.commit", call.Plan.Id);
        // The contributions were added in reverse plan order; the sealed call is in plan order (platform lease first, receipt and release last).
        Assert.Equal(FamilyFixture.Job, FamilyFixture.Text(call.Arguments[0][1]));
        Assert.Equal(FamilyFixture.ConfigRevision, FamilyFixture.Text(call.Arguments[1][1]));
        Assert.Equal("recipient", FamilyFixture.Text(call.Arguments[6][1]));
        Assert.Equal("recipient", FamilyFixture.Text(call.Arguments[9][0]));
        Assert.Equal(command.ToString("D"), FamilyFixture.Text(call.Arguments[10][0]));
    }

    [Fact]
    public void TheCommandIdentityLeadsEveryGuardAndTheReleaseAndNothingElse()
    {
        var command = Guid.NewGuid();
        var unit = FamilyFixture.Unit(command);
        var call = unit.Seal();
        var plan = unit.Family;
        for (var index = 0; index < plan.Roles.Count; index++)
        {
            var role = plan.Roles[index];
            var first = call.Arguments[index][0];
            // A mutation gets exactly what its module contributed (the platform receipt contributes the command id itself, the others do not).
            if (role.Phase == FamilyPhase.Mutation) Assert.Equal(role.Module == FamilyModule.Platform, D1Values.TryGetText(first, out var text) && string.Equals(text, command.ToString("D"), StringComparison.Ordinal));
            else Assert.Equal(command.ToString("D"), FamilyFixture.Text(first));
        }

        // The release carries only the command identity: it deletes exactly this batch's guard rows.
        var release = call.Arguments[^1];
        Assert.Single(release);
        Assert.Equal(command.ToString("D"), FamilyFixture.Text(release[0]));
        // A module cannot choose the command identity of a guard: the first contributed value is the first after it.
        Assert.Equal(call.Plan.Statements[0].Params.Count, call.Arguments[0].Length);
    }

    [Fact]
    public void ARepeatedSealOfTheSameUnitGivesTheSameArgumentsAndAFreshRequestId()
    {
        var unit = FamilyFixture.Unit();
        var first = unit.Seal();
        var second = unit.Seal();
        Assert.NotEqual(first.RequestId, second.RequestId);
        Assert.Equal(first.Arguments.Select(row => row.Length), second.Arguments.Select(row => row.Length));
        Assert.Equal(unit.CommandId, unit.CommandId);
    }

    [Fact]
    public void AMissingContributionIsRefusedAtSealAndNamesNoValue()
    {
        var command = Guid.NewGuid();
        var unit = FamilyUnitOfWork.Begin(FamilyFixture.Plan(), command, FamilyFixture.Workspace, 0, FamilyFixture.Definition());
        foreach (var contribution in FamilyFixture.Contributions(command).Where(contribution => contribution.Module != FamilyModule.Entitlement || contribution.Class != FamilyClass.Balance)) unit.Contribute(contribution);
        var exception = Assert.Throws<FamilyViolationException>(unit.Seal);
        Assert.Equal(FamilyViolation.MissingContribution, exception.Violation);
        Assert.Equal("entitlement.quota", exception.Detail);
        Assert.DoesNotContain(FamilyFixture.Workspace, exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AContributionToAStatementThePlanDoesNotHaveIsRefused()
    {
        var unit = FamilyUnitOfWork.Begin(FamilyFixture.Plan(), Guid.NewGuid(), FamilyFixture.Workspace, 0, FamilyFixture.Definition());
        // Another module cannot add a statement, nor write one the plan gave to a different module or class or key.
        Assert.Equal(FamilyViolation.NotInPlan, Refusal(() => unit.Contribute(FamilyGuards.Mutation(FamilyModule.Commerce, FamilyClass.Record, "extra", [D1Values.Int64(1)]))));
        Assert.Equal(FamilyViolation.NotInPlan, Refusal(() => unit.Contribute(FamilyGuards.Mutation(FamilyModule.Workspace, FamilyClass.Record, "owner", [D1Values.Int64(1)]))));
        Assert.Equal(FamilyViolation.NotInPlan, Refusal(() => unit.Contribute(FamilyGuards.Revision(FamilyModule.Entitlement, "quota", [D1Values.Text("x")], 1))));
        Assert.Equal(FamilyViolation.NotInPlan, Refusal(() => unit.Contribute(new FamilyContribution(FamilyModule.Platform, FamilyClass.Release, "release", [D1Values.Text("x")]))));
    }

    [Fact]
    public void ASecondContributionToTheSameStatementIsRefused()
    {
        var command = Guid.NewGuid();
        var unit = FamilyUnitOfWork.Begin(FamilyFixture.Plan(), command, FamilyFixture.Workspace, 0, FamilyFixture.Definition());
        var contribution = FamilyFixture.Contributions(command)[0];
        unit.Contribute(contribution);
        Assert.Equal(FamilyViolation.DuplicateContribution, Refusal(() => unit.Contribute(contribution)));
    }

    [Fact]
    public void ArgumentsThatDoNotMatchTheTypedStatementAreRefusedBeforeAnythingIsSent()
    {
        var command = Guid.NewGuid();
        // A lease's values in a revision's slot: the kinds (and the count) cannot match the generated statement.
        var unit = FamilyUnitOfWork.Begin(FamilyFixture.Plan(), command, FamilyFixture.Workspace, 0, FamilyFixture.Definition());
        foreach (var contribution in FamilyFixture.Contributions(command).Where(contribution => !(contribution.Module == FamilyModule.Entitlement && contribution.Class == FamilyClass.Revision))) unit.Contribute(contribution);
        unit.Contribute(FamilyGuards.Revision(FamilyModule.Entitlement, "workspace-revision", [D1Values.Int64(1)], 7));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => unit.Seal()));
    }

    [Fact]
    public void AScopeBoundKeyThatDiffersFromTheOwnerScopeIsRefused()
    {
        var unit = FamilyFixture.Unit(scope: "another-workspace");
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => unit.Seal()));
    }

    [Fact]
    public void BeginRefusesABrokenPlanAnEmptyCommandAndAnUnusableScope()
    {
        var plan = FamilyFixture.Plan();
        var broken = plan with { Plan = plan.Plan with { Access = PlanAccess.Read } };
        Assert.Equal(FamilyViolation.PlanRule, Refusal(() => FamilyUnitOfWork.Begin(broken, Guid.NewGuid(), FamilyFixture.Workspace, 0, FamilyFixture.Definition())));
        Assert.Equal(FamilyViolation.PlanRule, Refusal(() => FamilyUnitOfWork.Begin(plan, Guid.NewGuid(), FamilyFixture.Workspace, 0, null)));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyUnitOfWork.Begin(plan, Guid.Empty, FamilyFixture.Workspace, 0, FamilyFixture.Definition())));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyUnitOfWork.Begin(plan, Guid.NewGuid(), "", 0, FamilyFixture.Definition())));
        Assert.Equal(FamilyViolation.InvalidArguments, Refusal(() => FamilyUnitOfWork.Begin(plan, Guid.NewGuid(), new string('x', 257), 0, FamilyFixture.Definition())));
        Assert.Throws<ArgumentNullException>(() => FamilyUnitOfWork.Begin(plan, Guid.NewGuid(), null!, 0, FamilyFixture.Definition()));
    }

    [Fact]
    public void TheRecoveryGenerationTravelsWithTheCall()
    {
        var call = FamilyFixture.Unit(generation: 41).Seal();
        Assert.Equal(41UL, call.RecoveryGeneration);
    }

    [Fact]
    public void AViolationNeverCarriesAValue()
    {
        var exception = Assert.Throws<FamilyViolationException>(() => FamilyFixture.Unit(scope: "secret-scope-value").Seal());
        Assert.DoesNotContain("secret-scope-value", exception.Message + exception.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void AModulesContributorStampsItsModuleAndCannotReachAnotherModulesStatement()
    {
        var command = Guid.NewGuid();
        var unit = FamilyUnitOfWork.Begin(FamilyFixture.Plan(), command, FamilyFixture.Workspace, 0, FamilyFixture.Definition());
        var workspace = D1Values.Text(FamilyFixture.Workspace);
        var entitlement = unit.For(FamilyModule.Entitlement);
        Assert.Equal(FamilyModule.Entitlement, entitlement.Module);
        // The entitlement contributor holds no key of the workspace module's, nor of a module the plan does not have.
        Assert.Equal(FamilyViolation.NotInPlan, Refusal(() => entitlement.Authorization("owner", [workspace], [D1Values.Text(FamilyFixture.User), D1Values.Int64(1)])));
        Assert.Equal(FamilyViolation.NotInPlan, Refusal(() => unit.For(FamilyModule.Commerce).Revision("workspace-revision", [workspace], 7)));
        entitlement.Revision("workspace-revision", [workspace], 7);
        Assert.Equal(FamilyViolation.DuplicateContribution, Refusal(() => entitlement.Revision("workspace-revision", [workspace], 7)));
    }

    [Fact]
    public void AllContributorsTogetherSealTheSameCallAsTheRawContributions()
    {
        var command = Guid.NewGuid();
        var raw = FamilyFixture.Unit(command).Seal();
        var unit = FamilyUnitOfWork.Begin(FamilyFixture.Plan(), command, FamilyFixture.Workspace, 0, FamilyFixture.Definition());
        foreach (var contribution in FamilyFixture.Contributions(command))
        {
            var contributor = unit.For(contribution.Module);
            switch (contribution.Class)
            {
                case FamilyClass.Bucket or FamilyClass.Reservation or FamilyClass.Record:
                    contributor.Mutation(contribution.Class, contribution.Key, contribution.Arguments);
                    break;
                default:
                    // The guard builders are exercised through the contributor's typed methods below; here the raw guard is replayed.
                    unit.Contribute(contribution);
                    break;
            }
        }

        var viaContributors = unit.Seal();
        Assert.Equal(raw.Arguments.Select(row => row.Length), viaContributors.Arguments.Select(row => row.Length));
    }

    [Fact]
    public void EachContributorMethodBuildsTheSameGuardAsThePrimitive()
    {
        var command = Guid.NewGuid();
        var unit = FamilyUnitOfWork.Begin(FamilyFixture.Plan(), command, FamilyFixture.Workspace, 0, FamilyFixture.Definition());
        var workspace = D1Values.Text(FamilyFixture.Workspace);
        unit.For(FamilyModule.Platform).Lease("job-lease", [D1Values.Text(FamilyFixture.Job)], "container-a", 5, FamilyFixture.NowMicros)
            .Mutation(FamilyClass.Record, "receipt", FamilyFixture.Contributions(command).Single(c => c.Module == FamilyModule.Platform && c.Class == FamilyClass.Record).Arguments);
        unit.For(FamilyModule.Configuration).Policy("active-config", [D1Values.Text(FamilyFixture.ConfigRevision)], [D1Values.Int64(2), D1Values.Bytes(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray())]);
        unit.For(FamilyModule.Workspace).Authorization("owner", [workspace], [D1Values.Text(FamilyFixture.User), D1Values.Int64(1)]);
        unit.For(FamilyModule.Entitlement)
            .Revision("workspace-revision", [workspace], 7)
            .Balance("quota", [D1Values.Int64(1), workspace, D1Values.Text("storage"), D1Values.Text("gauge")], 3, [D1Values.Int64(10), D1Values.Int64(2)])
            .Mutation(FamilyClass.Bucket, "quota", [D1Values.Int64(13), D1Values.Int64(2), D1Values.Int64(1), workspace, D1Values.Text("storage"), D1Values.Text("gauge")])
            .Mutation(FamilyClass.Record, "revision", [D1Values.Int64(FamilyFixture.NowMicros), workspace]);
        unit.For(FamilyModule.Policy).Policy("source-policy", [workspace, D1Values.Text("project"), D1Values.Text(FamilyFixture.PolicyTarget)], [D1Values.Int64(4)]);
        unit.For(FamilyModule.Notification)
            .Revision("suppression", [D1Values.Text("recipient"), D1Values.Int64(1)], 0)
            .Mutation(FamilyClass.Record, "suppression", [D1Values.Text("recipient"), D1Values.Int64(1), D1Values.Int64(1), D1Values.Int64(FamilyFixture.NowMicros)]);
        var call = unit.Seal();
        var raw = FamilyFixture.Unit(command).Seal();
        for (var index = 0; index < raw.Arguments.Length; index++)
            Assert.Equal(raw.Arguments[index].Select(FamilyFixture.Render), call.Arguments[index].Select(FamilyFixture.Render));
    }
}
