// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.SharedFamilies;
using Xunit;

namespace ArcForges.Cloud.Tests.SharedFamilies;

/// <summary>The structural rules C# applies to a generated family plan before it runs anything (defence in depth against a stale generated file).</summary>
public sealed class FamilyPlanVerifierTests
{
    private static FamilyPlanDefinition WithRoles(FamilyPlanDefinition plan, Func<IReadOnlyList<FamilyStatementRole>, IEnumerable<FamilyStatementRole>> change)
    {
        var roles = change(plan.Roles).ToArray();
        // Keep the statement list aligned so only the rule under test fails.
        var statements = roles.Select(role => plan.Plan.Statements[Math.Min(IndexOf(plan, role), plan.Plan.Statements.Count - 1)]).ToArray();
        return plan with { Roles = roles, Plan = plan.Plan with { Statements = statements } };
    }

    private static int IndexOf(FamilyPlanDefinition plan, FamilyStatementRole role)
    {
        var index = plan.Roles.ToList().FindIndex(candidate => candidate.Equals(role));
        return index >= 0 ? index : 0;
    }

    private static IReadOnlyList<string> Problems(FamilyPlanDefinition plan, FamilyDefinition? definition = null) => FamilyPlanVerifier.Problems(plan, definition ?? FamilyFixture.Definition());

    [Fact]
    public void TheFixturePlanVerifiesClean()
    {
        Assert.Empty(Problems(FamilyFixture.Plan()));
    }

    [Fact]
    public void AFamilyThatIsNotInTheRegistryIsRefused()
    {
        Assert.Contains("is not in the registry", Assert.Single(FamilyPlanVerifier.Problems(FamilyFixture.Plan(), null)), StringComparison.Ordinal);
        var other = FamilyFixture.Definition() with { Id = "other" };
        Assert.Contains("is not in the registry", Assert.Single(FamilyPlanVerifier.Problems(FamilyFixture.Plan(), other)), StringComparison.Ordinal);
    }

    [Fact]
    public void ARoleCountThatDiffersFromTheStatementCountIsRefused()
    {
        var plan = FamilyFixture.Plan();
        var short1 = plan with { Roles = plan.Roles.Take(plan.Roles.Count - 1).ToArray() };
        Assert.Contains(Problems(short1), problem => problem.Contains("statements for", StringComparison.Ordinal));
    }

    [Fact]
    public void ThePlanIdAccessAndFirstParameterRulesAreEnforced()
    {
        var plan = FamilyFixture.Plan();
        Assert.Contains(Problems(plan with { Plan = plan.Plan with { Id = "foundation.readiness" } }), problem => problem.Contains("families.<family>.<name>", StringComparison.Ordinal));
        Assert.Contains(Problems(plan with { Plan = plan.Plan with { Id = "families.other.commit" } }), problem => problem.Contains("families.<family>.<name>", StringComparison.Ordinal));
        Assert.Contains(Problems(plan with { Plan = plan.Plan with { Access = PlanAccess.Read } }), problem => problem.Contains("write plan", StringComparison.Ordinal));
        var statements = plan.Plan.Statements.ToArray();
        statements[0] = new PlanStatement([new PlanParam(PlanKind.Int64)], null);
        Assert.Contains(Problems(plan with { Plan = plan.Plan with { Statements = statements } }), problem => problem.Contains("command id as its first text parameter", StringComparison.Ordinal));
        statements[0] = new PlanStatement([], null);
        Assert.Contains(Problems(plan with { Plan = plan.Plan with { Statements = statements } }), problem => problem.Contains("command id as its first text parameter", StringComparison.Ordinal));
        statements[0] = new PlanStatement([new PlanParam(PlanKind.Text, true)], null);
        Assert.Contains(Problems(plan with { Plan = plan.Plan with { Statements = statements } }), problem => problem.Contains("command id as its first text parameter", StringComparison.Ordinal));
    }

    [Fact]
    public void ARequiredParticipantWithoutAStatementIsRefused()
    {
        var plan = WithRoles(FamilyFixture.Plan(), roles => roles.Where(role => role.Module != FamilyModule.Configuration));
        Assert.Contains(Problems(plan), problem => problem.Contains("required participant config has no statement", StringComparison.Ordinal));
    }

    [Fact]
    public void AModuleThatIsNotAParticipantIsRefused()
    {
        var plan = FamilyFixture.Plan();
        var definition = FamilyFixture.Definition() with { Participants = FamilyFixture.Definition().Participants.Where(participant => participant.Module != FamilyModule.Policy).ToArray() };
        Assert.Contains(Problems(plan, definition), problem => problem.Contains("module policy is not a participant of family fixture-pair", StringComparison.Ordinal));
    }

    [Fact]
    public void AModuleThatWritesWithoutAGuardOfItsOwnIsRefused()
    {
        var plan = WithRoles(FamilyFixture.Plan(), roles => roles.Where(role => !(role.Module == FamilyModule.Notification && role.Phase == FamilyPhase.Guard)));
        Assert.Contains(Problems(plan), problem => problem.Contains("module notification writes without a guard of its own", StringComparison.Ordinal));
    }

    [Fact]
    public void AGuardOnlyParticipantIsAllowedToReadWithoutWriting()
    {
        // The policy module in the fixture guards and never writes: a read-only authorization or policy port may participate (SU-01).
        Assert.DoesNotContain(FamilyFixture.Plan().Roles, role => role.Module == FamilyModule.Policy && role.Phase == FamilyPhase.Mutation);
        Assert.Empty(Problems(FamilyFixture.Plan()));
    }

    [Fact]
    public void APlanNeedsAGuardAndAMutation()
    {
        var noGuards = WithRoles(FamilyFixture.Plan(), roles => roles.Where(role => role.Phase != FamilyPhase.Guard));
        Assert.Contains(Problems(noGuards), problem => problem.Contains("at least one guard", StringComparison.Ordinal));
        var noMutations = WithRoles(FamilyFixture.Plan(), roles => roles.Where(role => role.Phase != FamilyPhase.Mutation));
        Assert.Contains(Problems(noMutations), problem => problem.Contains("at least one mutation", StringComparison.Ordinal));
    }

    [Fact]
    public void ADuplicateGuardKeyAcrossClassesIsRefused()
    {
        var plan = FamilyFixture.Plan();
        var roles = plan.Roles.ToList();
        // The same guard key (module.key) in two classes would collide on the guard table's primary key.
        roles[3] = roles[3] with { Key = "quota" };
        var collided = plan with { Roles = roles };
        Assert.Contains(Problems(collided), problem => problem.Contains("duplicate guard key entitlement.quota", StringComparison.Ordinal));
    }

    [Fact]
    public void AnOutOfOrderPlanIsRefusedWithTheOrderProblem()
    {
        var plan = FamilyFixture.Plan();
        var roles = plan.Roles.ToArray();
        (roles[1], roles[2]) = (roles[2], roles[1]);
        Assert.Contains(Problems(plan with { Roles = roles }), problem => problem.Contains("SU-04 order", StringComparison.Ordinal));
    }

    [Fact]
    public void VerifyAllReportsEveryProblemOfEveryPlanAndADuplicateFamily()
    {
        var plan = FamilyFixture.Plan();
        var broken = plan with { Plan = plan.Plan with { Access = PlanAccess.Read } };
        var problems = FamilyCatalog.VerifyAll([FamilyFixture.Definition(), FamilyFixture.Definition()], [plan, broken]);
        Assert.Contains("duplicate family fixture-pair", problems);
        Assert.Contains(problems, problem => problem.StartsWith("families.fixture-pair.commit: a family plan is a write plan", StringComparison.Ordinal));
        Assert.Empty(FamilyCatalog.VerifyAll([FamilyFixture.Definition()], [plan]));
        Assert.Null(FamilyCatalog.Find("nothing", [FamilyFixture.Definition()]));
        Assert.NotNull(FamilyCatalog.Find("fixture-pair", [FamilyFixture.Definition()]));
    }

    [Fact]
    public void TheEngineTypesAreInternalAndCarryNoSqlText()
    {
        var types = typeof(FamilyModule).Assembly.GetTypes().Where(type => string.Equals(type.Namespace, "ArcForges.Cloud.Storage.SharedFamilies", StringComparison.Ordinal)).ToArray();
        Assert.NotEmpty(types);
        Assert.All(types, type => Assert.False(type.IsVisible, type.FullName));
        var folder = Path.Combine(T.RepoRoot().FullName, "src", "ArcForges.Cloud.Storage.D1", "SharedFamilies");
        foreach (var file in Directory.EnumerateFiles(folder, "*.cs"))
        {
            var text = File.ReadAllText(file);
            Assert.DoesNotMatch(@"\b(?:SELECT|INSERT\s+INTO|DELETE\s+FROM|UPDATE\s+\w+\s+SET)\b", text);
            Assert.DoesNotContain("System.Reflection", text, StringComparison.Ordinal);
            Assert.DoesNotContain("Activator", text, StringComparison.Ordinal);
        }
    }
}
