// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.SharedFamilies;
using Xunit;

namespace ArcForges.Cloud.Tests.SharedFamilies;

/// <summary>
/// The fixed module lock order of Design SU-04 and the order rule of a family plan, held to the same shared vectors as the TypeScript
/// generator (<c>Vectors/family-lock-order.json</c>): both implementations must give the same verdict on every case.
/// </summary>
public sealed class LockOrderTests
{
    [Fact]
    public void TheOrderIsExactlyTheSharedVectorAndSupportAndTrustSafetyHaveNoPosition()
    {
        var expected = FamilyFixture.Vectors.GetProperty("lockOrder").EnumerateArray().Select(item => item.GetString()!).ToArray();
        Assert.Equal(expected, ModuleLockOrder.Order.Select(ModuleLockOrder.Owner).ToArray());
        Assert.Equal(17, ModuleLockOrder.Order.Count);
        Assert.All(ModuleLockOrder.Order, module => Assert.True(ModuleLockOrder.HasPosition(module)));
        Assert.False(ModuleLockOrder.HasPosition(FamilyModule.Platform));
        Assert.False(ModuleLockOrder.TryFromOwner("support", out _));
        Assert.False(ModuleLockOrder.TryFromOwner("trustsafety", out _));
        Assert.False(ModuleLockOrder.TryFromOwner("", out _));
        Assert.False(ModuleLockOrder.TryFromOwner("Identity", out _));
        Assert.True(ModuleLockOrder.TryFromOwner("platform", out var platform) && platform == FamilyModule.Platform);
    }

    [Fact]
    public void ThePositionsAreStrictlyIncreasingAndThePlatformSitsOutsideTheOrder()
    {
        var ranks = ModuleLockOrder.Order.Select(module => ModuleLockOrder.Rank(module, FamilyPhase.Guard)).ToArray();
        Assert.Equal(Enumerable.Range(0, 17), ranks);
        Assert.Equal(ranks, ModuleLockOrder.Order.Select(module => ModuleLockOrder.Rank(module, FamilyPhase.Mutation)).ToArray());
        Assert.Equal(-1, ModuleLockOrder.Rank(FamilyModule.Platform, FamilyPhase.Guard));
        Assert.Equal(17, ModuleLockOrder.Rank(FamilyModule.Platform, FamilyPhase.Mutation));
        Assert.Equal(17, ModuleLockOrder.Rank(FamilyModule.Platform, FamilyPhase.Release));
        Assert.Throws<ArgumentOutOfRangeException>(() => ModuleLockOrder.Rank((FamilyModule)99, FamilyPhase.Guard));
    }

    [Fact]
    public void EveryModuleOwnerIsAnOwnerOfThePlanRegistryAndNothingElseIs()
    {
        using var registry = JsonDocument.Parse(File.ReadAllText(Path.Combine(T.RepoRoot().FullName, "storage", "plans", "owners.json")));
        var owners = registry.RootElement.GetProperty("owners").EnumerateArray().Where(owner => owner.GetProperty("kind").GetString() is "module" or "platform").Select(owner => owner.GetProperty("owner").GetString()!).ToHashSet();
        foreach (var module in Enum.GetValues<FamilyModule>()) Assert.Contains(ModuleLockOrder.Owner(module), owners);
        // The two module owners with no SU-04 position are exactly the registry owners the engine cannot enlist.
        Assert.Equal(["support", "trustsafety"], owners.Except(Enum.GetValues<FamilyModule>().Select(ModuleLockOrder.Owner)).Order().ToArray());
    }

    public static TheoryData<int> CaseIndexes()
    {
        var data = new TheoryData<int>();
        var count = FamilyFixture.Vectors.GetProperty("orderCases").GetArrayLength();
        for (var index = 0; index < count; index++) data.Add(index);
        return data;
    }

    [Theory]
    [MemberData(nameof(CaseIndexes))]
    public void EachSharedOrderVectorHasTheVerdictTheGeneratorGives(int index)
    {
        var testCase = FamilyFixture.Vectors.GetProperty("orderCases")[index];
        var expectedValid = testCase.GetProperty("valid").GetBoolean();
        var roles = new List<FamilyStatementRole>();
        var known = true;
        foreach (var text in testCase.GetProperty("roles").EnumerateArray())
        {
            roles.Add(FamilyFixture.ParseRole(text.GetString()!, out var isKnown));
            known &= isKnown;
        }

        // A module with no position is not a FamilyModule at all, so such a plan cannot even be expressed: that is the refusal.
        var problems = known ? FamilyPlanVerifier.OrderProblems(roles) : ["unknown module"];
        Assert.True(expectedValid == (problems.Count == 0), testCase.GetProperty("name").GetString() + ": " + string.Join("; ", problems));
    }

    [Fact]
    public void TheOrderRuleNamesTheFirstRuleAPlanBreaks()
    {
        var problems = FamilyPlanVerifier.OrderProblems(
        [
            new(FamilyModule.Workspace, FamilyPhase.Guard, FamilyClass.Revision, "a"),
            new(FamilyModule.Identity, FamilyPhase.Guard, FamilyClass.Revision, "a"),
            new(FamilyModule.Workspace, FamilyPhase.Mutation, FamilyClass.Record, "a"),
            new(FamilyModule.Platform, FamilyPhase.Release, FamilyClass.Release, "release"),
        ]);
        var problem = Assert.Single(problems);
        Assert.Contains("module identity may not follow module workspace (SU-04 order)", problem, StringComparison.Ordinal);
    }

    [Fact]
    public void StableKeysAreSortedAscendingAndADuplicateKeyIsRefused()
    {
        Assert.Equal(["a", "b", "c"], FamilyKeyOrder.Ascending(["c", "a", "b"]));
        Assert.Equal(["A", "a"], FamilyKeyOrder.Ascending(["a", "A"]));
        Assert.Empty(FamilyKeyOrder.Ascending([]));
        var duplicate = Assert.Throws<FamilyViolationException>(() => FamilyKeyOrder.Ascending(["a", "b", "a"]));
        Assert.Equal(FamilyViolation.InvalidArguments, duplicate.Violation);
    }

    [Fact]
    public void TheCheckedInRegistryAndPlansVerifyAndTheFamilyCatalogIsClosed()
    {
        Assert.Empty(FamilyCatalog.VerifyAll());
        Assert.Equal(PlanManifest.FamilyPlans.Count, PlanManifest.All.Count(plan => plan.Id.StartsWith("families.", StringComparison.Ordinal)));
        Assert.All(PlanManifest.FamilyCatalog, family => Assert.All(family.Participants, participant => Assert.True(ModuleLockOrder.HasPosition(participant.Module))));
    }
}
