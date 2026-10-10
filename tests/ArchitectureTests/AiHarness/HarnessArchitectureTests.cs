// SPDX-License-Identifier: AGPL-3.0-only
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>
/// The architecture suite of the ported AI policy (architecture.test.ts, HAR.40 validation (d)): the 86 pass and refuse fixtures (the AI policy's 84 and two CLOUD.84 S38(1) wire-package fixtures), one
/// test per fixture; the coverage, documentation and obligation checks; and the earlier C# refusals.
/// </summary>
public sealed class HarnessArchitectureTests
{
    private static readonly string Root = CloudRepository.FindRoot();

    private static readonly IReadOnlyList<AiFixture> Fixtures = HarnessArchitectureFixtures.AiFixtures();

    public static IEnumerable<object[]> AiFixtureCases() => Fixtures.Select(fixture => new object[] { fixture.Rule, fixture.Kind, fixture.Name });

    public static IEnumerable<object[]> CSharpRefusalCases() => HarnessArchitectureFixtures.CSharpRefusals().Select(refusal => new object[] { refusal.Rule, refusal.Case });

    [Fact]
    public void AcceptsTheMinimalCompliantRepository()
    {
        Assert.Empty(HarnessArchitecture.Audit(HarnessArchitectureFixtures.Baseline()));
    }

    [Theory]
    [MemberData(nameof(AiFixtureCases))]
    public void EveryAiFixtureYieldsItsOutcome(string rule, string kind, string name)
    {
        var fixture = Fixtures.Single(item => item.Rule == rule && item.Kind == kind && item.Name == name);
        var findings = fixture.Run();
        if (kind == "pass") Assert.Empty(findings);
        else Assert.Contains(findings, finding => finding.Rule == rule);
    }

    [Fact]
    public void TheFixtureSetIsTheAiPolicySuiteWithTwentySevenPassingAndFiftySevenRefusedFixtures()
    {
        Assert.Equal(86, Fixtures.Count);
        Assert.Equal(28, Fixtures.Count(fixture => fixture.Kind == "pass"));
        Assert.Equal(58, Fixtures.Count(fixture => fixture.Kind == "fail"));
        Assert.Equal(Fixtures.Count, Fixtures.Select(fixture => (fixture.Rule, fixture.Name)).Distinct().Count());
    }

    [Fact]
    public void EveryRuleHasAPassingAndARefusedFixtureExceptNamingScan()
    {
        // naming-scan is exercised against the real scanner in NamingGateTests, as in the AI suite.
        foreach (var rule in HarnessArchitecture.Rules.Where(rule => rule.Id != "naming-scan"))
        {
            var own = Fixtures.Where(fixture => fixture.Rule == rule.Id).ToList();
            Assert.True(own.Any(fixture => fixture.Kind == "pass"), rule.Id + " has no passing fixture");
            Assert.True(own.Any(fixture => fixture.Kind == "fail"), rule.Id + " has no refused fixture");
        }

        foreach (var fixture in Fixtures)
        {
            Assert.True(HarnessArchitecture.Rules.Any(rule => rule.Id == fixture.Rule), "unknown rule " + fixture.Rule);
        }

        Assert.Equal(HarnessArchitecture.Rules.Count, HarnessArchitecture.Rules.Select(rule => rule.Id).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void DocumentsEveryRuleInTheFoundationDocument()
    {
        var description = File.ReadAllText(Path.Combine(Root, "docs/harness-foundation.md"));
        foreach (var rule in HarnessArchitecture.Rules)
        {
            Assert.Contains("`" + rule.Id + "`", description, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void TheCatalogueHoldsTheTwentySevenSuccessorRulesUnderTheFiveObligations()
    {
        Assert.Equal(27, HarnessArchitecture.Rules.Count);
        Assert.Equal(HarnessArchitecture.Rules.Count, HarnessArchitecture.Rules.Select(rule => rule.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(new[] { "WP-05.00", "WP-05.01", "WP-05.02", "WP-05.03", "WP-05.04" }, HarnessArchitecture.Rules.Select(rule => rule.Obligation).Distinct(StringComparer.Ordinal).OrderBy(o => o, StringComparer.Ordinal).ToArray());
    }

    [Theory]
    [MemberData(nameof(CSharpRefusalCases))]
    public void EveryEarlierCSharpRefusalRaisesItsRule(string rule, string caseName)
    {
        var sources = HarnessArchitectureFixtures.CSharpRefusals().Single(refusal => refusal.Rule == rule && refusal.Case == caseName).Sources;
        Assert.Contains(HarnessArchitecture.Audit(sources), finding => finding.Rule == rule);
    }
}
