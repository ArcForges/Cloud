// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>
/// The GOV.10 successor architecture rules as offline architecture tests (HAR.40 validation (d)): every rule has a passing fixture and at
/// least one refusing fixture, the clean tree passes, and the real Cloud inputs of this checkout carry no finding.
/// </summary>
public sealed class HarnessArchitectureTests
{
    private static readonly string Root = CloudRepository.FindRoot();

    public static IEnumerable<object[]> RuleIds() => HarnessArchitecture.Rules.Select(rule => new object[] { rule.Id });

    public static IEnumerable<object[]> Refusals() => HarnessArchitectureFixtures.Refusals().Select(refusal => new object[] { refusal.Rule, refusal.Case });

    [Fact]
    public void TheCatalogueHoldsTheTwentySevenSuccessorRulesUnderTheFiveObligations()
    {
        Assert.Equal(27, HarnessArchitecture.Rules.Count);
        Assert.Equal(HarnessArchitecture.Rules.Count, HarnessArchitecture.Rules.Select(rule => rule.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(new[] { "WP-05.00", "WP-05.01", "WP-05.02", "WP-05.03", "WP-05.04" }, HarnessArchitecture.Rules.Select(rule => rule.Obligation).Distinct(StringComparer.Ordinal).OrderBy(o => o, StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public void TheCleanBaselineHasNoFindingForAnyRule()
    {
        Assert.Empty(HarnessArchitecture.Audit(HarnessArchitectureFixtures.Baseline()));
    }

    [Theory]
    [MemberData(nameof(RuleIds))]
    public void EveryRulePassesItsCleanFixture(string rule)
    {
        Assert.DoesNotContain(HarnessArchitecture.Audit(HarnessArchitectureFixtures.Baseline()), finding => finding.Rule == rule);
    }

    [Theory]
    [MemberData(nameof(Refusals))]
    public void EveryRuleRefusesItsDefectFixture(string rule, string caseName)
    {
        var sources = HarnessArchitectureFixtures.Refusals().Single(refusal => refusal.Rule == rule && refusal.Case == caseName).Sources;
        Assert.Contains(HarnessArchitecture.Audit(sources), finding => finding.Rule == rule);
    }

    [Fact]
    public void EveryRuleIsNamedByARefusingFixtureSoAnUndocumentedRuleCannotHidePassing()
    {
        var refused = HarnessArchitectureFixtures.Refusals().Select(refusal => refusal.Rule).ToHashSet(StringComparer.Ordinal);
        var unrefused = HarnessArchitecture.Rules.Select(rule => rule.Id).Where(id => !refused.Contains(id)).ToList();
        var unknown = refused.Where(id => HarnessArchitecture.Rules.All(rule => rule.Id != id)).ToList();
        Assert.Empty(unrefused);
        Assert.Empty(unknown);
    }

    [Fact]
    public void TheRealCloudInputsOfThisCheckoutCarryNoFindingOutsideTheOwnedExceptions()
    {
        var sources = RealSources();
        var exceptions = ReadExceptions();
        var unexcepted = HarnessArchitecture.Audit(sources)
            .Where(finding => !exceptions.Any(row => row.Rule == finding.Rule && row.Path == finding.File))
            .ToList();
        Assert.Empty(unexcepted);
    }

    [Fact]
    public void TheSuccessorExceptionsAreExactOwnedReasonedAndExpireWithinOneHundredEightyDays()
    {
        var today = DateOnly.FromDateTime(DateTime.UtcNow);
        var sources = RealSources();
        var problems = new List<string>();
        foreach (var row in ReadExceptions())
        {
            if (!HarnessArchitecture.Rules.Any(rule => rule.Id == row.Rule)) problems.Add("Unknown rule: " + row.Rule);
            if (!sources.ContainsKey(row.Path) || row.Path.Contains('*', StringComparison.Ordinal)) problems.Add("Exception is not an exact audited path: " + row.Path);
            if (string.IsNullOrWhiteSpace(row.Owner) || string.IsNullOrWhiteSpace(row.Reason)) problems.Add("Exception has no owner or reason: " + row.Rule);
            if (row.Expires <= today || row.Expires > today.AddDays(180)) problems.Add("Exception must expire within 180 days: " + row.Rule + " " + row.Path);
        }

        Assert.Empty(problems);
    }

    private static List<(string Rule, string Path, string Owner, string Reason, DateOnly Expires)> ReadExceptions()
    {
        using var document = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, "eng/policy/harness-architecture-exceptions.json")));
        return document.RootElement.EnumerateArray().Select(row => (
            row.GetProperty("rule").GetString()!,
            row.GetProperty("path").GetString()!,
            row.GetProperty("owner").GetString()!,
            row.GetProperty("reason").GetString()!,
            DateOnly.ParseExact(row.GetProperty("expires").GetString()!, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture))).ToList();
    }

    /// <summary>The tracked inputs the rules read, plus the naming report of this checkout when the policy gate has written it.</summary>
    private static Dictionary<string, string> RealSources()
    {
        var sources = new Dictionary<string, string>(StringComparer.Ordinal);
        var listed = Git("ls-files").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var path in listed.Where(IsAuditedInput))
        {
            sources[path] = File.ReadAllText(Path.Combine(Root, path));
        }

        var report = Path.Combine(Root, HarnessArchitecture.NamingReport);
        if (File.Exists(report))
        {
            sources[HarnessArchitecture.NamingReport] = File.ReadAllText(report);
        }

        return sources;
    }

    private static bool IsAuditedInput(string path)
    {
        if (path.EndsWith(".csproj", StringComparison.Ordinal)) return true;
        if (path is "Directory.Build.props" or "Directory.Packages.props" or "package.json" or "wrangler.json" or "eng/policy/licence-boundary.json" or "eng/policy/naming-candidate.json") return true;
        if (path.StartsWith("src/", StringComparison.Ordinal) && path.EndsWith(".cs", StringComparison.Ordinal)) return true;
        return path.StartsWith("worker/", StringComparison.Ordinal) && path.EndsWith(".ts", StringComparison.Ordinal);
    }

    private static string Git(string arguments)
    {
        var start = new ProcessStartInfo("git") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        start.ArgumentList.Add("-C");
        start.ArgumentList.Add(Root);
        foreach (var argument in arguments.Split(' ')) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("git did not start");
        var output = process.StandardOutput.ReadToEnd();
        process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
        return output;
    }
}
