// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Build.Policy.Architecture;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>
/// The shared AT-01..AT-14 / RP-01..RP-10 rule table applied with Cloud's owner, roles and Native AOT posture. Every rule
/// has a valid fixture that must pass and a violating fixture that must report exactly that rule.
/// </summary>
public sealed class SharedPolicyTests
{
    public static TheoryData<string> Rules => [.. PolicyEngine.Rules];

    [Theory]
    [MemberData(nameof(Rules))]
    public void EveryRuleAcceptsItsValidFixtureAndRejectsItsViolation(string rule)
    {
        using var valid = PolicyCase.Create(rule, violation: false);
        Assert.Empty(valid.Check());
        using var invalid = PolicyCase.Create(rule, violation: true);
        Assert.Contains(invalid.Check(), finding => finding.Rule == rule);
    }

    [Fact]
    public void RuleManifestHasExactlyTheAuthoritativeTwentyFourRules()
    {
        Assert.Equal(24, PolicyEngine.Rules.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(
            Enumerable.Range(1, 14).Select(value => $"AT-{value:00}").Concat(Enumerable.Range(1, 10).Select(value => $"RP-{value:00}")),
            PolicyEngine.Rules);
    }

    [Fact]
    public void BannedApiCatalogHasTheSevenCanonicalCategories()
    {
        Assert.Equal(
            ["BAN-REFLECTION", "BAN-CODEGEN", "BAN-BLOCKING", "BAN-PROVIDER", "BAN-LOGGING", "BAN-MONEY", "BAN-POINTER"],
            BannedSymbolScanner.CategoryCatalog.Select(category => category.Id));
        Assert.All(BannedSymbolScanner.CategoryCatalog, category =>
        {
            Assert.False(string.IsNullOrWhiteSpace(category.Name));
            Assert.False(string.IsNullOrWhiteSpace(category.Description));
        });
    }

    [Fact]
    public void GraphRejectsMissingOwnersAndReferenceCycles()
    {
        using var fixture = PolicyCase.Create("AT-01", violation: false);
        var first = fixture.Projects[0];
        Assert.Throws<InvalidOperationException>(() => new ProjectGraph([first with { ProjectReferences = ["missing.csproj"] }]));
        Assert.Throws<InvalidOperationException>(() => new ProjectGraph([first with { ProjectReferences = [first.Classification.Path] }]));
    }

    [Fact]
    public void ExceptionsAreExactOwnedExpiringAndCannotCoverAnotherPath()
    {
        using var fixture = PolicyCase.Create("RP-02", violation: true);
        var exception = new PolicyException("RP-02", fixture.Projects[^1].Classification.Path, CloudRepository.Owner, "Bounded migration", new DateOnly(2030, 1, 1));
        fixture.Exceptions.Add(exception);
        Assert.Empty(fixture.Check());
        fixture.Exceptions[0] = exception with { Path = "other.csproj" };
        Assert.Contains(fixture.Check(), finding => finding.Rule == "RP-02");
        foreach (var invalid in new[]
        {
            exception with { Path = "*" },
            exception with { Owner = "Other" },
            exception with { Expires = new DateOnly(2020, 1, 1) },
            exception with { Reason = " " },
            exception with { Rule = "AT-99" },
        })
        {
            fixture.Exceptions[0] = invalid;
            Assert.Throws<InvalidOperationException>(() => fixture.Check());
        }
    }

    [Theory]
    [InlineData("RP-01")]
    [InlineData("RP-08")]
    [InlineData("RP-09")]
    public void ExternalGateEvidenceMustMatchTheExactSourceAndNotJustSayPassed(string rule)
    {
        using var fixture = PolicyCase.Create(rule, violation: false);
        int index = fixture.Evidence.FindIndex(evidence => evidence.Rule == rule);
        var evidence = fixture.Evidence[index];
        Assert.Empty(fixture.Check());
        fixture.Evidence[index] = evidence with { SourceCommit = new string('b', 40) };
        Assert.Contains(fixture.Check(), finding => finding.Rule == rule);
        fixture.Evidence[index] = evidence with { Findings = [new PolicyFinding(rule, "source.cs", "canonical finding")] };
        Assert.Contains(fixture.Check(), finding => finding.Rule == rule);
        fixture.Evidence.RemoveAt(index);
        Assert.Contains(fixture.Check(), finding => finding.Rule == rule);
    }

    [Theory]
    [InlineData("Microsoft.Data.Sqlite", "Persistence")]
    [InlineData("Microsoft.EntityFrameworkCore", "Infrastructure")]
    [InlineData("Avalonia", "UserInterface")]
    [InlineData("Grpc.Net.Client", "PublicApiAdapter")]
    public void LayersRejectResolvedPackageEdgesWithoutProjectReferences(string package, string dependencyRole)
    {
        foreach (var layer in new[] { ProjectRole.Domain, ProjectRole.Application })
        {
            using var fixture = PolicyCase.Create("AT-01", violation: false);
            fixture.SetDomainLayer(layer);
            fixture.AddDomainPackage(package, Enum.Parse<ProjectRole>(dependencyRole));
            Assert.Contains(fixture.Check(), finding => finding.Rule == "AT-01");
            fixture.AddDomainPackage("Pure.Foundation.Fixture", ProjectRole.Foundation);
            Assert.DoesNotContain(fixture.Check(), finding => finding.Rule == "AT-01");
            fixture.DependencyRoles.Clear();
            Assert.Contains(fixture.Check(), finding => finding.Rule == "AT-01");
        }
    }

    [Theory]
    [InlineData("public delegate System.IntPtr Callback();", true)]
    [InlineData("public delegate void Callback(System.Runtime.InteropServices.SafeHandle value);", true)]
    [InlineData("public delegate string Callback(int value);", false)]
    [InlineData("public delegate Callback Callback();", false)]
    public void NativeCallbackSignaturesCannotCrossAPublicBoundary(string declaration, bool rejected)
    {
        using var fixture = PolicyCase.Create("AT-06", violation: false);
        fixture.AddCallback(declaration);
        Assert.Equal(rejected, fixture.Check().Any(finding => finding.Rule == "AT-06"));
    }

    [Fact]
    public void SameNamedTestTypeCannotHideProductionApi()
    {
        using var fixture = PolicyCase.Create("RP-10", violation: false);
        fixture.AddCollidingApi();
        Assert.Contains(fixture.Check(), finding => finding.Rule == "AT-06" && finding.Path == "collision/collision.csproj");
    }

    [Fact]
    public void ProductionCannotReachTestOnlyNativeTarget()
    {
        using var fixture = PolicyCase.Create("AT-09", violation: false);
        var native = fixture.Projects.Single(project => project.Classification.Role == ProjectRole.NativeWorker);
        fixture.Projects[0] = fixture.Projects[0] with
        {
            Classification = fixture.Projects[0].Classification with { Production = true },
            ProjectReferences = [native.Classification.Path],
        };
        Assert.Contains(fixture.Check(), finding => finding.Rule == "AT-09");
    }

    [Fact]
    public void TraitOnlyMethodsAndNonTestProjectsCannotSatisfyPublicApiContracts()
    {
        using var fixture = PolicyCase.Create("RP-10", violation: false);
        fixture.ReplaceTestAttribute("Xunit.Trait(\"category\", \"contract\")");
        Assert.Contains(fixture.Check(), finding => finding.Rule == "RP-10");
        fixture.ReplaceTestAttribute("Xunit.Fact");
        Assert.Empty(fixture.Check());
        fixture.Projects[0] = fixture.Projects[0] with
        {
            Classification = fixture.Projects[0].Classification with { Role = ProjectRole.BuildTool },
        };
        Assert.Contains(fixture.Check(), finding => finding.Rule == "RP-10");
    }

    [Theory]
    [InlineData("C:\\r\\src\\ArcForges.Cloud\\obj\\arcforges-policy\\Release\\generated\\System.Text.Json.SourceGeneration\\System.Text.Json.SourceGeneration.JsonSourceGenerator\\Ctx.g.cs", true)]
    [InlineData("/r/src/ArcForges.Cloud/obj/arcforges-policy/Release/generated/Microsoft.AspNetCore.Http.RequestDelegateGenerator/X/Routes.g.cs", true)]
    [InlineData("/r/src/ArcForges.Cloud/obj/arcforges-policy/Release/generated/Third.Party.Generator/X/Evil.g.cs", false)]
    [InlineData("/r/src/ArcForges.Cloud/obj/Release/net10.0/generated/System.Text.Json.SourceGeneration/X/Stale.g.cs", false)]
    [InlineData("/r/src/ArcForges.Cloud/Foundation/Authored.cs", false)]
    [InlineData("/r/src/ArcForges.Cloud/System.Text.Json.SourceGeneration/Authored.cs", false)]
    public void OnlyFirstPartyGeneratorOutputOfTheEvaluationIsExemptFromSourceScanning(string path, bool exempt)
    {
        Assert.Equal(exempt, CloudRepository.IsOfficialGeneratorOutput(path));
    }
    [Fact]
    public void TheCloudCompilationReaderStaysFailClosed()
    {
        string file = Path.GetTempFileName();
        try
        {
            var project = new ProjectFacts(new("subject.csproj", ProjectRole.Foundation, CloudRepository.Owner),
                "net10.0", "Library", "AGPL-3.0-only", "AGPL", [], [file], [typeof(object).Assembly.Location],
                new Dictionary<string, string> { ["AssemblyName"] = "Subject" }, new Dictionary<string, string>());
            File.WriteAllText(file, "public class Api { public string Value => string.Empty; }");
            Assert.NotNull(CloudRepository.ReadCompilation(project));
            File.WriteAllText(file, "public class Api { public MissingType Value => null; }");
            Assert.Throws<InvalidOperationException>(() => CloudRepository.ReadCompilation(project));
            Assert.Throws<InvalidOperationException>(() => CloudRepository.ReadCompilation(project with { OutputType = "WinExe" }));
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Fact]
    public void UnresolvedPublicTypesCannotPassSemanticProjectEvaluation()
    {
        string file = Path.GetTempFileName();
        try
        {
            var project = new ProjectFacts(new("subject.csproj", ProjectRole.Foundation, CloudRepository.Owner),
                "net10.0", "Library", "AGPL-3.0-only", "AGPL", [], [file], [typeof(object).Assembly.Location],
                new Dictionary<string, string> { ["AssemblyName"] = "Subject" }, new Dictionary<string, string>());
            File.WriteAllText(file, "public class Api { public string Value => string.Empty; }");
            _ = ProjectGraph.ReadCompilation(project);
            File.WriteAllText(file, "public class Api { public MissingType Value => null; }");
            Assert.Throws<InvalidOperationException>(() => ProjectGraph.ReadCompilation(project));
        }
        finally
        {
            File.Delete(file);
        }
    }
}
