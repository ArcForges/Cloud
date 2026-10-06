// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Build.Policy.Architecture;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

public sealed class PolicyBoundaryTests
{
    [Theory]
    [InlineData("Entitlement", "BD-01")]
    [InlineData("Settings", "BD-02")]
    [InlineData("Readiness", "BD-03")]
    [InlineData("Ingress", "BD-04")]
    public void HeaderOnlyDependenciesCannotHideInRecordParametersOrInheritance(string area, string rule)
    {
        string target = area is "Readiness" or "Ingress" ? "ArcForges.Cloud." + area : "ArcForges.Cloud.Modules." + area;
        foreach (string declaration in new[]
        {
            "public record Restriction(Alias? Value);",
            "public class Restriction : Alias;",
            "public class Outer { public record Restriction(System.Collections.Generic.List<Alias?[]> Values); }",
            "public delegate Alias Restriction(Alias input);",
        })
        {
            string source = $$"""
                using Alias = {{target}}.Decision;
                namespace {{target}} { public class Decision; }
                namespace ArcForges.Cloud.Modules.Policy.Domain { {{declaration}} }
                """;
            var findings = PolicyBoundaryGuard.Check(FixtureCompiler.Create("Boundary", new Dictionary<string, string> { ["boundary.cs"] = source }));
            Assert.NotEmpty(findings);
            Assert.All(findings, finding => Assert.StartsWith(rule, finding, StringComparison.Ordinal));
        }
    }

    [Theory]
    [InlineData("Entitlement", "BD-01")]
    [InlineData("Settings", "BD-02")]
    [InlineData("Readiness", "BD-03")]
    [InlineData("Ingress", "BD-04")]
    public void EachFoundingBoundaryRejectsAnAliasedGenericSignatureAndExecutableReference(string area, string rule)
    {
        string target = area is "Readiness" or "Ingress" ? "ArcForges.Cloud." + area : "ArcForges.Cloud.Modules." + area;
        string source = $$"""
            using Alias = {{target}}.Decision;
            namespace {{target}} { public class Decision { public static int Evaluate() => 1; } }
            namespace ArcForges.Cloud.Modules.Policy.Domain
            {
                public class Restriction : System.Collections.Generic.List<Alias>
                {
                    public Alias[] Values { get; } = [];
                    public int Evaluate() => Alias.Evaluate();
                }
            }
            """;
        var findings = PolicyBoundaryGuard.Check(FixtureCompiler.Create("Boundary", new Dictionary<string, string> { ["boundary.cs"] = source }));
        Assert.NotEmpty(findings);
        Assert.All(findings, finding => Assert.StartsWith(rule, finding, StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("Entitlement", "BD-01")]
    [InlineData("Settings", "BD-02")]
    [InlineData("Readiness", "BD-03")]
    [InlineData("Ingress", "BD-04")]
    public void TheDecisionOwnerCannotUseAPolicyTypeAsItsOwnAuthority(string area, string rule)
    {
        string target = area is "Readiness" or "Ingress" ? "ArcForges.Cloud." + area : "ArcForges.Cloud.Modules." + area;
        string source = $$"""
            namespace ArcForges.Cloud.Modules.Policy { public sealed class Restriction; }
            namespace {{target}} { public sealed class Decision { public ArcForges.Cloud.Modules.Policy.Restriction Value { get; } = new(); } }
            """;
        var findings = PolicyBoundaryGuard.Check(FixtureCompiler.Create("Boundary", new Dictionary<string, string> { ["boundary.cs"] = source }));
        Assert.NotEmpty(findings);
        Assert.All(findings, finding => Assert.StartsWith(rule, finding, StringComparison.Ordinal));
    }

    [Fact]
    public void TheExistingRootHealthProjectionCannotBecomeAPolicyDecision()
    {
        foreach (string source in new[]
        {
            """
            namespace ArcForges.Cloud { public record HealthStatus(bool Ready); }
            namespace ArcForges.Cloud.Modules.Policy { public record Flag(ArcForges.Cloud.HealthStatus RuntimeHealth); }
            """,
            """
            namespace ArcForges.Cloud.Modules.Policy { public class Restriction; }
            namespace ArcForges.Cloud { public record HealthStatus(ArcForges.Cloud.Modules.Policy.Restriction Policy); }
            """,
        })
        {
            var findings = PolicyBoundaryGuard.Check(FixtureCompiler.Create("Boundary", new Dictionary<string, string> { ["boundary.cs"] = source }));
            Assert.NotEmpty(findings);
            Assert.All(findings, finding => Assert.StartsWith("BD-03", finding, StringComparison.Ordinal));
        }
    }

    [Fact]
    public void TheHistoricalRootNamespaceGrantPortCannotBypassCommercialSeparation()
    {
        const string source = """
            namespace ArcForges.Cloud.Modules { public interface IEntitlementGrantPort { int Issue(); } }
            namespace ArcForges.Cloud.Modules.Policy { public class Flag { public int Apply(ArcForges.Cloud.Modules.IEntitlementGrantPort port) => port.Issue(); } }
            """;
        var findings = PolicyBoundaryGuard.Check(FixtureCompiler.Create("Boundary", new Dictionary<string, string> { ["boundary.cs"] = source }));
        Assert.NotEmpty(findings);
        Assert.All(findings, finding => Assert.StartsWith("BD-01", finding, StringComparison.Ordinal));
    }

    [Fact]
    public void HostCompositionCanKeepTheIndependentDecisionsAndNeutralPrimitivePortsSeparate()
    {
        const string source = """
            namespace ArcForges.Cloud.Modules { public interface IStatePort { string Read(); } }
            namespace ArcForges.Cloud.Modules.Policy { public sealed class Restriction { public string Read(ArcForges.Cloud.Modules.IStatePort port) => port.Read(); } }
            namespace ArcForges.Cloud.Modules.Entitlement { public sealed class Decision; }
            namespace ArcForges.Cloud.Composition { public sealed record Decisions(ArcForges.Cloud.Modules.Policy.Restriction Restriction, ArcForges.Cloud.Modules.Entitlement.Decision Entitlement); }
            """;
        Assert.Empty(PolicyBoundaryGuard.Check(FixtureCompiler.Create("Boundary", new Dictionary<string, string> { ["boundary.cs"] = source })));
    }
}
