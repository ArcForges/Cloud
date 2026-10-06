// SPDX-License-Identifier: AGPL-3.0-only
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

public sealed class PolicyBoundaryTests
{
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
