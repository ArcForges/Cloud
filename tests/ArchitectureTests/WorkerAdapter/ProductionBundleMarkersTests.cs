// SPDX-License-Identifier: AGPL-3.0-only
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests.WorkerAdapter;

/// <summary>
/// The both-ways fixtures of the production bundle's proof-only markers (worker-3): the bundle of the center's own account pages passes,
/// and a route string below /session/v1/ that the generated table does not list fails, whatever its second segment.
/// </summary>
public sealed class ProductionBundleMarkersTests
{
    private static readonly string Generated = CloudRepository.Read(CloudRepository.FindRoot(), "worker/tables/center-tables.generated.ts");

    private static IReadOnlySet<string> Pages => ProductionBundleMarkers.GeneratedPagePathsOf(Generated);

    /// <summary>A bundle of the generated routes and some code around them.</summary>
    private static string Bundle(params string[] extra) =>
        "var a = 1;\n" + string.Join("\n", Pages.Select(path => $"route(\"{path}\");")) + "\n" + string.Join("\n", extra) + "\nexport { CloudContainer };\n";

    [Fact]
    public void TheGeneratedTableListsTheSevenWebBrowserSessionRoutes()
    {
        Assert.Equal(7, Pages.Count);
        Assert.All(Pages, path => Assert.StartsWith("/session/v1/web/", path, StringComparison.Ordinal));
    }

    [Fact]
    public void ABundleOfExactlyTheGeneratedRoutesPasses() => Assert.Empty(ProductionBundleMarkers.Violations(Bundle(), Pages));

    [Theory]
    [InlineData("/session/v1/web/proof-only-route")]
    [InlineData("/session/v1/bootstrap")]
    [InlineData("/session/v1/logout")]
    [InlineData("/session/v1/web/")]
    [InlineData("/session/v1/web/bootstrap/extra")]
    [InlineData("/session/v1/")]
    public void ARouteBelowTheSessionPrefixThatTheTableDoesNotListFails(string route) =>
        Assert.Contains(ProductionBundleMarkers.Violations(Bundle($"fetch(\"{route}\");"), Pages), violation => violation.Contains(route, StringComparison.Ordinal));

    [Fact]
    public void AGeneratedRouteThatTheBundleLacksFails()
    {
        var bundle = Bundle().Replace(Pages.Order().First(), "/elsewhere", StringComparison.Ordinal);
        Assert.Contains(ProductionBundleMarkers.Violations(bundle, Pages), violation => violation.Contains("lacks the generated page route", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("FoundationContainer")]
    [InlineData("FOUNDATION_PROOF")]
    [InlineData("/proof/v1/probe")]
    [InlineData("/internal/foundation/v1/x")]
    public void AProofOnlyNameStillFails(string marker) =>
        Assert.Contains(ProductionBundleMarkers.Violations(Bundle($"use(\"{marker}\");"), Pages), violation => violation.Contains("proof-only marker", StringComparison.Ordinal));
}
