// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.ArchitectureTests.WorkerAdapter;

/// <summary>
/// What the production bundle may not contain (CLOUD.84 D1 and S39): names that only the proof entry, its foundation, its harness alarm or
/// its verification may hold, and every route string below <c>/session/v1/</c> that is not one of the center's own WebBrowserSession routes
/// (AF-CTR-03 A2: generated into <c>worker/tables/center-tables.generated.ts</c>, dark in production because the pages surface is off).
/// The proof pipeline's <c>/session/v1/bootstrap</c> and <c>/session/v1/logout</c> are such paths, and so is any other path below
/// <c>/session/v1/web/</c> that the generated table does not list.
/// </summary>
internal static class ProductionBundleMarkers
{
    /// <summary>Names that only the proof entry, its foundation, its harness alarm or its verification may contain.</summary>
    public static readonly string[] ProofOnlyMarkers =
    [
        "FoundationContainer",
        "FoundationJobCoordinator",
        "HarnessRunAlarm",
        "storage.internal",
        "objects.internal",
        "harness.internal",
        "/proof/v1/",
        "/internal/foundation/v1/",
        "arcforges.proof.v1",
        "PipelineProbe",
        "FOUNDATION_PROOF",
        "PROOF_OPERATOR",
        "cloud.readiness.v1",
        "proofRouteTable",
        "eng/verification",
        "WAKE_QUEUE",
        "JOB_COORDINATOR",
    ];

    /// <summary>The prefix whose strings in the bundle must be exactly the generated WebBrowserSession routes.</summary>
    public const string SessionPrefix = "/session/v1/";

    private static readonly Regex SessionStrings = new(@"/session/v1/[A-Za-z0-9_/-]*", RegexOptions.CultureInvariant);

    private static readonly Regex GeneratedPagePaths = new("path:\\s*\"(?<path>/session/v1/[^\"]+)\"", RegexOptions.CultureInvariant);

    /// <summary>The WebBrowserSession route paths of the generated Worker table (the rows whose path lies below the session prefix).</summary>
    public static IReadOnlySet<string> GeneratedPagePathsOf(string generatedTable) =>
        GeneratedPagePaths.Matches(generatedTable).Select(match => match.Groups["path"].Value).ToHashSet(StringComparer.Ordinal);

    /// <summary>
    /// The violations of a production bundle: each proof-only marker it holds, each string below the session prefix that is not a generated
    /// page route, and each generated page route it lacks (the set of those strings is exactly the generated list).
    /// </summary>
    public static IReadOnlyList<string> Violations(string bundle, IReadOnlySet<string> pagePaths)
    {
        var violations = new List<string>();
        foreach (var marker in ProofOnlyMarkers)
            if (bundle.Contains(marker, StringComparison.Ordinal)) violations.Add($"The production bundle contains a proof-only marker: {marker}");
        var found = SessionStrings.Matches(bundle).Select(match => match.Value).ToHashSet(StringComparer.Ordinal);
        foreach (var path in found.Where(path => !pagePaths.Contains(path)).Order(StringComparer.Ordinal))
            violations.Add($"The production bundle contains a proof-only marker: {path} (a path below {SessionPrefix} that the generated table does not list)");
        foreach (var path in pagePaths.Where(path => !found.Contains(path)).Order(StringComparer.Ordinal))
            violations.Add($"The production bundle lacks the generated page route {path}");
        return violations;
    }
}
