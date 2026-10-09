// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using ArcForges.Build.Policy.Architecture;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>Cloud's own repository inventory: solution membership, licence boundary and the reviewed exception list.</summary>
internal static class RepositoryInventoryPolicy
{
    /// <summary>The solution, the repository's project files and the reviewed role inventory describe exactly the same projects.</summary>
    public static IReadOnlyList<string> CheckProjects(string solutionXml, IEnumerable<string> projectFiles, IEnumerable<ProjectClassification> classifications)
    {
        var problems = new List<string>();
        string[] solution = [.. XDocument.Parse(solutionXml).Descendants("Project").Select(project => project.Attribute("Path")?.Value ?? string.Empty).Order(StringComparer.Ordinal)];
        string[] files = [.. projectFiles.Order(StringComparer.Ordinal)];
        string[] roles = [.. classifications.Select(project => project.Path).Order(StringComparer.Ordinal)];
        if (roles.Distinct(StringComparer.Ordinal).Count() != roles.Length)
        {
            problems.Add("A project has more than one role classification.");
        }

        Compare("solution", solution, "project files", files, problems);
        Compare("role inventory", roles, "project files", files, problems);
        return problems;
    }

    /// <summary>Every managed project is AGPL-3.0-only / AGPL and listed in the licence-boundary inventory.</summary>
    public static IReadOnlyList<string> CheckLicences(string inventoryJson, IReadOnlyDictionary<string, string> projects, string commonProps)
    {
        var problems = new List<string>();
        using var inventory = JsonDocument.Parse(inventoryJson);
        var root = inventory.RootElement;
        if (root.GetProperty("repository").GetString() != CloudRepository.Owner
            || root.GetProperty("spdxLicense").GetString() != "AGPL-3.0-only" || root.GetProperty("licenceBoundary").GetString() != "AGPL")
        {
            problems.Add("The licence-boundary inventory is not the Cloud AGPL-3.0-only inventory.");
        }

        string[] listed = [.. root.GetProperty("projects").EnumerateArray()
            .Where(row => row.GetProperty("kind").GetString() == "msbuild").Select(row => row.GetProperty("path").GetString()!).Order(StringComparer.Ordinal)];
        Compare("licence inventory", listed, "project files", [.. projects.Keys.Order(StringComparer.Ordinal)], problems);
        var common = XDocument.Parse(commonProps);
        foreach (var (path, xml) in projects)
        {
            var documents = new[] { common, XDocument.Parse(xml) };
            string? Value(string name) => documents.SelectMany(document => document.Descendants()).Where(element => element.Name.LocalName == name)
                .Select(element => element.Value.Trim()).LastOrDefault();
            if (Value("PackageLicenseExpression") != "AGPL-3.0-only" || Value("LicenceBoundary") != "AGPL")
            {
                problems.Add($"{path} does not declare AGPL-3.0-only / AGPL.");
            }
        }

        return problems;
    }

    /// <summary>
    /// The exception inventory is exact, owned and short-lived. AGPL needs no RP-02/RP-03 row, and a banned-API finding is reported at
    /// project granularity, so waiving an AOT-path ban would hide every occurrence in the project: neither can be waived.
    /// </summary>
    public static IReadOnlyList<string> CheckExceptions(IEnumerable<PolicyException> rows, IEnumerable<ProjectClassification> projects, DateOnly today)
    {
        var problems = new List<string>();
        var known = projects.ToDictionary(project => project.Path, StringComparer.Ordinal);
        foreach (var row in rows)
        {
            if (!PolicyEngine.Rules.Contains(row.Rule) && !row.Rule.StartsWith("BAN-", StringComparison.Ordinal))
            {
                problems.Add($"Unknown rule in exception: {row.Rule}.");
            }

            if (row.Owner != CloudRepository.Owner || string.IsNullOrWhiteSpace(row.Reason) || row.Path.Contains('*', StringComparison.Ordinal))
            {
                problems.Add($"Exception {row.Rule} {row.Path} is not exact and owned.");
            }

            if (!known.TryGetValue(row.Path, out var project))
            {
                problems.Add($"Exception path is not a Cloud project: {row.Path}.");
            }

            if (row.Expires <= today || row.Expires > today.AddYears(1))
            {
                problems.Add($"Exception {row.Rule} {row.Path} must expire within one year.");
            }

            if (row.Rule is "RP-02" or "RP-03")
            {
                problems.Add("Cloud is AGPL-3.0-only: the licence-boundary rules cannot be waived.");
            }

            if (row.Rule is "BAN-REFLECTION" or "BAN-CODEGEN" or "RP-07" && project is { Aot: true })
            {
                problems.Add("The Native AOT service cannot waive reflection, code generation or trim/AOT diagnostics.");
            }
        }

        return problems;
    }

    private static void Compare(string leftName, string[] left, string rightName, string[] right, List<string> problems)
    {
        foreach (string missing in left.Except(right, StringComparer.Ordinal))
        {
            problems.Add($"{missing} is in the {leftName} but not in the {rightName}.");
        }

        foreach (string missing in right.Except(left, StringComparer.Ordinal))
        {
            problems.Add($"{missing} is in the {rightName} but not in the {leftName}.");
        }
    }
}

/// <summary>The forbidden-term scan wiring (WP-05.02): the exact NuGet scanner identity, the check gate and the hosted evidence order.</summary>
internal static class NamingWiring
{
    /// <param name="packageJson">The workspace manifest; its policy script and check gate run the scan.</param>
    /// <param name="projectScript">The Node naming gate that verifies the restored package and runs the scanner.</param>
    /// <param name="candidateJson">eng/policy/naming-candidate.json: the NuGet identity, archive digest and asset digests.</param>
    /// <param name="lockJson">The architecture host's NuGet lock: the candidate is a direct, locked reference at the exact version.</param>
    /// <param name="packagesProps">Directory.Packages.props: the central version of the candidate.</param>
    /// <param name="architectureProject">The architecture host project: a build-only package reference to the candidate.</param>
    public static IReadOnlyList<string> Check(string packageJson, string projectScript, string candidateJson, string lockJson, string packagesProps, string architectureProject)
    {
        var problems = new List<string>();
        using var package = JsonDocument.Parse(packageJson);
        using var candidate = JsonDocument.Parse(candidateJson);
        using var lockfile = JsonDocument.Parse(lockJson);
        var scripts = package.RootElement.GetProperty("scripts");
        if (!scripts.TryGetProperty("policy", out var policy) || policy.GetString() != "node tooling/project.ts naming")
        {
            problems.Add("package.json has no policy script running the forbidden-term scan.");
        }

        if (!scripts.TryGetProperty("check", out var check) || !Regex.IsMatch(check.GetString() ?? string.Empty, @"(?:^|&& )npm run policy(?: &&|$)"))
        {
            problems.Add("The check gate does not run the policy script.");
        }

        foreach (string expected in new[] { "check_naming.py", "--repository", "Cloud=", "artifacts/evidence/naming.json", "naming-candidate.json", "-I", "NUGET_PACKAGES", "archiveSha512", "nupkg" })
        {
            if (!projectScript.Contains(expected, StringComparison.Ordinal))
            {
                problems.Add($"tooling/project.ts does not wire the scan input {expected}.");
            }
        }

        var root = candidate.RootElement;
        string version = root.GetProperty("version").GetString() ?? string.Empty;
        if (root.GetProperty("package").GetString() != "ArcForges.Contracts.Validation" || root.GetProperty("ecosystem").GetString() != "nuget"
            || !Regex.IsMatch(version, @"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
            || !Regex.IsMatch(root.GetProperty("sourceCommit").GetString() ?? string.Empty, "^[0-9a-f]{40}$")
            || !Regex.IsMatch(root.GetProperty("archiveSha512").GetString() ?? string.Empty, "^[A-Za-z0-9+/]{86}==$"))
        {
            problems.Add("The naming candidate does not identify the exact NuGet ArcForges.Contracts.Validation archive.");
        }

        var assets = root.GetProperty("assets").EnumerateObject().ToArray();
        if (assets.Length == 0 || assets.Any(asset => !Regex.IsMatch(asset.Value.GetString() ?? string.Empty, "^[0-9a-f]{64}$")))
        {
            problems.Add("The naming candidate asset digests are missing or malformed.");
        }

        if (!Regex.IsMatch(packagesProps, $@"<PackageVersion Include=""ArcForges\.Contracts\.Validation"" Version=""{Regex.Escape(version)}"" />"))
        {
            problems.Add("Directory.Packages.props does not centrally pin the naming candidate at its exact version.");
        }

        if (!architectureProject.Contains("<PackageReference Include=\"ArcForges.Contracts.Validation\"", StringComparison.Ordinal) || !architectureProject.Contains("PrivateAssets=\"all\"", StringComparison.Ordinal))
        {
            problems.Add("The architecture host does not reference the naming candidate as a build-only package.");
        }

        var locked = lockfile.RootElement.GetProperty("dependencies");
        bool lockedVersion = locked.TryGetProperty("net10.0", out var framework)
            && framework.TryGetProperty("ArcForges.Contracts.Validation", out var entry)
            && entry.TryGetProperty("type", out var type) && type.GetString() == "Direct"
            && entry.TryGetProperty("resolved", out var resolved) && resolved.GetString() == version;
        if (!lockedVersion)
        {
            problems.Add("The architecture host lock does not hold the naming candidate as a direct package at its exact version.");
        }

        return problems;
    }
}

/// <summary>
/// The hosted gate order that gives RP-09 its meaning: the existing pinned Gitleaks step must have succeeded before the locked
/// build, the canonical naming scan and the architecture host run in the same job, and the aggregate check must require that job.
/// </summary>
internal static class CiWiring
{
    private const string GitleaksPin = "zricethezav/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f";
    private const string DotnetPin = "actions/setup-dotnet@a98b56852c35b8e3190ac28c8c2271da59106c68";

    public static IReadOnlyList<string> Check(string workflow, string packageJson)
    {
        var problems = new List<string>();
        string quality = Job(workflow, "quality");
        string source = Job(workflow, "source");
        string verify = Job(workflow, "verify");
        string[] ordered =
        [
            "name: Scan Git history for secrets",
            GitleaksPin,
            DotnetPin,
            "dotnet restore Cloud.slnx --locked-mode",
            "dotnet build Cloud.slnx -c Release --no-restore",
            "npm run policy",
            "dotnet test --project tests/ArchitectureTests -c Release --no-build --filter-class ArcForges.Cloud.ArchitectureTests.EvaluatedRepositoryGate",
        ];
        int previous = -1;
        foreach (string step in ordered)
        {
            int current = quality.IndexOf(step, StringComparison.Ordinal);
            if (current <= previous)
            {
                problems.Add($"The quality job must run '{step}' after the preceding hosted gate step.");
            }

            previous = Math.Max(previous, current);
        }

        if (!quality.Contains("ARCFORGES_ARCHITECTURE_GATE: hosted", StringComparison.Ordinal))
        {
            problems.Add("The quality job does not declare the hosted architecture gate mode.");
        }

        int scan = quality.IndexOf("name: Scan Git history for secrets", StringComparison.Ordinal);
        string afterScan = scan < 0 ? string.Empty : quality[scan..];
        if (!afterScan.Contains("--redact=100", StringComparison.Ordinal) || !afterScan.Contains("--no-banner", StringComparison.Ordinal))
        {
            problems.Add("The existing redacted Gitleaks command changed or was removed.");
        }

        if (afterScan.Contains("continue-on-error: true", StringComparison.Ordinal) || Regex.IsMatch(afterScan, @"if:.*(?:always|failure|cancelled)\(\)"))
        {
            problems.Add("A step after Gitleaks can run when the secret scan failed.");
        }

        if (!Regex.IsMatch(quality, @"timeout-minutes: (?:2\d|[3-9]\d)\b"))
        {
            problems.Add("The quality job needs a timeout of at least 20 minutes for the locked build and architecture gate.");
        }

        if (!source.Contains("npm run check\n", StringComparison.Ordinal) || !source.Contains("npm run check:dotnet\n", StringComparison.Ordinal))
        {
            problems.Add("The source job no longer runs the check gate and the solution tests.");
        }

        if (!verify.Contains("test \"$QUALITY\" = success", StringComparison.Ordinal))
        {
            problems.Add("The aggregate verify job no longer requires the quality job.");
        }

        using var manifest = JsonDocument.Parse(packageJson);
        string solutionTests = manifest.RootElement.GetProperty("scripts").GetProperty("check:dotnet").GetString() ?? string.Empty;
        if (!solutionTests.Contains("dotnet test --solution Cloud.slnx", StringComparison.Ordinal))
        {
            problems.Add("check:dotnet no longer runs every solution test project.");
        }

        return problems;
    }

    private static string Job(string workflow, string name)
    {
        var match = Regex.Match(workflow, @"(?ms)^  " + Regex.Escape(name) + @":\r?\n(?<body>.*?)(?=^  [A-Za-z][A-Za-z0-9-]*:\r?$|\z)");
        return match.Success ? match.Groups["body"].Value.Replace("\r\n", "\n", StringComparison.Ordinal) : string.Empty;
    }
}
