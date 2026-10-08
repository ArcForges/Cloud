// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>One finding of a GOV.10 successor rule: the rule, the repository-relative file and the detail.</summary>
internal sealed record HarnessFinding(string Rule, string File, string Detail);

/// <summary>A rule of the catalogue and the WP-05 obligation it serves.</summary>
internal sealed record HarnessRule(string Id, string Obligation, string Summary);

/// <summary>
/// The GOV.10 successor architecture rules for the C# Harness (HAR.40 validation (d)). The AI Node/TypeScript policy (completed
/// 2026-10-04) is re-expressed over Cloud's C# projects, manifests and Worker sources with the same rule names and obligations.
/// Every rule reads a map of repository-relative files, so the same code audits the real tree and the fixtures.
/// Recorded limits (carried over from GOV.10, with the reviewed tightening path in the harness-foundation document): C# rules
/// match syntax, not symbols, so aliasing and indirection are not seen; Worker rules read TypeScript text and see one module
/// specifier per import statement; and the audit reads the top-level project graph only.
/// </summary>
internal static partial class HarnessArchitecture
{
    /// <summary>The single host project: nothing in src references it.</summary>
    public const string Entry = "src/ArcForges.Cloud/ArcForges.Cloud.csproj";

    /// <summary>The naming gate report of this checkout (written by npm run policy); absent from git.</summary>
    public const string NamingReport = "artifacts/evidence/naming.json";

    /// <summary>The enumerated Apache-2.0 boundary projects of Cloud: none (Cloud is AGPL-3.0-only).</summary>
    public static readonly IReadOnlySet<string> ApacheBoundaryProjects = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>The licence expressions a shipped AGPL boundary may carry, from the AI policy allowance (LGPL is development-only).</summary>
    public static readonly IReadOnlySet<string> AllowedAgpl = new HashSet<string>(StringComparer.Ordinal)
    {
        "0BSD", "AGPL-3.0-only", "AGPL-3.0-or-later", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BlueOak-1.0.0", "CC-BY-4.0", "CC0-1.0",
        "ISC", "MIT", "MIT-0", "MPL-2.0", "Python-2.0", "Unlicense", "Zlib",
    };

    /// <summary>The licences an Apache-2.0 boundary may carry (AGPL terms are excluded).</summary>
    public static readonly IReadOnlySet<string> AllowedApache = new HashSet<string>(AllowedAgpl.Where(id => !id.StartsWith("AGPL", StringComparison.Ordinal)), StringComparer.Ordinal);

    public static readonly IReadOnlyList<HarnessRule> Rules =
    [
        new("layer-cycle", "WP-05.00", "The project graph and the Worker import graph are acyclic"),
        new("layer-entry", "WP-05.00", "No source project references the host entry"),
        new("layer-escape", "WP-05.00", "Project and Worker references stay inside the repository (no escape, absolute path or URL)"),
        new("layer-runtime-dependency", "WP-05.00", "Source projects use only centrally declared packages; Worker imports only declared runtime dependencies and Workers modules"),
        new("layer-product-reference", "WP-05.00", "Only the published Contracts packages are referenced from another owner; the build-only tooling never ships"),
        new("layer-business-authority", "WP-05.00", "Modules reference only their abstractions; Worker adapters hold no business store authority"),
        new("layer-public-exposure", "WP-05.00", "The Worker has no workers.dev or preview exposure"),
        new("licence-declaration", "WP-05.01", "Every project declares the boundary and the SPDX expression of the inventory"),
        new("licence-boundary-set", "WP-05.01", "The Apache-boundary set equals the enumerated list (empty for Cloud)"),
        new("licence-cross-boundary", "WP-05.01", "No Apache-boundary project references an AGPL project"),
        new("licence-allowlist", "WP-05.01", "Every declared project licence is allowed for its boundary; LGPL is development-only"),
        new("naming-identity", "WP-05.02", "The naming candidate is the exact NuGet identity, centrally pinned and locked"),
        new("naming-scan", "WP-05.02", "The naming scan of this checkout passed with zero findings under the pinned policy"),
        new("wire-package", "WP-05.03", "Contracts runtime packages share one exact version"),
        new("wire-import", "WP-05.03", "Generated types are imported only from the package; no source reaches into Contracts"),
        new("wire-source", "WP-05.03", "No copied generated source or schema file is authored in this repository"),
        new("wire-codec", "WP-05.03", "No handwritten or alternative wire codec"),
        new("wire-schema", "WP-05.03", "No handwritten message schema implements the generated message contract"),
        new("wire-shadow", "WP-05.03", "No local declaration redefines a generated wire namespace"),
        new("banned-reflection", "WP-05.04", "No reflection emit or dynamic loading on the Cloud path"),
        new("banned-dynamic-code", "WP-05.04", "No dynamic typing, script compilation or dynamic evaluation"),
        new("banned-blocking-wait", "WP-05.04", "No sync-over-async wait or synchronous host call"),
        new("banned-provider-sdk", "WP-05.04", "No provider SDK package or provider endpoint in source"),
        new("banned-provider-call", "WP-05.04", "The Workers AI binding is called only inside the ai.internal adapter"),
        new("banned-secret-logging", "WP-05.04", "No logging of secret-bearing or content-bearing values"),
        new("banned-float-money", "WP-05.04", "No floating-point type for money, credit or price values"),
        new("banned-raw-memory", "WP-05.04", "No unsafe or raw unmanaged memory"),
    ];

    /// <summary>Audits a map of repository-relative files; the result is ordered and free of duplicates.</summary>
    public static IReadOnlyList<HarnessFinding> Audit(IReadOnlyDictionary<string, string> sources)
    {
        ArgumentNullException.ThrowIfNull(sources);
        var context = new Context(sources);
        LayerRules(context);
        LicenceRules(context);
        NamingRules(context);
        WireRules(context);
        BannedRules(context);
        return context.Findings.Distinct().OrderBy(f => f.Rule, StringComparer.Ordinal).ThenBy(f => f.File, StringComparer.Ordinal).ThenBy(f => f.Detail, StringComparer.Ordinal).ToList();
    }

    /// <summary>The per-audit state: the files, the parsed projects and syntax trees, and the findings.</summary>
    internal sealed class Context
    {
        private readonly Dictionary<string, Project> projects = new(StringComparer.Ordinal);
        private readonly Dictionary<string, SyntaxTree> csharp = new(StringComparer.Ordinal);

        public Context(IReadOnlyDictionary<string, string> sources)
        {
            Sources = sources;
            foreach (var (path, text) in sources)
            {
                if (path.EndsWith(".csproj", StringComparison.Ordinal))
                {
                    projects[path] = Project.Parse(path, text, this);
                }
                else if (path.EndsWith(".cs", StringComparison.Ordinal) && (path.StartsWith("src/", StringComparison.Ordinal) || path.StartsWith("tests/", StringComparison.Ordinal)))
                {
                    csharp[path] = CSharpSyntaxTree.ParseText(text, path: path);
                }
            }
        }

        public IReadOnlyDictionary<string, string> Sources { get; }

        public List<HarnessFinding> Findings { get; } = [];

        public IReadOnlyDictionary<string, Project> Projects => projects;

        public IReadOnlyDictionary<string, SyntaxTree> CSharp => csharp;

        public void Report(string rule, string file, string detail) => Findings.Add(new HarnessFinding(rule, file, detail));

        public string? Text(string path) => Sources.TryGetValue(path, out var text) ? text : null;

        /// <summary>Source-project C# files (src/ only): the production path the banned and wire rules guard.</summary>
        public IEnumerable<KeyValuePair<string, SyntaxTree>> ProductionCSharp => csharp.Where(entry => entry.Key.StartsWith("src/", StringComparison.Ordinal));

        /// <summary>Worker TypeScript sources (worker/ only).</summary>
        public IEnumerable<KeyValuePair<string, string>> WorkerTypeScript =>
            Sources.Where(entry => entry.Key.StartsWith("worker/", StringComparison.Ordinal) && entry.Key.EndsWith(".ts", StringComparison.Ordinal));

        /// <summary>The package versions and the declared packages of Directory.Packages.props, when the file is in the audit.</summary>
        public IReadOnlyDictionary<string, string> CentralPackages()
        {
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            var props = Text("Directory.Packages.props");
            if (props is null) return result;
            foreach (var element in XDocument.Parse(props).Descendants("PackageVersion"))
            {
                var id = element.Attribute("Include")?.Value;
                if (id is not null) result[id] = element.Attribute("Version")?.Value ?? string.Empty;
            }

            return result;
        }

        /// <summary>The default PackageLicenseExpression of Directory.Build.props, or null when it does not declare one.</summary>
        public string? DefaultLicence() => Text("Directory.Build.props") is { } props ? ElementValue(props, "PackageLicenseExpression") : null;

        public static string? ElementValue(string xml, string name)
        {
            var element = XDocument.Parse(xml).Descendants().FirstOrDefault(e => e.Name.LocalName == name);
            return element?.Value.Trim();
        }
    }

    /// <summary>A parsed project file: its references, its packages, its compile includes and its declared licence.</summary>
    internal sealed record Project(
        string Path,
        IReadOnlyList<(string Raw, string? Resolved)> ProjectReferences,
        IReadOnlyList<(string Id, string? Version, bool PrivateAssets)> PackageReferences,
        IReadOnlyList<string> CompileIncludes,
        string? Boundary,
        string? Licence)
    {
        public static Project Parse(string path, string xml, Context context)
        {
            var document = XDocument.Parse(xml);
            string Attribute(XElement element, string name) => element.Attribute(name)?.Value ?? string.Empty;
            var references = document.Descendants("ProjectReference")
                .Select(element => Attribute(element, "Include").Replace('\\', '/'))
                .Select(raw => (Raw: raw, Resolved: Normalize(path, raw)))
                .ToList();
            var packages = document.Descendants("PackageReference")
                .Select(element => (Id: Attribute(element, "Include"), Version: element.Attribute("Version")?.Value, PrivateAssets: Attribute(element, "PrivateAssets") == "all"))
                .ToList();
            var compiles = document.Descendants().Where(e => e.Name.LocalName == "Compile" && e.Attribute("Include") is not null)
                .Select(e => e.Attribute("Include")!.Value.Replace('\\', '/'))
                .ToList();
            var boundary = document.Descendants().FirstOrDefault(e => e.Name.LocalName == "LicenceBoundary")?.Value.Trim();
            var licence = document.Descendants().FirstOrDefault(e => e.Name.LocalName == "PackageLicenseExpression")?.Value.Trim() ?? context.DefaultLicence();
            return new Project(path, references, packages, compiles, boundary, licence);
        }

        /// <summary>The repository-relative target of a project-relative path, or null when it leaves the repository root.</summary>
        public static string? Normalize(string fromFile, string include)
        {
            if (include.StartsWith("/", StringComparison.Ordinal) || Regex.IsMatch(include, "^[A-Za-z]:|^[a-z][a-z0-9+.-]*://", RegexOptions.IgnoreCase))
            {
                return null;
            }

            var directory = fromFile.Contains('/', StringComparison.Ordinal) ? fromFile[..fromFile.LastIndexOf('/')] : string.Empty;
            var segments = new List<string>(directory.Split('/', StringSplitOptions.RemoveEmptyEntries));
            foreach (var part in include.Split('/', StringSplitOptions.RemoveEmptyEntries))
            {
                if (part == ".") continue;
                if (part == "..")
                {
                    if (segments.Count == 0) return null;
                    segments.RemoveAt(segments.Count - 1);
                }
                else
                {
                    segments.Add(part);
                }
            }

            return string.Join('/', segments);
        }
    }
}
