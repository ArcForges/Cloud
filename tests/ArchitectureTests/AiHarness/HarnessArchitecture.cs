// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>One finding of a GOV.10 successor rule: the rule, the repository-relative file and the detail.</summary>
internal sealed record HarnessFinding(string Rule, string File, string Detail);

/// <summary>A rule of the catalogue and the WP-05 obligation it serves.</summary>
internal sealed record HarnessRule(string Id, string Obligation, string Summary);

/// <summary>Options of one audit. The generated TypeScript names are the wire types of the installed published package, when present.</summary>
internal sealed record HarnessAuditOptions(IReadOnlySet<string>? GeneratedTypeScriptNames = null);

/// <summary>
/// The GOV.10 successor architecture rules for the C# Harness (HAR.40 validation (d)). The AI Node/TypeScript policy (completed 2026-10-04)
/// is ported to Cloud's layout: C# projects and manifests are read as before, and the Worker TypeScript is read through the policy lexer
/// (<see cref="PolicyLexer"/>), so the Worker rules see module declarations and not text patterns. Every rule reads a map of
/// repository-relative files, so the same code audits the real tree and the fixtures.
/// Adaptations to Cloud's layout are recorded in the harness-foundation document: the Worker entry is worker/index.ts; the Workers AI
/// adapter is the worker/ai/internal folder; the store rules apply to the adapter folders, because Cloud's own storage bridge holds D1 by
/// design; and a public route is refused only when it exposes an internal path, because the Cloud API route is public by design.
/// Recorded limits (carried over from GOV.10): the rules match lexical tokens and syntax, not symbols, so aliasing and indirection are not
/// seen; the task-result check is a syntactic heuristic; and the wrangler audit covers the top level and each environment.
/// </summary>
internal static partial class HarnessArchitecture
{
    /// <summary>The single host project: nothing in src references it.</summary>
    public const string HostEntry = "src/ArcForges.Cloud/ArcForges.Cloud.csproj";

    /// <summary>The Worker entry: nothing but the entry itself may import it (the AI Workflow entry rule, ported to the Cloud Worker).</summary>
    public const string WorkerEntry = "worker/index.ts";

    /// <summary>The Workers AI adapter folder: the only Worker code that may call the inference binding.</summary>
    public const string AdapterFolder = "worker/ai/internal/";

    /// <summary>The Harness adapter folder: the wake handle and its configuration.</summary>
    public const string HarnessFolder = "worker/harness/";

    /// <summary>The one file that may hold the Durable Object lifecycle (the run alarm).</summary>
    public const string AlarmFile = "worker/harness/run-alarm.ts";

    /// <summary>The naming gate report of this checkout (written by npm run policy); absent from git.</summary>
    public const string NamingReport = "artifacts/evidence/naming.json";

    /// <summary>The published wire package of the Worker (Contracts npm).</summary>
    public const string PublicWirePackage = "@arcforges/proto";

    /// <summary>The Contracts packages the repository may reference from another owner.</summary>
    public static readonly IReadOnlySet<string> AdmittedPackages = new HashSet<string>(StringComparer.Ordinal)
    {
        PublicWirePackage, "@arcforges/ai-internal", "@arcforges/api-client",
    };

    /// <summary>The enumerated Apache-2.0 boundary projects of Cloud: none (Cloud is AGPL-3.0-only).</summary>
    public static readonly IReadOnlySet<string> ApacheBoundaryProjects = new HashSet<string>(StringComparer.Ordinal);

    /// <summary>The licence identifiers a shipped AGPL boundary may carry (the AI policy's allowance; LGPL is development-only).</summary>
    public static readonly IReadOnlySet<string> AllowedAgpl = new HashSet<string>(StringComparer.Ordinal)
    {
        "0BSD", "AGPL-3.0-only", "AGPL-3.0-or-later", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "BlueOak-1.0.0", "CC-BY-4.0", "CC0-1.0",
        "ISC", "MIT", "MIT-0", "MPL-2.0", "Python-2.0", "Unlicense", "Zlib",
    };

    /// <summary>The licence identifiers a development-only consumer may also carry (LGPL-3.0 combines into an AGPL work only in tooling).</summary>
    public static readonly IReadOnlySet<string> DevelopmentOnlyLgpl = new HashSet<string>(StringComparer.Ordinal) { "LGPL-3.0-only", "LGPL-3.0-or-later" };

    /// <summary>The licences an Apache-2.0 boundary may carry (AGPL terms are excluded).</summary>
    public static readonly IReadOnlySet<string> AllowedApache = new HashSet<string>(AllowedAgpl.Where(id => !id.StartsWith("AGPL", StringComparison.Ordinal)), StringComparer.Ordinal);

    public static readonly IReadOnlyList<HarnessRule> Rules =
    [
        new("layer-cycle", "WP-05.00", "The project graph and the Worker import graph are acyclic"),
        new("layer-entry", "WP-05.00", "Nothing imports the Worker entry or the host entry"),
        new("layer-escape", "WP-05.00", "References stay inside the repository (no sibling checkout, parent escape, absolute path, URL or tests from the Worker)"),
        new("layer-runtime-dependency", "WP-05.00", "Source projects use only centrally declared packages; Worker imports only declared runtime dependencies and Workers modules"),
        new("layer-product-reference", "WP-05.00", "Only the published Contracts packages are referenced from another owner; the build-only tooling never ships"),
        new("layer-business-authority", "WP-05.00", "Modules reference only their abstractions; Worker adapters hold no business store authority or binding"),
        new("layer-public-exposure", "WP-05.00", "The Worker has no workers.dev or preview exposure and no route that exposes an internal path"),
        new("licence-declaration", "WP-05.01", "Every project declares a boundary and an SPDX expression, and the inventory lists exactly these projects"),
        new("licence-boundary-set", "WP-05.01", "The Apache-boundary set equals the enumerated list (empty for Cloud); an AGPL boundary is exactly AGPL-3.0-only"),
        new("licence-cross-boundary", "WP-05.01", "No Apache-boundary project references an AGPL project"),
        new("licence-allowlist", "WP-05.01", "Every locked dependency and declared licence expression is allowed for its boundary; LGPL is development-only"),
        new("naming-identity", "WP-05.02", "The naming candidate is the exact NuGet identity, centrally pinned, locked and published from its producer"),
        new("naming-scan", "WP-05.02", "The naming scan of this checkout passed with zero findings under the pinned policy"),
        new("wire-package", "WP-05.03", "The wire package is one exact registry-locked pin, and the Worker imports it only as a runtime dependency"),
        new("wire-import", "WP-05.03", "Generated types are imported only from the package root; no source reaches into a build output or a copied tree"),
        new("wire-source", "WP-05.03", "No copied generated source or schema file is authored in this repository"),
        new("wire-codec", "WP-05.03", "No handwritten or alternative wire codec"),
        new("wire-schema", "WP-05.03", "A codec call takes a generated schema from the published package"),
        new("wire-shadow", "WP-05.03", "No local declaration redefines a generated wire type"),
        new("banned-reflection", "WP-05.04", "No reflection entry point or prototype mutation on the Cloud path"),
        new("banned-dynamic-code", "WP-05.04", "No dynamic code generation, computed import or runtime compilation"),
        new("banned-blocking-wait", "WP-05.04", "No blocking wait, synchronous host call or busy-wait on the Cloud path"),
        new("banned-provider-sdk", "WP-05.04", "No provider SDK import or direct provider endpoint call"),
        new("banned-provider-call", "WP-05.04", "The inference binding is called only inside the Workers AI adapter"),
        new("banned-secret-logging", "WP-05.04", "No logging of secret-bearing or content-bearing values"),
        new("banned-float-money", "WP-05.04", "No floating-point arithmetic or number type in money, credit or price values"),
        new("banned-raw-memory", "WP-05.04", "No raw or shared memory handle"),
    ];

    /// <summary>Audits a map of repository-relative files; the result is ordered and free of duplicates.</summary>
    public static IReadOnlyList<HarnessFinding> Audit(IReadOnlyDictionary<string, string> sources, HarnessAuditOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(sources);
        var context = new Context(sources, options ?? new HarnessAuditOptions());
        LayerRules(context);
        LicenceRules(context);
        NamingRules(context);
        WireRules(context);
        BannedRules(context);
        TypeScriptTokenRules(context, context.Options);
        return context.Findings.Distinct().OrderBy(f => f.Rule, StringComparer.Ordinal).ThenBy(f => f.File, StringComparer.Ordinal).ThenBy(f => f.Detail, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// The inventory of one checkout: the tracked and nonignored files (ignored output is never inventoried), read as text, plus the naming
    /// report of this checkout when the policy gate has written it (the report is generated, so it is ignored by Git and read by path).
    /// </summary>
    public static Dictionary<string, string> ReadSources(string root)
    {
        var sources = new Dictionary<string, string>(StringComparer.Ordinal);
        var names = Git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").Split('\0', StringSplitOptions.RemoveEmptyEntries);
        foreach (var name in names.Where(IsInventoried).Order(StringComparer.Ordinal))
        {
            var target = Path.Combine(root, name);
            if (File.Exists(target)) sources[name] = File.ReadAllText(target, Encoding.UTF8);
        }

        var report = Path.Combine(root, NamingReport);
        if (File.Exists(report)) sources[NamingReport] = File.ReadAllText(report, Encoding.UTF8);
        return sources;
    }

    /// <summary>The number of inventoried files of a checkout (the tracked and nonignored set, before the naming report is added).</summary>
    public static int InventoryCount(string root) => ReadSources(root).Keys.Count(name => name != NamingReport);

    private static bool IsInventoried(string path)
    {
        if (path.StartsWith("artifacts/", StringComparison.Ordinal)) return false;
        return path is ".node-version" or ".npmrc" || path.EndsWith(".csproj", StringComparison.Ordinal) || path.EndsWith(".props", StringComparison.Ordinal)
            || path.EndsWith(".cs", StringComparison.Ordinal) || path.EndsWith(".json", StringComparison.Ordinal) || path.EndsWith(".proto", StringComparison.Ordinal)
            || CodeFile().IsMatch(path);
    }

    /// <summary>Whether a path is Worker or repository TypeScript or JavaScript that the token rules read (declarations are not read).</summary>
    public static bool IsCodeFile(string path) => CodeFile().IsMatch(path) && !DeclarationFile().IsMatch(path);

    /// <summary>Whether a path is Worker release code: TypeScript under worker/, never a test or a declaration.</summary>
    public static bool IsRelease(string path) => ReleaseFile().IsMatch(path);

    [GeneratedRegex(@"\.[cm]?[jt]s$", RegexOptions.CultureInvariant)]
    private static partial Regex CodeFile();

    [GeneratedRegex(@"\.d\.[cm]?ts$", RegexOptions.CultureInvariant)]
    private static partial Regex DeclarationFile();

    [GeneratedRegex(@"^worker/.+\.[cm]?ts$", RegexOptions.CultureInvariant)]
    private static partial Regex ReleaseFile();

    private static string Git(string root, params string[] arguments)
    {
        var start = new ProcessStartInfo("git") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        start.ArgumentList.Add("-C");
        start.ArgumentList.Add(root);
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("git did not start");
        var output = process.StandardOutput.ReadToEnd();
        process.StandardError.ReadToEnd();
        process.WaitForExit();
        if (process.ExitCode != 0) throw new InvalidOperationException("git " + string.Join(' ', arguments) + " failed.");
        return output;
    }

    /// <summary>The per-audit state: the files, the parsed projects, the Worker token streams and the findings.</summary>
    internal sealed class Context
    {
        private readonly Dictionary<string, Project> projects = new(StringComparer.Ordinal);
        private readonly Dictionary<string, SyntaxTree> csharp = new(StringComparer.Ordinal);
        private readonly Dictionary<string, TypeScriptFile> typeScript = new(StringComparer.Ordinal);

        public Context(IReadOnlyDictionary<string, string> sources, HarnessAuditOptions options)
        {
            Sources = sources;
            Options = options;
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

                if (IsCodeFile(path))
                {
                    var tokens = PolicyLexer.Tokenize(text);
                    typeScript[path] = new TypeScriptFile(path, text, tokens, PolicyLexer.ModuleReferences(tokens), IsRelease(path));
                }
            }
        }

        public IReadOnlyDictionary<string, string> Sources { get; }

        public HarnessAuditOptions Options { get; }

        public List<HarnessFinding> Findings { get; } = [];

        public IReadOnlyDictionary<string, Project> Projects => projects;

        public IReadOnlyDictionary<string, SyntaxTree> CSharp => csharp;

        /// <summary>Every audited TypeScript or JavaScript file, in path order.</summary>
        public IEnumerable<TypeScriptFile> TypeScript => typeScript.Values.OrderBy(file => file.Path, StringComparer.Ordinal);

        /// <summary>The Worker release files: the TypeScript the Worker runs.</summary>
        public IEnumerable<TypeScriptFile> Release => TypeScript.Where(file => file.Release);

        /// <summary>Source-project C# files (src/ only): the production path the banned and wire rules guard.</summary>
        public IEnumerable<KeyValuePair<string, SyntaxTree>> ProductionCSharp => csharp.Where(entry => entry.Key.StartsWith("src/", StringComparison.Ordinal)).OrderBy(entry => entry.Key, StringComparer.Ordinal);

        public void Report(string rule, string file, string detail) => Findings.Add(new HarnessFinding(rule, file, detail));

        public string? Text(string path) => Sources.TryGetValue(path, out var text) ? text : null;

        /// <summary>The package versions of Directory.Packages.props, when the file is in the audit.</summary>
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

    /// <summary>One TypeScript or JavaScript file read through the policy lexer.</summary>
    internal sealed record TypeScriptFile(string Path, string Text, IReadOnlyList<Token> Tokens, IReadOnlyList<ModuleReference> References, bool Release);

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
            static string Attribute(XElement element, string name) => element.Attribute(name)?.Value ?? string.Empty;
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
            if (include.StartsWith("/", StringComparison.Ordinal) || Regex.IsMatch(include, "^[A-Za-z]:|^[a-z][a-z0-9+.-]*://", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
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

    // ------------------------------------------------------------ JSON helpers (manifests and configuration)

    /// <summary>Parses a JSON text, or returns null when it is absent or not valid JSON (the rules then report it).</summary>
    internal static JsonNode? ParseJson(string? text)
    {
        if (text is null) return null;
        try
        {
            return JsonNode.Parse(text);
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }

    internal static JsonObject? Obj(JsonNode? node) => node as JsonObject;

    internal static string? Str(JsonNode? node) => node is JsonValue value && value.TryGetValue(out string? text) ? text : null;

    internal static bool IsFalse(JsonNode? node) => node is JsonValue value && value.TryGetValue(out bool flag) && !flag;

    /// <summary>The string entries of a JSON object (name to version or expression), ignoring any other kind.</summary>
    internal static Dictionary<string, string> StringMap(JsonNode? node)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        if (Obj(node) is not { } map) return result;
        foreach (var (key, value) in map)
        {
            if (Str(value) is { } text) result[key] = text;
        }

        return result;
    }

    internal static readonly string[] ManifestSections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];

    internal static string PackageName(string specifier) =>
        specifier.StartsWith("@", StringComparison.Ordinal) ? string.Join('/', specifier.Split('/').Take(2)) : specifier.Split('/')[0];

    /// <summary>Resolves a relative module specifier to an audited file, or reports that it leaves the repository.</summary>
    internal static (bool Escaped, string? File) ResolveLocal(string from, string target, IReadOnlyDictionary<string, string> sources)
    {
        var stem = NormalizePosix(JoinPosix(DirectoryOf(from), target));
        if (stem == ".." || stem.StartsWith("../", StringComparison.Ordinal)) return (true, null);
        var baseName = JavaScriptExtension().Replace(stem, string.Empty);
        var candidates = new[] { stem, baseName + ".ts", baseName + ".mts", baseName + "/index.ts" };
        return (false, candidates.FirstOrDefault(sources.ContainsKey));
    }

    private static string DirectoryOf(string path)
    {
        var index = path.LastIndexOf('/');
        return index < 0 ? "." : path[..index];
    }

    private static string JoinPosix(string directory, string target) => directory + "/" + target;

    /// <summary>A POSIX path normalization that keeps leading ".." segments, so an escape from the repository root stays visible.</summary>
    internal static string NormalizePosix(string path)
    {
        var stack = new List<string>();
        foreach (var part in path.Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            if (part == ".") continue;
            if (part == ".." && stack.Count > 0 && stack[^1] != "..") stack.RemoveAt(stack.Count - 1);
            else stack.Add(part);
        }

        return string.Join('/', stack);
    }

    [GeneratedRegex(@"\.[cm]?js$", RegexOptions.CultureInvariant)]
    private static partial Regex JavaScriptExtension();
}
