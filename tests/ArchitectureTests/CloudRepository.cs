// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using ArcForges.Build.Policy.Architecture;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>The repository facts the shared engine cannot infer: stable project roles, inputs and evidence readers.</summary>
internal static class CloudRepository
{
    public const string Owner = "Cloud";
    public const string Service = "src/ArcForges.Cloud/ArcForges.Cloud.csproj";
    public const string ServiceTests = "tests/ArcForges.Cloud.Tests/ArcForges.Cloud.Tests.csproj";
    public const string Consumer = "tests/ArcForges.Cloud.Consumer/ArcForges.Cloud.Consumer.csproj";
    public const string Host = "tests/ArchitectureTests/ArcForges.Cloud.ArchitectureTests.csproj";
    public const string ModuleAbstractions = "src/ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj";
    public const string StorageD1 = "src/ArcForges.Cloud.Storage.D1/ArcForges.Cloud.Storage.D1.csproj";

    /// <summary>
    /// Cloud is one Native AOT host project and composition root. It is classified as the shell rather than an adapter on purpose: the
    /// shared engine then rejects every provider SDK call in it (Cloud holds no provider adapter; Cloudflare is reached only through
    /// the signed Worker facade) and does not apply the RPC-adapter entry-point rule to its implicitly declared record members.
    /// Roles are declared here, never inferred from names, so a new project fails the inventory test until its role is reviewed.
    /// </summary>
    public static IReadOnlyList<ProjectClassification> Classifications { get; } =
    [
        new(Service, ProjectRole.Shell, Owner, Production: true, Aot: true),
        new(ServiceTests, ProjectRole.Test, Owner, Production: false, Aot: false),
        new(Consumer, ProjectRole.Test, Owner, Production: false, Aot: false),
        new(Host, ProjectRole.Test, Owner, Production: false, Aot: false),
        // CLOUD.02 (ADP-07 inventory binding): the shared boundary types, the named-plan bridge and the nineteen module boundaries.
        // The bridge is Persistence so that the host, a shell, may reference it (AT-14) and no module may (AT-07). A module boundary
        // holds only its descriptor today, so it is classified as an Abstractions seam owned by its module; a module task that adds
        // layered code re-reviews this role together with its own policy changes.
        new(ModuleAbstractions, ProjectRole.Abstractions, Owner, Production: true, Aot: true),
        new(StorageD1, ProjectRole.Persistence, Owner, Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Identity/ArcForges.Cloud.Modules.Identity.csproj", ProjectRole.Abstractions, Owner, "Identity", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Workspace/ArcForges.Cloud.Modules.Workspace.csproj", ProjectRole.Abstractions, Owner, "Workspace", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Devices/ArcForges.Cloud.Modules.Devices.csproj", ProjectRole.Abstractions, Owner, "Devices", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Entitlement/ArcForges.Cloud.Modules.Entitlement.csproj", ProjectRole.Abstractions, Owner, "Entitlement", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Commerce/ArcForges.Cloud.Modules.Commerce.csproj", ProjectRole.Abstractions, Owner, "Commerce", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Chat/ArcForges.Cloud.Modules.Chat.csproj", ProjectRole.Abstractions, Owner, "Chat", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Task/ArcForges.Cloud.Modules.Task.csproj", ProjectRole.Abstractions, Owner, "Task", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Agent/ArcForges.Cloud.Modules.Agent.csproj", ProjectRole.Abstractions, Owner, "Agent", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Sync/ArcForges.Cloud.Modules.Sync.csproj", ProjectRole.Abstractions, Owner, "Sync", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Resource/ArcForges.Cloud.Modules.Resource.csproj", ProjectRole.Abstractions, Owner, "Resource", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Search/ArcForges.Cloud.Modules.Search.csproj", ProjectRole.Abstractions, Owner, "Search", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.PackageCatalog/ArcForges.Cloud.Modules.PackageCatalog.csproj", ProjectRole.Abstractions, Owner, "PackageCatalog", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Notification/ArcForges.Cloud.Modules.Notification.csproj", ProjectRole.Abstractions, Owner, "Notification", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Policy/ArcForges.Cloud.Modules.Policy.csproj", ProjectRole.Abstractions, Owner, "Policy", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Scope/ArcForges.Cloud.Modules.Scope.csproj", ProjectRole.Abstractions, Owner, "Scope", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Configuration/ArcForges.Cloud.Modules.Configuration.csproj", ProjectRole.Abstractions, Owner, "Configuration", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Audit/ArcForges.Cloud.Modules.Audit.csproj", ProjectRole.Abstractions, Owner, "Audit", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.Support/ArcForges.Cloud.Modules.Support.csproj", ProjectRole.Abstractions, Owner, "Support", Production: true, Aot: true),
        new("src/ArcForges.Cloud.Modules.TrustSafety/ArcForges.Cloud.Modules.TrustSafety.csproj", ProjectRole.Abstractions, Owner, "TrustSafety", Production: true, Aot: true),
    ];

    /// <summary>
    /// Reconstructs the semantic input of a completed build exactly as the shared producer does, with one addition the producer does
    /// not know: ASP.NET Core's request-delegate generator emits C# interceptors, which the compiler only accepts for namespaces
    /// named in the project's InterceptorsNamespaces. Every diagnostic still fails closed.
    /// </summary>
    public static CSharpCompilation ReadCompilation(ProjectFacts project)
    {
        if (project.Sources.Count == 0 || project.AssemblyReferences.Count == 0
            || project.Sources.Concat(project.AssemblyReferences).Any(path => !File.Exists(path)))
        {
            throw new InvalidOperationException("Completed source/reference inputs are required: " + project.Classification.Path);
        }

        var options = new CSharpParseOptions(LanguageVersion.CSharp14,
            preprocessorSymbols: project.Properties.GetValueOrDefault("DefineConstants", string.Empty).Split(';', StringSplitOptions.RemoveEmptyEntries))
            .WithFeatures([new KeyValuePair<string, string>("InterceptorsNamespaces", "Microsoft.AspNetCore.Http.Generated")]);
        var kind = project.OutputType switch
        {
            "Library" => OutputKind.DynamicallyLinkedLibrary,
            "Exe" => OutputKind.ConsoleApplication,
            _ => throw new InvalidOperationException("Unsupported managed output kind: " + project.OutputType),
        };
        var compilation = CSharpCompilation.Create(project.Properties["AssemblyName"],
            project.Sources.Distinct(StringComparer.Ordinal).Select(path => CSharpSyntaxTree.ParseText(File.ReadAllText(path), options, path)),
            project.AssemblyReferences.Distinct(StringComparer.Ordinal).Select(path => MetadataReference.CreateFromFile(path)),
            new CSharpCompilationOptions(kind, allowUnsafe: true, nullableContextOptions: NullableContextOptions.Enable));
        var errors = compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error).ToArray();
        return errors.Length == 0 ? compilation
            : throw new InvalidOperationException("Invalid owning compilation: " + project.Classification.Path + Environment.NewLine
                + string.Join(Environment.NewLine, errors.Select(error => error.ToString())));
    }
    /// <summary>
    /// Source emitted by the pinned SDK's own first-party generators into the evaluation-owned generated directory of the project being
    /// scanned. It is reconstructed so that authored code resolves against it, but it is not Cloud-authored: its AOT safety is enforced by
    /// the Native AOT compiler with warnings as errors (the candidate build), not by source scanning. The exemption is anchored: the
    /// rooted tree path must lie under <c>&lt;projectDirectory&gt;/obj/arcforges-policy/Release/generated/&lt;generator&gt;/</c> with the
    /// generator directory matching a listed name exactly. The producer deletes and recreates that directory for every evaluation, so
    /// nothing committed there survives; a path anywhere else (a nested or another project's obj directory, a prefix-extended generator
    /// name, a traversal) is authored source. Output of any other generator is never exempt.
    /// </summary>
    public static bool IsOfficialGeneratorOutput(string path, string? projectDirectory)
    {
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(projectDirectory) || !Path.IsPathRooted(path) || !Path.IsPathRooted(projectDirectory))
        {
            return false;
        }

        string generated = Path.GetFullPath(Path.Combine(projectDirectory, "obj", "arcforges-policy", "Release", "generated"))
            .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        string full = Path.GetFullPath(path);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (!full.StartsWith(generated, comparison))
        {
            return false;
        }

        string[] parts = full[generated.Length..].Split(Path.DirectorySeparatorChar);
        return parts.Length >= 3 && OfficialGenerators.Any(generator => string.Equals(parts[0], generator, comparison));
    }

    internal static readonly string[] OfficialGenerators =
    [
        "System.Text.Json.SourceGeneration", "Microsoft.AspNetCore.Http.RequestDelegateGenerator", "Microsoft.Extensions.Logging.Generators",
        "System.Text.RegularExpressions.Generator", "Microsoft.Interop.LibraryImportGenerator",
    ];
    public static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "Cloud.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ?? throw new InvalidOperationException("The owning Cloud repository was not found.");
    }

    public static string Read(string root, string relative) => File.ReadAllText(Path.Combine(root, relative));

    /// <summary>The digest every Cloud dependency input and the shared engine use: SHA-256 of the UTF-8 text with LF line endings.</summary>
    public static string LfSha256(string text) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text.Replace("\r\n", "\n", StringComparison.Ordinal))));

    public static string Head(string root) => Git(root, "rev-parse", "HEAD");

    public static bool IsDirty(string root) => Git(root, "status", "--porcelain").Length != 0;

    private static string Git(string root, params string[] arguments)
    {
        var start = new ProcessStartInfo("git")
        {
            WorkingDirectory = root,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string argument in arguments)
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Git did not start.");
        var output = process.StandardOutput.ReadToEndAsync();
        if (!process.WaitForExit(30_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Git identity lookup timed out.");
        }

        return process.ExitCode == 0 ? output.GetAwaiter().GetResult().Trim() : throw new InvalidOperationException("Git identity could not be read.");
    }

    /// <summary>The admitted dependency inputs, bound by exact LF digest. The engine reports any drift as an RP-06 toolchain difference.</summary>
    public static IReadOnlyDictionary<string, string> ReadInputHashes(string root)
    {
        using var policy = JsonDocument.Parse(Read(root, "eng/policy/dependency-policy.json"));
        return policy.RootElement.GetProperty("inputs").EnumerateObject()
            .ToDictionary(input => input.Name, input => input.Value.GetString()!, StringComparer.Ordinal);
    }

    /// <summary>The reviewed exception inventory. Rows are exact rule/path pairs; wildcards never parse.</summary>
    public static IReadOnlyList<PolicyException> ParseExceptions(string json)
    {
        using var document = JsonDocument.Parse(json);
        if (document.RootElement.ValueKind != JsonValueKind.Array)
        {
            throw new InvalidOperationException("The policy exception inventory must be an array.");
        }

        static string Text(JsonElement row, string name) => row.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()! : throw new InvalidOperationException("A policy exception row is incomplete.");
        return document.RootElement.EnumerateArray().Select(row => new PolicyException(Text(row, "rule"), Text(row, "path"),
            Text(row, "owner"), Text(row, "reason"),
            DateOnly.ParseExact(Text(row, "expires"), "yyyy-MM-dd", CultureInfo.InvariantCulture))).ToArray();
    }

    /// <summary>
    /// Reads the canonical forbidden-term scan result. It is trusted only when it is the WP00 source-policy scan of this exact commit,
    /// from a clean checkout, with exactly one Cloud row and no findings.
    /// </summary>
    public static ExternalPolicyEvidence ReadNamingEvidence(string reportJson, string sourceCommit, string rule)
    {
        using var document = JsonDocument.Parse(reportJson);
        var report = document.RootElement;
        bool wellFormed = report.GetProperty("evidenceClass").GetString() == "source-policy-scan"
            && report.GetProperty("substeps").EnumerateArray().Select(value => value.GetString()).SequenceEqual(["WP00.00", "WP00.01"]);
        if (!wellFormed)
        {
            return new ExternalPolicyEvidence(rule, sourceCommit, false, [Finding(rule, "The naming report is not the canonical source-policy scan.")]);
        }

        var rows = report.GetProperty("repositories").EnumerateArray().Where(row => row.GetProperty("repository").GetString() == Owner).ToArray();
        if (rows.Length != 1)
        {
            return new ExternalPolicyEvidence(rule, sourceCommit, false, [Finding(rule, "The naming report needs exactly one Cloud row.")]);
        }

        var row = rows[0];
        bool bound = row.GetProperty("commit").GetString() == sourceCommit && !row.GetProperty("dirty").GetBoolean();
        bool passed = row.GetProperty("status").GetString() == "pass" && row.GetProperty("findings").GetArrayLength() == 0;
        if (!bound || !passed)
        {
            return new ExternalPolicyEvidence(rule, sourceCommit, false,
                [Finding(rule, bound ? "The naming scan reported findings." : "The naming report is stale or from a dirty checkout.")]);
        }

        return new ExternalPolicyEvidence(rule, sourceCommit, true, []);
    }

    /// <summary>
    /// Licence classification of every resolved NuGet package, read from the restored package's own nuspec through the project's
    /// restore assets. Nothing is downloaded: a package without a licence expression stays unclassified and fails RP-02.
    /// </summary>
    public static IReadOnlyDictionary<string, string> ReadPackageLicences(IEnumerable<ProjectFacts> projects)
    {
        var licences = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var project in projects.Where(project => project.Properties.ContainsKey("ProjectAssetsFile")))
        {
            using var assets = JsonDocument.Parse(File.ReadAllText(project.Properties["ProjectAssetsFile"]));
            var folders = assets.RootElement.GetProperty("packageFolders").EnumerateObject().Select(folder => folder.Name).ToArray();
            foreach (var library in assets.RootElement.GetProperty("libraries").EnumerateObject()
                .Where(library => library.Value.GetProperty("type").GetString() == "package"))
            {
                string name = library.Name[..library.Name.LastIndexOf('/')];
                string relative = library.Value.GetProperty("path").GetString()!;
                string? nuspec = folders.Select(folder => Path.Combine(folder, relative, name.ToLowerInvariant() + ".nuspec"))
                    .FirstOrDefault(File.Exists);
                string? licence = nuspec is null ? null : ReadNuspecLicence(File.ReadAllText(nuspec));
                if (licence is not null)
                {
                    licences.TryAdd(name, licence);
                }
            }
        }

        return licences;
    }

    internal static string? ReadNuspecLicence(string nuspec) => XDocument.Parse(nuspec).Descendants()
        .FirstOrDefault(element => element.Name.LocalName == "license" && element.Attribute("type")?.Value == "expression")?.Value.Trim();

    private static PolicyFinding Finding(string rule, string message) => new(rule, "artifacts/evidence/naming.json", message);
}
