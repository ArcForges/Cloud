// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using ArcForges.Build.Policy.Architecture;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>The repository facts the shared engine cannot infer: stable project roles, inputs and evidence readers.</summary>
internal static class CloudRepository
{
    public const string Owner = "Cloud";
    public const string Service = "src/ArcForges.Cloud/ArcForges.Cloud.csproj";
    public const string ServiceTests = "tests/ArcForges.Cloud.Tests/ArcForges.Cloud.Tests.csproj";
    public const string Consumer = "tests/ArcForges.Cloud.Consumer/ArcForges.Cloud.Consumer.csproj";
    public const string Host = "tests/ArchitectureTests/ArcForges.Cloud.ArchitectureTests.csproj";

    /// <summary>
    /// Cloud is one Native AOT host project: the public gRPC/gRPC-Web adapter and its composition root. Roles are declared here,
    /// never inferred from names, so a new project fails the inventory test until its role is reviewed.
    /// </summary>
    public static IReadOnlyList<ProjectClassification> Classifications { get; } =
    [
        new(Service, ProjectRole.PublicApiAdapter, Owner, Production: true, Aot: true),
        new(ServiceTests, ProjectRole.Test, Owner, Production: false, Aot: false),
        new(Consumer, ProjectRole.Test, Owner, Production: false, Aot: false),
        new(Host, ProjectRole.Test, Owner, Production: false, Aot: false),
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
        bool wellFormed = report.TryGetProperty("evidenceClass", out var evidenceClass)
            && evidenceClass.GetString() == "source-policy-scan"
            && report.TryGetProperty("substeps", out var substeps)
            && substeps.EnumerateArray().Select(value => value.GetString()).SequenceEqual(["WP00.00", "WP00.01"])
            && report.TryGetProperty("repositories", out var repositories);
        if (!wellFormed)
        {
            return new ExternalPolicyEvidence(rule, sourceCommit, false, [Finding(rule, "The naming report is not the canonical source-policy scan.")]);
        }

        var rows = repositories.EnumerateArray().Where(row => row.GetProperty("repository").GetString() == Owner).ToArray();
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
