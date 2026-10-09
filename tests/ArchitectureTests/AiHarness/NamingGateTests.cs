// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>
/// The pinned NuGet identity of the canonical naming scanner and policy (GOV.10 successor, WP-05.02, P2-021 item 4). The scanner and
/// the policy come only from the NuGet package ArcForges.Contracts.Validation 1.0.0-ci.205.1 (Contracts source 696242d, the GOV.14
/// binding of the CON.23 identity). The npm @arcforges/proto 1.0.0-ci.287.1 publication carries the same bytes and is provenance only.
/// The 1.0.0-ci.129.1 line is refused because it checks a different forbidden-name set.
/// </summary>
internal static class NamingCandidate
{
    public const string PackageId = "ArcForges.Contracts.Validation";
    public const string Version = "1.0.0-ci.205.1";
    public const string SourceCommit = "696242d16034262ce8b7268e8d157cd0e5bee544";
    public const string ArchiveSha512 = "OWvMF30zpN6ms2KlQCtax5P7TACrgK50Vb0drN5zy4iXgk2TZd+5UU+LDGaA2ioowA1EQIZx8ZUyRoayZaHadA==";
    public const string ScannerPath = "tools/naming/eng/check_naming.py";
    public const string ScannerSha256 = "7c4cd7041b8b53e1bfb6fc0016befcd50259ffaca512d389456e00d3c26d5eaf";
    public const string PolicyPath = "tools/naming/eng/policy/product-names.json";
    public const string PolicySha256 = "f5d596298ec50e3b116abc6df1b34efef93045ed52f6235b0a2aaaf97a1f4df5";

    /// <summary>The restored NuGet package folder, from the GeneratePathProperty of the architecture host project.</summary>
    public static string PackageRoot =>
        typeof(NamingCandidate).Assembly.GetCustomAttributes<AssemblyMetadataAttribute>().Single(a => a.Key == "NamingPackageRoot").Value
        ?? throw new InvalidOperationException("The naming package root is not bound.");

    /// <summary>Checks a package identity before any archive byte is read: a different id or version is refused.</summary>
    public static IReadOnlyList<string> VerifyIdentity(string packageId, string version) =>
        packageId == PackageId && version == Version ? [] : ["The naming package identity is not the pinned NuGet candidate."];

    /// <summary>
    /// Checks the archive, its sidecar digest, the packaged source commit and both packaged asset digests. Every check fails closed: a
    /// missing or altered byte is a finding, and nothing else is accepted in its place.
    /// </summary>
    public static IReadOnlyList<string> VerifyArchive(byte[] archive, string sidecarSha512, byte[] sourceJson, IReadOnlyDictionary<string, byte[]> assets)
    {
        var problems = new List<string>();
        if (Convert.ToBase64String(SHA512.HashData(archive)) != ArchiveSha512) problems.Add("The archive SHA512 differs from the pinned candidate.");
        if (sidecarSha512.Trim() != ArchiveSha512) problems.Add("The archive sidecar digest differs from the pinned candidate.");
        try
        {
            using var source = JsonDocument.Parse(sourceJson);
            if (!source.RootElement.TryGetProperty("commit", out var commit) || commit.GetString() != SourceCommit)
                problems.Add("The packaged source commit differs from the pinned candidate.");
        }
        catch (JsonException)
        {
            problems.Add("The packaged source record is not valid JSON.");
        }

        problems.AddRange(VerifyAsset(assets, ScannerPath, ScannerSha256, "scanner"));
        problems.AddRange(VerifyAsset(assets, PolicyPath, PolicySha256, "policy"));
        return problems;
    }

    private static IEnumerable<string> VerifyAsset(IReadOnlyDictionary<string, byte[]> assets, string path, string expected, string label)
    {
        if (!assets.TryGetValue(path, out var bytes)) return ["The packaged " + label + " is missing."];
        return Convert.ToHexStringLower(SHA256.HashData(bytes)) == expected ? [] : ["The packaged " + label + " differs from the pinned SHA256."];
    }
}

/// <summary>Naming identity and naming scan (GOV.10 successor rules naming-identity and naming-scan, WP-05.02).</summary>
public sealed class NamingGateTests
{
    private static readonly string Root = CloudRepository.FindRoot();

    private static string PackageFile(string name) => Path.Combine(NamingCandidate.PackageRoot, name);

    private static Dictionary<string, byte[]> Assets(byte[]? scanner = null, byte[]? policy = null) => new()
    {
        [NamingCandidate.ScannerPath] = scanner ?? File.ReadAllBytes(Path.Combine(NamingCandidate.PackageRoot, NamingCandidate.ScannerPath)),
        [NamingCandidate.PolicyPath] = policy ?? File.ReadAllBytes(Path.Combine(NamingCandidate.PackageRoot, NamingCandidate.PolicyPath)),
    };

    [Fact]
    public void TheCandidateRecordNamesTheSamePinnedNuGetIdentityAsTheTests()
    {
        using var record = JsonDocument.Parse(CloudRepository.Read(Root, "eng/policy/naming-candidate.json"));
        var root = record.RootElement;
        Assert.Equal(NamingCandidate.PackageId, root.GetProperty("package").GetString());
        Assert.Equal("nuget", root.GetProperty("ecosystem").GetString());
        Assert.Equal(NamingCandidate.Version, root.GetProperty("version").GetString());
        Assert.Equal(NamingCandidate.SourceCommit, root.GetProperty("sourceCommit").GetString());
        Assert.Equal(NamingCandidate.ArchiveSha512, root.GetProperty("archiveSha512").GetString());
        Assert.Equal(NamingCandidate.ScannerSha256, root.GetProperty("assets").GetProperty(NamingCandidate.ScannerPath).GetString());
        Assert.Equal(NamingCandidate.PolicySha256, root.GetProperty("assets").GetProperty(NamingCandidate.PolicyPath).GetString());
    }

    [Fact]
    public void TheRestoredArchiveMatchesEveryPinnedDigestBeforeTheScannerRuns()
    {
        var archive = File.ReadAllBytes(PackageFile($"{NamingCandidate.PackageId.ToLowerInvariant()}.{NamingCandidate.Version}.nupkg"));
        var sidecar = File.ReadAllText(PackageFile($"{NamingCandidate.PackageId.ToLowerInvariant()}.{NamingCandidate.Version}.nupkg.sha512"));
        var source = File.ReadAllBytes(PackageFile("source.json"));
        Assert.Empty(NamingCandidate.VerifyIdentity(NamingCandidate.PackageId, NamingCandidate.Version));
        Assert.Empty(NamingCandidate.VerifyArchive(archive, sidecar, source, Assets()));
    }

    [Fact]
    public void AnArchiveOrPackagedAssetThatIsNotThePinnedBytesIsRefusedBeforeTheScannerRuns()
    {
        var archive = File.ReadAllBytes(PackageFile($"{NamingCandidate.PackageId.ToLowerInvariant()}.{NamingCandidate.Version}.nupkg"));
        var sidecar = File.ReadAllText(PackageFile($"{NamingCandidate.PackageId.ToLowerInvariant()}.{NamingCandidate.Version}.nupkg.sha512"));
        var source = File.ReadAllBytes(PackageFile("source.json"));
        var policy = File.ReadAllBytes(Path.Combine(NamingCandidate.PackageRoot, NamingCandidate.PolicyPath));
        var scanner = File.ReadAllBytes(Path.Combine(NamingCandidate.PackageRoot, NamingCandidate.ScannerPath));

        var altered = (byte[])policy.Clone();
        altered[^1] ^= 0x20;
        Assert.Contains(NamingCandidate.VerifyArchive(archive, sidecar, source, Assets(policy: altered)), finding => finding.Contains("policy", StringComparison.Ordinal));

        var swappedScanner = (byte[])scanner.Clone();
        swappedScanner[0] ^= 0x01;
        Assert.Contains(NamingCandidate.VerifyArchive(archive, sidecar, source, Assets(scanner: swappedScanner)), finding => finding.Contains("scanner", StringComparison.Ordinal));

        var altered2 = (byte[])archive.Clone();
        altered2[^1] ^= 0x01;
        Assert.NotEmpty(NamingCandidate.VerifyArchive(altered2, sidecar, source, Assets()));
        Assert.NotEmpty(NamingCandidate.VerifyArchive(archive, "unknown", source, Assets()));
        Assert.NotEmpty(NamingCandidate.VerifyArchive(archive, sidecar, Encoding.UTF8.GetBytes("{\"commit\":\"main\"}"), Assets()));
        Assert.NotEmpty(NamingCandidate.VerifyArchive(archive, sidecar, source, new Dictionary<string, byte[]>()));
    }

    [Theory]
    [InlineData("ArcForges.Contracts.Validation", "1.0.0-ci.129.1")]
    [InlineData("ArcForges.Contracts.Validation", "1.0.0-ci.205.2")]
    [InlineData("@arcforges/proto", "1.0.0-ci.287.1")]
    public void AnotherPackageOrLineIsRefusedAtIdentity(string packageId, string version)
    {
        Assert.NotEmpty(NamingCandidate.VerifyIdentity(packageId, version));
    }

    [Fact]
    public void TheScannerReportsZeroFindingsOnTheCloudTree()
    {
        var (exit, output, error) = Run("python", ["-I", Path.Combine(NamingCandidate.PackageRoot, NamingCandidate.ScannerPath), "--repository", "Cloud=" + Root]);
        Assert.True(exit == 0, "The naming scanner failed: " + error);
        Assert.Contains("Cloud: pass;", output, StringComparison.Ordinal);
        Assert.Contains("0 findings", output, StringComparison.Ordinal);
    }

    [Fact]
    public void EveryForbiddenNameOfThePinnedPolicyIsDetectedByTheScanner()
    {
        var names = ForbiddenNames();
        Assert.NotEmpty(names);
        using var repository = ForbiddenFixtureRepository(names.Select((name, index) => (name, "forbidden-" + index + ".txt")));
        var (exit, output, _) = Run("python", ["-I", Path.Combine(NamingCandidate.PackageRoot, NamingCandidate.ScannerPath), "--repository", "Cloud=" + repository.Path]);
        Assert.Equal(1, exit);
        foreach (var name in names)
            Assert.Contains("\"name\": \"" + name + "\"", output, StringComparison.Ordinal);
    }

    [Fact]
    public void AFailingScannerBecomesAFindingNotAPass()
    {
        // A scanner that cannot find the policy it was packaged with reports an error and exits non-zero: the gate turns that into a finding.
        using var repository = ForbiddenFixtureRepository([("ordinary note with no reserved word", "note.txt")]);
        var (exit, output, _) = Run("python", ["-I", Path.Combine(NamingCandidate.PackageRoot, NamingCandidate.ScannerPath), "--repository", "Cloud=" + repository.Path + "-missing"]);
        Assert.NotEqual(0, exit);
        Assert.DoesNotContain(": pass;", output, StringComparison.Ordinal);
    }

    private static string[] ForbiddenNames()
    {
        using var policy = JsonDocument.Parse(File.ReadAllText(Path.Combine(NamingCandidate.PackageRoot, NamingCandidate.PolicyPath)));
        return policy.RootElement.GetProperty("forbiddenNames").EnumerateArray().Select(item => item.GetProperty("name").GetString()!).ToArray();
    }

    /// <summary>A temporary Git root named Cloud with its files; the names are built at run time so no forbidden literal enters the tree.</summary>
    private static TempRepository ForbiddenFixtureRepository(IEnumerable<(string Content, string Path)> files)
    {
        var repository = new TempRepository();
        foreach (var (content, path) in files)
        {
            File.WriteAllText(Path.Combine(repository.Path, path), "reference " + content + " end\n");
        }

        Run("git", ["-C", repository.Path, "init", "-q"]);
        Run("git", ["-C", repository.Path, "remote", "add", "origin", "https://github.com/ArcForges/Cloud.git"]);
        Run("git", ["-C", repository.Path, "add", "-A"]);
        Run("git", ["-C", repository.Path, "-c", "user.name=architecture", "-c", "user.email=architecture@example.invalid", "commit", "-q", "-m", "fixture"]);
        return repository;
    }

    private static (int Exit, string Output, string Error) Run(string file, string[] args)
    {
        var start = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("The process did not start: " + file);
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output, error);
    }

    private sealed class TempRepository : IDisposable
    {
        public TempRepository()
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "arcforges-naming-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            // Git marks its object files read-only; clear that so the fixture directory can always be removed.
            foreach (var entry in Directory.EnumerateFileSystemEntries(Path, "*", SearchOption.AllDirectories))
            {
                if (!Directory.Exists(entry)) File.SetAttributes(entry, FileAttributes.Normal);
            }

            Directory.Delete(Path, recursive: true);
        }
    }
}
