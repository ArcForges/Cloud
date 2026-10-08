// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text.Json;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>The real Git inventory suite (repository.test.ts, HAR.40 validation (d)), ported one-for-one.</summary>
public sealed class HarnessRepositoryTests
{
    private static readonly string Root = CloudRepository.FindRoot();

    [Fact]
    public void TheCurrentRepositorySatisfiesEveryArchitectureRuleOutsideTheOwnedRegister()
    {
        var sources = HarnessArchitecture.ReadSources(Root);
        var findings = HarnessArchitecture.Audit(sources);
        var register = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, ArchitectureExceptions.RegisterPath)));
        var result = ArchitectureExceptions.Apply(findings, register.RootElement, DateOnly.FromDateTime(DateTime.UtcNow));
        register.Dispose();
        Assert.Empty(result.Problems);
        Assert.Empty(result.Remaining);
        Assert.Equal(27, HarnessArchitecture.Rules.Count);
        Assert.True(sources.Keys.Count(name => name != HarnessArchitecture.NamingReport) > 50);
    }

    [Fact]
    public void TheRegisterNamesOnlyTrackedFilesAndExpiresWithinTheLifetimeCap()
    {
        var sources = HarnessArchitecture.ReadSources(Root);
        using var register = JsonDocument.Parse(File.ReadAllText(Path.Combine(Root, ArchitectureExceptions.RegisterPath)));
        foreach (var entry in register.RootElement.GetProperty("exceptions").EnumerateArray())
        {
            var file = entry.GetProperty("file").GetString()!;
            Assert.True(sources.ContainsKey(file), "The register names a file outside the audit: " + file);
            var created = DateOnly.ParseExact(entry.GetProperty("created").GetString()!, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
            var expires = DateOnly.ParseExact(entry.GetProperty("expires").GetString()!, "yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
            Assert.True(expires.DayNumber - created.DayNumber is > 0 and <= ArchitectureExceptions.MaxExceptionDays);
        }
    }

    [Fact]
    public void TheInventoryReadsTrackedAndNonignoredFilesAndSkipsIgnoredOnes()
    {
        var fixture = Path.Combine(Path.GetTempPath(), "arcforges-architecture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixture);
        try
        {
            Git(fixture, "init", "-q");
            foreach (var (name, content) in HarnessArchitectureFixtures.Baseline())
            {
                Write(fixture, name, content);
            }

            Write(fixture, ".gitignore", "artifacts/\n");
            Assert.Empty(HarnessArchitecture.Audit(HarnessArchitecture.ReadSources(fixture)));

            // Ignored output is never inventoried, so a violation there is not seen.
            Write(fixture, "artifacts/bad.ts", "import \"node:fs\";\n");
            Assert.Empty(HarnessArchitecture.Audit(HarnessArchitecture.ReadSources(fixture)));

            // An untracked but not ignored file is part of the inventory.
            Write(fixture, "worker/bad.ts", "import \"node:fs\";\n");
            Assert.Contains(HarnessArchitecture.Audit(HarnessArchitecture.ReadSources(fixture)), finding => finding.Rule == "layer-runtime-dependency");
        }
        finally
        {
            // Git marks its object files read-only; clear that so the fixture directory can always be removed.
            foreach (var entry in Directory.EnumerateFileSystemEntries(fixture, "*", SearchOption.AllDirectories))
            {
                if (!Directory.Exists(entry)) File.SetAttributes(entry, FileAttributes.Normal);
            }

            Directory.Delete(fixture, recursive: true);
        }
    }

    private static void Write(string root, string name, string content)
    {
        var target = Path.Combine(root, name);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.WriteAllText(target, content);
    }

    private static void Git(string root, params string[] arguments)
    {
        var start = new ProcessStartInfo("git") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        start.ArgumentList.Add("-C");
        start.ArgumentList.Add(root);
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("git did not start");
        process.StandardOutput.ReadToEnd();
        process.StandardError.ReadToEnd();
        process.WaitForExit();
        Assert.Equal(0, process.ExitCode);
    }
}
