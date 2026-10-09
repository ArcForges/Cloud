// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>The real repository inputs against the policies the fixtures above prove: static facts that need no build output.</summary>
public sealed class ActualRepositoryTests
{
    private static readonly string Root = CloudRepository.FindRoot();

    [Fact]
    public void SolutionProjectFilesAndRolesAreTheSameClassifiedProjects()
    {
        var files = TrackedFiles().Where(file => file.EndsWith(".csproj", StringComparison.Ordinal)).ToArray();
        Assert.Equal(CloudRepository.Classifications.Count, files.Length);
        Assert.Empty(RepositoryInventoryPolicy.CheckProjects(CloudRepository.Read(Root, "Cloud.slnx"), files, CloudRepository.Classifications));
    }

    [Fact]
    public void EveryProjectDeclaresAgpl3OnlyAndNoPolicyExceptionIsNeeded()
    {
        var projects = ProjectFiles();
        Assert.Empty(RepositoryInventoryPolicy.CheckLicences(CloudRepository.Read(Root, "eng/policy/licence-boundary.json"), projects, CloudRepository.Read(Root, "Directory.Build.props")));
        var exceptions = CloudRepository.ParseExceptions(CloudRepository.Read(Root, "eng/policy/exceptions.json"));
        Assert.Empty(RepositoryInventoryPolicy.CheckExceptions(exceptions, CloudRepository.Classifications, DateOnly.FromDateTime(DateTime.UtcNow)));
        // Cloud is AGPL-3.0-only: the architecture host consumes the AGPL ArcForges.Build.Policy package directly with no RP-03 row.
        Assert.Empty(exceptions);
    }

    [Fact]
    public void ContractsAreConsumedOnlyAsOneExactPublishedCandidate()
    {
        Assert.Empty(ContractConsumptionPolicy.CheckPins(CloudRepository.Read(Root, "Directory.Packages.props"), CloudRepository.Read(Root, "package.json")));
        Assert.Empty(ContractConsumptionPolicy.CheckProjectInputs(Root, ProjectFiles()));
        Assert.Empty(ContractConsumptionPolicy.CheckTrackedFiles(TrackedFiles()));
    }

    [Fact]
    public void TheNativeAotServiceDeclaresItsPostureInTheProjectFile()
    {
        Assert.Empty(CloudAotPolicy.CheckProject(CloudRepository.Read(Root, CloudRepository.Service), CloudRepository.Read(Root, "Directory.Build.props")));
    }

    [Fact]
    public void TheForbiddenTermScanIsWiredIntoTheCheckGateWithTheExactPublishedScanner()
    {
        Assert.Empty(NamingWiring.Check(CloudRepository.Read(Root, "package.json"), CloudRepository.Read(Root, "tooling/project.ts"),
            CloudRepository.Read(Root, "eng/policy/naming-candidate.json"), CloudRepository.Read(Root, "tests/ArchitectureTests/packages.lock.json"),
            CloudRepository.Read(Root, "Directory.Packages.props"), CloudRepository.Read(Root, "tests/ArchitectureTests/ArcForges.Cloud.ArchitectureTests.csproj")));
    }

    [Fact]
    public void TheHostedGateRunsAfterTheExistingSecretScanInTheSameJob()
    {
        Assert.Empty(CiWiring.Check(CloudRepository.Read(Root, ".github/workflows/ci.yml"), CloudRepository.Read(Root, "package.json")));
    }

    [Fact]
    public void TheBuildPolicyPinIsAtLeastTheSharedEngineCandidate()
    {
        var props = System.Xml.Linq.XDocument.Parse(CloudRepository.Read(Root, "Directory.Packages.props"));
        string pin = props.Descendants("PackageVersion").Single(element => element.Attribute("Include")!.Value == "ArcForges.Build.Policy").Attribute("Version")!.Value;
        var match = System.Text.RegularExpressions.Regex.Match(pin, @"^1\.0\.0-ci\.(?<build>\d+)\.\d+$");
        Assert.True(match.Success && int.Parse(match.Groups["build"].Value, System.Globalization.CultureInfo.InvariantCulture) >= 94,
            "The architecture host needs the GOV.06 ArcForges.Build.Policy candidate (1.0.0-ci.94.1) or a later one.");
    }
    private static Dictionary<string, string> ProjectFiles() => TrackedFiles().Where(file => file.EndsWith(".csproj", StringComparison.Ordinal))
        .ToDictionary(file => file, file => CloudRepository.Read(Root, file), StringComparer.Ordinal);

    private static string[] TrackedFiles()
    {
        var start = new ProcessStartInfo("git")
        {
            WorkingDirectory = Root,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (string argument in new[] { "ls-files", "-z", "--cached", "--others", "--exclude-standard" })
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Process.Start(start) ?? throw new InvalidOperationException("Git did not start.");
        var output = process.StandardOutput.ReadToEndAsync();
        if (!process.WaitForExit(30_000))
        {
            process.Kill(entireProcessTree: true);
            throw new TimeoutException("Git file listing timed out.");
        }

        Assert.Equal(0, process.ExitCode);
        return [.. output.GetAwaiter().GetResult().Split('\0', StringSplitOptions.RemoveEmptyEntries)];
    }
}

/// <summary>RP-09 evidence resolution: only the exact hosted quality job after the secret scan establishes it.</summary>
public sealed class HostedEvidenceTests
{
    private const string Head = "0123456789abcdef0123456789abcdef01234567";

    private static Func<string, string?> Environment(string? mode = "hosted", string actions = "true", string job = "quality", string sha = Head) => name => name switch
    {
        "ARCFORGES_ARCHITECTURE_GATE" => mode,
        "GITHUB_ACTIONS" => actions,
        "GITHUB_JOB" => job,
        "GITHUB_SHA" => sha,
        _ => null,
    };

    [Fact]
    public void TheExactHostedQualityJobEstablishesTheSecretScanEvidence()
    {
        var environment = Environment();
        var evidence = HostedEvidence.Resolve(environment, Head, [], HostedEvidence.IsHostedMode(environment));
        Assert.True(evidence.Passed);
        Assert.Empty(evidence.Findings);
    }

    [Theory]
    [InlineData("local-mode")]
    [InlineData("not-actions")]
    [InlineData("other-job")]
    [InlineData("other-commit")]
    [InlineData("workflow")]
    public void AnythingElseLeavesTheSecretScanUnverified(string defect)
    {
        var environment = defect switch
        {
            "local-mode" => Environment(mode: null),
            "not-actions" => Environment(actions: "false"),
            "other-job" => Environment(job: "source"),
            "other-commit" => Environment(sha: new string('b', 40)),
            _ => Environment(),
        };
        var evidence = HostedEvidence.Resolve(environment, Head, defect == "workflow" ? ["ordering"] : [], HostedEvidence.IsHostedMode(environment));
        Assert.False(evidence.Passed);
        Assert.NotEmpty(evidence.Findings);
    }
}
