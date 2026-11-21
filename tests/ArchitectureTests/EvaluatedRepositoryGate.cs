// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Build.Policy.Architecture;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>
/// The shared engine over Cloud's active managed verification projects. It needs the completed Release build and the canonical naming
/// report, and runs in the Linux source job (RP-09 unverified, asserted as the only finding) and in the hosted quality job after
/// the existing secret scan (<c>ARCFORGES_ARCHITECTURE_GATE=hosted</c>, every rule must hold).
/// </summary>
public sealed class EvaluatedRepositoryGate
{
    /// <summary>
    /// The standing WorkerAdapter literal check (CLOUD.84 D9 and S43) runs in the hosted architecture gate as well as in check:dotnet: every
    /// worker literal is either a closed protocol constant or an owned, expiring register row, and every register row names a finding.
    /// </summary>
    [Fact]
    public void TheWorkerAdapterHoldsNoBusinessLiteralOutsideTheNamedLists()
    {
        var root = CloudRepository.FindRoot();
        var sources = ArcForges.Cloud.ArchitectureTests.AiHarness.HarnessArchitecture.ReadSources(root);
        using var register = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(root, ArcForges.Cloud.ArchitectureTests.AiHarness.ArchitectureExceptions.RegisterPath)));
        var result = ArcForges.Cloud.ArchitectureTests.WorkerAdapter.WorkerLiteralScan.ApplyRegister(sources, register.RootElement, DateOnly.FromDateTime(DateTime.UtcNow));
        Assert.Empty(result.Problems);
        Assert.Empty(result.Remaining);
    }

    [Fact]
    public void ActiveManagedProjectsSatisfyTheSharedArchitecturePolicy()
    {
        string root = CloudRepository.FindRoot();
        string head = CloudRepository.Head(root);
        bool hosted = HostedEvidence.IsHostedMode(Environment.GetEnvironmentVariable);

        var projects = CloudRepository.ActiveClassifications.Select(classification => ProjectGraph.Evaluate(root, classification, "Release")).ToArray();
        Assert.All(projects, project => Assert.Empty(project.ProjectReferences));
        var compilations = projects.ToDictionary(project => project.Classification.Path, CloudRepository.ReadCompilation, StringComparer.Ordinal);
        string report = CloudRepository.Read(root, "artifacts/evidence/naming.json");
        var evidence = new[]
        {
            CloudRepository.ReadNamingEvidence(report, head, "RP-01"),
            CloudRepository.ReadNamingEvidence(report, head, "RP-08"),
            HostedEvidence.Resolve(Environment.GetEnvironmentVariable, head,
                CiWiring.Check(CloudRepository.Read(root, ".github/workflows/ci.yml"), CloudRepository.Read(root, "package.json")), hosted),
        };
        var repository = new RepositoryFacts(root, CloudRepository.Owner, projects,
            CloudRepository.ParseExceptions(CloudRepository.Read(root, "eng/policy/exceptions.json")), []);
        var configuration = new RepositoryPolicyConfiguration(head, CloudRepository.ReadInputHashes(root),
            CloudRepository.ReadPackageLicences(projects), new HashSet<string>(StringComparer.Ordinal), [], [], evidence);
        var findings = PolicyEngine.Check(repository, configuration, compilations, DateOnly.FromDateTime(DateTime.UtcNow)).ToList();

        foreach (var unverified in evidence.Where(item => !item.Passed))
        {
            findings.AddRange(unverified.Findings);
        }

        if (!hosted)
        {
            // Everything except the hosted secret-scan ordering is verified here; that one rule needs the quality job.
            Assert.Contains(findings, finding => finding.Rule == "RP-09");
            findings.RemoveAll(finding => finding.Rule == "RP-09");
        }

        Assert.True(findings.Count == 0, string.Join(Environment.NewLine, findings.Select(finding => $"{finding.Rule} {finding.Path}:{finding.Line} {finding.Message}")));
    }

}

/// <summary>RP-09 is the existing required secret scan. It is trusted only in the hosted job that runs the architecture host after it.</summary>
internal static class HostedEvidence
{
    public const string Variable = "ARCFORGES_ARCHITECTURE_GATE";

    public static bool IsHostedMode(Func<string, string?> environment) => environment(Variable) == "hosted";

    public static ExternalPolicyEvidence Resolve(Func<string, string?> environment, string head, IReadOnlyList<string> workflowProblems, bool hosted)
    {
        const string rule = "RP-09";
        string? source = environment("GITHUB_SHA");
        bool identity = environment("GITHUB_ACTIONS") == "true" && environment("GITHUB_JOB") == "quality" && source == head && head.Length == 40;
        if (hosted && identity && workflowProblems.Count == 0)
        {
            return new ExternalPolicyEvidence(rule, head, true, []);
        }

        string reason = !hosted ? "The secret scan result is only trusted in the hosted quality job."
            : !identity ? "The hosted gate requires the exact GitHub quality job and source identity."
            : "The hosted workflow no longer orders the secret scan before the architecture gate.";
        return new ExternalPolicyEvidence(rule, head, false, [new PolicyFinding(rule, ".github/workflows/ci.yml", reason)]);
    }
}
