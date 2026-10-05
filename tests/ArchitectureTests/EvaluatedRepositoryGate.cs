// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Build.Policy.Architecture;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>
/// The shared engine over Cloud's real evaluated project graph. It needs the completed Release build and the canonical naming
/// report, and runs in the Linux source job (RP-09 unverified, asserted as the only finding) and in the hosted quality job after
/// the existing secret scan (<c>ARCFORGES_ARCHITECTURE_GATE=hosted</c>, every rule must hold).
/// </summary>
public sealed class EvaluatedRepositoryGate
{
    /// <summary>The public Cloud API and the real test methods that exercise each member. A new public member fails RP-10 until mapped here.</summary>
    private static readonly (string Api, string Method, string TestType, string[] Tests)[] ApiTests =
    [
        ("ArcForges.Cloud.HelloEndpoint", "SayHello", "ArcForges.Cloud.Tests.HelloEndpointTests",
            ["PreservesThePublishedGreeting", "EmptyNameHasThePublishedStatus", "OversizedNameIsResourceExhausted"]),
        ("ArcForges.Cloud.BuildIdentity", "Resolve", "ArcForges.Cloud.Tests.BuildIdentityTests",
            ["NineRealSourceKindsAreIndependentAndDeterministic", "CurrentContractsReceiptShapeResolvesThroughTheHelloSchemaSource", "InvalidSourcesCannotProduceAReport"]),
        ("ArcForges.Cloud.BuildIdentity", "ValidateBuild", "ArcForges.Cloud.Tests.BuildIdentityTests", ["DirtyOrIncompleteCiIdentityIsRejected"]),
        ("ArcForges.Cloud.BuildIdentity", "FromAssembly", "ArcForges.Cloud.Tests.BuildMetadataTests", ["EveryOwnedAssemblyCarriesActualSourceAndBuildIdentity"]),
    ];

    [Fact]
    public void ActualCloudProjectsSatisfyTheSharedArchitecturePolicy()
    {
        string root = CloudRepository.FindRoot();
        string head = CloudRepository.Head(root);
        bool hosted = HostedEvidence.IsHostedMode(Environment.GetEnvironmentVariable);

        var projects = CloudRepository.Classifications.Select(classification => ProjectGraph.Evaluate(root, classification, "Release")).ToArray();
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
            CloudRepository.ParseExceptions(CloudRepository.Read(root, "eng/policy/exceptions.json")), ContractTestBindings(compilations));
        var configuration = new RepositoryPolicyConfiguration(head, CloudRepository.ReadInputHashes(root),
            CloudRepository.ReadPackageLicences(projects), new HashSet<string>(StringComparer.Ordinal), [], [], evidence);
        var findings = PolicyEngine.Check(repository, configuration, compilations, DateOnly.FromDateTime(DateTime.UtcNow)).ToList();

        var service = compilations[CloudRepository.Service];
        var serviceProject = projects.Single(project => project.Classification.Path == CloudRepository.Service);
        // Banned-symbol findings inside the SDK's own generator output are not Cloud-authored (see CloudRepository.IsOfficialGeneratorOutput).
        findings.RemoveAll(finding => finding.Rule.StartsWith("BAN-", StringComparison.Ordinal) && CloudRepository.IsOfficialGeneratorOutput(finding.Path));
        foreach (string problem in CloudAotPolicy.FindSuppressions(service))
        {
            findings.Add(new PolicyFinding("RP-07", CloudRepository.Service, "Trim or AOT suppression at " + problem));
        }

        foreach (string problem in CloudAotPolicy.FindUnregisteredJsonSerialization(service))
        {
            findings.Add(new PolicyFinding("BAN-REFLECTION", CloudRepository.Service, "JSON serialization without compile-time metadata at " + problem));
        }

        foreach (string problem in ContractConsumptionPolicy.CheckServiceBases(service).Concat(ContractConsumptionPolicy.CheckNoAuthoredWireMessages(service)))
        {
            findings.Add(new PolicyFinding("AT-04", CloudRepository.Service, problem));
        }

        foreach (var unverified in evidence.Where(item => !item.Passed))
        {
            findings.AddRange(unverified.Findings);
        }

        Assert.True(serviceProject.Properties["PublishAot"] == "true" && serviceProject.OutputType == "Exe", "The service must stay the Native AOT executable.");
        if (!hosted)
        {
            // Everything except the hosted secret-scan ordering is verified here; that one rule needs the quality job.
            Assert.Contains(findings, finding => finding.Rule == "RP-09");
            findings.RemoveAll(finding => finding.Rule == "RP-09");
        }

        Assert.True(findings.Count == 0, string.Join(Environment.NewLine, findings.Select(finding => $"{finding.Rule} {finding.Path}:{finding.Line} {finding.Message}")));
    }

    private static IReadOnlyList<ContractTestBinding> ContractTestBindings(IReadOnlyDictionary<string, CSharpCompilation> compilations)
    {
        var tests = compilations[CloudRepository.ServiceTests];
        var service = compilations[CloudRepository.Service];
        var result = new List<ContractTestBinding>();
        foreach (var (api, method, testType, names) in ApiTests)
        {
            var apiMethods = service.GetTypeByMetadataName(api)?.GetMembers(method).OfType<IMethodSymbol>().ToArray() ?? [];
            var testMethods = tests.GetTypeByMetadataName(testType)?.GetMembers().OfType<IMethodSymbol>().Where(candidate => names.Contains(candidate.Name)).ToArray() ?? [];
            Assert.True(apiMethods.Length > 0 && testMethods.Length == names.Length, $"The contract test map names a missing member: {api}.{method}.");
            result.AddRange(from apiMethod in apiMethods
                            from test in testMethods
                            select new ContractTestBinding(PolicyEngine.MethodIdentity(apiMethod), CloudRepository.ServiceTests, PolicyEngine.MethodIdentity(test)));
        }

        return result;
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
