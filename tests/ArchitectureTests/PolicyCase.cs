// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using ArcForges.Build.Policy.Architecture;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace ArcForges.Cloud.ArchitectureTests;

/// <summary>
/// One offline Cloud-shaped repository: real compiled fixture sources, real lock files on disk, no execution. Every rule gets a valid
/// and a violating case built from the same constructor so that a pair differs only in the property under test.
/// </summary>
internal sealed class PolicyCase : IDisposable
{
    public const string SourceCommit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string TestProject = "test/test.csproj";
    private readonly string root = Path.Combine(Path.GetTempPath(), "arcforges-cloud-policy-" + Guid.NewGuid().ToString("N"));
    private readonly Dictionary<string, CSharpCompilation> compilations = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> licences = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> toolchain = new(StringComparer.Ordinal);
    private readonly List<ContractTestBinding> contractTests = [];
    private readonly List<LocalServiceBinding> services = [];
    private readonly List<WireTypeBinding> wireTypes = [];

    private PolicyCase()
    {
        Directory.CreateDirectory(root);
        string global = Path.Combine(root, "global.json");
        File.WriteAllText(global, "{\"sdk\":{\"version\":\"10.0.401\"}}");
        toolchain.Add("global.json", CloudRepository.LfSha256(File.ReadAllText(global)));
        Add("test", ProjectRole.Test, "namespace FixtureTests; public class Contracts { [Xunit.Fact] public void Verify() {} }", production: false);
    }

    public List<ProjectFacts> Projects { get; } = [];

    public List<PolicyException> Exceptions { get; } = [];

    public Dictionary<string, ProjectRole> DependencyRoles { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<ExternalPolicyEvidence> Evidence { get; } =
    [
        new("RP-01", SourceCommit, true, []),
        new("RP-08", SourceCommit, true, []),
        new("RP-09", SourceCommit, true, []),
    ];

    public static PolicyCase Create(string rule, bool violation)
    {
        var fixture = new PolicyCase();
        switch (rule)
        {
            case "AT-01":
                fixture.Add("dependency", violation ? ProjectRole.Infrastructure : ProjectRole.Abstractions);
                fixture.Add("subject", ProjectRole.Domain, references: ["dependency/dependency.csproj"]);
                break;
            case "AT-02":
            case "AT-03":
                fixture.Add("dependency", violation ? ProjectRole.UserInterface : ProjectRole.Abstractions);
                fixture.Add("subject", rule == "AT-02" ? ProjectRole.LocalRpcAdapter : ProjectRole.PublicApiAdapter, references: ["dependency/dependency.csproj"]);
                break;
            case "AT-04":
                fixture.Add("dependency", violation ? ProjectRole.NativeAdapter : ProjectRole.Foundation);
                fixture.Add("subject", ProjectRole.Contracts, references: ["dependency/dependency.csproj"]);
                break;
            case "AT-05":
                fixture.Add("dependency", violation ? ProjectRole.Domain : ProjectRole.Abstractions, owner: "OtherProduct");
                fixture.Add("subject", ProjectRole.Application, references: ["dependency/dependency.csproj"]);
                break;
            case "AT-06":
                fixture.Add("subject", ProjectRole.NativeAdapter, violation
                    ? "public static class Api { public static System.IntPtr Value() => System.IntPtr.Zero; }"
                    : "public static class Api { public static int Value() => 1; }");
                break;
            case "AT-07":
                fixture.Add("dependency", ProjectRole.Persistence, module: violation ? "OtherModule" : "Module");
                fixture.Add("subject", ProjectRole.Infrastructure, references: ["dependency/dependency.csproj"], module: "Module");
                break;
            case "AT-08":
            case "AT-11":
                string argument = rule == "AT-08" && violation ? "object" : "int";
                string port = rule == "AT-11" && violation ? string.Empty : "private readonly IPort port = new Port();";
                fixture.Add("subject", ProjectRole.LocalRpcAdapter,
                    $$"""
                    [System.CodeDom.Compiler.GeneratedCode("grpc_csharp_plugin", "1")] public static class GeneratedRpc
                    { public abstract class ServiceBase { public abstract int Call({{argument}} value); } }
                    internal interface IPort { int Call(); } internal sealed class Port : IPort { int IPort.Call() => 1; }
                    public sealed class Service : GeneratedRpc.ServiceBase { {{port}} public override int Call({{argument}} value) => 1; }
                    """);
                fixture.services.Add(new("Service", "GeneratedRpc.ServiceBase", "IPort"));
                break;
            case "AT-09":
                fixture.Add("subject", ProjectRole.NativeWorker, production: violation);
                break;
            case "AT-10":
                fixture.Add("subject", ProjectRole.Infrastructure, packages: new Dictionary<string, string> { [violation ? "Refit" : "Safe.Http"] = "1.0.0" });
                break;
            case "AT-12":
                string attribute = violation ? string.Empty : "[System.CodeDom.Compiler.GeneratedCode(\"protoc\", \"1\")] ";
                fixture.Add("subject", ProjectRole.Contracts, attribute + "public sealed class WireMessage { public int Value { get; set; } }");
                string schema = Path.Combine(fixture.root, "message.proto");
                File.WriteAllText(schema, "syntax = \"proto3\"; message WireMessage { int32 value = 1; }");
                fixture.wireTypes.Add(new("WireMessage", "message.proto", CloudRepository.LfSha256(File.ReadAllText(schema))));
                break;
            case "AT-13":
                fixture.Add("dependency", violation ? ProjectRole.Infrastructure : ProjectRole.Abstractions, module: "OtherModule");
                fixture.Add("subject", ProjectRole.Infrastructure, references: ["dependency/dependency.csproj"], module: "Module");
                break;
            case "AT-14":
                fixture.Add("dependency", violation ? ProjectRole.Domain : ProjectRole.Foundation);
                fixture.Add("subject", ProjectRole.Shell, references: ["dependency/dependency.csproj"]);
                break;
            case "RP-01":
            case "RP-08":
            case "RP-09":
                fixture.Add("subject", ProjectRole.Foundation);
                int index = fixture.Evidence.FindIndex(evidence => evidence.Rule == rule);
                fixture.Evidence[index] = fixture.Evidence[index] with { Passed = !violation };
                break;
            case "RP-02":
                fixture.Add("subject", ProjectRole.Foundation, license: violation ? string.Empty : "AGPL-3.0-only");
                break;
            case "RP-03":
                fixture.Add("dependency", ProjectRole.Foundation, boundary: violation ? "AGPL" : "Apache", license: violation ? "AGPL-3.0-only" : "Apache-2.0");
                fixture.Add("subject", ProjectRole.Foundation, references: ["dependency/dependency.csproj"], boundary: "Apache", license: "Apache-2.0");
                break;
            case "RP-04":
                // The mobile-licence rule is exercised on its own fixture; the real Cloud gate leaves MobileDistributable off.
                fixture.Add("subject", ProjectRole.Infrastructure, packages: new Dictionary<string, string> { ["Library"] = "1.0.0" });
                fixture.licences["Library"] = violation ? "GPL-3.0-only" : "MIT";
                fixture.mobile = true;
                break;
            case "RP-05":
                fixture.Add("subject", ProjectRole.Foundation);
                if (violation)
                {
                    fixture.SetProperty("ManagePackageVersionsCentrally", "false");
                }

                break;
            case "RP-06":
                fixture.Add("subject", ProjectRole.Foundation);
                if (violation)
                {
                    File.WriteAllText(Path.Combine(fixture.root, "global.json"), "{}");
                }

                break;
            case "RP-07":
                fixture.Add("subject", ProjectRole.Foundation);
                if (violation)
                {
                    fixture.SetProperty("SuppressTrimAnalysisWarnings", "true");
                }

                break;
            case "RP-10":
                fixture.Add("subject", ProjectRole.Foundation, "public static class Api { public static int Value() => 1; }");
                if (violation)
                {
                    fixture.contractTests.Clear();
                }

                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(rule), rule, "Unknown policy rule.");
        }

        return fixture;
    }

    private bool mobile;

    public IReadOnlyList<PolicyFinding> Check() => PolicyEngine.Check(
        new RepositoryFacts(root, CloudRepository.Owner, Projects, Exceptions, contractTests),
        new RepositoryPolicyConfiguration(SourceCommit, toolchain, licences, new HashSet<string>(StringComparer.Ordinal) { "MIT", "Apache-2.0" },
            services, wireTypes, Evidence, MobileDistributable: mobile, DependencyRoles: DependencyRoles),
        compilations, new DateOnly(2026, 10, 4));

    public void Replace(string project, string source) => compilations[project] = Compile(Path.GetFileNameWithoutExtension(project), source);

    public void ReplaceTestAttribute(string attribute) => Replace(TestProject,
        "namespace FixtureTests; public class Contracts { [" + attribute + "] public void Verify() {} }");

    public void SetDomainLayer(ProjectRole role)
    {
        int index = Projects.FindIndex(project => project.Classification.Role == ProjectRole.Domain);
        Projects[index] = Projects[index] with { Classification = Projects[index].Classification with { Role = role } };
    }

    public void AddDomainPackage(string package, ProjectRole role)
    {
        int index = Projects.FindIndex(project => project.Classification.Role is ProjectRole.Domain or ProjectRole.Application);
        Projects[index] = Projects[index] with { Packages = new Dictionary<string, string> { [package] = "1.0.0" } };
        licences[package] = "MIT";
        DependencyRoles[package] = role;
    }

    public void AddCallback(string declaration) => Add("callback", ProjectRole.Foundation,
        declaration + " public class Api { public Callback? Value { get; } }");

    public void AddCollidingApi() => Add("collision", ProjectRole.Foundation,
        "namespace FixtureTests; public class Contracts { public System.IntPtr Handle() => default; }");

    public void Dispose()
    {
        string expectedParent = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
        if (Path.GetDirectoryName(root) != expectedParent || !Path.GetFileName(root).StartsWith("arcforges-cloud-policy-", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Unexpected fixture cleanup path.");
        }

        Directory.Delete(root, recursive: true);
    }

    private static CSharpCompilation Compile(string name, string source) => FixtureCompiler.Compile(name,
        new Dictionary<string, string> { [name + ".cs"] = source }, [typeof(Xunit.FactAttribute).Assembly.Location]);

    private void SetProperty(string name, string value)
    {
        int index = Projects.Count - 1;
        var properties = new Dictionary<string, string>(Projects[index].Properties, StringComparer.Ordinal) { [name] = value };
        Projects[index] = Projects[index] with { Properties = properties };
    }

    private void Add(string name, ProjectRole role, string source = "internal sealed class Empty {}", string[]? references = null,
        string owner = CloudRepository.Owner, string module = "", bool production = true, string license = "AGPL-3.0-only",
        string boundary = "AGPL", Dictionary<string, string>? packages = null)
    {
        string path = name + "/" + name + ".csproj";
        string directory = Path.Combine(root, name);
        Directory.CreateDirectory(directory);
        File.WriteAllText(Path.Combine(root, path), "<Project />");
        packages ??= new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        File.WriteAllText(Path.Combine(directory, "packages.lock.json"), JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["version"] = 1,
            ["dependencies"] = new Dictionary<string, object>
            {
                ["net10.0"] = packages.ToDictionary(package => package.Key, package => new Dictionary<string, string> { ["type"] = "Direct", ["resolved"] = package.Value }),
            },
        }));
        foreach (string package in packages.Keys)
        {
            licences.TryAdd(package, "MIT");
        }

        Projects.Add(new ProjectFacts(new ProjectClassification(path, role, owner, module, production), "net10.0", "Library", license, boundary,
            references ?? [], [name + ".cs"], [], new Dictionary<string, string>(StringComparer.Ordinal)
            {
                ["ManagePackageVersionsCentrally"] = "true",
                ["RestorePackagesWithLockFile"] = "true",
                ["EnableTrimAnalyzer"] = "true",
                ["EnableAotAnalyzer"] = "true",
            }, packages));
        var compilation = Compile(name, source);
        compilations.Add(path, compilation);
        if (!production)
        {
            return;
        }

        foreach (var tree in compilation.SyntaxTrees)
        {
            var model = compilation.GetSemanticModel(tree);
            foreach (var method in tree.GetRoot().DescendantNodes().OfType<MethodDeclarationSyntax>())
            {
                if (model.GetDeclaredSymbol(method) is IMethodSymbol symbol && symbol.DeclaredAccessibility == Accessibility.Public)
                {
                    contractTests.Add(new(PolicyEngine.MethodIdentity(symbol), TestProject, "FixtureTests.Contracts.Verify()"));
                }
            }
        }
    }
}
