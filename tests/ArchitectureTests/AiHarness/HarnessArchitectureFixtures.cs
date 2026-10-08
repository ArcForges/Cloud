// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>
/// The pass and refuse fixtures of the GOV.10 successor rules. <see cref="Baseline"/> is clean for every rule; each refusal is the
/// baseline with one defect, and every defect is aimed at one rule, so a refusal proves that rule and no other.
/// </summary>
internal static class HarnessArchitectureFixtures
{
    private const string Task = "src/ArcForges.Cloud.Modules.Task/ArcForges.Cloud.Modules.Task.csproj";
    private const string Identity = "src/ArcForges.Cloud.Modules.Identity/ArcForges.Cloud.Modules.Identity.csproj";
    private const string Abstractions = "src/ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj";
    private const string ArchitectureHost = "tests/ArchitectureTests/ArcForges.Cloud.ArchitectureTests.csproj";

    private static string Csproj(string sdk, string body) =>
        "<Project Sdk=\"" + sdk + "\">\n" + body + "\n</Project>\n";

    private static string Module(string name, string references = "", string extra = "") =>
        Csproj("Microsoft.NET.Sdk",
            "  <PropertyGroup>\n    <LicenceBoundary>AGPL</LicenceBoundary>\n  </PropertyGroup>\n  <ItemGroup>\n" + references + extra + "  </ItemGroup>");

    private static string Abstraction() => Module("Abstractions");

    private static string Reference(string path) => "    <ProjectReference Include=\"" + path + "\" />\n";

    private static string Package(string id, bool privateAssets = false) =>
        "    <PackageReference Include=\"" + id + "\"" + (privateAssets ? " PrivateAssets=\"all\"" : string.Empty) + " />\n";

    /// <summary>The clean repository: every rule passes on it.</summary>
    public static Dictionary<string, string> Baseline() => new(StringComparer.Ordinal)
    {
        ["Directory.Build.props"] = "<Project>\n  <PropertyGroup>\n    <PackageLicenseExpression>AGPL-3.0-only</PackageLicenseExpression>\n  </PropertyGroup>\n</Project>\n",
        ["Directory.Packages.props"] =
            "<Project>\n  <ItemGroup>\n    <PackageVersion Include=\"ArcForges.Contracts.PublicApi\" Version=\"1.0.0-ci.287.1\" />\n"
            + "    <PackageVersion Include=\"ArcForges.Contracts.Validation\" Version=\"1.0.0-ci.205.1\" />\n"
            + "    <PackageVersion Include=\"Grpc.Net.Client\" Version=\"2.84.0\" />\n  </ItemGroup>\n</Project>\n",
        ["package.json"] = "{ \"name\": \"cloud\", \"dependencies\": { \"@arcforges/ai-internal\": \"1.0.0-ci.287.1\" }, \"devDependencies\": { \"wrangler\": \"4.143.1\" } }",
        ["wrangler.json"] = "{ \"name\": \"cloud\", \"workers_dev\": false, \"preview_urls\": false, \"env\": { \"proof\": { \"workers_dev\": false, \"preview_urls\": false } } }",
        ["eng/policy/licence-boundary.json"] =
            "{ \"schemaVersion\": 1, \"repository\": \"Cloud\", \"spdxLicense\": \"AGPL-3.0-only\", \"licenceBoundary\": \"AGPL\", \"projects\": [ { \"path\": \"package.json\", \"kind\": \"npm\" }, { \"path\": \"" + Task + "\", \"kind\": \"msbuild\" }, { \"path\": \"" + Identity + "\", \"kind\": \"msbuild\" }, { \"path\": \"" + Abstractions + "\", \"kind\": \"msbuild\" }, { \"path\": \"" + ArchitectureHost + "\", \"kind\": \"msbuild\" } ] }",
        ["eng/policy/naming-candidate.json"] =
            "{ \"package\": \"ArcForges.Contracts.Validation\", \"ecosystem\": \"nuget\", \"version\": \"1.0.0-ci.205.1\", \"sourceCommit\": \"696242d16034262ce8b7268e8d157cd0e5bee544\", \"archiveSha512\": \"OWvMF30zpN6ms2KlQCtax5P7TACrgK50Vb0drN5zy4iXgk2TZd+5UU+LDGaA2ioowA1EQIZx8ZUyRoayZaHadA==\", \"publication\": \"https://github.com/ArcForges/Contracts/actions/runs/36356146302\", \"assets\": { \"tools/naming/eng/check_naming.py\": \"7c4cd7041b8b53e1bfb6fc0016befcd50259ffaca512d389456e00d3c26d5eaf\", \"tools/naming/eng/policy/product-names.json\": \"f5d596298ec50e3b116abc6df1b34efef93045ed52f6235b0a2aaaf97a1f4df5\" } }",
        ["artifacts/evidence/naming.json"] = "{ \"policySha256\": \"f5d596298ec50e3b116abc6df1b34efef93045ed52f6235b0a2aaaf97a1f4df5\", \"repositories\": [ { \"repository\": \"Cloud\", \"status\": \"pass\", \"findings\": [] } ] }",
        [ArchitectureHost] = Csproj("Microsoft.NET.Sdk", "  <PropertyGroup>\n    <LicenceBoundary>AGPL</LicenceBoundary>\n  </PropertyGroup>\n  <ItemGroup>\n" + Package("ArcForges.Contracts.Validation", privateAssets: true) + "  </ItemGroup>"),
        [Abstractions] = Abstraction(),
        [Task] = Module("Task", Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj")),
        [Identity] = Module("Identity", Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj")),
        ["src/ArcForges.Cloud.Modules.Task/Harness/Clock.cs"] = "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Clock\n{\n    internal static long Ticks(long a, long b) => a + b;\n}\n",
        ["worker/ai/internal/envelope.ts"] = "export const version = 1;\n",
        ["worker/ai/internal/handler.ts"] = "import { version } from \"./envelope.ts\";\n\nexport const handle = (env: unknown) => env && version;\n",
        ["worker/harness/run-alarm.ts"] = "import { version } from \"../ai/internal/envelope.ts\";\n\nexport const alarm = version;\n",
    };

    /// <summary>Every refusal, named by its rule and case. The sources are the baseline with one aimed defect.</summary>
    public static IReadOnlyList<(string Rule, string Case, IReadOnlyDictionary<string, string> Sources)> Refusals() => RefusalList().Select(r => (r.Rule, r.Case, (IReadOnlyDictionary<string, string>)r.Build())).ToList();

    private static IEnumerable<(string Rule, string Case, Func<Dictionary<string, string>> Build)> RefusalList()
    {
        Dictionary<string, string> With(Dictionary<string, string> sources, string path, string content)
        {
            sources[path] = content;
            return sources;
        }

        // layer-cycle
        yield return ("layer-cycle", "projects", () =>
        {
            var sources = With(Baseline(), Task, Module("Task", Reference("../ArcForges.Cloud.Modules.Identity/ArcForges.Cloud.Modules.Identity.csproj")));
            return With(sources, Identity, Module("Identity", Reference("../ArcForges.Cloud.Modules.Task/ArcForges.Cloud.Modules.Task.csproj")));
        }
        );
        yield return ("layer-cycle", "worker-imports", () =>
        {
            var sources = With(Baseline(), "worker/ai/internal/a.ts", "import { b } from \"./b.ts\";\nexport const a = b;\n");
            return With(sources, "worker/ai/internal/b.ts", "import { a } from \"./a.ts\";\nexport const b = a;\n");
        }
        );

        // layer-entry
        yield return ("layer-entry", "source-references-host", () => With(Baseline(), Task, Module("Task", Reference("../ArcForges.Cloud/ArcForges.Cloud.csproj"))));

        // layer-escape
        yield return ("layer-escape", "project-leaves-repository", () => With(Baseline(), Task, Module("Task", Reference("../../../../Contracts/src/Foo.csproj"))));
        yield return ("layer-escape", "worker-url-import", () => With(Baseline(), "worker/ai/internal/handler.ts", "import { x } from \"https://example.invalid/x.js\";\nexport const h = x;\n"));

        // layer-runtime-dependency
        yield return ("layer-runtime-dependency", "undeclared-package", () => With(Baseline(), Task, Module("Task", Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj"), Package("Left.Pad"))));
        yield return ("layer-runtime-dependency", "worker-undeclared-import", () => With(Baseline(), "worker/ai/internal/handler.ts", "import { pad } from \"left-pad\";\nexport const h = pad;\n"));

        // layer-product-reference
        yield return ("layer-product-reference", "desktop-package", () => With(Baseline(), Task, Module("Task", Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj"), Package("ArcForges.Desktop.Core"))));
        yield return ("layer-product-reference", "worker-other-owner", () => With(Baseline(), "worker/ai/internal/handler.ts", "import { x } from \"@arcforges/desktop-core\";\nexport const h = x;\n"));

        // layer-business-authority
        yield return ("layer-business-authority", "module-to-module", () => With(Baseline(), Task, Module("Task", Reference("../ArcForges.Cloud.Modules.Identity/ArcForges.Cloud.Modules.Identity.csproj"))));
        yield return ("layer-business-authority", "adapter-store-type", () => With(Baseline(), "worker/ai/internal/handler.ts", "export const h = (db: D1Database) => db;\n"));

        // layer-public-exposure
        yield return ("layer-public-exposure", "workers-dev-enabled", () => With(Baseline(), "wrangler.json", "{ \"name\": \"cloud\", \"workers_dev\": true, \"preview_urls\": false }"));

        // licence-declaration
        yield return ("licence-declaration", "no-boundary", () => With(Baseline(), Task, Csproj("Microsoft.NET.Sdk", "  <ItemGroup>\n" + Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj") + "  </ItemGroup>")));

        // licence-boundary-set
        yield return ("licence-boundary-set", "undeclared-apache", () => With(Baseline(), Task, Csproj("Microsoft.NET.Sdk", "  <PropertyGroup>\n    <LicenceBoundary>Apache</LicenceBoundary>\n  </PropertyGroup>")));

        // licence-cross-boundary
        yield return ("licence-cross-boundary", "apache-to-agpl", () => With(Baseline(), Task, Csproj("Microsoft.NET.Sdk", "  <PropertyGroup>\n    <LicenceBoundary>Apache</LicenceBoundary>\n  </PropertyGroup>\n  <ItemGroup>\n" + Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj") + "  </ItemGroup>")));

        // licence-allowlist
        yield return ("licence-allowlist", "lgpl-in-source", () => With(Baseline(), Task, Csproj("Microsoft.NET.Sdk", "  <PropertyGroup>\n    <LicenceBoundary>AGPL</LicenceBoundary>\n    <PackageLicenseExpression>LGPL-3.0-only</PackageLicenseExpression>\n  </PropertyGroup>")));

        // naming-identity
        yield return ("naming-identity", "candidate-version", () => With(Baseline(), "eng/policy/naming-candidate.json", Baseline()["eng/policy/naming-candidate.json"].Replace("1.0.0-ci.205.1", "1.0.0-ci.129.1", StringComparison.Ordinal)));
        yield return ("naming-identity", "central-pin", () => With(Baseline(), "Directory.Packages.props", Baseline()["Directory.Packages.props"].Replace("Validation\" Version=\"1.0.0-ci.205.1", "Validation\" Version=\"1.0.0-ci.204.1", StringComparison.Ordinal)));

        // naming-scan
        yield return ("naming-scan", "report-with-findings", () => With(Baseline(), "artifacts/evidence/naming.json", "{ \"policySha256\": \"f5d596298ec50e3b116abc6df1b34efef93045ed52f6235b0a2aaaf97a1f4df5\", \"repositories\": [ { \"repository\": \"Cloud\", \"status\": \"fail\", \"findings\": [ { \"name\": \"fixture-term\" } ] } ] }"));
        yield return ("naming-scan", "report-missing", () => { var s = Baseline(); s.Remove("artifacts/evidence/naming.json"); return s; });

        // wire-package
        yield return ("wire-package", "two-contract-versions", () => With(Baseline(), "Directory.Packages.props", Baseline()["Directory.Packages.props"].Replace("Grpc.Net.Client", "ArcForges.Contracts.Events\" Version=\"1.0.0-ci.205.1\" /> <PackageVersion Include=\"Grpc.Net.Client", StringComparison.Ordinal)));

        // wire-import
        yield return ("wire-import", "compile-outside-project", () => With(Baseline(), Task, Csproj("Microsoft.NET.Sdk", "  <ItemGroup>\n    <Compile Include=\"..\\..\\..\\Contracts\\src\\Foo.cs\" />\n  </ItemGroup>")));
        yield return ("wire-import", "worker-deep-proto", () => With(Baseline(), "worker/ai/internal/handler.ts", "import { x } from \"@arcforges/proto/src/index.ts\";\nexport const h = x;\n"));

        // wire-source
        yield return ("wire-source", "copied-pb-source", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Hello.pb.cs", "// copied\n"));

        // wire-codec
        yield return ("wire-codec", "varint-writer", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Codec.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Codec\n{\n    internal static void WriteVarint(ulong value) { }\n}\n"));
        yield return ("wire-codec", "protobufjs-import", () => With(Baseline(), "worker/ai/internal/handler.ts", "import { Reader } from \"protobufjs\";\nexport const h = Reader;\n"));

        // wire-schema
        yield return ("wire-schema", "handwritten-message", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Hello.cs", "using Google.Protobuf;\n\nnamespace ArcForges.Cloud.Modules.Task;\n\ninternal sealed class Hello : IMessage<Hello> { }\n"));

        // wire-shadow
        yield return ("wire-shadow", "generated-namespace", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Shadow.cs", "namespace ArcForges.Contracts.Hello;\n\ninternal sealed class Request { }\n"));

        // banned-reflection
        yield return ("banned-reflection", "activator", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Loader.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Loader\n{\n    internal static object Make(System.Type t) => System.Activator.CreateInstance(t)!;\n}\n"));
        yield return ("banned-reflection", "emit-namespace", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Emit.cs", "using System.Reflection.Emit;\n\nnamespace ArcForges.Cloud.Modules.Task;\n\ninternal sealed class Emit { }\n"));

        // banned-dynamic-code
        yield return ("banned-dynamic-code", "dynamic-local", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Dyn.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Dyn\n{\n    internal static void Run() { dynamic d = 1; }\n}\n"));
        yield return ("banned-dynamic-code", "worker-eval", () => With(Baseline(), "worker/ai/internal/handler.ts", "export const h = eval(\"1\");\n"));

        // banned-blocking-wait
        yield return ("banned-blocking-wait", "task-result", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Wait.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Wait\n{\n    internal static int Run(System.Threading.Tasks.Task<int> task) => task.Result;\n}\n"));
        yield return ("banned-blocking-wait", "worker-sync-read", () => With(Baseline(), "worker/ai/internal/handler.ts", "import { readFileSync } from \"node:fs\";\nexport const h = readFileSync(\"x\");\n"));

        // banned-provider-sdk
        yield return ("banned-provider-sdk", "provider-package", () => With(Baseline(), Task, Module("Task", Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj"), Package("OpenAI"))));
        yield return ("banned-provider-sdk", "provider-endpoint", () => With(Baseline(), "worker/ai/internal/handler.ts", "export const url = \"https://api.openai.com/v1/chat\";\n"));

        // banned-provider-call
        yield return ("banned-provider-call", "binding-outside-adapter", () => With(Baseline(), "worker/harness/run-alarm.ts", "export const run = (env: { AI: { run(x: string): unknown } }) => env.AI.run(\"model\");\n"));

        // banned-secret-logging
        yield return ("banned-secret-logging", "console-api-key", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Log.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Log\n{\n    internal static void Write(string apiKey) => System.Console.WriteLine(apiKey);\n}\n"));
        yield return ("banned-secret-logging", "worker-console-prompt", () => With(Baseline(), "worker/ai/internal/handler.ts", "export const h = (prompt: string) => console.log(prompt);\n"));

        // banned-float-money
        yield return ("banned-float-money", "double-price", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Money.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Money\n{\n    internal static double Total() { double priceTotal = 1.0; return priceTotal; }\n}\n"));
        yield return ("banned-float-money", "worker-number-amount", () => With(Baseline(), "worker/ai/internal/handler.ts", "export const h = (amount: number) => amount;\n"));

        // banned-raw-memory
        yield return ("banned-raw-memory", "unsafe-class", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Raw.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal unsafe class Raw { }\n"));
        yield return ("banned-raw-memory", "worker-linear-memory", () => With(Baseline(), "worker/ai/internal/handler.ts", "export const m = new WebAssembly.Memory({ initial: 1 });\n"));
    }
}
