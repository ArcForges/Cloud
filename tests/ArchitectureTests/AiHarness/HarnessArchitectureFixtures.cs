// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.Json.Nodes;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>
/// One pass or refuse fixture of the ported AI policy suite (HAR.40 validation (d)). A pass fixture yields no finding for any rule; a refuse
/// fixture yields a finding of its own rule. The fixture set is the AI policy's 84 fixtures (27 pass, 57 refuse), each keeping the AI rule,
/// kind and name, applied to the Cloud layout: the Worker entry is worker/index.ts, the Workers AI adapter is worker/ai/internal, and the AI
/// src/ files become worker/ files. <see cref="Name"/> is the AI fixture name.
/// </summary>
internal sealed record AiFixture(string Rule, string Kind, string Name, Func<IReadOnlyList<HarnessFinding>> Run);

/// <summary>The fixtures of the GOV.10 successor rules: the AI policy fixtures ported one-for-one, and the earlier C# refusals.</summary>
internal static partial class HarnessArchitectureFixtures
{
    private const string Pin = "1.0.0-ci.287.1";
    private static readonly string Integrity = "sha512-" + new string('A', 86) + "==";
    private const string Task = "src/ArcForges.Cloud.Modules.Task/ArcForges.Cloud.Modules.Task.csproj";
    private const string Identity = "src/ArcForges.Cloud.Modules.Identity/ArcForges.Cloud.Modules.Identity.csproj";
    private const string Abstractions = "src/ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj";
    private const string ArchitectureHost = "tests/ArchitectureTests/ArcForges.Cloud.ArchitectureTests.csproj";

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    private static string Csproj(string sdk, string body) =>
        "<Project Sdk=\"" + sdk + "\">\n" + body + "\n</Project>\n";

    private static string Module(string name, string references = "", string extra = "") =>
        Csproj("Microsoft.NET.Sdk",
            "  <PropertyGroup>\n    <LicenceBoundary>AGPL</LicenceBoundary>\n  </PropertyGroup>\n  <ItemGroup>\n" + references + extra + "  </ItemGroup>");

    private static string Reference(string path) => "    <ProjectReference Include=\"" + path + "\" />\n";

    private static string Package(string id, bool privateAssets = false) =>
        "    <PackageReference Include=\"" + id + "\"" + (privateAssets ? " PrivateAssets=\"all\"" : string.Empty) + " />\n";

    /// <summary>The clean repository: every rule yields no finding on it.</summary>
    public static Dictionary<string, string> Baseline() => new(StringComparer.Ordinal)
    {
        ["Directory.Build.props"] = "<Project>\n  <PropertyGroup>\n    <PackageLicenseExpression>AGPL-3.0-only</PackageLicenseExpression>\n  </PropertyGroup>\n</Project>\n",
        ["Directory.Packages.props"] =
            "<Project>\n  <ItemGroup>\n    <PackageVersion Include=\"ArcForges.Contracts.PublicApi\" Version=\"1.0.0-ci.287.1\" />\n"
            + "    <PackageVersion Include=\"ArcForges.Contracts.Validation\" Version=\"1.0.0-ci.205.1\" />\n"
            + "    <PackageVersion Include=\"Grpc.Net.Client\" Version=\"2.84.0\" />\n  </ItemGroup>\n</Project>\n",
        ["package.json"] = Manifest(),
        ["package-lock.json"] = Lock(),
        ["wrangler.json"] = Wrangler(),
        ["eng/policy/licence-boundary.json"] = Inventory(),
        ["eng/policy/naming-candidate.json"] = Candidate(),
        ["artifacts/evidence/naming.json"] = "{ \"policySha256\": \"f5d596298ec50e3b116abc6df1b34efef93045ed52f6235b0a2aaaf97a1f4df5\", \"repositories\": [ { \"repository\": \"Cloud\", \"status\": \"pass\", \"findings\": [] } ] }",
        [ArchitectureHost] = Csproj("Microsoft.NET.Sdk", "  <PropertyGroup>\n    <LicenceBoundary>AGPL</LicenceBoundary>\n  </PropertyGroup>\n  <ItemGroup>\n" + Package("ArcForges.Contracts.Validation", privateAssets: true) + "  </ItemGroup>"),
        [Abstractions] = Module("Abstractions"),
        [Task] = Module("Task", Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj")),
        [Identity] = Module("Identity", Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj")),
        ["src/ArcForges.Cloud.Modules.Task/Harness/Clock.cs"] = "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Clock\n{\n    internal static long Ticks(long a, long b) => a + b;\n}\n",
        ["worker/index.ts"] = "import { version } from \"./ai/internal/envelope.ts\";\nimport { sayHello } from \"./hello.ts\";\n\nexport const entry = [version, sayHello(\"x\")];\n",
        ["worker/hello.ts"] = Hello,
        ["worker/deployment.ts"] = "export const note = \"uses only plain values\";\n",
        ["worker/ai/internal/envelope.ts"] = "export const version = 1;\n",
        ["worker/ai/internal/handler.ts"] = Handler(),
        ["worker/harness/run-alarm.ts"] = "import { version } from \"../ai/internal/envelope.ts\";\n\nexport const alarm = version;\n",
    };

    private const string Hello =
        "import { SayHelloRequestSchema } from \"@arcforges/proto\";\n"
        + "import { create, fromBinary, toBinary } from \"@bufbuild/protobuf\";\n"
        + "export function sayHello(name: string) {\n"
        + "  const request = create(SayHelloRequestSchema, { name });\n"
        + "  return fromBinary(SayHelloRequestSchema, toBinary(SayHelloRequestSchema, request)).name;\n"
        + "}\n";

    /// <summary>The Workers AI adapter: the inference binding is called here, and only here.</summary>
    private static string Handler(string extra = "") =>
        "import { version } from \"./envelope.ts\";\n" + extra
        + "\nexport async function requestTool(ai: Ai, name: string) {\n"
        + "  return ai.run(\"model\", { messages: [name, version] });\n"
        + "}\n\nexport const handle = (env: unknown) => env && version;\n";

    private static string Manifest(Action<JsonObject>? edit = null)
    {
        var manifest = new JsonObject
        {
            ["name"] = "@arcforges/cloud-workspace",
            ["license"] = "AGPL-3.0-only",
            ["arcforges"] = new JsonObject { ["licenceBoundary"] = "AGPL" },
            ["dependencies"] = new JsonObject { ["@arcforges/ai-internal"] = Pin, ["@arcforges/proto"] = Pin, ["@bufbuild/protobuf"] = "2.15.0" },
            ["devDependencies"] = new JsonObject { ["wrangler"] = "4.143.1" },
        };
        edit?.Invoke(manifest);
        return manifest.ToJsonString(Indented);
    }

    private static string Lock(Action<JsonObject>? editPackages = null)
    {
        var packages = new JsonObject
        {
            [""] = new JsonObject
            {
                ["dependencies"] = new JsonObject { ["@arcforges/ai-internal"] = Pin, ["@arcforges/proto"] = Pin, ["@bufbuild/protobuf"] = "2.15.0" },
                ["devDependencies"] = new JsonObject { ["wrangler"] = "4.143.1" },
            },
            ["node_modules/@arcforges/proto"] = new JsonObject
            {
                ["version"] = Pin,
                ["resolved"] = "https://registry.npmjs.org/@arcforges/proto/-/proto-" + Pin + ".tgz",
                ["integrity"] = Integrity,
                ["license"] = "Apache-2.0",
            },
            ["node_modules/@arcforges/ai-internal"] = new JsonObject { ["version"] = Pin, ["license"] = "Apache-2.0" },
            ["node_modules/@bufbuild/protobuf"] = new JsonObject { ["version"] = "2.15.0", ["license"] = "(Apache-2.0 AND BSD-3-Clause)" },
            ["node_modules/wrangler"] = new JsonObject { ["version"] = "4.143.1", ["license"] = "MIT", ["dev"] = true },
        };
        editPackages?.Invoke(packages);
        return new JsonObject { ["lockfileVersion"] = 3, ["packages"] = packages }.ToJsonString(Indented);
    }

    private static string Wrangler(Action<JsonObject>? edit = null)
    {
        var wrangler = new JsonObject
        {
            ["name"] = "arcforges-cloud",
            ["main"] = "worker/index.ts",
            ["workers_dev"] = false,
            ["preview_urls"] = false,
            ["ai"] = new JsonObject { ["binding"] = "AI" },
            ["env"] = new JsonObject { ["proof"] = new JsonObject { ["workers_dev"] = false, ["preview_urls"] = false } },
        };
        edit?.Invoke(wrangler);
        return wrangler.ToJsonString(Indented);
    }

    private static string Candidate(Action<JsonObject>? edit = null)
    {
        var candidate = new JsonObject
        {
            ["package"] = NamingCandidate.PackageId,
            ["ecosystem"] = "nuget",
            ["version"] = NamingCandidate.Version,
            ["sourceCommit"] = NamingCandidate.SourceCommit,
            ["archiveSha512"] = NamingCandidate.ArchiveSha512,
            ["publication"] = "https://github.com/ArcForges/Contracts/actions/runs/36356146302",
            ["assets"] = new JsonObject
            {
                [NamingCandidate.ScannerPath] = NamingCandidate.ScannerSha256,
                [NamingCandidate.PolicyPath] = NamingCandidate.PolicySha256,
            },
        };
        edit?.Invoke(candidate);
        return candidate.ToJsonString(Indented);
    }

    /// <summary>The licence inventory: the npm manifests named, and the C# projects of the baseline.</summary>
    private static string Inventory(params string[] npm)
    {
        var rows = new JsonArray();
        var manifests = npm.Length == 0 ? new[] { "package.json" } : npm;
        foreach (var path in manifests) rows.Add(new JsonObject { ["path"] = path, ["kind"] = "npm" });
        foreach (var path in new[] { Abstractions, Task, Identity, ArchitectureHost }) rows.Add(new JsonObject { ["path"] = path, ["kind"] = "msbuild" });
        return new JsonObject
        {
            ["schemaVersion"] = 1,
            ["repository"] = "Cloud",
            ["spdxLicense"] = "AGPL-3.0-only",
            ["licenceBoundary"] = "AGPL",
            ["projects"] = rows,
        }.ToJsonString(Indented);
    }

    private static Action<Dictionary<string, string>> Put(string path, string text) => files => files[path] = text;

    private static Action<Dictionary<string, string>> All(params Action<Dictionary<string, string>>[] edits) => files =>
    {
        foreach (var edit in edits) edit(files);
    };

    private static IReadOnlyList<HarnessFinding> Run(Action<Dictionary<string, string>>? edit, HarnessAuditOptions? options)
    {
        var files = Baseline();
        edit?.Invoke(files);
        return HarnessArchitecture.Audit(files, options);
    }

    private static AiFixture Pass(string rule, string name, Action<Dictionary<string, string>>? edit = null, HarnessAuditOptions? options = null) =>
        new(rule, "pass", name, () => Run(edit, options));

    private static AiFixture Fail(string rule, string name, Action<Dictionary<string, string>>? edit = null, HarnessAuditOptions? options = null) =>
        new(rule, "fail", name, () => Run(edit, options));

    /// <summary>The naming-identity fixtures run against a candidate record and the pinned publication.</summary>
    private static AiFixture Naming(string kind, string name, Action<JsonObject>? adjust) =>
        new("naming-identity", kind, name, () => Run(Put("eng/policy/naming-candidate.json", Candidate(adjust)), null));

    private static readonly string[] Npm = ["package.json"];

    /// <summary>
    /// The AI policy's 84 fixtures, in their AI order. Each carries the AI rule, kind and name; the Cloud path of each is noted where it
    /// differs from the AI layout. Passing fixtures are near misses of the refused construct, not unrelated files.
    /// </summary>
    public static IReadOnlyList<AiFixture> AiFixtures() =>
    [
        // WP-05.00
        Pass("layer-cycle", "diamond import without a cycle", All(
            Put("worker/ai/internal/diamond-a.ts", "import \"./diamond-b.ts\";\nimport \"./diamond-c.ts\";\nexport const a = 1;\n"),
            Put("worker/ai/internal/diamond-b.ts", "import \"./diamond-d.ts\";\nexport const b = 1;\n"),
            Put("worker/ai/internal/diamond-c.ts", "import \"./diamond-d.ts\";\nexport const c = 1;\n"),
            Put("worker/ai/internal/diamond-d.ts", "export const d = 1;\n"))),
        Fail("layer-cycle", "two modules import each other", All(
            Put("worker/ai/internal/hello.ts", "import \"./handler.ts\";\nexport const hello = 1;\n"),
            Put("worker/ai/internal/handler.ts", Handler("import \"./hello.ts\";\n")))),
        Pass("layer-entry", "entry imports modules"),
        Fail("layer-entry", "a module imports the Workflow entry", Put("worker/ai/internal/deployment.ts", "import \"../../index.ts\";\nexport const d = 1;\n")),
        Pass("layer-escape", "tests import Worker source", Put("tests/worker/hello.test.ts", "import { sayHello } from \"../../worker/hello.ts\";\nsayHello(\"x\");\n")),
        Fail("layer-escape", "Worker source imports a test helper", All(
            Put("worker/deployment.ts", "import \"../tests/worker/helper.ts\";\n"),
            Put("tests/worker/helper.ts", "export const helper = 1;\n"))),
        Fail("layer-escape", "Worker source imports a sibling checkout", Put("worker/deployment.ts", "import \"../../../../Cloud/src/billing\";\n")),
        Pass("layer-runtime-dependency", "Workers module and declared runtime package", Put("worker/deployment.ts",
            "import { NonRetryableError } from \"cloudflare:workers\";\nimport { create } from \"@bufbuild/protobuf\";\nvoid NonRetryableError;\nvoid create;\n")),
        Fail("layer-runtime-dependency", "Worker source imports a development tool", Put("worker/deployment.ts", "import \"vitest\";\n")),
        Fail("layer-runtime-dependency", "Worker source imports a Node built-in", Put("worker/deployment.ts",
            "import { readFileSync } from \"node:fs\";\nvoid readFileSync;\n")),
        Pass("layer-product-reference", "public wire package"),
        Fail("layer-product-reference", "private internal package declared", Put("package.json", Manifest(m => m["dependencies"]!.AsObject()["@arcforges/cloud-internal"] = "1.0.0"))),
        Fail("layer-product-reference", "private internal package imported", Put("worker/deployment.ts", "import \"@arcforges/cloud-internal\";\n")),
        Pass("layer-business-authority", "AI, Workflow and version bindings only"),
        Fail("layer-business-authority", "D1 database binding", All(
            Put("wrangler.json", Wrangler(m => m["d1_databases"] = new JsonArray(new JsonObject { ["binding"] = "DB" }))),
            Put("worker/ai/internal/handler.ts", Handler("\nexport const store = (env: { DB: unknown }) => env.DB;\n")))),
        Fail("layer-business-authority", "R2 store type in Worker source", Put("worker/ai/internal/deployment.ts", "export interface Env { BUCKET: R2Bucket }\n")),
        Pass("layer-public-exposure", "private Worker"),
        Fail("layer-public-exposure", "workers.dev enabled", Put("wrangler.json", "{ \"workers_dev\": true, \"preview_urls\": false }")),
        Fail("layer-public-exposure", "public route", Put("wrangler.json", Wrangler(m => m["routes"] = new JsonArray("example.invalid/*")))),

        // WP-05.01
        Pass("licence-declaration", "complete declaration and inventory"),
        Fail("licence-declaration", "no SPDX identifier", Put("package.json", Manifest(m => m.Remove("license")))),
        Fail("licence-declaration", "no boundary", Put("package.json", Manifest(m => m.Remove("arcforges")))),
        Fail("licence-declaration", "manifest absent from the inventory", Put("tools/package.json",
            "{ \"name\": \"tool\", \"license\": \"AGPL-3.0-only\", \"arcforges\": { \"licenceBoundary\": \"AGPL\" } }")),
        Pass("licence-boundary-set", "empty Apache set"),
        Fail("licence-boundary-set", "an unlisted Apache-boundary project", Put("package.json", Manifest(m =>
        {
            m["license"] = "Apache-2.0";
            m["arcforges"] = new JsonObject { ["licenceBoundary"] = "Apache" };
        }))),
        Fail("licence-boundary-set", "AGPL boundary with another licence", Put("package.json", Manifest(m => m["license"] = "MIT"))),
        Pass("licence-cross-boundary", "AGPL project referencing an AGPL project", All(
            Put("package.json", Manifest(m => m["dependencies"]!.AsObject()["@arcforges/tool"] = "1.0.0")),
            Put("tools/package.json", "{ \"name\": \"@arcforges/tool\", \"license\": \"AGPL-3.0-only\", \"arcforges\": { \"licenceBoundary\": \"AGPL\" } }"),
            Put("eng/policy/licence-boundary.json", Inventory("package.json", "tools/package.json")))),
        Fail("licence-cross-boundary", "Apache project referencing the AGPL project", All(
            Put("sdk/package.json", "{ \"name\": \"@arcforges/sdk\", \"license\": \"Apache-2.0\", \"arcforges\": { \"licenceBoundary\": \"Apache\" }, \"dependencies\": { \"@arcforges/cloud-workspace\": \"1.0.0\" } }"),
            Put("eng/policy/licence-boundary.json", Inventory("package.json", "sdk/package.json")))),
        Pass("licence-allowlist", "OR expression with an allowed alternative", Put("package-lock.json", Lock(p =>
            p["node_modules/dual"] = new JsonObject { ["version"] = "1.0.0", ["license"] = "(MIT OR GPL-3.0-only)" }))),
        Pass("licence-allowlist", "LGPL in a development-only tool", Put("package-lock.json", Lock(p =>
            p["node_modules/tool"] = new JsonObject { ["version"] = "1.0.0", ["license"] = "LGPL-3.0-or-later", ["dev"] = true }))),
        Fail("licence-allowlist", "GPL-only dependency", Put("package-lock.json", Lock(p =>
            p["node_modules/gpl"] = new JsonObject { ["version"] = "1.0.0", ["license"] = "GPL-3.0-only" }))),
        Fail("licence-allowlist", "LGPL in the shipped runtime closure", Put("package-lock.json", Lock(p =>
            p["node_modules/lgpl"] = new JsonObject { ["version"] = "1.0.0", ["license"] = "LGPL-3.0-or-later" }))),
        Fail("licence-allowlist", "dependency without a licence", Put("package-lock.json", Lock(p =>
            p["node_modules/none"] = new JsonObject { ["version"] = "1.0.0" }))),

        // WP-05.02
        Naming("pass", "candidate equals the installed published assets", null),
        Naming("fail", "changed scanner bytes", c => c["assets"]!.AsObject()[NamingCandidate.ScannerPath] = new string('d', 64)),
        Naming("fail", "changed policy bytes", c => c["assets"]!.AsObject()[NamingCandidate.PolicyPath] = new string('e', 64)),
        Naming("fail", "version differs from the pin", c => c["version"] = "1.0.0-ci.2.1"),
        Naming("fail", "producer commit differs from source.json", c => c["sourceCommit"] = new string('f', 40)),
        Naming("fail", "extra asset", c => c["assets"]!.AsObject()["tools/naming/extra.py"] = new string('a', 64)),
        Naming("fail", "publication outside the producer", c => c["publication"] = "https://example.invalid/runs/1"),

        // WP-05.03
        Pass("wire-package", "exact registry-locked candidate"),
        Fail("wire-package", "floating selector", Put("package.json", Manifest(m => m["dependencies"]!.AsObject()["@arcforges/proto"] = "^" + Pin))),
        Fail("wire-package", "non-registry tarball", Put("package-lock.json", Lock(p =>
            p["node_modules/@arcforges/proto"] = new JsonObject
            {
                ["version"] = Pin,
                ["resolved"] = "https://example.invalid/proto.tgz",
                ["integrity"] = Integrity,
                ["license"] = "Apache-2.0",
            }))),
        Fail("wire-package", "declared only as a development dependency", Put("package.json", Manifest(m =>
        {
            m["dependencies"]!.AsObject().Remove("@arcforges/proto");
            m["devDependencies"]!.AsObject()["@arcforges/proto"] = Pin;
        }))),
        Pass("wire-import", "package root"),
        Fail("wire-import", "build output subpath", Put("worker/deployment.ts",
            "import { SayHelloRequestSchema } from \"@arcforges/proto/dist/index.js\";\nvoid SayHelloRequestSchema;\n")),
        Pass("wire-source", "application code"),
        Fail("wire-source", "copied generated module", Put("worker/gen/hello_pb.ts", "export const copied = 1;\n")),
        Fail("wire-source", "authored schema file", Put("proto/hello.proto", "syntax = \"proto3\";\n")),
        Fail("wire-source", "protoc output header", Put("worker/deployment.ts", "// @generated by protoc-gen-es v2\nexport const copied = 1;\n")),
        Pass("wire-codec", "generated schema through the runtime"),
        Fail("wire-codec", "wire reader import", Put("worker/deployment.ts",
            "import { BinaryReader } from \"@bufbuild/protobuf/wire\";\nvoid BinaryReader;\n")),
        Fail("wire-codec", "alternative runtime", Put("worker/deployment.ts", "import \"protobufjs\";\n")),
        Fail("wire-codec", "manual varint masks", Put("worker/deployment.ts", "export const low = (byte: number) => (byte & 0x7f) | 0x80;\n")),
        Pass("wire-schema", "schema imported from the published package"),
        Fail("wire-schema", "locally defined schema", Put("worker/deployment.ts",
            "import { fromBinary } from \"@bufbuild/protobuf\";\nconst localSchema = {};\nexport const decode = (bytes: Uint8Array) => fromBinary(localSchema as never, bytes);\n")),
        Pass("wire-shadow", "unrelated local type", Put("worker/deployment.ts", "export interface HelloParams { name: string }\n"),
            new HarnessAuditOptions(new HashSet<string>(StringComparer.Ordinal) { "SayHelloRequest" })),
        Fail("wire-shadow", "local redefinition of a generated message", Put("worker/deployment.ts", "export interface SayHelloRequest { name: string }\n"),
            new HarnessAuditOptions(new HashSet<string>(StringComparer.Ordinal) { "SayHelloRequest" })),

        // WP-05.04
        Pass("banned-reflection", "ordinary object keys", Put("worker/deployment.ts", "export const k = Object.keys({});\n")),
        Fail("banned-reflection", "Reflect entry point", Put("worker/deployment.ts", "export const k = Reflect.ownKeys({});\n")),
        Fail("banned-reflection", "prototype mutation", Put("worker/deployment.ts", "export const k = (o: object) => Object.setPrototypeOf(o, null);\n")),
        Pass("banned-dynamic-code", "banned names only in strings and comments", Put("worker/deployment.ts",
            "// eval and new Function are text here\nexport const note = \"eval(Function)\";\n")),
        Fail("banned-dynamic-code", "Function constructor", Put("worker/deployment.ts", "export const f = new Function(\"return 1\");\n")),
        Fail("banned-dynamic-code", "eval", Put("worker/deployment.ts", "export const f = () => eval(\"1\");\n")),
        Fail("banned-dynamic-code", "computed import", Put("worker/deployment.ts", "export const load = (name: string) => import(`./${name}`);\n")),
        Pass("banned-blocking-wait", "asynchronous timer", Put("worker/deployment.ts",
            "export const wait = () => new Promise((done) => setTimeout(done, 10));\n")),
        Fail("banned-blocking-wait", "Atomics.wait", Put("worker/deployment.ts", "export const wait = (cell: Int32Array) => Atomics.wait(cell, 0, 0);\n")),
        Fail("banned-blocking-wait", "synchronous host call", Put("worker/deployment.ts",
            "export const read = (fs: { readFileSync(path: string): string }) => fs.readFileSync(\"x\");\n")),
        Fail("banned-blocking-wait", "clock busy-wait", Put("worker/deployment.ts", "export const spin = () => { while (Date.now() < 5) {} };\n")),
        Pass("banned-provider-sdk", "adapter uses the Workers AI binding"),
        Fail("banned-provider-sdk", "provider SDK import", Put("worker/deployment.ts", "import \"openai\";\n")),
        Fail("banned-provider-sdk", "direct provider endpoint", Put("worker/deployment.ts",
            "export const url = \"https://api.anthropic.com/v1/messages\";\n")),
        Pass("banned-provider-call", "binding called inside the adapter"),
        Fail("banned-provider-call", "binding called outside the adapter", Put("worker/deployment.ts",
            "export const call = (env: { AI: Ai }) => env.AI.run(\"model\", {});\n")),
        Pass("banned-secret-logging", "static status message", Put("worker/deployment.ts", "console.log(\"started\");\n")),
        Fail("banned-secret-logging", "logging a token", Put("worker/deployment.ts", "const token = 'x'; console.log(token);\n")),
        Fail("banned-secret-logging", "logging the whole environment", Put("worker/deployment.ts", "console.log(this.env);\n")),
        Fail("banned-secret-logging", "logging inside a template", Put("worker/deployment.ts",
            "const prompt = 'x'; console.error(`failed: ${prompt}`);\n")),
        Pass("banned-float-money", "integer minor units", Put("worker/deployment.ts", "export const priceCents = BigInt(100);\n")),
        Fail("banned-float-money", "parseFloat on an amount", Put("worker/deployment.ts", "export const amount = parseFloat(\"1.5\");\n")),
        Fail("banned-float-money", "number-typed credit balance", Put("worker/deployment.ts", "export const creditBalance: number = 1;\n")),
        Pass("banned-raw-memory", "managed buffer", Put("worker/deployment.ts", "export const b = new ArrayBuffer(8);\n")),
        Fail("banned-raw-memory", "shared buffer", Put("worker/deployment.ts", "export const b = new SharedArrayBuffer(8);\n")),
        Fail("banned-raw-memory", "WebAssembly memory", Put("worker/deployment.ts", "export const m = new WebAssembly.Memory({ initial: 1 });\n")),
    ];

    /// <summary>
    /// The refusals of the earlier C# port, kept as their own theory: each is the clean baseline with one aimed defect in a C# project, a
    /// manifest or a Worker file. Every case names the rule it must raise.
    /// </summary>
    public static IReadOnlyList<(string Rule, string Case, IReadOnlyDictionary<string, string> Sources)> CSharpRefusals() => CSharpRefusalList().Select(r => (r.Rule, r.Case, (IReadOnlyDictionary<string, string>)r.Build())).ToList();

    private static IEnumerable<(string Rule, string Case, Func<Dictionary<string, string>> Build)> CSharpRefusalList()
    {
        Dictionary<string, string> With(Dictionary<string, string> sources, string path, string content)
        {
            sources[path] = content;
            return sources;
        }

        yield return ("layer-cycle", "projects", () => With(With(Baseline(), Task, Module("Task", Reference("../ArcForges.Cloud.Modules.Identity/ArcForges.Cloud.Modules.Identity.csproj"))), Identity, Module("Identity", Reference("../ArcForges.Cloud.Modules.Task/ArcForges.Cloud.Modules.Task.csproj"))));
        yield return ("layer-entry", "source-references-host", () => With(Baseline(), Task, Module("Task", Reference("../ArcForges.Cloud/ArcForges.Cloud.csproj"))));
        yield return ("layer-escape", "project-leaves-repository", () => With(Baseline(), Task, Module("Task", Reference("../../../../Contracts/src/Foo.csproj"))));
        yield return ("layer-escape", "worker-url-import", () => With(Baseline(), "worker/ai/internal/handler.ts", "import { x } from \"https://example.invalid/x.js\";\nexport const h = x;\n"));
        yield return ("layer-runtime-dependency", "undeclared-package", () => With(Baseline(), Task, Module("Task", Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj"), Package("Left.Pad"))));
        yield return ("layer-product-reference", "desktop-package", () => With(Baseline(), Task, Module("Task", Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj"), Package("ArcForges.Desktop.Core"))));
        yield return ("layer-product-reference", "worker-other-owner", () => With(Baseline(), "worker/ai/internal/handler.ts", "import { x } from \"@arcforges/desktop-core\";\nexport const h = x;\n"));
        yield return ("layer-business-authority", "module-to-module", () => With(Baseline(), Task, Module("Task", Reference("../ArcForges.Cloud.Modules.Identity/ArcForges.Cloud.Modules.Identity.csproj"))));
        yield return ("layer-business-authority", "adapter-store-type", () => With(Baseline(), "worker/ai/internal/handler.ts", "export const h = (db: D1Database) => db;\n"));
        yield return ("layer-public-exposure", "workers-dev-enabled", () => With(Baseline(), "wrangler.json", "{ \"name\": \"cloud\", \"workers_dev\": true, \"preview_urls\": false }"));
        yield return ("licence-declaration", "no-boundary", () => With(Baseline(), Task, Csproj("Microsoft.NET.Sdk", "  <ItemGroup>\n" + Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj") + "  </ItemGroup>")));
        yield return ("licence-boundary-set", "undeclared-apache", () => With(Baseline(), Task, Csproj("Microsoft.NET.Sdk", "  <PropertyGroup>\n    <LicenceBoundary>Apache</LicenceBoundary>\n  </PropertyGroup>")));
        yield return ("licence-cross-boundary", "apache-to-agpl", () => With(Baseline(), Task, Csproj("Microsoft.NET.Sdk", "  <PropertyGroup>\n    <LicenceBoundary>Apache</LicenceBoundary>\n  </PropertyGroup>\n  <ItemGroup>\n" + Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj") + "  </ItemGroup>")));
        yield return ("licence-boundary-set", "csproj-agpl-with-lgpl", () => With(Baseline(), Task, Csproj("Microsoft.NET.Sdk", "  <PropertyGroup>\n    <LicenceBoundary>AGPL</LicenceBoundary>\n    <PackageLicenseExpression>LGPL-3.0-only</PackageLicenseExpression>\n  </PropertyGroup>")));
        yield return ("licence-allowlist", "lgpl-in-source", () => With(Baseline(), Task, Csproj("Microsoft.NET.Sdk", "  <PropertyGroup>\n    <LicenceBoundary>AGPL</LicenceBoundary>\n    <PackageLicenseExpression>(AGPL-3.0-only AND LGPL-3.0-only)</PackageLicenseExpression>\n  </PropertyGroup>")));
        yield return ("naming-identity", "central-pin", () => With(Baseline(), "Directory.Packages.props", Baseline()["Directory.Packages.props"].Replace("Validation\" Version=\"1.0.0-ci.205.1", "Validation\" Version=\"1.0.0-ci.204.1", StringComparison.Ordinal)));
        yield return ("naming-scan", "report-with-findings", () => With(Baseline(), "artifacts/evidence/naming.json", "{ \"policySha256\": \"f5d596298ec50e3b116abc6df1b34efef93045ed52f6235b0a2aaaf97a1f4df5\", \"repositories\": [ { \"repository\": \"Cloud\", \"status\": \"fail\", \"findings\": [ { \"name\": \"fixture-term\" } ] } ] }"));
        yield return ("naming-scan", "report-missing", () => { var s = Baseline(); s.Remove("artifacts/evidence/naming.json"); return s; });
        yield return ("wire-package", "two-contract-versions", () => With(Baseline(), "Directory.Packages.props", Baseline()["Directory.Packages.props"].Replace("Grpc.Net.Client", "ArcForges.Contracts.Events\" Version=\"1.0.0-ci.205.1\" /> <PackageVersion Include=\"Grpc.Net.Client", StringComparison.Ordinal)));
        yield return ("wire-import", "compile-outside-project", () => With(Baseline(), Task, Csproj("Microsoft.NET.Sdk", "  <ItemGroup>\n    <Compile Include=\"..\\..\\..\\Contracts\\src\\Foo.cs\" />\n  </ItemGroup>")));
        yield return ("wire-import", "worker-deep-proto", () => With(Baseline(), "worker/ai/internal/handler.ts", "import { x } from \"@arcforges/proto/src/index.ts\";\nexport const h = x;\n"));
        yield return ("wire-source", "copied-pb-source", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Hello.pb.cs", "// copied\n"));
        yield return ("wire-codec", "varint-writer", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Codec.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Codec\n{\n    internal static void WriteVarint(ulong value) { }\n}\n"));
        yield return ("wire-codec", "protobufjs-import", () => With(Baseline(), "worker/ai/internal/handler.ts", "import { Reader } from \"protobufjs\";\nexport const h = Reader;\n"));
        yield return ("wire-schema", "handwritten-message", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Hello.cs", "using Google.Protobuf;\n\nnamespace ArcForges.Cloud.Modules.Task;\n\ninternal sealed class Hello : IMessage<Hello> { }\n"));
        yield return ("wire-shadow", "generated-namespace", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Shadow.cs", "namespace ArcForges.Contracts.Hello;\n\ninternal sealed class Request { }\n"));
        yield return ("banned-reflection", "activator", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Loader.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Loader\n{\n    internal static object Make(System.Type t) => System.Activator.CreateInstance(t)!;\n}\n"));
        yield return ("banned-reflection", "emit-namespace", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Emit.cs", "using System.Reflection.Emit;\n\nnamespace ArcForges.Cloud.Modules.Task;\n\ninternal sealed class Emit { }\n"));
        yield return ("banned-dynamic-code", "dynamic-local", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Dyn.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Dyn\n{\n    internal static void Run() { dynamic d = 1; }\n}\n"));
        yield return ("banned-dynamic-code", "worker-eval", () => With(Baseline(), "worker/ai/internal/handler.ts", "export const h = eval(\"1\");\n"));
        yield return ("banned-blocking-wait", "task-result", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Wait.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Wait\n{\n    internal static int Run(System.Threading.Tasks.Task<int> task) => task.Result;\n}\n"));
        yield return ("banned-provider-sdk", "provider-package", () => With(Baseline(), Task, Module("Task", Reference("../ArcForges.Cloud.Modules.Abstractions/ArcForges.Cloud.Modules.Abstractions.csproj"), Package("OpenAI"))));
        yield return ("banned-provider-call", "binding-outside-adapter", () => With(Baseline(), "worker/harness/run-alarm.ts", "export const run = (env: { AI: { run(x: string): unknown } }) => env.AI.run(\"model\");\n"));
        yield return ("banned-secret-logging", "console-api-key", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Log.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Log\n{\n    internal static void Write(string apiKey) => System.Console.WriteLine(apiKey);\n}\n"));
        yield return ("banned-secret-logging", "worker-console-prompt", () => With(Baseline(), "worker/ai/internal/handler.ts", "export const h = (prompt: string) => console.log(prompt);\n"));
        yield return ("banned-float-money", "double-price", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Money.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal static class Money\n{\n    internal static double Total() { double priceTotal = 1.0; return priceTotal; }\n}\n"));
        yield return ("banned-float-money", "worker-number-amount", () => With(Baseline(), "worker/ai/internal/handler.ts", "export const h = (amount: number) => amount;\n"));
        yield return ("banned-raw-memory", "unsafe-class", () => With(Baseline(), "src/ArcForges.Cloud.Modules.Task/Raw.cs", "namespace ArcForges.Cloud.Modules.Task;\n\ninternal unsafe class Raw { }\n"));
        yield return ("banned-raw-memory", "worker-linear-memory", () => With(Baseline(), "worker/ai/internal/handler.ts", "export const m = new WebAssembly.Memory({ initial: 1 });\n"));
    }
}
