// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace ArcForges.Cloud.ArchitectureTests.AiHarness;

/// <summary>The rule bodies of the GOV.10 successor (one method per obligation family).</summary>
internal static partial class HarnessArchitecture
{
    private const string Adapter = "worker/ai/internal/";
    private const string Harness = "worker/harness/";
    private const string AlarmFile = "worker/harness/run-alarm.ts";
    private const string ApacheBoundary = "Apache";
    private const string AgplBoundary = "AGPL";

    private static readonly Regex TsSpecifier = new(
        @"(?:\bimport\s+(?:type\s+)?(?:[^'""`;]*?\s+from\s+)?|\bexport\s+[^'""`;]*?\s+from\s+|\bimport\s*\(\s*|\brequire\s*\(\s*)['""]([^'""]+)['""]",
        RegexOptions.CultureInvariant);

    private static readonly Regex TsComputedImport = new(@"\bimport\s*\(\s*(?!['""])", RegexOptions.CultureInvariant);

    private static readonly Regex ProviderPackage = new(
        @"^(?:openai|@openai/|@anthropic-ai/|@google/(?:genai|generative-ai)|@google-cloud/(?:vertexai|aiplatform)|@mistralai/|@aws-sdk/client-bedrock|@azure/openai|cohere-ai|groq-sdk|ollama|replicate|together-ai|langchain|@langchain/|ai$|@ai-sdk/)",
        RegexOptions.CultureInvariant);

    private static readonly Regex ProviderNuget = new(
        @"^(?:OpenAI|Anthropic|Mistral|Cohere|Groq|Ollama|Replicate|Azure\.AI\.OpenAI|Google\.Cloud\.AIPlatform|Amazon\.BedrockRuntime|AWSSDK\.BedrockRuntime|LangChain)(?:\.|$)",
        RegexOptions.CultureInvariant);

    private static readonly Regex ProviderHost = new(
        @"(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.cohere\.(?:ai|com)|api\.mistral\.ai|api\.groq\.com|openrouter\.ai|api\.together\.xyz|api\.replicate\.com|bedrock-runtime|api\.cloudflare\.com/client/v4/accounts/[^/]+/ai)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex WireCodecPackage = new(
        @"^(?:@bufbuild/protobuf/(?:wire|codegenv\d+|reflect)(?:/|$)|protobufjs(?:/|$)|google-protobuf(?:/|$)|@protobuf-ts/|ts-proto|pbf$|long$)",
        RegexOptions.CultureInvariant);

    private static readonly Regex SensitiveName = new(
        @"secret|token|passw|credential|api[_-]?key|authoriz|cookie|session|prompt|messages?|content|conversation|completion|transcript|payload|^env$|^headers$|^request$|^body$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex ReflectionCall = new(@"\b(?:Activator\.CreateInstance|Assembly\.Load(?:From|File)?|Type\.GetType|DynamicMethod|ILGenerator)\b", RegexOptions.CultureInvariant);

    private static readonly Regex LoggingCall = new(@"(?:^|\.)(?:Console\.Write\w*|Debug\.Write\w*|Trace\.Write\w*)$|(?:^|\.)Log\w*$", RegexOptions.CultureInvariant);

    private static readonly Regex TsLogging = new(@"\bconsole\.(?:log|info|warn|error|debug)\s*\(([^)]*)\)", RegexOptions.CultureInvariant);

    private static readonly Regex TsMoneyNumber = new(@"\b(\w*(?:credit|price|amount|cost|balance|money|charge|fee|billing|payment|refund|tax|currency)\w*)\s*:\s*number\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private static readonly Regex TsSyncHost = new(@"\bAtomics\.wait\s*\(|\breadFileSync\s*\(|\bexecSync\s*\(|\bspawnSync\s*\(", RegexOptions.CultureInvariant);

    private static readonly Regex TsRawMemory = new(@"\bnew\s+WebAssembly\.Memory\s*\(|\bWebAssembly\.Memory\b", RegexOptions.CultureInvariant);

    private static readonly Regex TsDynamicCode = new(@"\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['""]", RegexOptions.CultureInvariant);

    private static readonly Regex TsProviderCall = new(@"\benv\.AI\b", RegexOptions.CultureInvariant);

    private static readonly Regex TsForbiddenAuthority = new(@"\b(?:D1Database|R2Bucket|KVNamespace|Hyperdrive|Queue)\b", RegexOptions.CultureInvariant);

    private static readonly string[] MoneyParts =
    [
        "credit", "credits", "balance", "balances", "money", "price", "prices", "amount", "amounts", "cost", "costs", "charge", "charges",
        "billing", "currency", "fee", "fees", "invoice", "payment", "payments", "refund", "usd", "cent", "cents", "tax",
    ];

    private static readonly string[] WireCodecNames = ["CodedOutputStream", "CodedInputStream", "WireFormat", "WriteVarint", "ReadVarint", "WriteTag", "ReadTag", "WriteRawVarint32"];

    private static readonly string[] ProviderNamespaces = ["OpenAI", "Anthropic", "Mistral", "Cohere", "Groq", "Ollama", "Replicate", "LangChain"];

    // ---------------------------------------------------------------- WP-05.00 layering

    private static void LayerRules(Context c)
    {
        // layer-cycle: the project graph (resolved references among audited projects) must be acyclic.
        var graph = c.Projects.ToDictionary(
            p => p.Key,
            p => p.Value.ProjectReferences.Where(r => r.Resolved is not null && c.Projects.ContainsKey(r.Resolved)).Select(r => r.Resolved!).ToList(),
            StringComparer.Ordinal);
        foreach (var cycle in FindCycles(graph))
        {
            c.Report("layer-cycle", cycle[0], "Project reference cycle: " + string.Join(" -> ", cycle));
        }

        // layer-cycle: the Worker import graph must be acyclic too.
        var worker = c.WorkerTypeScript.ToDictionary(entry => entry.Key, entry => WorkerImports(entry.Key, entry.Value, c.Sources), StringComparer.Ordinal);
        foreach (var cycle in FindCycles(worker))
        {
            c.Report("layer-cycle", cycle[0], "Worker import cycle: " + string.Join(" -> ", cycle));
        }

        // layer-entry: no source project references the host entry.
        foreach (var project in c.Projects.Values.Where(p => p.Path.StartsWith("src/", StringComparison.Ordinal)))
        {
            if (project.ProjectReferences.Any(r => r.Resolved == Entry))
            {
                c.Report("layer-entry", project.Path, "References the host entry " + Entry);
            }
        }

        // layer-escape: references stay inside the repository and are not absolute or URL paths; Worker imports are not URLs or absolute.
        foreach (var project in c.Projects.Values)
        {
            foreach (var reference in project.ProjectReferences.Where(r => r.Resolved is null))
            {
                c.Report("layer-escape", project.Path, "Project reference leaves the repository: " + reference.Raw);
            }
        }

        foreach (var (file, text) in c.WorkerTypeScript)
        {
            foreach (var specifier in Specifiers(text))
            {
                if (Regex.IsMatch(specifier, "^(?:[a-z][a-z\\d+.-]*://|file:|/|[A-Za-z]:)", RegexOptions.IgnoreCase))
                {
                    c.Report("layer-escape", file, "External or absolute import: " + specifier);
                }
            }
        }

        // layer-runtime-dependency: source projects use only centrally declared packages.
        var central = c.CentralPackages();
        foreach (var project in c.Projects.Values.Where(p => p.Path.StartsWith("src/", StringComparison.Ordinal)))
        {
            foreach (var package in project.PackageReferences.Where(p => !central.ContainsKey(p.Id)))
            {
                c.Report("layer-runtime-dependency", project.Path, "Package is not centrally declared: " + package.Id);
            }
        }

        // layer-runtime-dependency: the Worker imports only declared runtime dependencies and the Workers platform modules.
        var runtime = RuntimeDependencies(c);
        foreach (var (file, text) in c.WorkerTypeScript)
        {
            foreach (var specifier in Specifiers(text).Where(s => !s.StartsWith(".", StringComparison.Ordinal)))
            {
                if (specifier.StartsWith("cloudflare:", StringComparison.Ordinal) || specifier.StartsWith("node:", StringComparison.Ordinal))
                {
                    continue;
                }

                if (!runtime.Contains(PackageName(specifier)))
                {
                    c.Report("layer-runtime-dependency", file, "Import is not a declared runtime dependency: " + specifier);
                }
            }
        }

        // layer-product-reference: other owners are referenced only through the published Contracts packages.
        foreach (var project in c.Projects.Values.Where(p => p.Path.StartsWith("src/", StringComparison.Ordinal)))
        {
            foreach (var package in project.PackageReferences.Where(p => p.Id.StartsWith("ArcForges.", StringComparison.Ordinal)))
            {
                if (package.Id == NamingCandidate.PackageId || !package.Id.StartsWith("ArcForges.Contracts.", StringComparison.Ordinal))
                {
                    c.Report("layer-product-reference", project.Path, "Unadmitted ArcForges package in source: " + package.Id);
                }
            }
        }

        foreach (var (file, text) in c.WorkerTypeScript)
        {
            foreach (var specifier in Specifiers(text).Where(s => s.StartsWith("@arcforges/", StringComparison.Ordinal)))
            {
                if (specifier != "@arcforges/ai-internal" && specifier != "@arcforges/proto" && !specifier.StartsWith("@arcforges/proto/", StringComparison.Ordinal))
                {
                    c.Report("layer-product-reference", file, "Unadmitted ArcForges import: " + specifier);
                }
            }
        }

        // layer-business-authority: a module references only its abstractions; the Worker adapters hold no business store type.
        foreach (var project in c.Projects.Values.Where(p => p.Path.StartsWith("src/ArcForges.Cloud.Modules.", StringComparison.Ordinal)
            && !p.Path.StartsWith("src/ArcForges.Cloud.Modules.Abstractions/", StringComparison.Ordinal)))
        {
            foreach (var reference in project.ProjectReferences.Where(r => r.Resolved is not null && !r.Resolved.StartsWith("src/ArcForges.Cloud.Modules.Abstractions/", StringComparison.Ordinal)
                && !r.Resolved.StartsWith(ModuleFolder(project.Path), StringComparison.Ordinal)))
            {
                c.Report("layer-business-authority", project.Path, "Module references a non-abstraction project: " + reference.Raw);
            }
        }

        foreach (var (file, text) in c.WorkerTypeScript.Where(entry => entry.Key.StartsWith(Adapter, StringComparison.Ordinal) || entry.Key.StartsWith(Harness, StringComparison.Ordinal)))
        {
            foreach (Match match in TsForbiddenAuthority.Matches(text))
            {
                c.Report("layer-business-authority", file, "Business store authority in an adapter: " + match.Value);
            }

            if (file != AlarmFile && Regex.IsMatch(text, @"\bDurableObject\b"))
            {
                c.Report("layer-business-authority", file, "Durable Object lifecycle is held only by the run alarm");
            }
        }

        // layer-public-exposure: the Worker has no workers.dev or preview exposure, at the top level or in any environment.
        var wrangler = c.Text("wrangler.json");
        if (wrangler is null)
        {
            c.Report("layer-public-exposure", "wrangler.json", "Worker configuration is missing");
            return;
        }

        using var document = JsonDocument.Parse(wrangler);
        var environments = new List<(string Name, JsonElement Element)> { ("top", document.RootElement) };
        if (document.RootElement.TryGetProperty("env", out var env) && env.ValueKind == JsonValueKind.Object)
        {
            environments.AddRange(env.EnumerateObject().Select(e => ("env." + e.Name, e.Value)));
        }

        foreach (var (name, element) in environments)
        {
            foreach (var key in new[] { "workers_dev", "preview_urls" })
            {
                if (!element.TryGetProperty(key, out var value) || value.ValueKind != JsonValueKind.False)
                {
                    if (element.TryGetProperty(key, out _) || name == "top")
                    {
                        c.Report("layer-public-exposure", "wrangler.json", name + " " + key + " must be false");
                    }
                }
            }
        }
    }

    // ---------------------------------------------------------------- WP-05.01 licence

    private static void LicenceRules(Context c)
    {
        var inventoryText = c.Text("eng/policy/licence-boundary.json");
        var declared = c.Projects.Values.Where(p => p.Path.StartsWith("src/", StringComparison.Ordinal) || p.Path.StartsWith("tests/", StringComparison.Ordinal)).ToList();

        // licence-declaration: every project declares its boundary and an SPDX expression; the inventory lists exactly these projects.
        foreach (var project in declared)
        {
            if (project.Boundary is null) c.Report("licence-declaration", project.Path, "Project declares no LicenceBoundary");
            if (project.Licence is null) c.Report("licence-declaration", project.Path, "Project declares no PackageLicenseExpression");
            else if (project.Licence != "AGPL-3.0-only" && project.Boundary != ApacheBoundary) c.Report("licence-declaration", project.Path, "Licence differs from the AGPL boundary: " + project.Licence);
        }

        if (inventoryText is not null)
        {
            using var inventory = JsonDocument.Parse(inventoryText);
            var listed = inventory.RootElement.GetProperty("projects").EnumerateArray()
                .Where(p => p.GetProperty("kind").GetString() == "msbuild").Select(p => p.GetProperty("path").GetString()!).ToHashSet(StringComparer.Ordinal);
            foreach (var project in declared.Where(p => p.Path.EndsWith(".csproj", StringComparison.Ordinal) && !listed.Contains(p.Path)))
            {
                c.Report("licence-declaration", project.Path, "Project is not in the licence inventory");
            }
        }

        // licence-boundary-set: the Apache boundary is exactly the enumerated set (empty for Cloud).
        var apache = declared.Where(p => p.Boundary == ApacheBoundary).Select(p => p.Path).ToHashSet(StringComparer.Ordinal);
        foreach (var path in apache.Except(ApacheBoundaryProjects, StringComparer.Ordinal))
        {
            c.Report("licence-boundary-set", path, "Apache boundary is not enumerated");
        }

        foreach (var path in ApacheBoundaryProjects.Except(apache, StringComparer.Ordinal))
        {
            c.Report("licence-boundary-set", path, "Enumerated Apache boundary is not declared");
        }

        // licence-cross-boundary: no Apache-boundary project references an AGPL project.
        foreach (var project in declared.Where(p => p.Boundary == ApacheBoundary))
        {
            foreach (var reference in project.ProjectReferences.Where(r => r.Resolved is not null && c.Projects.ContainsKey(r.Resolved)))
            {
                if (c.Projects[reference.Resolved!].Boundary != ApacheBoundary)
                {
                    c.Report("licence-cross-boundary", project.Path, "Apache-boundary project references AGPL project: " + reference.Raw);
                }
            }
        }

        // licence-allowlist: every declared licence token is allowed for the boundary; LGPL is development-only and never shipped.
        foreach (var project in declared.Where(p => p.Licence is not null))
        {
            var allowed = project.Boundary == ApacheBoundary ? AllowedApache : AllowedAgpl;
            foreach (var token in Regex.Matches(project.Licence!, @"[A-Za-z0-9.+-]+").Select(m => m.Value).Where(t => t is not ("AND" or "OR" or "WITH")))
            {
                if (token.StartsWith("LGPL", StringComparison.Ordinal) && project.Path.StartsWith("src/", StringComparison.Ordinal))
                {
                    c.Report("licence-allowlist", project.Path, "LGPL is development-only and ships in source: " + token);
                }
                else if (!allowed.Contains(token) && !token.StartsWith("LGPL", StringComparison.Ordinal))
                {
                    c.Report("licence-allowlist", project.Path, "Licence is not allowed for the boundary: " + token);
                }
            }
        }
    }

    // ---------------------------------------------------------------- WP-05.02 naming

    private static void NamingRules(Context c)
    {
        // naming-identity: the candidate record is the exact NuGet identity, centrally pinned and locked as a build-only reference.
        var candidateText = c.Text("eng/policy/naming-candidate.json");
        if (candidateText is null)
        {
            c.Report("naming-identity", "eng/policy/naming-candidate.json", "The naming candidate record is missing");
        }
        else
        {
            using var candidate = JsonDocument.Parse(candidateText);
            var root = candidate.RootElement;
            var assets = root.GetProperty("assets");
            var exact =
                root.GetProperty("package").GetString() == NamingCandidate.PackageId
                && root.GetProperty("ecosystem").GetString() == "nuget"
                && root.GetProperty("version").GetString() == NamingCandidate.Version
                && root.GetProperty("sourceCommit").GetString() == NamingCandidate.SourceCommit
                && root.GetProperty("archiveSha512").GetString() == NamingCandidate.ArchiveSha512
                && assets.GetProperty(NamingCandidate.ScannerPath).GetString() == NamingCandidate.ScannerSha256
                && assets.GetProperty(NamingCandidate.PolicyPath).GetString() == NamingCandidate.PolicySha256;
            if (!exact) c.Report("naming-identity", "eng/policy/naming-candidate.json", "The candidate is not the pinned NuGet identity");
        }

        if (c.CentralPackages().GetValueOrDefault(NamingCandidate.PackageId) != NamingCandidate.Version)
        {
            c.Report("naming-identity", "Directory.Packages.props", "The naming candidate is not centrally pinned at the exact version");
        }

        var architecture = c.Projects.GetValueOrDefault("tests/ArchitectureTests/ArcForges.Cloud.ArchitectureTests.csproj");
        if (architecture is null || !architecture.PackageReferences.Any(p => p.Id == NamingCandidate.PackageId && p.PrivateAssets))
        {
            c.Report("naming-identity", "tests/ArchitectureTests/ArcForges.Cloud.ArchitectureTests.csproj", "The naming candidate is not a build-only reference of the architecture host");
        }

        // naming-scan: the checkout's scan report passed for Cloud under the pinned policy with zero findings.
        var reportText = c.Text(NamingReport);
        if (reportText is null)
        {
            c.Report("naming-scan", NamingReport, "The naming scan report is missing; run the policy gate first");
            return;
        }

        using var report = JsonDocument.Parse(reportText);
        var rows = report.RootElement.GetProperty("repositories").EnumerateArray().Where(r => r.GetProperty("repository").GetString() == "Cloud").ToList();
        if (rows.Count != 1 || rows[0].GetProperty("status").GetString() != "pass" || rows[0].GetProperty("findings").GetArrayLength() != 0)
        {
            c.Report("naming-scan", NamingReport, "The naming scan of Cloud did not pass with zero findings");
        }

        if (report.RootElement.GetProperty("policySha256").GetString() != NamingCandidate.PolicySha256)
        {
            c.Report("naming-scan", NamingReport, "The scan ran under another policy");
        }
    }

    // ---------------------------------------------------------------- WP-05.03 wire

    private static void WireRules(Context c)
    {
        // wire-package: every runtime Contracts package shares one exact version (the naming tool is build-only and excluded).
        var contracts = c.CentralPackages().Where(p => p.Key.StartsWith("ArcForges.Contracts.", StringComparison.Ordinal) && p.Key != NamingCandidate.PackageId)
            .Select(p => p.Value).Distinct(StringComparer.Ordinal).ToList();
        if (contracts.Count > 1)
        {
            c.Report("wire-package", "Directory.Packages.props", "Contracts runtime packages come from more than one version");
        }

        // wire-import: a project compiles only its own files, and the Worker imports the generated package at its root only.
        foreach (var project in c.Projects.Values)
        {
            var folder = project.Path[..project.Path.LastIndexOf('/')] + "/";
            foreach (var include in project.CompileIncludes)
            {
                var target = Project.Normalize(project.Path, include);
                if (target is null || !target.StartsWith(folder, StringComparison.Ordinal))
                {
                    c.Report("wire-import", project.Path, "Compiles a file outside its project folder: " + include);
                }
            }
        }

        foreach (var (file, text) in c.WorkerTypeScript)
        {
            foreach (var specifier in Specifiers(text).Where(s => s.StartsWith("@arcforges/proto/", StringComparison.Ordinal)))
            {
                c.Report("wire-import", file, "Deep import of the generated package: " + specifier);
            }
        }

        // wire-source: no copied generated source or schema file is authored in source or Worker folders.
        foreach (var path in c.Sources.Keys.Where(p => p.StartsWith("src/", StringComparison.Ordinal) || p.StartsWith("worker/", StringComparison.Ordinal)))
        {
            if (Regex.IsMatch(path, @"(?:\.pb\.cs|_pb\.cs|\.proto|\.binpb|\.pb\.ts|_pb\.ts)$", RegexOptions.CultureInvariant))
            {
                c.Report("wire-source", path, "Copied generated source or schema");
            }
        }

        // wire-codec: no handwritten or alternative wire codec in production C#; no protobuf codec package in the Worker.
        foreach (var (file, tree) in c.ProductionCSharp)
        {
            foreach (var token in tree.GetRoot().DescendantTokens().Where(t => t.IsKind(SyntaxKind.IdentifierToken) && WireCodecNames.Contains(t.ValueText, StringComparer.Ordinal)))
            {
                c.Report("wire-codec", file, "Handwritten wire codec primitive: " + token.ValueText);
            }
        }

        foreach (var (file, text) in c.WorkerTypeScript)
        {
            foreach (var specifier in Specifiers(text).Where(s => WireCodecPackage.IsMatch(s)))
            {
                c.Report("wire-codec", file, "Alternative wire codec import: " + specifier);
            }
        }

        // wire-schema: production C# does not implement the generated message contract itself.
        foreach (var (file, tree) in c.ProductionCSharp)
        {
            foreach (var declaration in tree.GetRoot().DescendantNodes().OfType<BaseTypeDeclarationSyntax>())
            {
                if (declaration.BaseList is { } list && list.Types.Any(t => t.ToString().Contains("IMessage", StringComparison.Ordinal)))
                {
                    c.Report("wire-schema", file, "Handwritten message implements the generated contract: " + declaration.Identifier.ValueText);
                }
            }
        }

        // wire-shadow: no production declaration sits in a generated Contracts namespace.
        foreach (var (file, tree) in c.ProductionCSharp)
        {
            foreach (var name in tree.GetRoot().DescendantNodes().OfType<BaseNamespaceDeclarationSyntax>().Select(n => n.Name.ToString()))
            {
                if (name == "ArcForges.Contracts" || name.StartsWith("ArcForges.Contracts.", StringComparison.Ordinal))
                {
                    c.Report("wire-shadow", file, "Declares a type in the generated namespace " + name);
                }
            }
        }
    }

    // ---------------------------------------------------------------- WP-05.04 banned

    private static void BannedRules(Context c)
    {
        foreach (var (file, tree) in c.ProductionCSharp)
        {
            var root = tree.GetRoot();

            // banned-reflection: no reflection emit, dynamic loading or reflective construction.
            foreach (var use in root.DescendantNodes().OfType<UsingDirectiveSyntax>().Where(u => u.Name?.ToString().StartsWith("System.Reflection.Emit", StringComparison.Ordinal) == true))
            {
                c.Report("banned-reflection", file, "Reflection emit namespace");
            }

            foreach (var invocation in root.DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                var text = invocation.Expression.ToString();
                if (ReflectionCall.IsMatch(text)) c.Report("banned-reflection", file, "Reflective call: " + text);
                if (text.EndsWith("Expression.Compile", StringComparison.Ordinal) || text.EndsWith("CSharpScript.EvaluateAsync", StringComparison.Ordinal))
                {
                    c.Report("banned-dynamic-code", file, "Runtime compilation: " + text);
                }

                // banned-blocking-wait: no sync-over-async wait or sync host call.
                if (text.EndsWith(".Wait", StringComparison.Ordinal) || text.EndsWith("GetAwaiter().GetResult", StringComparison.Ordinal) || text.EndsWith(".GetResult", StringComparison.Ordinal))
                {
                    c.Report("banned-blocking-wait", file, "Blocking wait: " + text);
                }

                // banned-secret-logging: no logging of a secret-bearing or content-bearing value.
                if (LoggingCall.IsMatch(text) && invocation.ArgumentList.DescendantTokens().Any(t => t.IsKind(SyntaxKind.IdentifierToken) && SensitiveName.IsMatch(t.ValueText)))
                {
                    c.Report("banned-secret-logging", file, "Logs a sensitive value through " + text);
                }

                // banned-raw-memory: no unmanaged memory helpers.
                if (text.Contains("Marshal.AllocHGlobal", StringComparison.Ordinal) || text.Contains("NativeMemory.", StringComparison.Ordinal))
                {
                    c.Report("banned-raw-memory", file, "Unmanaged memory: " + text);
                }
            }

            // A task result read is a blocking wait; a stored receipt named Result is not (a syntactic heuristic, a named limit).
            foreach (var member in root.DescendantNodes().OfType<MemberAccessExpressionSyntax>().Where(m => m.Name.Identifier.ValueText == "Result" && IsTaskLike(m.Expression)))
            {
                c.Report("banned-blocking-wait", file, "Blocking task result: " + member);
            }

            foreach (var identifier in root.DescendantTokens().Where(t => t.IsKind(SyntaxKind.IdentifierToken) && t.ValueText == "dynamic"))
            {
                c.Report("banned-dynamic-code", file, "Dynamic type at line " + (identifier.GetLocation().GetLineSpan().StartLinePosition.Line + 1));
            }

            // Pinned memory is raw memory; stackalloc yields a managed Span and is not raw memory.
            foreach (var node in root.DescendantNodes().Where(n => n.IsKind(SyntaxKind.FixedStatement)))
            {
                c.Report("banned-raw-memory", file, "Pinned memory: " + node.Kind());
            }

            foreach (var token in root.DescendantTokens().Where(t => t.IsKind(SyntaxKind.UnsafeKeyword)))
            {
                c.Report("banned-raw-memory", file, "Unsafe code at line " + (token.GetLocation().GetLineSpan().StartLinePosition.Line + 1));
            }

            foreach (var use in root.DescendantNodes().OfType<UsingDirectiveSyntax>().Where(u => ProviderNamespaces.Any(p => u.Name?.ToString().StartsWith(p, StringComparison.Ordinal) == true)))
            {
                c.Report("banned-provider-sdk", file, "Provider namespace: " + use.Name);
            }

            foreach (var literal in root.DescendantTokens().Where(t => t.IsKind(SyntaxKind.StringLiteralToken)).Where(t => ProviderHost.IsMatch(t.ValueText)))
            {
                c.Report("banned-provider-sdk", file, "Direct provider endpoint in source");
            }
        }

        foreach (var project in c.Projects.Values.Where(p => p.Path.StartsWith("src/", StringComparison.Ordinal)))
        {
            foreach (var package in project.PackageReferences.Where(p => ProviderNuget.IsMatch(p.Id)))
            {
                c.Report("banned-provider-sdk", project.Path, "Provider SDK package: " + package.Id);
            }
        }

        foreach (var (file, text) in c.WorkerTypeScript)
        {
            foreach (var specifier in Specifiers(text).Where(s => ProviderPackage.IsMatch(s)))
            {
                c.Report("banned-provider-sdk", file, "Provider SDK import: " + specifier);
            }

            if (ProviderHost.IsMatch(text)) c.Report("banned-provider-sdk", file, "Direct provider endpoint in the Worker");
            if (TsDynamicCode.IsMatch(text) || TsComputedImport.IsMatch(text)) c.Report("banned-dynamic-code", file, "Dynamic code or computed import");
            if (TsSyncHost.IsMatch(text)) c.Report("banned-blocking-wait", file, "Synchronous host call on the Worker path");
            if (TsRawMemory.IsMatch(text)) c.Report("banned-raw-memory", file, "Raw linear memory handle");
            if (!file.StartsWith(Adapter, StringComparison.Ordinal) && TsProviderCall.IsMatch(text))
            {
                c.Report("banned-provider-call", file, "The Workers AI binding is used outside the ai.internal adapter");
            }

            foreach (Match match in TsLogging.Matches(text))
            {
                if (SensitiveName.IsMatch(match.Groups[1].Value))
                {
                    c.Report("banned-secret-logging", file, "Logs a sensitive value: " + match.Groups[1].Value.Trim());
                }
            }

            foreach (Match match in TsMoneyNumber.Matches(text))
            {
                c.Report("banned-float-money", file, "Money value typed as number: " + match.Groups[1].Value);
            }
        }

        // banned-float-money: production C# declares money values in decimal only.
        foreach (var (file, tree) in c.ProductionCSharp)
        {
            var root = tree.GetRoot();
            foreach (var declaration in root.DescendantNodes().OfType<VariableDeclarationSyntax>().Where(d => IsFloating(d.Type)))
            {
                foreach (var variable in declaration.Variables.Where(v => IsMoney(v.Identifier.ValueText)))
                {
                    c.Report("banned-float-money", file, "Floating money value: " + variable.Identifier.ValueText);
                }
            }

            foreach (var parameter in root.DescendantNodes().OfType<ParameterSyntax>().Where(p => p.Type is not null && IsFloating(p.Type) && IsMoney(p.Identifier.ValueText)))
            {
                c.Report("banned-float-money", file, "Floating money parameter: " + parameter.Identifier.ValueText);
            }

            foreach (var property in root.DescendantNodes().OfType<PropertyDeclarationSyntax>().Where(p => IsFloating(p.Type) && IsMoney(p.Identifier.ValueText)))
            {
                c.Report("banned-float-money", file, "Floating money property: " + property.Identifier.ValueText);
            }
        }
    }

    // ---------------------------------------------------------------- helpers

    private static bool IsFloating(TypeSyntax type) =>
        type.ToString() is "double" or "float" or "Double" or "Single" or "System.Double" or "System.Single";

    private static bool IsMoney(string identifier)
    {
        var parts = Regex.Replace(identifier, "([a-z\\d])([A-Z])", "$1_$2").ToLowerInvariant().Split(['_', '$'], StringSplitOptions.RemoveEmptyEntries);
        return parts.Any(part => MoneyParts.Contains(part, StringComparer.Ordinal));
    }

    private static string ModuleFolder(string path) => path[..(path.LastIndexOf('/') + 1)];

    /// <summary>True for an expression that can name a task: a call, or a name ending in task.</summary>
    private static bool IsTaskLike(ExpressionSyntax expression) =>
        expression is InvocationExpressionSyntax || expression.ToString().EndsWith("task", StringComparison.OrdinalIgnoreCase);

    private static IReadOnlyList<string> Specifiers(string text) =>
        TsSpecifier.Matches(text).Select(m => m.Groups[1].Value).ToList();

    private static string PackageName(string specifier) =>
        specifier.StartsWith("@", StringComparison.Ordinal) ? string.Join('/', specifier.Split('/').Take(2)) : specifier.Split('/')[0];

    private static HashSet<string> RuntimeDependencies(Context c)
    {
        var result = new HashSet<string>(StringComparer.Ordinal);
        var text = c.Text("package.json");
        if (text is null) return result;
        using var document = JsonDocument.Parse(text);
        if (document.RootElement.TryGetProperty("dependencies", out var dependencies))
        {
            foreach (var property in dependencies.EnumerateObject()) result.Add(property.Name);
        }

        return result;
    }

    /// <summary>The relative Worker imports of one file, resolved to the audited Worker files (only in-repository edges).</summary>
    private static List<string> WorkerImports(string file, string text, IReadOnlyDictionary<string, string> sources)
    {
        var edges = new List<string>();
        foreach (var specifier in Specifiers(text).Where(s => s.StartsWith(".", StringComparison.Ordinal)))
        {
            var stem = Project.Normalize(file, specifier.Replace(".js", ".ts", StringComparison.Ordinal).Replace(".mjs", ".ts", StringComparison.Ordinal));
            if (stem is null) continue;
            var target = new[] { stem, stem + ".ts", stem + "/index.ts" }.FirstOrDefault(t => sources.ContainsKey(t));
            if (target is not null) edges.Add(target);
        }

        return edges;
    }

    /// <summary>Every cycle found by a depth-first walk, each as a closed list of nodes.</summary>
    private static List<List<string>> FindCycles(IReadOnlyDictionary<string, List<string>> graph)
    {
        var cycles = new List<List<string>>();
        var state = new Dictionary<string, int>(StringComparer.Ordinal);
        var stack = new List<string>();

        void Visit(string node)
        {
            state[node] = 1;
            stack.Add(node);
            foreach (var next in graph.GetValueOrDefault(node) ?? [])
            {
                if (!state.TryGetValue(next, out var seen))
                {
                    if (graph.ContainsKey(next)) Visit(next);
                }
                else if (seen == 1)
                {
                    var start = stack.IndexOf(next);
                    cycles.Add([.. stack.Skip(start), next]);
                }
            }

            stack.RemoveAt(stack.Count - 1);
            state[node] = 2;
        }

        foreach (var node in graph.Keys.OrderBy(k => k, StringComparer.Ordinal))
        {
            if (!state.ContainsKey(node)) Visit(node);
        }

        return cycles;
    }
}
