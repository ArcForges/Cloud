// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ArcForges.Cloud;

/// <summary>Offline support information from compiled metadata and embedded, source-bound inputs.</summary>
public static partial class BuildIdentity
{
    public static readonly string[] AxisNames = ["AppVersion", "ContractSet", "CapabilityVersion", "NativeFormatVersion",
        "StorageSchemaVersion", "NativeAbiVersion", "PolicySchemaVersion", "ExtensionProtocolVersion", "PackageVersion"];
    private static readonly string[] Kinds = ["release", "contracts", "declarations", "declarations", "migrations",
        "native-abi", "declarations", "declarations", "packages"];

    public static JsonObject FromAssembly(Assembly assembly)
    {
        var metadata = assembly.GetCustomAttributes<AssemblyMetadataAttribute>().ToDictionary(a => a.Key, a => a.Value, StringComparer.Ordinal);
        string Field(string key) => metadata["ArcForges." + key] ?? throw new InvalidOperationException("Missing compiled build identity.");
        var version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion.Split('+')[0];
        var kind = Field("BuildKind");
        var id = Field("BuildId");
        var build = new JsonObject
        {
            ["sourceCommit"] = Field("SourceCommit"),
            ["dirty"] = bool.Parse(Field("Dirty")),
            ["kind"] = kind,
            ["buildId"] = id,
            ["runId"] = kind == "ci" ? id.Split('.')[0] : null,
            ["runAttempt"] = kind == "ci" ? int.Parse(id.Split('.')[1], CultureInfo.InvariantCulture) : (int?)null,
            ["pipelineRun"] = kind == "ci" ? Field("PipelineRun") : null,
            ["sourceDateEpoch"] = long.Parse(Field("SourceDateEpoch"), CultureInfo.InvariantCulture)
        };
        string Resource(string name)
        {
            using var stream = assembly.GetManifestResourceStream("Cloud." + name) ?? throw new InvalidOperationException("Missing embedded source: " + name);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            return reader.ReadToEnd();
        }
        var inputs = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["assembly/release.json"] = new JsonObject { ["versions"] = new JsonArray(new JsonObject { ["subject"] = "Cloud", ["version"] = version }) }.ToJsonString(),
            ["packages/contracts/source.json"] = Resource("ContractsSource"),
            ["src/ArcForges.Cloud/packages.lock.json"] = Resource("PackageLock"),
            ["package-lock.json"] = Resource("NpmLock")
        };
        ValidateBuild(build);
        return new JsonObject
        {
            ["schema"] = "arcforges.build-identity.v1",
            ["owner"] = "Cloud",
            ["artifact"] = new JsonObject { ["id"] = "Cloud", ["version"] = version },
            ["build"] = build,
            ["axes"] = Resolve(JsonNode.Parse(Resource("VersionSources"))!.AsObject(), path => inputs[path])
        };
    }

    public static JsonObject Resolve(JsonObject catalog, Func<string, string> read)
    {
        Require(catalog["schemaVersion"]!.GetValue<int>() == 1 && catalog["owner"]!.GetValue<string>() == "Cloud", "Wrong source catalog.");
        var definitions = catalog["axes"]!.AsObject();
        Require(definitions.Select(p => p.Key).ToHashSet(StringComparer.Ordinal).SetEquals(AxisNames), "Exactly nine independent axes are required.");
        var result = new JsonObject();
        for (var index = 0; index < AxisNames.Length; index++)
        {
            var name = AxisNames[index];
            var definition = definitions[name]!.AsObject();
            var kind = definition["kind"]!.GetValue<string>();
            Require(kind == Kinds[index], "Wrong source kind for " + name);
            if (definition["absence"] is { } absence)
            {
                Require(definition.All(p => p.Key is "kind" or "absence" or "reason" or "producer"), "Unknown absent-axis field.");
                var status = absence.GetValue<string>();
                Require(status is "not-applicable" or "not-produced" && !string.IsNullOrWhiteSpace(definition["reason"]?.GetValue<string>()), "Invalid absence.");
                Require(status != "not-produced" || !string.IsNullOrWhiteSpace(definition["producer"]?.GetValue<string>()), "Missing future producer.");
                var absent = new JsonObject { ["status"] = status, ["reason"] = definition["reason"]!.DeepClone() };
                if (definition["producer"] is { } producer) absent["producer"] = producer.DeepClone();
                result[name] = absent;
                continue;
            }
            Require(definition.All(p => p.Key is "kind" or "sources"), "Aliases and unknown source properties are forbidden.");
            var values = new SortedDictionary<string, JsonObject>(StringComparer.Ordinal);
            foreach (var item in definition["sources"]!.AsArray())
            {
                var path = item!.GetValue<string>();
                Require(!Path.IsPathRooted(path) && path.IndexOfAny(['\\', ':']) < 0 && !path.Split('/').Any(p => p is "" or "." or ".."), "Unsafe source path.");
                var content = read(path).Replace("\r\n", "\n", StringComparison.Ordinal);
                var source = new JsonObject { ["path"] = path, ["sha256"] = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content))) };
                void Add(string subject, string version, JsonNode? descriptor = null)
                {
                    Require(!string.IsNullOrWhiteSpace(subject) && VersionPattern().IsMatch(version), "Malformed subject or version.");
                    var value = new JsonObject { ["subject"] = subject, ["version"] = version, ["source"] = source.DeepClone() };
                    if (descriptor is not null) value["descriptorSha256"] = descriptor.DeepClone();
                    Require(values.TryAdd(subject, value), "Duplicate version subject.");
                }
                if (kind == "native-abi")
                {
                    var major = AbiMajor().Match(content);
                    var minor = AbiMinor().Match(content);
                    Require(major.Success && minor.Success, "Missing native ABI constants.");
                    Add(path, major.Groups[1].Value + "." + minor.Groups[1].Value);
                    continue;
                }
                var document = JsonNode.Parse(content)!.AsObject();
                if (kind == "contracts")
                {
                    var schema = ContractPattern().Match(document["schema"]!.GetValue<string>());
                    Require(schema.Success && HashPattern().IsMatch(document["descriptorSha256"]!.GetValue<string>()) && !document["dirty"]!.GetValue<bool>(), "Invalid restored contract provenance.");
                    Add(schema.Groups[1].Value, schema.Groups[2].Value, document["descriptorSha256"]);
                }
                else if (kind == "packages")
                {
                    if (document["lockfileVersion"] is not null)
                    {
                        foreach (var package in document["packages"]!.AsObject())
                        {
                            if (package.Key.Length == 0) continue;
                            Add("pkg:npm/" + package.Key, package.Value!["version"]!.GetValue<string>());
                        }
                        continue;
                    }
                    foreach (var framework in document["dependencies"]!.AsObject())
                        foreach (var dependency in framework.Value!.AsObject())
                        {
                            if (dependency.Value!["type"]!.GetValue<string>() == "Project") continue;
                            Add("pkg:nuget/" + dependency.Key + "?target=" + framework.Key, dependency.Value["resolved"]!.GetValue<string>());
                        }
                }
                else
                {
                    var declarations = document[kind == "migrations" ? "migrations" : "versions"]!.AsArray();
                    var selected = kind == "migrations" ? declarations.TakeLast(1) : declarations;
                    foreach (var value in selected) Add(value!["subject"]!.GetValue<string>(), value["version"]!.GetValue<string>());
                }
            }
            Require(kind == "packages" || values.Count > 0, "No implemented source for " + name);
            result[name] = new JsonObject { ["status"] = "present", ["values"] = new JsonArray(values.Values.Select(v => (JsonNode)v).ToArray()) };
        }
        return result;
    }

    public static void ValidateBuild(JsonObject build)
    {
        Require(build.Select(p => p.Key).ToHashSet(StringComparer.Ordinal).SetEquals(["sourceCommit", "dirty", "kind", "buildId", "runId", "runAttempt", "pipelineRun", "sourceDateEpoch"]), "Unknown or missing build fields.");
        var commit = build["sourceCommit"]!.GetValue<string>();
        Require(CommitPattern().IsMatch(commit) && build["sourceDateEpoch"]!.GetValue<long>() > 0, "Invalid source identity.");
        var dirty = build["dirty"]!.GetValue<bool>();
        var id = build["buildId"]!.GetValue<string>();
        var kind = build["kind"]!.GetValue<string>();
        if (kind == "ci")
        {
            var run = build["runId"]!.GetValue<string>();
            var attempt = build["runAttempt"]!.GetValue<int>();
            Require(!dirty && RunPattern().IsMatch(run) && attempt > 0 && id == run + "." + attempt.ToString(CultureInfo.InvariantCulture)
                && build["pipelineRun"]!.GetValue<string>() == "https://github.com/ArcForges/Cloud/actions/runs/" + run, "Invalid CI identity.");
        }
        else Require(kind == "local" && id == "local." + commit && build["runId"] is null && build["runAttempt"] is null && build["pipelineRun"] is null, "Invalid local identity.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
    [GeneratedRegex(@"^[0-9]+(?:\.[0-9]+)*(?:[-+][A-Za-z0-9.-]+)?$")]
    private static partial Regex VersionPattern();
    [GeneratedRegex(@"^([a-zA-Z0-9_.]+)\.v([1-9][0-9]*)$")]
    private static partial Regex ContractPattern();
    [GeneratedRegex(@"^[a-f0-9]{64}$")]
    private static partial Regex HashPattern();
    [GeneratedRegex(@"^[a-f0-9]{40}$")]
    private static partial Regex CommitPattern();
    [GeneratedRegex(@"^[1-9][0-9]*$")]
    private static partial Regex RunPattern();
    [GeneratedRegex(@"#define\s+ARC_ABI_MAJOR\s+(\d+)")]
    private static partial Regex AbiMajor();
    [GeneratedRegex(@"#define\s+ARC_ABI_MINOR\s+(\d+)")]
    private static partial Regex AbiMinor();
}
