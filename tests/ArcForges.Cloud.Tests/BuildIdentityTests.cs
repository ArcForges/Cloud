// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json.Nodes;
using ArcForges.Cloud;
using Xunit;

namespace ArcForges.Cloud.Tests;

public sealed class BuildIdentityTests
{
    private static string Root()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (!File.Exists(Path.Combine(current.FullName, "eng/version-sources.json"))) current = current.Parent!;
        return current.FullName;
    }

    [Fact]
    public void NineRealSourceKindsAreIndependentAndDeterministic()
    {
        // Mechanism fixture: these declarations do not claim production format/storage support.
        var catalog = JsonNode.Parse(File.ReadAllText(Path.Combine(Root(), "eng/version-sources.json")))!.AsObject();
        var sources = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var name in BuildIdentity.AxisNames)
        {
            var kind = catalog["axes"]![name]!["kind"]!.GetValue<string>();
            catalog["axes"]![name] = new JsonObject { ["kind"] = kind, ["sources"] = new JsonArray(name + ".json") };
            sources[name + ".json"] = kind switch
            {
                "contracts" => "{\"schema\":\"fixture.rpc.v1\",\"descriptorSha256\":\"" + new string('a', 64) + "\",\"dirty\":false}",
                "packages" => "{\"dependencies\":{\"net10.0\":{\"fixture.package\":{\"type\":\"Direct\",\"resolved\":\"1.0\"}}}}",
                "native-abi" => "#define ARC_ABI_MAJOR 1\n#define ARC_ABI_MINOR 0\n",
                "migrations" => "{\"migrations\":[{\"subject\":\"fixture.store\",\"version\":\"0.9\"},{\"subject\":\"fixture.store\",\"version\":\"1.0\"}]}",
                _ => "{\"versions\":[{\"subject\":\"fixture.owned\",\"version\":\"1.0\"}]}"
            };
        }
        var first = BuildIdentity.Resolve(catalog, path => sources[path]);
        Assert.Equal(9, first.Count);
        foreach (var name in BuildIdentity.AxisNames)
        {
            Assert.Equal(name == "ContractSet" ? "1" : "1.0", first[name]!["values"]![0]!["version"]!.GetValue<string>());
            var changed = new Dictionary<string, string>(sources, StringComparer.Ordinal);
            changed[name + ".json"] = name switch
            {
                "ContractSet" => sources[name + ".json"].Replace("rpc.v1", "rpc.v2", StringComparison.Ordinal),
                "NativeAbiVersion" => sources[name + ".json"].Replace("MAJOR 1", "MAJOR 2", StringComparison.Ordinal),
                _ => sources[name + ".json"].Replace("1.0", "2.0", StringComparison.Ordinal)
            };
            var next = BuildIdentity.Resolve(catalog, path => changed[path]);
            foreach (var axis in BuildIdentity.AxisNames) Assert.Equal(axis != name, JsonNode.DeepEquals(first[axis], next[axis]));
        }
        Assert.Equal(first.ToJsonString(), BuildIdentity.Resolve(catalog, path => sources[path]).ToJsonString());
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("unknown")]
    [InlineData("alias")]
    [InlineData("producer")]
    [InlineData("kind")]
    [InlineData("duplicate")]
    [InlineData("version")]
    [InlineData("path")]
    public void InvalidSourcesCannotProduceAReport(string mode)
    {
        var catalog = JsonNode.Parse(File.ReadAllText(Path.Combine(Root(), "eng/version-sources.json")))!.AsObject();
        switch (mode)
        {
            case "missing": catalog["axes"]!.AsObject().Remove("AppVersion"); break;
            case "unknown": catalog["axes"]!["OtherVersion"] = new JsonObject(); break;
            case "alias": catalog["axes"]!["AppVersion"]!["alias"] = "PackageVersion"; break;
            case "producer": catalog["axes"]!["CapabilityVersion"]!.AsObject().Remove("producer"); break;
            case "kind": catalog["axes"]!["AppVersion"]!["kind"] = "packages"; break;
            case "path": catalog["axes"]!["AppVersion"]!["sources"]![0] = "../outside.json"; break;
        }
        string Read(string path) => path switch
        {
            "assembly/release.json" when mode == "duplicate" => "{\"versions\":[{\"subject\":\"app\",\"version\":\"1\"},{\"subject\":\"app\",\"version\":\"2\"}]}",
            "assembly/release.json" when mode == "version" => "{\"versions\":[{\"subject\":\"app\",\"version\":\"AppVersion\"}]}",
            "assembly/release.json" => "{\"versions\":[{\"subject\":\"app\",\"version\":\"1\"}]}",
            "packages/contracts/source.json" => "{\"schema\":\"fixture.rpc.v1\",\"descriptorSha256\":\"" + new string('a', 64) + "\",\"dirty\":false}",
            "src/ArcForges.Cloud/packages.lock.json" => "{\"dependencies\":{}}",
            _ => "{\"versions\":[{\"subject\":\"app\",\"version\":\"1\"}]}"
        };
        Assert.Throws<InvalidOperationException>(() => BuildIdentity.Resolve(catalog, Read));
    }

    [Fact]
    public void DirtyOrIncompleteCiIdentityIsRejected()
    {
        var local = new JsonObject
        {
            ["sourceCommit"] = new string('a', 40),
            ["sourceDateEpoch"] = 1L,
            ["dirty"] = true,
            ["kind"] = "local",
            ["buildId"] = "local." + new string('a', 40),
            ["runId"] = null,
            ["runAttempt"] = null,
            ["pipelineRun"] = null
        };
        BuildIdentity.ValidateBuild(local);
        local["kind"] = "ci";
        local["runId"] = "123";
        local["runAttempt"] = 1;
        local["buildId"] = "123.1";
        local["pipelineRun"] = "https://github.com/ArcForges/Cloud/actions/runs/123";
        Assert.Throws<InvalidOperationException>(() => BuildIdentity.ValidateBuild(local));
        local["dirty"] = false;
        BuildIdentity.ValidateBuild(local);
        local["runAttempt"] = 0;
        Assert.Throws<InvalidOperationException>(() => BuildIdentity.ValidateBuild(local));
    }
}
