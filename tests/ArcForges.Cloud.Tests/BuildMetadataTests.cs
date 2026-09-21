// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using ArcForges.Cloud;
using Xunit;

namespace ArcForges.Cloud.Tests;

public sealed class BuildMetadataTests
{
    [Fact]
    public void EveryOwnedAssemblyCarriesActualSourceAndBuildIdentity()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (!File.Exists(Path.Combine(directory.FullName, "Cloud.slnx"))) directory = directory.Parent!;
        var root = directory.FullName;
        string Git(params string[] arguments)
        {
            var info = new ProcessStartInfo("git") { WorkingDirectory = root, RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            foreach (var argument in arguments) info.ArgumentList.Add(argument);
            using var process = Process.Start(info)!;
            var output = process.StandardOutput.ReadToEndAsync();
            if (!process.WaitForExit(30_000)) { process.Kill(true); throw new TimeoutException("Git identity lookup timed out."); }
            Assert.Equal(0, process.ExitCode);
            return output.GetAwaiter().GetResult().Trim();
        }
        var commit = Git("rev-parse", "HEAD");
        var ci = Environment.GetEnvironmentVariable("GITHUB_ACTIONS") == "true";
        var run = Environment.GetEnvironmentVariable("GITHUB_RUN_ID");
        var expected = new Dictionary<string, string>
        {
            ["ArcForges.SourceCommit"] = commit,
            ["ArcForges.SourceDateEpoch"] = Git("show", "-s", "--format=%ct", commit),
            ["ArcForges.Dirty"] = Git("status", "--porcelain").Length == 0 ? "false" : "true",
            ["ArcForges.BuildKind"] = ci ? "ci" : "local",
            ["ArcForges.BuildId"] = ci ? run + "." + Environment.GetEnvironmentVariable("GITHUB_RUN_ATTEMPT") : "local." + commit,
            ["ArcForges.PipelineRun"] = ci ? "https://github.com/ArcForges/Cloud/actions/runs/" + run : "local"
        };
        string[] assemblies = ["src/ArcForges.Cloud", "tests/ArcForges.Cloud.Consumer", "tests/ArcForges.Cloud.Tests"];
        foreach (var project in assemblies)
        {
            var name = Path.GetFileName(project);
            using var stream = File.OpenRead(Path.Combine(root, project, "bin/Release/net10.0", name + ".dll"));
            using var pe = new PEReader(stream);
            var reader = pe.GetMetadataReader();
            var actual = new Dictionary<string, string?>();
            foreach (var handle in reader.GetAssemblyDefinition().GetCustomAttributes())
            {
                var attribute = reader.GetCustomAttribute(handle);
                if (attribute.Constructor.Kind != HandleKind.MemberReference) continue;
                var parent = reader.GetMemberReference((MemberReferenceHandle)attribute.Constructor).Parent;
                if (parent.Kind != HandleKind.TypeReference) continue;
                var type = reader.GetTypeReference((TypeReferenceHandle)parent);
                if (reader.GetString(type.Name) != "AssemblyMetadataAttribute" || reader.GetString(type.Namespace) != "System.Reflection") continue;
                var blob = reader.GetBlobReader(attribute.Value);
                Assert.Equal(1, blob.ReadUInt16());
                actual.Add(blob.ReadSerializedString()!, blob.ReadSerializedString());
            }
            foreach (var field in expected) Assert.Equal(field.Value, actual.GetValueOrDefault(field.Key));
        }
        var report = BuildIdentity.FromAssembly(typeof(HelloEndpoint).Assembly);
        Assert.Equal(commit, report["build"]!["sourceCommit"]!.GetValue<string>());
        Assert.Equal(9, report["axes"]!.AsObject().Count);
    }
}
