// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Text.RegularExpressions;
using Xunit;

namespace ArcForges.Cloud.ArchitectureTests.WorkerAdapter;

/// <summary>
/// CLOUD.84 D1 and S39: the production Worker is built by wrangler from worker/index.ts alone, and that bundle contains no proof-only
/// symbol, route, fixture or verification code. The isolated proof environment has its own entry (worker/proof/entry.ts) and bundle. The
/// bundle is built here with wrangler's dry-run into a temporary directory, so the check is the one the candidate job performs.
/// </summary>
public sealed class ProductionBundleTests
{
    /// <summary>Names that only the proof entry, its foundation, its harness alarm or its verification may contain.</summary>
    private static readonly string[] ProofOnlyMarkers =
    [
        "FoundationContainer",
        "FoundationJobCoordinator",
        "HarnessRunAlarm",
        "storage.internal",
        "objects.internal",
        "harness.internal",
        "/proof/v1/",
        "/session/v1/",
        "/internal/foundation/v1/",
        "arcforges.proof.v1",
        "PipelineProbe",
        "FOUNDATION_PROOF",
        "PROOF_OPERATOR",
        "cloud.readiness.v1",
        "proofRouteTable",
        "eng/verification",
        "WAKE_QUEUE",
        "JOB_COORDINATOR",
    ];

    [Fact]
    public void TheProductionEntryImportsNoProofOnlyModule()
    {
        var entry = CloudRepository.Read(CloudRepository.FindRoot(), "worker/index.ts");
        var imports = Regex.Matches(entry, "from \"([^\"]+)\"").Select(match => match.Groups[1].Value).ToArray();
        Assert.Equal(["@cloudflare/containers", "./foundation/cloud-container.ts", "./router.ts"], imports);
    }

    [Fact]
    public async Task TheProductionBundleHoldsNoProofOnlySymbolRouteOrFixture()
    {
        var root = CloudRepository.FindRoot();
        var directory = Path.Combine(Path.GetTempPath(), "arcforges-production-bundle-" + Guid.NewGuid().ToString("N"));
        try
        {
            var script = Path.Combine(root, "node_modules", "wrangler", "bin", "wrangler.js");
            Assert.True(File.Exists(script), "The locked wrangler is required for the production bundle check: run npm ci first.");
            var start = new ProcessStartInfo("node")
            {
                WorkingDirectory = root,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            start.ArgumentList.Add(script);
            foreach (var argument in new[] { "deploy", "--dry-run", "--containers-rollout", "none", "--outdir", directory })
                start.ArgumentList.Add(argument);
            start.Environment["WRANGLER_SEND_METRICS"] = "false";
            using var process = Process.Start(start) ?? throw new InvalidOperationException("node could not be started.");
            var cancellation = TestContext.Current.CancellationToken;
            var stdout = process.StandardOutput.ReadToEndAsync(cancellation);
            var stderr = process.StandardError.ReadToEndAsync(cancellation);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            timeout.CancelAfter(TimeSpan.FromMinutes(4));
            await process.WaitForExitAsync(timeout.Token);
            Assert.True(process.ExitCode == 0, $"The production dry-run failed: {await stderr}{await stdout}");

            var bundle = File.ReadAllText(Path.Combine(directory, "index.js"));
            foreach (var marker in ProofOnlyMarkers)
                Assert.False(bundle.Contains(marker, StringComparison.Ordinal), $"The production bundle contains a proof-only marker: {marker}");

            // The production exports are the Container class, the Container proxy and the fetch entry. No proof class is exported.
            var exports = Regex.Match(bundle, @"export\s*\{(?<names>[^}]*)\}").Groups["names"].Value;
            Assert.Equal(["CloudContainer", "ContainerProxy", "index_default as default"], exports.Split(',').Select(name => name.Trim()).Where(name => name.Length > 0).Order().ToArray());
            // The one outbound host of the production class is ai.internal; no proof host is registered.
            Assert.Contains("\"ai.internal\"", bundle, StringComparison.Ordinal);
        }
        finally
        {
            if (Directory.Exists(directory)) Directory.Delete(directory, recursive: true);
        }
    }
}
