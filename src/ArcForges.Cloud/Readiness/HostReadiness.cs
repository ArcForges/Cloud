// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Readiness;

/// <summary>
/// The host's half of readiness (WP-21.07, CLOUD.84 S39(1)): D1 is judged by running the named readiness plan once through the real plan
/// executor, and a failure is classified instead of collapsed, so a plan-manifest mismatch, a recovery-generation mismatch and a refused
/// signature are reported as a misconfigured deployment and never as a transient outage. The whole report is then evaluated by
/// <see cref="ReadinessEvaluator"/> from the Worker's observations. Nothing is retried and nothing is written.
/// </summary>
internal sealed class HostReadiness(IPlanExecutor executor, FoundationOptions options)
{
    /// <summary>The schema version the readiness plan returns and the only one this host accepts.</summary>
    public const string SchemaVersion = "1";

    public async Task<ReadinessReport> ReportAsync(ReadinessObservations observations, CancellationToken cancellationToken)
    {
        var d1 = await CheckD1Async(cancellationToken);
        return ReadinessEvaluator.Evaluate(observations, d1, PlanManifest.Hash, SchemaVersion, HostRevision.Current);
    }

    private async Task<ReadinessComponent> CheckD1Async(CancellationToken cancellationToken)
    {
        try
        {
            var call = PlanCall.New(PlanManifest.Foundation.Readiness, options.SessionScope, options.RecoveryGeneration, [[]]);
            var result = await executor.ExecuteAsync(call, cancellationToken);
            return result.Rows.Count == 1 && D1Values.TryGetInt64(result.Rows[0][0], out var version) && version == 1
                ? ReadinessComponent.Ready(ReadinessEvidence.Probed)
                : new ReadinessComponent(ReadinessStates.Misconfigured, ReadinessReasons.SchemaMismatch, ReadinessEvidence.Probed);
        }
        catch (PlanFailureException failure)
        {
            return failure.Kind switch
            {
                // The Worker's generated plans and this host's compiled plans were built from different manifests.
                PlanFailureKind.ManifestMismatch => new ReadinessComponent(ReadinessStates.Misconfigured, ReadinessReasons.PlanHashMismatch, ReadinessEvidence.Probed),
                PlanFailureKind.StaleGeneration => new ReadinessComponent(ReadinessStates.Misconfigured, ReadinessReasons.RecoveryGenerationMismatch, ReadinessEvidence.Probed),
                // The Worker refused the signed call (401): a key that differs between Worker and host, or a clock beyond the signing window.
                PlanFailureKind.Transport => new ReadinessComponent(ReadinessStates.Misconfigured, ReadinessReasons.KeyMismatch, ReadinessEvidence.Probed),
                _ => new ReadinessComponent(ReadinessStates.Unavailable, ReadinessReasons.D1Unavailable, ReadinessEvidence.Probed),
            };
        }
    }
}
