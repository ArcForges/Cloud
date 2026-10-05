// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Foundation;
using ArcForges.Cloud.Storage;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Readiness;

/// <summary>
/// One component of the host's readiness report. <c>State</c> is <c>ready</c>, <c>unavailable</c> (a retry may succeed) or
/// <c>misconfigured</c> (a retry cannot succeed until the deployment is repaired); <c>Reason</c> is one of the closed codes of
/// <see cref="HostReadinessReasons"/>. Nothing here carries content: no SQL, value, error text or identifier.
/// </summary>
internal sealed record ReadinessComponent(string State, string? Reason = null)
{
    public static readonly ReadinessComponent Ready = new(HostReadinessStates.Ready);

    public static ReadinessComponent Unavailable(string reason) => new(HostReadinessStates.Unavailable, reason);

    public static ReadinessComponent Misconfigured(string reason) => new(HostReadinessStates.Misconfigured, reason);
}

/// <summary>The components only the host can see. The Worker owns the rest (ingress, Durable Object, R2, Queue) and the Container is the host's own existence.</summary>
internal sealed record ReadinessComponents(ReadinessComponent D1);

/// <summary>
/// The reply of the signed internal readiness operation. <c>Ready</c> is true exactly when every component is ready, and the
/// Worker refuses a reply in which the two disagree. The manifest hash and revision stay what the operator scenarios read.
/// </summary>
internal sealed record ReadinessResponse(bool Ready, string ManifestHash, string SchemaVersion, string? Revision, ReadinessComponents Components);

internal static class HostReadinessStates
{
    public const string Ready = "ready";
    public const string Unavailable = "unavailable";
    public const string Misconfigured = "misconfigured";
}

/// <summary>The closed reason codes the host reports; the Worker accepts exactly these.</summary>
internal static class HostReadinessReasons
{
    public const string D1Unavailable = "d1_unavailable";
    public const string PlanHashMismatch = "plan_hash_mismatch";
    public const string SchemaMismatch = "schema_mismatch";
    public const string RecoveryGenerationMismatch = "recovery_generation_mismatch";
    public const string KeyMismatch = "key_mismatch";
}

/// <summary>
/// The host's half of readiness (WP-21.07): D1 is judged by running the named readiness plan once through the real plan
/// executor, and a failure is classified instead of collapsed, so a plan-manifest mismatch, a recovery-generation mismatch
/// and a refused signature are reported as a misconfigured deployment and never as a transient outage. Nothing is retried and
/// nothing is written.
/// </summary>
internal sealed class HostReadiness(IPlanExecutor executor, FoundationOptions options)
{
    /// <summary>The schema version the readiness plan returns and the only one this host accepts.</summary>
    public const string SchemaVersion = "1";

    public async Task<ReadinessResponse> ReportAsync(CancellationToken cancellationToken)
    {
        var d1 = await CheckD1Async(cancellationToken);
        return new ReadinessResponse(d1.State == HostReadinessStates.Ready, PlanManifest.Hash, SchemaVersion, HostRevision.Current, new ReadinessComponents(d1));
    }

    private async Task<ReadinessComponent> CheckD1Async(CancellationToken cancellationToken)
    {
        try
        {
            var call = PlanCall.New(PlanManifest.Foundation.Readiness, options.SessionScope, options.RecoveryGeneration, [[]]);
            var result = await executor.ExecuteAsync(call, cancellationToken);
            return result.Rows.Count == 1 && D1Values.TryGetInt64(result.Rows[0][0], out var version) && version == 1
                ? ReadinessComponent.Ready
                : ReadinessComponent.Misconfigured(HostReadinessReasons.SchemaMismatch);
        }
        catch (PlanFailureException failure)
        {
            return failure.Kind switch
            {
                // The Worker answered with a manifest hash that is not this host's: the two were built from different plans.
                PlanFailureKind.ManifestMismatch => ReadinessComponent.Misconfigured(HostReadinessReasons.PlanHashMismatch),
                PlanFailureKind.StaleGeneration => ReadinessComponent.Misconfigured(HostReadinessReasons.RecoveryGenerationMismatch),
                // The Worker refused the signed call (401): a key that differs between Worker and host, or a clock beyond the signing window.
                PlanFailureKind.Transport => ReadinessComponent.Misconfigured(HostReadinessReasons.KeyMismatch),
                _ => ReadinessComponent.Unavailable(HostReadinessReasons.D1Unavailable),
            };
        }
    }
}
