// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Readiness;

/// <summary>
/// One component of the readiness report. <c>State</c> is one of <see cref="ReadinessVocabulary.States"/>; <c>Reason</c> is one of the closed
/// <see cref="ReadinessVocabulary.Reasons"/>, present only when the component is not ready. Nothing here carries content: no request, value,
/// secret, SQL, error text or object key. <c>Missing</c> names declared bindings only.
/// </summary>
internal sealed record ReadinessComponent(string State, string? Reason = null, string? Evidence = null, string[]? Missing = null, int? ElapsedMs = null)
{
    public static readonly ReadinessComponent NotRequired = new(ReadinessStates.NotRequired);

    public static ReadinessComponent Ready(string evidence, int? elapsedMs = null) => new(ReadinessStates.Ready, null, evidence, null, elapsedMs);

    public static ReadinessComponent Unavailable(string reason, string evidence, int? elapsedMs = null) => new(ReadinessStates.Unavailable, reason, evidence, null, elapsedMs);

    public static ReadinessComponent Misconfigured(string[] missing) => new(ReadinessStates.Misconfigured, MissingReason(missing), null, missing);

    /// <summary>A key or secret absent is a key problem; any other declared binding is a binding problem.</summary>
    public static string MissingReason(string[] names) =>
        names.All(name => ReadinessVocabulary.KeyBindings.Contains(name, StringComparer.Ordinal))
            ? ReadinessReasons.KeyMissing
            : ReadinessReasons.BindingMissing;
}

/// <summary>The components of the report, in the order the vocabulary lists them.</summary>
internal sealed record ReadinessComponents(
    ReadinessComponent Ingress,
    ReadinessComponent Container,
    ReadinessComponent D1,
    ReadinessComponent DurableObject,
    ReadinessComponent R2,
    ReadinessComponent Queue);

/// <summary>What the Container host reports about itself. It is present only in the host's own report.</summary>
internal sealed record ReadinessHost(string ManifestHash, string SchemaVersion, string? Revision);

/// <summary>
/// The readiness report. <c>Ready</c> is true exactly when <c>Status</c> is ready. The wire names are the ones docs/cloud-readiness.md documents.
/// </summary>
internal sealed record ReadinessReport(string Schema, string Status, bool Ready, string Environment, string WorkerRevision, ReadinessComponents Components, ReadinessHost? Host);

/// <summary>The states and reasons the evaluator and the Worker share, as constants.</summary>
internal static class ReadinessStates
{
    public const string Ready = "ready";
    public const string Starting = "starting";
    public const string Unavailable = "unavailable";
    public const string Misconfigured = "misconfigured";
    public const string Unknown = "unknown";
    public const string NotRequired = "not_required";
}

/// <summary>The evidence levels of a component: a bounded read answered, or only a declared binding was checked.</summary>
internal static class ReadinessEvidence
{
    public const string Probed = "probed";
    public const string Bound = "bound";
}

/// <summary>The closed reason codes of the readiness vocabulary.</summary>
internal static class ReadinessReasons
{
    public const string BindingMissing = "binding_missing";
    public const string KeyMissing = "key_missing";
    public const string ContainerNotReady = "container_not_ready";
    public const string PlanHashMismatch = "plan_hash_mismatch";
    public const string SchemaMismatch = "schema_mismatch";
    public const string RecoveryGenerationMismatch = "recovery_generation_mismatch";
    public const string KeyMismatch = "key_mismatch";
    public const string D1Unavailable = "d1_unavailable";
    public const string NoAnswerInWait = "no_answer_in_wait";
    public const string Unreachable = "unreachable";
}
