// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Readiness;

/// <summary>
/// One declared binding of a component: the Worker's binding (or secret) name, the component it belongs to and the environments that declare it.
/// </summary>
internal sealed record ReadinessBinding(string Component, string Name, string[] Environments);

/// <summary>
/// The closed readiness vocabulary (WP-21.07, schema cloud.readiness.v1) and the binding declarations per environment. Readiness is evaluated
/// here (CLOUD.84 S39(1)); the generator reads these declarations into worker/tables/cloud-tables.generated.ts (S34), so the Worker names the
/// same components, states, reasons, bindings and probe outcomes and holds no copy of its own. Only names of bindings and secrets appear here,
/// never a value.
/// </summary>
internal static class ReadinessVocabulary
{
    /// <summary>The report schema identifier. The report schema is stable: its fields and vocabulary are the ones documented in docs/cloud-readiness.md.</summary>
    public const string Schema = "cloud.readiness.v1";

    /// <summary>Seconds a client is advised to wait before it tries again after a transient refusal (Design D1 profile, section 3).</summary>
    public const int RetryAfterSeconds = 2;

    /// <summary>The longest the readiness check waits for one component (Design D1 profile section 3; launch-capacity.v1 readinessTimeoutMs).</summary>
    public const int ReadinessWaitMilliseconds = 8000;

    public const string Production = "production";
    public const string Proof = "proof";

    public static readonly string[] Environments = [Production, Proof];

    public static readonly string[] Components = ["ingress", "container", "d1", "durableObject", "r2", "queue"];

    /// <summary>ready, starting, unavailable, misconfigured, unknown and not_required, the states of one component.</summary>
    public static readonly string[] States = ["ready", "starting", "unavailable", "misconfigured", "unknown", "not_required"];

    /// <summary>The states the whole can take, in the order the status is decided.</summary>
    public static readonly string[] Statuses = ["ready", "starting", "unavailable", "misconfigured"];

    /// <summary>The statuses for which a retry can help.</summary>
    public static readonly string[] RetryableStatuses = ["starting", "unavailable"];

    public static readonly string[] Evidence = ["probed", "bound"];

    public static readonly string[] Reasons =
    [
        "binding_missing",
        "key_missing",
        "key_mismatch",
        "host_route_missing",
        "host_reply_invalid",
        "host_error",
        "no_instance_available",
        "start_failed",
        "rate_limited",
        "no_answer_in_wait",
        "unreachable",
        "container_not_ready",
        "plan_hash_mismatch",
        "schema_mismatch",
        "recovery_generation_mismatch",
        "d1_unavailable",
    ];

    /// <summary>The bindings and secrets whose absence is reported as <c>key_missing</c> rather than <c>binding_missing</c>.</summary>
    public static readonly string[] KeyBindings = ["HMAC_W2C_KEY", "HMAC_C2W_KEY", "CSRF_SECRET"];

    /// <summary>The outcomes of a bounded Worker probe of a Durable Object or R2.</summary>
    public static readonly string[] ProbeOutcomes = ["ready", "no_answer_in_wait", "unreachable"];

    /// <summary>
    /// Every declared binding. The production Worker declares only the Hello bindings (ingress and the Container); the isolated proof
    /// environment declares the rest. A binding of a component is met when its name is present with the expected shape, which the Worker checks.
    /// </summary>
    public static readonly ReadinessBinding[] Bindings =
    [
        new("ingress", "SOURCE_REVISION", [Production, Proof]),
        new("ingress", "HELLO_RATE_LIMITER", [Production, Proof]),
        new("ingress", "ALLOWED_ORIGIN", [Proof]),
        new("container", "CLOUD_CONTAINER", [Production, Proof]),
        new("container", "HMAC_W2C_KEY", [Proof]),
        new("container", "CSRF_SECRET", [Proof]),
        new("d1", "DB", [Proof]),
        new("d1", "RECOVERY_GENERATION", [Proof]),
        new("d1", "HMAC_C2W_KEY", [Proof]),
        new("durableObject", "JOB_COORDINATOR", [Proof]),
        new("r2", "OBJECTS", [Proof]),
        new("r2", "REALM_ID", [Proof]),
        new("queue", "WAKE_QUEUE", [Proof]),
    ];

    /// <summary>The components an environment declares. Ingress and the Container are declared everywhere; the rest only in the proof environment.</summary>
    public static bool Declares(ReadinessBinding binding, string environment) => binding.Environments.Contains(environment, StringComparer.Ordinal);
}
