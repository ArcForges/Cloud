// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Readiness;

/// <summary>
/// Evaluates readiness (WP-21.07, CLOUD.84 S39(1)): every declared component is judged separately from the Worker's raw observations and the
/// host's own D1 check, and the whole is ready only when every required component is ready. A missing binding, a plan-manifest mismatch or a
/// failed D1 check fails readiness instead of letting a partially configured deployment look successful. Nothing is retried or written.
/// </summary>
internal static class ReadinessEvaluator
{
    private const int MaxRevisionLength = 80;
    private const int MaxElapsedMilliseconds = 60_000;

    /// <summary>
    /// The closed shape check of an observation: a known environment, a revision of at most 80 characters, a lowercase SHA-256 manifest hash,
    /// exactly the declared bindings, and a probe for each bound component the environment requires. A refusal is a 400.
    /// </summary>
    public static bool IsWellFormed(ReadinessObservations observations)
    {
        if (!ReadinessVocabulary.Environments.Contains(observations.Environment, StringComparer.Ordinal)) return false;
        if (observations.WorkerRevision.Length > MaxRevisionLength) return false;
        if (!IsManifestHash(observations.ManifestHash)) return false;
        var declared = ReadinessVocabulary.Bindings.Select(binding => binding.Name).ToHashSet(StringComparer.Ordinal);
        if (observations.Bindings.Count != declared.Count || !observations.Bindings.Keys.All(declared.Contains)) return false;
        if (!ValidProbe(observations.DurableObject) || !ValidProbe(observations.R2)) return false;
        if (ProbeMissing(observations, "durableObject", observations.DurableObject)) return false;
        return !ProbeMissing(observations, "r2", observations.R2);
    }

    /// <summary>Judges every component. The caller has checked <see cref="IsWellFormed"/>.</summary>
    /// <param name="observations">The Worker's observations.</param>
    /// <param name="hostD1">The host's own check of the named readiness plan, already classified.</param>
    /// <param name="hostManifestHash">The plan-manifest hash this host was compiled with.</param>
    /// <param name="hostSchemaVersion">The schema version the readiness plan returns.</param>
    /// <param name="hostRevision">The revision this host was compiled from.</param>
    public static ReadinessReport Evaluate(ReadinessObservations observations, ReadinessComponent hostD1, string hostManifestHash, string hostSchemaVersion, string? hostRevision)
    {
        if (!IsWellFormed(observations)) throw new ArgumentException("The readiness observations are malformed.", nameof(observations));
        var ingress = Judge(observations, "ingress", () => ReadinessComponent.Ready(ReadinessEvidence.Bound));
        // The host answered the signed call, so the Container is up and trusts the Worker's key.
        var container = Judge(observations, "container", () => ReadinessComponent.Ready(ReadinessEvidence.Probed));
        var d1 = Judge(observations, "d1", () => observations.ManifestHash == hostManifestHash
            ? hostD1
            : new ReadinessComponent(ReadinessStates.Misconfigured, ReadinessReasons.PlanHashMismatch, ReadinessEvidence.Probed));
        var durableObject = Judge(observations, "durableObject", () => Probe(observations.DurableObject!));
        var r2 = Judge(observations, "r2", () => Probe(observations.R2!));
        var queue = Judge(observations, "queue", () => ReadinessComponent.Ready(ReadinessEvidence.Bound));
        var components = new ReadinessComponents(ingress, container, d1, durableObject, r2, queue);
        var status = Summarize([ingress, container, d1, durableObject, r2, queue]);
        return new ReadinessReport(
            ReadinessVocabulary.Schema,
            status,
            status == ReadinessStates.Ready,
            observations.Environment,
            observations.WorkerRevision,
            components,
            new ReadinessHost(hostManifestHash, hostSchemaVersion, hostRevision));
    }

    /// <summary>
    /// The status of the whole. It fails closed: the order is misconfigured, unavailable, starting, then ready. An undetermined component
    /// never counts as ready, and a component that is not required takes no part.
    /// </summary>
    public static string Summarize(IReadOnlyList<ReadinessComponent> components)
    {
        var states = components.Select(component => component.State).ToList();
        if (states.Contains(ReadinessStates.Misconfigured)) return ReadinessStates.Misconfigured;
        if (states.Contains(ReadinessStates.Unavailable)) return ReadinessStates.Unavailable;
        if (states.Contains(ReadinessStates.Starting)) return ReadinessStates.Starting;
        // An undetermined component only remains when its cause was not reported: it still never counts as ready.
        if (states.Contains(ReadinessStates.Unknown)) return ReadinessStates.Unavailable;
        return ReadinessStates.Ready;
    }

    /// <summary>True only for a status a retry can help: starting or unavailable. A misconfigured deployment will not heal by itself.</summary>
    public static bool IsTransient(string status) => ReadinessVocabulary.RetryableStatuses.Contains(status, StringComparer.Ordinal);

    private static ReadinessComponent Judge(ReadinessObservations observations, string component, Func<ReadinessComponent> bound)
    {
        if (!Requires(observations.Environment, component)) return ReadinessComponent.NotRequired;
        var missing = Missing(observations, component);
        return missing.Length > 0 ? ReadinessComponent.Misconfigured(missing) : bound();
    }

    private static ReadinessComponent Probe(ReadinessProbe probe) => probe.Outcome switch
    {
        "ready" => ReadinessComponent.Ready(ReadinessEvidence.Probed, probe.ElapsedMs),
        "no_answer_in_wait" => ReadinessComponent.Unavailable(ReadinessReasons.NoAnswerInWait, ReadinessEvidence.Probed, probe.ElapsedMs),
        _ => ReadinessComponent.Unavailable(ReadinessReasons.Unreachable, ReadinessEvidence.Probed, probe.ElapsedMs),
    };

    /// <summary>A component is required when the environment declares at least one of its bindings.</summary>
    private static bool Requires(string environment, string component) =>
        ReadinessVocabulary.Bindings.Any(binding => binding.Component == component && binding.Environments.Contains(environment, StringComparer.Ordinal));

    /// <summary>The names of the declared bindings of a component, in the environment, that are not met.</summary>
    private static string[] Missing(ReadinessObservations observations, string component) =>
        ReadinessVocabulary.Bindings
            .Where(binding => binding.Component == component && binding.Environments.Contains(observations.Environment, StringComparer.Ordinal))
            .Where(binding => !observations.Bindings[binding.Name])
            .Select(binding => binding.Name)
            .ToArray();

    /// <summary>A required probe whose binding is met must be present: a probe is never assumed.</summary>
    private static bool ProbeMissing(ReadinessObservations observations, string component, ReadinessProbe? probe) =>
        Requires(observations.Environment, component) && Missing(observations, component).Length == 0 && probe is null;

    private static bool ValidProbe(ReadinessProbe? probe) =>
        probe is null || (ReadinessVocabulary.ProbeOutcomes.Contains(probe.Outcome, StringComparer.Ordinal) && probe.ElapsedMs is >= 0 and <= MaxElapsedMilliseconds);

    /// <summary>A lowercase SHA-256 hex digest, the only spelling of a plan manifest hash.</summary>
    private static bool IsManifestHash(string text) => text.Length == 64 && text.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
}
