// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Readiness;

/// <summary>
/// The result of one bounded Worker probe of a Durable Object or R2. <c>Outcome</c> is one of <see cref="ReadinessVocabulary.ProbeOutcomes"/>.
/// </summary>
internal sealed record ReadinessProbe(string Outcome, int ElapsedMs);

/// <summary>
/// The raw observations the Worker forwards on the signed readiness call (CLOUD.84 S39(1)): its environment, its revision and plan manifest hash,
/// whether each declared binding is met, and the outcome of its Durable Object and R2 probes. The Worker reads no verdict out of them. A probe is
/// present for each component the environment requires whose binding is met; <see cref="ReadinessEvaluator.IsWellFormed"/> checks that.
/// </summary>
internal sealed record ReadinessObservations(
    string Environment,
    string WorkerRevision,
    string ManifestHash,
    Dictionary<string, bool> Bindings,
    ReadinessProbe? DurableObject = null,
    ReadinessProbe? R2 = null);
