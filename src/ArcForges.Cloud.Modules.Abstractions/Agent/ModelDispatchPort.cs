// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

/// <summary>
/// What a model dispatch is known to have done. Only <see cref="Succeeded"/> carries an answer. <see cref="RefusedBeforeDispatch"/> means
/// the supplier was not called (it may be retried with a fresh attempt). <see cref="Unknown"/> means the call may have reached the
/// supplier: it is never retried automatically (HAR.40 validation (a), contracts 05 line 88).
/// </summary>
public enum ModelDispatchStatus
{
    Succeeded,
    RefusedBeforeDispatch,
    FailedDidNotHappen,
    Unknown,
}

/// <summary>The pinned model and tariff snapshot a dispatch names. A snapshot that is missing or differs from the admitted one is refused.</summary>
public sealed record ModelSnapshot(string ModelId, string TariffSnapshotId);

/// <summary>
/// One model call. <see cref="RequestJson"/> is the frozen Workers AI request, already serialised in C#; the dispatcher forwards it
/// unchanged and never reads its content. <see cref="Deadline"/> bounds the await of the supplier answer.
/// </summary>
public sealed record ModelCallRequest(string ModelId, string TariffSnapshotId, string RequestJson, int MaxOutputTokens, int ToolCount, TimeSpan Deadline);

/// <summary>The dispatch answer. <see cref="ResponseJson"/> is the supplier's JSON object, present only when <see cref="Status"/> is Succeeded.</summary>
public sealed record ModelCallResult(ModelDispatchStatus Status, string? ResponseJson, string Reason);

/// <summary>
/// The model dispatch port of the Agent module. The Task module's harness calls it through this abstraction only; the Agent module owns
/// the admitted-model catalogue, the per-model rate admission and the transport to the ai.internal Worker route.
/// </summary>
public interface IModelDispatchPort
{
    /// <summary>The admitted snapshot of a model, or null when the model is not admitted (a missing snapshot).</summary>
    ModelSnapshot? SnapshotOf(string modelId);

    Task<ModelCallResult> DispatchAsync(ModelCallRequest request, CancellationToken cancellationToken);
}
