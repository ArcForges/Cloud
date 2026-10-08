// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using ArcForges.Cloud.Modules.Task.Harness.HelloSlice.Domain;

namespace ArcForges.Cloud.Modules.Task.Harness.HelloSlice.Application;

/// <summary>What the slice reports. <see cref="Succeeded"/> is the only status that carries the greeting.</summary>
internal enum HelloStatus
{
    Succeeded,

    /// <summary>Refused before any claim or dispatch (a bad name, an unpinned or changed snapshot, a busy or foreign run).</summary>
    Refused,

    /// <summary>The run ended with a failure that needs no reconciliation (a refusal before dispatch, a bad answer).</summary>
    Failed,

    /// <summary>A dispatch may have happened and its outcome is unknown: the run waits for reconciliation and is never retried here.</summary>
    Interrupted,

    /// <summary>The fence was lost: the slice stopped and wrote nothing further.</summary>
    LeaseLost,
}

internal sealed record HelloResult(HelloStatus Status, string Reason, string? Message);

/// <summary>
/// The Hello-agent slice of the C# harness (HAR.40 section (c)): admission, the first model call, the local say_hello tool and the final
/// model call, each a counted step reserved under the fence before any dispatch. It runs only against the pinned model and tariff snapshot,
/// it runs a run once (a run with recorded effects is never restarted here), and every failure ends in a settled state or a stop with no
/// write. Retries and their limits come from the executor: a pre-dispatch refusal may be retried twice with a fresh attempt, and an unknown
/// effect is never retried.
/// </summary>
internal sealed class HelloAgentSlice(IHarnessStore store, IModelDispatchPort models, IHarnessIds ids, TimeProvider time, HelloModelSettings settings, TimeSpan keepaliveInterval)
{
    internal async Task<HelloResult> RunAsync(HarnessRun run, RunIdentity identity, string name, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (identity.RunId != run.RunId) throw new ArgumentException("The identity names another run.", nameof(identity));
        if (!HelloNames.IsValid(name)) return Refused("invalid_name");

        var pinned = identity.Pinned;
        if (!pinned.IsPinned) return Refused("unpinned");
        if (!IsBoundedToken(identity.WorkerVersion) || !IsBoundedToken(identity.CloudBuildIdentity)) return Refused("identity");
        // The pinned pair must be the admitted one now: a missing or changed snapshot is refused before any claim or dispatch.
        var snapshot = models.SnapshotOf(pinned.ModelId);
        if (snapshot is null) return Refused("snapshot_missing");
        if (!string.Equals(snapshot.TariffSnapshotId, pinned.TariffSnapshotId, StringComparison.Ordinal)) return Refused("snapshot_changed");

        var effects = new HelloEffectPort(models, settings, keepaliveInterval);
        var executor = new HarnessExecutor(store, effects, ids, time);
        var claimed = await executor.ClaimAsync(run, identity, cancellationToken).ConfigureAwait(false);
        if (claimed.Status != ClaimStatus.Claimed || claimed.Claim is null) return Refused("claim_" + claimed.Status.ToString().ToLowerInvariant());

        var claim = claimed.Claim;
        effects.RenewLease = token => executor.RenewIfDueAsync(claim, token);
        try
        {
            return await RunClaimedAsync(executor, effects, claim, name, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The release is a short fenced write that must not be cancelled with the caller: a dispatch may be in flight, and an interrupted
            // run is the safe state for it (the next claim records any unresolved effect as unknown and never repeats it).
            return await SettleAsync(executor, claim, RunState.Interrupted, HelloStatus.Interrupted, "cancelled", null, CancellationToken.None).ConfigureAwait(false);
        }
    }

    private async Task<HelloResult> RunClaimedAsync(HarnessExecutor executor, HelloEffectPort effects, ClaimedRun claim, string name, CancellationToken cancellationToken)
    {
        var pinned = claim.Identity.Pinned;
        var loaded = await store.LoadAsync(claim.Fence.Run, cancellationToken).ConfigureAwait(false);
        if (loaded is null) return new HelloResult(HelloStatus.Failed, "run_missing", null);
        var budget = loaded.Budget;
        if (budget.CountedSteps != 0 || budget.Subrequests != 0 || budget.ModelCalls != 0 || budget.ToolInvocations != 0)
            return await SettleAsync(executor, claim, RunState.Interrupted, HelloStatus.Refused, "already_started", null, cancellationToken).ConfigureAwait(false);

        // Admission is a fenced checkpoint with no effect: the identity it binds is the Worker version and the Cloud build, with the epoch.
        if (!await CheckpointAsync(claim, Sha("admission|" + claim.Identity.DigestForEpoch(claim.Fence.Epoch)), cancellationToken).ConfigureAwait(false))
            return new HelloResult(HelloStatus.LeaseLost, "checkpoint_admission", null);

        // Model step: the first call asks for the one tool.
        var requestTool = HelloRequests.RequestTool(name, settings);
        var (firstStop, firstBody) = await StepAsync(executor, effects, claim, HelloSteps.RequestTool, EffectKind.ModelCall, requestTool, pinned, settings.MaxOutputTokens, 1, cancellationToken).ConfigureAwait(false);
        if (firstStop is not null) return await ApplyStopAsync(executor, claim, firstStop, cancellationToken).ConfigureAwait(false);

        ToolProposal proposal;
        try
        {
            proposal = HelloResponses.ParseToolProposal(firstBody!, name);
        }
        catch (HelloResponseException exception)
        {
            return await SettleAsync(executor, claim, RunState.Failed, HelloStatus.Failed, exception.Code, null, cancellationToken).ConfigureAwait(false);
        }

        if (!await CheckpointAsync(claim, Sha(firstBody!), cancellationToken).ConfigureAwait(false))
            return new HelloResult(HelloStatus.LeaseLost, "checkpoint_model", null);

        // Tool step: the verified name, through the local say_hello tool. No external effect.
        var (toolStop, greeting) = await StepAsync(executor, effects, claim, HelloSteps.SayHello, EffectKind.ToolInvocation, name, pinned, 0, 0, cancellationToken).ConfigureAwait(false);
        if (toolStop is not null) return await ApplyStopAsync(executor, claim, toolStop, cancellationToken).ConfigureAwait(false);
        if (!await CheckpointAsync(claim, Sha(greeting!), cancellationToken).ConfigureAwait(false))
            return new HelloResult(HelloStatus.LeaseLost, "checkpoint_tool", null);

        // Final step: the second model call with the verified tool result and tools switched off.
        var finish = HelloRequests.Finish(name, proposal.CallId, greeting!, settings);
        var (finalStop, finalBody) = await StepAsync(executor, effects, claim, HelloSteps.FinishGreeting, EffectKind.ModelCall, finish, pinned, settings.MaxOutputTokens, 0, cancellationToken).ConfigureAwait(false);
        if (finalStop is not null) return await ApplyStopAsync(executor, claim, finalStop, cancellationToken).ConfigureAwait(false);

        string message;
        try
        {
            message = HelloResponses.ParseFinal(finalBody!);
        }
        catch (HelloResponseException exception)
        {
            return await SettleAsync(executor, claim, RunState.Failed, HelloStatus.Failed, exception.Code, null, cancellationToken).ConfigureAwait(false);
        }

        if (!await CheckpointAsync(claim, Sha(finalBody!), cancellationToken).ConfigureAwait(false))
            return new HelloResult(HelloStatus.LeaseLost, "checkpoint_final", null);
        return await SettleAsync(executor, claim, RunState.Succeeded, HelloStatus.Succeeded, "ok", message, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>One counted step: stage, reserve, dispatch once and record the outcome (the executor), then read the answer body of the command.</summary>
    private static async Task<(Stop? Stop, string? Body)> StepAsync(
        HarnessExecutor executor,
        HelloEffectPort effects,
        ClaimedRun claim,
        string operation,
        EffectKind kind,
        string body,
        PinnedSnapshot pinned,
        int maxOutputTokens,
        int toolCount,
        CancellationToken cancellationToken)
    {
        effects.Stage(operation, body, toolCount);
        var request = new EffectRequest(kind, operation, Convert.ToHexStringLower(Sha(body)), pinned, maxOutputTokens, Encoding.UTF8.GetByteCount(body), toolCount);
        var step = await executor.RunEffectAsync(claim, request, LoopBounds.Default, cancellationToken).ConfigureAwait(false);
        switch (step.Status)
        {
            case EffectStepStatus.Succeeded:
                var answer = step.CommandId is { } commandId ? effects.TakeBody(commandId) : null;
                return answer is null ? (new Stop(HelloStatus.Interrupted, RunState.Interrupted, "result_missing_" + operation), null) : (null, answer);
            case EffectStepStatus.UnknownEffect:
                return (new Stop(HelloStatus.Interrupted, RunState.Interrupted, "unknown_effect_" + operation), null);
            case EffectStepStatus.FailedDidNotHappen:
                return (new Stop(HelloStatus.Failed, RunState.Failed, "step_failed_" + operation), null);
            case EffectStepStatus.RefusedExhausted:
                return (new Stop(HelloStatus.Failed, RunState.Failed, "step_refused_" + operation), null);
            default:
                return (NotDispatchedStop(step.Reason, operation), null);
        }
    }

    /// <summary>What a step that made no external call does to the run. A stop with no next state writes nothing further.</summary>
    private static Stop NotDispatchedStop(NotDispatchedReason reason, string operation) => reason switch
    {
        NotDispatchedReason.LeaseLost or NotDispatchedReason.StaleWriter or NotDispatchedReason.StoreRefused => new Stop(HelloStatus.LeaseLost, null, reason + "_" + operation),
        NotDispatchedReason.StoreUnknown or NotDispatchedReason.StoreUnavailable => new Stop(HelloStatus.Interrupted, RunState.Interrupted, reason + "_" + operation),
        NotDispatchedReason.NotFound => new Stop(HelloStatus.Failed, null, "run_missing"),
        NotDispatchedReason.BudgetPausedAtEffectGuard => new Stop(HelloStatus.Refused, RunState.Paused, "budget_paused"),
        _ => new Stop(HelloStatus.Failed, RunState.Failed, reason + "_" + operation),
    };

    private async Task<HelloResult> ApplyStopAsync(HarnessExecutor executor, ClaimedRun claim, Stop stop, CancellationToken cancellationToken) =>
        stop.Next is { } next
            ? await SettleAsync(executor, claim, next, stop.Status, stop.Reason, null, cancellationToken).ConfigureAwait(false)
            : new HelloResult(stop.Status, stop.Reason, null);

    /// <summary>Releases the lease to a state. A refused release reports a lost lease: the outcome is never claimed as settled.</summary>
    private static async Task<HelloResult> SettleAsync(HarnessExecutor executor, ClaimedRun claim, RunState next, HelloStatus status, string reason, string? message, CancellationToken cancellationToken)
    {
        var stored = await executor.YieldAsync(claim, next, cancellationToken).ConfigureAwait(false);
        return stored == StoreStatus.Succeeded ? new HelloResult(status, reason, message) : new HelloResult(HelloStatus.LeaseLost, "release_" + stored.ToString().ToLowerInvariant(), null);
    }

    private async Task<bool> CheckpointAsync(ClaimedRun claim, byte[] receipt, CancellationToken cancellationToken) =>
        await store.CheckpointAsync(claim.Fence, ids.NewId(), receipt, Micros(), cancellationToken).ConfigureAwait(false) == StoreStatus.Succeeded;

    private long Micros() => (time.GetUtcNow() - DateTimeOffset.UnixEpoch).Ticks / 10;

    private static HelloResult Refused(string reason) => new(HelloStatus.Refused, reason, null);

    private static byte[] Sha(string text) => SHA256.HashData(Encoding.UTF8.GetBytes(text));

    private static bool IsBoundedToken(string value) =>
        value.Length is >= 1 and <= 128 && value.All(character => character is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '_' or ':' or '/' or '-');

    /// <summary>A stop: the status to report and the state to release the run to, or none when the fence is gone and nothing may be written.</summary>
    private sealed record Stop(HelloStatus Status, RunState? Next, string Reason);
}
