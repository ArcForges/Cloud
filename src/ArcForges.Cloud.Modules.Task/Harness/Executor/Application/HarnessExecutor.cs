// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Application;

/// <summary>A claimed run: the fence of this claim and the local view of its lease. It is held by one executor only.</summary>
internal sealed class ClaimedRun
{
    internal ClaimedRun(RunIdentity identity, Fence fence, long expiresAtMicros, long renewedAtMicros, RunSnapshot admitted)
    {
        Identity = identity;
        Fence = fence;
        ExpiresAtMicros = expiresAtMicros;
        RenewedAtMicros = renewedAtMicros;
        Admitted = admitted;
    }

    internal RunIdentity Identity { get; }

    internal Fence Fence { get; }

    /// <summary>The run as the claim left it, read under the new lease: its budget already carries the claim's charge.</summary>
    internal RunSnapshot Admitted { get; }

    internal long ExpiresAtMicros { get; set; }

    internal long RenewedAtMicros { get; set; }

    /// <summary>False once this executor released the lease; a released fence never writes again.</summary>
    internal bool Released { get; set; }
}

internal enum ClaimStatus
{
    Claimed,

    /// <summary>The run is not in a claimable state (running, paused, succeeded and so on).</summary>
    NotClaimable,

    /// <summary>The run does not exist in this workspace.</summary>
    NotFound,

    /// <summary>The recovery generation of the identity is not the run's current generation.</summary>
    StaleGeneration,

    /// <summary>
    /// The identity's model and tariff pin is not the pin the run was first claimed with, or the identity is unpinned. Nothing is claimed and
    /// nothing is dispatched.
    /// </summary>
    PinRefused,

    /// <summary>Another live lease holds the run, or the claim lost a race.</summary>
    Refused,

    Unknown,
    Unavailable,
}

internal sealed record ClaimResult(ClaimStatus Status, ClaimedRun? Claim, long? Epoch);

/// <summary>How a claim decides its pin (HAR.40 validation (f)).</summary>
internal enum ClaimPinRule
{
    /// <summary>The caller supplies the model and tariff pair it will dispatch against; an unpinned identity is refused.</summary>
    Supplied,

    /// <summary>A wake dispatches nothing and supplies no pin: the claim uses the pair the run already stores, and is refused when none is stored.</summary>
    InheritStored,
}

internal enum EffectStepStatus
{
    /// <summary>The supplier answered and the outcome is recorded.</summary>
    Succeeded,

    /// <summary>The effect did not happen and was recorded as a failure with no retry.</summary>
    FailedDidNotHappen,

    /// <summary>Every pre-dispatch attempt was refused; the step is settled as refused.</summary>
    RefusedExhausted,

    /// <summary>The dispatch was made and its effect is unknown; it is never retried and waits for reconciliation.</summary>
    UnknownEffect,

    /// <summary>
    /// No external call was made by this step (see <see cref="EffectStepResult.Reason"/>). A step with this status never reached the supplier
    /// call. A dispatch intent may still be durable when the intent write itself was unknown; the resume then records that effect as unknown
    /// and never dispatches it again.
    /// </summary>
    NotDispatched,

    /// <summary>
    /// The supplier call was made, but its outcome could not be recorded under the fence (<see cref="EffectStepResult.Kind"/> is what the
    /// supplier answered, when it answered). The durable state stays dispatching, so the effect is unknown to the caller: it is never retried,
    /// and the next resume records it as unknown. The caller must reconcile it as an interrupted effect, never as one that did not happen.
    /// </summary>
    OutcomeNotRecorded,
}

internal enum NotDispatchedReason
{
    None,
    LeaseLost,
    PinRefused,
    RequestOutsideCaps,
    BudgetPausedAtEffectGuard,
    BudgetHardStepCeiling,
    BudgetSubrequestStop,
    BudgetModelCallCap,
    BudgetToolInvocationCap,
    StoreRefused,
    StoreUnknown,
    StoreUnavailable,
    StaleWriter,
    NotFound,
}

/// <summary>
/// The result of one effect step. <see cref="Reason"/> says why a step stopped without a settled outcome: for <see cref="EffectStepStatus.NotDispatched"/>
/// why no call was made, for <see cref="EffectStepStatus.OutcomeNotRecorded"/> which store status refused the outcome.
/// </summary>
internal sealed record EffectStepResult(EffectStepStatus Status, NotDispatchedReason Reason, Guid? CommandId, int Attempts, EffectResultKind? Kind);

internal enum ResumeKind
{
    /// <summary>No attempt is open; nothing to resume.</summary>
    NothingOpen,

    /// <summary>A reserved attempt had no dispatch intent: it is recorded as refused before dispatch, so a fresh attempt may follow.</summary>
    ReleasedBeforeDispatch,

    /// <summary>A dispatch intent had no outcome: the effect is unknown. It is never dispatched again.</summary>
    UnknownEffectRecorded,

    /// <summary>The recorded state could not be settled under this fence.</summary>
    Stopped,
}

internal sealed record ResumeResult(ResumeKind Kind, Guid? CommandId, StoreStatus? Store);

/// <summary>
/// The C# executor of one run. It claims a lease (60 seconds, renewed every 20 seconds), reserves every counted step under the fence
/// before dispatch, records a durable dispatch intent before the external call, records every outcome under the fence, and on resume
/// never dispatches an effect whose intent was recorded. Each effect is dispatched at most once per command; a pre-dispatch refusal
/// may be retried at most <see cref="BudgetPolicy.MaxPreDispatchRetries"/> times with a fresh attempt identity.
/// </summary>
internal sealed class HarnessExecutor(IHarnessStore store, IEffectPort effects, IHarnessIds ids, TimeProvider time)
{
    private const int MaxResultRefLength = 128;

    /// <summary>Claims the run for this executor. The epoch of the new lease is one more than the previous one.</summary>
    internal Task<ClaimResult> ClaimAsync(HarnessRun run, RunIdentity identity, CancellationToken cancellationToken) =>
        ClaimAsync(run, identity, BudgetCharge.Zero, ClaimPinRule.Supplied, cancellationToken);

    /// <summary>
    /// Claims the run. <paramref name="extraCharge"/> is the charge of what the caller does under the claim (a wake delivery and its resume read);
    /// it is written in the claim batch with the claim's own charge, so the counters never lag the calls.
    /// </summary>
    internal Task<ClaimResult> ClaimAsync(HarnessRun run, RunIdentity identity, BudgetCharge extraCharge, CancellationToken cancellationToken) =>
        ClaimAsync(run, identity, extraCharge, ClaimPinRule.Supplied, cancellationToken);

    /// <summary>
    /// Claims the run under <paramref name="pinRule"/>. A dispatching caller supplies its pin (<see cref="ClaimPinRule.Supplied"/>). A wake dispatches
    /// nothing and carries no pin, so it claims under the pin the run already stores (<see cref="ClaimPinRule.InheritStored"/>): the claim batch then
    /// writes the same pair, and a run that never stored a pin is refused before any write.
    /// </summary>
    internal async Task<ClaimResult> ClaimAsync(HarnessRun run, RunIdentity identity, BudgetCharge extraCharge, ClaimPinRule pinRule, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(identity);
        if (identity.RunId != run.RunId) throw new ArgumentException("The identity names another run.", nameof(identity));
        var before = await store.LoadAsync(run, cancellationToken).ConfigureAwait(false);
        if (before is null) return new ClaimResult(ClaimStatus.NotFound, null, null);
        if (before.RecoveryGeneration != identity.RecoveryGeneration) return new ClaimResult(ClaimStatus.StaleGeneration, null, null);
        if (before.State is not (RunState.Queued or RunState.Running or RunState.Waiting or RunState.Interrupted))
            return new ClaimResult(ClaimStatus.NotClaimable, null, null);

        // The pin is the model and tariff pair the run was first claimed with. A different pair is refused here and again in the claim batch, so
        // no lease is taken and nothing is dispatched under a changed pin. An inherited pin is the stored pair, so it cannot differ.
        var pin = identity.Pinned;
        if (pinRule == ClaimPinRule.InheritStored && !pin.IsPinned)
        {
            if (before.Pin is null) return new ClaimResult(ClaimStatus.PinRefused, null, null);
            pin = before.Pin;
        }

        if (!pin.IsPinned || (before.Pin is not null && !before.Pin.Matches(pin)))
            return new ClaimResult(ClaimStatus.PinRefused, null, null);
        identity = identity with { Pinned = pin };

        var holder = ids.NewId();
        var now = Micros();
        var expires = now + LeasePolicy.TermMicros;
        var status = await store.ClaimAsync(
            run,
            new ClaimCommand(
                ids.NewId(),
                holder,
                identity.WorkflowId,
                identity.WorkerVersion,
                identity.RecoveryGeneration,
                now,
                expires,
                identity.Pinned,
                BudgetDefinition.Claim + extraCharge),
            cancellationToken).ConfigureAwait(false);
        if (status != StoreStatus.Succeeded) return new ClaimResult(FromStore(status), null, null);

        // The claim is real only when this holder owns the lease that the store now shows.
        var after = await store.LoadAsync(run, cancellationToken).ConfigureAwait(false);
        if (after is null || after.Lease is not { } lease || lease.Holder != holder) return new ClaimResult(ClaimStatus.Refused, null, null);
        var fence = new Fence(run, holder, lease.Epoch, identity.RecoveryGeneration);
        return new ClaimResult(ClaimStatus.Claimed, new ClaimedRun(identity, fence, lease.ExpiresAtMicros, now, after), lease.Epoch);
    }

    /// <summary>Renews the lease when a renewal is due. Returns false when the lease is lost; the caller then makes no further call.</summary>
    internal async Task<bool> RenewIfDueAsync(ClaimedRun claim, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claim);
        if (claim.Released) return false;
        var now = Micros();
        if (now >= claim.ExpiresAtMicros) return false;
        if (!LeasePolicy.RenewalDue(claim.RenewedAtMicros, now)) return true;
        var expires = now + LeasePolicy.TermMicros;
        var status = await store.RenewAsync(claim.Fence, ids.NewId(), now, expires, cancellationToken).ConfigureAwait(false);
        if (status != StoreStatus.Succeeded) return false;
        claim.ExpiresAtMicros = expires;
        claim.RenewedAtMicros = now;
        return true;
    }

    /// <summary>
    /// Runs one effect step: reserve, record the dispatch intent, dispatch once, record the outcome, and retry only a pre-dispatch refusal.
    /// Every write is fenced; the first refused fence stops the step with no further call.
    /// </summary>
    internal async Task<EffectStepResult> RunEffectAsync(ClaimedRun claim, EffectRequest request, LoopBounds bounds, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claim);
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(bounds);
        if (claim.Released) return NotDispatched(NotDispatchedReason.LeaseLost, null, 0);
        if (!await RenewIfDueAsync(claim, cancellationToken).ConfigureAwait(false)) return NotDispatched(NotDispatchedReason.LeaseLost, null, 0);
        if (!claim.Identity.Pinned.Matches(request.Pinned)) return NotDispatched(NotDispatchedReason.PinRefused, null, 0);
        if (request.Kind == EffectKind.ModelCall
            && !ModelRequestCaps.Admits(request.MaxOutputTokens, request.TextInputTokens, request.ToolCount))
            return NotDispatched(NotDispatchedReason.RequestOutsideCaps, null, 0);

        // This read is the first attempt's counted state read (see BudgetDefinition.ModelAttempt); the reservation below charges it.
        var snapshot = await store.LoadAsync(claim.Fence.Run, cancellationToken).ConfigureAwait(false);
        if (snapshot is null) return NotDispatched(NotDispatchedReason.NotFound, null, 0);
        if (snapshot.Lease?.Holder != claim.Fence.Holder) return NotDispatched(NotDispatchedReason.LeaseLost, null, 0);
        if (snapshot.Pin is null || !snapshot.Pin.Matches(request.Pinned)) return NotDispatched(NotDispatchedReason.PinRefused, null, 0);
        var local = BudgetGuard.ForEffect(snapshot.Budget, CostOf(request.Kind, 1), bounds);
        if (local != GuardDecision.Allowed) return NotDispatched(FromGuard(local), null, 0);

        var commandId = ids.NewId();
        var stepId = ids.NewId();
        var requestSha = claim.Identity.DigestForEpoch(claim.Fence.Epoch) + ":" + request.RequestDigest;
        var requestHash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(requestSha)));
        for (var ordinal = 1; ; ordinal++)
        {
            var attemptId = ids.NewId();
            var cost = CostOf(request.Kind, ordinal);
            var reserve = await store.ReserveStepAsync(
                claim.Fence,
                new ReserveCommand(
                    ids.NewId(),
                    commandId,
                    attemptId,
                    stepId,
                    ordinal,
                    request.Operation,
                    requestHash,
                    cost,
                    BudgetPolicy.EffectStepGuard,
                    BudgetPolicy.EffectSubrequestStop,
                    bounds.ModelCalls,
                    bounds.ToolInvocations,
                    Micros(),
                    request.Pinned),
                cancellationToken).ConfigureAwait(false);
            if (reserve != StoreStatus.Succeeded) return await ExplainRefusalAsync(claim, reserve, ordinal, commandId, cost, cancellationToken).ConfigureAwait(false);

            var intent = await store.MarkDispatchAsync(claim.Fence, ids.NewId(), attemptId, Micros(), cancellationToken).ConfigureAwait(false);
            if (intent != StoreStatus.Succeeded)
            {
                // No intent is durable, so nothing was or will be dispatched by this attempt.
                return NotDispatched(FromStoreStep(intent), commandId, ordinal);
            }

            EffectResult result;
            try
            {
                result = await effects.DispatchAsync(
                    new EffectCall(commandId, attemptId, stepId, request.Operation, requestHash, request.Pinned, cost),
                    cancellationToken).ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                // A call that raised may have reached the supplier: its effect is unknown and it is never retried.
                _ = exception;
                result = new EffectResult(EffectResultKind.Unknown, null);
            }

            var kind = result.Kind;
            if (kind == EffectResultKind.Succeeded && !IsBoundedRef(result.ResultRef))
            {
                // The answer cannot be recorded as a bounded reference, so it is recorded as unknown rather than guessed.
                kind = EffectResultKind.Unknown;
            }

            // The stored result is a JSON reference object, never the content.
            var resultRef = kind == EffectResultKind.Succeeded ? "{\"ref\":\"" + result.ResultRef + "\"}" : null;

            var outcome = Describe(kind);
            var recorded = await store.RecordOutcomeAsync(
                claim.Fence,
                new OutcomeCommand(
                    ids.NewId(),
                    attemptId,
                    AttemptState.Running,
                    CommandStates.Dispatching,
                    outcome.Attempt,
                    outcome.Failure,
                    outcome.Certainty,
                    outcome.Command,
                    resultRef,
                    Micros(),
                    BudgetCharge.Zero),
                cancellationToken).ConfigureAwait(false);
            if (recorded != StoreStatus.Succeeded)
            {
                // The supplier was called: this is not a NotDispatched step. The durable state stays dispatching, so a resume records the effect
                // as unknown and never repeats it.
                return new EffectStepResult(EffectStepStatus.OutcomeNotRecorded, FromStoreStep(recorded), commandId, ordinal, kind);
            }

            switch (RetryPolicy.Decide(kind, ordinal))
            {
                case RetryDecision.Retry:
                    continue;
                case RetryDecision.Settled when kind == EffectResultKind.Succeeded:
                    return new EffectStepResult(EffectStepStatus.Succeeded, NotDispatchedReason.None, commandId, ordinal, kind);
                case RetryDecision.Settled:
                    return new EffectStepResult(EffectStepStatus.FailedDidNotHappen, NotDispatchedReason.None, commandId, ordinal, kind);
                case RetryDecision.NeverRetriedUnknown:
                    return new EffectStepResult(EffectStepStatus.UnknownEffect, NotDispatchedReason.None, commandId, ordinal, kind);
                default:
                    return new EffectStepResult(EffectStepStatus.RefusedExhausted, NotDispatchedReason.None, commandId, ordinal, kind);
            }
        }
    }

    /// <summary>
    /// Resumes after a crash or a takeover. A reserved attempt without a dispatch intent is released as refused (nothing was sent). A
    /// dispatch intent without an outcome is recorded as an unknown effect and is never dispatched again.
    /// </summary>
    internal async Task<ResumeResult> ResumeAsync(ClaimedRun claim, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claim);
        if (claim.Released) return new ResumeResult(ResumeKind.Stopped, null, StoreStatus.Refused);
        var open = await store.LoadOpenAttemptAsync(claim.Fence.Run, cancellationToken).ConfigureAwait(false);
        if (open is null) return new ResumeResult(ResumeKind.NothingOpen, null, null);

        if (open.State == AttemptState.Pending && open.CommandState == CommandStates.Reserved)
        {
            var released = await store.RecordOutcomeAsync(
                claim.Fence,
                new OutcomeCommand(ids.NewId(), open.AttemptId, AttemptState.Pending, CommandStates.Reserved, AttemptState.Failed,
                    FailureClass.Refused, EffectCertainty.DidNotHappen, CommandStates.Refused, null, Micros(), BudgetDefinition.ResumedOutcome),
                cancellationToken).ConfigureAwait(false);
            return released == StoreStatus.Succeeded
                ? new ResumeResult(ResumeKind.ReleasedBeforeDispatch, open.CommandId, released)
                : new ResumeResult(ResumeKind.Stopped, open.CommandId, released);
        }

        if (open.State == AttemptState.Running && open.CommandState == CommandStates.Dispatching)
        {
            var unknown = await store.RecordOutcomeAsync(
                claim.Fence,
                new OutcomeCommand(ids.NewId(), open.AttemptId, AttemptState.Running, CommandStates.Dispatching, AttemptState.Failed,
                    FailureClass.UnknownEffect, EffectCertainty.Unknown, CommandStates.Outcome, null, Micros(), BudgetDefinition.ResumedOutcome),
                cancellationToken).ConfigureAwait(false);
            return unknown == StoreStatus.Succeeded
                ? new ResumeResult(ResumeKind.UnknownEffectRecorded, open.CommandId, unknown)
                : new ResumeResult(ResumeKind.Stopped, open.CommandId, unknown);
        }

        return new ResumeResult(ResumeKind.Stopped, open.CommandId, StoreStatus.Refused);
    }

    /// <summary>Gives up the lease and records the next run state under the fence. The released fence never writes again.</summary>
    internal async Task<StoreStatus> YieldAsync(ClaimedRun claim, RunState nextState, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(claim);
        if (nextState is RunState.Queued or RunState.Running) throw new ArgumentOutOfRangeException(nameof(nextState));
        if (claim.Released) return StoreStatus.Refused;
        var status = await store.YieldAsync(claim.Fence, ids.NewId(), nextState, Micros(), cancellationToken).ConfigureAwait(false);
        if (status == StoreStatus.Succeeded) claim.Released = true;
        return status;
    }

    private async Task<EffectStepResult> ExplainRefusalAsync(ClaimedRun claim, StoreStatus status, int ordinal, Guid commandId, EffectCost cost, CancellationToken cancellationToken)
    {
        var reason = FromStoreStep(status);
        if (status == StoreStatus.Refused)
        {
            var snapshot = await store.LoadAsync(claim.Fence.Run, cancellationToken).ConfigureAwait(false);
            if (snapshot?.Lease is not { } lease || lease.Holder != claim.Fence.Holder || Micros() >= lease.ExpiresAtMicros)
                reason = NotDispatchedReason.StaleWriter;
            else if (snapshot.Pin is null || !snapshot.Pin.Matches(claim.Identity.Pinned))
                reason = NotDispatchedReason.PinRefused;
            else if (snapshot.Budget.CountedSteps + cost.Steps > BudgetPolicy.EffectStepGuard)
                reason = NotDispatchedReason.BudgetPausedAtEffectGuard;
        }

        return NotDispatched(reason, commandId, ordinal - 1);
    }

    /// <summary>The reserved cost of one attempt of an effect of this kind (see <see cref="BudgetDefinition"/>).</summary>
    private static EffectCost CostOf(EffectKind kind, int ordinal) =>
        kind == EffectKind.ModelCall ? BudgetDefinition.ModelAttempt(ordinal) : BudgetDefinition.ToolAttempt(ordinal);

    private EffectStepResult NotDispatched(NotDispatchedReason reason, Guid? commandId, int attempts, EffectResultKind? kind = null) =>
        new(EffectStepStatus.NotDispatched, reason, commandId, attempts, kind);

    private long Micros() => (time.GetUtcNow() - DateTimeOffset.UnixEpoch).Ticks / 10;

    private static bool IsBoundedRef(string? value) =>
        value is not null && value.Length is >= 1 and <= MaxResultRefLength
        && value.All(character => character is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '_' or ':' or '/' or '-');

    private static (AttemptState Attempt, FailureClass? Failure, EffectCertainty? Certainty, string Command) Describe(EffectResultKind kind) => kind switch
    {
        EffectResultKind.Succeeded => (AttemptState.Succeeded, null, EffectCertainty.Happened, CommandStates.Outcome),
        EffectResultKind.RefusedBeforeDispatch => (AttemptState.Failed, FailureClass.Refused, EffectCertainty.DidNotHappen, CommandStates.Refused),
        EffectResultKind.FailedDidNotHappen => (AttemptState.Failed, FailureClass.Permanent, EffectCertainty.DidNotHappen, CommandStates.Outcome),
        _ => (AttemptState.Failed, FailureClass.UnknownEffect, EffectCertainty.Unknown, CommandStates.Outcome),
    };

    private static NotDispatchedReason FromGuard(GuardDecision decision) => decision switch
    {
        GuardDecision.PausedAtEffectGuard => NotDispatchedReason.BudgetPausedAtEffectGuard,
        GuardDecision.HardStepCeiling => NotDispatchedReason.BudgetHardStepCeiling,
        GuardDecision.SubrequestStop => NotDispatchedReason.BudgetSubrequestStop,
        GuardDecision.ModelCallCap => NotDispatchedReason.BudgetModelCallCap,
        GuardDecision.ToolInvocationCap => NotDispatchedReason.BudgetToolInvocationCap,
        _ => NotDispatchedReason.None,
    };

    private static NotDispatchedReason FromStoreStep(StoreStatus status) => status switch
    {
        StoreStatus.Refused => NotDispatchedReason.StoreRefused,
        StoreStatus.Stale => NotDispatchedReason.StaleWriter,
        StoreStatus.Unknown => NotDispatchedReason.StoreUnknown,
        StoreStatus.Unavailable => NotDispatchedReason.StoreUnavailable,
        _ => NotDispatchedReason.None,
    };

    private static ClaimStatus FromStore(StoreStatus status) => status switch
    {
        StoreStatus.Refused => ClaimStatus.Refused,
        StoreStatus.Stale => ClaimStatus.StaleGeneration,
        StoreStatus.Unknown => ClaimStatus.Unknown,
        StoreStatus.Unavailable => ClaimStatus.Unavailable,
        _ => ClaimStatus.Refused,
    };
}

internal enum EffectKind
{
    ModelCall,
    ToolInvocation,
}

/// <summary>
/// One effect request. It carries a digest of the request content rather than the content, so no prompt or body is ever persisted by
/// the executor (checkpoints are references only).
/// </summary>
internal sealed record EffectRequest(
    EffectKind Kind,
    string Operation,
    string RequestDigest,
    PinnedSnapshot Pinned,
    int MaxOutputTokens,
    int TextInputTokens,
    int ToolCount);
