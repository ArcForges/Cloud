// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Application;

internal enum WakeStatus
{
    /// <summary>The wake was not for a claimable run, or the claim lost a race; nothing was written.</summary>
    NotClaimed,

    /// <summary>The run was claimed, its open attempt settled, and the lease released to waiting.</summary>
    Settled,

    /// <summary>
    /// The wake could not be settled because the store was unknown or unavailable, or the recorded state could not be resumed under the
    /// fence. The caller answers a retryable status so the wake is delivered again.
    /// </summary>
    Stopped,
}

internal sealed record WakeOutcome(WakeStatus Status, ClaimStatus Claim, ResumeKind? Resume, RunState? ReleasedTo);

/// <summary>
/// The wake of a run: claim, resume, release. It is the foundation the Harness loop of HAR.00 builds on; it runs no model or tool step.
/// The Durable Object alarm and the Worker only deliver the wake, and every decision here is C#.
/// </summary>
internal sealed class HarnessWakeHandler(HarnessExecutor executor)
{
    internal async Task<WakeOutcome> HandleAsync(HarnessRun run, RunIdentity identity, CancellationToken cancellationToken)
    {
        var claimed = await executor.ClaimAsync(run, identity, cancellationToken).ConfigureAwait(false);
        // An unsettled store is never a delivered wake: the caller retries it. Any other refusal is a run that is not ours to wake.
        if (claimed.Status is ClaimStatus.Unknown or ClaimStatus.Unavailable)
            return new WakeOutcome(WakeStatus.Stopped, claimed.Status, null, null);
        if (claimed.Status != ClaimStatus.Claimed || claimed.Claim is null)
            return new WakeOutcome(WakeStatus.NotClaimed, claimed.Status, null, null);

        var claim = claimed.Claim;
        var resumed = await executor.ResumeAsync(claim, cancellationToken).ConfigureAwait(false);
        if (resumed.Kind == ResumeKind.Stopped)
        {
            // The wake dispatches nothing, so the lease it holds is released to waiting when the store allows it. Otherwise the retry would
            // see its own live lease and be taken as delivered. A release that cannot settle leaves the lease to its term.
            _ = await executor.YieldAsync(claim, RunState.Waiting, cancellationToken).ConfigureAwait(false);
            return new WakeOutcome(WakeStatus.Stopped, ClaimStatus.Claimed, resumed.Kind, null);
        }

        var released = await executor.YieldAsync(claim, RunState.Waiting, cancellationToken).ConfigureAwait(false);
        return released == StoreStatus.Succeeded
            ? new WakeOutcome(WakeStatus.Settled, ClaimStatus.Claimed, resumed.Kind, RunState.Waiting)
            : new WakeOutcome(WakeStatus.Stopped, ClaimStatus.Claimed, resumed.Kind, null);
    }
}
