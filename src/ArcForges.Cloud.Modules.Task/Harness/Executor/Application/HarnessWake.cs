// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Application;

internal enum WakeStatus
{
    /// <summary>The wake was not for a claimable run, or the run is not claimable now; nothing was written.</summary>
    NotClaimed,

    /// <summary>The run was claimed, its open attempt settled, and the lease released to waiting.</summary>
    Settled,

    /// <summary>
    /// The wake could not be settled: the store was unknown or unavailable, a live lease of another holder refused the claim (the holder may
    /// have crashed, so the wake is retried across the lease term), or the recorded state could not be resumed under the fence. The caller
    /// answers a retryable status so the wake is delivered again.
    /// </summary>
    Stopped,

    /// <summary>A store read was not served. Nothing was claimed or dispatched; the caller answers a typed retryable status.</summary>
    Unavailable,
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
        ClaimResult claimed;
        try
        {
            // The wake's own counted calls are charged in its claim batch: the wait cycle and container call that delivered it, and the open-attempt
            // read of the resume that follows under the new lease (BudgetDefinition). The wake carries no pin: it claims under the pair the run stores.
            claimed = await executor.ClaimAsync(
                run,
                identity,
                BudgetDefinition.WakeDelivery + BudgetDefinition.ResumeRead,
                ClaimPinRule.InheritStored,
                cancellationToken).ConfigureAwait(false);
        }
        catch (HarnessReadUnavailableException)
        {
            // A read failed. If the claim itself committed, the lease it left is this wake's own and expires on its term; the retry waits it out.
            return new WakeOutcome(WakeStatus.Unavailable, ClaimStatus.Unavailable, null, null);
        }

        // An unsettled store is never a delivered wake, and a run whose live lease belongs to another holder is not skipped: both are retried.
        if (claimed.Status is ClaimStatus.Unknown or ClaimStatus.Unavailable or ClaimStatus.Refused)
            return new WakeOutcome(WakeStatus.Stopped, claimed.Status, null, null);
        if (claimed.Status != ClaimStatus.Claimed || claimed.Claim is null)
            return new WakeOutcome(WakeStatus.NotClaimed, claimed.Status, null, null);

        var claim = claimed.Claim;
        ResumeResult resumed;
        try
        {
            resumed = await executor.ResumeAsync(claim, cancellationToken).ConfigureAwait(false);
        }
        catch (HarnessReadUnavailableException)
        {
            // Nothing was dispatched. The lease this wake holds is released to waiting so the retry claims at once instead of seeing its own lease.
            _ = await executor.YieldAsync(claim, RunState.Waiting, cancellationToken).ConfigureAwait(false);
            return new WakeOutcome(WakeStatus.Unavailable, ClaimStatus.Claimed, null, null);
        }

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
