// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Application;

internal enum WakeStatus
{
    /// <summary>The wake was not for a claimable run, or the claim lost a race; nothing was written.</summary>
    NotClaimed,

    /// <summary>The run was claimed, its open attempt settled, and the lease released to waiting.</summary>
    Settled,

    /// <summary>The wake could not be settled under the fence; the lease is not released by this path.</summary>
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
        if (claimed.Status != ClaimStatus.Claimed || claimed.Claim is null)
            return new WakeOutcome(WakeStatus.NotClaimed, claimed.Status, null, null);

        var claim = claimed.Claim;
        var resumed = await executor.ResumeAsync(claim, cancellationToken).ConfigureAwait(false);
        if (resumed.Kind == ResumeKind.Stopped)
            return new WakeOutcome(WakeStatus.Stopped, ClaimStatus.Claimed, resumed.Kind, null);

        var released = await executor.YieldAsync(claim, RunState.Waiting, cancellationToken).ConfigureAwait(false);
        return released == StoreStatus.Succeeded
            ? new WakeOutcome(WakeStatus.Settled, ClaimStatus.Claimed, resumed.Kind, RunState.Waiting)
            : new WakeOutcome(WakeStatus.Stopped, ClaimStatus.Claimed, resumed.Kind, null);
    }
}
