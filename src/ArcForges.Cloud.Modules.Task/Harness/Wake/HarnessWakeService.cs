// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Infrastructure;

namespace ArcForges.Cloud.Modules.Task.Harness.Wake;

/// <summary>
/// The wake of a run as the Task module serves it (HAR.40): the signed wake claims the run under the Cloud build identity and the Worker
/// version identifier, resumes it and releases the lease to Waiting. It runs no model or tool step; every decision is C#. The host composes it
/// with its own W2C verifier, so the module never depends on the signing implementation.
/// </summary>
public sealed class HarnessWakeService(
    IModulePlanPort plans,
    string cloudBuildIdentity,
    long recoveryGeneration,
    TimeProvider time,
    Func<string, string, string, Func<string, string?>, bool> verify) : IHarnessWakePort
{
    /// <summary>True only when the verifier accepts the signature over the exact method, target and body hash.</summary>
    public bool Authenticate(string method, string rawTarget, string bodySha256Hex, Func<string, string?> header)
    {
        ArgumentNullException.ThrowIfNull(header);
        return verify(method, rawTarget, bodySha256Hex, header);
    }

    /// <summary>
    /// Takes one wake. A run that is absent, not claimable or at another recovery generation is taken as delivered. A run whose live lease
    /// belongs to another holder, a store that cannot settle the wake and a read that is not served are retried (Stopped, Unavailable).
    /// </summary>
    public async Task<HarnessWakeReply> HandleAsync(HarnessWakeMessage message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(message);
        if (!IsWorkerVersion(message.WorkerVersion)) throw new ArgumentException("A wake carries a bounded Worker version identifier.", nameof(message));
        var executor = new HarnessExecutor(new D1HarnessStore(plans), new NoDispatchEffects(), new RandomHarnessIds(), time);
        // A wake dispatches nothing, so it carries no pinned model or tariff; its claim inherits the pair the run stores (ClaimPinRule.InheritStored),
        // and the identity still binds the Worker version and the build.
        var identity = new RunIdentity(message.RunId, cloudBuildIdentity, message.WorkerVersion, recoveryGeneration, new PinnedSnapshot(string.Empty, string.Empty));
        var outcome = await new HarnessWakeHandler(executor).HandleAsync(new HarnessRun(message.WorkspaceId, message.RunId), identity, cancellationToken).ConfigureAwait(false);
        return outcome.Status switch
        {
            WakeStatus.Stopped => HarnessWakeReply.Stopped,
            WakeStatus.Unavailable => HarnessWakeReply.Unavailable,
            _ => HarnessWakeReply.Taken,
        };
    }

    internal static bool IsWorkerVersion(string value) =>
        value.Length is >= 1 and <= 128 && value.All(character => character is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '_' or ':' or '-');

    /// <summary>A wake must never reach an external effect: any dispatch here is a programming error and fails closed.</summary>
    private sealed class NoDispatchEffects : IEffectPort
    {
        public Task<EffectResult> DispatchAsync(EffectCall call, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("A wake dispatches no external effect.");
    }
}
