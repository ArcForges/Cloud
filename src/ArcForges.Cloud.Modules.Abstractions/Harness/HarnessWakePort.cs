// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

/// <summary>The private route of the Durable Object wake (HAR.40). Only the Cloudflare Worker calls it, with a W2C signature.</summary>
public static class HarnessWakeRoute
{
    public const string Path = "/internal/harness/v1/wake";

    /// <summary>The largest wake body; the host's own body limit is far above it.</summary>
    public const int MaxBodyBytes = 4096;
}

/// <summary>One wake: a run and the Cloudflare Worker version identifier that delivered it. The Cloud build identity is the host's own.</summary>
public sealed record HarnessWakeMessage(Guid WorkspaceId, Guid RunId, string WorkerVersion, long WakeAtMs);

/// <summary>
/// What the wake did. <see cref="Stopped"/> means the store could not settle the wake, or a live lease of another holder refused it: the caller
/// retries it later. <see cref="Unavailable"/> means a store read was not served, so nothing was claimed or written; it is retryable too.
/// </summary>
public enum HarnessWakeReply
{
    Taken,
    Stopped,
    Unavailable,
}

/// <summary>The wake port of the Task module, implemented by the module and composed by the host with its own W2C verifier.</summary>
public interface IHarnessWakePort
{
    /// <summary>True only for a request whose W2C signature verifies over the exact method, target and body hash.</summary>
    bool Authenticate(string method, string rawTarget, string bodySha256Hex, Func<string, string?> header);

    Task<HarnessWakeReply> HandleAsync(HarnessWakeMessage message, CancellationToken cancellationToken);
}

/// <summary>
/// The schedule of one run's wake: the run and the Unix time in milliseconds at which its Durable Object alarm must deliver the wake (HAR.40).
/// The run is addressed by its workspace and run identifiers, the same pair the wake carries.
/// </summary>
public sealed record HarnessAlarmSchedule(Guid WorkspaceId, Guid RunId, long WakeAtMs);

/// <summary>
/// What the alarm arming did. <see cref="Armed"/> is the only reply that lets the executor park a run with a timer; every other outcome is a refusal,
/// and the executor does not park.
/// </summary>
public enum HarnessAlarmReply
{
    Armed,
    Refused,
}

/// <summary>
/// The alarm port of the Task module (HAR.40 alarm arming). The executor arms the run's wake before it parks the run with a timer and cancels it
/// on a best-effort basis when the parking commit fails. The implementation sends one closed JSON request to the outbound virtual host
/// <c>harness.internal</c>; it fails closed, so every transport or validation failure is a refusal and never a fault.
/// </summary>
public interface IHarnessAlarmPort
{
    /// <summary>Arms the run's wake for the scheduled time. <see cref="HarnessAlarmReply.Refused"/> on any failure.</summary>
    Task<HarnessAlarmReply> ScheduleAsync(HarnessAlarmSchedule schedule, CancellationToken cancellationToken);

    /// <summary>Cancels the run's armed wake. Best effort: the caller treats a failure as no cancellation, which a stray wake makes harmless.</summary>
    Task CancelAsync(Guid workspaceId, Guid runId, CancellationToken cancellationToken);
}
