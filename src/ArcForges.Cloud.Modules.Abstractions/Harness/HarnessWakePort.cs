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
