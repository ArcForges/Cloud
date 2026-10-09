// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Agent.Dispatch.Domain;

/// <summary>
/// One token bucket per admitted model (HAR.40 validation b: per-model token-bucket admission). A call takes one token; a call that finds no
/// token is refused before any dispatch. The buckets live in this process: with one Container instance (production max_instances 1) they are
/// the whole admission, and a larger fleet needs a shared admission record first (a remaining item in the report).
/// </summary>
internal sealed class ModelRateBuckets(int capacity, int refillPerSecond)
{
    /// <summary>One whole token in micro-tokens. A microsecond refills refillPerSecond micro-tokens.</summary>
    private const long MicroPerToken = 1_000_000;

    private readonly object gate = new();
    private readonly Dictionary<string, (long MicroTokens, long AtMicros)> buckets = new(StringComparer.Ordinal);

    /// <summary>Takes one token of <paramref name="model"/> at <paramref name="nowMicros"/>; false when the bucket holds none.</summary>
    public bool TryTake(string model, long nowMicros)
    {
        ArgumentException.ThrowIfNullOrEmpty(model);
        var full = capacity * MicroPerToken;
        lock (gate)
        {
            var (tokens, at) = buckets.TryGetValue(model, out var stored) ? stored : (full, nowMicros);
            var elapsed = Math.Max(0, nowMicros - at);
            tokens = Math.Min(full, tokens + elapsed * refillPerSecond);
            var allowed = tokens >= MicroPerToken;
            if (allowed) tokens -= MicroPerToken;
            buckets[model] = (tokens, nowMicros);
            return allowed;
        }
    }
}
