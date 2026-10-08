// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

/// <summary>What one dispatched or refused effect attempt is known to have done.</summary>
internal enum EffectResultKind
{
    /// <summary>The supplier answered; the effect happened and its result is recorded.</summary>
    Succeeded,

    /// <summary>Refused before the request was processed; the effect did not happen.</summary>
    RefusedBeforeDispatch,

    /// <summary>Definitively failed and the effect did not happen (for example a validation refusal).</summary>
    FailedDidNotHappen,

    /// <summary>Anything else, including a lost response, a cancellation and an exception after the call was made.</summary>
    Unknown,
}

internal enum RetryDecision
{
    /// <summary>A fresh attempt with a new attempt identity may follow.</summary>
    Retry,

    /// <summary>The effect is settled (succeeded, or failed without a retry); no further attempt is made.</summary>
    Settled,

    /// <summary>The effect is unknown after its dispatch intent; it is never retried automatically (contracts 05 line 88).</summary>
    NeverRetriedUnknown,

    /// <summary>Pre-dispatch retries are exhausted.</summary>
    Exhausted,
}

internal static class RetryPolicy
{
    /// <summary>
    /// Only a refusal before dispatch may be retried, at most <see cref="BudgetPolicy.MaxPreDispatchRetries"/> times. An attempt is
    /// ordinal 1 for the first try, so ordinal N has N-1 retries behind it.
    /// </summary>
    internal static RetryDecision Decide(EffectResultKind kind, int attemptOrdinal)
    {
        if (attemptOrdinal < 1) throw new ArgumentOutOfRangeException(nameof(attemptOrdinal));
        return kind switch
        {
            EffectResultKind.Succeeded => RetryDecision.Settled,
            EffectResultKind.FailedDidNotHappen => RetryDecision.Settled,
            EffectResultKind.Unknown => RetryDecision.NeverRetriedUnknown,
            EffectResultKind.RefusedBeforeDispatch when attemptOrdinal - 1 < BudgetPolicy.MaxPreDispatchRetries => RetryDecision.Retry,
            _ => RetryDecision.Exhausted,
        };
    }
}
