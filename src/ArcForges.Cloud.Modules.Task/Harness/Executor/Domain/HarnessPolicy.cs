// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

/// <summary>The lease of one run: a 60-second term, renewed every 20 seconds under the live fence (contracts 05 sections 1 and 4).</summary>
internal static class LeasePolicy
{
    internal const long TermMicros = 60_000_000;
    internal const long RenewIntervalMicros = 20_000_000;

    /// <summary>True when a renewal is due at <paramref name="nowMicros"/> for a lease last renewed at <paramref name="renewedAtMicros"/>.</summary>
    internal static bool RenewalDue(long renewedAtMicros, long nowMicros) => nowMicros - renewedAtMicros >= RenewIntervalMicros;
}

/// <summary>
/// The executor's budget values (HAR.40 validation (b)). They are C# values under the reviewed budget definition, never the Cloudflare
/// Workflow platform settings they replace. Each is a ceiling the database also enforces at its hard value.
/// </summary>
internal static class BudgetPolicy
{
    /// <summary>New model or tool effects stop while the counted steps are at this value; the rest is reserved for reconciliation and finalisation.</summary>
    internal const long EffectStepGuard = 24_000;

    /// <summary>No counted step may follow once the counted steps reach this value (the hard ceiling).</summary>
    internal const long HardStepCeiling = 25_000;

    /// <summary>The 1,000 steps above the effect guard, reserved for final receipts and reconciliation.</summary>
    internal const long ReconciliationStepReserve = HardStepCeiling - EffectStepGuard;

    /// <summary>New model or tool dispatch stops at this many counted subrequests (contracts 05 line 170).</summary>
    internal const long EffectSubrequestStop = 900_000;

    /// <summary>The subrequest allowance of a run, of which the last 100,000 are reserved for reconciliation.</summary>
    internal const long SubrequestAllowance = 1_000_000;

    /// <summary>At most two pre-dispatch retries, each with a fresh attempt identity (contracts 05 line 88).</summary>
    internal const int MaxPreDispatchRetries = 2;

    /// <summary>The checkpoint limit: 128 KiB, references only (contracts 05 lines 15 and 151).</summary>
    internal const int CheckpointLimitBytes = 131_072;

    /// <summary>The Hello slice's current model deadline in seconds (AI src/index.ts lines 19 to 23); it may not exceed the Design 120 seconds.</summary>
    internal const int ModelDeadlineSeconds = 90;

    /// <summary>The Design loop deadline for an external model await (contracts 05 line 88).</summary>
    internal const int LoopDeadlineSeconds = 120;
}

/// <summary>
/// Loop bounds of one run. A policy may narrow a default and never enlarge a hard limit (contracts 05 line 86); a value outside
/// 1 to hard is refused when the policy is built.
/// </summary>
internal sealed record LoopBounds
{
    internal const int DefaultModelCalls = 16;
    internal const int HardModelCalls = 64;
    internal const int DefaultToolInvocations = 64;
    internal const int HardToolInvocations = 256;
    internal const int DefaultToolParallelism = 4;
    internal const int HardToolParallelism = 8;
    internal const int NoProgressLimit = 3;

    private LoopBounds(int modelCalls, int toolInvocations, int toolParallelism)
    {
        ModelCalls = modelCalls;
        ToolInvocations = toolInvocations;
        ToolParallelism = toolParallelism;
    }

    internal int ModelCalls { get; }

    internal int ToolInvocations { get; }

    internal int ToolParallelism { get; }

    /// <summary>The Design defaults, with no narrowing.</summary>
    internal static LoopBounds Default { get; } = new(DefaultModelCalls, DefaultToolInvocations, DefaultToolParallelism);

    /// <summary>A narrowed policy. Each value must lie between 1 and its hard limit.</summary>
    internal static LoopBounds Narrow(int modelCalls, int toolInvocations, int toolParallelism)
    {
        if (modelCalls is < 1 or > HardModelCalls) throw new ArgumentOutOfRangeException(nameof(modelCalls));
        if (toolInvocations is < 1 or > HardToolInvocations) throw new ArgumentOutOfRangeException(nameof(toolInvocations));
        if (toolParallelism is < 1 or > HardToolParallelism) throw new ArgumentOutOfRangeException(nameof(toolParallelism));
        return new LoopBounds(modelCalls, toolInvocations, toolParallelism);
    }
}

/// <summary>The model request caps checked before any dispatch (architecture 09 line 360; contracts 05 line 86).</summary>
internal static class ModelRequestCaps
{
    internal const int OutputTokenCap = 4096;
    internal const int TextInputTokenCap = 24_000;
    internal const int ToolCountCap = 32;
    internal const int ContextBytesDefault = 262_144;
    internal const int ContextBytesHard = 1_048_576;
    internal const int ContextItemsDefault = 200;
    internal const int ContextItemsHard = 500;

    /// <summary>True when the request is within every cap; a request outside them is never dispatched.</summary>
    internal static bool Admits(int maxOutputTokens, int textInputTokens, int toolCount) =>
        maxOutputTokens is >= 1 and <= OutputTokenCap
        && textInputTokens is >= 0 and <= TextInputTokenCap
        && toolCount is >= 0 and <= ToolCountCap;
}
