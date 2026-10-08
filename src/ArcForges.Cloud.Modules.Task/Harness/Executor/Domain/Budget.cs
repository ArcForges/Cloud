// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

/// <summary>The durable counters of one run (task_harness_budget). They never decrease and are never reset.</summary>
internal readonly record struct BudgetCounters(long CountedSteps, long Subrequests, long ModelCalls, long ToolInvocations);

/// <summary>What one effect attempt reserves before it is dispatched.</summary>
internal readonly record struct EffectCost(long Steps, long Subrequests, long ModelCalls, long ToolInvocations)
{
    /// <summary>One model call: one counted step, the reserved subrequests, one model call.</summary>
    internal static EffectCost ModelCall => new(1, BudgetPolicy.SubrequestsPerEffect, 1, 0);

    /// <summary>One tool invocation: one counted step, the reserved subrequests, one tool invocation.</summary>
    internal static EffectCost ToolInvocation => new(1, BudgetPolicy.SubrequestsPerEffect, 0, 1);
}

internal enum GuardDecision
{
    Allowed,

    /// <summary>The effect guard is reached: new effects pause; the run may finish only with no effect unresolved.</summary>
    PausedAtEffectGuard,

    /// <summary>The hard ceiling is reached: no further counted step.</summary>
    HardStepCeiling,

    /// <summary>The effect subrequest stop is reached; 100,000 remain for reconciliation.</summary>
    SubrequestStop,

    ModelCallCap,

    ToolInvocationCap,
}

/// <summary>The pure budget decisions. Effects are refused at the earliest guard, in the order the Design states them.</summary>
internal static class BudgetGuard
{
    internal static GuardDecision ForEffect(BudgetCounters counters, EffectCost cost, LoopBounds bounds)
    {
        ArgumentNullException.ThrowIfNull(bounds);
        if (counters.CountedSteps + cost.Steps > BudgetPolicy.HardStepCeiling) return GuardDecision.HardStepCeiling;
        if (counters.CountedSteps + cost.Steps > BudgetPolicy.EffectStepGuard) return GuardDecision.PausedAtEffectGuard;
        if (counters.Subrequests + cost.Subrequests > BudgetPolicy.EffectSubrequestStop) return GuardDecision.SubrequestStop;
        if (counters.ModelCalls + cost.ModelCalls > bounds.ModelCalls) return GuardDecision.ModelCallCap;
        if (counters.ToolInvocations + cost.ToolInvocations > bounds.ToolInvocations) return GuardDecision.ToolInvocationCap;
        return GuardDecision.Allowed;
    }

    /// <summary>Reconciliation and finalisation may use the reserve, so only the hard ceilings apply.</summary>
    internal static GuardDecision ForReconciliation(BudgetCounters counters, long steps, long subrequests)
    {
        if (counters.CountedSteps + steps > BudgetPolicy.HardStepCeiling) return GuardDecision.HardStepCeiling;
        if (counters.Subrequests + subrequests > BudgetPolicy.SubrequestAllowance) return GuardDecision.SubrequestStop;
        return GuardDecision.Allowed;
    }
}
