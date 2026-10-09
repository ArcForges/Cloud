// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

/// <summary>The durable counters of one run (task_harness_budget). They never decrease and are never reset.</summary>
internal readonly record struct BudgetCounters(long CountedSteps, long Subrequests, long ModelCalls, long ToolInvocations);

/// <summary>
/// The counted classes of the reviewed C# budget definition (HAR.40 validation (b)(1), which HAR.00 validations (1) and (2) inherit). Every
/// listed call is one counted step. A subrequest is counted for the classes that leave the executor (D1 calls, outbound fetches, container
/// calls and R2 operations); a pre-dispatch retry and a wait cycle are steps only.
/// </summary>
internal enum CountedClass
{
    /// <summary>One D1 statement (a read) or one D1 batch (a write) that the executor issues.</summary>
    D1Call,

    /// <summary>One outbound fetch, including the <c>ai.internal</c> call of a model step.</summary>
    OutboundFetch,

    /// <summary>One call into the container, such as a wake delivered to it.</summary>
    ContainerCall,

    /// <summary>One R2 operation. The executor issues none today; any R2 call charges this class.</summary>
    R2Operation,

    /// <summary>One pre-dispatch retry: a fresh attempt identity of an effect that was refused before dispatch.</summary>
    Retry,

    /// <summary>One wait cycle: one wake delivery of a run.</summary>
    WaitCycle,
}

/// <summary>What a set of counted calls costs in counted steps and in subrequests.</summary>
internal readonly record struct BudgetCharge(long Steps, long Subrequests)
{
    internal static BudgetCharge Zero => new(0, 0);

    /// <summary>The charge of <paramref name="count"/> counted calls of one class.</summary>
    internal static BudgetCharge Of(CountedClass counted, int count = 1)
    {
        if (count < 0) throw new ArgumentOutOfRangeException(nameof(count));
        return new BudgetCharge(count * BudgetDefinition.StepWeight(counted), count * BudgetDefinition.SubrequestWeight(counted));
    }

    public static BudgetCharge operator +(BudgetCharge left, BudgetCharge right) =>
        new(left.Steps + right.Steps, left.Subrequests + right.Subrequests);
}

/// <summary>
/// The reviewed budget definition: the step and subrequest weight of every counted class and the charge of each executor operation. The
/// charges are reserved or written in the same fenced batch as the call they pay for, so a counter never lags a call that happened.
/// </summary>
internal static class BudgetDefinition
{
    /// <summary>Every counted class is one counted step.</summary>
    internal static long StepWeight(CountedClass counted) => counted switch
    {
        CountedClass.D1Call or CountedClass.OutboundFetch or CountedClass.ContainerCall or CountedClass.R2Operation
            or CountedClass.Retry or CountedClass.WaitCycle => 1,
        _ => throw new ArgumentOutOfRangeException(nameof(counted)),
    };

    /// <summary>The classes that leave the executor (a D1 call, an outbound fetch, a container call, an R2 operation) are subrequests.</summary>
    internal static long SubrequestWeight(CountedClass counted) => counted switch
    {
        CountedClass.D1Call or CountedClass.OutboundFetch or CountedClass.ContainerCall or CountedClass.R2Operation => 1,
        CountedClass.Retry or CountedClass.WaitCycle => 0,
        _ => throw new ArgumentOutOfRangeException(nameof(counted)),
    };

    /// <summary>
    /// One effect attempt, reserved under the fence before its dispatch: the reservation, the dispatch intent and the outcome are three D1 batches.
    /// A model attempt adds its one outbound fetch; a tool attempt has no external call. The first attempt also counts the state read that
    /// precedes its reservation; a later attempt counts one retry instead.
    /// </summary>
    internal static EffectCost ModelAttempt(int ordinal) => Attempt(ordinal, outbound: true, modelCalls: 1, toolInvocations: 0);

    /// <summary>One tool attempt (the local say_hello tool): no outbound fetch, one tool invocation.</summary>
    internal static EffectCost ToolAttempt(int ordinal) => Attempt(ordinal, outbound: false, modelCalls: 0, toolInvocations: 1);

    /// <summary>The charge of a claim: the claim batch and the two state reads of the claim sequence (the read before the claim and the read after it).</summary>
    internal static BudgetCharge Claim => BudgetCharge.Of(CountedClass.D1Call, 3);

    /// <summary>The charge of one wake delivery: one wait cycle and the container call that carried it.</summary>
    internal static BudgetCharge WakeDelivery => BudgetCharge.Of(CountedClass.WaitCycle) + BudgetCharge.Of(CountedClass.ContainerCall);

    /// <summary>
    /// The charge reserved before a run is parked with a timer (HAR.40 alarm arming): one outbound fetch for the arm and one for the best-effort
    /// cancel. The cancel can only follow a commit that did not happen, and then no fenced write is left to charge it, so both calls are reserved
    /// in the batch that precedes the arm. A reserved cancel that is not sent leaves the counters one subrequest higher, which is the conservative side.
    /// </summary>
    internal static BudgetCharge AlarmReservation => BudgetCharge.Of(CountedClass.OutboundFetch, 2);

    /// <summary>The charge of the open-attempt read that a resumed wake makes under its new lease.</summary>
    internal static BudgetCharge ResumeRead => BudgetCharge.Of(CountedClass.D1Call);

    /// <summary>The charge of one lease renewal, one checkpoint or one yield: one D1 batch each.</summary>
    internal static BudgetCharge MaintenanceBatch => BudgetCharge.Of(CountedClass.D1Call);

    /// <summary>The charge of an outcome written on resume for an attempt that was not reserved in this process: one D1 batch.</summary>
    internal static BudgetCharge ResumedOutcome => BudgetCharge.Of(CountedClass.D1Call);

    private static EffectCost Attempt(int ordinal, bool outbound, long modelCalls, long toolInvocations)
    {
        if (ordinal < 1) throw new ArgumentOutOfRangeException(nameof(ordinal));
        var charge = BudgetCharge.Of(CountedClass.D1Call, 3);
        if (outbound) charge += BudgetCharge.Of(CountedClass.OutboundFetch);
        charge += ordinal == 1 ? BudgetCharge.Of(CountedClass.D1Call) : BudgetCharge.Of(CountedClass.Retry);
        return new EffectCost(charge.Steps, charge.Subrequests, modelCalls, toolInvocations);
    }
}

/// <summary>What one effect attempt reserves before it is dispatched: its counted steps and subrequests, and its model and tool counts.</summary>
internal readonly record struct EffectCost(long Steps, long Subrequests, long ModelCalls, long ToolInvocations)
{
    /// <summary>The first model attempt of an effect (see <see cref="BudgetDefinition.ModelAttempt"/>).</summary>
    internal static EffectCost ModelCall => BudgetDefinition.ModelAttempt(1);

    /// <summary>The first tool attempt of an effect (see <see cref="BudgetDefinition.ToolAttempt"/>).</summary>
    internal static EffectCost ToolInvocation => BudgetDefinition.ToolAttempt(1);
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
