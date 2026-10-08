// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.HarnessFoundation;

/// <summary>The reviewed C# budget definition: the counted classes, their weights and the charge of every executor operation (HAR.40 (b)(1)).</summary>
public sealed class HarnessBudgetTests
{
    [Fact]
    public void EveryCountedClassWeighsOneStep()
    {
        foreach (var counted in Enum.GetValues<CountedClass>()) Assert.Equal(1, BudgetDefinition.StepWeight(counted));
    }

    [Fact]
    public void OnlyTheClassesThatLeaveTheExecutorAreSubrequests()
    {
        Assert.Equal(1, BudgetDefinition.SubrequestWeight(CountedClass.D1Call));
        Assert.Equal(1, BudgetDefinition.SubrequestWeight(CountedClass.OutboundFetch));
        Assert.Equal(1, BudgetDefinition.SubrequestWeight(CountedClass.ContainerCall));
        Assert.Equal(1, BudgetDefinition.SubrequestWeight(CountedClass.R2Operation));
        Assert.Equal(0, BudgetDefinition.SubrequestWeight(CountedClass.Retry));
        Assert.Equal(0, BudgetDefinition.SubrequestWeight(CountedClass.WaitCycle));
    }

    [Fact]
    public void TheFirstModelAttemptReservesItsStateReadAndFourBatchesAndItsOutboundFetch()
    {
        // The state read, the reservation, the dispatch intent, the outbound fetch and the outcome: five counted steps and subrequests.
        var first = BudgetDefinition.ModelAttempt(1);
        Assert.Equal(new EffectCost(5, 5, 1, 0), first);
        Assert.Equal(first, EffectCost.ModelCall);
    }

    [Fact]
    public void ARetryCountsTheRetryClassInsteadOfTheStateRead()
    {
        Assert.Equal(new EffectCost(5, 4, 1, 0), BudgetDefinition.ModelAttempt(2));
        Assert.Equal(new EffectCost(5, 4, 1, 0), BudgetDefinition.ModelAttempt(3));
    }

    [Fact]
    public void AToolAttemptHasNoOutboundFetch()
    {
        Assert.Equal(new EffectCost(4, 4, 0, 1), BudgetDefinition.ToolAttempt(1));
        Assert.Equal(new EffectCost(5, 4, 0, 1), BudgetDefinition.ToolAttempt(2));
        Assert.Equal(new EffectCost(4, 4, 0, 1), EffectCost.ToolInvocation);
    }

    [Fact]
    public void TheClaimWakeAndMaintenanceChargesAreTheCountedCallsTheyPay()
    {
        Assert.Equal(new BudgetCharge(3, 3), BudgetDefinition.Claim);
        Assert.Equal(new BudgetCharge(2, 1), BudgetDefinition.WakeDelivery);
        Assert.Equal(new BudgetCharge(1, 1), BudgetDefinition.ResumeRead);
        Assert.Equal(new BudgetCharge(1, 1), BudgetDefinition.MaintenanceBatch);
        Assert.Equal(new BudgetCharge(1, 1), BudgetDefinition.ResumedOutcome);
    }

    [Fact]
    public void AnOutOfRangeAttemptOrCountIsRefused()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => BudgetDefinition.ModelAttempt(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => BudgetDefinition.ToolAttempt(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => BudgetCharge.Of(CountedClass.D1Call, -1));
    }

    [Fact]
    public void TheStepGuardPausesOnTheModelEffectThatWouldCrossIt()
    {
        // A model effect costs five steps: at 23,995 the effect ends at the guard exactly; at 23,996 it would cross it and pauses.
        Assert.Equal(GuardDecision.Allowed, BudgetGuard.ForEffect(new BudgetCounters(23_995, 0, 0, 0), BudgetDefinition.ModelAttempt(1), LoopBounds.Default));
        Assert.Equal(GuardDecision.PausedAtEffectGuard, BudgetGuard.ForEffect(new BudgetCounters(23_996, 0, 0, 0), BudgetDefinition.ModelAttempt(1), LoopBounds.Default));
    }
}
