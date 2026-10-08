// SPDX-License-Identifier: AGPL-3.0-only
using System.Text;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.HarnessFoundation;

/// <summary>The pure executor rules: lease timing, budget ceilings, retry, checkpoints, pins, identity and loop bounds.</summary>
public sealed class HarnessDomainTests
{
    [Fact]
    public void TheLeaseIsSixtySecondsAndIsRenewedEveryTwentySeconds()
    {
        Assert.Equal(60_000_000L, LeasePolicy.TermMicros);
        Assert.Equal(20_000_000L, LeasePolicy.RenewIntervalMicros);
        Assert.False(LeasePolicy.RenewalDue(renewedAtMicros: 0, nowMicros: 19_999_999));
        Assert.True(LeasePolicy.RenewalDue(renewedAtMicros: 0, nowMicros: 20_000_000));
    }

    [Fact]
    public void TheBudgetValuesAreTheReviewedOnes()
    {
        Assert.Equal(24_000, BudgetPolicy.EffectStepGuard);
        Assert.Equal(25_000, BudgetPolicy.HardStepCeiling);
        Assert.Equal(1_000, BudgetPolicy.ReconciliationStepReserve);
        Assert.Equal(900_000, BudgetPolicy.EffectSubrequestStop);
        Assert.Equal(1_000_000, BudgetPolicy.SubrequestAllowance);
        Assert.Equal(2, BudgetPolicy.MaxPreDispatchRetries);
        Assert.Equal(131_072, BudgetPolicy.CheckpointLimitBytes);
        Assert.Equal(90, BudgetPolicy.ModelDeadlineSeconds);
        Assert.True(BudgetPolicy.ModelDeadlineSeconds <= BudgetPolicy.LoopDeadlineSeconds);
    }

    [Fact]
    public void AnEffectIsAllowedUpToTheEffectGuardAndPausedAtItWithoutAnyWrite()
    {
        // A model effect costs five counted steps, so the last effect that ends at the guard starts at 23,995.
        var cost = EffectCost.ModelCall;
        var bounds = LoopBounds.Default;
        Assert.Equal(GuardDecision.Allowed, BudgetGuard.ForEffect(new BudgetCounters(23_995, 0, 0, 0), cost, bounds));
        Assert.Equal(GuardDecision.PausedAtEffectGuard, BudgetGuard.ForEffect(new BudgetCounters(23_996, 0, 0, 0), cost, bounds));
        Assert.Equal(GuardDecision.PausedAtEffectGuard, BudgetGuard.ForEffect(new BudgetCounters(24_000, 0, 0, 0), cost, bounds));
    }

    [Fact]
    public void TheLastThousandStepsAreReservedForReconciliation()
    {
        // An effect stops at 24,000 counted steps while reconciliation may still count up to the 25,000 hard ceiling.
        Assert.Equal(GuardDecision.PausedAtEffectGuard, BudgetGuard.ForEffect(new BudgetCounters(24_000, 0, 0, 0), EffectCost.ModelCall, LoopBounds.Default));
        Assert.Equal(GuardDecision.Allowed, BudgetGuard.ForReconciliation(new BudgetCounters(24_000, 0, 0, 0), 1, 0));
        Assert.Equal(GuardDecision.HardStepCeiling, BudgetGuard.ForReconciliation(new BudgetCounters(25_000, 0, 0, 0), 1, 0));
    }

    [Fact]
    public void TheSubrequestStopLeavesReconciliationItsAllowance()
    {
        // A model call reserves four subrequests, so 899,996 is the last counted value that still dispatches.
        Assert.Equal(GuardDecision.Allowed, BudgetGuard.ForEffect(new BudgetCounters(0, 899_995, 0, 0), EffectCost.ModelCall, LoopBounds.Default));
        Assert.Equal(GuardDecision.SubrequestStop, BudgetGuard.ForEffect(new BudgetCounters(0, 899_996, 0, 0), EffectCost.ModelCall, LoopBounds.Default));
        Assert.Equal(GuardDecision.Allowed, BudgetGuard.ForReconciliation(new BudgetCounters(0, 899_997, 0, 0), 1, 4));
        Assert.Equal(GuardDecision.SubrequestStop, BudgetGuard.ForReconciliation(new BudgetCounters(0, 999_998, 0, 0), 1, 4));
    }

    [Fact]
    public void ModelAndToolCapsStopBeforeTheNextCall()
    {
        var narrow = LoopBounds.Narrow(modelCalls: 2, toolInvocations: 3, toolParallelism: 1);
        Assert.Equal(GuardDecision.Allowed, BudgetGuard.ForEffect(new BudgetCounters(0, 0, 1, 0), EffectCost.ModelCall, narrow));
        Assert.Equal(GuardDecision.ModelCallCap, BudgetGuard.ForEffect(new BudgetCounters(0, 0, 2, 0), EffectCost.ModelCall, narrow));
        Assert.Equal(GuardDecision.ToolInvocationCap, BudgetGuard.ForEffect(new BudgetCounters(0, 0, 0, 3), EffectCost.ToolInvocation, narrow));
    }

    [Fact]
    public void APolicyNarrowsButNeverEnlargesALoopBound()
    {
        var narrowed = LoopBounds.Narrow(modelCalls: 4, toolInvocations: 8, toolParallelism: 2);
        Assert.Equal(4, narrowed.ModelCalls);
        Assert.Throws<ArgumentOutOfRangeException>(() => LoopBounds.Narrow(LoopBounds.HardModelCalls + 1, 1, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => LoopBounds.Narrow(1, LoopBounds.HardToolInvocations + 1, 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => LoopBounds.Narrow(1, 1, LoopBounds.HardToolParallelism + 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => LoopBounds.Narrow(0, 1, 1));
        Assert.Equal(16, LoopBounds.Default.ModelCalls);
        Assert.Equal(64, LoopBounds.Default.ToolInvocations);
        Assert.Equal(4, LoopBounds.Default.ToolParallelism);
        Assert.Equal(3, LoopBounds.NoProgressLimit);
    }

    [Fact]
    public void ARetryHappensOnlyBeforeDispatchAndAtMostTwiceWithAFreshAttempt()
    {
        Assert.Equal(RetryDecision.Retry, RetryPolicy.Decide(EffectResultKind.RefusedBeforeDispatch, attemptOrdinal: 1));
        Assert.Equal(RetryDecision.Retry, RetryPolicy.Decide(EffectResultKind.RefusedBeforeDispatch, attemptOrdinal: 2));
        Assert.Equal(RetryDecision.Exhausted, RetryPolicy.Decide(EffectResultKind.RefusedBeforeDispatch, attemptOrdinal: 3));
        Assert.Equal(RetryDecision.NeverRetriedUnknown, RetryPolicy.Decide(EffectResultKind.Unknown, attemptOrdinal: 1));
        Assert.Equal(RetryDecision.Settled, RetryPolicy.Decide(EffectResultKind.Succeeded, attemptOrdinal: 1));
        Assert.Equal(RetryDecision.Settled, RetryPolicy.Decide(EffectResultKind.FailedDidNotHappen, attemptOrdinal: 1));
        Assert.Throws<ArgumentOutOfRangeException>(() => RetryPolicy.Decide(EffectResultKind.Unknown, attemptOrdinal: 0));
    }

    [Fact]
    public void ACheckpointIsReferencesOnlyAndBounded()
    {
        var receipt = new byte[32];
        var json = Encoding.UTF8.GetString(new CheckpointRef(7, receipt, "wait.approval", "worker.v1").ToCanonicalJson());
        Assert.Equal("{\"ordinal\":7,\"receiptSha256\":\"" + new string('0', 64) + "\",\"waitKey\":\"wait.approval\",\"workerVersion\":\"worker.v1\"}", json);
        Assert.Throws<ArgumentException>(() => new CheckpointRef(0, new byte[31], null, "worker.v1").ToCanonicalJson());
        Assert.Throws<ArgumentException>(() => new CheckpointRef(0, receipt, new string('k', 129), "worker.v1").ToCanonicalJson());
        Assert.Throws<ArgumentException>(() => new CheckpointRef(0, receipt, "wait key with spaces", "worker.v1").ToCanonicalJson());
        Assert.Throws<ArgumentException>(() => new CheckpointRef(0, receipt, null, "prompt: say hello").ToCanonicalJson());
    }

    [Fact]
    public void ADispatchNeedsTheSamePinnedModelAndTariffAndNothingElse()
    {
        var pinned = new PinnedSnapshot("model.alpha", "tariff.2026-10");
        Assert.True(pinned.Matches(new PinnedSnapshot("model.alpha", "tariff.2026-10")));
        Assert.False(pinned.Matches(new PinnedSnapshot("model.beta", "tariff.2026-10")));
        Assert.False(pinned.Matches(new PinnedSnapshot("model.alpha", "tariff.2026-11")));
        Assert.False(new PinnedSnapshot("", "tariff.2026-10").IsPinned);
        Assert.False(new PinnedSnapshot("model alpha", "tariff.2026-10").IsPinned);
        Assert.False(new PinnedSnapshot("model.alpha", "tariff/2026 10").IsPinned);
        Assert.False(new PinnedSnapshot("model.alpha", "tariff.2026-10").Matches(new PinnedSnapshot("", "")));
    }

    [Fact]
    public void ARunIdentityDiffersWhenAnyComponentChanges()
    {
        var pin = new PinnedSnapshot("model.alpha", "tariff.2026-10");
        var run = Guid.Parse("00000000-0000-4000-8000-0000000000d1");
        var baseline = new RunIdentity(run, "cloud.build.1", "worker.v1", 1, pin);
        Assert.Equal(baseline.DigestForEpoch(1), new RunIdentity(run, "cloud.build.1", "worker.v1", 1, pin).DigestForEpoch(1));
        Assert.NotEqual(baseline.DigestForEpoch(1), baseline.DigestForEpoch(2));
        Assert.NotEqual(baseline.DigestForEpoch(1), new RunIdentity(run, "cloud.build.2", "worker.v1", 1, pin).DigestForEpoch(1));
        Assert.NotEqual(baseline.DigestForEpoch(1), new RunIdentity(run, "cloud.build.1", "worker.v2", 1, pin).DigestForEpoch(1));
        Assert.NotEqual(baseline.DigestForEpoch(1), new RunIdentity(run, "cloud.build.1", "worker.v1", 2, pin).DigestForEpoch(1));
        Assert.NotEqual(baseline.DigestForEpoch(1), new RunIdentity(run, "cloud.build.1", "worker.v1", 1, pin with { TariffSnapshotId = "tariff.2026-11" }).DigestForEpoch(1));
        Assert.Equal("af-" + run.ToString("D") + "-1", baseline.WorkflowId);
    }

    [Fact]
    public void ModelRequestsOutsideTheCapsAreNeverAdmitted()
    {
        Assert.True(ModelRequestCaps.Admits(maxOutputTokens: 4096, textInputTokens: 24_000, toolCount: 32));
        Assert.False(ModelRequestCaps.Admits(maxOutputTokens: 4097, textInputTokens: 1, toolCount: 0));
        Assert.False(ModelRequestCaps.Admits(maxOutputTokens: 0, textInputTokens: 1, toolCount: 0));
        Assert.False(ModelRequestCaps.Admits(maxOutputTokens: 1, textInputTokens: 24_001, toolCount: 0));
        Assert.False(ModelRequestCaps.Admits(maxOutputTokens: 1, textInputTokens: 1, toolCount: 33));
    }
}
