// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Storage.SharedFamilies;

/// <summary>What a family batch did, in the terms of Design model 04 sections 3 and 4.</summary>
internal enum FamilyOutcome
{
    /// <summary>The batch committed: every guard held and every mutation, receipt and outbox row is visible together.</summary>
    Committed,

    /// <summary>A guard was false: the whole batch rolled back and nothing was committed. Reread current state and recalculate.</summary>
    GuardRefused,

    /// <summary>A constraint refused the batch (a duplicate receipt key, or a physical rule). Nothing was committed by this batch.</summary>
    ConstraintRefused,

    /// <summary>The recovery generation moved. Nothing was committed.</summary>
    StaleGeneration,

    /// <summary>D1 was overloaded. Nothing was committed.</summary>
    Overloaded,

    /// <summary>The Worker answered before sending anything to D1 (for example an expired deadline). Nothing was committed.</summary>
    Unavailable,

    /// <summary>The effect is unknown: the batch may have committed. Resolve it through the command receipt.</summary>
    UnknownOutcome,

    /// <summary>The plan or the manifest was refused (a defect or a deployment skew); nothing ran.</summary>
    Rejected,
}

/// <summary>The one safe next step after a family batch.</summary>
internal enum FamilyFollowUp
{
    None,

    /// <summary>Read the current state, recalculate, and submit again under the original command identity.</summary>
    RereadAndRecalculate,

    /// <summary>Read the command receipt: the same request hash returns the original result, a different hash is an idempotency conflict.</summary>
    ReadCommandReceipt,

    /// <summary>Look the command receipt up. The caller never reports a safe retry and never submits under a new command identity.</summary>
    LookUpReceiptNeverRetryAsNewCommand,

    /// <summary>Obtain the current recovery generation and start over with a fresh unit of work.</summary>
    RefreshRecoveryGeneration,

    /// <summary>Nothing was committed; the same command may be submitted again later.</summary>
    RetryLaterWithSameCommand,

    /// <summary>A defect or a deployment skew: surface it, do not retry.</summary>
    ReportDefect,
}

internal sealed record FamilyResult(FamilyOutcome Outcome, FamilyFollowUp FollowUp, Guid CommandId, int Attempts, ulong Changes, PlanFailureKind? Failure)
{
    public bool Committed => Outcome == FamilyOutcome.Committed;
}

/// <summary>
/// The reread policy after a false guard (Design SU-04: reread and recalculate with bounded jitter only under the original command
/// receipt). Attempts and delay are bounded; the delay is full jitter over an exponential ceiling.
/// </summary>
internal sealed record FamilyRetryPolicy
{
    public static readonly TimeSpan MaxDelayLimit = TimeSpan.FromSeconds(1);

    public FamilyRetryPolicy(int maxAttempts, TimeSpan baseDelay, TimeSpan maxDelay)
    {
        if (maxAttempts is < 1 or > 8) throw new ArgumentOutOfRangeException(nameof(maxAttempts));
        if (baseDelay < TimeSpan.Zero || maxDelay < baseDelay || maxDelay > MaxDelayLimit) throw new ArgumentOutOfRangeException(nameof(maxDelay));
        MaxAttempts = maxAttempts;
        BaseDelay = baseDelay;
        MaxDelay = maxDelay;
    }

    public static FamilyRetryPolicy Default { get; } = new(3, TimeSpan.FromMilliseconds(25), TimeSpan.FromMilliseconds(250));

    /// <summary>Including the first; a policy of one never rereads.</summary>
    public int MaxAttempts { get; }

    public TimeSpan BaseDelay { get; }

    public TimeSpan MaxDelay { get; }

    /// <summary>The wait before attempt <paramref name="failedAttempt"/> + 1: a fraction (<paramref name="jitter"/> in [0, 1)) of min(MaxDelay, BaseDelay * 2^(failedAttempt - 1)).</summary>
    public TimeSpan DelayAfter(int failedAttempt, double jitter)
    {
        var ceiling = Math.Min(MaxDelay.TotalMilliseconds, BaseDelay.TotalMilliseconds * Math.Pow(2, Math.Clamp(failedAttempt - 1, 0, 30)));
        return TimeSpan.FromMilliseconds(ceiling * Math.Clamp(jitter, 0.0, 0.999999));
    }
}

/// <summary>
/// Executes sealed family units of work as one named plan call each, on the existing plan bridge (so one fixed D1 batch and no second
/// execution path), maps each failure to its safe next step, and rereads under the original command only after a false guard.
/// A failure of any other kind is never retried here: an unknown outcome is resolved by receipt lookup (Design model 04 section 3).
/// </summary>
internal sealed class FamilyExecutor
{
    private readonly IPlanExecutor plans;
    private readonly Func<TimeSpan, CancellationToken, Task> wait;
    private readonly Func<double> fraction;

    /// <param name="plans">The plan bridge; one call is one fixed D1 batch.</param>
    /// <param name="delay">Waits between rereads; <see cref="Task.Delay(TimeSpan, CancellationToken)"/> by default.</param>
    /// <param name="jitter">A fraction in [0, 1) that scales the bounded delay; <see cref="Random.NextDouble"/> by default.</param>
    public FamilyExecutor(IPlanExecutor plans, Func<TimeSpan, CancellationToken, Task>? delay = null, Func<double>? jitter = null)
    {
        ArgumentNullException.ThrowIfNull(plans);
        this.plans = plans;
        wait = delay ?? Task.Delay;
        fraction = jitter ?? Random.Shared.NextDouble;
    }

    /// <summary>Executes the unit once.</summary>
    public async Task<FamilyResult> ExecuteAsync(FamilyUnitOfWork unit, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(unit);
        var call = unit.Seal();
        try
        {
            var result = await plans.ExecuteAsync(call, cancellationToken);
            return new FamilyResult(FamilyOutcome.Committed, FamilyFollowUp.None, unit.CommandId, 1, result.Changes, null);
        }
        catch (PlanFailureException failure)
        {
            var (outcome, followUp) = Map(failure.Kind);
            return new FamilyResult(outcome, followUp, unit.CommandId, 1, 0, failure.Kind);
        }
    }

    /// <summary>
    /// Executes, and after a false guard rebuilds the unit (the caller rereads current state and recalculates in <paramref name="build"/>),
    /// waits a bounded jitter and executes again, at most <see cref="FamilyRetryPolicy.MaxAttempts"/> times. Every attempt must carry
    /// the command identity of the first; a different one is refused, because a retry under a new identity would be a second command.
    /// </summary>
    public async Task<FamilyResult> ExecuteWithRereadAsync(Func<int, CancellationToken, Task<FamilyUnitOfWork>> build, FamilyRetryPolicy policy, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(build);
        ArgumentNullException.ThrowIfNull(policy);
        Guid? command = null;
        for (var attempt = 1; ; attempt++)
        {
            var unit = await build(attempt, cancellationToken);
            if (command is null) command = unit.CommandId;
            else if (unit.CommandId != command) throw new FamilyViolationException(FamilyViolation.CommandIdentityChanged, "attempt " + attempt.ToString(System.Globalization.CultureInfo.InvariantCulture));
            var result = (await ExecuteAsync(unit, cancellationToken)) with { Attempts = attempt };
            if (result.Outcome != FamilyOutcome.GuardRefused || attempt >= policy.MaxAttempts) return result;
            await wait(policy.DelayAfter(attempt, fraction()), cancellationToken);
        }
    }

    private static (FamilyOutcome Outcome, FamilyFollowUp FollowUp) Map(PlanFailureKind kind) => kind switch
    {
        PlanFailureKind.Precondition => (FamilyOutcome.GuardRefused, FamilyFollowUp.RereadAndRecalculate),
        PlanFailureKind.Constraint => (FamilyOutcome.ConstraintRefused, FamilyFollowUp.ReadCommandReceipt),
        PlanFailureKind.StaleGeneration => (FamilyOutcome.StaleGeneration, FamilyFollowUp.RefreshRecoveryGeneration),
        PlanFailureKind.Overloaded => (FamilyOutcome.Overloaded, FamilyFollowUp.RetryLaterWithSameCommand),
        PlanFailureKind.Unavailable => (FamilyOutcome.Unavailable, FamilyFollowUp.RetryLaterWithSameCommand),
        PlanFailureKind.UnknownOutcome => (FamilyOutcome.UnknownOutcome, FamilyFollowUp.LookUpReceiptNeverRetryAsNewCommand),
        _ => (FamilyOutcome.Rejected, FamilyFollowUp.ReportDefect),
    };
}
