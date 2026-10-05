// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.SharedFamilies;
using Xunit;

namespace ArcForges.Cloud.Tests.SharedFamilies;

/// <summary>
/// The executor: one family batch is one named plan call on the existing bridge; each failure maps to its one safe next step; only a
/// false guard is reread, under the original command identity, with bounded attempts and bounded jitter.
/// </summary>
public sealed class FamilyExecutorTests
{
    /// <summary>The kind, the outcome and the follow-up by name (the engine types are internal, so they cannot appear in a public signature).</summary>
    public static TheoryData<string, string, string> Mapping() => new()
    {
        { "Precondition", "GuardRefused", "RereadAndRecalculate" },
        { "Constraint", "ConstraintRefused", "ReadCommandReceipt" },
        { "StaleGeneration", "StaleGeneration", "RefreshRecoveryGeneration" },
        { "Overloaded", "Overloaded", "RetryLaterWithSameCommand" },
        { "Unavailable", "Unavailable", "RetryLaterWithSameCommand" },
        { "UnknownOutcome", "UnknownOutcome", "LookUpReceiptNeverRetryAsNewCommand" },
        { "InvalidPlan", "Rejected", "ReportDefect" },
        { "ManifestMismatch", "Rejected", "ReportDefect" },
        { "Transport", "Rejected", "ReportDefect" },
    };

    private static List<TimeSpan> NoDelay(out Func<TimeSpan, CancellationToken, Task> delay)
    {
        var waited = new List<TimeSpan>();
        delay = (span, _) =>
        {
            waited.Add(span);
            return Task.CompletedTask;
        };
        return waited;
    }

    [Fact]
    public async Task ACommittedBatchReportsItsChangesAndNoFollowUp()
    {
        var executor = new FamilyExecutor(new ScriptedExecutor((_, _) => new PlanResult([], 12)));
        var unit = FamilyFixture.Unit();
        var result = await executor.ExecuteAsync(unit, T.Ct);
        Assert.True(result.Committed);
        Assert.Equal((FamilyOutcome.Committed, FamilyFollowUp.None, 1, 12UL, (PlanFailureKind?)null), (result.Outcome, result.FollowUp, result.Attempts, result.Changes, result.Failure));
        Assert.Equal(unit.CommandId, result.CommandId);
    }

    [Fact]
    public async Task OneBatchIsOnePlanCallOnTheBridgeWithTheSealedArguments()
    {
        var bridge = new ScriptedExecutor((_, _) => new PlanResult([], 12));
        var unit = FamilyFixture.Unit(generation: 3);
        await new FamilyExecutor(bridge).ExecuteAsync(unit, T.Ct);
        var call = Assert.Single(bridge.Calls);
        Assert.Equal("families.fixture-pair.commit", call.Plan.Id);
        Assert.Equal(PlanAccess.Write, call.Plan.Access);
        Assert.Equal(3UL, call.RecoveryGeneration);
        Assert.Equal(12, call.Arguments.Length);
    }

    [Theory]
    [MemberData(nameof(Mapping))]
    public async Task EachFailureMapsToItsOutcomeAndSafeNextStep(string kindName, string outcomeName, string followUpName)
    {
        var kind = Enum.Parse<PlanFailureKind>(kindName);
        var bridge = ScriptedExecutor.Failing(kind);
        var result = await new FamilyExecutor(bridge).ExecuteAsync(FamilyFixture.Unit(), T.Ct);
        Assert.False(result.Committed);
        Assert.Equal((Enum.Parse<FamilyOutcome>(outcomeName), Enum.Parse<FamilyFollowUp>(followUpName), kind, 0UL), (result.Outcome, result.FollowUp, result.Failure!.Value, result.Changes));
    }

    [Theory]
    [MemberData(nameof(Mapping))]
    public async Task OnlyAFalseGuardIsEverReread(string kindName, string outcomeName, string followUpName)
    {
        _ = followUpName;
        var kind = Enum.Parse<PlanFailureKind>(kindName);
        var outcome = Enum.Parse<FamilyOutcome>(outcomeName);
        var bridge = ScriptedExecutor.Failing(kind, null);
        var waited = NoDelay(out var delay);
        var builds = 0;
        var result = await new FamilyExecutor(bridge, delay, () => 0.5).ExecuteWithRereadAsync((_, _) =>
        {
            builds++;
            return Task.FromResult(FamilyFixture.Unit(Guid.Parse("11111111-1111-4111-8111-111111111111")));
        }, FamilyRetryPolicy.Default, T.Ct);
        if (outcome == FamilyOutcome.GuardRefused)
        {
            Assert.True(result.Committed);
            Assert.Equal(2, builds);
            Assert.Equal(2, bridge.Calls.Count);
            Assert.Single(waited);
        }
        else
        {
            // Unknown outcome, constraint, stale generation and every other failure end the attempt: no second build, no second call.
            Assert.Equal(outcome, result.Outcome);
            Assert.Equal(1, builds);
            Assert.Single(bridge.Calls);
            Assert.Empty(waited);
        }
    }

    [Fact]
    public async Task AFalseGuardIsRereadUnderTheOriginalCommandWithBoundedJitter()
    {
        var command = Guid.Parse("22222222-2222-4222-8222-222222222222");
        var bridge = ScriptedExecutor.Failing(PlanFailureKind.Precondition, PlanFailureKind.Precondition, null);
        var waited = NoDelay(out var delay);
        var attempts = new List<int>();
        var policy = new FamilyRetryPolicy(3, TimeSpan.FromMilliseconds(100), TimeSpan.FromMilliseconds(250));
        var result = await new FamilyExecutor(bridge, delay, () => 0.5).ExecuteWithRereadAsync((attempt, _) =>
        {
            attempts.Add(attempt);
            return Task.FromResult(FamilyFixture.Unit(command));
        }, policy, T.Ct);
        Assert.True(result.Committed);
        Assert.Equal(3, result.Attempts);
        Assert.Equal([1, 2, 3], attempts);
        // Full jitter over an exponential ceiling, capped: 0.5 * min(250, 100 * 2^0) then 0.5 * min(250, 100 * 2^1).
        Assert.Equal([TimeSpan.FromMilliseconds(50), TimeSpan.FromMilliseconds(100)], waited);
        // Every attempt carried the original command identity in its guards and its release.
        Assert.All(bridge.Calls, call =>
        {
            Assert.Equal(command.ToString("D"), FamilyFixture.Text(call.Arguments[0][0]));
            Assert.Equal(command.ToString("D"), FamilyFixture.Text(call.Arguments[^1][0]));
        });
        Assert.Equal(3, bridge.Calls.Select(call => call.RequestId).Distinct().Count());
    }

    [Fact]
    public async Task TheRereadIsBoundedByTheAttemptsOfThePolicy()
    {
        var bridge = ScriptedExecutor.Failing(PlanFailureKind.Precondition);
        var waited = NoDelay(out var delay);
        var command = Guid.NewGuid();
        var result = await new FamilyExecutor(bridge, delay, () => 0.999).ExecuteWithRereadAsync((_, _) => Task.FromResult(FamilyFixture.Unit(command)), FamilyRetryPolicy.Default, T.Ct);
        Assert.Equal((FamilyOutcome.GuardRefused, FamilyFollowUp.RereadAndRecalculate, 3), (result.Outcome, result.FollowUp, result.Attempts));
        Assert.Equal(3, bridge.Calls.Count);
        Assert.Equal(2, waited.Count);
        Assert.All(waited, span => Assert.InRange(span, TimeSpan.Zero, FamilyRetryPolicy.Default.MaxDelay));
        var once = ScriptedExecutor.Failing(PlanFailureKind.Precondition);
        var single = await new FamilyExecutor(once, delay, () => 0.5).ExecuteWithRereadAsync((_, _) => Task.FromResult(FamilyFixture.Unit(command)), new FamilyRetryPolicy(1, TimeSpan.Zero, TimeSpan.Zero), T.Ct);
        Assert.Equal((FamilyOutcome.GuardRefused, 1), (single.Outcome, single.Attempts));
        Assert.Single(once.Calls);
    }

    [Fact]
    public async Task ARereadThatChangesTheCommandIdentityIsRefusedBeforeAnythingIsSent()
    {
        var bridge = ScriptedExecutor.Failing(PlanFailureKind.Precondition, null);
        var executor = new FamilyExecutor(bridge, (_, _) => Task.CompletedTask, () => 0);
        var exception = await Assert.ThrowsAsync<FamilyViolationException>(() => executor.ExecuteWithRereadAsync((_, _) => Task.FromResult(FamilyFixture.Unit()), FamilyRetryPolicy.Default, T.Ct));
        Assert.Equal(FamilyViolation.CommandIdentityChanged, exception.Violation);
        Assert.Single(bridge.Calls);
    }

    [Fact]
    public async Task ACancelledWaitStopsTheRereadAndSendsNothingMore()
    {
        var bridge = ScriptedExecutor.Failing(PlanFailureKind.Precondition, null);
        var command = Guid.NewGuid();
        var executor = new FamilyExecutor(bridge, (_, _) => Task.FromCanceled(new CancellationToken(true)), () => 0.5);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => executor.ExecuteWithRereadAsync((_, _) => Task.FromResult(FamilyFixture.Unit(command)), FamilyRetryPolicy.Default, T.Ct));
        Assert.Single(bridge.Calls);
    }

    [Fact]
    public async Task ASealFailureSurfacesAsAViolationAndSendsNothing()
    {
        var bridge = new ScriptedExecutor((_, _) => new PlanResult([], 12));
        var unit = FamilyFixture.Unit(scope: "another-workspace");
        await Assert.ThrowsAsync<FamilyViolationException>(() => new FamilyExecutor(bridge).ExecuteAsync(unit, T.Ct));
        Assert.Empty(bridge.Calls);
    }

    [Fact]
    public void ThePolicyIsBoundedAndTheDelayNeverExceedsItsCeiling()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new FamilyRetryPolicy(0, TimeSpan.Zero, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new FamilyRetryPolicy(9, TimeSpan.Zero, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new FamilyRetryPolicy(3, TimeSpan.FromMilliseconds(-1), TimeSpan.FromMilliseconds(5)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new FamilyRetryPolicy(3, TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(5)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new FamilyRetryPolicy(3, TimeSpan.Zero, TimeSpan.FromSeconds(2)));
        var policy = new FamilyRetryPolicy(8, TimeSpan.FromMilliseconds(10), TimeSpan.FromMilliseconds(200));
        for (var failed = 1; failed <= 100; failed++)
        {
            Assert.InRange(policy.DelayAfter(failed, 0.0), TimeSpan.Zero, TimeSpan.Zero);
            Assert.InRange(policy.DelayAfter(failed, 0.999999), TimeSpan.Zero, TimeSpan.FromMilliseconds(200));
            Assert.InRange(policy.DelayAfter(failed, 7.5), TimeSpan.Zero, TimeSpan.FromMilliseconds(200));
            Assert.InRange(policy.DelayAfter(failed, -3), TimeSpan.Zero, TimeSpan.FromMilliseconds(200));
        }

        Assert.Equal(TimeSpan.FromMilliseconds(10 * 0.5), policy.DelayAfter(1, 0.5));
        Assert.Equal(TimeSpan.FromMilliseconds(40 * 0.5), policy.DelayAfter(3, 0.5));
        Assert.Equal(TimeSpan.FromMilliseconds(200 * 0.5), policy.DelayAfter(8, 0.5));
    }

    [Fact]
    public async Task TwoContainersContendingOnTheSameStateOneCommitsAndTheOtherRereadsAndCommitsAfter()
    {
        // The in-memory model of one D1: a single revision that a family batch guards and increments atomically. The SQL of that behaviour
        // is proven in the oracle and on workerd's D1; this proves the executor's side of it: a stale batch is refused whole and a reread under
        // the same command then commits against current state, so two Containers never both apply one revision.
        long revision = 7;
        var commits = new List<(string Command, long Read)>();
        var gate = new object();
        var bridge = new ScriptedExecutor((call, _) =>
        {
            lock (gate)
            {
                var expected = FamilyFixture.Int(call.Arguments[3][2]);
                if (expected != revision) throw new PlanFailureException(PlanFailureKind.Precondition);
                commits.Add((FamilyFixture.Text(call.Arguments[0][0]), expected));
                revision++;
                return new PlanResult([], 12);
            }
        });
        var executor = new FamilyExecutor(bridge, (_, _) => Task.CompletedTask, () => 0.5);
        var start = new TaskCompletionSource();
        var reads = new int[2];
        async Task<FamilyResult> Container(int id)
        {
            var command = Guid.NewGuid();
            return await executor.ExecuteWithRereadAsync(async (attempt, token) =>
            {
                // Both containers read the revision before either commits (the first attempt), then reread current state.
                long read;
                lock (gate) read = revision;
                if (attempt == 1)
                {
                    reads[id] = 1;
                    await start.Task.WaitAsync(token);
                }

                var unit = FamilyUnitOfWork.Begin(FamilyFixture.Plan(), command, FamilyFixture.Workspace, 0, FamilyFixture.Definition());
                foreach (var contribution in FamilyFixture.Contributions(command, revision: attempt == 1 ? 7 : read)) unit.Contribute(contribution);
                return unit;
            }, FamilyRetryPolicy.Default, T.Ct);
        }

        var first = Container(0);
        var second = Container(1);
        while (Volatile.Read(ref reads[0]) + Volatile.Read(ref reads[1]) < 2) await Task.Yield();
        start.SetResult();
        var results = await Task.WhenAll(first, second);
        Assert.All(results, result => Assert.True(result.Committed));
        Assert.Equal(9, revision);
        Assert.Equal(2, commits.Count);
        Assert.Equal([7L, 8L], commits.Select(commit => commit.Read).Order().ToArray());
        Assert.Equal(1, results.Count(result => result.Attempts == 1));
        Assert.Equal(1, results.Count(result => result.Attempts == 2));
        Assert.Equal(2, commits.Select(commit => commit.Command).Distinct().Count());
    }
}
