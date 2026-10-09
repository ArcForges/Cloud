// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Infrastructure;
using ArcForges.Cloud.Modules.Task.Harness.HelloSlice.Application;
using ArcForges.Cloud.Modules.Task.Harness.HelloSlice.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.HarnessFoundation;

/// <summary>The model port of the tests. It records every dispatch, answers from a script, and otherwise answers the two steps of the slice.</summary>
internal sealed class FakeModels : IModelDispatchPort
{
    public Dictionary<string, ModelSnapshot> Snapshots { get; } = new(StringComparer.Ordinal)
    {
        ["model.alpha"] = new ModelSnapshot("model.alpha", "tariff.2026-10"),
    };

    public Queue<ModelCallResult> Script { get; } = new();

    public List<ModelCallRequest> Calls { get; } = [];

    /// <summary>Runs inside the call, after the dispatch is recorded and before the answer returns.</summary>
    public Func<ModelCallRequest, Task>? DuringCall { get; set; }

    /// <summary>When set, the call raises instead of answering.</summary>
    public Exception? Throws { get; set; }

    public ModelSnapshot? SnapshotOf(string modelId) => Snapshots.GetValueOrDefault(modelId);

    public async Task<ModelCallResult> DispatchAsync(ModelCallRequest request, CancellationToken cancellationToken)
    {
        Calls.Add(request);
        if (DuringCall is not null) await DuringCall(request).ConfigureAwait(false);
        if (Throws is not null) throw Throws;
        if (Script.Count > 0) return Script.Dequeue();
        return request.RequestJson.Contains("\"tools\"", StringComparison.Ordinal)
            ? Answer(Answers.ToolCall())
            : Answer(Answers.Final("Hello, Ada!"));
    }

    internal static ModelCallResult Answer(string json) => new(ModelDispatchStatus.Succeeded, json, "ok");
}

/// <summary>The plan port with one named read answered as unavailable from its Nth read on; the earlier reads are served, so a claim can commit first.</summary>
internal sealed class ReadNotServedFromPort(IModulePlanPort inner, string plan, int fromRead) : IModulePlanPort
{
    private int reads;

    public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken)
    {
        if (read.PlanId != plan) return inner.ReadAsync(read, cancellationToken);
        reads++;
        return reads >= fromRead
            ? Task.FromResult(ModulePlanOutcome.Of(ModulePlanStatus.Unavailable))
            : inner.ReadAsync(read, cancellationToken);
    }

    public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken) => inner.WriteAsync(write, cancellationToken);
}

/// <summary>Model answers in the shape the supplier returns (one choice, one assistant message).</summary>
internal static class Answers
{
    public static string ToolCall(string argumentName = "Ada", string functionName = "say_hello", string finish = "tool_calls", string callId = "call_1") =>
        "{\"choices\":[{\"finish_reason\":\"" + finish + "\",\"message\":{\"role\":\"assistant\",\"tool_calls\":[{\"type\":\"function\",\"id\":\""
        + callId + "\",\"function\":{\"name\":\"" + functionName + "\",\"arguments\":\"{\\\"name\\\":\\\"" + argumentName + "\\\"}\"}}]}}]}";

    public static string Final(string text, string finish = "stop") =>
        "{\"choices\":[{\"finish_reason\":\"" + finish + "\",\"message\":{\"role\":\"assistant\",\"content\":\"" + text + "\"}}]}";
}

public sealed class HelloSliceTests
{
    private static HelloAgentSlice Slice(HarnessFixture fixture, IModelDispatchPort models, TimeSpan? keepalive = null, HelloModelSettings? settings = null) =>
        new(new D1HarnessStore(fixture.Port), models, fixture.Ids, fixture.Clock, settings ?? HelloModelSettings.Deployed, keepalive ?? TimeSpan.FromHours(1));

    private static HelloAgentSlice SliceOver(HarnessFixture fixture, IModelDispatchPort models, IModulePlanPort port) =>
        new(new D1HarnessStore(port), models, fixture.Ids, fixture.Clock, HelloModelSettings.Deployed, TimeSpan.FromHours(1));

    private static HarnessExecutor Executor(HarnessFixture fixture) => new(new D1HarnessStore(fixture.Port), new FakeEffects(), fixture.Ids, fixture.Clock);

    private static async Task<long> LeaseExpiryAsync(HarnessFixture fixture)
    {
        var rows = await fixture.QueryAsync("SELECT expires_at FROM task_execution_lease WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        return long.Parse(rows[0][0]!, System.Globalization.CultureInfo.InvariantCulture);
    }

    [Fact]
    public async Task TheHelloRunAdmitsDispatchesOneToolAndFinishesWithEachStepCountedOnce()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(HelloStatus.Succeeded, result.Status);
        Assert.Equal("ok", result.Reason);
        Assert.Equal("Hello, Ada!", result.Message);
        Assert.Equal("6", await fixture.RunStateAsync());
        Assert.Equal(2, models.Calls.Count);
        Assert.All(models.Calls, call =>
        {
            Assert.Equal("model.alpha", call.ModelId);
            Assert.Equal("tariff.2026-10", call.TariffSnapshotId);
            Assert.Equal(TimeSpan.FromSeconds(90), call.Deadline);
            Assert.Equal(1024, call.MaxOutputTokens);
        });
        Assert.Equal(1, models.Calls[0].ToolCount);
        Assert.Equal(0, models.Calls[1].ToolCount);
        Assert.Contains("\"tools\":[{\"type\":\"function\"", models.Calls[0].RequestJson, StringComparison.Ordinal);
        Assert.Contains("\"tool_choice\":\"none\"", models.Calls[1].RequestJson, StringComparison.Ordinal);
        // The claim 3 (claim batch and two reads), the model step 5 and the tool step 4 and the final model step 5 (BudgetDefinition), one
        // checkpoint per answer and at admission (4), and the yield (1): 22 steps and 22 subrequests, two model calls and one tool invocation.
        Assert.Equal(new BudgetCounters(CountedSteps: 22, Subrequests: 22, ModelCalls: 2, ToolInvocations: 1), await fixture.BudgetAsync());
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
    }

    [Fact]
    public async Task TheRunRecordsTheWorkerVersionAndTheBuildIdentityAndNoContentIsPersisted()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var result = await Slice(fixture, new FakeModels()).RunAsync(fixture.Run, HarnessFixture.Identity("worker.v9", "cloud.build.7"), "Ada", T.Ct);
        Assert.Equal(HelloStatus.Succeeded, result.Status);

        var run = await fixture.QueryAsync("SELECT worker_version, workflow_id FROM task_run WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal("worker.v9", run[0][0]);
        Assert.StartsWith("af-", run[0][1], StringComparison.Ordinal);

        // Every stored reference is a content-addressed hash; no prompt, name, greeting or answer text reaches the database.
        var refs = await fixture.QueryAsync("SELECT result_ref, request_sha256 FROM task_execution_command");
        Assert.Equal(3, refs.Count);
        Assert.All(refs, row =>
        {
            Assert.Matches("^\\{\"ref\":\"sha256-[0-9a-f]{64}\"\\}$", row[0]!);
            Assert.Matches("^[0-9a-f]{64}$", row[1]!);
        });
        var stored = string.Join("|", refs.SelectMany(row => row).Where(value => value is not null));
        Assert.DoesNotContain("Ada", stored, StringComparison.Ordinal);
        Assert.DoesNotContain("Hello", stored, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("a\u0007b")]
    [InlineData("a\u007fb")]
    public async Task AnInvalidNameIsRefusedBeforeAnyClaimOrDispatch(string name)
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), name, T.Ct);
        Assert.Equal(HelloStatus.Refused, result.Status);
        Assert.Equal("invalid_name", result.Reason);
        Assert.Equal("1", await fixture.RunStateAsync());
        Assert.Empty(models.Calls);
    }

    [Fact]
    public async Task ANameOverEightyCodePointsOrTwoHundredFiftySixBytesIsRefused()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        var slice = Slice(fixture, models);
        var tooManyCodePoints = new string('a', 81);
        var tooManyBytes = string.Concat(Enumerable.Repeat("\U0001F600", 80));
        Assert.Equal(80, tooManyBytes.EnumerateRunes().Count());
        Assert.True(System.Text.Encoding.UTF8.GetByteCount(tooManyBytes) > 256);
        Assert.Equal(HelloStatus.Refused, (await slice.RunAsync(fixture.Run, HarnessFixture.Identity(), tooManyCodePoints, T.Ct)).Status);
        Assert.Equal(HelloStatus.Refused, (await slice.RunAsync(fixture.Run, HarnessFixture.Identity(), tooManyBytes, T.Ct)).Status);
        Assert.Empty(models.Calls);
        Assert.Equal("1", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task AnUnpinnedRunIsRefusedBeforeAnyClaim()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var identity = new RunIdentity(HarnessFixture.RunId, "cloud.build.1", "worker.v1", 1, new PinnedSnapshot(string.Empty, string.Empty));
        var models = new FakeModels();
        var result = await Slice(fixture, models).RunAsync(fixture.Run, identity, "Ada", T.Ct);
        Assert.Equal(new HelloResult(HelloStatus.Refused, "unpinned", null), result);
        Assert.Equal("1", await fixture.RunStateAsync());
        Assert.Empty(models.Calls);
    }

    [Fact]
    public async Task AMissingAdmittedSnapshotIsRefusedBeforeAnyClaimOrDispatch()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        models.Snapshots.Clear();
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);
        Assert.Equal(new HelloResult(HelloStatus.Refused, "snapshot_missing", null), result);
        Assert.Equal("1", await fixture.RunStateAsync());
        Assert.Empty(models.Calls);
    }

    [Fact]
    public async Task AChangedTariffSnapshotIsRefusedBeforeAnyClaimOrDispatch()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        models.Snapshots["model.alpha"] = new ModelSnapshot("model.alpha", "tariff.2026-11");
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);
        Assert.Equal(new HelloResult(HelloStatus.Refused, "snapshot_changed", null), result);
        Assert.Equal("1", await fixture.RunStateAsync());
        Assert.Empty(models.Calls);
    }

    [Theory]
    [InlineData("", "cloud.build.1")]
    [InlineData("worker with spaces", "cloud.build.1")]
    [InlineData("worker.v1", "")]
    public async Task AnIdentityWithoutBoundedWorkerVersionAndBuildIsRefused(string worker, string build)
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(worker, build), "Ada", T.Ct);
        Assert.Equal(new HelloResult(HelloStatus.Refused, "identity", null), result);
        Assert.Empty(models.Calls);
    }

    [Fact]
    public async Task ARunHeldByAnotherLiveClaimIsRefusedWithoutAWrite()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var first = await Executor(fixture).ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
        Assert.Equal(ClaimStatus.Claimed, first.Status);
        var models = new FakeModels();
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);
        Assert.Equal(new HelloResult(HelloStatus.Refused, "claim_refused", null), result);
        Assert.Equal("2", await fixture.RunStateAsync());
        Assert.Empty(models.Calls);
    }

    [Fact]
    public async Task ARunThatAlreadyRecordedAnEffectIsNeverRestartedHere()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        // The claim creates the budget row, so the run is claimed once, released to Waiting, and only then has its counted step raised.
        var executor = Executor(fixture);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        Assert.Equal(StoreStatus.Succeeded, await executor.YieldAsync(claim, RunState.Waiting, T.Ct));
        // A reserved model effect is written as its increments (ModelAttempt(1): five steps, five subrequests, one model call), never as a lower value.
        await fixture.ExecAsync(
            "UPDATE task_harness_budget SET counted_steps = counted_steps + 5, subrequests = subrequests + 5, model_calls = model_calls + 1 WHERE run_id = '"
            + HarnessFixture.RunId.ToString("D") + "';");
        var models = new FakeModels();
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);
        Assert.Equal(new HelloResult(HelloStatus.Refused, "already_started", null), result);
        Assert.Equal("5", await fixture.RunStateAsync());
        Assert.Empty(models.Calls);
    }

    [Fact]
    public void TheModelSettingsAcceptOnlyValuesInsideTheDesignCapsAndTheDeployedValuesAreNinetySecondsAndOneKiloToken()
    {
        Assert.Equal(90, HelloModelSettings.Deployed.DeadlineSeconds);
        Assert.Equal(1024, HelloModelSettings.Deployed.MaxOutputTokens);
        Assert.Equal(120, HelloModelSettings.Create(120, 4096).DeadlineSeconds);
        Assert.Throws<ArgumentOutOfRangeException>(() => HelloModelSettings.Create(121, 1024));
        Assert.Throws<ArgumentOutOfRangeException>(() => HelloModelSettings.Create(0, 1024));
        Assert.Throws<ArgumentOutOfRangeException>(() => HelloModelSettings.Create(90, 4097));
        Assert.Throws<ArgumentOutOfRangeException>(() => HelloModelSettings.Create(90, 0));
    }

    [Fact]
    public async Task APreDispatchRefusalIsRetriedAtMostTwiceWithAFreshAttemptAndThenSucceeds()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        models.Script.Enqueue(new ModelCallResult(ModelDispatchStatus.RefusedBeforeDispatch, null, "rate_limited"));
        models.Script.Enqueue(new ModelCallResult(ModelDispatchStatus.RefusedBeforeDispatch, null, "rate_limited"));
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(HelloStatus.Succeeded, result.Status);
        Assert.Equal(4, models.Calls.Count);
        // Every attempt is reserved, so each refused attempt counts against the step and model budgets. The first step is 5 steps and 5
        // subrequests, each retry is 5 steps (its retry class) and 4 subrequests. With the claim 3, four checkpoints, the tool step 4,
        // the final step 5 and the yield 1: 32 steps and 30 subrequests.
        Assert.Equal(new BudgetCounters(CountedSteps: 32, Subrequests: 30, ModelCalls: 4, ToolInvocations: 1), await fixture.BudgetAsync());
    }

    [Fact]
    public async Task APreDispatchRefusalAfterTheRetryLimitFailsTheRunWithNoFurtherCall()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        for (var attempt = 0; attempt < 3; attempt++) models.Script.Enqueue(new ModelCallResult(ModelDispatchStatus.RefusedBeforeDispatch, null, "rate_limited"));
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(new HelloResult(HelloStatus.Failed, "step_refused_request-tool", null), result);
        Assert.Equal(3, models.Calls.Count);
        Assert.Equal("8", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task AnUnknownOutcomeIsNeverRetriedAndTheRunWaitsForReconciliation()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        models.Script.Enqueue(new ModelCallResult(ModelDispatchStatus.Unknown, null, "adapter_502"));
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(new HelloResult(HelloStatus.Interrupted, "unknown_effect_request-tool", null), result);
        Assert.Single(models.Calls);
        Assert.Equal("5", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task ADispatchThatRaisesIsAnUnknownEffectRecordedAsSuchAndNotRetried()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels { Throws = new InvalidOperationException("the connection was cut") };
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(HelloStatus.Interrupted, result.Status);
        Assert.Single(models.Calls);
        var attempts = await fixture.QueryAsync("SELECT state, effect_certainty FROM task_attempt WHERE run_id = '" + HarnessFixture.RunId.ToString("D") + "'");
        Assert.Equal(new[] { new[] { "4", "3" } }, attempts.Select(row => row.ToArray()).ToArray());
    }

    [Fact]
    public async Task ADefinitelyFailedDispatchFailsTheRunWithoutRetry()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        models.Script.Enqueue(new ModelCallResult(ModelDispatchStatus.FailedDidNotHappen, null, "deadline_out_of_range"));
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);
        Assert.Equal(new HelloResult(HelloStatus.Failed, "step_failed_request-tool", null), result);
        Assert.Single(models.Calls);
        Assert.Equal("8", await fixture.RunStateAsync());
    }

    [Theory]
    [InlineData("{\"choices\":[]}", "choice_count")]
    [InlineData("not json", "response_json")]
    [InlineData("[]", "response_shape")]
    [InlineData("{\"error\":\"boom\"}", "response_error")]
    [InlineData("{\"choices\":[{\"finish_reason\":\"length\",\"message\":{\"role\":\"assistant\",\"tool_calls\":[]}}]}", "output_truncated")]
    [InlineData("{\"choices\":[{\"finish_reason\":\"stop\",\"message\":{\"role\":\"assistant\",\"tool_calls\":[]}}]}", "finish_reason")]
    [InlineData("{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"role\":\"user\",\"tool_calls\":[]}}]}", "message_speaker")]
    [InlineData("{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"role\":\"assistant\",\"refusal\":\"no\",\"tool_calls\":[]}}]}", "refusal")]
    [InlineData("{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"role\":\"assistant\",\"function_call\":{}}}]}", "legacy_function_call")]
    [InlineData("{\"choices\":[{\"finish_reason\":\"content_filter\",\"message\":{\"role\":\"assistant\"}}]}", "content_filtered")]
    public async Task AMalformedFirstAnswerFailsTheRunWithItsClosedReasonAndNoRetry(string answer, string reason)
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        models.Script.Enqueue(FakeModels.Answer(answer));
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);
        Assert.Equal(new HelloResult(HelloStatus.Failed, reason, null), result);
        Assert.Single(models.Calls);
        Assert.Equal("8", await fixture.RunStateAsync());
    }

    [Theory]
    [InlineData("say_hello", "Ada", "tool_count")]
    [InlineData("other_tool", "Ada", "tool_shape")]
    [InlineData("say_hello", "Bob", "tool_name_changed")]
    [InlineData("say_hello", "", "tool_arguments")]
    public async Task AToolProposalThatDoesNotMatchTheRequestFailsTheRun(string functionName, string argument, string reason)
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        var answer = reason == "tool_count"
            ? "{\"choices\":[{\"finish_reason\":\"tool_calls\",\"message\":{\"role\":\"assistant\",\"tool_calls\":[]}}]}"
            : Answers.ToolCall(argument, functionName);
        models.Script.Enqueue(FakeModels.Answer(answer));
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);
        Assert.Equal(new HelloResult(HelloStatus.Failed, reason, null), result);
        Assert.Single(models.Calls);
    }

    [Theory]
    [InlineData("   ", "final_text")]
    [InlineData("", "final_text")]
    [InlineData("hi", "output_truncated")]
    public async Task AMalformedFinalAnswerFailsTheRunAfterTheToolStep(string text, string reason)
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        models.Script.Enqueue(FakeModels.Answer(Answers.ToolCall()));
        models.Script.Enqueue(FakeModels.Answer(text.Length == 2 ? Answers.Final(text, "length") : Answers.Final(text)));
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);
        Assert.Equal(new HelloResult(HelloStatus.Failed, reason, null), result);
        Assert.Equal(2, models.Calls.Count);
        // The claim 3, the admission and two answers' checkpoints (3), the two model steps 5 and 5, the tool step 4 and the yield 1.
        Assert.Equal(new BudgetCounters(CountedSteps: 21, Subrequests: 21, ModelCalls: 2, ToolInvocations: 1), await fixture.BudgetAsync());
    }

    [Fact]
    public async Task ALeaseLostDuringTheCallStopsWithNoFurtherWriteAndTheEffectStaysUnresolved()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels
        {
            DuringCall = _ =>
            {
                // The lease term is 60 seconds and no keepalive runs here: a call that outlives it loses its fence.
                fixture.Clock.AdvanceSeconds(61);
                return Task.CompletedTask;
            },
        };
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(HelloStatus.LeaseLost, result.Status);
        Assert.Single(models.Calls);
        var command = await fixture.QueryAsync("SELECT state FROM task_execution_command");
        Assert.Equal("dispatching", command[0][0]);
        Assert.Equal("2", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task ALongCallKeepsItsFenceByRenewingTheLeaseOnTheKeepaliveSchedule()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        models.DuringCall = async _ =>
        {
            if (models.Calls.Count != 1) return;
            // Three 25-second advances take the first call past the 60-second term. Each advance waits for the keepalive to extend the lease.
            for (var step = 0; step < 3; step++)
            {
                var before = await LeaseExpiryAsync(fixture);
                fixture.Clock.AdvanceSeconds(25);
                for (var poll = 0; poll < 400 && await LeaseExpiryAsync(fixture) == before; poll++) await Task.Delay(5);
                Assert.NotEqual(before, await LeaseExpiryAsync(fixture));
            }
        };
        var result = await Slice(fixture, models, TimeSpan.FromMilliseconds(5)).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(HelloStatus.Succeeded, result.Status);
        Assert.Equal(2, models.Calls.Count);
        Assert.Equal("6", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task ACancelledCallSettlesInterruptedWithOneDispatchAndNoRetry()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        using var cancel = new CancellationTokenSource();
        var models = new FakeModels
        {
            DuringCall = _ =>
            {
                cancel.Cancel();
                throw new OperationCanceledException(cancel.Token);
            },
        };
        var result = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", cancel.Token);

        Assert.Equal(HelloStatus.Interrupted, result.Status);
        Assert.Single(models.Calls);
        Assert.Equal("5", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task TheStoreRefusesASecondReservationOfTheSameCommandIdentifier()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var executor = Executor(fixture);
        var claim = (await executor.ClaimAsync(fixture.Run, HarnessFixture.Identity(), T.Ct)).Claim!;
        var store = new D1HarnessStore(fixture.Port);
        var commandId = fixture.Ids.NewId();

        ReserveCommand Reserve(Guid attempt) => new(
            fixture.Ids.NewId(), commandId, attempt, fixture.Ids.NewId(), 1, "request-tool", new string('a', 64),
            EffectCost.ModelCall, BudgetPolicy.EffectStepGuard, BudgetPolicy.EffectSubrequestStop, 16, 64, fixture.Clock.Micros(), HarnessFixture.Pin);

        Assert.Equal(StoreStatus.Succeeded, await store.ReserveStepAsync(claim.Fence, Reserve(fixture.Ids.NewId()), T.Ct));
        Assert.Equal(StoreStatus.Refused, await store.ReserveStepAsync(claim.Fence, Reserve(fixture.Ids.NewId()), T.Ct));
    }

    [Fact]
    public async Task ARunReadNotServedDuringTheClaimIsRetryableAndChangesNothing()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        var result = await SliceOver(fixture, models, new FailingReadPlanPort(fixture.Port, "task.harness-executor-run-load")).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(new HelloResult(HelloStatus.Unavailable, "read_unavailable_claim", null), result);
        Assert.Empty(models.Calls);
        Assert.Equal("1", await fixture.RunStateAsync());
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
    }

    [Fact]
    public async Task ARunReadNotServedUnderItsClaimReleasesTheRunToWaitingBeforeAnyDispatchAndTheRetryCompletes()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var models = new FakeModels();
        // The claim makes two run-load reads (before and after the claim commits); the third is the first step's read under the lease.
        var result = await SliceOver(fixture, models, new ReadNotServedFromPort(fixture.Port, "task.harness-executor-run-load", 3)).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(new HelloResult(HelloStatus.Unavailable, "read_unavailable", null), result);
        Assert.Empty(models.Calls);
        Assert.Equal("3", await fixture.RunStateAsync());
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());

        var retry = await Slice(fixture, models).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);
        Assert.Equal(HelloStatus.Succeeded, retry.Status);
        Assert.Equal("6", await fixture.RunStateAsync());
    }

    /// <summary>The Hello slice as the proof composition builds it: the read-unavailable exit parks through the registered alarm port.</summary>
    private static HelloAgentSlice AlarmSlice(HarnessFixture fixture, IHarnessStore store, IModelDispatchPort models, IHarnessAlarmPort? alarm) =>
        new(store, models, fixture.Ids, fixture.Clock, HelloModelSettings.Deployed, TimeSpan.FromHours(1), alarm);

    /// <summary>A store whose yields are recorded in order, over a plan port that answers the first step's run read as unavailable.</summary>
    private static YieldScriptStore UnavailableOnFirstStepStore(HarnessFixture fixture, List<string> events, StoreStatus? yieldOutcome = null) =>
        new(new D1HarnessStore(new ReadNotServedFromPort(fixture.Port, "task.harness-executor-run-load", 3)), events, yieldOutcome);

    [Fact]
    public async Task AReadNotServedWithTheAlarmPortParksTheRunWithAWakeAboutOneSecondLaterAndTheWakeResumesIt()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var events = new List<string>();
        var alarm = new RecordingAlarm();
        var models = new FakeModels();
        var nowMs = fixture.Clock.Micros() / 1000;

        var result = await AlarmSlice(fixture, UnavailableOnFirstStepStore(fixture, events), models, alarm).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(new HelloResult(HelloStatus.Unavailable, "read_unavailable", null), result);
        // The wake is armed before the waiting commit, and the run is parked with its lease released.
        Assert.Equal(new[] { "arm" }, alarm.Events);
        Assert.Equal(new[] { "commit:Waiting" }, events);
        var schedule = Assert.Single(alarm.Schedules);
        Assert.Equal(HarnessFixture.WorkspaceId, schedule.WorkspaceId);
        Assert.Equal(HarnessFixture.RunId, schedule.RunId);
        Assert.Equal(nowMs + 1000, schedule.WakeAtMs);
        Assert.Empty(models.Calls);
        Assert.Equal("3", await fixture.RunStateAsync());
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());

        // The wake at the scheduled time claims the parked run and settles it, with no caller retry and no dispatch.
        fixture.Clock.AdvanceSeconds(1);
        var wake = await new HarnessWakeHandler(new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock)).HandleAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
        Assert.Equal(WakeStatus.Settled, wake.Status);
        Assert.Equal(ClaimStatus.Claimed, wake.Claim);
        Assert.Equal(ResumeKind.NothingOpen, wake.Resume);
        Assert.Equal("3", await fixture.RunStateAsync());
        Assert.Empty(models.Calls);

        // The caller's own retry then runs the greeting to completion on the claimed run.
        var retry = await AlarmSlice(fixture, new D1HarnessStore(fixture.Port), models, alarm).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);
        Assert.Equal(HelloStatus.Succeeded, retry.Status);
        Assert.Equal("Hello, Ada!", retry.Message);
        Assert.Equal("6", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task AReadNotServedWithoutTheAlarmPortSettlesToWaitingAsBefore()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var events = new List<string>();
        var models = new FakeModels();

        var result = await AlarmSlice(fixture, UnavailableOnFirstStepStore(fixture, events), models, alarm: null).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(new HelloResult(HelloStatus.Unavailable, "read_unavailable", null), result);
        Assert.Equal(new[] { "commit:Waiting" }, events);
        Assert.Empty(models.Calls);
        Assert.Equal("3", await fixture.RunStateAsync());
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());
    }

    [Fact]
    public async Task ARefusedArmAnswersTheRetryableReplyWithoutParkingAndTheRunClaimsAfterItsLeaseTerm()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var events = new List<string>();
        var alarm = new RecordingAlarm { Reply = _ => HarnessAlarmReply.Refused };
        var models = new FakeModels();

        var result = await AlarmSlice(fixture, UnavailableOnFirstStepStore(fixture, events), models, alarm).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(new HelloResult(HelloStatus.Unavailable, "read_unavailable", null), result);
        Assert.Equal(new[] { "arm" }, alarm.Events);
        Assert.Empty(events);
        Assert.Empty(models.Calls);
        // Not parked: the run stays under the lease the claim took, and nothing is written after the refused arm.
        Assert.Equal("2", await fixture.RunStateAsync());
        Assert.Equal(0, await fixture.CountOpenAttemptsAsync());

        // A wake delivered while that lease is live is refused and retried, not taken.
        var early = await new HarnessWakeHandler(new HarnessExecutor(fixture.Store, new FakeEffects(), fixture.Ids, fixture.Clock)).HandleAsync(fixture.Run, HarnessFixture.Identity(), T.Ct);
        Assert.Equal(WakeStatus.Stopped, early.Status);
        Assert.Equal("2", await fixture.RunStateAsync());

        // The caller's retry claims the run once the lease has expired, and completes it.
        fixture.Clock.AdvanceSeconds(61);
        var retry = await AlarmSlice(fixture, new D1HarnessStore(fixture.Port), models, alarm).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);
        Assert.Equal(HelloStatus.Succeeded, retry.Status);
        Assert.Equal("6", await fixture.RunStateAsync());
    }

    [Fact]
    public async Task AWaitingCommitThatDidNotHappenAfterArmingCancelsTheWakeAndReleasesWithTheFailedReleaseReply()
    {
        using var fixture = await HarnessFixture.CreateAsync();
        var events = new List<string>();
        var alarm = new RecordingAlarm();
        var models = new FakeModels();

        var result = await AlarmSlice(fixture, UnavailableOnFirstStepStore(fixture, events, StoreStatus.Refused), models, alarm).RunAsync(fixture.Run, HarnessFixture.Identity(), "Ada", T.Ct);

        Assert.Equal(new HelloResult(HelloStatus.LeaseLost, "release_refused", null), result);
        Assert.Equal(new[] { "arm", "cancel" }, alarm.Events);
        Assert.Equal(new[] { "commit:Waiting" }, events);
        Assert.Empty(models.Calls);
        Assert.Equal("2", await fixture.RunStateAsync());
    }

    [Fact]
    public void ARunIdentityBindsTheWorkerVersionAndTheBuildIdentityApartAndPerEpoch()
    {
        var pin = HarnessFixture.Pin;
        var worker = new RunIdentity(HarnessFixture.RunId, "build.A", "worker.B", 1, pin);
        var swapped = new RunIdentity(HarnessFixture.RunId, "worker.B", "build.A", 1, pin);
        var otherBuild = new RunIdentity(HarnessFixture.RunId, "build.C", "worker.B", 1, pin);
        Assert.NotEqual(worker.DigestForEpoch(1), swapped.DigestForEpoch(1));
        Assert.NotEqual(worker.DigestForEpoch(1), otherBuild.DigestForEpoch(1));
        Assert.NotEqual(worker.DigestForEpoch(1), worker.DigestForEpoch(2));
        Assert.Equal(worker.DigestForEpoch(1), new RunIdentity(HarnessFixture.RunId, "build.A", "worker.B", 1, pin).DigestForEpoch(1));
    }
}
