// SPDX-License-Identifier: AGPL-3.0-only
using System.Collections.Concurrent;
using System.Globalization;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Task;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Infrastructure;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Entitlement;
using Xunit;

namespace ArcForges.Cloud.Tests.HarnessFoundation;

/// <summary>Deterministic identifiers in the canonical lower-case UUID form the physical schema requires.</summary>
internal sealed class SequentialIds(long start = 0x1000) : IHarnessIds
{
    private long next = start;

    public Guid NewId() => Guid.Parse("00000000-0000-4000-8000-" + Interlocked.Increment(ref next).ToString("x12", CultureInfo.InvariantCulture));
}

/// <summary>Clock steps and instants in the units the executor uses (whole UTC microseconds).</summary>
internal static class HarnessClock
{
    public static void AdvanceSeconds(this SettableTimeProvider clock, long seconds) =>
        clock.SetSeconds(clock.GetUtcNow().ToUnixTimeSeconds() + seconds);

    public static long Micros(this SettableTimeProvider clock) => (clock.GetUtcNow() - DateTimeOffset.UnixEpoch).Ticks / 10;
}

/// <summary>
/// The external supplier of the tests. It records every dispatch, answers from a script (success when the script is empty), and may run a
/// hook during the call to interleave another writer. A dispatch is the only place an external effect is counted.
/// </summary>
internal sealed class FakeEffects : IEffectPort
{
    private readonly ConcurrentQueue<EffectResult> script = new();

    public List<EffectCall> Calls { get; } = [];

    /// <summary>Runs inside the call, after the dispatch is counted and before the answer returns.</summary>
    public Func<EffectCall, Task>? DuringCall { get; set; }

    /// <summary>When set, the call raises instead of answering (an unknown effect).</summary>
    public bool Throws { get; set; }

    public void Answer(EffectResult result) => script.Enqueue(result);

    public int Count => Calls.Count;

    public async Task<EffectResult> DispatchAsync(EffectCall call, CancellationToken cancellationToken)
    {
        Calls.Add(call);
        if (DuringCall is not null) await DuringCall(call).ConfigureAwait(false);
        if (Throws) throw new InvalidOperationException("The supplier connection was cut after the request was sent.");
        return script.TryDequeue(out var result) ? result : new EffectResult(EffectResultKind.Succeeded, "result.ok");
    }
}

/// <summary>A deliberate process death at a chosen write of the plan port: before the write reaches the store, or after it committed.</summary>
internal sealed class SimulatedCrash(int write, bool after) : Exception("A simulated crash at write " + write + (after ? " after commit." : " before commit."));

/// <summary>
/// Wraps the real plan port and kills the caller at the <paramref name="crashAtWrite"/>-th write. Reads pass through and are never counted,
/// because only writes are the fenced boundaries the crash matrix covers.
/// </summary>
internal sealed class CrashingPlanPort(IModulePlanPort inner, int crashAtWrite, bool after) : IModulePlanPort
{
    private int writes;

    public int Writes => writes;

    public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken) => inner.ReadAsync(read, cancellationToken);

    public async Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken)
    {
        var index = Interlocked.Increment(ref writes);
        if (index == crashAtWrite && !after) throw new SimulatedCrash(index, after: false);
        var outcome = await inner.WriteAsync(write, cancellationToken).ConfigureAwait(false);
        if (index == crashAtWrite && after) throw new SimulatedCrash(index, after: true);
        return outcome;
    }
}

/// <summary>
/// One run of one workspace on the SQLite oracle: the real Task plans, the real constraints and the real batch rollback. The oracle is
/// SQLite, not D1, so the HMAC path and the provider limits are not exercised here (the local workerd run repeats the engine cases).
/// </summary>
internal sealed class HarnessFixture : IDisposable
{
    public static readonly Guid WorkspaceId = Guid.Parse("00000000-0000-4000-8000-0000000000b1");
    public static readonly Guid TaskId = Guid.Parse("00000000-0000-4000-8000-0000000000c1");
    public static readonly Guid RunId = Guid.Parse("00000000-0000-4000-8000-0000000000d1");

    public static readonly PinnedSnapshot Pin = new("model.alpha", "tariff.2026-10");

    private HarnessFixture(SqliteBridgeExecutor bridge, SettableTimeProvider clock)
    {
        Bridge = bridge;
        Clock = clock;
        Port = new ModulePlanPortFactory(bridge, bridge.Generation, clock).For(TaskModule.Instance.Descriptor);
        Store = new D1HarnessStore(Port);
    }

    public SqliteBridgeExecutor Bridge { get; }

    public SettableTimeProvider Clock { get; }

    /// <summary>The port every store call of this fixture goes through.</summary>
    public IModulePlanPort Port { get; }

    public D1HarnessStore Store { get; }

    public SequentialIds Ids { get; } = new();

    public HarnessRun Run => new(WorkspaceId, RunId);

    public static RunIdentity Identity(string worker = "worker.v1", string build = "cloud.build.1", long generation = 1, PinnedSnapshot? pin = null) =>
        new(RunId, build, worker, generation, pin ?? Pin);

    /// <summary>Creates the oracle, the clock at a fixed instant and one queued run of generation 1 in the workspace.</summary>
    public static async Task<HarnessFixture> CreateAsync(int state = (int)RunState.Queued)
    {
        var clock = new SettableTimeProvider(DateTimeOffset.UnixEpoch.AddSeconds(1_000_000));
        var bridge = new SqliteBridgeExecutor(recoveryGeneration: 1);
        var fixture = new HarnessFixture(bridge, clock);
        await bridge.ExecAsync(
            "PRAGMA foreign_keys = OFF;"
            + "INSERT INTO task_task (task_id, workspace_id, origin_surface, origin_device_id, state, reason_facet, intent_summary, created_at, updated_at, rev,"
            + " product_id, origin_installation_id, transient_input_ref, transient_output_receipt_id, current_iteration, current_provider_attempt_id,"
            + " final_message_id, terminal_output_commit_id, no_answer_reason, has_unknown_effect, history_mode)"
            + " VALUES ('" + TaskId.ToString("D") + "', '" + WorkspaceId.ToString("D") + "', 1, NULL, 1, 1, 'fixture', 1, 1, 0,"
            + " 'arcscope', NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, 0, 2);"
            + "INSERT INTO task_run (run_id, task_id, ordinal, state, workflow_id, worker_version, recovery_generation, last_iteration_receipt, created_at, updated_at, rev)"
            + " VALUES ('" + RunId.ToString("D") + "', '" + TaskId.ToString("D") + "', 1, " + state.ToString(CultureInfo.InvariantCulture)
            + ", '', '', 1, NULL, 1, 1, 0);"
            + "PRAGMA foreign_keys = ON;",
            T.Ct).ConfigureAwait(false);
        return fixture;
    }

    /// <summary>Runs fixture SQL (test setup only): the budget may be raised to a chosen level, never lowered.</summary>
    public Task ExecAsync(string sql) => Bridge.ExecAsync(sql, T.Ct);

    public async Task<List<string?[]>> QueryAsync(string sql) => await Bridge.QueryAsync(sql, T.Ct).ConfigureAwait(false);

    /// <summary>The durable counters of the run, read as text (test assertions only).</summary>
    public async Task<BudgetCounters> BudgetAsync()
    {
        var rows = await QueryAsync("SELECT counted_steps, subrequests, model_calls, tool_invocations FROM task_harness_budget WHERE run_id = '" + RunId.ToString("D") + "'").ConfigureAwait(false);
        if (rows.Count == 0) return new BudgetCounters(0, 0, 0, 0);
        return new BudgetCounters(
            long.Parse(rows[0][0]!, CultureInfo.InvariantCulture),
            long.Parse(rows[0][1]!, CultureInfo.InvariantCulture),
            long.Parse(rows[0][2]!, CultureInfo.InvariantCulture),
            long.Parse(rows[0][3]!, CultureInfo.InvariantCulture));
    }

    public async Task<long> CountOpenAttemptsAsync()
    {
        var rows = await QueryAsync("SELECT COUNT(*) FROM task_attempt WHERE run_id = '" + RunId.ToString("D") + "' AND state IN (1, 2)").ConfigureAwait(false);
        return long.Parse(rows[0][0]!, CultureInfo.InvariantCulture);
    }

    public async Task<string?> RunStateAsync()
    {
        var rows = await QueryAsync("SELECT state FROM task_run WHERE run_id = '" + RunId.ToString("D") + "'").ConfigureAwait(false);
        return rows.Count == 0 ? null : rows[0][0];
    }

    public void Dispose() => Bridge.Dispose();
}
