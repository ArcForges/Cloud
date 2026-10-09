// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Application;
using ArcForges.Cloud.Modules.Task.Harness.Executor.Domain;

namespace ArcForges.Cloud.Modules.Task.Harness.Executor.Infrastructure;

/// <summary>The named plans of the Task owner that the executor uses (<c>storage/plans/task/harness-executor-*.sql</c>).</summary>
internal static class HarnessPlans
{
    internal const string RunLoad = "task.harness-executor-run-load";
    internal const string AttemptLoad = "task.harness-executor-attempt-load";
    internal const string Claim = "task.harness-executor-claim";
    internal const string Renew = "task.harness-executor-renew";
    internal const string ReserveStep = "task.harness-executor-reserve-step";
    internal const string MarkDispatch = "task.harness-executor-mark-dispatch";
    internal const string RecordOutcome = "task.harness-executor-record-outcome";
    internal const string Checkpoint = "task.harness-executor-checkpoint";
    internal const string Yield = "task.harness-executor-yield";
}

/// <summary>
/// The executor's durable store over D1, written only against the Abstractions plan port: each call names one reviewed plan of the Task
/// owner and sends exact typed arguments. It names no table and no SQL. A plan's guard holds the fence, so a stale or expired writer
/// commits nothing, and every write is sent once: an unknown outcome is reported, never retried here.
/// </summary>
internal sealed class D1HarnessStore(IModulePlanPort plans) : IHarnessStore
{
    public async Task<RunSnapshot?> LoadAsync(HarnessRun run, CancellationToken cancellationToken)
    {
        var scope = Scope(run);
        var outcome = await plans.ReadAsync(
            new ModulePlanRead(HarnessPlans.RunLoad, scope, [PlanValue.FromText(Id(run.RunId)), PlanValue.FromText(scope)]),
            cancellationToken).ConfigureAwait(false);
        if (outcome.Status == ModulePlanStatus.Unavailable) throw new HarnessReadUnavailableException(HarnessPlans.RunLoad);
        if (outcome.Status != ModulePlanStatus.Succeeded) throw Refused(outcome.Status);
        if (outcome.Rows.Count == 0) return null;
        var row = outcome.Rows[0];
        var lease = row[5].IsNull
            ? null
            : new LeaseRow(new Guid(row[5].AsText()), Int(row[6]), Int(row[7]), Int(row[8]));
        var budget = row[9].IsNull
            ? new BudgetCounters(0, 0, 0, 0)
            : new BudgetCounters(Int(row[9]), Int(row[10]), Int(row[11]), Int(row[12]));
        var pin = row[14].IsNull || row[15].IsNull ? null : new PinnedSnapshot(row[14].AsText(), row[15].AsText());
        return new RunSnapshot(
            (RunState)Int(row[0]),
            Int(row[1]),
            Int(row[2]),
            row[3].AsText(),
            row[4].AsText(),
            lease,
            budget,
            pin,
            row[13].IsNull ? null : row[13].AsBytes().ToArray());
    }

    public async Task<OpenAttempt?> LoadOpenAttemptAsync(HarnessRun run, CancellationToken cancellationToken)
    {
        var scope = Scope(run);
        var outcome = await plans.ReadAsync(
            new ModulePlanRead(HarnessPlans.AttemptLoad, scope, [PlanValue.FromText(Id(run.RunId)), PlanValue.FromText(scope)]),
            cancellationToken).ConfigureAwait(false);
        if (outcome.Status == ModulePlanStatus.Unavailable) throw new HarnessReadUnavailableException(HarnessPlans.AttemptLoad);
        if (outcome.Status != ModulePlanStatus.Succeeded) throw Refused(outcome.Status);
        if (outcome.Rows.Count == 0) return null;
        var row = outcome.Rows[0];
        return new OpenAttempt(
            new Guid(row[0].AsText()),
            new Guid(row[1].AsText()),
            new Guid(row[2].AsText()),
            (int)Int(row[3]),
            (AttemptState)Int(row[4]),
            row[5].AsOptionalText());
    }

    public Task<StoreStatus> ClaimAsync(HarnessRun run, ClaimCommand command, CancellationToken cancellationToken) =>
        WriteAsync(
            HarnessPlans.Claim,
            run,
            [
                [
                    T(command.GuardId), T(run.RunId), T(run.WorkspaceId), I(command.RecoveryGeneration), T(run.RunId), I(command.NowMicros),
                    T(run.RunId), T(run.RunId), T(command.Pinned.ModelId), T(command.Pinned.TariffSnapshotId),
                ],
                [T(run.RunId), T(command.Holder), T(command.WorkflowId), T(command.WorkerVersion), I(command.ExpiresAtMicros), I(command.RecoveryGeneration)],
                [T(run.RunId), I(command.Charge.Steps), I(command.Charge.Subrequests), T(command.Pinned.ModelId), T(command.Pinned.TariffSnapshotId), I(command.NowMicros)],
                [T(command.WorkflowId), T(command.WorkerVersion), I(command.RecoveryGeneration), I(command.NowMicros), T(run.RunId)],
                [T(command.GuardId)],
            ],
            cancellationToken);

    public Task<StoreStatus> RenewAsync(Fence fence, Guid guardId, long nowMicros, long expiresAtMicros, BudgetCharge extraCharge, CancellationToken cancellationToken) =>
        WriteAsync(
            HarnessPlans.Renew,
            fence.Run,
            [
                [T(guardId), T(fence.Run.RunId), T(fence.Run.WorkspaceId), T(fence.Holder), I(fence.Epoch), I(fence.RecoveryGeneration), I(nowMicros)],
                [I(expiresAtMicros), T(fence.Run.RunId), T(fence.Holder), I(fence.Epoch)],
                [I(BudgetDefinition.MaintenanceBatch.Steps + extraCharge.Steps), I(BudgetDefinition.MaintenanceBatch.Subrequests + extraCharge.Subrequests), I(nowMicros), T(fence.Run.RunId)],
                [T(guardId)],
            ],
            cancellationToken);

    public Task<StoreStatus> ReserveStepAsync(Fence fence, ReserveCommand command, CancellationToken cancellationToken) =>
        WriteAsync(
            HarnessPlans.ReserveStep,
            fence.Run,
            [
                [
                    T(command.GuardId), T(fence.Run.RunId), T(fence.Run.WorkspaceId), T(fence.Holder), I(fence.Epoch), I(fence.RecoveryGeneration),
                    I(command.NowMicros), I(command.Cost.Steps), I(command.StepLimit), I(command.Cost.Subrequests), I(command.SubrequestLimit),
                    I(command.Cost.ModelCalls), I(command.ModelLimit), I(command.Cost.ToolInvocations), I(command.ToolLimit),
                    T(command.Pinned.ModelId), T(command.Pinned.TariffSnapshotId), T(command.CommandId),
                ],
                [I(command.Cost.Steps), I(command.Cost.Subrequests), I(command.Cost.ModelCalls), I(command.Cost.ToolInvocations), I(command.NowMicros), T(fence.Run.RunId)],
                [T(command.CommandId), T(fence.Run.RunId), I(fence.Epoch), T(command.Operation), T(command.RequestSha256), I(command.NowMicros)],
                [T(command.AttemptId), T(fence.Run.RunId), T(command.StepId), T(command.CommandId), I(command.Ordinal)],
                [T(command.GuardId)],
            ],
            cancellationToken);

    public Task<StoreStatus> MarkDispatchAsync(Fence fence, Guid guardId, Guid attemptId, long nowMicros, CancellationToken cancellationToken) =>
        WriteAsync(
            HarnessPlans.MarkDispatch,
            fence.Run,
            [
                [T(guardId), T(fence.Run.RunId), T(fence.Run.WorkspaceId), T(fence.Holder), I(fence.Epoch), I(fence.RecoveryGeneration), I(nowMicros), T(attemptId)],
                [I(nowMicros), T(attemptId), T(fence.Run.RunId)],
                [T(attemptId), T(fence.Run.RunId), T(fence.Run.RunId)],
                [T(guardId)],
            ],
            cancellationToken);

    public Task<StoreStatus> RecordOutcomeAsync(Fence fence, OutcomeCommand command, CancellationToken cancellationToken) =>
        WriteAsync(
            HarnessPlans.RecordOutcome,
            fence.Run,
            [
                [
                    T(command.GuardId), T(fence.Run.RunId), T(fence.Run.WorkspaceId), T(fence.Holder), I(fence.Epoch), I(fence.RecoveryGeneration),
                    I(command.NowMicros), T(command.AttemptId), I((long)command.ExpectedAttemptState), T(command.ExpectedCommandState),
                ],
                [
                    I((long)command.NewAttemptState), I(command.Failure is null ? -1 : (long)command.Failure.Value),
                    I(command.Certainty is null ? -1 : (long)command.Certainty.Value), I(command.NowMicros), T(command.AttemptId), T(fence.Run.RunId),
                    I((long)command.ExpectedAttemptState),
                ],
                [
                    T(command.NewCommandState), command.ResultRef is null ? PlanValue.Null : PlanValue.FromText(command.ResultRef),
                    T(command.AttemptId), T(fence.Run.RunId), T(fence.Run.RunId), T(command.ExpectedCommandState),
                ],
                [I(command.Charge.Steps), I(command.Charge.Subrequests), I(command.NowMicros), T(fence.Run.RunId)],
                [T(command.GuardId)],
            ],
            cancellationToken);

    public Task<StoreStatus> CheckpointAsync(Fence fence, Guid guardId, byte[] receiptSha256, long nowMicros, CancellationToken cancellationToken) =>
        WriteAsync(
            HarnessPlans.Checkpoint,
            fence.Run,
            [
                [T(guardId), T(fence.Run.RunId), T(fence.Run.WorkspaceId), T(fence.Holder), I(fence.Epoch), I(fence.RecoveryGeneration), I(nowMicros)],
                [PlanValue.FromBytes(receiptSha256), I(nowMicros), T(fence.Run.RunId)],
                [I(BudgetDefinition.MaintenanceBatch.Steps), I(BudgetDefinition.MaintenanceBatch.Subrequests), I(nowMicros), T(fence.Run.RunId)],
                [T(guardId)],
            ],
            cancellationToken);

    public Task<StoreStatus> YieldAsync(Fence fence, Guid guardId, RunState nextState, long nowMicros, CancellationToken cancellationToken) =>
        WriteAsync(
            HarnessPlans.Yield,
            fence.Run,
            [
                [T(guardId), T(fence.Run.RunId), T(fence.Run.WorkspaceId), T(fence.Holder), I(fence.Epoch), I(fence.RecoveryGeneration), I(nowMicros)],
                [I((long)nextState), I(nowMicros), T(fence.Run.RunId)],
                [T(fence.Run.RunId), T(fence.Holder), I(fence.Epoch)],
                [I(BudgetDefinition.MaintenanceBatch.Steps), I(BudgetDefinition.MaintenanceBatch.Subrequests), I(nowMicros), T(fence.Run.RunId)],
                [T(guardId)],
            ],
            cancellationToken);

    private async Task<StoreStatus> WriteAsync(string planId, HarnessRun run, IReadOnlyList<IReadOnlyList<PlanValue>> statements, CancellationToken cancellationToken)
    {
        var outcome = await plans.WriteAsync(new ModulePlanWrite(planId, Scope(run), statements, null), cancellationToken).ConfigureAwait(false);
        return outcome.Status switch
        {
            ModulePlanStatus.Succeeded => StoreStatus.Succeeded,
            ModulePlanStatus.GuardRefused or ModulePlanStatus.ConstraintRefused or ModulePlanStatus.ReplayedFailure
                or ModulePlanStatus.ReusedIdentifier or ModulePlanStatus.ReceiptExpired or ModulePlanStatus.DuplicateMessage => StoreStatus.Refused,
            ModulePlanStatus.StaleGeneration => StoreStatus.Stale,
            ModulePlanStatus.UnknownOutcome => StoreStatus.Unknown,
            ModulePlanStatus.Unavailable => StoreStatus.Unavailable,
            ModulePlanStatus.Replayed => StoreStatus.Succeeded,
            _ => throw Refused(outcome.Status),
        };
    }

    private static InvalidOperationException Refused(ModulePlanStatus status) =>
        new("The harness plan was refused as a defect: " + status);

    private static string Scope(HarnessRun run) => Id(run.WorkspaceId);

    private static string Id(Guid value) => value.ToString("D");

    private static long Int(PlanValue value) => long.Parse(value.AsText(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture);

    private static PlanValue T(Guid value) => PlanValue.FromText(Id(value));

    private static PlanValue T(string value) => PlanValue.FromText(value);

    private static PlanValue I(long value) => PlanValue.FromInt64(value);
}
