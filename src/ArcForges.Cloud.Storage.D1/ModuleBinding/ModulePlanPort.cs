// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage.Archive;
using ArcForges.Cloud.Storage.Outbox;
using ArcForges.Cloud.Storage.Receipts;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.ModuleBinding;

/// <summary>
/// Creates the plan port of one module over the signed Worker executor (the generic plan-execution port of COM.16). A module project
/// references only the shared Abstractions project, so this is the one place the Abstractions port meets the storage layer: it implements
/// <see cref="IModulePlanPort"/> by looking a named plan up in the generated manifest, refusing a plan whose owner is not the module
/// the port was created for, and mapping every plan failure to a typed status. It sends no SQL text and names no table.
/// </summary>
internal sealed class ModulePlanPortFactory : IModulePlanPortFactory
{
    private readonly IPlanExecutor executor;
    private readonly ulong recoveryGeneration;
    private readonly TimeProvider time;
    private readonly IReadOnlyDictionary<string, PlanDefinition> plans;

    public ModulePlanPortFactory(IPlanExecutor executor, ulong recoveryGeneration, TimeProvider time)
        : this(executor, recoveryGeneration, time, PlanManifest.All)
    {
    }

    /// <summary>The catalogue is a parameter so that a test can bind a fixture plan; the production composition always passes the generated manifest.</summary>
    internal ModulePlanPortFactory(IPlanExecutor executor, ulong recoveryGeneration, TimeProvider time, IReadOnlyList<PlanDefinition> catalogue)
    {
        this.executor = executor ?? throw new ArgumentNullException(nameof(executor));
        this.recoveryGeneration = recoveryGeneration;
        this.time = time ?? throw new ArgumentNullException(nameof(time));
        ArgumentNullException.ThrowIfNull(catalogue);
        plans = catalogue.ToDictionary(plan => plan.Id, StringComparer.Ordinal);
    }

    public IModulePlanPort For(ModuleDescriptor module)
    {
        ArgumentNullException.ThrowIfNull(module);
        return new ModulePlanPort(module, executor, recoveryGeneration, time, plans);
    }
}

internal sealed class ModulePlanPort : IModulePlanPort
{
    private readonly ModuleDescriptor module;
    private readonly IPlanExecutor executor;
    private readonly ulong recoveryGeneration;
    private readonly IReadOnlyDictionary<string, PlanDefinition> plans;
    private readonly CommitExecutor commits;

    public ModulePlanPort(ModuleDescriptor module, IPlanExecutor executor, ulong recoveryGeneration, TimeProvider time, IReadOnlyDictionary<string, PlanDefinition> plans)
    {
        this.module = module;
        this.executor = executor;
        this.recoveryGeneration = recoveryGeneration;
        this.plans = plans;
        commits = new CommitExecutor(executor, new CommandReceiptStore(executor, recoveryGeneration, time), new InboxStore(executor, recoveryGeneration));
    }

    public async Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(read);
        var plan = Owned(read.PlanId, PlanAccess.Read);
        if (plan.Statements.Count != 1) throw new ArgumentException("A read plan has exactly one statement.", nameof(read));
        try
        {
            var call = PlanCall.New(plan, read.OwnerScope, recoveryGeneration, [[.. read.Arguments.Select(ToScalar)]]);
            var result = await executor.ExecuteAsync(call, cancellationToken).ConfigureAwait(false);
            var rows = new List<IReadOnlyList<PlanValue>>(result.Rows.Count);
            foreach (var row in result.Rows) rows.Add([.. row.Select(FromScalar)]);
            return new ModulePlanOutcome(ModulePlanStatus.Succeeded, rows);
        }
        catch (PlanFailureException exception)
        {
            return ModulePlanOutcome.Of(Map(exception.Kind));
        }
        catch (FormatException)
        {
            return ModulePlanOutcome.Of(ModulePlanStatus.Rejected);
        }
    }

    public async Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(write);
        var plan = Owned(write.PlanId, PlanAccess.Write);
        var owner = write.OwnerArguments.Select(arguments => arguments.Select(ToScalar).ToArray()).ToArray();
        try
        {
            if (write.Commit is null)
            {
                if (owner.Length != plan.Statements.Count) throw new ArgumentException("A plan without a commit tail takes the arguments of every statement.", nameof(write));
                await executor.ExecuteAsync(PlanCall.New(plan, write.OwnerScope, recoveryGeneration, owner), cancellationToken).ConfigureAwait(false);
                return ModulePlanOutcome.Of(ModulePlanStatus.Succeeded);
            }

            var values = ToTail(write.Commit);
            var call = PlanCall.New(plan, write.OwnerScope, recoveryGeneration, CommitTail.Bind(plan, write.OwnerScope, owner, values));
            var outcome = await commits.ExecuteAsync(call, values, cancellationToken).ConfigureAwait(false);
            return new ModulePlanOutcome(Map(outcome.Kind), [], outcome.Stored?.ResultPayloadJson);
        }
        catch (PlanFailureException exception)
        {
            return ModulePlanOutcome.Of(Map(exception.Kind));
        }
    }

    /// <summary>The plan, found by its id, when it belongs to this module and has the expected access. A foreign or unknown plan is a caller defect and never reaches the executor.</summary>
    private PlanDefinition Owned(string planId, PlanAccess access)
    {
        ArgumentException.ThrowIfNullOrEmpty(planId);
        // The owner is the whole first segment of the plan id: "entitlement.x" belongs to Entitlement, "entitlementx.y" and "x.entitlement.y" do not.
        var boundary = planId.IndexOf('.', StringComparison.Ordinal);
        if (boundary <= 0 || !string.Equals(planId[..boundary], module.PlanOwner, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The plan '" + planId + "' is not a plan of the " + module.Name + " module.");
        }

        if (!plans.TryGetValue(planId, out var plan)) throw new InvalidOperationException("The plan '" + planId + "' is not in the plan manifest.");
        if (plan.Access != access) throw new InvalidOperationException("The plan '" + planId + "' is not a " + access.ToString().ToLowerInvariant() + " plan.");
        return plan;
    }

    private static CommitTailValues ToTail(ModuleCommit commit)
    {
        var identity = new CommandIdentity(commit.CommandId, commit.WorkspaceId, commit.ActorRef, commit.Operation, commit.RequestHash);
        var receipt = new CommandReceipt(identity, commit.ResultPayloadJson, commit.ResultRevision, commit.CreatedAtMicros, commit.ExpiresAtMicros);
        var events = commit.Events.Select(e => new OutboxEvent(e.OutboxId, e.AggregateKind, e.AggregateId, e.AggregateRevision, e.EventType, e.PayloadJson, e.WorkspaceId, e.CorrelationId, e.CausationId)).ToList();
        return new CommitTailValues(receipt, events, new ChangeRecord(commit.ChangeSchemaVersion, commit.ChangeRecordJson));
    }

    internal static ModulePlanStatus Map(CommitKind kind) => kind switch
    {
        CommitKind.Committed => ModulePlanStatus.Succeeded,
        CommitKind.Replayed => ModulePlanStatus.Replayed,
        CommitKind.ReplayedFailure => ModulePlanStatus.ReplayedFailure,
        CommitKind.DuplicateMessage => ModulePlanStatus.DuplicateMessage,
        CommitKind.ReusedIdentifier => ModulePlanStatus.ReusedIdentifier,
        CommitKind.ReceiptExpired => ModulePlanStatus.ReceiptExpired,
        CommitKind.GuardFailed => ModulePlanStatus.GuardRefused,
        _ => ModulePlanStatus.UnknownOutcome,
    };

    internal static ModulePlanStatus Map(PlanFailureKind kind) => kind switch
    {
        PlanFailureKind.Precondition => ModulePlanStatus.GuardRefused,
        PlanFailureKind.Constraint => ModulePlanStatus.ConstraintRefused,
        PlanFailureKind.UnknownOutcome => ModulePlanStatus.UnknownOutcome,
        PlanFailureKind.StaleGeneration => ModulePlanStatus.StaleGeneration,
        PlanFailureKind.Overloaded or PlanFailureKind.Unavailable or PlanFailureKind.Transport => ModulePlanStatus.Unavailable,
        _ => ModulePlanStatus.Rejected,
    };

    private static D1Scalar ToScalar(PlanValue value) => value.Kind switch
    {
        PlanValueKind.Null => D1Values.Null(),
        PlanValueKind.Int64 => D1Values.Int64(value.AsInt64()),
        PlanValueKind.Text => D1Values.Text(value.AsText()),
        PlanValueKind.Bytes => D1Values.Bytes(value.AsBytes()),
        PlanValueKind.Bool => D1Values.Bool(value.AsBool()),
        _ => throw new ArgumentOutOfRangeException(nameof(value)),
    };

    /// <summary>Only the scalar kinds the port carries come back; an unsigned or decimal column is not part of a module plan result today and is refused.</summary>
    private static PlanValue FromScalar(D1Scalar scalar)
    {
        if (D1Values.IsNull(scalar)) return PlanValue.Null;
        if (D1Values.TryGetInt64(scalar, out var integer)) return PlanValue.FromInt64(integer);
        if (D1Values.TryGetText(scalar, out var text)) return PlanValue.FromText(text);
        if (D1Values.TryGetBytes(scalar, out var bytes)) return PlanValue.FromBytes(bytes);
        if (D1Values.TryGetBool(scalar, out var flag)) return PlanValue.FromBool(flag);
        throw new FormatException("The plan returned a scalar kind the module port does not carry.");
    }
}
