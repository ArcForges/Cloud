// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage.Archive;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Storage.Outbox;
using ArcForges.Cloud.Storage.Receipts;
using ArcForges.Cloud.Storage.SharedFamilies;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.FamilyBinding;

/// <summary>
/// Creates the family port of one module over the signed Worker executor. This is the one place the Abstractions family port meets the
/// shared-family engine of CLOUD.06: it looks the family up in the generated registry, checks the caller and every contribution against
/// <see cref="FamilyContributionPolicy"/>, builds the platform statements from the commit tail, seals one unit of work and executes it with
/// <see cref="FamilyExecutor"/> (one named plan call, one D1 batch), then reconciles every non-success with the command receipt exactly as the
/// module plan port does. It sends no SQL text and names no table.
/// </summary>
internal sealed class ModuleFamilyPortFactory : IModuleFamilyPortFactory
{
    private readonly IPlanExecutor executor;
    private readonly ulong recoveryGeneration;
    private readonly TimeProvider time;
    private readonly IReadOnlyList<FamilyDefinition> catalog;
    private readonly IReadOnlyList<FamilyPlanDefinition> plans;

    public ModuleFamilyPortFactory(IPlanExecutor executor, ulong recoveryGeneration, TimeProvider time)
        : this(executor, recoveryGeneration, time, PlanManifest.FamilyCatalog, PlanManifest.FamilyPlans)
    {
    }

    /// <summary>The registry and the plans are parameters so that a test can bind a fixture family; the production composition always passes the generated manifest.</summary>
    internal ModuleFamilyPortFactory(IPlanExecutor executor, ulong recoveryGeneration, TimeProvider time, IReadOnlyList<FamilyDefinition> catalog, IReadOnlyList<FamilyPlanDefinition> plans)
    {
        this.executor = executor ?? throw new ArgumentNullException(nameof(executor));
        this.recoveryGeneration = recoveryGeneration;
        this.time = time ?? throw new ArgumentNullException(nameof(time));
        this.catalog = catalog ?? throw new ArgumentNullException(nameof(catalog));
        this.plans = plans ?? throw new ArgumentNullException(nameof(plans));
    }

    public IModuleFamilyPort For(ModuleDescriptor module)
    {
        ArgumentNullException.ThrowIfNull(module);
        return new ModuleFamilyPort(module, executor, recoveryGeneration, time, catalog, plans);
    }
}

/// <summary>
/// The family port of one module. A caller defect (an unknown family, a plan of another family, a caller that is not a participant, a
/// statement of another module or of the platform, an unknown, duplicated or missing statement, a plan whose platform statements do not
/// fit the commit tail) throws <see cref="InvalidOperationException"/> and a malformed commit throws <see cref="ArgumentException"/>, as the
/// module plan port does for a foreign plan; arguments of the wrong kind or count are <see cref="ModulePlanStatus.Rejected"/>. None of them
/// reaches the executor.
/// </summary>
internal sealed class ModuleFamilyPort : IModuleFamilyPort
{
    private readonly ModuleDescriptor module;
    private readonly IPlanExecutor executor;
    private readonly ulong recoveryGeneration;
    private readonly IReadOnlyList<FamilyDefinition> catalog;
    private readonly IReadOnlyList<FamilyPlanDefinition> plans;
    private readonly CommandReceiptStore receipts;

    public ModuleFamilyPort(ModuleDescriptor module, IPlanExecutor executor, ulong recoveryGeneration, TimeProvider time, IReadOnlyList<FamilyDefinition> catalog, IReadOnlyList<FamilyPlanDefinition> plans)
    {
        this.module = module;
        this.executor = executor;
        this.recoveryGeneration = recoveryGeneration;
        this.catalog = catalog;
        this.plans = plans;
        receipts = new CommandReceiptStore(executor, recoveryGeneration, time);
    }

    public async Task<ModulePlanOutcome> ExecuteAsync(ModuleFamilyCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(call);
        ArgumentNullException.ThrowIfNull(call.Statements);
        ArgumentNullException.ThrowIfNull(call.Commit);
        ArgumentException.ThrowIfNullOrEmpty(call.Family);
        ArgumentException.ThrowIfNullOrEmpty(call.PlanId);
        ArgumentNullException.ThrowIfNull(call.OwnerScope);

        var definition = FamilyCatalog.Find(call.Family, catalog) ?? throw Refused("the family '" + call.Family + "' is not in the family registry");
        var family = FindPlan(call.PlanId, call.Family) ?? throw Refused("the plan '" + call.PlanId + "' is not a plan of the family '" + call.Family + "'");
        if (!FamilyContributionPolicy.TryResolveCaller(module, definition, out var caller)) throw Refused("the " + module.Name + " module is not a participant of the family '" + call.Family + "'");

        var values = ToTail(call.Commit);
        var tail = CommitTail.Arguments(call.OwnerScope, values);
        FamilyUnitOfWork unit;
        try
        {
            unit = FamilyUnitOfWork.Begin(family, values.Receipt.Identity.CommandId, call.OwnerScope, recoveryGeneration, definition);
            foreach (var statement in call.Statements) unit.Contribute(Contribution(call.Family, caller, statement));
            ContributeTail(unit, family, values.Events.Count, tail);
            unit.Seal();
        }
        catch (FamilyViolationException violation) when (violation.Violation == FamilyViolation.InvalidArguments)
        {
            return ModulePlanOutcome.Of(ModulePlanStatus.Rejected);
        }
        catch (FamilyViolationException violation)
        {
            throw new InvalidOperationException("The family call was refused: " + violation.Violation + " (" + violation.Detail + ").", violation);
        }

        var result = await new FamilyExecutor(executor).ExecuteAsync(unit, cancellationToken).ConfigureAwait(false);
        if (result.Committed) return ModulePlanOutcome.Of(ModulePlanStatus.Succeeded);
        return result.Failure switch
        {
            PlanFailureKind.Precondition or PlanFailureKind.Constraint => await AfterRefusalAsync(values.Receipt.Identity, result.Failure.Value, cancellationToken).ConfigureAwait(false),
            PlanFailureKind.UnknownOutcome => await AfterUnknownAsync(values.Receipt.Identity, cancellationToken).ConfigureAwait(false),
            { } kind => ModulePlanOutcome.Of(ModulePlanPort.Map(kind)),
            null => ModulePlanOutcome.Of(ModulePlanStatus.Rejected),
        };
    }

    private FamilyPlanDefinition? FindPlan(string planId, string family)
    {
        foreach (var candidate in plans)
        {
            if (string.Equals(candidate.Plan.Id, planId, StringComparison.Ordinal) && string.Equals(candidate.Family, family, StringComparison.Ordinal)) return candidate;
        }

        return null;
    }

    /// <summary>One module contribution: an owner of the SU-04 order, never the platform, and the caller's own unless the closed exception list allows it.</summary>
    private static FamilyContribution Contribution(string family, FamilyModule caller, FamilyStatement statement)
    {
        ArgumentNullException.ThrowIfNull(statement);
        ArgumentNullException.ThrowIfNull(statement.Module);
        ArgumentNullException.ThrowIfNull(statement.Key);
        ArgumentNullException.ThrowIfNull(statement.Arguments);
        if (!ModuleLockOrder.TryFromOwner(statement.Module, out var owner)) throw Refused("'" + statement.Module + "' is not a module of the SU-04 order");
        if (owner == FamilyModule.Platform) throw Refused("a module never contributes a platform statement; the commit tail supplies them");
        if (!FamilyContributionPolicy.MayContribute(family, caller, owner))
            throw Refused("the " + ModuleLockOrder.Owner(caller) + " module may not contribute the " + statement.Module + "." + statement.Key + " statement");
        if (!Enum.IsDefined(statement.Class)) throw new ArgumentOutOfRangeException(nameof(statement), "Unknown statement class.");
        return new FamilyContribution(owner, ToClass(statement.Class), statement.Key, [.. statement.Arguments.Select(ToScalar)]);
    }

    /// <summary>
    /// Binds the commit tail, in order, onto the plan's platform mutation statements. Their number and parameter kinds must be the canonical
    /// tail of a commit with this many outbox events, and the plan must end with the generated release, which the unit of work fills.
    /// </summary>
    private static void ContributeTail(FamilyUnitOfWork unit, FamilyPlanDefinition family, int events, D1Scalar[][] tail)
    {
        var roles = new List<int>();
        for (var index = 0; index < family.Roles.Count; index++)
        {
            if (family.Roles[index] is { Module: FamilyModule.Platform, Phase: FamilyPhase.Mutation }) roles.Add(index);
        }

        var kinds = CommitTail.Kinds(events, inbox: false);
        if (roles.Count != kinds.Count || roles.Count != tail.Length)
            throw Refused("the platform statements of the plan '" + family.Plan.Id + "' do not fit a commit with " + events.ToString(System.Globalization.CultureInfo.InvariantCulture) + " outbox events");
        if (family.Roles.Count == 0 || family.Roles[^1].Phase != FamilyPhase.Release) throw Refused("the plan '" + family.Plan.Id + "' does not end with the guard release");
        var platform = unit.For(FamilyModule.Platform);
        for (var position = 0; position < roles.Count; position++)
        {
            var role = family.Roles[roles[position]];
            if (!SameKinds(family.Plan.Statements[roles[position]].Params, kinds[position].Params))
                throw Refused("the platform statement " + role.Key + " of the plan '" + family.Plan.Id + "' is not the canonical " + kinds[position].Role + " statement");
            platform.Mutation(role.Class, role.Key, tail[position]);
        }
    }

    /// <summary>The batch rolled back as a whole: a false guard or a refused constraint, or a duplicate of a command that already committed.</summary>
    private async Task<ModulePlanOutcome> AfterRefusalAsync(CommandIdentity identity, PlanFailureKind failure, CancellationToken cancellationToken)
    {
        ReplayDecision decision;
        try
        {
            decision = await receipts.ClassifyAsync(identity, cancellationToken).ConfigureAwait(false);
        }
        catch (PlanFailureException exception)
        {
            // Nothing was committed by this call; whether the command committed earlier is not known yet, so the caller retries the same command.
            return ModulePlanOutcome.Of(ModulePlanPort.Map(exception.Kind));
        }

        if (decision.Kind == ReplayKind.NotSeen) return ModulePlanOutcome.Of(failure == PlanFailureKind.Precondition ? ModulePlanStatus.GuardRefused : ModulePlanStatus.ConstraintRefused);
        return FromReplay(decision, committedByThisCall: false);
    }

    /// <summary>The batch may have committed: only the receipt can tell, and a failed receipt read leaves the outcome unknown.</summary>
    private async Task<ModulePlanOutcome> AfterUnknownAsync(CommandIdentity identity, CancellationToken cancellationToken)
    {
        ReplayDecision decision;
        try
        {
            decision = await receipts.ClassifyAsync(identity, cancellationToken).ConfigureAwait(false);
        }
        catch (PlanFailureException)
        {
            return ModulePlanOutcome.Of(ModulePlanStatus.UnknownOutcome);
        }

        return decision.Kind == ReplayKind.NotSeen ? ModulePlanOutcome.Of(ModulePlanStatus.UnknownOutcome) : FromReplay(decision, committedByThisCall: true);
    }

    private static ModulePlanOutcome FromReplay(ReplayDecision decision, bool committedByThisCall) => decision.Kind switch
    {
        // After an unknown outcome the receipt is this call's own commit; after a refused batch it is an earlier one.
        ReplayKind.Replay => new ModulePlanOutcome(committedByThisCall ? ModulePlanStatus.Succeeded : ModulePlanStatus.Replayed, [], decision.Stored?.ResultPayloadJson),
        ReplayKind.ReplayOfFailure => new ModulePlanOutcome(ModulePlanStatus.ReplayedFailure, [], decision.Stored?.ResultPayloadJson),
        ReplayKind.ReusedIdentifier => ModulePlanOutcome.Of(ModulePlanStatus.ReusedIdentifier),
        ReplayKind.Expired => ModulePlanOutcome.Of(ModulePlanStatus.ReceiptExpired),
        _ => ModulePlanOutcome.Of(ModulePlanStatus.UnknownOutcome),
    };

    private static InvalidOperationException Refused(string reason) => new("The family call was refused: " + reason + ".");

    private static FamilyClass ToClass(FamilyStatementClass value) => value switch
    {
        FamilyStatementClass.Authorization => FamilyClass.Authorization,
        FamilyStatementClass.Revision => FamilyClass.Revision,
        FamilyStatementClass.Policy => FamilyClass.Policy,
        FamilyStatementClass.Balance => FamilyClass.Balance,
        FamilyStatementClass.Lease => FamilyClass.Lease,
        FamilyStatementClass.Bucket => FamilyClass.Bucket,
        FamilyStatementClass.Reservation => FamilyClass.Reservation,
        FamilyStatementClass.Record => FamilyClass.Record,
        _ => throw new ArgumentOutOfRangeException(nameof(value)),
    };

    /// <summary>The same conversion as the module plan port: the commit tail values that the plan's platform statements store.</summary>
    private static CommitTailValues ToTail(ModuleCommit commit)
    {
        ArgumentNullException.ThrowIfNull(commit.Events);
        var identity = new CommandIdentity(commit.CommandId, commit.WorkspaceId, commit.ActorRef, commit.Operation, commit.RequestHash);
        var receipt = new CommandReceipt(identity, commit.ResultPayloadJson, commit.ResultRevision, commit.CreatedAtMicros, commit.ExpiresAtMicros);
        var events = commit.Events.Select(e => new OutboxEvent(e.OutboxId, e.AggregateKind, e.AggregateId, e.AggregateRevision, e.EventType, e.PayloadJson, e.WorkspaceId, e.CorrelationId, e.CausationId)).ToList();
        return new CommitTailValues(receipt, events, new ChangeRecord(commit.ChangeSchemaVersion, commit.ChangeRecordJson));
    }

    private static D1Scalar ToScalar(PlanValue value) => value.Kind switch
    {
        PlanValueKind.Null => D1Values.Null(),
        PlanValueKind.Int64 => D1Values.Int64(value.AsInt64()),
        PlanValueKind.Text => D1Values.Text(value.AsText()),
        PlanValueKind.Bytes => D1Values.Bytes(value.AsBytes()),
        PlanValueKind.Bool => D1Values.Bool(value.AsBool()),
        _ => throw new ArgumentOutOfRangeException(nameof(value)),
    };

    private static bool SameKinds(IReadOnlyList<PlanParam> left, IReadOnlyList<PlanParam> right)
    {
        if (left.Count != right.Count) return false;
        for (var index = 0; index < left.Count; index++)
        {
            if (left[index] != right[index]) return false;
        }

        return true;
    }
}
