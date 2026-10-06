// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage.Archive;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Storage.Outbox;
using ArcForges.Cloud.Storage.Receipts;
using ArcForges.Cloud.Storage.SharedFamilies;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.FamilyBinding;

internal sealed class ModuleFamilyPortFactory(IPlanExecutor executor, ulong recoveryGeneration, TimeProvider time) : IModuleFamilyPortFactory
{
    public IModuleFamilyPort For(ModuleDescriptor module) => new ModuleFamilyPort(module, executor, recoveryGeneration, time);
}

internal sealed class ModuleFamilyPort : IModuleFamilyPort
{
    private readonly ModuleDescriptor module;
    private readonly ulong generation;
    private readonly CommandReceiptStore receipts;
    private readonly FamilyExecutor families;

    public ModuleFamilyPort(ModuleDescriptor module, IPlanExecutor executor, ulong generation, TimeProvider time)
    {
        this.module = module ?? throw new ArgumentNullException(nameof(module));
        this.generation = generation;
        receipts = new CommandReceiptStore(executor, generation, time);
        families = new FamilyExecutor(executor);
    }

    public async Task<ModulePlanOutcome> InspectAsync(string familyId, ModuleCommandIdentity identity, CancellationToken cancellationToken)
    {
        Participant(familyId);
        ArgumentNullException.ThrowIfNull(identity);
        try
        {
            return Replay(await receipts.ClassifyAsync(new CommandIdentity(identity.CommandId, identity.WorkspaceId, identity.ActorRef, identity.Operation, identity.RequestHash), cancellationToken).ConfigureAwait(false));
        }
        catch (PlanFailureException failure)
        {
            return ModulePlanOutcome.Of(ModulePlanPort.Map(failure.Kind));
        }
    }

    public async Task<ModulePlanOutcome> WriteAsync(ModuleFamilyWrite write, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(write);
        var participant = Participant(write.FamilyId);
        var definition = PlanManifest.FamilyPlans.SingleOrDefault(plan => plan.Plan.Id == write.PlanId && plan.Family == write.FamilyId)
            ?? throw new InvalidOperationException("The family plan is not registered.");
        var unit = FamilyUnitOfWork.Begin(definition, write.Commit.CommandId, write.OwnerScope, generation);
        foreach (var contribution in write.Contributions)
        {
            if (!ModuleLockOrder.TryFromOwner(contribution.Owner, out var owner)
                || (owner != participant && !(participant == FamilyModule.Identity && write.FamilyId == "account-enrollment" && owner == FamilyModule.Workspace)))
                throw new InvalidOperationException("The family contribution is not owned by the calling module.");
            var kind = contribution.Class switch
            {
                "authorization" => FamilyClass.Authorization,
                "revision" => FamilyClass.Revision,
                "policy" => FamilyClass.Policy,
                "balance" => FamilyClass.Balance,
                "lease" => FamilyClass.Lease,
                "bucket" => FamilyClass.Bucket,
                "reservation" => FamilyClass.Reservation,
                "record" => FamilyClass.Record,
                _ => throw new InvalidOperationException("The family statement class is unknown."),
            };
            unit.Contribute(new FamilyContribution(owner, kind, contribution.Key, [.. contribution.Arguments.Select(Scalar)]));
        }

        var tail = Tail(write.Commit);
        var tailArguments = CommitTail.Arguments(write.OwnerScope, tail);
        var roles = definition.Roles.Where(role => role.Module == FamilyModule.Platform && role.Phase == FamilyPhase.Mutation).ToArray();
        if (roles.Length != tailArguments.Length) throw new InvalidOperationException("The family commit tail does not match the registered plan.");
        for (var index = 0; index < roles.Length; index++)
            unit.Contribute(new FamilyContribution(FamilyModule.Platform, roles[index].Class, roles[index].Key, tailArguments[index]));
        unit.Seal(); // Validate every contribution before any receipt read or executor call.
        try
        {
            var before = await receipts.ClassifyAsync(tail.Receipt.Identity, cancellationToken).ConfigureAwait(false);
            if (before.Kind != ReplayKind.NotSeen) return Replay(before);
            var result = await families.ExecuteAsync(unit, cancellationToken).ConfigureAwait(false);
            if (result.Committed) return ModulePlanOutcome.Of(ModulePlanStatus.Succeeded);
            if (result.Outcome is FamilyOutcome.GuardRefused or FamilyOutcome.ConstraintRefused or FamilyOutcome.UnknownOutcome)
            {
                var after = await receipts.ClassifyAsync(tail.Receipt.Identity, cancellationToken).ConfigureAwait(false);
                if (after.Kind != ReplayKind.NotSeen) return Replay(after);
            }
            return ModulePlanOutcome.Of(result.Failure is { } failure ? ModulePlanPort.Map(failure) : ModulePlanStatus.UnknownOutcome);
        }
        catch (PlanFailureException failure)
        {
            return ModulePlanOutcome.Of(ModulePlanPort.Map(failure.Kind));
        }
    }

    private FamilyModule Participant(string family)
    {
        var registered = PlanManifest.FamilyCatalog.SingleOrDefault(item => item.Id == family)
            ?? throw new InvalidOperationException("The family is not registered.");
        if (!ModuleLockOrder.TryFromOwner(module.PlanOwner, out var participant) || participant == FamilyModule.Platform
            || !registered.Participants.Any(item => item.Module == participant))
            throw new InvalidOperationException("The calling module is not a participant of the family.");
        return participant;
    }

    private static ModulePlanOutcome Replay(ReplayDecision decision) => new(decision.Kind switch
    {
        ReplayKind.NotSeen => ModulePlanStatus.Succeeded,
        ReplayKind.Replay => ModulePlanStatus.Replayed,
        ReplayKind.ReplayOfFailure => ModulePlanStatus.ReplayedFailure,
        ReplayKind.ReusedIdentifier => ModulePlanStatus.ReusedIdentifier,
        ReplayKind.Expired => ModulePlanStatus.ReceiptExpired,
        _ => ModulePlanStatus.UnknownOutcome,
    }, [], decision.Stored?.ResultPayloadJson);

    private static CommitTailValues Tail(ModuleCommit commit) => new(
        new CommandReceipt(new CommandIdentity(commit.CommandId, commit.WorkspaceId, commit.ActorRef, commit.Operation, commit.RequestHash), commit.ResultPayloadJson,
            commit.ResultRevision, commit.CreatedAtMicros, commit.ExpiresAtMicros),
        [.. commit.Events.Select(item => new OutboxEvent(item.OutboxId, item.AggregateKind, item.AggregateId, item.AggregateRevision, item.EventType, item.PayloadJson,
            item.WorkspaceId, item.CorrelationId, item.CausationId))], new ChangeRecord(commit.ChangeSchemaVersion, commit.ChangeRecordJson));

    private static D1Scalar Scalar(PlanValue value) => value.Kind switch
    {
        PlanValueKind.Null => D1Values.Null(),
        PlanValueKind.Int64 => D1Values.Int64(value.AsInt64()),
        PlanValueKind.Text => D1Values.Text(value.AsText()),
        PlanValueKind.Bytes => D1Values.Bytes(value.AsBytes()),
        PlanValueKind.Bool => D1Values.Bool(value.AsBool()),
        _ => throw new ArgumentOutOfRangeException(nameof(value)),
    };
}
