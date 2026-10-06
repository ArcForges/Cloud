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
    private readonly object issuer = new();

    public IModuleFamilyPort For(ModuleDescriptor module) => new ModuleFamilyPort(module, executor, recoveryGeneration, time, issuer);
}

internal sealed class ModuleFamilyPort : IModuleFamilyPort
{
    private readonly ModuleDescriptor module;
    private readonly ulong generation;
    private readonly CommandReceiptStore receipts;
    private readonly FamilyExecutor families;
    private readonly object issuer;
    private readonly IPlanExecutor executor;

    public ModuleFamilyPort(ModuleDescriptor module, IPlanExecutor executor, ulong generation, TimeProvider time, object issuer)
    {
        this.module = module ?? throw new ArgumentNullException(nameof(module));
        this.generation = generation;
        receipts = new CommandReceiptStore(executor, generation, time);
        families = new FamilyExecutor(executor);
        this.issuer = issuer;
        this.executor = executor;
    }

    private sealed record AuthorizedContributions(object Issuer, string FamilyId, string PlanId, IReadOnlyList<FamilyContribution> Items) : IModuleFamilyContributionSet;

    public async Task<ModulePlanOutcome> ReadAsync(string familyId, ModulePlanRead read, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(read);
        Participant(familyId);
        if (module.PlanOwner != "identity" || familyId != "account-enrollment"
            || read.PlanId is not ("workspace.workspace-load" or "workspace.workspace-by-owner"))
            throw new InvalidOperationException("This participant-owned read is not admitted for the calling module and family.");
        var plan = PlanManifest.All.Single(item => item.Id == read.PlanId);
        if (plan.Access != PlanAccess.Read || plan.Statements.Count != 1)
            throw new InvalidOperationException("The admitted participant plan must be a single-statement read.");
        try
        {
            var call = PlanCall.New(plan, read.OwnerScope, generation, [[.. read.Arguments.Select(Scalar)]]);
            PlanArguments.Validate(call);
            var result = await executor.ExecuteAsync(call, cancellationToken).ConfigureAwait(false);
            return new ModulePlanOutcome(ModulePlanStatus.Succeeded, [.. result.Rows.Select(row => (IReadOnlyList<PlanValue>)[.. row.Select(Value)])]);
        }
        catch (PlanFailureException failure)
        {
            return ModulePlanOutcome.Of(ModulePlanPort.Map(failure.Kind));
        }
        catch (FormatException)
        {
            return ModulePlanOutcome.Of(ModulePlanStatus.Rejected);
        }
    }

    public IModuleFamilyContributionSet Contribute(string familyId, string planId, IReadOnlyList<ModuleFamilyContribution> contributions)
    {
        var definition = Definition(familyId, planId);
        return new AuthorizedContributions(issuer, familyId, planId, Own(definition, contributions));
    }

    public async Task<ModulePlanOutcome> InspectAsync(string familyId, ModuleCommandIdentity identity, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
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
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(write);
        var definition = Definition(write.FamilyId, write.PlanId);
        var unit = FamilyUnitOfWork.Begin(definition, write.Commit.CommandId, write.OwnerScope, generation);
        foreach (var contribution in Own(definition, write.Contributions)) unit.Contribute(contribution);
        foreach (var bundle in write.Participants ?? [])
        {
            if (bundle is not AuthorizedContributions authorized || !ReferenceEquals(authorized.Issuer, issuer)
                || authorized.FamilyId != write.FamilyId || authorized.PlanId != write.PlanId)
                throw new InvalidOperationException("The participant contribution capability is not valid for this factory and plan.");
            foreach (var contribution in authorized.Items) unit.Contribute(contribution);
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

    private FamilyPlanDefinition Definition(string familyId, string planId)
    {
        Participant(familyId);
        return PlanManifest.FamilyPlans.SingleOrDefault(plan => plan.Plan.Id == planId && plan.Family == familyId)
            ?? throw new InvalidOperationException("The family plan is not registered.");
    }

    private IReadOnlyList<FamilyContribution> Own(FamilyPlanDefinition definition, IReadOnlyList<ModuleFamilyContribution> contributions)
    {
        ArgumentNullException.ThrowIfNull(contributions);
        var participant = Participant(definition.Family);
        var output = new List<FamilyContribution>();
        var keys = new HashSet<(FamilyModule, FamilyClass, string)>();
        foreach (var contribution in contributions)
        {
            if (!ModuleLockOrder.TryFromOwner(contribution.Owner, out var owner)
                || (owner != participant && !(participant == FamilyModule.Identity && definition.Family == "account-enrollment"
                    && definition.Plan.Id == "families.account-enrollment.create-user" && owner == FamilyModule.Workspace)))
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
            var roleIndex = -1;
            for (var index = 0; index < definition.Roles.Count; index++)
                if (definition.Roles[index] is { } role && role.Module == owner && role.Class == kind && role.Key == contribution.Key && role.Phase != FamilyPhase.Release) roleIndex = index;
            if (roleIndex < 0 || !keys.Add((owner, kind, contribution.Key))) throw new InvalidOperationException("The owner contribution is absent or duplicated in this plan.");
            var values = contribution.Arguments.Select(Scalar).ToArray();
            var statement = definition.Plan.Statements[roleIndex];
            var expected = statement.Params.Count - (definition.Roles[roleIndex].Phase == FamilyPhase.Guard ? 1 : 0);
            if (expected != values.Length) throw new InvalidOperationException("The owner contribution has the wrong argument count.");
            output.Add(new FamilyContribution(owner, kind, contribution.Key, values));
        }
        return output;
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

    private static PlanValue Value(D1Scalar scalar)
    {
        if (D1Values.IsNull(scalar)) return PlanValue.Null;
        if (D1Values.TryGetInt64(scalar, out var integer)) return PlanValue.FromInt64(integer);
        if (D1Values.TryGetText(scalar, out var text)) return PlanValue.FromText(text);
        if (D1Values.TryGetBytes(scalar, out var bytes)) return PlanValue.FromBytes(bytes);
        if (D1Values.TryGetBool(scalar, out var flag)) return PlanValue.FromBool(flag);
        throw new FormatException("The participant plan returned an unsupported scalar kind.");
    }
}
