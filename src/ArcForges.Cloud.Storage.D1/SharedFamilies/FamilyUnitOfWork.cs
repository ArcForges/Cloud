// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.SharedFamilies;

/// <summary>
/// One immutable commit plan being assembled for a shared family (Design SU-02): every module contributes the typed arguments of its
/// own statements, and <see cref="Seal"/> orders them into the arguments of one named plan call. The order is the generated plan's
/// order, which the generator and <see cref="FamilyPlanVerifier"/> hold to the SU-04 rule, so no caller can reorder statements.
/// The command identity is supplied here to every guard and to the release, so all guard rows of the batch share one command and
/// the release deletes exactly them. A unit of work is assembled by one caller at a time and is not thread-safe.
/// </summary>
internal sealed class FamilyUnitOfWork
{
    private readonly Dictionary<(FamilyModule Module, FamilyClass Class, string Key), FamilyContribution> contributions = [];
    private readonly string ownerScope;
    private readonly ulong recoveryGeneration;

    private FamilyUnitOfWork(FamilyPlanDefinition family, Guid commandId, string ownerScope, ulong recoveryGeneration)
    {
        Family = family;
        CommandId = commandId;
        this.ownerScope = ownerScope;
        this.recoveryGeneration = recoveryGeneration;
    }

    public FamilyPlanDefinition Family { get; }

    /// <summary>The stable identity of the command; a reread under the same command keeps it (Design section 4).</summary>
    public Guid CommandId { get; }

    /// <summary>Starts a unit of work. A plan that breaks a structural rule is refused here, before any contribution.</summary>
    public static FamilyUnitOfWork Begin(FamilyPlanDefinition family, Guid commandId, string ownerScope, ulong recoveryGeneration, FamilyDefinition? definition = null)
    {
        ArgumentNullException.ThrowIfNull(family);
        ArgumentNullException.ThrowIfNull(ownerScope);
        var problems = FamilyPlanVerifier.Problems(family, definition ?? FamilyCatalog.Find(family.Family));
        if (problems.Count > 0) throw new FamilyViolationException(FamilyViolation.PlanRule, problems[0]);
        if (commandId == Guid.Empty || ownerScope.Length is 0 or > 256) throw new FamilyViolationException(FamilyViolation.InvalidArguments, "command identity or owner scope");
        return new FamilyUnitOfWork(family, commandId, ownerScope, recoveryGeneration);
    }

    /// <summary>
    /// The handle through which one module contributes. It stamps the module on everything it adds, so a module that is handed only its own
    /// contributor can never reach a statement the plan gave to another module (Design SU-02: each module contributes only its own statements).
    /// </summary>
    public FamilyContributor For(FamilyModule module) => new(this, module);

    /// <summary>Adds the arguments of one statement. The statement must exist in the plan under the contributing module, once.</summary>
    public FamilyUnitOfWork Contribute(FamilyContribution contribution)
    {
        ArgumentNullException.ThrowIfNull(contribution);
        var found = false;
        foreach (var role in Family.Roles)
        {
            if (role.Phase != FamilyPhase.Release && role.Module == contribution.Module && role.Class == contribution.Class && string.Equals(role.Key, contribution.Key, StringComparison.Ordinal))
            {
                found = true;
                break;
            }
        }

        if (!found) throw new FamilyViolationException(FamilyViolation.NotInPlan, ModuleLockOrder.Owner(contribution.Module) + "." + contribution.Key);
        if (!contributions.TryAdd((contribution.Module, contribution.Class, contribution.Key), contribution))
            throw new FamilyViolationException(FamilyViolation.DuplicateContribution, ModuleLockOrder.Owner(contribution.Module) + "." + contribution.Key);
        return this;
    }

    /// <summary>
    /// Builds the plan call: the arguments in plan order, the command identity in front of every guard and the release, the type and scope
    /// checks of the bridge applied before anything is sent. Every statement must have its contribution.
    /// </summary>
    public PlanCall Seal()
    {
        var command = D1Values.Text(CommandId.ToString("D"));
        var arguments = new D1Scalar[Family.Roles.Count][];
        for (var index = 0; index < arguments.Length; index++)
        {
            var role = Family.Roles[index];
            if (role.Phase == FamilyPhase.Release)
            {
                arguments[index] = [command];
                continue;
            }

            if (!contributions.TryGetValue((role.Module, role.Class, role.Key), out var contribution))
                throw new FamilyViolationException(FamilyViolation.MissingContribution, ModuleLockOrder.Owner(role.Module) + "." + role.Key);
            arguments[index] = role.Phase == FamilyPhase.Guard ? [command, .. contribution.Arguments] : [.. contribution.Arguments];
        }

        var call = PlanCall.New(Family.Plan, ownerScope, recoveryGeneration, arguments);
        try
        {
            PlanArguments.Validate(call);
        }
        catch (PlanFailureException exception) when (exception.Kind == PlanFailureKind.InvalidPlan)
        {
            throw new FamilyViolationException(FamilyViolation.InvalidArguments, Family.Plan.Id);
        }

        return call;
    }
}

/// <summary>
/// One module's view of a unit of work. Every method adds the arguments of one of that module's own statements, named by class and stable key,
/// using the same typed primitives as <see cref="FamilyGuards"/> and returning the contributor for chaining.
/// </summary>
internal sealed class FamilyContributor
{
    private readonly FamilyUnitOfWork unit;

    internal FamilyContributor(FamilyUnitOfWork unit, FamilyModule module)
    {
        this.unit = unit;
        Module = module;
    }

    public FamilyModule Module { get; }

    public FamilyContributor Authorization(string key, IReadOnlyList<D1Scalar> by, IReadOnlyList<D1Scalar> match, long? freshAfterMicros = null) => Add(FamilyGuards.Authorization(Module, key, by, match, freshAfterMicros));

    public FamilyContributor Policy(string key, IReadOnlyList<D1Scalar> by, IReadOnlyList<D1Scalar> match, long? freshAfterMicros = null) => Add(FamilyGuards.Policy(Module, key, by, match, freshAfterMicros));

    public FamilyContributor Revision(string key, IReadOnlyList<D1Scalar> by, long expectedRevision) => Add(FamilyGuards.Revision(Module, key, by, expectedRevision));

    public FamilyContributor Balance(string key, IReadOnlyList<D1Scalar> by, long expectedRevision, IReadOnlyList<D1Scalar> exact) => Add(FamilyGuards.Balance(Module, key, by, expectedRevision, exact));

    public FamilyContributor Lease(string key, IReadOnlyList<D1Scalar> by, string holder, long fence, long nowMicros) => Add(FamilyGuards.Lease(Module, key, by, holder, fence, nowMicros));

    public FamilyContributor Mutation(FamilyClass @class, string key, IReadOnlyList<D1Scalar> arguments) => Add(FamilyGuards.Mutation(Module, @class, key, arguments));

    private FamilyContributor Add(FamilyContribution contribution)
    {
        unit.Contribute(contribution);
        return this;
    }
}

/// <summary>Stable key order for a module that fans one guard or mutation out over several rows (SU-04: within a module, sorted stable keys).</summary>
internal static class FamilyKeyOrder
{
    /// <summary>The keys in ascending ordinal order; a duplicate key is refused because it would guard or write one row twice.</summary>
    public static string[] Ascending(IEnumerable<string> keys)
    {
        ArgumentNullException.ThrowIfNull(keys);
        var sorted = keys.ToArray();
        Array.Sort(sorted, StringComparer.Ordinal);
        for (var index = 1; index < sorted.Length; index++)
        {
            if (string.Equals(sorted[index], sorted[index - 1], StringComparison.Ordinal)) throw new FamilyViolationException(FamilyViolation.InvalidArguments, "duplicate stable key");
        }

        return sorted;
    }
}
