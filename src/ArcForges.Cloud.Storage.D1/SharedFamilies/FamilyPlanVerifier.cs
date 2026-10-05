// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Storage.SharedFamilies;

/// <summary>
/// The structural rules of a family plan as C# enforces them when it loads the generated manifest: the same rules the generator
/// enforces, repeated here so that a stale or hand-edited generated file is refused before anything is sent (defence in depth).
/// Shared vectors (<c>Vectors/family-lock-order.json</c>) hold both implementations to the same verdicts.
/// </summary>
internal static class FamilyPlanVerifier
{
    /// <summary>
    /// Design SU-04 as a rule over the roles of one plan: every guard, then every mutation, then the one release; inside a phase by
    /// module in the SU-04 order (platform first among guards and last among mutations), then by class, then by stable key ascending,
    /// each combination at most once. One message per violation, empty when the order is valid.
    /// </summary>
    public static IReadOnlyList<string> OrderProblems(IReadOnlyList<FamilyStatementRole> roles)
    {
        ArgumentNullException.ThrowIfNull(roles);
        var problems = new List<string>();
        for (var index = 0; index < roles.Count; index++)
        {
            var role = roles[index];
            var where = "statement " + (index + 1).ToString(System.Globalization.CultureInfo.InvariantCulture) + " (" + role.Phase + " " + ModuleLockOrder.Owner(role.Module) + "." + role.Key + ")";
            if (role.Module != FamilyModule.Platform && !ModuleLockOrder.HasPosition(role.Module)) problems.Add(where + ": the module has no position in the SU-04 order");
            if (ClassRank(role) < 0) problems.Add(where + ": class " + role.Class + " does not belong to a " + role.Phase + " statement");
            if (role.Phase == FamilyPhase.Release && (index != roles.Count - 1 || role.Module != FamilyModule.Platform)) problems.Add(where + ": the release is the one platform statement at the very end");
            if (index == 0) continue;
            var previous = roles[index - 1];
            if (role.Phase < previous.Phase)
            {
                problems.Add(where + ": a " + role.Phase + " statement may not follow a " + previous.Phase + " statement (guards, then mutations, then the release)");
                continue;
            }

            if (role.Phase != previous.Phase) continue;
            var module = ModuleLockOrder.Rank(role.Module, role.Phase);
            var before = ModuleLockOrder.Rank(previous.Module, previous.Phase);
            if (module < before) problems.Add(where + ": module " + ModuleLockOrder.Owner(role.Module) + " may not follow module " + ModuleLockOrder.Owner(previous.Module) + " (SU-04 order)");
            else if (module == before)
            {
                var rank = ClassRank(role);
                var previousRank = ClassRank(previous);
                if (rank < previousRank) problems.Add(where + ": class " + role.Class + " may not follow class " + previous.Class + " within the module");
                else if (rank == previousRank)
                {
                    var order = string.CompareOrdinal(role.Key, previous.Key);
                    if (order < 0) problems.Add(where + ": stable key " + role.Key + " may not follow " + previous.Key + " (ascending within a class)");
                    else if (order == 0) problems.Add(where + ": duplicate key in the class");
                }
            }
        }

        return problems;
    }

    /// <summary>Every structural problem of <paramref name="family"/> against its registry entry; empty when the plan may run.</summary>
    public static IReadOnlyList<string> Problems(FamilyPlanDefinition family, FamilyDefinition? definition)
    {
        ArgumentNullException.ThrowIfNull(family);
        var problems = new List<string>();
        var plan = family.Plan;
        if (definition is null || !string.Equals(definition.Id, family.Family, StringComparison.Ordinal))
        {
            problems.Add("the family " + family.Family + " is not in the registry");
            return problems;
        }

        var segments = plan.Id.Split('.');
        if (segments.Length != 3 || !string.Equals(segments[0], "families", StringComparison.Ordinal) || !string.Equals(segments[1], family.Family, StringComparison.Ordinal))
            problems.Add("a family plan id is families.<family>.<name> of its own family");
        if (plan.Access != PlanAccess.Write) problems.Add("a family plan is a write plan");
        if (family.Roles.Count != plan.Statements.Count)
        {
            problems.Add("the plan has " + plan.Statements.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) + " statements for " + family.Roles.Count.ToString(System.Globalization.CultureInfo.InvariantCulture) + " roles");
            return problems;
        }

        problems.AddRange(OrderProblems(family.Roles));
        for (var index = 0; index < family.Roles.Count; index++)
        {
            var role = family.Roles[index];
            if (role.Phase == FamilyPhase.Mutation) continue;
            var parameters = plan.Statements[index].Params;
            if (parameters.Count == 0 || parameters[0] is not { Kind: PlanKind.Text, Nullable: false })
                problems.Add("statement " + (index + 1).ToString(System.Globalization.CultureInfo.InvariantCulture) + ": a guard or release statement takes the command id as its first text parameter");
        }

        var modules = family.Roles.Where(role => role.Module != FamilyModule.Platform).Select(role => role.Module).ToHashSet();
        foreach (var module in modules)
        {
            if (definition.Participants.All(participant => participant.Module != module)) problems.Add("module " + ModuleLockOrder.Owner(module) + " is not a participant of family " + family.Family);
            var own = family.Roles.Where(role => role.Module == module).ToArray();
            if (own.Any(role => role.Phase == FamilyPhase.Mutation) && own.All(role => role.Phase != FamilyPhase.Guard))
                problems.Add("module " + ModuleLockOrder.Owner(module) + " writes without a guard of its own");
        }

        foreach (var participant in definition.Participants.Where(participant => participant.Required && !modules.Contains(participant.Module)))
            problems.Add("required participant " + ModuleLockOrder.Owner(participant.Module) + " has no statement");
        if (family.Roles.All(role => role.Phase != FamilyPhase.Guard)) problems.Add("a family plan has at least one guard");
        if (family.Roles.All(role => role.Phase != FamilyPhase.Mutation)) problems.Add("a family plan has at least one mutation");
        var guardKeys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var role in family.Roles.Where(role => role.Phase == FamilyPhase.Guard))
        {
            if (!guardKeys.Add(ModuleLockOrder.Owner(role.Module) + "." + role.Key)) problems.Add("duplicate guard key " + ModuleLockOrder.Owner(role.Module) + "." + role.Key);
        }

        return problems;
    }

    private static int ClassRank(FamilyStatementRole role) => role.Phase switch
    {
        FamilyPhase.Guard => role.Class switch
        {
            FamilyClass.Authorization => 0,
            FamilyClass.Revision => 1,
            FamilyClass.Policy => 2,
            FamilyClass.Balance => 3,
            FamilyClass.Lease => 4,
            _ => -1,
        },
        FamilyPhase.Mutation => role.Class switch
        {
            FamilyClass.Bucket => 0,
            FamilyClass.Reservation => 1,
            FamilyClass.Record => 2,
            _ => -1,
        },
        FamilyPhase.Release => role.Class == FamilyClass.Release ? 0 : -1,
        _ => -1,
    };
}

/// <summary>The generated registry and plan list with the verification every use of them goes through.</summary>
internal static class FamilyCatalog
{
    /// <summary>Looks a family up in the generated registry.</summary>
    public static FamilyDefinition? Find(string family, IReadOnlyList<FamilyDefinition>? catalog = null)
    {
        foreach (var definition in catalog ?? PlanManifest.FamilyCatalog)
        {
            if (string.Equals(definition.Id, family, StringComparison.Ordinal)) return definition;
        }

        return null;
    }

    /// <summary>Verifies every generated family plan against the generated registry; the result is empty when all of them may run.</summary>
    public static IReadOnlyList<string> VerifyAll(IReadOnlyList<FamilyDefinition>? catalog = null, IReadOnlyList<FamilyPlanDefinition>? plans = null)
    {
        var problems = new List<string>();
        var registry = catalog ?? PlanManifest.FamilyCatalog;
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var definition in registry)
        {
            if (!ids.Add(definition.Id)) problems.Add("duplicate family " + definition.Id);
        }

        foreach (var family in plans ?? PlanManifest.FamilyPlans)
        {
            foreach (var problem in FamilyPlanVerifier.Problems(family, Find(family.Family, registry))) problems.Add(family.Plan.Id + ": " + problem);
        }

        return problems;
    }
}
