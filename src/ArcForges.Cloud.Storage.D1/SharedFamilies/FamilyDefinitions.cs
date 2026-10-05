// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Storage.SharedFamilies;

/// <summary>One participant of a family in the closed registry <c>storage/plans/families.json</c> (Design SU-01).</summary>
/// <param name="Module">The participating module.</param>
/// <param name="Required">Whether every plan of the family has a statement of the module; a conditional participant states <paramref name="When"/>.</param>
/// <param name="When">The stated condition of a conditional participant, such as "when quota changes".</param>
internal sealed record FamilyParticipant(FamilyModule Module, bool Required, string? When);

/// <summary>A shared transaction family and its closed participant list. Adding a family or a participant is a design change through the Architecture Owner.</summary>
internal sealed record FamilyDefinition(string Id, string Title, string Source, IReadOnlyList<FamilyParticipant> Participants);

/// <summary>The role of one statement of a family plan: the module that owns every table it names, its phase, class and stable key.</summary>
internal sealed record FamilyStatementRole(FamilyModule Module, FamilyPhase Phase, FamilyClass Class, string Key);

/// <summary>
/// A generated family plan: the named plan the Worker executes and, statement by statement, the role each statement plays in the
/// guarded batch. The roles come from the same generator pass as the SQL, so they cannot drift from it.
/// </summary>
internal sealed record FamilyPlanDefinition(PlanDefinition Plan, string Family, IReadOnlyList<FamilyStatementRole> Roles);

/// <summary>Why the engine refused a family plan or a unit of work. A refusal never carries a value, a statement or a table name.</summary>
internal enum FamilyViolation
{
    /// <summary>The generated plan breaks a structural rule (order, participants, guard coverage, shape).</summary>
    PlanRule,

    /// <summary>A contribution names a statement the plan does not have, or one that a different module owns.</summary>
    NotInPlan,

    /// <summary>The same statement was contributed twice.</summary>
    DuplicateContribution,

    /// <summary>A statement of the plan received no contribution.</summary>
    MissingContribution,

    /// <summary>The contributed arguments do not match the typed statement, or the command identity and scope are unusable.</summary>
    InvalidArguments,

    /// <summary>A reread attempt changed the command identity, which would turn a retry into a second command.</summary>
    CommandIdentityChanged,
}

internal sealed class FamilyViolationException(FamilyViolation violation, string detail) : Exception("Shared family refused: " + violation)
{
    public FamilyViolation Violation { get; } = violation;

    /// <summary>The structural fact, for example a statement position. Never a value.</summary>
    public string Detail { get; } = detail;
}
