// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage.SharedFamilies;

namespace ArcForges.Cloud.Storage.FamilyBinding;

/// <summary>One reviewed exception to the rule that a module contributes only the statements of its own module.</summary>
/// <param name="Family">The registered family the exception holds in, and no other.</param>
/// <param name="Caller">The module that calls the family port.</param>
/// <param name="Statement">The module whose statements the caller may also contribute.</param>
/// <param name="Reason">The recorded reason; a new row is a design change through the Architecture Owner.</param>
internal sealed record FamilyContributionException(string Family, FamilyModule Caller, FamilyModule Statement, string Reason);

/// <summary>
/// Who may contribute what to a shared family batch (Design SU-02: each module contributes only its own statements). A caller must be a
/// participant of the family in the closed registry, a statement must belong to the caller, and the platform statements (receipt, outbox,
/// change archive, release) are built by the adapter from the commit tail, never by a module. The only exception is the closed list below.
/// </summary>
internal static class FamilyContributionPolicy
{
    /// <summary>The account-enrollment family identifier of <c>storage/plans/families.json</c>.</summary>
    public const string AccountEnrollment = "account-enrollment";

    /// <summary>
    /// The closed exception list: exactly one row. The enrollment initiator (Identity) also contributes the <c>workspace</c> statements of
    /// <c>account-enrollment</c>, because the single-owner workspace provisioning is carried by the Identity core of CLOUD.11 and the
    /// Workspace boundary has no persistence of its own (reviewed CLOUD.72 planning decision, 2026-10-05).
    /// </summary>
    public static IReadOnlyList<FamilyContributionException> Exceptions { get; } =
    [
        new(AccountEnrollment, FamilyModule.Identity, FamilyModule.Workspace,
            "the enrollment initiator provisions the owner's default workspace in the same batch; the Workspace boundary has no persistence of its own"),
    ];

    /// <summary>
    /// The family module of the calling module, when it is a participant of <paramref name="definition"/>. A module without a position in the
    /// SU-04 order (support, trustsafety), the platform owner and a non-participant are not resolved.
    /// </summary>
    public static bool TryResolveCaller(ModuleDescriptor module, FamilyDefinition definition, out FamilyModule caller)
    {
        ArgumentNullException.ThrowIfNull(module);
        ArgumentNullException.ThrowIfNull(definition);
        if (!ModuleLockOrder.TryFromOwner(module.PlanOwner, out caller) || caller == FamilyModule.Platform) return false;
        foreach (var participant in definition.Participants)
        {
            if (participant.Module == caller) return true;
        }

        return false;
    }

    /// <summary>Whether <paramref name="caller"/> may contribute a statement of <paramref name="statement"/> to <paramref name="family"/>.</summary>
    public static bool MayContribute(string family, FamilyModule caller, FamilyModule statement)
    {
        ArgumentNullException.ThrowIfNull(family);
        if (caller == FamilyModule.Platform || statement == FamilyModule.Platform) return false;
        if (caller == statement) return true;
        foreach (var row in Exceptions)
        {
            if (string.Equals(row.Family, family, StringComparison.Ordinal) && row.Caller == caller && row.Statement == statement) return true;
        }

        return false;
    }
}
