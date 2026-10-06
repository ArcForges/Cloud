// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

/// <summary>One module-owned statement of a registered shared transaction family. Guard arguments omit the command id, supplied by the coordinator.</summary>
public sealed record ModuleFamilyContribution(string Owner, string Class, string Key, IReadOnlyList<PlanValue> Arguments);

/// <summary>A complete family transaction: registered plan, typed owner contributions and the shared commit tail. No SQL or storage types cross this boundary.</summary>
public sealed record ModuleFamilyWrite(string FamilyId, string PlanId, string OwnerScope, IReadOnlyList<ModuleFamilyContribution> Contributions, ModuleCommit Commit,
    IReadOnlyList<IModuleFamilyContributionSet>? Participants = null);

/// <summary>Opaque owner-bound contributions. Only the storage adapter's issuing factory can create a set it will accept; a caller cannot assert a foreign owner.</summary>
public interface IModuleFamilyContributionSet;

/// <summary>The stable command identity used to check a receipt before deciding whether an enrollment creates anything.</summary>
public sealed record ModuleCommandIdentity(Guid CommandId, Guid? WorkspaceId, string ActorRef, string Operation, string RequestHash);

/// <summary>A module's capability to execute registered families. Foreign contributions and non-participants are refused before execution.</summary>
public interface IModuleFamilyPort
{
    /// <summary>Executes an explicitly admitted participant-owned read. The temporary enrollment ownership lookup admits exactly two named Workspace reads to Identity; all other foreign reads are refused.</summary>
    Task<ModulePlanOutcome> ReadAsync(string familyId, ModulePlanRead read, CancellationToken cancellationToken);

    /// <summary>Seals this module's contributions for one exact registered family plan. A coordinator combines the resulting capabilities without seeing or changing their content.</summary>
    IModuleFamilyContributionSet Contribute(string familyId, string planId, IReadOnlyList<ModuleFamilyContribution> contributions);

    /// <summary>Succeeded means no receipt was seen; every other status follows the same vocabulary as plan execution. A replay returns its stored result.</summary>
    Task<ModulePlanOutcome> InspectAsync(string familyId, ModuleCommandIdentity identity, CancellationToken cancellationToken);

    Task<ModulePlanOutcome> WriteAsync(ModuleFamilyWrite write, CancellationToken cancellationToken);
}

/// <summary>Creates a family capability for one module descriptor; the host binds this once.</summary>
public interface IModuleFamilyPortFactory
{
    IModuleFamilyPort For(ModuleDescriptor module);
}
