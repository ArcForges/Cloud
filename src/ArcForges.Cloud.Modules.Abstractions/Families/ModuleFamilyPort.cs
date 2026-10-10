// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

/// <summary>
/// The class of one statement of a shared family plan (Design SU-04): the guard classes authorization, revision, policy, balance and lease,
/// and the mutation classes bucket, reservation and record. The generated release of the guard rows is never contributed by a module.
/// </summary>
public enum FamilyStatementClass
{
    Authorization,
    Revision,
    Policy,
    Balance,
    Lease,
    Bucket,
    Reservation,
    Record,
}

/// <summary>
/// The typed arguments of one statement of a family plan, named by the owner of the statement (the plan owner of a module, for example
/// <c>identity</c>), its class and its stable key (Design SU-02). A guard's arguments are its key values followed by its expected values;
/// the command identity in front of every guard is supplied by the family engine, never by a module. It names no SQL and no table.
/// </summary>
public sealed record FamilyStatement(string Module, FamilyStatementClass Class, string Key, IReadOnlyList<PlanValue> Arguments);

/// <summary>
/// One call of a registered shared transaction family: the family, the named family plan, the owner scope of the batch, the calling
/// module's statement contributions (in any order: the plan decides the order) and the commit tail. <see cref="Commit"/> supplies the
/// receipt, the outbox events and the change record that the plan's platform statements write, and the command whose guard rows the
/// plan releases.
/// </summary>
public sealed record ModuleFamilyCall(string Family, string PlanId, string OwnerScope, IReadOnlyList<FamilyStatement> Statements, ModuleCommit Commit);

/// <summary>
/// The one way a module runs a shared family plan (Design SU-01 to SU-04): its own statement contributions and the commit tail in, a typed
/// status of the plan-execution vocabulary out (<see cref="ModulePlanStatus"/>; <see cref="ModulePlanOutcome.StoredResultJson"/> carries the
/// stored original result of a replay). The implementation refuses an unknown family, a plan of another family, a caller that is not a
/// participant and a statement the caller may not contribute, before anything is sent, and executes the batch on the existing
/// shared-family engine, so there is no second execution path.
/// </summary>
public interface IModuleFamilyPort
{
    Task<ModulePlanOutcome> ExecuteAsync(ModuleFamilyCall call, CancellationToken cancellationToken);
}

/// <summary>Creates the family port of one module. The composition binds it once; a module asks for its own port and no other.</summary>
public interface IModuleFamilyPortFactory
{
    IModuleFamilyPort For(ModuleDescriptor module);
}
