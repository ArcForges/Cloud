// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.SharedFamilies;

namespace ArcForges.Cloud.Tests.Families;

/// <summary>
/// Builds calls of the registered family <c>account-enrollment</c> (plan <c>families.account-enrollment.create-user</c>) in the shape the
/// Identity statement builders produce (the same statement keys, argument order and tail as CLOUD.11's shared vector), with fresh
/// identifiers per enrollment, so the family port is exercised on the real plan.
/// </summary>
internal sealed record Enrollment(Guid Command, Guid Realm, Guid User, Guid Credential, Guid Workspace, string Provider, string Subject, Guid Outbox)
{
    public const string Family = "account-enrollment";
    public const string Plan = "families.account-enrollment.create-user";
    public const long CreatedAt = 1_790_000_000_000_000;
    public const long Retention = 7L * 86_400_000_000;

    public static readonly Guid DefaultRealm = new("00000000-0000-4000-8000-0000000000a1");

    public static Enrollment New(string subject = "subject-1", Guid? realm = null, Guid? command = null) =>
        new(command ?? Guid.NewGuid(), realm ?? DefaultRealm, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), "provider-1", subject, Guid.NewGuid());

    public string Scope => Workspace.ToString("D");

    public string RequestHash => "enroll-" + User.ToString("N") + Credential.ToString("N");

    public static PlanValue T(Guid value) => PlanValue.FromText(value.ToString("D"));

    public static PlanValue T(string value) => PlanValue.FromText(value);

    public static PlanValue I(long value) => PlanValue.FromInt64(value);

    /// <summary>The Identity and Workspace statements, in the order IdentityStatements.Enroll lists them (not plan order).</summary>
    public List<FamilyStatement> Statements() =>
    [
        new("identity", FamilyStatementClass.Revision, "credential-id", [T(Credential), I(0)]),
        new("identity", FamilyStatementClass.Revision, "credential-subject", [T(Realm), T(Provider), T(Subject), I(0)]),
        new("identity", FamilyStatementClass.Revision, "user", [T(Realm), T(User), I(0)]),
        new("workspace", FamilyStatementClass.Revision, "owner", [T(Realm), T(User), I(0)]),
        new("workspace", FamilyStatementClass.Revision, "workspace", [T(Workspace), I(0)]),
        new("identity", FamilyStatementClass.Record, "credential",
        [
            T(Credential), T(User), I(2), T(Subject), PlanValue.Null, PlanValue.Null, I(-1), I(-1), PlanValue.Null, I(-1), PlanValue.Null, I(CreatedAt),
            T(Realm), T(Provider), PlanValue.Null,
        ]),
        new("identity", FamilyStatementClass.Record, "account", [T(User), T(Realm), T("Ada"), I(CreatedAt)]),
        new("workspace", FamilyStatementClass.Record, "workspace", [T(Workspace), T(Realm), T(User), T("Personal"), T("eu"), I(CreatedAt)]),
    ];

    public string ResultJson => "{\"userId\":\"" + User.ToString("D") + "\",\"workspaceId\":\"" + Workspace.ToString("D") + "\"}";

    public ModuleCommit Commit(int events = 1, long createdAt = CreatedAt, string? requestHash = null) => new(
        Command,
        Workspace,
        "user:" + User.ToString("D"),
        "identity.account.enroll",
        requestHash ?? RequestHash,
        ResultJson,
        1,
        createdAt,
        createdAt + Retention,
        [.. Enumerable.Range(0, events).Select(index => new ModuleOutboxEvent(
            index == 0 ? Outbox : Guid.NewGuid(), "identity.user", User, 1, "identity.user.enrolled", "{\"method\":2}", Workspace, Command, null))],
        1,
        "{\"op\":\"identity.account.enroll\"}");

    public ModuleFamilyCall Call(IReadOnlyList<FamilyStatement>? statements = null, ModuleCommit? commit = null, string family = Family, string plan = Plan, string? scope = null) =>
        new(family, plan, scope ?? Scope, statements ?? Statements(), commit ?? Commit());
}

/// <summary>Fixture families for refusals that the production registry cannot show.</summary>
internal static class FamilyPortCatalog
{
    public static FamilyPlanDefinition EnrollmentPlan => PlanManifest.FamilyPlans.Single(plan => plan.Plan.Id == Enrollment.Plan);

    /// <summary>
    /// A family other than account-enrollment with the same participants and the same statement shape: the reviewed exception does not
    /// hold in it, so the Identity caller may not contribute its workspace statements there.
    /// </summary>
    public static (IReadOnlyList<FamilyDefinition> Catalog, IReadOnlyList<FamilyPlanDefinition> Plans) OtherFamily()
    {
        var source = EnrollmentPlan;
        var plan = source.Plan with { Id = "families.other-family.create-user" };
        var family = new FamilyPlanDefinition(plan, "other-family", source.Roles);
        var definition = new FamilyDefinition("other-family", "Fixture family", "test", [new(FamilyModule.Identity, true, null), new(FamilyModule.Workspace, true, null)]);
        return ([.. PlanManifest.FamilyCatalog, definition], [.. PlanManifest.FamilyPlans, family]);
    }
}
