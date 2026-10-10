// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Entitlement;
using ArcForges.Cloud.Tests.IdentityCore;
using Xunit;

namespace ArcForges.Cloud.Tests.WorkspaceDirectory;

/// <summary>
/// The CLOUD.72 workspace read plans (<c>workspace.workspace-get</c>, <c>workspace.workspace-by-owner</c>; S54(1)) through the Workspace
/// module's own plan port over the SQLite oracle bridge (production Worker plan code, every committed migration). Every read is scoped by
/// realm; the read by id binds the workspace id as the owner scope, so a call whose scope is another workspace is refused before the
/// executor. SQLite is not D1.
/// </summary>
public sealed class WorkspaceReadPlanTests : IDisposable
{
    private const string WorkspaceA = "40000000-0000-4000-8000-000000000001";
    private const string WorkspaceB = "40000000-0000-4000-8000-000000000002";
    private const string WorkspaceC = "40000000-0000-4000-8000-000000000003";

    private static readonly ModuleDescriptor WorkspaceModule = ModuleDescriptor.Create("Workspace", "workspace");

    private static readonly string?[] WorkspaceAColumns =
        [WorkspaceA, IdentityReadPlanTests.RealmA, IdentityReadPlanTests.UserA, "Personal", "eu", "1", "1", "20", "3"];

    private readonly SqliteBridgeExecutor bridge = new(recoveryGeneration: 1);
    private readonly FakeTime time = new(DateTimeOffset.FromUnixTimeSeconds(1_790_000_000));

    public void Dispose() => bridge.Dispose();

    private IModulePlanPort Port() => new ModulePlanPortFactory(bridge, 1, time).For(WorkspaceModule);

    private async Task SeedAsync()
    {
        await IdentityReadPlanTests.SeedAsync(bridge);
        await bridge.ExecAsync(
            "INSERT INTO workspace_workspace (workspace_id, realm_id, owner_user_id, name, data_region, protection_profile, state, created_at, rev) VALUES "
            + "('" + WorkspaceA + "', '" + IdentityReadPlanTests.RealmA + "', '" + IdentityReadPlanTests.UserA + "', 'Personal', 'eu', 1, 1, 20, 3), "
            + "('" + WorkspaceB + "', '" + IdentityReadPlanTests.RealmA + "', '" + IdentityReadPlanTests.UserB + "', 'Grace', 'us', 1, 3, 21, 1), "
            + "('" + WorkspaceC + "', '" + IdentityReadPlanTests.RealmB + "', '" + IdentityReadPlanTests.UserC + "', 'Edsger', 'eu', 1, 2, 22, 7);",
            T.Ct);
    }

    private static PlanValue Text(string value) => PlanValue.FromText(value);

    private Task<ModulePlanOutcome> GetAsync(string realm, string workspace, string? scope = null) =>
        Port().ReadAsync(new ModulePlanRead("workspace.workspace-get", scope ?? workspace, [Text(realm), Text(workspace)]), T.Ct);

    private Task<ModulePlanOutcome> ByOwnerAsync(string realm, string owner) =>
        Port().ReadAsync(new ModulePlanRead("workspace.workspace-by-owner", realm, [Text(realm), Text(owner)]), T.Ct);

    [Fact]
    public async Task WorkspaceGetReturnsTheFullWorkspaceRow()
    {
        await SeedAsync();

        Assert.Equal(WorkspaceAColumns, Assert.Single(IdentityReadPlanTests.Rows(await GetAsync(IdentityReadPlanTests.RealmA, WorkspaceA))));

        // A suspended or pending-deletion workspace is returned with its state: the caller decides.
        var pending = Assert.Single(IdentityReadPlanTests.Rows(await GetAsync(IdentityReadPlanTests.RealmA, WorkspaceB)));
        Assert.Equal([WorkspaceB, IdentityReadPlanTests.RealmA, IdentityReadPlanTests.UserB, "Grace", "us", "1", "3", "21", "1"], pending);
    }

    [Fact]
    public async Task WorkspaceGetIsScopedByRealm()
    {
        await SeedAsync();

        Assert.Empty(IdentityReadPlanTests.Rows(await GetAsync(IdentityReadPlanTests.RealmB, WorkspaceA)));
        Assert.Empty(IdentityReadPlanTests.Rows(await GetAsync(IdentityReadPlanTests.RealmA, WorkspaceC)));
        Assert.Equal(WorkspaceC, Assert.Single(IdentityReadPlanTests.Rows(await GetAsync(IdentityReadPlanTests.RealmB, WorkspaceC)))[0]);
        Assert.Empty(IdentityReadPlanTests.Rows(await GetAsync(IdentityReadPlanTests.RealmA, "40000000-0000-4000-8000-0000000000ff")));
    }

    [Fact]
    public async Task WorkspaceGetBindsTheWorkspaceIdAsTheOwnerScopeAndRefusesAnotherScopeBeforeTheExecutor()
    {
        await SeedAsync();
        Assert.Contains(PlanManifest.Workspace.WorkspaceGet.Statements[0].Params, param => param.Kind == PlanKind.Scope);
        var calls = bridge.Calls;

        var outcome = await GetAsync(IdentityReadPlanTests.RealmA, WorkspaceA, scope: WorkspaceB);

        Assert.Equal(ModulePlanStatus.Rejected, outcome.Status);
        Assert.Empty(outcome.Rows);
        Assert.Equal(calls, bridge.Calls);
    }

    [Fact]
    public async Task WorkspaceByOwnerReturnsTheOwnersOneWorkspaceInTheRealm()
    {
        await SeedAsync();

        Assert.Equal(WorkspaceAColumns, Assert.Single(IdentityReadPlanTests.Rows(await ByOwnerAsync(IdentityReadPlanTests.RealmA, IdentityReadPlanTests.UserA))));
        Assert.Equal(WorkspaceB, Assert.Single(IdentityReadPlanTests.Rows(await ByOwnerAsync(IdentityReadPlanTests.RealmA, IdentityReadPlanTests.UserB)))[0]);
        Assert.Equal(WorkspaceC, Assert.Single(IdentityReadPlanTests.Rows(await ByOwnerAsync(IdentityReadPlanTests.RealmB, IdentityReadPlanTests.UserC)))[0]);
    }

    [Fact]
    public async Task WorkspaceByOwnerIsScopedByRealmAndOwner()
    {
        await SeedAsync();

        Assert.Empty(IdentityReadPlanTests.Rows(await ByOwnerAsync(IdentityReadPlanTests.RealmB, IdentityReadPlanTests.UserA)));
        Assert.Empty(IdentityReadPlanTests.Rows(await ByOwnerAsync(IdentityReadPlanTests.RealmA, IdentityReadPlanTests.UserC)));
        Assert.Empty(IdentityReadPlanTests.Rows(await ByOwnerAsync(IdentityReadPlanTests.RealmA, "10000000-0000-4000-8000-0000000000ff")));
    }

    [Fact]
    public async Task TheSchemaKeepsAtMostOneWorkspacePerOwnerAndRealmSoTheOneRowBoundHolds()
    {
        await SeedAsync();
        Assert.Equal(1, PlanManifest.Workspace.WorkspaceByOwner.MaxRows);

        var refusal = await bridge.RefusalAsync(
            "INSERT INTO workspace_workspace (workspace_id, realm_id, owner_user_id, name, data_region, protection_profile, state, created_at, rev) VALUES "
            + "('40000000-0000-4000-8000-000000000004', '" + IdentityReadPlanTests.RealmA + "', '" + IdentityReadPlanTests.UserA + "', 'Second', 'eu', 1, 1, 30, 0);",
            T.Ct);

        Assert.Contains("UNIQUE", refusal, StringComparison.Ordinal);
        Assert.Single(IdentityReadPlanTests.Rows(await ByOwnerAsync(IdentityReadPlanTests.RealmA, IdentityReadPlanTests.UserA)));
    }
}
