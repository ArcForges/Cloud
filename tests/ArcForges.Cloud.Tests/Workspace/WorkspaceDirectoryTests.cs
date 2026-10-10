// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Composition;
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Workspace;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Entitlement;
using ArcForges.Cloud.Tests.IdentityCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.WorkspaceDirectory;

/// <summary>
/// The published workspace read port (<see cref="IWorkspaceDirectory"/>, S54(1)) as other modules see it: resolved from the Workspace module's
/// own registration, over the real Workspace plan port and the SQLite oracle bridge (production Worker plan code, every committed migration;
/// SQLite is not D1), and over a scripted plan port for the plan calls, the status mapping and the strict row decoding.
/// </summary>
public sealed class WorkspaceDirectoryTests : IDisposable
{
    private const string RealmA = IdentityReadPlanTests.RealmA;
    private const string RealmB = IdentityReadPlanTests.RealmB;
    private const string UserA = IdentityReadPlanTests.UserA;
    private const string UserB = IdentityReadPlanTests.UserB;
    private const string UserC = IdentityReadPlanTests.UserC;
    private const string WorkspaceA = WorkspaceReadPlanTests.WorkspaceA;
    private const string WorkspaceB = WorkspaceReadPlanTests.WorkspaceB;
    private const string WorkspaceC = WorkspaceReadPlanTests.WorkspaceC;
    private const string Unknown = "40000000-0000-4000-8000-0000000000ff";

    private static readonly WorkspaceRecord RecordA = new(WorkspaceA, RealmA, UserA, "Personal", "eu", 1, WorkspaceRecordState.Active, 20, 3);

    private readonly SqliteBridgeExecutor bridge = new(recoveryGeneration: 1);
    private readonly FakeTime time = new(DateTimeOffset.FromUnixTimeSeconds(1_790_000_000));

    public void Dispose() => bridge.Dispose();

    /// <summary>The directory exactly as the Workspace module registers it, over the given plan port factory.</summary>
    private static IWorkspaceDirectory Directory(IModulePlanPortFactory factory)
    {
        var services = new ServiceCollection();
        services.AddSingleton(factory);
        ((IModuleBoundary)WorkspaceModule.Instance).Register(services);
        return services.BuildServiceProvider().GetRequiredService<IWorkspaceDirectory>();
    }

    private IWorkspaceDirectory Oracle() => Directory(new ModulePlanPortFactory(bridge, 1, time));

    private static ScriptedPort Scripted(Func<ModulePlanRead, ModulePlanOutcome> answer, out IWorkspaceDirectory directory)
    {
        var port = new ScriptedPort(answer);
        directory = Directory(new ScriptedFactory(port));
        return port;
    }

    private static ModulePlanOutcome RowsOf(params IReadOnlyList<PlanValue>[] rows) => new(ModulePlanStatus.Succeeded, rows);

    private static PlanValue[] Row(
        string workspace = WorkspaceA, string realm = RealmA, string owner = UserA, long profile = 1, long state = 1, long createdAt = 20, long revision = 3) =>
        [PlanValue.FromText(workspace), PlanValue.FromText(realm), PlanValue.FromText(owner), PlanValue.FromText("Personal"), PlanValue.FromText("eu"),
            PlanValue.FromInt64(profile), PlanValue.FromInt64(state), PlanValue.FromInt64(createdAt), PlanValue.FromInt64(revision)];

    private static void AssertFound(WorkspaceRecord expected, WorkspaceDirectoryResult result)
    {
        Assert.Equal(WorkspaceDirectoryStatus.Found, result.Status);
        Assert.Equal(expected, result.Workspace);
        Assert.Null(result.Detail);
    }

    private static void AssertNotFound(WorkspaceDirectoryResult result)
    {
        Assert.Equal(WorkspaceDirectoryStatus.NotFound, result.Status);
        Assert.Null(result.Workspace);
    }

    [Fact]
    public async Task AWorkspaceIsFoundByIdentifierWithItsStoredStateAsPrimitives()
    {
        await WorkspaceReadPlanTests.SeedAsync(bridge);
        var directory = Oracle();

        AssertFound(RecordA, await directory.FindAsync(RealmA, WorkspaceA, T.Ct));
        AssertFound(new WorkspaceRecord(WorkspaceB, RealmA, UserB, "Grace", "us", 1, WorkspaceRecordState.PendingDeletion, 21, 1),
            await directory.FindAsync(RealmA, WorkspaceB, T.Ct));
        AssertFound(new WorkspaceRecord(WorkspaceC, RealmB, UserC, "Edsger", "eu", 1, WorkspaceRecordState.Suspended, 22, 7),
            await directory.FindAsync(RealmB, WorkspaceC, T.Ct));
    }

    [Fact]
    public async Task AReadByIdentifierIsScopedByRealm()
    {
        await WorkspaceReadPlanTests.SeedAsync(bridge);
        var directory = Oracle();

        AssertNotFound(await directory.FindAsync(RealmB, WorkspaceA, T.Ct));
        AssertNotFound(await directory.FindAsync(RealmA, WorkspaceC, T.Ct));
        AssertNotFound(await directory.FindAsync(RealmA, Unknown, T.Ct));
    }

    [Fact]
    public async Task AWorkspaceIsFoundByItsOneOwnerInTheRealm()
    {
        await WorkspaceReadPlanTests.SeedAsync(bridge);
        var directory = Oracle();

        AssertFound(RecordA, await directory.FindByOwnerAsync(RealmA, UserA, T.Ct));
        Assert.Equal(WorkspaceB, (await directory.FindByOwnerAsync(RealmA, UserB, T.Ct)).Workspace?.WorkspaceId);
        Assert.Equal(WorkspaceC, (await directory.FindByOwnerAsync(RealmB, UserC, T.Ct)).Workspace?.WorkspaceId);
    }

    [Fact]
    public async Task AReadByOwnerIsScopedByRealmAndOwner()
    {
        await WorkspaceReadPlanTests.SeedAsync(bridge);
        var directory = Oracle();

        AssertNotFound(await directory.FindByOwnerAsync(RealmB, UserA, T.Ct));
        AssertNotFound(await directory.FindByOwnerAsync(RealmA, UserC, T.Ct));
        AssertNotFound(await directory.FindByOwnerAsync(RealmA, "10000000-0000-4000-8000-0000000000ff", T.Ct));
    }

    [Theory]
    [InlineData("")]
    [InlineData("40000000-0000-4000-8000-00000000000")]
    [InlineData("40000000-0000-4000-8000-0000000000011")]
    [InlineData("40000000-0000-4000-8000-0000000000A1")]
    [InlineData("{40000000-0000-4000-8000-000000000001}")]
    [InlineData("40000000000040008000000000000001")]
    [InlineData("40000000-0000-4000-8000-000000000001\n")]
    [InlineData(" 40000000-0000-4000-8000-000000000001")]
    [InlineData("4000000g-0000-4000-8000-000000000001")]
    public async Task AMalformedIdentifierIsRefusedBeforeAnyPlanCall(string malformed)
    {
        await WorkspaceReadPlanTests.SeedAsync(bridge);
        var directory = Oracle();
        var calls = bridge.Calls;

        var results = new[]
        {
            await directory.FindAsync(malformed, WorkspaceA, T.Ct),
            await directory.FindAsync(RealmA, malformed, T.Ct),
            await directory.FindByOwnerAsync(malformed, UserA, T.Ct),
            await directory.FindByOwnerAsync(RealmA, malformed, T.Ct),
        };

        Assert.All(results, result =>
        {
            Assert.Equal(WorkspaceDirectoryStatus.InvalidRequest, result.Status);
            Assert.Null(result.Workspace);
            if (malformed.Trim().Length > 0) Assert.DoesNotContain(malformed.Trim(), result.Detail!, StringComparison.Ordinal);
        });
        Assert.Equal(calls, bridge.Calls);
    }

    [Fact]
    public async Task ANullIdentifierIsRefusedBeforeAnyPlanCall()
    {
        var port = Scripted(_ => throw new InvalidOperationException("no plan call is expected"), out var directory);

        Assert.Equal(WorkspaceDirectoryStatus.InvalidRequest, (await directory.FindAsync(null!, WorkspaceA, T.Ct)).Status);
        Assert.Equal(WorkspaceDirectoryStatus.InvalidRequest, (await directory.FindByOwnerAsync(RealmA, null!, T.Ct)).Status);
        Assert.Empty(port.Reads);
    }

    [Fact]
    public async Task EachReadIsExactlyOneNamedPlanOfTheWorkspaceOwnerWithItsScopeAndArguments()
    {
        var port = Scripted(_ => RowsOf(Row()), out var directory);

        AssertFound(RecordA, await directory.FindAsync(RealmA, WorkspaceA, T.Ct));
        AssertFound(RecordA, await directory.FindByOwnerAsync(RealmA, UserA, T.Ct));

        Assert.Equal(2, port.Reads.Count);
        Assert.Equal("workspace.workspace-get", port.Reads[0].PlanId);
        Assert.Equal(WorkspaceA, port.Reads[0].OwnerScope);
        Assert.Equal(new[] { PlanValue.FromText(RealmA), PlanValue.FromText(WorkspaceA) }, port.Reads[0].Arguments);
        Assert.Equal("workspace.workspace-by-owner", port.Reads[1].PlanId);
        Assert.Equal(RealmA, port.Reads[1].OwnerScope);
        Assert.Equal(new[] { PlanValue.FromText(RealmA), PlanValue.FromText(UserA) }, port.Reads[1].Arguments);
        // Both plans exist in the checked-in manifest under the Workspace owner, so the real port accepts them.
        Assert.Equal("workspace.workspace-get", PlanManifest.Workspace.WorkspaceGet.Id);
        Assert.Equal("workspace.workspace-by-owner", PlanManifest.Workspace.WorkspaceByOwner.Id);
    }

    /// <summary>The answer for every plan status other than a success: retryable when nothing was served, otherwise a defect.</summary>
    private static readonly Dictionary<ModulePlanStatus, WorkspaceDirectoryStatus> StatusMapping = new()
    {
        [ModulePlanStatus.Unavailable] = WorkspaceDirectoryStatus.Unavailable,
        [ModulePlanStatus.StaleGeneration] = WorkspaceDirectoryStatus.Unavailable,
        [ModulePlanStatus.Rejected] = WorkspaceDirectoryStatus.Defect,
        [ModulePlanStatus.UnknownOutcome] = WorkspaceDirectoryStatus.Defect,
        [ModulePlanStatus.GuardRefused] = WorkspaceDirectoryStatus.Defect,
        [ModulePlanStatus.ConstraintRefused] = WorkspaceDirectoryStatus.Defect,
        [ModulePlanStatus.Replayed] = WorkspaceDirectoryStatus.Defect,
        [ModulePlanStatus.ReplayedFailure] = WorkspaceDirectoryStatus.Defect,
        [ModulePlanStatus.DuplicateMessage] = WorkspaceDirectoryStatus.Defect,
        [ModulePlanStatus.ReusedIdentifier] = WorkspaceDirectoryStatus.Defect,
        [ModulePlanStatus.ReceiptExpired] = WorkspaceDirectoryStatus.Defect,
    };

    public static TheoryData<string> FailedStatuses() => [.. StatusMapping.Keys.Select(status => status.ToString())];

    [Theory]
    [MemberData(nameof(FailedStatuses))]
    public async Task EveryPlanStatusOtherThanSuccessBecomesATypedAnswerWithoutAWorkspace(string name)
    {
        var status = Enum.Parse<ModulePlanStatus>(name);
        // A status that is not a success never yields a workspace, even if the port were to carry rows with it.
        Scripted(_ => new ModulePlanOutcome(status, [Row()]), out var directory);

        foreach (var result in new[] { await directory.FindAsync(RealmA, WorkspaceA, T.Ct), await directory.FindByOwnerAsync(RealmA, UserA, T.Ct) })
        {
            Assert.Equal(StatusMapping[status], result.Status);
            Assert.Null(result.Workspace);
            Assert.Contains(name, result.Detail!, StringComparison.Ordinal);
            Assert.DoesNotContain(RealmA, result.Detail!, StringComparison.Ordinal);
            Assert.DoesNotContain(WorkspaceA, result.Detail!, StringComparison.Ordinal);
            Assert.DoesNotContain(UserA, result.Detail!, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void EveryPlanStatusIsCoveredByTheMappingTable() =>
        Assert.Equal(Enum.GetValues<ModulePlanStatus>().Order(), StatusMapping.Keys.Append(ModulePlanStatus.Succeeded).Order());

    private static readonly Dictionary<string, PlanValue[][]> DefectRowCases = new(StringComparer.Ordinal)
    {
        ["two rows"] = [Row(), Row()],
        ["a missing column"] = [[.. Row().Take(8)]],
        ["an extra column"] = [[.. Row(), PlanValue.Null]],
        ["a null identifier"] = [[PlanValue.Null, .. Row().Skip(1)]],
        ["an integer identifier"] = [[PlanValue.FromInt64(1), .. Row().Skip(1)]],
        ["an upper-case identifier"] = [Row(owner: "10000000-0000-4000-8000-0000000000AB")],
        ["a non-canonical realm"] = [Row(realm: "realm-a")],
        ["a null name"] = [[.. Row().Take(3), PlanValue.Null, .. Row().Skip(4)]],
        ["a null data region"] = [[.. Row().Take(4), PlanValue.Null, .. Row().Skip(5)]],
        ["a textual state"] = [[.. Row().Take(6), PlanValue.FromText("1"), .. Row().Skip(7)]],
        ["a boolean revision"] = [[.. Row().Take(8), PlanValue.FromBool(true)]],
        ["an unknown state"] = [Row(state: 4)],
        ["a zero state"] = [Row(state: 0)],
        ["an unknown protection profile"] = [Row(profile: 2)],
        ["a negative creation instant"] = [Row(createdAt: -1)],
        ["a negative revision"] = [Row(revision: -1)],
        ["another realm"] = [Row(realm: RealmB)],
        ["another workspace"] = [Row(workspace: WorkspaceB)],
        ["another owner"] = [Row(owner: UserB)],
    };

    public static TheoryData<string> DefectRows() => [.. DefectRowCases.Keys];

    [Theory]
    [MemberData(nameof(DefectRows))]
    public async Task AStoredRowThatIsNotExactlyTheOneAskedForIsADefectAndNeverAWorkspace(string reason)
    {
        Scripted(_ => RowsOf(DefectRowCases[reason]), out var directory);

        // "another workspace" is only wrong for a read by identifier and "another owner" only for a read by owner; every other row is wrong for both.
        var results = reason switch
        {
            "another workspace" => new[] { await directory.FindAsync(RealmA, WorkspaceA, T.Ct) },
            "another owner" => new[] { await directory.FindByOwnerAsync(RealmA, UserA, T.Ct) },
            _ => new[] { await directory.FindAsync(RealmA, WorkspaceA, T.Ct), await directory.FindByOwnerAsync(RealmA, UserA, T.Ct) },
        };

        Assert.All(results, result =>
        {
            Assert.Equal(WorkspaceDirectoryStatus.Defect, result.Status);
            Assert.Null(result.Workspace);
            Assert.False(string.IsNullOrEmpty(result.Detail));
        });
    }

    [Fact]
    public async Task ACancelledReadIsNotSwallowed()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();
        var port = Scripted(_ => throw new OperationCanceledException(cancelled.Token), out var directory);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await directory.FindAsync(RealmA, WorkspaceA, cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await directory.FindByOwnerAsync(RealmA, UserA, cancelled.Token));
        Assert.Equal(2, port.Reads.Count);
    }

    [Fact]
    public void TheModuleRegistersTheDirectoryAndNeedsThePlanPortFactoryItDoesNotProvide()
    {
        var services = new ServiceCollection();
        ((IModuleBoundary)WorkspaceModule.Instance).Register(services);

        Assert.Single(services, descriptor => descriptor.ServiceType == typeof(IWorkspaceDirectory));
        Assert.DoesNotContain(services, descriptor => descriptor.ServiceType == typeof(IModulePlanPortFactory));
        using var provider = services.BuildServiceProvider();
        Assert.Throws<InvalidOperationException>(() => provider.GetRequiredService<IWorkspaceDirectory>());
    }

    [Fact]
    public void TheDirectoryAsksTheFactoryForTheWorkspaceDescriptorOnlyAndIsOneInstance()
    {
        var factory = new ScriptedFactory(new ScriptedPort(_ => RowsOf()));
        var services = new ServiceCollection();
        services.AddSingleton<IModulePlanPortFactory>(factory);
        ((IModuleBoundary)WorkspaceModule.Instance).Register(services);
        ((IModuleBoundary)WorkspaceModule.Instance).Register(services);
        using var provider = services.BuildServiceProvider();

        Assert.Same(provider.GetRequiredService<IWorkspaceDirectory>(), provider.GetRequiredService<IWorkspaceDirectory>());
        Assert.Single(services, descriptor => descriptor.ServiceType == typeof(IWorkspaceDirectory));
        Assert.Equal(new[] { WorkspaceModule.Instance.Descriptor }, factory.Requested);
        Assert.Equal("workspace", factory.Requested[0].PlanOwner);
    }

    [Fact]
    public async Task UnderTheFoundationConfigurationTheHostResolvesTheDirectoryOverThePlanExecutor()
    {
        await WorkspaceReadPlanTests.SeedAsync(bridge);
        var builder = WebApplication.CreateSlimBuilder();
        builder.Services.AddSingleton<IPlanExecutor>(bridge);
        new FoundationModule(T.Options(generation: 1)).Register(builder);
        new ModulePlanBindingModule().Register(builder);
        new ModuleBoundaryHost(WorkspaceModule.Instance).Register(builder);
        await using var app = builder.Build();

        var directory = app.Services.GetRequiredService<IWorkspaceDirectory>();

        AssertFound(RecordA, await directory.FindAsync(RealmA, WorkspaceA, T.Ct));
        AssertFound(RecordA, await directory.FindByOwnerAsync(RealmA, UserA, T.Ct));
    }

    [Fact]
    public async Task WithoutTheFoundationConfigurationTheHostResolvesNoDirectory()
    {
        // Production binds no plan executor today (the COM.16 gap): the directory is listed but nothing resolves it.
        var builder = WebApplication.CreateSlimBuilder();
        new FoundationModule(_ => null).Register(builder);
        new ModulePlanBindingModule().Register(builder);
        new ModuleBoundaryHost(WorkspaceModule.Instance).Register(builder);
        await using var app = builder.Build();

        Assert.Throws<InvalidOperationException>(() => app.Services.GetRequiredService<IWorkspaceDirectory>());
    }

    private sealed class ScriptedPort(Func<ModulePlanRead, ModulePlanOutcome> answer) : IModulePlanPort
    {
        public List<ModulePlanRead> Reads { get; } = [];

        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken)
        {
            Reads.Add(read);
            return Task.FromResult(answer(read));
        }

        public Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("The workspace directory never writes.");
    }

    private sealed class ScriptedFactory(IModulePlanPort port) : IModulePlanPortFactory
    {
        public List<ModuleDescriptor> Requested { get; } = [];

        public IModulePlanPort For(ModuleDescriptor module)
        {
            Requested.Add(module);
            return port;
        }
    }
}
