// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement;
using ArcForges.Cloud.Modules.Entitlement.Persistence.Infrastructure;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Application;
using ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Tests.Receipts;
using Xunit;
using static ArcForges.Cloud.Tests.Receipts.ScriptedExecutor;

namespace ArcForges.Cloud.Tests.Entitlement;

/// <summary>
/// What the D1 store does with the answers of the plans: the exact arguments of the commit plan, the mapping of every failure to a commit
/// outcome or a typed exception, and the consistency rule of a paged read. The SQL behind the answers runs in
/// <see cref="D1EntitlementStoreTests"/> and in tests/worker/entitlement-plans.test.ts.
/// </summary>
public sealed class D1EntitlementStoreUnitTests
{
    private static readonly string Workspace = D1EntitlementHarness.Uuid(0xB1);

    private sealed class FixedTime : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => Samples.Now;
    }

    private static (D1EntitlementStore Store, ScriptedExecutor Storage) Create()
    {
        var storage = new ScriptedExecutor();
        var port = new ModulePlanPortFactory(storage, 1, new FixedTime()).For(EntitlementModule.Instance.Descriptor);
        return (new D1EntitlementStore(port), storage);
    }

    private static (EntitlementAppend Append, EntitlementSnapshot Snapshot) Sample()
    {
        var grant = new Grant(D1EntitlementHarness.Uuid(0x91), Workspace, GrantKind.Capability, "cloud.sync", new CapabilityValue(), GrantSource.AdminGrant, "ticket-1",
            Fixtures.T(0), null, "operator", Fixtures.T(5), "reason");
        var records = EntitlementRecordSet.Empty(Workspace) with { Grants = [grant] };
        return (EntitlementAppend.None with { Grants = [grant] }, EntitlementResolver.Resolve(records, Fixtures.Definitions(), Fixtures.T(6)));
    }

    [Fact]
    public async Task TheCommitPlanCarriesTheGuardedRevisionTheContentIdentityAndTheTail()
    {
        var (store, storage) = Create();
        var (append, snapshot) = Sample();
        storage.Handler = _ => Changed();

        Assert.Equal(CommitOutcome.Committed, await store.CommitAsync(Workspace, 3, append, snapshot, T.Ct));

        var call = storage.Calls.Single();
        Assert.Equal("entitlement.commit", call.Plan.Id);
        Assert.Equal(Workspace, call.OwnerScope);
        Assert.Equal(call.Plan.Statements.Count, call.Arguments.Length);
        var command = Text(call.Arguments[0][0]);
        Assert.Equal(Workspace, Text(call.Arguments[0][1]));
        Assert.Equal(3, Int(call.Arguments[0][2]));
        Assert.Equal(new long[] { 4, 6_000_000, 3 }, new[] { Int(call.Arguments[1][1]), Int(call.Arguments[1][2]), Int(call.Arguments[1][3]) });
        Assert.Equal(Guid.ParseExact(command, "D").ToString("D"), command);
        // The release is the last statement and carries the same command identity as the guard.
        Assert.Equal(command, Text(call.Arguments[^1][0]));
        Assert.Equal(command, Text(call.Arguments[0][0]));

        // The same content under the same revision is the same command; another revision or content is another command.
        storage.Calls.Clear();
        await store.CommitAsync(Workspace, 3, append, snapshot, T.Ct);
        await store.CommitAsync(Workspace, 4, append, snapshot, T.Ct);
        Assert.Equal(command, Text(storage.Calls[0].Arguments[0][0]));
        Assert.NotEqual(command, Text(storage.Calls[1].Arguments[0][0]));
    }

    [Fact]
    public async Task EveryCommitFailureIsAnOutcomeOrATypedException()
    {
        var (store, storage) = Create();
        var (append, snapshot) = Sample();
        storage.Handler = call => call.Plan.Id == "platform.command-load" ? Rows() : throw Fail(PlanFailureKind.Precondition);
        Assert.Equal(CommitOutcome.RevisionConflict, await store.CommitAsync(Workspace, 0, append, snapshot, T.Ct));

        storage.Handler = call => call.Plan.Id == "platform.command-load" ? Rows() : throw Fail(PlanFailureKind.UnknownOutcome);
        Assert.Equal(CommitOutcome.UnknownOutcome, await store.CommitAsync(Workspace, 0, append, snapshot, T.Ct));

        foreach (var (kind, failure) in new[]
        {
            (PlanFailureKind.Overloaded, EntitlementStoreFailure.Unavailable), (PlanFailureKind.Unavailable, EntitlementStoreFailure.Unavailable),
            (PlanFailureKind.StaleGeneration, EntitlementStoreFailure.Unavailable), (PlanFailureKind.InvalidPlan, EntitlementStoreFailure.Defect),
            (PlanFailureKind.ManifestMismatch, EntitlementStoreFailure.Defect),
        })
        {
            storage.Handler = _ => throw Fail(kind);
            var thrown = await Assert.ThrowsAsync<EntitlementStoreException>(async () => await store.CommitAsync(Workspace, 0, append, snapshot, T.Ct));
            Assert.Equal(failure, thrown.Failure);
        }

        // A constraint with no receipt is a defect (a value the schema refuses), never a replay.
        storage.Handler = call => call.Plan.Id == "platform.command-load" ? Rows() : throw Fail(PlanFailureKind.Constraint);
        Assert.Equal(EntitlementStoreFailure.Defect, (await Assert.ThrowsAsync<EntitlementStoreException>(async () => await store.CommitAsync(Workspace, 0, append, snapshot, T.Ct))).Failure);
    }

    [Fact]
    public async Task ARequestThatBreaksTheCommitBoundsIsRefusedBeforeStorage()
    {
        var (store, storage) = Create();
        var (append, snapshot) = Sample();
        var many = Enumerable.Range(0, D1EntitlementStore.MaxAppendPerKind + 1)
            .Select(i => append.Grants[0] with { GrantId = D1EntitlementHarness.Uuid(0x3000 + i) }).ToArray();

        await Assert.ThrowsAsync<ArgumentException>(async () => await store.CommitAsync(Workspace, 0, append with { Grants = [.. many] }, snapshot, T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(async () => await store.CommitAsync(Workspace, 0, append with { Grants = [append.Grants[0] with { WorkspaceId = D1EntitlementHarness.Uuid(0xB2) }] }, snapshot, T.Ct));
        await Assert.ThrowsAsync<ArgumentException>(async () => await store.CommitAsync(D1EntitlementHarness.Uuid(0xB2), 0, append, snapshot, T.Ct));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await store.CommitAsync(Workspace, -1, append, snapshot, T.Ct));
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () => await store.CommitAsync(Workspace, long.MaxValue, append, snapshot, T.Ct));
        Assert.Empty(storage.Calls);
    }

    [Fact]
    public async Task AReadThatSawTwoRevisionsStartsAgainAndGivesUpAfterThreeAttempts()
    {
        var (store, storage) = Create();
        var revisionReads = 0;
        // Attempt one reads 1 then 2 (changed), attempt two reads 3 then 4 (changed), attempt three reads 5 then 6 (changed): no consistent read exists.
        storage.Handler = call => call.Plan.Id == "entitlement.revision-load" ? Rows([D1Values.Int64(++revisionReads)]) : Rows();
        var thrown = await Assert.ThrowsAsync<EntitlementStoreException>(async () => await store.LoadAsync(Workspace, T.Ct));
        Assert.Equal(EntitlementStoreFailure.Unavailable, thrown.Failure);
        Assert.Equal(6, revisionReads);

        // A history that settles is returned with the revision of the settled read.
        revisionReads = 0;
        storage.Handler = call => call.Plan.Id == "entitlement.revision-load" ? Rows([D1Values.Int64(revisionReads++ < 2 ? revisionReads : 3)]) : Rows();
        var state = await store.LoadAsync(Workspace, T.Ct);
        Assert.Equal(3, state.Revision);
        Assert.Null(state.Snapshot);
        Assert.Equal(0, state.Records.Count);
    }

    [Fact]
    public async Task AnUnreachableStoreIsUnavailableAndAMalformedAnswerIsADefect()
    {
        var (store, storage) = Create();
        storage.Handler = _ => throw Fail(PlanFailureKind.Overloaded);
        Assert.Equal(EntitlementStoreFailure.Unavailable, (await Assert.ThrowsAsync<EntitlementStoreException>(async () => await store.LoadAsync(Workspace, T.Ct))).Failure);

        storage.Handler = call => call.Plan.Id == "entitlement.revision-load" ? Rows([D1Values.Int64(-1)]) : Rows();
        Assert.Equal(EntitlementStoreFailure.Defect, (await Assert.ThrowsAsync<EntitlementStoreException>(async () => await store.LoadAsync(Workspace, T.Ct))).Failure);

        storage.Handler = call => call.Plan.Id == "entitlement.revision-load" ? Rows([D1Values.Int64(1), D1Values.Int64(2)]) : Rows();
        Assert.Equal(EntitlementStoreFailure.Defect, (await Assert.ThrowsAsync<EntitlementStoreException>(async () => await store.LoadAsync(Workspace, T.Ct))).Failure);
    }

    [Fact]
    public async Task APagedReadKeepsAskingAfterTheLastRowItGotAndStopsOnAShortPage()
    {
        var (store, storage) = Create();
        var pages = 0;
        storage.Handler = call =>
        {
            switch (call.Plan.Id)
            {
                case "entitlement.revision-load":
                    return Rows([D1Values.Int64(2)]);
                case "entitlement.activations-load":
                    pages++;
                    var after = Int(call.Arguments[0][1]);
                    var start = after == 0 ? 1 : after + 1;
                    var count = pages == 1 ? 100 : 5;
                    return new PlanResult([.. Enumerable.Range(0, count).Select(i => (IReadOnlyList<D1Scalar>)[D1Values.Text("bundle-1"), D1Values.Int64(start + i)])], 0);
                default:
                    return Rows();
            }
        };

        var state = await store.LoadAsync(Workspace, T.Ct);

        Assert.Equal(2, pages);
        Assert.Equal(105, state.Records.Activations.Length);
        Assert.Equal(Enumerable.Range(1, 105).Select(i => (long)i), state.Records.Activations.Select(a => a.ActivatedAt.Value));
    }

    [Fact]
    public void TheStoreIsRegisteredLazilyAndTheModuleListsTheGrantPort()
    {
        var services = new Microsoft.Extensions.DependencyInjection.ServiceCollection();
        ((IModuleBoundary)EntitlementModule.Instance).Register(services);

        Assert.Contains(services, d => d.ServiceType == typeof(IEntitlementStore));
        Assert.Contains(services, d => d.ServiceType == typeof(IEntitlementGrantPort));
        Assert.Contains(services, d => d.ServiceType == typeof(EntitlementService));
        Assert.Contains(services, d => d.ServiceType == typeof(IEntitlementIdSource));
    }

    [Fact]
    public void TheProductionIdentifierSourceIssuesCanonicalLowerCaseUuids()
    {
        var source = new GuidEntitlementIdSource();
        var ids = Enumerable.Range(0, 50).Select(_ => source.NewId()).ToArray();
        Assert.Equal(50, ids.Distinct().Count());
        Assert.All(ids, id => Assert.Equal(Guid.ParseExact(id, "D").ToString("D"), id));
    }
}
