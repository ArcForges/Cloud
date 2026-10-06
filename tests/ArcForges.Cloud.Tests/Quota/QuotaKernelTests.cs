// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;
using ArcForges.Cloud.Modules.Entitlement;
using ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Application;
using ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Domain;
using ArcForges.Cloud.Modules.Entitlement.Quota.Kernel.Infrastructure;
using ArcForges.Cloud.Storage.ModuleBinding;
using ArcForges.Cloud.Storage.Capacity;
using ArcForges.Cloud.Tests.Entitlement;
using ArcForges.Cloud.Capacity;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ArcForges.Cloud.Tests.CapacityQuotaTests;

/// <summary>Actual kernel/store/receipt/Worker plans and all migrations over SQLite. Only the unavailable
/// Configuration/business measurement authority and injected D1 transport failures are substitutes.</summary>
public sealed class QuotaKernelTests
{
    [Fact]
    public async Task LoadAdapterMeasuresActualGuardedReservationAndVerifiesPrimaryPersistenceOnReplay()
    {
        using var h = new Harness(); await h.Budget(h.Storage, 100);
        var fixture = new LoadFixture(new(h.Context, h.Storage, 1, 90, h.Now + 60000000, new('a', 64)));
        var operation = new CapacityQuotaLoadOperation(fixture, h.Kernel, CapacityLoadKind.Command);
        var call = new CapacityLoadCall(Id(700), Id(701), CapacityLoadKind.Command, 0, new('a', 64));
        var first = await operation.ExecuteAsync(call, T.Ct);
        Assert.Equal(CapacityLoadStatus.Acknowledged, first.Status); Assert.True(first.DurableVerified);
        Assert.Equal(first, await operation.ExecuteAsync(call, T.Ct));
        Assert.Equal(1, (await h.State(h.Storage)).Held); Assert.Equal(1, await h.Count("entitlement_quota_reservation"));
        Assert.Equal(2, await h.Count("platform_command"));
        fixture.Fixture = fixture.Fixture with { Bound = 2 };
        Assert.Equal(CapacityLoadStatus.InvariantFailure, (await operation.ExecuteAsync(call, T.Ct)).Status);
        fixture.Status = QuotaAuthorityStatus.Denied;
        Assert.Equal(CapacityLoadStatus.Refused, (await operation.ExecuteAsync(call, T.Ct)).Status);
        Assert.Equal(1, (await h.State(h.Storage)).Held);
        var read = new CapacityQuotaLoadOperation(fixture, h.Kernel, CapacityLoadKind.PrimaryRead);
        fixture.Status = QuotaAuthorityStatus.Authorized;
        Assert.Equal(CapacityLoadStatus.Acknowledged, (await read.ExecuteAsync(call with { Kind = CapacityLoadKind.PrimaryRead }, T.Ct)).Status);
    }

    [Fact]
    public async Task CallerMutationCannotReplaceTermsBetweenCanonicalSnapshotAndAdmissionAuthority()
    {
        using var h = new Harness(); await h.Budget(h.Storage, 100);
        h.Proofs.Ceilings[h.Storage] = 80;
        var unapproved = new QuotaAdmissionItem(Id(450), h.Storage, 90, 1, 1, 100);
        var approved = unapproved with { Bound = 10, AdmissionCeiling = 80 };
        List<QuotaAdmissionItem> caller = [unapproved];
        h.Proofs.CommandHook = () => caller[0] = approved;
        Assert.Equal(QuotaKernelStatus.Denied, (await h.Kernel.ReserveAsync(h.Admit(caller), T.Ct)).Status);
        Assert.Equal(0, (await h.State(h.Storage)).Held);
        caller[0] = approved;
        h.Proofs.CommandHook = () => caller[0] = unapproved;
        var result = await h.Kernel.ReserveAsync(h.Admit(caller), T.Ct);
        Assert.Equal(QuotaKernelStatus.Succeeded, result.Status);
        Assert.Equal(10, Assert.Single(result.Reservations!).Bound);
        Assert.Equal(10, (await h.State(h.Storage)).Held);
    }

    [Fact]
    public async Task ApprovedOperatorCeilingIsAtomicUnderCompetingWritersWithoutReducingCustomerHardLimit()
    {
        using var h = new Harness(); await h.Budget(h.Storage, 100);
        h.Proofs.Ceilings[h.Storage] = 90;
        var first = h.Admit([new(Id(401), h.Storage, 80, 1, 1, 90)]);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ReserveAsync(first, T.Ct)).Status);
        var settled = h.Effect(Id(401), 2, QuotaEffectKind.Consume, 70, false); h.Proofs.Approve(settled);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ApplyAsync(settled, T.Ct)).Status);
        var left = h.Admit([new(Id(402), h.Storage, 10, 1, 3, 90)]);
        var right = h.Admit([new(Id(403), h.Storage, 10, 1, 3, 90)]);
        var results = await Task.WhenAll(h.Kernel.ReserveAsync(left, T.Ct), h.Kernel.ReserveAsync(right, T.Ct));
        Assert.Single(results, r => r.Status == QuotaKernelStatus.Succeeded);
        Assert.Single(results, r => r.Status == QuotaKernelStatus.Conflict);
        var state = await h.State(h.Storage);
        Assert.Equal((100, 70, 20, 4), (state.Limit, state.Used, state.Held, state.Revision));
        Assert.Equal(QuotaKernelStatus.LimitExceeded, (await h.Kernel.ReserveAsync(h.Admit([new(h.NewId(), h.Storage, 1, 1, 4, 90)]), T.Ct)).Status);
        Assert.Equal(QuotaKernelStatus.Denied, (await h.Kernel.ReserveAsync(h.Admit([new(h.NewId(), h.Storage, 1, 1, 4)]), T.Ct)).Status);
        Assert.Equal(2, await h.Count("entitlement_quota_reservation"));
    }

    [Fact]
    public async Task OperatorCapacityUsesActualHeldCountersAndKeepsEssentialWorkAtPressureOrTelemetryFailure()
    {
        using var h = new Harness();
        var profile = CapacityTests.CapacityProfileTests.Selected() with { RealmId = h.Context.RealmId };
        var keys = Enumerable.Range(0, 7).Select(index => new QuotaBudgetKey(QuotaScopeKind.Deployment,
            "capacity:" + h.Context.RealmId.ToString("D"), "dimension:" + index, index < 4 ? "gauge" : "2026-10-06")).ToArray();
        var limits = CapacityProfileCodec.Dimensions(profile.RealmBudgets);
        for (var index = 0; index < 7; index++) await h.Budget(keys[index], checked((long)limits[index]), unit: index is 2 or 6 ? "bytes" : "count");
        var json = CapacityProfileCodec.Encode(profile);
        var source = new CapacitySources(new(json, CapacityJobCodec.Hash(json), h.Context.RealmId, profile.RealmBudgets,
            h.Context, keys, Enumerable.Repeat(1L, 7).ToArray()),
            new(h.Context.RealmId, 6000000000, 10000000000, 1000000, false, new('c', 64)));
        var gate = new CapacityAdmission(source, source, h.Kernel);
        var initial = await gate.EvaluateAsync(CapacityOperation.Growth, T.Ct);
        Assert.Equal(CapacityAdmissionStatus.Admitted, initial.Status);
        Assert.True(initial.ThirtyDayHeadroom); Assert.True(initial.PartitionDecisionRequired);
        Assert.Equal(60, initial.Pressures!.Single(p => p.Dimension == "d1Bytes").Percent);
        var originalInventory = source.State;
        source.State = source.State with { VerifiedD1MaximumBytes = 20000000000 };
        Assert.Equal(CapacityAdmissionStatus.Unavailable, (await gate.EvaluateAsync(CapacityOperation.Growth, T.Ct)).Status);
        Assert.Equal(CapacityAdmissionStatus.Admitted, (await gate.EvaluateAsync(CapacityOperation.Read, T.Ct)).Status);
        source.State = originalInventory;
        var hold = h.Admit([new(h.NewId(), keys[0], 1800000, 1, 1)]);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ReserveAsync(hold, T.Ct)).Status);
        Assert.Equal(CapacityAdmissionStatus.Busy, (await gate.EvaluateAsync(CapacityOperation.Growth, T.Ct)).Status);
        Assert.Equal(CapacityAdmissionStatus.Busy, (await gate.EvaluateAsync(CapacityOperation.Onboarding, T.Ct)).Status);
        Assert.Equal(CapacityAdmissionStatus.Admitted, (await gate.EvaluateAsync(CapacityOperation.Read, T.Ct)).Status);
        Assert.Equal(0, (await h.State(keys[0])).Used); Assert.Equal(1800000, (await h.State(keys[0])).Held);
        source.PhysicalStatus = QuotaAuthorityStatus.Unavailable;
        Assert.Equal(CapacityAdmissionStatus.Unavailable, (await gate.EvaluateAsync(CapacityOperation.Growth, T.Ct)).Status);
        var protectedWork = await gate.EvaluateAsync(CapacityOperation.Settle, T.Ct);
        Assert.Equal(CapacityAdmissionStatus.Admitted, protectedWork.Status); Assert.Null(protectedWork.Pressures);
        Assert.Equal(1800000, (await h.State(keys[0])).Held);
    }

    [Fact]
    public async Task MultiLimitAdmissionIsAtomicAndConcurrentStaleReservationCannotOverdraw()
    {
        using var h = new Harness();
        await h.Budget(h.Storage, 100);
        await h.Budget(h.Staging, 10);
        var rejected = h.Admit([new(Id(20), h.Storage, 20, 1, 1), new(Id(21), h.Staging, 11, 1, 1)]);
        Assert.Equal(QuotaKernelStatus.LimitExceeded, (await h.Kernel.ReserveAsync(rejected, T.Ct)).Status);
        Assert.Equal(0, (await h.State(h.Storage)).Held);
        Assert.Equal(0, await h.Count("entitlement_quota_reservation"));
        var first = h.Admit([new(Id(22), h.Storage, 8, 1, 1), new(Id(23), h.Staging, 8, 1, 1)]);
        var second = h.Admit([new(Id(24), h.Storage, 8, 1, 1), new(Id(25), h.Staging, 8, 1, 1)]);
        var results = await Task.WhenAll(h.Kernel.ReserveAsync(first, T.Ct), h.Kernel.ReserveAsync(second, T.Ct));
        Assert.Single(results, result => result.Status == QuotaKernelStatus.Succeeded);
        Assert.Single(results, result => result.Status == QuotaKernelStatus.Conflict);
        Assert.Equal(8, (await h.State(h.Storage)).Held);
        Assert.Equal(8, (await h.State(h.Staging)).Held);
        Assert.Equal(2, await h.Count("entitlement_quota_reservation"));
        Assert.Equal(3, await h.Count("platform_command"));
        Assert.Equal(0, await h.Count("platform_command_guard"));
    }

    [Fact]
    public async Task DowngradePreservesMeasuredUseAndHoldsWhileNewAdmissionsFail()
    {
        using var h = new Harness();
        await h.Budget(h.Storage, 100);
        var admission = h.Admit([new(Id(30), h.Storage, 80, 1, 1)]);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ReserveAsync(admission, T.Ct)).Status);
        var effect = h.Effect(Id(30), 2, QuotaEffectKind.Consume, 30, false);
        h.Proofs.Approve(effect);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ApplyAsync(effect, T.Ct)).Status);
        await h.Budget(h.Storage, 20, 2, 3);
        var state = await h.State(h.Storage);
        Assert.Equal((20, 30, 50, 2, 4), (state.Limit, state.Used, state.Held, state.PolicyVersion, state.Revision));
        var next = h.Admit([new(Id(31), h.Storage, 1, 2, 4)]);
        Assert.Equal(QuotaKernelStatus.LimitExceeded, (await h.Kernel.ReserveAsync(next, T.Ct)).Status);
        Assert.Equal(state, await h.State(h.Storage));
        var restored = new QuotaKernel(new D1QuotaKernelStore(h.Port), h.Proofs, h.Proofs, h.Clock);
        Assert.Equal(state, (await restored.ReadBudgetAsync(h.Context, h.Storage, T.Ct)).Value);
    }

    [Fact]
    public async Task ExpiryOnlySchedulesCleanupAndUnverifiedCleanupNeverFreesPhysicalBytes()
    {
        using var h = new Harness();
        await h.Budget(h.Storage, 100);
        var admission = h.Admit([new(Id(40), h.Storage, 60, 1, 1)]);
        await h.Kernel.ReserveAsync(admission, T.Ct);
        var consume = h.Effect(Id(40), 2, QuotaEffectKind.Consume, 20, false);
        h.Proofs.Approve(consume);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ApplyAsync(consume, T.Ct)).Status);
        h.Advance(TimeSpan.FromHours(1));
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.RequestCleanupAsync(new(h.NewId(), h.Context, Id(40), 3), T.Ct)).Status);
        Assert.Equal((20, 40), ((await h.State(h.Storage)).Used, (await h.State(h.Storage)).Held));
        Assert.Equal(QuotaReservationState.Releasing, (await h.Kernel.ReadReservationAsync(h.Context, Id(40), T.Ct)).Value!.State);
        var release = h.Effect(Id(40), 4, QuotaEffectKind.Release, 40, true);
        h.Proofs.MeasurementStatus = QuotaAuthorityStatus.Unavailable;
        Assert.Equal(QuotaKernelStatus.Unavailable, (await h.Kernel.ApplyAsync(release, T.Ct)).Status);
        Assert.Equal(40, (await h.State(h.Storage)).Held);
        h.Proofs.MeasurementStatus = QuotaAuthorityStatus.Authorized;
        Assert.Equal(QuotaKernelStatus.Denied, (await h.Kernel.ApplyAsync(release, T.Ct)).Status);
        h.Proofs.Approve(release);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ApplyAsync(release, T.Ct)).Status);
        Assert.Equal((20, 0), ((await h.State(h.Storage)).Used, (await h.State(h.Storage)).Held));
        var deletion = h.Effect(Id(40), 5, QuotaEffectKind.Adjust, -20, true);
        h.Proofs.Approve(deletion);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ApplyAsync(deletion, T.Ct)).Status);
        Assert.Equal(0, (await h.State(h.Storage)).Used);
        // New independently measured physical data makes arithmetic alone insufficient to prevent
        // a repeated deletion receipt from freeing another object's charged bytes.
        var newPhysical = h.Effect(Id(40), 6, QuotaEffectKind.Adjust, 20, true);
        h.Proofs.Approve(newPhysical);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ApplyAsync(newPhysical, T.Ct)).Status);
        var duplicateReceipt = deletion with { CommandId = h.NewId(), ExpectedBudgetRevision = 7, Measurement = deletion.Measurement with { EffectId = h.NewId() } };
        h.Proofs.Approve(duplicateReceipt);
        Assert.Equal(QuotaKernelStatus.Conflict, (await h.Kernel.ApplyAsync(duplicateReceipt, T.Ct)).Status);
        Assert.Equal(20, (await h.State(h.Storage)).Used);
        Assert.Equal(4, await h.Count("entitlement_quota_event"));
    }

    [Fact]
    public async Task PositivePhysicalEvidenceAndDeletionReceiptsCannotBeCountedTwiceAcrossReservations()
    {
        using var h = new Harness();
        await h.Budget(h.Storage, 100);
        await h.Kernel.ReserveAsync(h.Admit([new(Id(50), h.Storage, 30, 1, 1)]), T.Ct);
        var first = h.Effect(Id(50), 2, QuotaEffectKind.Consume, 20, true);
        h.Proofs.Approve(first);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ApplyAsync(first, T.Ct)).Status);
        await h.Kernel.ReserveAsync(h.Admit([new(Id(51), h.Storage, 30, 1, 3)]), T.Ct);
        var duplicate = h.Effect(Id(51), 4, QuotaEffectKind.Consume, 20, true) with
        {
            Measurement = first.Measurement with { EffectId = h.NewId() }
        };
        h.Proofs.Approve(duplicate);
        Assert.Equal(QuotaKernelStatus.Conflict, (await h.Kernel.ApplyAsync(duplicate, T.Ct)).Status);
        Assert.Equal((20, 30, 4), ((await h.State(h.Storage)).Used, (await h.State(h.Storage)).Held, (await h.State(h.Storage)).Revision));
        Assert.Equal(1, await h.Count("entitlement_quota_event"));
    }

    [Fact]
    public async Task ExactInt64BoundsNeverRoundOrOverflowAndGaugeAdjustmentCannotInventSpace()
    {
        using var h = new Harness();
        await h.Budget(h.Storage, long.MaxValue);
        var admission = h.Admit([new(Id(60), h.Storage, long.MaxValue, 1, 1)]);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ReserveAsync(admission, T.Ct)).Status);
        var consume = h.Effect(Id(60), 2, QuotaEffectKind.Consume, long.MaxValue, true);
        h.Proofs.Approve(consume);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ApplyAsync(consume, T.Ct)).Status);
        Assert.Equal(long.MaxValue, (await h.State(h.Storage)).Used);
        var overflow = h.Effect(Id(60), 3, QuotaEffectKind.Adjust, 1, true);
        h.Proofs.Approve(overflow);
        Assert.Equal(QuotaKernelStatus.Conflict, (await h.Kernel.ApplyAsync(overflow, T.Ct)).Status);
        Assert.Equal(QuotaKernelStatus.Invalid, (await h.Kernel.ApplyAsync(overflow with { Measurement = overflow.Measurement with { Quantity = long.MinValue } }, T.Ct)).Status);
        Assert.Equal(long.MaxValue, (await h.State(h.Storage)).Used);
        Assert.Equal(1, await h.Count("entitlement_quota_event"));
    }

    [Fact]
    public async Task ReplayRequiresCurrentPermissionButNotNewMeasurementAndExpiredIdentifierNeverWritesAgain()
    {
        using var h = new Harness();
        await h.Budget(h.Storage, 100);
        var admission = h.Admit([new(Id(70), h.Storage, 30, 1, 1)]);
        await h.Kernel.ReserveAsync(admission, T.Ct);
        var consume = h.Effect(Id(70), 2, QuotaEffectKind.Consume, 20, true);
        h.Proofs.Approve(consume);
        await h.Kernel.ApplyAsync(consume, T.Ct);
        h.Proofs.MeasurementStatus = QuotaAuthorityStatus.Unavailable;
        Assert.Equal(QuotaKernelStatus.Replayed, (await h.Kernel.ApplyAsync(consume, T.Ct)).Status);
        var calls = h.Bridge.Calls;
        h.Proofs.PermissionStatus = QuotaAuthorityStatus.Denied;
        Assert.Equal(QuotaKernelStatus.Denied, (await h.Kernel.ApplyAsync(consume, T.Ct)).Status);
        Assert.Equal(calls, h.Bridge.Calls);
        h.Proofs.PermissionStatus = QuotaAuthorityStatus.Authorized;
        h.Advance(TimeSpan.FromDays(2));
        Assert.Equal(QuotaKernelStatus.Replayed, (await h.Kernel.ReserveAsync(admission, T.Ct)).Status);
        Assert.Equal(QuotaKernelStatus.ReusedIdentifier, (await h.Kernel.ReserveAsync(admission with { OperationId = h.NewId() }, T.Ct)).Status);
        h.Advance(TimeSpan.FromDays(6));
        Assert.Equal(QuotaKernelStatus.ReceiptExpired, (await h.Kernel.ReserveAsync(admission, T.Ct)).Status);
        Assert.Equal(1, await h.Count("entitlement_quota_reservation"));
        Assert.Equal(1, await h.Count("entitlement_quota_event"));
    }

    [Fact]
    public async Task JobTakeoverBetweenAuthorizationAndWriteRefusesOldFenceAndPreservesHolds()
    {
        using var h = new Harness();
        await h.Budget(h.Storage, 100);
        var lease = new CapacityJobLease(Id(80), "holder-one", 1, h.Now + 30000000);
        await h.SeedJob(lease);
        var admission = h.Admit([new(Id(81), h.Storage, 30, 1, 1)]) with { JobLease = lease };
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ReserveAsync(admission, T.Ct)).Status);
        var consume = h.Effect(Id(81), 2, QuotaEffectKind.Consume, 20, true) with { JobLease = lease };
        h.Proofs.Approve(consume);
        // The reservation survives its first worker's genuine expiry. A replacement live lease
        // must be able to rebind it without allowing that expired holder to publish.
        var replacement = lease with { Fence = 2, Holder = "holder-two", LeasedUntilMicros = h.Now + 60000000 };
        var transport = new InterceptPort(h.Port, () => h.Takeover(replacement));
        var oldWorker = new QuotaKernel(new D1QuotaKernelStore(transport), h.Proofs, h.Proofs, h.Clock);
        Assert.Equal(QuotaKernelStatus.Conflict, (await oldWorker.ApplyAsync(consume, T.Ct)).Status);
        Assert.Equal((0, 30, 2), ((await h.State(h.Storage)).Used, (await h.State(h.Storage)).Held, (await h.State(h.Storage)).Revision));
        Assert.Equal(0, await h.Count("entitlement_quota_event"));
        h.Advance(TimeSpan.FromSeconds(31));
        var recovered = consume with { CommandId = h.NewId(), JobLease = replacement };
        h.Proofs.Approve(recovered);
        Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ApplyAsync(recovered, T.Ct)).Status);
        Assert.Equal(2, (await h.Kernel.ReadReservationAsync(h.Context, Id(81), T.Ct)).Value!.Fence);
        Assert.Equal(20, (await h.State(h.Storage)).Used);
    }

    [Theory]
    [InlineData("RealmId")]
    [InlineData("WorkspaceId")]
    [InlineData("Kind")]
    [InlineData("OwnerId")]
    [InlineData("RecoveryGeneration")]
    public async Task PersistedForeignJobBindingAfterAuthorizationCannotAdmitOrPublishQuota(string changedField)
    {
        foreach (var operation in new[] { "reserve", "effect", "cleanup" })
        {
            using var h = new Harness();
            await h.Budget(h.Storage, 100);
            var lease = new CapacityJobLease(Id(82), "holder", 1, h.Now + 30000000);
            await h.SeedJob(lease);
            var admission = h.Admit([new(Id(83), h.Storage, 30, 1, 1)]) with { JobLease = lease };
            if (operation != "reserve") Assert.Equal(QuotaKernelStatus.Succeeded, (await h.Kernel.ReserveAsync(admission, T.Ct)).Status);
            var path = changedField == "RecoveryGeneration" ? "$.Definition.RecoveryGeneration" : "$.Definition.Owner." + changedField;
            var changedValue = changedField == "RecoveryGeneration" ? "2" : changedField == "Kind" ? "foreign-owner" : Id(99).ToString("D");
            var transport = new InterceptPort(h.Port, () => h.Bridge.ExecAsync(
                $"UPDATE platform_job_lease SET payload=json_set(payload,'{path}','{changedValue}') WHERE job_id='{lease.JobId:D}';", T.Ct));
            var kernel = new QuotaKernel(new D1QuotaKernelStore(transport), h.Proofs, h.Proofs, h.Clock);
            QuotaKernelResult result;
            if (operation == "reserve") result = await kernel.ReserveAsync(admission, T.Ct);
            else if (operation == "effect")
            {
                var effect = h.Effect(Id(83), 2, QuotaEffectKind.Consume, 20, true) with { JobLease = lease };
                h.Proofs.Approve(effect); result = await kernel.ApplyAsync(effect, T.Ct);
            }
            else result = await kernel.RequestCleanupAsync(new(h.NewId(), h.Context, Id(83), 2, lease), T.Ct);
            Assert.Equal(QuotaKernelStatus.Conflict, result.Status);
            var budget = await h.State(h.Storage);
            Assert.Equal(0, budget.Used); Assert.Equal(operation == "reserve" ? 0 : 30, budget.Held);
            Assert.Equal(operation == "reserve" ? 1 : 2, budget.Revision);
            Assert.Equal(0, await h.Count("entitlement_quota_event"));
        }
    }

    [Fact]
    public async Task LostCommittedResponseRetriesExactReceiptAndCancellationAfterCommitDoesNotRollback()
    {
        using var h = new Harness();
        await h.Budget(h.Storage, 100);
        var admission = h.Admit([new(Id(90), h.Storage, 30, 1, 1)]);
        var lost = new FaultPort(h.Port, ModulePlanStatus.UnknownOutcome, applyFirst: true);
        var recover = new QuotaKernel(new D1QuotaKernelStore(lost), h.Proofs, h.Proofs, h.Clock);
        Assert.Equal(QuotaKernelStatus.Replayed, (await recover.ReserveAsync(admission, T.Ct)).Status);
        Assert.Equal(2, lost.Writes.Count);
        Assert.Equal(lost.Writes[0].Commit, lost.Writes[1].Commit);
        Assert.Equal(30, (await h.State(h.Storage)).Held);
        var unavailable = new FaultPort(h.Port, ModulePlanStatus.Unavailable);
        recover = new(new D1QuotaKernelStore(unavailable), h.Proofs, h.Proofs, h.Clock);
        Assert.Equal(QuotaKernelStatus.Unavailable, (await recover.ReserveAsync(h.Admit([new(Id(91), h.Storage, 1, 1, 2)]), T.Ct)).Status);
        Assert.Equal(3, unavailable.Writes.Count);
        using var canceled = new CancellationTokenSource();
        var cleanup = new QuotaCleanupCommand(h.NewId(), h.Context, Id(90), 2);
        var cancelPort = new InterceptPort(h.Port, null, canceled);
        recover = new(new D1QuotaKernelStore(cancelPort), h.Proofs, h.Proofs, h.Clock);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => recover.RequestCleanupAsync(cleanup, canceled.Token));
        Assert.Equal(QuotaKernelStatus.Replayed, (await h.Kernel.RequestCleanupAsync(cleanup, T.Ct)).Status);
        Assert.Equal(30, (await h.State(h.Storage)).Held);
        Assert.Equal(QuotaReservationState.Releasing, (await h.Kernel.ReadReservationAsync(h.Context, Id(90), T.Ct)).Value!.State);
    }

    [Fact]
    public async Task InvalidOrForeignContextsNeverReachAuthorityAndCompositionHasNoPermissiveSource()
    {
        using var h = new Harness();
        var invalid = h.Admit([new(Id(95), h.Storage, 1, 1, 1)]) with { Context = h.Context with { WorkspaceId = Id(96) } };
        Assert.Equal(QuotaKernelStatus.Invalid, (await h.Kernel.ReserveAsync(invalid, T.Ct)).Status);
        Assert.Equal(0, h.Proofs.Calls);
        Assert.Equal(QuotaKernelStatus.Invalid, (await h.Kernel.ReadBudgetAsync(h.Context, h.Storage with { QuotaKey = "broken\uD800" }, T.Ct)).Status);
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => h.Kernel.ReserveAsync(h.Admit([new(Id(97), h.Storage, 1, 1, 1)]), canceled.Token));
        var services = new ServiceCollection();
        services.AddSingleton<IModulePlanPortFactory>(new ModulePlanPortFactory(h.Bridge, h.Bridge.Generation, h.Clock));
        ((IModuleBoundary)EntitlementModule.Instance).Register(services);
        using var missing = services.BuildServiceProvider();
        Assert.Throws<InvalidOperationException>(() => missing.GetRequiredService<IQuotaKernelPort>());
        services.AddSingleton<IQuotaKernelAuthority>(h.Proofs); services.AddSingleton<IQuotaMeasurementAuthority>(h.Proofs);
        using var complete = services.BuildServiceProvider();
        Assert.IsType<QuotaKernel>(complete.GetRequiredService<IQuotaKernelPort>());
    }

    private static Guid Id(int value) => Guid.Parse(D1EntitlementHarness.Uuid(value));
    private sealed class Harness : IDisposable
    {
        private int sequence = 1000;
        internal SqliteBridgeExecutor Bridge { get; } = new();
        internal SettableTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);
        internal QuotaOwnerContext Context { get; } = new(Id(1), Id(2), "owner:component", 1, 1, "upload", Id(3));
        internal QuotaBudgetKey Storage { get; } = new(QuotaScopeKind.Workspace, Id(2).ToString("D"), "storage", "gauge");
        internal QuotaBudgetKey Staging { get; } = new(QuotaScopeKind.Deployment, "component-deployment", "staging", "gauge");
        internal IModulePlanPort Port { get; }
        internal QuotaKernel Kernel { get; }
        internal ProofSources Proofs { get; }
        internal long Now => QuotaRules.Now(Clock);
        internal Harness()
        {
            Port = new ModulePlanPortFactory(Bridge, Bridge.Generation, Clock).For(EntitlementModule.Instance.Descriptor);
            Proofs = new(Context);
            Kernel = new(new D1QuotaKernelStore(Port), Proofs, Proofs, Clock);
        }
        internal Guid NewId() => Id(Interlocked.Increment(ref sequence));
        internal async Task Budget(QuotaBudgetKey key, long limit, long version = 1, long revision = 0, string unit = "bytes")
        {
            var command = new QuotaBudgetCommand(NewId(), Context, new(key, unit, limit, version, revision));
            Proofs.Policies[key] = command.Change;
            Assert.Equal(QuotaKernelStatus.Succeeded, (await Kernel.PublishBudgetAsync(command, T.Ct)).Status);
        }
        internal QuotaAdmissionCommand Admit(IReadOnlyList<QuotaAdmissionItem> items) => new(NewId(), NewId(), Context, items, Now + 60000000);
        internal QuotaEffectCommand Effect(Guid reservation, long revision, QuotaEffectKind kind, long quantity, bool complete) =>
            new(NewId(), Context, reservation, revision, new(NewId(), kind, quantity, quantity > 0 ? NewId() : null, null, quantity < 0 ? NewId() : null), complete);
        internal async Task<QuotaBudgetState> State(QuotaBudgetKey key) => (await Kernel.ReadBudgetAsync(Context, key, T.Ct)).Value!;
        internal Task<long> Count(string table) => Bridge.CountAsync(table, "1=1", T.Ct);
        internal void Advance(TimeSpan duration) => Clock.SetSeconds(Clock.GetUtcNow().ToUnixTimeSeconds() + checked((long)duration.TotalSeconds));
        internal Task SeedJob(CapacityJobLease lease)
        {
            Proofs.Jobs.Add(lease.JobId);
            var definition = new CapacityJobDefinition(lease.JobId, "component-job",
                new(Context.RealmId, Context.WorkspaceId, Context.OwnerKind, Context.OwnerId),
                (ulong)Context.RecoveryGeneration, "{}", CapacityJobCodec.Hash("{}"), 10, 0);
            var payload = CapacityJobCodec.Envelope(new(definition, lease.Holder, lease.LeasedUntilMicros, 1,
                lease.Fence, CapacityJobState.Leased, "{}", 0)).Replace("'", "''", StringComparison.Ordinal);
            return Bridge.ExecAsync($"INSERT INTO platform_job_lease VALUES ('{lease.JobId:D}','component-job','{lease.Holder}',{lease.LeasedUntilMicros},1,{lease.Fence},2,'{payload}',0);", T.Ct);
        }
        internal Task Takeover(CapacityJobLease lease) => Bridge.ExecAsync($"UPDATE platform_job_lease SET holder='{lease.Holder}',fence_token={lease.Fence},leased_until={lease.LeasedUntilMicros} WHERE job_id='{lease.JobId:D}';", T.Ct);
        public void Dispose() => Bridge.Dispose();
    }

    // Missing POL02/COM07 and object/deletion producer boundaries. These fixtures bind actual command
    // scope/current configured policy and immutable measurement identity, never a caller success flag.
    private sealed class ProofSources(QuotaOwnerContext expected) : IQuotaKernelAuthority, IQuotaMeasurementAuthority
    {
        internal int Calls;
        internal Action? CommandHook;
        internal QuotaAuthorityStatus PermissionStatus = QuotaAuthorityStatus.Authorized;
        internal QuotaAuthorityStatus MeasurementStatus = QuotaAuthorityStatus.Authorized;
        internal Dictionary<QuotaBudgetKey, QuotaBudgetChange> Policies { get; } = [];
        internal Dictionary<QuotaBudgetKey, long> Ceilings { get; } = [];
        internal HashSet<Guid> Jobs { get; } = [];
        private bool OwnsJob(CapacityJobLease? lease) => lease is null || Jobs.Contains(lease.JobId);
        private readonly Dictionary<Guid, (Guid ReservationId, QuotaMeasurement Measurement)> measurements = [];
        internal void Approve(QuotaEffectCommand command) => measurements[command.Measurement.EffectId] = (command.ReservationId, command.Measurement);
        private Task<QuotaAuthorityStatus> Permission(QuotaOwnerContext context, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested(); Calls++;
            return Task.FromResult(context == expected ? PermissionStatus : QuotaAuthorityStatus.Denied);
        }
        public Task<QuotaAuthorityStatus> AuthorizeCommandAsync(QuotaOwnerContext context, QuotaKernelOperation operation, CancellationToken cancellationToken)
        {
            var hook = CommandHook; CommandHook = null; hook?.Invoke();
            return Permission(context, cancellationToken);
        }
        public Task<QuotaAuthorityStatus> AuthorizeReadAsync(QuotaOwnerContext context, QuotaBudgetKey? key, Guid? reservationId, CancellationToken cancellationToken) => Permission(context, cancellationToken);
        public async Task<QuotaAuthorityStatus> AuthorizeBudgetAsync(QuotaBudgetCommand command, CancellationToken cancellationToken) =>
            await Permission(command.Context, cancellationToken) == QuotaAuthorityStatus.Authorized && Policies.GetValueOrDefault(command.Change.Key) == command.Change
                ? QuotaAuthorityStatus.Authorized : QuotaAuthorityStatus.Denied;
        public async Task<QuotaAuthorityStatus> AuthorizeAdmissionAsync(QuotaAdmissionCommand command, CancellationToken cancellationToken) =>
            await Permission(command.Context, cancellationToken) == QuotaAuthorityStatus.Authorized && OwnsJob(command.JobLease) && command.Items.All(item => Policies.TryGetValue(item.Key, out var policy) && policy.PolicyVersion == item.PolicyVersion
                && (!Ceilings.TryGetValue(item.Key, out var ceiling) || item.AdmissionCeiling == ceiling))
                ? QuotaAuthorityStatus.Authorized : QuotaAuthorityStatus.Denied;
        public Task<QuotaAuthorityStatus> AuthorizeEffectAsync(QuotaEffectCommand command, QuotaReservation reservation, CancellationToken cancellationToken) => OwnsJob(command.JobLease) ? Permission(command.Context, cancellationToken) : Task.FromResult(QuotaAuthorityStatus.Denied);
        public Task<QuotaAuthorityStatus> AuthorizeCleanupAsync(QuotaCleanupCommand command, QuotaReservation reservation, CancellationToken cancellationToken) => OwnsJob(command.JobLease) ? Permission(command.Context, cancellationToken) : Task.FromResult(QuotaAuthorityStatus.Denied);
        public async Task<QuotaAuthorityStatus> VerifyAsync(QuotaOwnerContext context, QuotaReservation reservation, QuotaMeasurement measurement, CancellationToken cancellationToken)
        {
            if (await Permission(context, cancellationToken) != QuotaAuthorityStatus.Authorized) return QuotaAuthorityStatus.Denied;
            if (MeasurementStatus != QuotaAuthorityStatus.Authorized) return MeasurementStatus;
            return measurements.TryGetValue(measurement.EffectId, out var actual) && actual == (reservation.ReservationId, measurement)
                ? QuotaAuthorityStatus.Authorized : QuotaAuthorityStatus.Denied;
        }
    }

    // Only the unavailable approved operator manifest and real provider inventory observations are
    // substituted; CapacityAdmission queries the actual quota kernel/store/Worker plans below.
    private sealed class CapacitySources(ApprovedCapacityProfile profile, PhysicalCapacityState state) : IApprovedCapacityProfileSource, IPhysicalCapacitySource
    {
        internal PhysicalCapacityState State = state;
        internal QuotaAuthorityStatus PhysicalStatus = QuotaAuthorityStatus.Authorized;
        public Task<ApprovedCapacityProfileResult> ReadCurrentAsync(CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(new ApprovedCapacityProfileResult(QuotaAuthorityStatus.Authorized, profile)); }
        public Task<PhysicalCapacityResult> ReadAsync(Guid realmId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new PhysicalCapacityResult(realmId == State.RealmId ? PhysicalStatus : QuotaAuthorityStatus.Denied,
                PhysicalStatus == QuotaAuthorityStatus.Authorized ? State : null));
        }
    }

    private sealed class LoadFixture(CapacityQuotaFixture fixture) : ICapacityQuotaFixtureSource
    {
        internal CapacityQuotaFixture Fixture = fixture;
        internal QuotaAuthorityStatus Status = QuotaAuthorityStatus.Authorized;
        public Task<CapacityQuotaFixtureResult> ResolveAsync(CapacityLoadCall call, CancellationToken cancellationToken)
        { cancellationToken.ThrowIfCancellationRequested(); return Task.FromResult(new CapacityQuotaFixtureResult(Status, Fixture)); }
    }

    private sealed class FaultPort(IModulePlanPort inner, ModulePlanStatus failure, bool applyFirst = false) : IModulePlanPort
    {
        internal List<ModulePlanWrite> Writes { get; } = [];
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken) => inner.ReadAsync(read, cancellationToken);
        public async Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken)
        {
            Writes.Add(write);
            if (!applyFirst) return ModulePlanOutcome.Of(failure);
            if (Writes.Count > 1) return await inner.WriteAsync(write, cancellationToken);
            Assert.Equal(ModulePlanStatus.Succeeded, (await inner.WriteAsync(write, cancellationToken)).Status);
            return ModulePlanOutcome.Of(failure);
        }
    }
    private sealed class InterceptPort(IModulePlanPort inner, Func<Task>? beforeWrite, CancellationTokenSource? afterCommit = null) : IModulePlanPort
    {
        public Task<ModulePlanOutcome> ReadAsync(ModulePlanRead read, CancellationToken cancellationToken) => inner.ReadAsync(read, cancellationToken);
        public async Task<ModulePlanOutcome> WriteAsync(ModulePlanWrite write, CancellationToken cancellationToken)
        {
            if (beforeWrite is not null) await beforeWrite();
            var result = await inner.WriteAsync(write, cancellationToken);
            if (afterCommit is not null)
            {
                Assert.Equal(ModulePlanStatus.Succeeded, result.Status); afterCommit.Cancel(); cancellationToken.ThrowIfCancellationRequested();
            }
            return result;
        }
    }
}
