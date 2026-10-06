// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules;

namespace ArcForges.Cloud.Capacity;

internal enum CapacityOperation { Onboarding, CapacitySale, Growth, OptionalBackground, Read, Export, Cancel, Delete, Settle, Restore }
internal enum CapacityAdmissionStatus { Admitted, Busy, Unavailable, Invalid }
internal sealed record CapacityPressure(string Dimension, int Percent, bool Alert, bool Action);
internal sealed record CapacityAdmissionResult(CapacityAdmissionStatus Status, IReadOnlyList<CapacityPressure>? Pressures = null,
    bool PartitionDecisionRequired = false, bool ThirtyDayHeadroom = false);
internal sealed record ApprovedCapacityProfile(string Json, string Hash, Guid RealmId, CapacityAllocation VerifiedProviderLimits,
    QuotaOwnerContext Context, IReadOnlyList<QuotaBudgetKey> DimensionBudgets, IReadOnlyList<long> ExpectedPolicyVersions);
internal sealed record ApprovedCapacityProfileResult(QuotaAuthorityStatus Status, ApprovedCapacityProfile? Profile = null);
internal interface IApprovedCapacityProfileSource
{
    Task<ApprovedCapacityProfileResult> ReadCurrentAsync(CancellationToken cancellationToken);
}
internal sealed record PhysicalCapacityState(Guid RealmId, ulong D1Bytes, ulong VerifiedD1MaximumBytes, ulong DailyGrowthBytes,
    bool UnexplainedInventoryDrift, string SourceSnapshotHash);
internal sealed record PhysicalCapacityResult(QuotaAuthorityStatus Status, PhysicalCapacityState? State = null);
/// <summary>Actual provider/database inventory and growth observation, never a client quota declaration.</summary>
internal interface IPhysicalCapacitySource
{
    Task<PhysicalCapacityResult> ReadAsync(Guid realmId, CancellationToken cancellationToken);
}

/// <summary>Complete operator capacity admission over approved limits, actual kernel Used/Held
/// and measured physical inventory. The result is operational policy, never a customer entitlement
/// or an atomic reservation. Growth effects still acquire the actual guarded quota reservations.</summary>
internal sealed class CapacityAdmission(IApprovedCapacityProfileSource profiles, IPhysicalCapacitySource physical, IQuotaKernelPort quota)
{
    private static readonly string[] Names = ["vectors", "namespaces", "r2Bytes", "r2Objects", "classAPerDay", "classBPerDay", "servedBytesPerDay"];
    internal async Task<CapacityAdmissionResult> EvaluateAsync(CapacityOperation operation, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!Enum.IsDefined(operation)) return new(CapacityAdmissionStatus.Invalid);
        // This operator gate confers no business authorization. Protected work keeps its reserve
        // even if telemetry/configuration is unavailable; the owning operation still authorizes
        // scope and applies all settlement/deletion/lease guards independently.
        var reserved = operation is CapacityOperation.Read or CapacityOperation.Export or CapacityOperation.Cancel or CapacityOperation.Delete
            or CapacityOperation.Settle or CapacityOperation.Restore;
        var source = await profiles.ReadCurrentAsync(cancellationToken).ConfigureAwait(false);
        if (source.Status != QuotaAuthorityStatus.Authorized || source.Profile is not { } approved
            || approved.DimensionBudgets is null || approved.ExpectedPolicyVersions is null
            || approved.DimensionBudgets.Count != 7 || approved.ExpectedPolicyVersions.Count != 7)
            return new(reserved ? CapacityAdmissionStatus.Admitted : CapacityAdmissionStatus.Unavailable);
        approved = approved with { DimensionBudgets = Array.AsReadOnly(approved.DimensionBudgets.ToArray()),
            ExpectedPolicyVersions = Array.AsReadOnly(approved.ExpectedPolicyVersions.ToArray()) };
        if (approved.DimensionBudgets.Distinct().Count() != 7
            || approved.Context.RealmId != approved.RealmId || !CapacityProfileCodec.TryDecode(approved.Json, approved.Hash,
                approved.RealmId, approved.VerifiedProviderLimits, out var profile)) return new(reserved ? CapacityAdmissionStatus.Admitted : CapacityAdmissionStatus.Unavailable);
        var inventory = await physical.ReadAsync(approved.RealmId, cancellationToken).ConfigureAwait(false);
        if (inventory.Status != QuotaAuthorityStatus.Authorized || inventory.State is not { } observed
            || observed.RealmId != approved.RealmId || observed.VerifiedD1MaximumBytes is 0 or > 10000000000
            || !CapacityProfileCodec.Hash(observed.SourceSnapshotHash))
            return new(reserved ? CapacityAdmissionStatus.Admitted : CapacityAdmissionStatus.Unavailable);
        var limits = CapacityProfileCodec.Dimensions(profile!.RealmBudgets);
        List<CapacityPressure> pressures = [];
        var stopGrowth = false; var stopOnboarding = false; var stopOptional = false;
        for (var index = 0; index < 7; index++)
        {
            var read = await quota.ReadBudgetAsync(approved.Context, approved.DimensionBudgets[index], cancellationToken).ConfigureAwait(false);
            if (read.Status != QuotaKernelStatus.Succeeded || read.Value is not { } budget || budget.PolicyVersion != approved.ExpectedPolicyVersions[index]
                || budget.Used < 0 || budget.Held < 0 || budget.Limit < 0 || (ulong)budget.Limit != limits[index]
                || budget.Key != approved.DimensionBudgets[index] || budget.Unit != (index is 2 or 6 ? "bytes" : "count"))
                return new(reserved ? CapacityAdmissionStatus.Admitted : CapacityAdmissionStatus.Unavailable);
            var percent = Percent((UInt128)(ulong)budget.Used + (ulong)budget.Held, limits[index]);
            pressures.Add(new(Names[index], percent, percent >= 60, percent >= 70));
            stopOnboarding |= percent >= 80;
            if (index < 4) stopGrowth |= percent >= 90;
            else stopOptional |= percent >= 80;
        }
        var d1Percent = Percent(observed.D1Bytes, observed.VerifiedD1MaximumBytes);
        pressures.Add(new("d1Bytes", d1Percent, d1Percent >= 60, d1Percent >= 70));
        stopOnboarding |= d1Percent >= 80; stopGrowth |= d1Percent >= 90;
        var blocked = !reserved && (observed.UnexplainedInventoryDrift || (operation is CapacityOperation.Onboarding or CapacityOperation.CapacitySale) && stopOnboarding
            || operation == CapacityOperation.Growth && stopGrowth || operation == CapacityOperation.OptionalBackground && (stopGrowth || stopOptional));
        var thirtyDays = (UInt128)observed.D1Bytes + (UInt128)observed.DailyGrowthBytes * 30 < observed.VerifiedD1MaximumBytes;
        var partition = ((UInt128)observed.D1Bytes + (UInt128)observed.DailyGrowthBytes * 180) * 100 > (UInt128)observed.VerifiedD1MaximumBytes * 60;
        cancellationToken.ThrowIfCancellationRequested();
        return new(blocked ? CapacityAdmissionStatus.Busy : CapacityAdmissionStatus.Admitted, pressures, partition, thirtyDays);
    }
    private static int Percent(UInt128 value, ulong limit) => limit == 0 ? 100 : (int)UInt128.Min(100, value * 100 / limit);
}
