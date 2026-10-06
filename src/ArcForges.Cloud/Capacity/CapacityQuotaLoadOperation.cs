// SPDX-License-Identifier: AGPL-3.0-only
using System.Security.Cryptography;
using System.Text;
using ArcForges.Cloud.Modules;

namespace ArcForges.Cloud.Capacity;

internal sealed record CapacityQuotaFixture(QuotaOwnerContext Context, QuotaBudgetKey Budget, long Bound,
    long AdmissionCeiling, long ExpiresAtMicros, string WorkloadHash);

/// <summary>Actual authorized guarded-batch measurement adapter over the production quota kernel.
/// Fixture policy/realm/owner/period/bound/ceiling are approved server inputs, never workload client
/// quota or a permissive authority source. The fixture's retained holds are isolated and owned;
/// production cleanup follows actual verified termination, not a synthetic successful release.
/// This adapter measures infrastructure commands, not paid commercial debits or full L16 acceptance.</summary>
internal sealed class CapacityQuotaLoadOperation(ICapacityQuotaFixtureSource source, IQuotaKernelPort quota,
    CapacityLoadKind kind) : ICapacityLoadOperation
{
    public CapacityLoadKind Kind => kind is CapacityLoadKind.Command or CapacityLoadKind.PrimaryRead ? kind
        : throw new InvalidOperationException("Quota load adapter owns only command and primary read.");
    public async Task<CapacityLoadObservation> ExecuteAsync(CapacityLoadCall call, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (call.Kind != Kind || call.RunId == Guid.Empty || call.OperationId == Guid.Empty)
            return new(CapacityLoadStatus.Refused);
        var approved = await source.ResolveAsync(call, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (approved.Status != QuotaAuthorityStatus.Authorized || approved.Fixture is not { } fixture)
            return new(approved.Status == QuotaAuthorityStatus.Unavailable ? CapacityLoadStatus.Unavailable : CapacityLoadStatus.Refused);
        if (fixture.WorkloadHash != call.WorkloadHash || fixture.Bound <= 0 || fixture.AdmissionCeiling < fixture.Bound)
            return new(CapacityLoadStatus.Refused);
        var reservationId = new Guid(SHA256.HashData(Encoding.UTF8.GetBytes("capacity-reservation:" + call.OperationId.ToString("D"))).AsSpan(0, 16));
        if (Kind == CapacityLoadKind.Command)
        {
            var previous = await quota.ReadReservationAsync(fixture.Context, reservationId, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (previous.Status == QuotaKernelStatus.Succeeded && previous.Value is { } prior)
                return Matches(prior, fixture, call) ? new(CapacityLoadStatus.Acknowledged, DurableVerified: true) : new(CapacityLoadStatus.InvariantFailure);
            if (previous.Status != QuotaKernelStatus.NotFound) return new(Map(previous.Status));
        }
        var read = await quota.ReadBudgetAsync(fixture.Context, fixture.Budget, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (read.Status != QuotaKernelStatus.Succeeded || read.Value is not { } budget) return new(Map(read.Status));
        if (Kind == CapacityLoadKind.PrimaryRead) return new(CapacityLoadStatus.Acknowledged);
        var command = new QuotaAdmissionCommand(call.OperationId, call.OperationId, fixture.Context,
            [new(reservationId, fixture.Budget, fixture.Bound, budget.PolicyVersion, budget.Revision, fixture.AdmissionCeiling)], fixture.ExpiresAtMicros);
        var result = await quota.ReserveAsync(command, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (result.Status is not (QuotaKernelStatus.Succeeded or QuotaKernelStatus.Replayed)) return new(Map(result.Status));
        // Receipt acknowledgement alone is not proof that the current primary row retained the
        // admitted effect. Query the actual owner store and bind exact immutable reservation terms.
        var verify = await quota.ReadReservationAsync(fixture.Context, reservationId, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (verify.Status != QuotaKernelStatus.Succeeded || verify.Value is not { } saved)
            return new(verify.Status == QuotaKernelStatus.Unavailable ? CapacityLoadStatus.UnknownOutcome : CapacityLoadStatus.InvariantFailure,
                AcknowledgedLoss: verify.Status == QuotaKernelStatus.NotFound ? 1 : 0);
        if (!Matches(saved, fixture, call)) return new(CapacityLoadStatus.InvariantFailure);
        return new(CapacityLoadStatus.Acknowledged, DurableVerified: true);
    }
    private static bool Matches(QuotaReservation saved, CapacityQuotaFixture fixture, CapacityLoadCall call) =>
        saved.OperationId == call.OperationId && saved.Key == fixture.Budget && saved.OwnerKind == fixture.Context.OwnerKind
        && saved.OwnerId == fixture.Context.OwnerId && saved.Bound == fixture.Bound && saved.Consumed == 0
        && saved.State == QuotaReservationState.Held && saved.ExpiresAtMicros == fixture.ExpiresAtMicros;
    private static CapacityLoadStatus Map(QuotaKernelStatus status) => status switch
    {
        QuotaKernelStatus.Unavailable => CapacityLoadStatus.Unavailable,
        QuotaKernelStatus.UnknownOutcome => CapacityLoadStatus.UnknownOutcome,
        _ => CapacityLoadStatus.Refused,
    };
}

internal sealed record CapacityQuotaFixtureResult(QuotaAuthorityStatus Status, CapacityQuotaFixture? Fixture = null);
/// <summary>The actual operator fixture owner binds every run/session to an isolated current
/// approved quota policy and exact immutable metadata workload. Missing authority refuses the run.</summary>
internal interface ICapacityQuotaFixtureSource
{
    Task<CapacityQuotaFixtureResult> ResolveAsync(CapacityLoadCall call, CancellationToken cancellationToken);
}
