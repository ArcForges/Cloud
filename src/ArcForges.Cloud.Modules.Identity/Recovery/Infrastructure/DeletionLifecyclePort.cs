// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Recovery.Application;
using ArcForges.Cloud.Modules.Identity.Recovery.Domain;

namespace ArcForges.Cloud.Modules.Identity.Recovery.Infrastructure;

/// <summary>Identity owns the actual row read and contribution. A new-request policy is deliberately not a dependency.</summary>
internal sealed class DeletionLifecyclePort(IModulePlanPort plans, IModuleFamilyPort families,
    IRealmAuthorityPort authority, TimeProvider time) : IIdentityDeletionLifecyclePort, IDeletionTransitionStore
{
    public async Task<IdentityDeletionResult> ReadAsync(Guid realmId, Guid userId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (realmId == Guid.Empty || userId == Guid.Empty) return IdentityDeletionResult.Refused(IdentityDeletionFailure.StaleAuthority);
        var current = await authority.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (current.Snapshot is not { } realm) return IdentityDeletionResult.Refused(current.Failure switch
        {
            RealmAuthorityFailure.MissingConfiguration or RealmAuthorityFailure.InvalidConfiguration or RealmAuthorityFailure.Unavailable => IdentityDeletionFailure.Unavailable,
            RealmAuthorityFailure.Defect or null => IdentityDeletionFailure.Defect,
            _ => IdentityDeletionFailure.StaleAuthority,
        });
        if (realm.AuthEpoch <= 0 || realm.RecoveryGeneration < 0 || realm.RecoveryRevision <= 0)
            return IdentityDeletionResult.Refused(IdentityDeletionFailure.Defect);
        if (realm.RealmId != realmId) return IdentityDeletionResult.Refused(IdentityDeletionFailure.StaleAuthority);
        var canonicalRealm = realmId.ToString("D");
        var read = new ModulePlanRead("identity.deletion-current", canonicalRealm,
            [PlanValue.FromText(canonicalRealm), PlanValue.FromText(userId.ToString("D"))]);
        var result = await Read(read, cancellationToken).ConfigureAwait(false);
        if (result.Status != ModulePlanStatus.Succeeded) return IdentityDeletionResult.Refused(result.Status switch
        {
            ModulePlanStatus.Unavailable or ModulePlanStatus.UnknownOutcome => IdentityDeletionFailure.Unavailable,
            ModulePlanStatus.StaleGeneration or ModulePlanStatus.GuardRefused => IdentityDeletionFailure.StaleAuthority,
            _ => IdentityDeletionFailure.Defect,
        });
        if (result.Rows.Count == 0) return IdentityDeletionResult.Refused(IdentityDeletionFailure.NotPending);
        if (result.Rows.Count != 1 || result.Rows[0].Count != 15) return IdentityDeletionResult.Refused(IdentityDeletionFailure.Defect);
        try
        {
            var row = result.Rows[0];
            var lifecycle = new DeletionLifecycle(Id(row[0]), Id(row[1]), Id(row[2]), row[3].AsInt64(), row[4].AsInt64(), row[5].AsText(),
                row[6].AsInt64(), (UserState)checked((int)row[7].AsInt64()), (DeletionState)checked((int)row[8].AsInt64()),
                row[9].AsOptionalInt64(), row[10].AsOptionalInt64(), row[11].AsInt64());
            var userState = row[12].AsInt64();
            var userRevision = row[13].AsInt64();
            if (!lifecycle.HasValidShape() || lifecycle.RealmId != realmId || lifecycle.UserId != userId || userRevision <= 0)
                return IdentityDeletionResult.Refused(IdentityDeletionFailure.Defect);
            if (lifecycle.State != DeletionState.Pending) return IdentityDeletionResult.Refused(IdentityDeletionFailure.NotPending);
            if (userState != (long)UserState.PendingDeletion || row[14].AsOptionalInt64() != lifecycle.RequestedAtMicros)
                return IdentityDeletionResult.Refused(IdentityDeletionFailure.StaleAuthority);
            // Sample after all authority/storage reads; final writes still need the real transaction-clock fence.
            var sampled = UtcMicros.FromDateTimeOffset(time.GetUtcNow()).Value;
            if (sampled < lifecycle.RequestedAtMicros) return IdentityDeletionResult.Refused(IdentityDeletionFailure.StaleAuthority);
            if (!lifecycle.MayCancel(sampled)) return IdentityDeletionResult.Refused(IdentityDeletionFailure.Expired);
            return IdentityDeletionResult.Available(new(lifecycle.DeletionId, realmId, userId, lifecycle.RequestedAtMicros,
                lifecycle.GraceEndsAtMicros, lifecycle.PolicyVersion, lifecycle.GraceSeconds,
                (IdentityDeletionPreviousState)lifecycle.PreviousUserState, lifecycle.Revision, userRevision));
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException or OverflowException)
        {
            return IdentityDeletionResult.Refused(IdentityDeletionFailure.Defect);
        }
    }

    public async Task<IdentityDeletionFamilyResult> PrepareAsync(Guid realmId, Guid userId, string familyId, string planId,
        string ownerScope, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!Guid.TryParseExact(ownerScope, "D", out var scope) || scope == Guid.Empty || ownerScope != scope.ToString("D"))
            return IdentityDeletionFamilyResult.Refused(IdentityDeletionFailure.StaleAuthority);
        var read = await ReadAsync(realmId, userId, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (read.Snapshot is not { } snapshot) return IdentityDeletionFamilyResult.Refused(read.Failure ?? IdentityDeletionFailure.Defect);
        var sampled = UtcMicros.FromDateTimeOffset(time.GetUtcNow()).Value;
        if (sampled < snapshot.RequestedAtMicros) return IdentityDeletionFamilyResult.Refused(IdentityDeletionFailure.StaleAuthority);
        if (sampled >= snapshot.GraceEndsAtMicros) return IdentityDeletionFamilyResult.Refused(IdentityDeletionFailure.Expired);
        IModuleFamilyContributionSet contribution;
        try
        {
            contribution = families.ContributeScoped(familyId, planId, ownerScope,
        [
            new("identity", "authorization", "deletion-current",
                [T(snapshot.DeletionId), T(realmId), T(userId), I(snapshot.RequestedAtMicros),
                    PlanValue.FromText(snapshot.PolicyVersion), I((long)DeletionState.Pending), I(sampled)]),
            new("identity", "authorization", "deletion-user", [T(realmId), T(userId), I((long)UserState.PendingDeletion), I(snapshot.RequestedAtMicros), I(snapshot.UserRevision)]),
            new("identity", "revision", "deletion-revision", [T(snapshot.DeletionId), I(snapshot.LifecycleRevision)]),
        ]);
        }
        catch (ModuleFamilyContributionException exception)
        {
            return IdentityDeletionFamilyResult.Refused(exception.Failure == ModuleFamilyContributionFailure.Unavailable ? IdentityDeletionFailure.Unavailable : IdentityDeletionFailure.StaleAuthority);
        }
        cancellationToken.ThrowIfCancellationRequested();
        return IdentityDeletionFamilyResult.Available(snapshot, contribution);
    }

    private static Guid Id(PlanValue value)
    {
        var text = value.AsText();
        if (!Guid.TryParseExact(text, "D", out var id) || id == Guid.Empty || text != id.ToString("D")) throw new FormatException("Invalid identity shape.");
        return id;
    }

    private static PlanValue T(Guid value) => PlanValue.FromText(value.ToString("D"));
    private static PlanValue I(long value) => PlanValue.FromInt64(value);

    public async Task<DeletionStoredResult<DeletionUserAuthority>> UserAsync(Guid realmId, Guid userId, CancellationToken cancellationToken)
    {
        var result = await Read(new("identity.deletion-user", realmId.ToString("D"), [T(realmId), T(userId)]), cancellationToken).ConfigureAwait(false);
        if (Failure(result.Status) is { } failure) return new(null, failure);
        if (result.Rows.Count == 0) return new(null, IdentityDeletionFailure.StaleAuthority);
        if (result.Rows.Count != 1 || result.Rows[0].Count != 5) return new(null, IdentityDeletionFailure.Defect);
        try
        {
            var row = result.Rows[0];
            var state = row[2].AsInt64();
            var rev = row[4].AsInt64();
            if (Id(row[0]) != realmId || Id(row[1]) != userId || state is < 1 or > 5 || rev <= 0) return new(null, IdentityDeletionFailure.Defect);
            return new(new((UserState)state, rev, row[3].AsOptionalInt64()), null);
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException or OverflowException)
        {
            return new(null, IdentityDeletionFailure.Defect);
        }
    }

    public async Task<DeletionStoredResult<StoredDeletionAuthority>> LifecycleAsync(Guid realmId, Guid userId, Guid deletionId, CancellationToken cancellationToken)
    {
        var result = await Read(new("identity.deletion-state", realmId.ToString("D"), [T(realmId), T(userId), T(deletionId)]), cancellationToken).ConfigureAwait(false);
        if (Failure(result.Status) is { } failure) return new(null, failure);
        if (result.Rows.Count == 0) return new(null, IdentityDeletionFailure.NotPending);
        if (result.Rows.Count != 1 || result.Rows[0].Count != 15) return new(null, IdentityDeletionFailure.Defect);
        try
        {
            var row = result.Rows[0];
            var lifecycle = new DeletionLifecycle(Id(row[0]), Id(row[1]), Id(row[2]), row[3].AsInt64(), row[4].AsInt64(), row[5].AsText(),
                row[6].AsInt64(), (UserState)checked((int)row[7].AsInt64()), (DeletionState)checked((int)row[8].AsInt64()),
                row[9].AsOptionalInt64(), row[10].AsOptionalInt64(), row[11].AsInt64());
            var state = row[12].AsInt64();
            var revision = row[13].AsInt64();
            if (!lifecycle.HasValidShape() || lifecycle.DeletionId != deletionId || lifecycle.RealmId != realmId || lifecycle.UserId != userId
                || state is < 1 or > 5 || revision <= 0) return new(null, IdentityDeletionFailure.Defect);
            return new(new(lifecycle, (UserState)state, revision, row[14].AsOptionalInt64()), null);
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException or OverflowException)
        {
            return new(null, IdentityDeletionFailure.Defect);
        }
    }

    private async Task<ModulePlanOutcome> Read(ModulePlanRead read, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        for (var attempt = 0; ; attempt++)
        {
            ModulePlanOutcome result;
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(2), time);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
            try { result = await plans.ReadAsync(read, linked.Token).ConfigureAwait(false); }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested && deadline.IsCancellationRequested)
            {
                result = ModulePlanOutcome.Of(ModulePlanStatus.Unavailable);
            }
            cancellationToken.ThrowIfCancellationRequested();
            if (result.Status is not (ModulePlanStatus.Unavailable or ModulePlanStatus.UnknownOutcome) || attempt >= 2) return result;
            await Task.Delay(TimeSpan.FromMilliseconds(10 << attempt), time, cancellationToken).ConfigureAwait(false);
        }
    }

    private static IdentityDeletionFailure? Failure(ModulePlanStatus status) => status switch
    {
        ModulePlanStatus.Succeeded => null,
        ModulePlanStatus.Unavailable or ModulePlanStatus.UnknownOutcome => IdentityDeletionFailure.Unavailable,
        ModulePlanStatus.StaleGeneration or ModulePlanStatus.GuardRefused => IdentityDeletionFailure.StaleAuthority,
        _ => IdentityDeletionFailure.Defect,
    };
}
