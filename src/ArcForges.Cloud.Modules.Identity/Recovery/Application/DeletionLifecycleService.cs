// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Recovery.Configuration;
using ArcForges.Cloud.Modules.Identity.Recovery.Domain;

namespace ArcForges.Cloud.Modules.Identity.Recovery.Application;

internal sealed record DeletionUserAuthority(UserState State, long Revision, long? RequestedAtMicros);
internal sealed record StoredDeletionAuthority(DeletionLifecycle Lifecycle, UserState UserState, long UserRevision, long? UserRequestedAtMicros = null);
internal sealed record DeletionStoredResult<T>(T? Value, IdentityDeletionFailure? Failure) where T : class;

/// <summary>Actual Identity reads; no caller-supplied state/revision or policy can stand in for persistence.</summary>
internal interface IDeletionTransitionStore
{
    Task<DeletionStoredResult<DeletionUserAuthority>> UserAsync(Guid realmId, Guid userId, CancellationToken cancellationToken);
    Task<DeletionStoredResult<StoredDeletionAuthority>> LifecycleAsync(Guid realmId, Guid userId, Guid deletionId, CancellationToken cancellationToken);
}

internal enum DeletionTransition { Request, Cancel, BeginPurge, CompletePurge }
internal sealed record DeletionTransitionTarget(DeletionTransition Transition, Guid RealmId, Guid UserId, Guid DeletionId, string OwnerScope);
internal sealed record DeletionTransitionPreparation(DeletionLifecycle Lifecycle, long UserRevision, RealmAuthoritySnapshot Authority,
    IModuleFamilyContributionSet Contribution);
internal sealed record DeletionTransitionResult(DeletionTransitionPreparation? Value, IdentityDeletionFailure? Failure);

/// <summary>
/// Prepares only actual own lifecycle/User effects. It cannot execute a complete deletion transaction or attest provider purge;
/// CLOUD17 supplies the real action proof, revocation owners, durable notice, cleanup receipts and commit tail.
/// </summary>
internal sealed class DeletionLifecycleService(IDeletionTransitionStore store, DeletionPolicy policy,
    IRealmAuthorityPort authority, IModuleFamilyPort families, TimeProvider time)
{
    public async Task<DeletionTransitionResult> PrepareAsync(DeletionTransitionTarget target, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(target);
        if (target.RealmId == Guid.Empty || target.UserId == Guid.Empty || target.DeletionId == Guid.Empty
            || !Guid.TryParseExact(target.OwnerScope, "D", out var scope) || scope == Guid.Empty || target.OwnerScope != scope.ToString("D")
            || !Enum.IsDefined(target.Transition)) return Refused(IdentityDeletionFailure.StaleAuthority);
        var current = await authority.ResolveAsync(cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (current.Snapshot is not { } realm) return Refused(current.Failure switch
        {
            RealmAuthorityFailure.MissingConfiguration or RealmAuthorityFailure.InvalidConfiguration or RealmAuthorityFailure.Unavailable => IdentityDeletionFailure.Unavailable,
            RealmAuthorityFailure.Defect or null => IdentityDeletionFailure.Defect,
            _ => IdentityDeletionFailure.StaleAuthority,
        });
        if (realm.RealmId != target.RealmId) return Refused(IdentityDeletionFailure.StaleAuthority);
        if (realm.AuthEpoch <= 0 || realm.RecoveryGeneration < 0 || realm.RecoveryRevision <= 0) return Refused(IdentityDeletionFailure.Defect);
        DeletionLifecycle lifecycle;
        long userRevision;
        IReadOnlyList<ModuleFamilyContribution> own;
        string plan;
        if (target.Transition == DeletionTransition.Request)
        {
            var user = await store.UserAsync(target.RealmId, target.UserId, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (user.Value is not { } stored) return Refused(user.Failure ?? IdentityDeletionFailure.Defect);
            if (stored.State is not (UserState.Active or UserState.Restricted or UserState.Suspended) || stored.RequestedAtMicros is not null)
                return Refused(IdentityDeletionFailure.StaleAuthority);
            if (stored.Revision is <= 0 or long.MaxValue) return Refused(IdentityDeletionFailure.Defect);
            var configuration = policy.Capture();
            if (configuration.Failure is not null) return Refused(IdentityDeletionFailure.Unavailable);
            var sampled = Now();
            if (!configuration.TryGetDeadline(sampled, out var deadline)) return Refused(IdentityDeletionFailure.Defect);
            lifecycle = new(target.DeletionId, target.RealmId, target.UserId, sampled, deadline, configuration.Version!,
                configuration.GraceSeconds, stored.State, DeletionState.Pending, null, null, 1);
            if (!lifecycle.HasValidShape()) return Refused(IdentityDeletionFailure.Defect);
            userRevision = stored.Revision;
            own =
            [
                new("identity", "authorization", "deletion-request-user", [T(target.RealmId), T(target.UserId), I((long)stored.State), I(userRevision)]),
                new("identity", "revision", "deletion-pending-empty", [T(target.UserId), I((long)DeletionState.Pending), I(0)]),
                new("identity", "revision", "deletion-purging-empty", [T(target.UserId), I((long)DeletionState.Purging), I(0)]),
                new("identity", "revision", "deletion-revision", [T(target.DeletionId), I(0)]),
                new("identity", "record", "deletion-user", [I(sampled), T(target.UserId), I(userRevision)]),
                new("identity", "record", "deletion-lifecycle", [T(target.DeletionId), T(target.RealmId), T(target.UserId), I(sampled), I(deadline),
                    PlanValue.FromText(lifecycle.PolicyVersion), I(lifecycle.GraceSeconds), I((long)lifecycle.PreviousUserState)]),
            ];
            plan = "families.account-security.request-deletion";
        }
        else
        {
            var read = await store.LifecycleAsync(target.RealmId, target.UserId, target.DeletionId, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            if (read.Value is not { } stored) return Refused(read.Failure ?? IdentityDeletionFailure.Defect);
            lifecycle = stored.Lifecycle;
            userRevision = stored.UserRevision;
            if (!lifecycle.HasValidShape() || lifecycle.RealmId != target.RealmId || lifecycle.UserId != target.UserId
                || lifecycle.DeletionId != target.DeletionId || lifecycle.Revision == long.MaxValue || userRevision is <= 0 or long.MaxValue)
                return Refused(IdentityDeletionFailure.Defect);
            if (stored.UserState != UserState.PendingDeletion || stored.UserRequestedAtMicros != lifecycle.RequestedAtMicros)
                return Refused(IdentityDeletionFailure.StaleAuthority);
            var sampled = Now();
            if (sampled < lifecycle.RequestedAtMicros) return Refused(IdentityDeletionFailure.StaleAuthority);
            var cancellation = target.Transition == DeletionTransition.Cancel;
            if (cancellation && !lifecycle.MayCancel(sampled)) return Refused(lifecycle.State == DeletionState.Pending
                ? IdentityDeletionFailure.Expired : IdentityDeletionFailure.NotPending);
            if (target.Transition == DeletionTransition.BeginPurge && !lifecycle.MayBeginPurge(sampled)) return Refused(IdentityDeletionFailure.NotPending);
            if (target.Transition == DeletionTransition.CompletePurge && !lifecycle.MayCompletePurge(sampled)) return Refused(IdentityDeletionFailure.NotPending);
            var authorization = cancellation ? "deletion-current" : target.Transition == DeletionTransition.BeginPurge ? "deletion-due" : "deletion-purging";
            PlanValue[] bindings = [T(lifecycle.DeletionId), T(target.RealmId), T(target.UserId), I(lifecycle.RequestedAtMicros),
                PlanValue.FromText(lifecycle.PolicyVersion), I((long)lifecycle.State)];
            // Expiry fences also bind the captured server sample; due fences use only the actual database clock.
            if (cancellation) bindings = [.. bindings, I(sampled)];
            var list = new List<ModuleFamilyContribution>
            {
                new("identity", "authorization", authorization, bindings),
                new("identity", "authorization", "deletion-user", [T(target.RealmId), T(target.UserId), I((long)UserState.PendingDeletion), I(lifecycle.RequestedAtMicros), I(userRevision)]),
                new("identity", "revision", "deletion-revision", [T(lifecycle.DeletionId), I(lifecycle.Revision)]),
            };
            if (cancellation)
            {
                list.Add(new("identity", "record", "deletion-user", [I((long)lifecycle.PreviousUserState), T(target.UserId), I(userRevision)]));
                list.Add(new("identity", "record", "deletion-lifecycle", [I(sampled), T(target.DeletionId), I(lifecycle.Revision)]));
                plan = "families.account-security.cancel-deletion";
            }
            else if (target.Transition == DeletionTransition.BeginPurge)
            {
                list.Add(new("identity", "record", "deletion-lifecycle", [T(target.DeletionId), I(lifecycle.Revision)]));
                plan = "families.account-security.begin-deletion-purge";
            }
            else
            {
                list.Add(new("identity", "record", "deletion-user", [T(target.UserId), I(userRevision)]));
                list.Add(new("identity", "record", "deletion-lifecycle", [I(sampled), T(target.DeletionId), I(lifecycle.Revision)]));
                plan = "families.account-security.complete-deletion-purge";
            }
            own = list;
        }
        cancellationToken.ThrowIfCancellationRequested();
        IModuleFamilyContributionSet contribution;
        try { contribution = families.ContributeScoped("account-security", plan, target.OwnerScope, own); }
        catch (ModuleFamilyContributionException exception)
        {
            return Refused(exception.Failure == ModuleFamilyContributionFailure.Unavailable ? IdentityDeletionFailure.Unavailable : IdentityDeletionFailure.StaleAuthority);
        }
        cancellationToken.ThrowIfCancellationRequested();
        return new(new(lifecycle, userRevision, realm, contribution), null);
    }

    private long Now() => UtcMicros.FromDateTimeOffset(time.GetUtcNow()).Value;
    private static DeletionTransitionResult Refused(IdentityDeletionFailure failure) => new(null, failure);
    private static PlanValue T(Guid value) => PlanValue.FromText(value.ToString("D"));
    private static PlanValue I(long value) => PlanValue.FromInt64(value);
}
