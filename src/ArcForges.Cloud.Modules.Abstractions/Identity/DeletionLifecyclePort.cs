// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

/// <summary>The original permitted user state, captured before deletion; cancellation never upgrades it.</summary>
public enum IdentityDeletionPreviousState { Active = 1, Restricted = 2, Suspended = 3 }

/// <summary>Persisted immutable disclosure and actual current revisions. This data alone is not a write capability.</summary>
public sealed record IdentityDeletionSnapshot(Guid DeletionId, Guid RealmId, Guid UserId, long RequestedAtMicros,
    long GraceEndsAtMicros, string PolicyVersion, long GraceSeconds, IdentityDeletionPreviousState PreviousUserState,
    long LifecycleRevision, long UserRevision);

/// <summary>Safe, closed refusals. No provider, subject, policy value or database detail is disclosed.</summary>
public enum IdentityDeletionFailure { NotPending, Expired, StaleAuthority, Unavailable, Defect }

/// <summary>Exactly one fresh persisted pending snapshot or a refusal.</summary>
public sealed class IdentityDeletionResult
{
    private IdentityDeletionResult(IdentityDeletionSnapshot? snapshot, IdentityDeletionFailure? failure)
    {
        Snapshot = snapshot;
        Failure = failure;
    }

    public IdentityDeletionSnapshot? Snapshot { get; }
    public IdentityDeletionFailure? Failure { get; }

    public static IdentityDeletionResult Available(IdentityDeletionSnapshot snapshot) => new(snapshot ?? throw new ArgumentNullException(nameof(snapshot)), null);

    public static IdentityDeletionResult Refused(IdentityDeletionFailure failure) => Enum.IsDefined(failure)
        ? new(null, failure) : throw new ArgumentOutOfRangeException(nameof(failure));
}

/// <summary>Fresh facts and owner-sealed deadline/revision contribution for one exact registered consumer plan.</summary>
public sealed class IdentityDeletionFamilyResult
{
    private IdentityDeletionFamilyResult(IdentityDeletionSnapshot? snapshot, IModuleFamilyContributionSet? contribution, IdentityDeletionFailure? failure)
    {
        Snapshot = snapshot;
        Contribution = contribution;
        Failure = failure;
    }

    public IdentityDeletionSnapshot? Snapshot { get; }
    public IModuleFamilyContributionSet? Contribution { get; }
    public IdentityDeletionFailure? Failure { get; }

    public static IdentityDeletionFamilyResult Available(IdentityDeletionSnapshot snapshot, IModuleFamilyContributionSet contribution)
        => new(snapshot ?? throw new ArgumentNullException(nameof(snapshot)), contribution ?? throw new ArgumentNullException(nameof(contribution)), null);

    public static IdentityDeletionFamilyResult Refused(IdentityDeletionFailure failure) => Enum.IsDefined(failure)
        ? new(null, null, failure) : throw new ArgumentOutOfRangeException(nameof(failure));
}

/// <summary>Reads the actual original disclosure independently of current new-request policy configuration.</summary>
public interface IIdentityDeletionLifecyclePort
{
    Task<IdentityDeletionResult> ReadAsync(Guid realmId, Guid userId, CancellationToken cancellationToken);

    /// <summary>Re-reads persisted authority before sealing; unknown roles/plans or another issuing factory cannot supply this capability.</summary>
    Task<IdentityDeletionFamilyResult> PrepareAsync(Guid realmId, Guid userId, string familyId, string planId, string ownerScope, CancellationToken cancellationToken);
}
