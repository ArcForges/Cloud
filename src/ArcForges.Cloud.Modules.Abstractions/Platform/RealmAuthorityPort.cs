// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

/// <summary>Required deployment realm/authentication epoch bound to the real current/open persisted recovery authority.</summary>
public sealed record RealmAuthoritySnapshot(Guid RealmId, long AuthEpoch, long RecoveryGeneration, long RecoveryRevision);

/// <summary>Closed security-authority refusals, without environment values, credentials or provider diagnostics.</summary>
public enum RealmAuthorityFailure
{
    MissingConfiguration,
    InvalidConfiguration,
    MissingRecovery,
    ClosedRecovery,
    StaleGeneration,
    Unavailable,
    Defect,
}

/// <summary>Exactly one usable snapshot or one refusal; no default realm, epoch or generation exists.</summary>
public sealed class RealmAuthorityResult
{
    private RealmAuthorityResult(RealmAuthoritySnapshot? snapshot, RealmAuthorityFailure? failure)
    {
        Snapshot = snapshot;
        Failure = failure;
    }

    public RealmAuthoritySnapshot? Snapshot { get; }

    public RealmAuthorityFailure? Failure { get; }

    public static RealmAuthorityResult Available(RealmAuthoritySnapshot snapshot) => new(snapshot ?? throw new ArgumentNullException(nameof(snapshot)), null);

    public static RealmAuthorityResult Refused(RealmAuthorityFailure failure) => new(null, failure);
}

/// <summary>Resolves one configured realm's authority afresh from storage; callers cannot select another realm or override epochs.</summary>
public interface IRealmAuthorityPort
{
    Task<RealmAuthorityResult> ResolveAsync(CancellationToken cancellationToken);
}
