// SPDX-License-Identifier: AGPL-3.0-only
namespace ArcForges.Cloud.Modules;

/// <summary>The current open persisted Platform recovery authority, never a caller's expected generation.</summary>
public sealed record RecoveryEpochSnapshot(Guid RealmId, long Generation, long Revision);

/// <summary>Closed reasons why persisted recovery authority cannot be used. Failed reads never mean a missing row.</summary>
public enum RecoveryEpochFailure
{
    InvalidRealm,
    Missing,
    Closed,
    StaleGeneration,
    Unavailable,
    Defect,
}

/// <summary>Exactly one usable snapshot or one refusal; construction cannot represent success and failure together.</summary>
public sealed class RecoveryEpochResult
{
    private RecoveryEpochResult(RecoveryEpochSnapshot? snapshot, RecoveryEpochFailure? failure)
    {
        Snapshot = snapshot;
        Failure = failure;
    }

    public RecoveryEpochSnapshot? Snapshot { get; }

    public RecoveryEpochFailure? Failure { get; }

    public static RecoveryEpochResult Available(RecoveryEpochSnapshot snapshot) => new(snapshot ?? throw new ArgumentNullException(nameof(snapshot)), null);

    public static RecoveryEpochResult Refused(RecoveryEpochFailure failure) => new(null, failure);
}

/// <summary>Platform owns the exact bounded persisted read. Consumers cannot supply an epoch or a successful-read flag.</summary>
public interface IRecoveryEpochPort
{
    Task<RecoveryEpochResult> ReadAsync(Guid realmId, CancellationToken cancellationToken);
}
