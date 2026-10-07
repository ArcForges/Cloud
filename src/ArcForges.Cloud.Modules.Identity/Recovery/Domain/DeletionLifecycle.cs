// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Recovery.Configuration;

namespace ArcForges.Cloud.Modules.Identity.Recovery.Domain;

internal enum DeletionState { Pending = 1, Cancelled = 2, Purging = 3, Purged = 4 }

/// <summary>Stored lifecycle facts. A new request captures policy once; cancellation restores the captured state.</summary>
internal sealed record DeletionLifecycle(Guid DeletionId, Guid RealmId, Guid UserId, long RequestedAtMicros,
    long GraceEndsAtMicros, string PolicyVersion, long GraceSeconds, UserState PreviousUserState,
    DeletionState State, long? CancelledAtMicros, long? CompletedAtMicros, long Revision)
{
    public bool HasValidShape()
    {
        if (DeletionId == Guid.Empty || RealmId == Guid.Empty || UserId == Guid.Empty || RequestedAtMicros < 0
            || GraceEndsAtMicros <= RequestedAtMicros || !DeletionPolicy.IsKey(PolicyVersion) || GraceSeconds <= 0
            || PreviousUserState is not (UserState.Active or UserState.Restricted or UserState.Suspended) || Revision <= 0)
            return false;
        try
        {
            if (checked(RequestedAtMicros + checked(GraceSeconds * 1_000_000)) != GraceEndsAtMicros) return false;
        }
        catch (OverflowException) { return false; }
        return State switch
        {
            DeletionState.Pending or DeletionState.Purging => CancelledAtMicros is null && CompletedAtMicros is null,
            DeletionState.Cancelled => CancelledAtMicros is { } cancelled && cancelled >= RequestedAtMicros
                && cancelled < GraceEndsAtMicros && CompletedAtMicros is null,
            DeletionState.Purged => CompletedAtMicros is { } completed && completed >= GraceEndsAtMicros && CancelledAtMicros is null,
            _ => false,
        };
    }

    public bool MayCancel(long atMicros) => HasValidShape() && State == DeletionState.Pending
        && atMicros >= RequestedAtMicros && atMicros < GraceEndsAtMicros;

    public bool MayBeginPurge(long atMicros) => HasValidShape() && State == DeletionState.Pending && atMicros >= GraceEndsAtMicros;

    public bool MayCompletePurge(long atMicros) => HasValidShape() && State == DeletionState.Purging && atMicros >= GraceEndsAtMicros;
}
