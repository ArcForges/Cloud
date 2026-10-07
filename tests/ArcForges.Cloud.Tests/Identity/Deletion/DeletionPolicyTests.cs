// SPDX-License-Identifier: AGPL-3.0-only
using ArcForges.Cloud.Modules.Identity.Core.Domain;
using ArcForges.Cloud.Modules.Identity.Recovery.Configuration;
using ArcForges.Cloud.Modules.Identity.Recovery.Domain;
using Xunit;

namespace ArcForges.Cloud.Tests.Deletion;

public sealed class DeletionPolicyTests
{
    [Theory]
    [InlineData(null, "30", 0)]
    [InlineData("policy.v1", null, 0)]
    [InlineData("", "30", 1)]
    [InlineData("bad policy", "30", 1)]
    [InlineData("policy.v1", "0", 1)]
    [InlineData("policy.v1", "-1", 1)]
    [InlineData("policy.v1", "01", 1)]
    [InlineData("policy.v1", "+1", 1)]
    [InlineData("policy.v1", " 1", 1)]
    [InlineData("policy.v1", "9223372036855", 1)]
    public void RequiredCanonicalConfigurationHasNoFallback(string? version, string? seconds, int failure)
    {
        var policy = new DeletionPolicy(key => key.EndsWith("VERSION", StringComparison.Ordinal) ? version : seconds);
        var value = policy.Capture();
        Assert.Equal((DeletionPolicyFailure)failure, value.Failure);
        Assert.False(value.TryGetDeadline(100, out _));
    }

    [Fact]
    public async Task CaptureIsLazyImmutableAndConcurrent()
    {
        var calls = 0;
        var version = "policy.v1";
        var seconds = "30";
        var policy = new DeletionPolicy(key => { Interlocked.Increment(ref calls); return key.EndsWith("VERSION", StringComparison.Ordinal) ? version : seconds; });
        Assert.Equal(0, calls);
        var captures = await Task.WhenAll(Enumerable.Range(0, 32).Select(_ => Task.Run(policy.Capture)));
        Assert.Equal(2, calls);
        Assert.All(captures, value => Assert.Same(captures[0], value));
        version = "policy.v2";
        seconds = "999";
        Assert.Equal("policy.v1", policy.Capture().Version);
        Assert.Equal(30, policy.Capture().GraceSeconds);
    }

    [Fact]
    public void DeadlineUsesCheckedIntegerMicroseconds()
    {
        var policy = new DeletionPolicy(_ => "1").Capture();
        Assert.True(policy.TryGetDeadline(42, out var deadline));
        Assert.Equal(1_000_042, deadline);
        Assert.False(policy.TryGetDeadline(long.MaxValue, out _));
        Assert.False(policy.TryGetDeadline(-1, out _));
    }

    [Fact]
    public void PendingDeadlineAndOriginalStateAreNotRecomputed()
    {
        var row = Row();
        Assert.True(row.HasValidShape());
        Assert.True(row.MayCancel(1_000_009));
        Assert.False(row.MayCancel(1_000_010));
        Assert.True(row.MayBeginPurge(1_000_010));
        var cancelled = row with { State = DeletionState.Cancelled, CancelledAtMicros = 100, Revision = 2 };
        Assert.True(cancelled.HasValidShape());
        Assert.Equal(UserState.Suspended, cancelled.PreviousUserState);
        Assert.False(cancelled.MayCancel(100));
        Assert.False(cancelled.MayBeginPurge(2_000_000));
        var purging = row with { State = DeletionState.Purging, Revision = 2 };
        Assert.True(purging.MayCompletePurge(1_000_010));
        Assert.False(purging.MayCompletePurge(1_000_009));
        Assert.True((purging with { State = DeletionState.Purged, CompletedAtMicros = 1_000_010, Revision = 3 }).HasValidShape());
    }

    [Fact]
    public void InvalidTerminalFactsDurationAndRestorationStateAreRefused()
    {
        var row = Row();
        Assert.False((row with { GraceEndsAtMicros = row.GraceEndsAtMicros + 1 }).HasValidShape());
        Assert.False((row with { GraceSeconds = long.MaxValue }).HasValidShape());
        Assert.False((row with { PreviousUserState = UserState.Deleted }).HasValidShape());
        Assert.False((row with { CancelledAtMicros = 100 }).HasValidShape());
        Assert.False((row with { State = DeletionState.Cancelled }).HasValidShape());
        Assert.False((row with { State = DeletionState.Cancelled, CancelledAtMicros = row.GraceEndsAtMicros }).HasValidShape());
        Assert.False((row with { State = DeletionState.Purged, CompletedAtMicros = row.GraceEndsAtMicros - 1 }).HasValidShape());
        Assert.False((row with { Revision = 0 }).HasValidShape());
    }

    private static DeletionLifecycle Row() => new(Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
        Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc"),
        10, 1_000_010, "policy.v1", 1, UserState.Suspended, DeletionState.Pending, null, null, 1);
}
