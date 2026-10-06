// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Cloud.Modules.Identity.Recovery.Configuration;

/// <summary>Required policy for a new request only. Existing persisted deadlines never depend on this capture.</summary>
internal sealed class DeletionPolicy
{
    private readonly Lazy<DeletionPolicyCapture> capture;

    public DeletionPolicy(Func<string, string?> environment)
    {
        ArgumentNullException.ThrowIfNull(environment);
        capture = new(() => Parse(environment), LazyThreadSafetyMode.ExecutionAndPublication);
    }

    public DeletionPolicyCapture Capture() => capture.Value;

    internal static bool IsKey(string? value) => value is { Length: > 0 and <= 128 }
        && value.All(character => character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '.' or '_' or ':' or '/' or '-');

    private static DeletionPolicyCapture Parse(Func<string, string?> environment)
    {
        var version = environment("AF_IDENTITY_DELETION_POLICY_VERSION");
        var duration = environment("AF_IDENTITY_DELETION_GRACE_SECONDS");
        if (version is null || duration is null) return new(null, 0, DeletionPolicyFailure.MissingConfiguration);
        if (!IsKey(version) || !long.TryParse(duration, NumberStyles.None, CultureInfo.InvariantCulture, out var seconds)
            || seconds <= 0 || seconds > long.MaxValue / 1_000_000
            || duration != seconds.ToString(CultureInfo.InvariantCulture))
            return new(null, 0, DeletionPolicyFailure.InvalidConfiguration);
        return new(version, seconds, null);
    }
}

internal enum DeletionPolicyFailure { MissingConfiguration, InvalidConfiguration }

internal sealed record DeletionPolicyCapture(string? Version, long GraceSeconds, DeletionPolicyFailure? Failure)
{
    public bool TryGetDeadline(long requestedAtMicros, out long deadlineMicros)
    {
        deadlineMicros = 0;
        if (Failure is not null || requestedAtMicros < 0 || GraceSeconds <= 0) return false;
        try
        {
            deadlineMicros = checked(requestedAtMicros + checked(GraceSeconds * 1_000_000));
            return deadlineMicros > requestedAtMicros;
        }
        catch (OverflowException) { return false; }
    }
}
