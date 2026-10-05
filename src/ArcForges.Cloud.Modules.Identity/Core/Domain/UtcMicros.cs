// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Cloud.Modules.Identity.Core.Domain;

/// <summary>
/// An instant as whole microseconds since the Unix epoch in UTC, the precision of every D1 instant of the Cloud data model. The model
/// never reads a clock: every instant it handles is one of these values, taken by the service from the injected time source.
/// </summary>
internal readonly record struct UtcMicros(long Value) : IComparable<UtcMicros>
{
    private const long TicksPerMicrosecond = TimeSpan.TicksPerMillisecond / 1000;

    public static UtcMicros FromDateTimeOffset(DateTimeOffset instant) =>
        new(Math.DivRem(instant.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks, TicksPerMicrosecond, out var remainder)
            - (remainder < 0 ? 1 : 0));

    public int CompareTo(UtcMicros other) => Value.CompareTo(other.Value);

    public static bool operator <(UtcMicros left, UtcMicros right) => left.Value < right.Value;

    public static bool operator >(UtcMicros left, UtcMicros right) => left.Value > right.Value;

    public static bool operator <=(UtcMicros left, UtcMicros right) => left.Value <= right.Value;

    public static bool operator >=(UtcMicros left, UtcMicros right) => left.Value >= right.Value;

    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}