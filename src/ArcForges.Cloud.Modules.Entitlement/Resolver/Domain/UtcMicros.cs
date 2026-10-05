// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Cloud.Modules.Entitlement.Resolver.Domain;

/// <summary>
/// An instant as whole microseconds since the Unix epoch in UTC, the precision of every D1 instant of the Cloud data model. The
/// resolver never reads a clock and never sees a local time zone: every instant it handles is one of these values, supplied by the
/// single authoritative time source (EN-08).
/// </summary>
internal readonly record struct UtcMicros(long Value) : IComparable<UtcMicros>
{
    private const long TicksPerMicrosecond = TimeSpan.TicksPerMillisecond / 1000;

    public static UtcMicros FromDateTimeOffset(DateTimeOffset instant) =>
        new(Math.DivRem(instant.UtcTicks - DateTimeOffset.UnixEpoch.UtcTicks, TicksPerMicrosecond, out var remainder)
            - (remainder < 0 ? 1 : 0));

    public DateTimeOffset ToDateTimeOffset() =>
        new(DateTimeOffset.UnixEpoch.UtcTicks + (Value * TicksPerMicrosecond), TimeSpan.Zero);

    public int CompareTo(UtcMicros other) => Value.CompareTo(other.Value);

    public static bool operator <(UtcMicros left, UtcMicros right) => left.Value < right.Value;

    public static bool operator >(UtcMicros left, UtcMicros right) => left.Value > right.Value;

    public static bool operator <=(UtcMicros left, UtcMicros right) => left.Value <= right.Value;

    public static bool operator >=(UtcMicros left, UtcMicros right) => left.Value >= right.Value;

    public static UtcMicros Max(UtcMicros left, UtcMicros right) => left >= right ? left : right;

    public static UtcMicros Min(UtcMicros left, UtcMicros right) => left <= right ? left : right;

    public override string ToString() => Value.ToString(CultureInfo.InvariantCulture);
}
