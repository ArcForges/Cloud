// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;

namespace ArcForges.Cloud.Storage.Physical;

internal enum PhysicalValueKind
{
    Null,
    Integer,
    Unsigned,
    Decimal,
    Text,
    Bytes,
    Boolean,
}

/// <summary>
/// One logical column value before it is encoded for D1, or after it was decoded from a result. The representation is
/// exact: integers, unsigned integers and decimals are never converted to a floating-point number.
/// </summary>
internal readonly struct PhysicalValue : IEquatable<PhysicalValue>
{
    private readonly long integer;
    private readonly ulong unsigned;
    private readonly decimal number;
    private readonly string? text;
    private readonly byte[]? bytes;

    private PhysicalValue(PhysicalValueKind kind, long integer = 0, ulong unsigned = 0, decimal number = 0, string? text = null, byte[]? bytes = null)
    {
        Kind = kind;
        this.integer = integer;
        this.unsigned = unsigned;
        this.number = number;
        this.text = text;
        this.bytes = bytes;
    }

    public PhysicalValueKind Kind { get; }

    public bool IsNull => Kind == PhysicalValueKind.Null;

    public static PhysicalValue Null { get; } = new(PhysicalValueKind.Null);

    public static PhysicalValue FromInt64(long value) => new(PhysicalValueKind.Integer, integer: value);

    public static PhysicalValue FromUint64(ulong value) => new(PhysicalValueKind.Unsigned, unsigned: value);

    public static PhysicalValue FromDecimal(decimal value) => new(PhysicalValueKind.Decimal, number: value);

    public static PhysicalValue FromText(string value) => new(PhysicalValueKind.Text, text: value ?? throw new ArgumentNullException(nameof(value)));

    public static PhysicalValue FromBytes(ReadOnlySpan<byte> value) => new(PhysicalValueKind.Bytes, bytes: value.ToArray());

    public static PhysicalValue FromBool(bool value) => new(PhysicalValueKind.Boolean, integer: value ? 1 : 0);

    /// <summary>A UUID is stored as its canonical lower-case text; no Guid memory layout ever reaches the database.</summary>
    public static PhysicalValue FromId(Guid value) => FromText(value.ToString("D", CultureInfo.InvariantCulture));

    /// <summary>An instant is whole microseconds since the Unix epoch; a value with finer ticks is refused, never truncated.</summary>
    public static PhysicalValue FromInstant(DateTimeOffset value) => FromInt64(InstantMicroseconds.FromInstant(value));

    public long AsInt64() => Kind == PhysicalValueKind.Integer ? integer : throw Mismatch(PhysicalValueKind.Integer);

    public ulong AsUint64() => Kind == PhysicalValueKind.Unsigned ? unsigned : throw Mismatch(PhysicalValueKind.Unsigned);

    public decimal AsDecimal() => Kind == PhysicalValueKind.Decimal ? number : throw Mismatch(PhysicalValueKind.Decimal);

    public string AsText() => Kind == PhysicalValueKind.Text ? text! : throw Mismatch(PhysicalValueKind.Text);

    public bool AsBool() => Kind == PhysicalValueKind.Boolean ? integer == 1 : throw Mismatch(PhysicalValueKind.Boolean);

    public ReadOnlySpan<byte> AsBytes() => Kind == PhysicalValueKind.Bytes ? bytes : throw Mismatch(PhysicalValueKind.Bytes);

    public Guid AsId() => Guid.ParseExact(AsText(), "D");

    public DateTimeOffset AsInstant() => InstantMicroseconds.ToInstant(AsInt64());

    private PhysicalValueException Mismatch(PhysicalValueKind wanted) =>
        new("The value is " + Kind + " but " + wanted + " was requested.");

    public bool Equals(PhysicalValue other) =>
        Kind == other.Kind
        && integer == other.integer
        && unsigned == other.unsigned
        && number == other.number
        && string.Equals(text, other.text, StringComparison.Ordinal)
        && (bytes is null ? other.bytes is null : other.bytes is not null && bytes.AsSpan().SequenceEqual(other.bytes));

    public override bool Equals(object? obj) => obj is PhysicalValue other && Equals(other);

    public override int GetHashCode() => HashCode.Combine(Kind, integer, unsigned, number, text);

    public static bool operator ==(PhysicalValue left, PhysicalValue right) => left.Equals(right);

    public static bool operator !=(PhysicalValue left, PhysicalValue right) => !left.Equals(right);

    public override string ToString() => Kind switch
    {
        PhysicalValueKind.Null => "null",
        PhysicalValueKind.Integer => integer.ToString(CultureInfo.InvariantCulture),
        PhysicalValueKind.Unsigned => unsigned.ToString(CultureInfo.InvariantCulture),
        PhysicalValueKind.Decimal => number.ToString(CultureInfo.InvariantCulture),
        PhysicalValueKind.Boolean => integer == 1 ? "true" : "false",
        PhysicalValueKind.Text => "text",
        _ => "bytes",
    };
}

internal static class InstantMicroseconds
{
    // The range of whole microseconds representable as DateTimeOffset ticks (0001-01-01 to 9999-12-31).
    private const long TicksPerMicrosecond = 10;

    public static long FromInstant(DateTimeOffset value)
    {
        var utc = value.UtcDateTime;
        var ticks = utc.Ticks - DateTime.UnixEpoch.Ticks;
        if (ticks % TicksPerMicrosecond != 0) throw new PhysicalValueException("An instant is stored as whole microseconds; this value has finer ticks.");
        return ticks / TicksPerMicrosecond;
    }

    public static DateTimeOffset ToInstant(long microseconds)
    {
        var minimum = (DateTime.MinValue.Ticks - DateTime.UnixEpoch.Ticks) / TicksPerMicrosecond;
        var maximum = (DateTime.MaxValue.Ticks - DateTime.UnixEpoch.Ticks) / TicksPerMicrosecond;
        if (microseconds < minimum || microseconds > maximum) throw new PhysicalValueException("The stored instant is outside the representable range.");
        return new DateTimeOffset(DateTime.UnixEpoch.Ticks + (microseconds * TicksPerMicrosecond), TimeSpan.Zero);
    }
}
