// SPDX-License-Identifier: AGPL-3.0-only
using System.Buffers.Binary;

namespace ArcForges.Cloud.Storage.Physical;

/// <summary>
/// Owner-generated canonical sort keys for exact values that SQL must order (Design D1 profile section 2): D1 has no unsigned or
/// decimal type, and the canonical text of such a value does not sort numerically. A key is a byte string whose unsigned
/// byte-wise comparison (the comparison SQLite applies to a BLOB) equals the numeric order; the owner adds the identity as a
/// tie-breaker in its own index. Reference comparator vectors pin the encoding.
/// </summary>
internal static class ExactOrderBytes
{
    public const int Uint64Length = 8;
    public const int DecimalLength = 16;
    private const int DecimalScale = 9;

    /// <summary>Eight big-endian bytes.</summary>
    public static byte[] FromUint64(ulong value)
    {
        var key = new byte[Uint64Length];
        BinaryPrimitives.WriteUInt64BigEndian(key, value);
        return key;
    }

    /// <summary>Eight big-endian bytes of the signed value with the sign bit flipped, so negative values sort before positive ones.</summary>
    public static byte[] FromInt64(long value)
    {
        var key = new byte[Uint64Length];
        BinaryPrimitives.WriteUInt64BigEndian(key, unchecked((ulong)value) ^ 0x8000_0000_0000_0000UL);
        return key;
    }

    /// <summary>
    /// Sixteen bytes: the decimal scaled by 10^9 as a 128-bit integer in offset-binary form. A decimal outside the physical domain
    /// (more than nine fractional digits or more than 28 significant digits) is refused, never rounded.
    /// </summary>
    public static byte[] FromDecimal(decimal value)
    {
        var text = D1Values.FormatDecimal(value);
        var negative = text.StartsWith('-');
        var unsigned = negative ? text[1..] : text;
        var point = unsigned.IndexOf('.', StringComparison.Ordinal);
        var whole = point < 0 ? unsigned : unsigned[..point];
        var fraction = point < 0 ? "" : unsigned[(point + 1)..];
        if (fraction.Length > DecimalScale) throw new PhysicalValueException("A decimal sort key holds at most nine fractional digits.");
        var digits = whole + fraction.PadRight(DecimalScale, '0');
        var magnitude = UInt128.Parse(digits, System.Globalization.CultureInfo.InvariantCulture);
        var signed = negative ? -(Int128)magnitude : (Int128)magnitude;
        var offset = unchecked((UInt128)signed) ^ (UInt128.One << 127);
        var key = new byte[DecimalLength];
        BinaryPrimitives.WriteUInt128BigEndian(key, offset);
        return key;
    }

    public static int Compare(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) => left.SequenceCompareTo(right);
}
