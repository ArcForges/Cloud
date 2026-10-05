// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using ArcForges.Cloud.Hmac;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage;

/// <summary>
/// Exact construction and strict parsing of the generated D1 scalar union. 64-bit integers and decimals
/// are canonical text end to end; no floating-point or locale-dependent path exists.
/// </summary>
internal static class D1Values
{
    public const int MaxDecimalDigits = 28;
    public const int MaxDecimalFraction = 9;

    public static D1Scalar Null() => new D1ScalarD1NullValue(new D1NullValue { Kind = "null" });

    public static D1Scalar Bool(bool value) => new D1ScalarD1BooleanValue(new D1BooleanValue { Kind = "boolean", Value = value });

    public static D1Scalar Int64(long value) => new D1ScalarD1Int64Value(new D1Int64Value { Kind = "int64", Value = value.ToString(CultureInfo.InvariantCulture) });

    public static D1Scalar Uint64(ulong value) => new D1ScalarD1Uint64Value(new D1Uint64Value { Kind = "uint64", Value = value.ToString(CultureInfo.InvariantCulture) });

    public static D1Scalar Decimal(decimal value) => new D1ScalarD1DecimalValue(new D1DecimalValue { Kind = "decimal", Value = FormatDecimal(value) });

    public static D1Scalar Text(string value) => new D1ScalarD1TextValue(new D1TextValue { Kind = "text", Value = value });

    public static D1Scalar Bytes(ReadOnlySpan<byte> value) => new D1ScalarD1BytesValue(new D1BytesValue { Kind = "bytes", Value = Base64Url.Encode(value) });

    public static bool IsNull(D1Scalar? scalar) => scalar is D1ScalarD1NullValue;

    public static bool TryGetInt64(D1Scalar? scalar, out long value)
    {
        value = 0;
        return scalar is D1ScalarD1Int64Value item && TryParseInt64(item.Value.Value, out value);
    }

    public static bool TryGetUint64(D1Scalar? scalar, out ulong value)
    {
        value = 0;
        return scalar is D1ScalarD1Uint64Value item && TryParseUint64(item.Value.Value, out value);
    }

    public static bool TryGetDecimal(D1Scalar? scalar, out decimal value)
    {
        value = 0;
        return scalar is D1ScalarD1DecimalValue item && TryParseDecimal(item.Value.Value, out value);
    }

    public static bool TryGetText(D1Scalar? scalar, out string value)
    {
        value = "";
        if (scalar is not D1ScalarD1TextValue item) return false;
        value = item.Value.Value;
        return true;
    }

    public static bool TryGetBytes(D1Scalar? scalar, out byte[] value)
    {
        value = [];
        return scalar is D1ScalarD1BytesValue item && Base64Url.TryDecode(item.Value.Value, out value);
    }

    public static bool TryGetBool(D1Scalar? scalar, out bool value)
    {
        value = false;
        if (scalar is not D1ScalarD1BooleanValue item) return false;
        value = item.Value.Value;
        return true;
    }

    /// <summary>Plain digits with an optional minus: no plus, no leading zero, no negative zero; the range is exact.</summary>
    public static bool TryParseInt64(string? text, out long value)
    {
        value = 0;
        if (!IsCanonicalInteger(text, signed: true)) return false;
        return long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);
    }

    public static bool TryParseUint64(string? text, out ulong value)
    {
        value = 0;
        if (!IsCanonicalInteger(text, signed: false)) return false;
        return ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out value);
    }

    /// <summary>
    /// <c>-?(0|[1-9][0-9]*)(\.[0-9]{1,9})?</c>, no trailing fractional zero, no negative zero and at most 28 significant digits.
    /// </summary>
    public static bool TryParseDecimal(string? text, out decimal value)
    {
        value = 0;
        if (!IsCanonicalDecimal(text)) return false;
        return decimal.TryParse(text, NumberStyles.AllowLeadingSign | NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture, out value);
    }

    public static bool IsCanonicalDecimal(string? text)
    {
        if (text is null || text.Length is 0 or > 64) return false;
        var index = text[0] == '-' ? 1 : 0;
        var integerStart = index;
        while (index < text.Length && text[index] is >= '0' and <= '9') index++;
        var integerLength = index - integerStart;
        if (integerLength == 0 || (text[integerStart] == '0' && integerLength > 1)) return false;
        var significant = text.AsSpan(integerStart, integerLength).TrimStart('0').Length;
        var fractionLength = 0;
        if (index < text.Length)
        {
            if (text[index] != '.') return false;
            index++;
            var fractionStart = index;
            while (index < text.Length && text[index] is >= '0' and <= '9') index++;
            fractionLength = index - fractionStart;
            if (fractionLength is < 1 or > MaxDecimalFraction || index != text.Length || text[^1] == '0') return false;
            significant = significant > 0 ? significant + fractionLength : text.AsSpan(fractionStart, fractionLength).TrimStart('0').Length;
        }

        if (text[0] == '-' && text.AsSpan().IndexOfAnyInRange('1', '9') < 0) return false;
        return significant <= MaxDecimalDigits;
    }

    /// <summary>The canonical text of an exact decimal; a value outside the contract domain is refused, never rounded.</summary>
    public static string FormatDecimal(decimal value)
    {
        var text = value.ToString(CultureInfo.InvariantCulture);
        if (text.Contains('.', StringComparison.Ordinal)) text = text.TrimEnd('0').TrimEnd('.');
        if (text is "" or "-" or "-0") text = "0";
        if (!IsCanonicalDecimal(text)) throw new ArgumentOutOfRangeException(nameof(value), "The decimal is outside the canonical D1 domain.");
        return text;
    }

    private static bool IsCanonicalInteger(string? text, bool signed)
    {
        if (text is null || text.Length is 0 or > 20) return false;
        var start = signed && text[0] == '-' ? 1 : 0;
        if (start == text.Length) return false;
        for (var index = start; index < text.Length; index++)
        {
            if (text[index] is < '0' or > '9') return false;
        }

        if (text[start] == '0') return text.Length == 1;
        return true;
    }
}
