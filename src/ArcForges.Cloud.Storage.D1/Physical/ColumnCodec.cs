// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text;
using System.Text.Json;
using ArcForges.Contracts.CloudInternal.Storage.V1;

namespace ArcForges.Cloud.Storage.Physical;

/// <summary>
/// The typed exact bind and result adapter of one physical column. It turns a logical value into the generated D1 scalar the
/// named-plan bridge carries, and back. Every limit the stored representation has is checked here as well as by the database
/// check: D1 stores 64-bit integers as signed 64-bit only, has no unsigned or decimal type (both are canonical text), keeps JSON
/// as validated text and returns integers that a JavaScript number cannot hold, so no value takes a floating-point path.
/// </summary>
internal static class ColumnCodec
{
    public const int MaxBytes = 262144;
    public const int MaxJsonDepth = 64;
    public const int KeyMaxLength = 128;
    public const int ModelIdMaxLength = 256;
    public const int HashLength = 32;

    private static readonly UTF8Encoding Strict = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    /// <summary>The plan parameter kind a column is bound and read as.</summary>
    public static PlanKind PlanKindOf(PhysicalColumn column) => column.Kind switch
    {
        PhysicalKind.Id or PhysicalKind.Text or PhysicalKind.Key or PhysicalKind.ProductId or PhysicalKind.ModelId or PhysicalKind.Currency or PhysicalKind.Json => PlanKind.Text,
        PhysicalKind.Bool => PlanKind.Bool,
        PhysicalKind.Int32 or PhysicalKind.Int64 or PhysicalKind.Rev or PhysicalKind.Instant or PhysicalKind.Enum => PlanKind.Int64,
        PhysicalKind.Uint64 => PlanKind.Uint64,
        PhysicalKind.Decimal => PlanKind.Decimal,
        _ => PlanKind.Bytes,
    };

    public static PlanParam ParamOf(PhysicalColumn column) => new(PlanKindOf(column), column.Nullable);

    /// <summary>Validates the value against the column and returns the exact scalar to bind. Throws before anything is sent.</summary>
    public static D1Scalar Encode(PhysicalColumn column, PhysicalValue value)
    {
        ArgumentNullException.ThrowIfNull(column);
        if (value.IsNull)
        {
            if (!column.Nullable) throw new PhysicalValueException("The column " + column.Name + " is not nullable.");
            return D1Values.Null();
        }

        switch (column.Kind)
        {
            case PhysicalKind.Id:
                return D1Values.Text(RequireId(column, value.AsText()));
            case PhysicalKind.Text:
                return D1Values.Text(RequireText(column, value.AsText()));
            case PhysicalKind.Key:
                return D1Values.Text(RequireKey(column, value.AsText()));
            case PhysicalKind.ProductId:
                return D1Values.Text(RequireProduct(column, value.AsText()));
            case PhysicalKind.ModelId:
                return D1Values.Text(RequireModelId(column, value.AsText()));
            case PhysicalKind.Currency:
                return D1Values.Text(RequireCurrency(column, value.AsText()));
            case PhysicalKind.Bool:
                return D1Values.Bool(value.AsBool());
            case PhysicalKind.Int32:
                {
                    var number = value.AsInt64();
                    if (number is < int.MinValue or > int.MaxValue) throw new PhysicalValueException("The column " + column.Name + " is a 32-bit integer.");
                    return D1Values.Int64(number);
                }

            case PhysicalKind.Int64:
            case PhysicalKind.Instant:
                return D1Values.Int64(value.AsInt64());
            case PhysicalKind.Rev:
                {
                    var number = value.AsInt64();
                    if (number < 0) throw new PhysicalValueException("The column " + column.Name + " is a non-negative revision.");
                    return D1Values.Int64(number);
                }

            case PhysicalKind.Uint64:
                return D1Values.Uint64(value.AsUint64());
            case PhysicalKind.Decimal:
                return EncodeDecimal(column, value.AsDecimal());
            case PhysicalKind.Hash:
                {
                    var bytes = value.AsBytes();
                    if (bytes.Length != HashLength) throw new PhysicalValueException("The column " + column.Name + " is exactly 32 bytes.");
                    return D1Values.Bytes(bytes);
                }

            case PhysicalKind.Bytes:
            case PhysicalKind.Proto:
                {
                    var bytes = value.AsBytes();
                    if (bytes.Length > MaxBytes) throw new PhysicalValueException("The column " + column.Name + " is at most 256 KiB.");
                    return D1Values.Bytes(bytes);
                }

            case PhysicalKind.Json:
                return D1Values.Text(RequireJson(column, value.AsText()));
            case PhysicalKind.Enum:
                {
                    var registered = PhysicalSchema.FindEnum(column.EnumName ?? throw new PhysicalValueException("The enum column has no registry name."));
                    var number = value.AsInt64();
                    if (number is < 1 or > ushort.MaxValue || !registered.TryGetName((int)number, out _))
                        throw new PhysicalValueException("The number " + number.ToString(CultureInfo.InvariantCulture) + " is not registered in " + registered.Name + ".");
                    return D1Values.Int64(number);
                }

            default:
                throw new PhysicalValueException("Unsupported column kind.");
        }
    }

    /// <summary>A named member of the column's enum as the value to bind.</summary>
    public static PhysicalValue EnumByName(PhysicalColumn column, string name)
    {
        ArgumentNullException.ThrowIfNull(column);
        var registered = PhysicalSchema.FindEnum(column.EnumName ?? throw new PhysicalValueException("The column is not an enum."));
        return registered.TryGetNumber(name, out var number)
            ? PhysicalValue.FromInt64(number)
            : throw new PhysicalValueException("The enum " + registered.Name + " has no member " + name + ".");
    }

    /// <summary>
    /// Reads a result scalar strictly. A kind or shape the column cannot hold is a defect (a plan returned something the schema
    /// forbids), never a client error. An enum number that is not registered is refused unless the registry entry preserves unknowns.
    /// </summary>
    public static PhysicalValue Decode(PhysicalColumn column, D1Scalar? scalar)
    {
        ArgumentNullException.ThrowIfNull(column);
        if (scalar is null) throw new PhysicalValueException("The result has no scalar for " + column.Name + ".");
        if (D1Values.IsNull(scalar))
            return column.Nullable ? PhysicalValue.Null : throw new PhysicalValueException("The column " + column.Name + " returned null but is not nullable.");
        switch (column.Kind)
        {
            case PhysicalKind.Id:
                return PhysicalValue.FromText(RequireId(column, Text(column, scalar)));
            case PhysicalKind.Text:
                return PhysicalValue.FromText(RequireText(column, Text(column, scalar)));
            case PhysicalKind.Key:
                return PhysicalValue.FromText(RequireKey(column, Text(column, scalar)));
            case PhysicalKind.ProductId:
                return PhysicalValue.FromText(RequireProduct(column, Text(column, scalar)));
            case PhysicalKind.ModelId:
                return PhysicalValue.FromText(RequireModelId(column, Text(column, scalar)));
            case PhysicalKind.Currency:
                return PhysicalValue.FromText(RequireCurrency(column, Text(column, scalar)));
            case PhysicalKind.Json:
                return PhysicalValue.FromText(RequireJson(column, Text(column, scalar)));
            case PhysicalKind.Bool:
                return D1Values.TryGetBool(scalar, out var flag) ? PhysicalValue.FromBool(flag) : throw Wrong(column);
            case PhysicalKind.Int32:
                {
                    var number = Int64Of(column, scalar);
                    return number is < int.MinValue or > int.MaxValue ? throw Wrong(column) : PhysicalValue.FromInt64(number);
                }

            case PhysicalKind.Int64:
            case PhysicalKind.Instant:
                return PhysicalValue.FromInt64(Int64Of(column, scalar));
            case PhysicalKind.Rev:
                {
                    var number = Int64Of(column, scalar);
                    return number < 0 ? throw Wrong(column) : PhysicalValue.FromInt64(number);
                }

            case PhysicalKind.Uint64:
                return D1Values.TryGetUint64(scalar, out var unsigned) ? PhysicalValue.FromUint64(unsigned) : throw Wrong(column);
            case PhysicalKind.Decimal:
                {
                    if (!D1Values.TryGetDecimal(scalar, out var number)) throw Wrong(column);
                    return PhysicalValue.FromDecimal(number);
                }

            case PhysicalKind.Hash:
                {
                    if (!D1Values.TryGetBytes(scalar, out var bytes) || bytes.Length != HashLength) throw Wrong(column);
                    return PhysicalValue.FromBytes(bytes);
                }

            case PhysicalKind.Bytes:
            case PhysicalKind.Proto:
                {
                    if (!D1Values.TryGetBytes(scalar, out var bytes) || bytes.Length > MaxBytes) throw Wrong(column);
                    return PhysicalValue.FromBytes(bytes);
                }

            case PhysicalKind.Enum:
                {
                    var registered = PhysicalSchema.FindEnum(column.EnumName ?? throw Wrong(column));
                    var number = Int64Of(column, scalar);
                    if (number is >= 1 and <= ushort.MaxValue && registered.TryGetName((int)number, out _)) return PhysicalValue.FromInt64(number);
                    if (registered.PreserveUnknown && number is >= 1 and <= ushort.MaxValue) return PhysicalValue.FromInt64(number);
                    throw new PhysicalValueException("The number " + number.ToString(CultureInfo.InvariantCulture) + " is not registered in " + registered.Name + ".");
                }

            default:
                throw Wrong(column);
        }
    }

    private static D1Scalar EncodeDecimal(PhysicalColumn column, decimal value)
    {
        try
        {
            return D1Values.Decimal(value);
        }
        catch (ArgumentOutOfRangeException)
        {
            throw new PhysicalValueException("The column " + column.Name + " holds at most 28 significant digits with at most 9 fractional digits.");
        }
    }

    private static string Text(PhysicalColumn column, D1Scalar scalar) => D1Values.TryGetText(scalar, out var text) ? text : throw Wrong(column);

    private static long Int64Of(PhysicalColumn column, D1Scalar scalar) => D1Values.TryGetInt64(scalar, out var number) ? number : throw Wrong(column);

    private static PhysicalValueException Wrong(PhysicalColumn column) => new("The result for " + column.Name + " is not a valid " + column.Kind + ".");

    private static string RequireId(PhysicalColumn column, string text) =>
        IsCanonicalId(text) ? text : throw new PhysicalValueException("The column " + column.Name + " is a canonical lower-case UUID.");

    public static bool IsCanonicalId(string text)
    {
        if (text.Length != 36) return false;
        for (var index = 0; index < 36; index++)
        {
            var c = text[index];
            if (index is 8 or 13 or 18 or 23)
            {
                if (c != '-') return false;
            }
            else if (c is not ((>= '0' and <= '9') or (>= 'a' and <= 'f')))
            {
                return false;
            }
        }

        return true;
    }

    private static string RequireText(PhysicalColumn column, string text)
    {
        int bytes;
        try
        {
            bytes = Strict.GetByteCount(text);
        }
        catch (EncoderFallbackException)
        {
            throw new PhysicalValueException("The column " + column.Name + " holds well-formed Unicode text.");
        }

        if (bytes > MaxBytes || (column.MaxBytes is { } limit && bytes > limit)) throw new PhysicalValueException("The column " + column.Name + " exceeds its size limit.");
        return text;
    }

    public static bool IsKey(string text)
    {
        if (text.Length is 0 or > KeyMaxLength) return false;
        foreach (var c in text)
        {
            if (!(c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '.' or '_' or ':' or '/' or '-')) return false;
        }

        return true;
    }

    private static string RequireKey(PhysicalColumn column, string text) =>
        IsKey(text) ? text : throw new PhysicalValueException("The column " + column.Name + " is a Key: ASCII letters, digits and ._:/- up to 128 characters.");

    private static string RequireProduct(PhysicalColumn column, string text) =>
        text is "arcscope" or "companion" ? text : throw new PhysicalValueException("The column " + column.Name + " is a closed product id.");

    private static string RequireModelId(PhysicalColumn column, string text) =>
        text.Length is >= 1 and <= ModelIdMaxLength ? text : throw new PhysicalValueException("The column " + column.Name + " is a model id of at most 256 characters.");

    private static string RequireCurrency(PhysicalColumn column, string text)
    {
        if (text.Length != 3 || text.Any(c => c is < 'A' or > 'Z')) throw new PhysicalValueException("The column " + column.Name + " is three upper-case ASCII letters.");
        return text;
    }

    private static string RequireJson(PhysicalColumn column, string text)
    {
        RequireText(column, text);
        if (text.Length == 0) throw new PhysicalValueException("The column " + column.Name + " is not valid JSON.");
        try
        {
            using var document = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = MaxJsonDepth });
            var root = document.RootElement.ValueKind;
            if (column.JsonRoot == PhysicalJsonRoot.Object && root != JsonValueKind.Object) throw new PhysicalValueException("The column " + column.Name + " is a JSON object.");
            if (column.JsonRoot == PhysicalJsonRoot.Array && root != JsonValueKind.Array) throw new PhysicalValueException("The column " + column.Name + " is a JSON array.");
        }
        catch (JsonException)
        {
            throw new PhysicalValueException("The column " + column.Name + " is not valid JSON.");
        }

        return text;
    }
}
