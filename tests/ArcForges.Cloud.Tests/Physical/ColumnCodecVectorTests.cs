// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Text.Json;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.Physical;
using ArcForges.Contracts.CloudInternal.Storage.V1;
using Xunit;

namespace ArcForges.Cloud.Tests.Physical;

/// <summary>
/// The shared exact-value vectors (Vectors/physical-columns.json) against the C# adapters. The same file drives the SQLite oracle
/// (tests/worker/d1-physical-columns.test.ts): every value the host encodes is exactly the scalar the Worker accepts and the database
/// stores, and every value one side refuses the other refuses too.
/// </summary>
public sealed class ColumnCodecVectorTests
{
    private static readonly Dictionary<string, PhysicalKind> Kinds = new(StringComparer.Ordinal)
    {
        ["id"] = PhysicalKind.Id,
        ["text"] = PhysicalKind.Text,
        ["key"] = PhysicalKind.Key,
        ["productId"] = PhysicalKind.ProductId,
        ["modelId"] = PhysicalKind.ModelId,
        ["bool"] = PhysicalKind.Bool,
        ["int"] = PhysicalKind.Int32,
        ["int64"] = PhysicalKind.Int64,
        ["rev"] = PhysicalKind.Rev,
        ["instant"] = PhysicalKind.Instant,
        ["uint64"] = PhysicalKind.Uint64,
        ["decimal"] = PhysicalKind.Decimal,
        ["currency"] = PhysicalKind.Currency,
        ["hash"] = PhysicalKind.Hash,
        ["bytes"] = PhysicalKind.Bytes,
        ["proto"] = PhysicalKind.Proto,
        ["json"] = PhysicalKind.Json,
        ["enum"] = PhysicalKind.Enum,
    };

    private static JsonElement Load()
    {
        var path = Path.Combine(T.RepoRoot().FullName, "tests", "ArcForges.Cloud.Tests", "Vectors", "physical-columns.json");
        return JsonDocument.Parse(File.ReadAllText(path)).RootElement;
    }

    private static PhysicalColumn ColumnOf(JsonElement column)
    {
        var kind = Kinds[column.GetProperty("kind").GetString()!];
        var root = PhysicalJsonRoot.Any;
        if (column.TryGetProperty("jsonRoot", out var jsonRoot)) root = jsonRoot.GetString() == "array" ? PhysicalJsonRoot.Array : PhysicalJsonRoot.Object;
        return new PhysicalColumn("v", kind, column.GetProperty("nullable").GetBoolean(), column.TryGetProperty("enum", out var name) ? name.GetString() : null, root);
    }

    private static PhysicalValue ValueOf(JsonElement value)
    {
        if (value.TryGetProperty("null", out _)) return PhysicalValue.Null;
        if (value.TryGetProperty("text", out var text)) return PhysicalValue.FromText(text.GetString()!);
        if (value.TryGetProperty("int64", out var integer)) return PhysicalValue.FromInt64(long.Parse(integer.GetString()!, CultureInfo.InvariantCulture));
        if (value.TryGetProperty("uint64", out var unsigned)) return PhysicalValue.FromUint64(ulong.Parse(unsigned.GetString()!, CultureInfo.InvariantCulture));
        if (value.TryGetProperty("decimal", out var number)) return PhysicalValue.FromDecimal(decimal.Parse(number.GetString()!, NumberStyles.Float, CultureInfo.InvariantCulture));
        if (value.TryGetProperty("bytesHex", out var hex)) return PhysicalValue.FromBytes(Convert.FromHexString(hex.GetString()!));
        if (value.TryGetProperty("bool", out var flag)) return PhysicalValue.FromBool(flag.GetBoolean());
        throw new InvalidOperationException("Unknown vector value.");
    }

    private static D1Scalar ScalarOf(JsonElement scalar)
    {
        var kind = scalar.GetProperty("kind").GetString()!;
        string Value() => scalar.GetProperty("value").GetString()!;
        return kind switch
        {
            "null" => new D1ScalarD1NullValue(new D1NullValue { Kind = "null" }),
            "boolean" => new D1ScalarD1BooleanValue(new D1BooleanValue { Kind = "boolean", Value = scalar.GetProperty("value").GetBoolean() }),
            "int64" => new D1ScalarD1Int64Value(new D1Int64Value { Kind = "int64", Value = Value() }),
            "uint64" => new D1ScalarD1Uint64Value(new D1Uint64Value { Kind = "uint64", Value = Value() }),
            "decimal" => new D1ScalarD1DecimalValue(new D1DecimalValue { Kind = "decimal", Value = Value() }),
            "text" => new D1ScalarD1TextValue(new D1TextValue { Kind = "text", Value = Value() }),
            "bytes" => new D1ScalarD1BytesValue(new D1BytesValue { Kind = "bytes", Value = Value() }),
            _ => throw new InvalidOperationException("Unknown scalar kind."),
        };
    }

    private static (string Kind, string Value) Describe(D1Scalar scalar) => scalar switch
    {
        D1ScalarD1NullValue => ("null", ""),
        D1ScalarD1BooleanValue item => ("boolean", item.Value.Value ? "true" : "false"),
        D1ScalarD1Int64Value item => ("int64", item.Value.Value),
        D1ScalarD1Uint64Value item => ("uint64", item.Value.Value),
        D1ScalarD1DecimalValue item => ("decimal", item.Value.Value),
        D1ScalarD1TextValue item => ("text", item.Value.Value),
        D1ScalarD1BytesValue item => ("bytes", item.Value.Value),
        _ => throw new InvalidOperationException("Unknown scalar."),
    };

    private static (string Kind, string Value) Expected(JsonElement scalar)
    {
        var kind = scalar.GetProperty("kind").GetString()!;
        if (kind == "null") return (kind, "");
        var value = scalar.GetProperty("value");
        return (kind, value.ValueKind == JsonValueKind.True ? "true" : value.ValueKind == JsonValueKind.False ? "false" : value.GetString()!);
    }

    [Fact]
    public void EveryRoundTripVectorEncodesToExactlyTheSharedScalarAndDecodesBack()
    {
        var count = 0;
        foreach (var vector in Load().GetProperty("cases").EnumerateArray().Where(entry => entry.GetProperty("roundTrip").GetBoolean()))
        {
            var name = vector.GetProperty("name").GetString();
            var column = ColumnOf(vector.GetProperty("column"));
            var value = ValueOf(vector.GetProperty("value"));
            Assert.True(Expected(vector.GetProperty("scalar")) == Describe(ColumnCodec.Encode(column, value)), name);
            var decoded = ColumnCodec.Decode(column, ScalarOf(vector.GetProperty("scalar")));
            Assert.True(value.Equals(decoded), name);
            count++;
        }

        Assert.True(count > 55, count.ToString(CultureInfo.InvariantCulture));
    }

    [Fact]
    public void EveryRefusalVectorIsRefusedByTheDecoderAndByTheEncoderWhenItHasAValue()
    {
        var count = 0;
        foreach (var vector in Load().GetProperty("cases").EnumerateArray().Where(entry => !entry.GetProperty("roundTrip").GetBoolean()))
        {
            var name = vector.GetProperty("name").GetString();
            var column = ColumnOf(vector.GetProperty("column"));
            var scalar = ScalarOf(vector.GetProperty("scalar"));
            Assert.Throws<PhysicalValueException>(() => ColumnCodec.Decode(column, scalar));
            if (vector.TryGetProperty("value", out var value))
            {
                PhysicalValue logical;
                try
                {
                    logical = ValueOf(value);
                }
                catch (FormatException)
                {
                    // A value the host type cannot even represent (an out-of-range number) is refused before it reaches the codec.
                    count++;
                    continue;
                }
                catch (OverflowException)
                {
                    count++;
                    continue;
                }

                Assert.Throws<PhysicalValueException>(() => ColumnCodec.Encode(column, logical));
            }

            count++;
        }

        Assert.True(count > 40, count.ToString(CultureInfo.InvariantCulture));
    }

    [Fact]
    public void EveryKindMapsToTheSamePlanKindAsTheSqliteOracle()
    {
        var planKinds = Load().GetProperty("planKinds");
        var expected = new Dictionary<string, PlanKind>(StringComparer.Ordinal)
        {
            ["text"] = PlanKind.Text,
            ["bool"] = PlanKind.Bool,
            ["int64"] = PlanKind.Int64,
            ["uint64"] = PlanKind.Uint64,
            ["decimal"] = PlanKind.Decimal,
            ["bytes"] = PlanKind.Bytes,
        };
        foreach (var kind in planKinds.EnumerateObject())
            Assert.Equal(expected[kind.Value.GetString()!], ColumnCodec.PlanKindOf(new PhysicalColumn("v", Kinds[kind.Name], false, kind.Name == "enum" ? "TaskState" : null)));
        Assert.Equal(Kinds.Count, planKinds.EnumerateObject().Count());
    }

    [Fact]
    public void BytesAndTextAtTheirSizeLimitsAreAcceptedAndOneOverIsRefused()
    {
        var bytes = new PhysicalColumn("v", PhysicalKind.Bytes, false);
        Assert.NotNull(ColumnCodec.Encode(bytes, PhysicalValue.FromBytes(new byte[ColumnCodec.MaxBytes])));
        Assert.Throws<PhysicalValueException>(() => ColumnCodec.Encode(bytes, PhysicalValue.FromBytes(new byte[ColumnCodec.MaxBytes + 1])));
        var text = new PhysicalColumn("v", PhysicalKind.Text, false);
        Assert.NotNull(ColumnCodec.Encode(text, PhysicalValue.FromText(new string('a', ColumnCodec.MaxBytes))));
        Assert.Throws<PhysicalValueException>(() => ColumnCodec.Encode(text, PhysicalValue.FromText(new string('a', ColumnCodec.MaxBytes + 1))));
        var capped = new PhysicalColumn("v", PhysicalKind.Text, false, MaxBytes: 4);
        Assert.NotNull(ColumnCodec.Encode(capped, PhysicalValue.FromText("abcd")));
        Assert.Throws<PhysicalValueException>(() => ColumnCodec.Encode(capped, PhysicalValue.FromText("abcde")));
        // A lone surrogate is not well-formed text and is never stored.
        Assert.Throws<PhysicalValueException>(() => ColumnCodec.Encode(text, PhysicalValue.FromText("a\ud800b")));
    }

    [Fact]
    public void AValueOfTheWrongLogicalKindIsRefused()
    {
        var id = new PhysicalColumn("v", PhysicalKind.Id, false);
        Assert.Throws<PhysicalValueException>(() => ColumnCodec.Encode(id, PhysicalValue.FromInt64(1)));
        var integer = new PhysicalColumn("v", PhysicalKind.Int64, false);
        Assert.Throws<PhysicalValueException>(() => ColumnCodec.Encode(integer, PhysicalValue.FromText("1")));
        Assert.Throws<PhysicalValueException>(() => ColumnCodec.Encode(integer, PhysicalValue.FromUint64(1)));
        var unsigned = new PhysicalColumn("v", PhysicalKind.Uint64, false);
        Assert.Throws<PhysicalValueException>(() => ColumnCodec.Encode(unsigned, PhysicalValue.FromInt64(1)));
    }

    [Fact]
    public void AnEnumIsEncodedFromItsMemberNameAndAnUnknownStoredNumberIsRefusedUnlessThePreservingRegistryKeepsIt()
    {
        var column = new PhysicalColumn("v", PhysicalKind.Enum, false, "TaskState");
        var number = ColumnCodec.EnumByName(column, "waiting");
        Assert.Equal(3, number.AsInt64());
        Assert.Throws<PhysicalValueException>(() => ColumnCodec.EnumByName(column, "missing"));
        Assert.Throws<PhysicalValueException>(() => ColumnCodec.Decode(column, D1Values.Int64(99)));
        Assert.All(PhysicalSchema.Enums, entry => Assert.False(entry.PreserveUnknown, entry.Name));
    }
}
