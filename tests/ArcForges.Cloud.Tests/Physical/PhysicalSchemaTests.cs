// SPDX-License-Identifier: AGPL-3.0-only
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ArcForges.Cloud.Storage;
using ArcForges.Cloud.Storage.Physical;
using Xunit;

namespace ArcForges.Cloud.Tests.Physical;

/// <summary>
/// The generated C# column maps against the checked-in physical manifest and migration lock, read independently here: a stale or
/// hand-edited generated file, a table the manifest does not list or a lock that disagrees with its files fails.
/// </summary>
public sealed class PhysicalSchemaTests
{
    private static string Physical(params string[] parts) => Path.Combine([T.RepoRoot().FullName, "src", "ArcForges.Cloud.Storage.D1", .. parts]);

    private sealed record ManifestColumn(string Name, string Type, bool Nullable);

    private static IReadOnlyList<(string Owner, string Table, IReadOnlyList<ManifestColumn> Columns, IReadOnlyList<string> Key)> Manifest()
    {
        var tables = new List<(string, string, IReadOnlyList<ManifestColumn>, IReadOnlyList<string>)>();
        foreach (var file in Directory.EnumerateFiles(Physical("Physical", "manifest"), "*.json").Where(path => !path.EndsWith("enums.json", StringComparison.Ordinal)))
        {
            using var document = JsonDocument.Parse(File.ReadAllText(file));
            var owner = document.RootElement.GetProperty("owner").GetString()!;
            foreach (var table in document.RootElement.GetProperty("tables").EnumerateArray())
            {
                var columns = table.GetProperty("columns").EnumerateArray()
                    .Select(column => new ManifestColumn(column.GetProperty("name").GetString()!, column.GetProperty("type").GetString()!, column.TryGetProperty("nullable", out var nullable) && nullable.GetBoolean()))
                    .ToArray();
                tables.Add((owner, table.GetProperty("name").GetString()!, columns, table.GetProperty("primaryKey").EnumerateArray().Select(key => key.GetString()!).ToArray()));
            }
        }

        return tables;
    }

    private static IEnumerable<(string Name, PhysicalKind Kind, bool Nullable)> Expand(ManifestColumn column) => column.Type switch
    {
        "money" => [(column.Name, PhysicalKind.Decimal, column.Nullable), (column.Name + "_currency", PhysicalKind.Currency, column.Nullable)],
        "aggregateRef" => [(column.Name + "_kind", PhysicalKind.Key, column.Nullable), (column.Name + "_id", PhysicalKind.Id, column.Nullable)],
        "id" => [(column.Name, PhysicalKind.Id, column.Nullable)],
        "text" => [(column.Name, PhysicalKind.Text, column.Nullable)],
        "key" => [(column.Name, PhysicalKind.Key, column.Nullable)],
        "productId" => [(column.Name, PhysicalKind.ProductId, column.Nullable)],
        "modelId" => [(column.Name, PhysicalKind.ModelId, column.Nullable)],
        "bool" => [(column.Name, PhysicalKind.Bool, column.Nullable)],
        "int" => [(column.Name, PhysicalKind.Int32, column.Nullable)],
        "int64" => [(column.Name, PhysicalKind.Int64, column.Nullable)],
        "rev" => [(column.Name, PhysicalKind.Rev, column.Nullable)],
        "instant" => [(column.Name, PhysicalKind.Instant, column.Nullable)],
        "uint64" => [(column.Name, PhysicalKind.Uint64, column.Nullable)],
        "decimal" => [(column.Name, PhysicalKind.Decimal, column.Nullable)],
        "currency" => [(column.Name, PhysicalKind.Currency, column.Nullable)],
        "hash" => [(column.Name, PhysicalKind.Hash, column.Nullable)],
        "bytes" => [(column.Name, PhysicalKind.Bytes, column.Nullable)],
        "proto" => [(column.Name, PhysicalKind.Proto, column.Nullable)],
        "json" => [(column.Name, PhysicalKind.Json, column.Nullable)],
        "enum" => [(column.Name, PhysicalKind.Enum, column.Nullable)],
        _ => throw new InvalidOperationException("Unknown manifest type " + column.Type),
    };

    [Fact]
    public void EveryTableAndColumnOfTheGeneratedMapIsExactlyTheManifest()
    {
        var manifest = Manifest();
        Assert.Equal(manifest.Count, PhysicalSchema.Tables.Count);
        Assert.Equal(158, PhysicalSchema.Tables.Count);
        foreach (var (owner, name, columns, key) in manifest)
        {
            var table = PhysicalSchema.FindTable(name);
            Assert.Equal(owner, table.Owner);
            Assert.Equal(key, table.PrimaryKey);
            var expected = columns.SelectMany(Expand).ToArray();
            Assert.Equal(expected.Length, table.Columns.Count);
            for (var index = 0; index < expected.Length; index++)
            {
                Assert.Equal(expected[index].Name, table.Columns[index].Name);
                Assert.Equal(expected[index].Kind, table.Columns[index].Kind);
                Assert.Equal(expected[index].Nullable, table.Columns[index].Nullable);
            }
        }
    }

    [Fact]
    public void EveryTableKeepsItsOwnersPrefixAndItsKeyColumnsAreNotNullable()
    {
        foreach (var table in PhysicalSchema.Tables)
        {
            Assert.StartsWith(table.Owner.Replace('-', '_') + "_", table.Name, StringComparison.Ordinal);
            Assert.NotEmpty(table.PrimaryKey);
            foreach (var key in table.PrimaryKey) Assert.False(table.Column(key).Nullable, table.Name + "." + key);
            Assert.Equal(table.Columns.Count, table.Columns.Select(column => column.Name).Distinct(StringComparer.Ordinal).Count());
        }

        Assert.Equal(PhysicalSchema.Tables.Count, PhysicalSchema.Tables.Select(table => table.Name).Distinct(StringComparer.Ordinal).Count());
    }

    [Fact]
    public void EveryEnumColumnNamesARegisteredEnumWithUniqueNumbers()
    {
        foreach (var entry in PhysicalSchema.Enums)
        {
            Assert.Equal(entry.Members.Count, entry.Members.Select(member => member.Number).Distinct().Count());
            Assert.All(entry.Members, member => Assert.InRange(member.Number, 1, ushort.MaxValue));
        }

        foreach (var table in PhysicalSchema.Tables)
            foreach (var column in table.Columns.Where(column => column.Kind == PhysicalKind.Enum))
                Assert.NotNull(PhysicalSchema.FindEnum(column.EnumName!));
    }

    [Fact]
    public void TheMigrationLockIdentityIsTheOneTheHostWasCompiledAgainst()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Physical("Migrations", "migrations.lock.json")));
        var entries = document.RootElement.GetProperty("migrations").EnumerateArray().ToArray();
        var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        foreach (var entry in entries)
        {
            var sequence = entry.GetProperty("sequence").GetInt32();
            var file = entry.GetProperty("file").GetString()!;
            var text = File.ReadAllText(Physical("Migrations", file)).Replace("\r\n", "\n", StringComparison.Ordinal);
            var checksum = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
            Assert.Equal(checksum, entry.GetProperty("sha256").GetString());
            hash.AppendData(Encoding.UTF8.GetBytes(sequence.ToString(CultureInfo.InvariantCulture) + ":" + checksum + "\n"));
        }

        Assert.Equal(PhysicalSchema.HighestMigration, entries.Length - 1);
        Assert.Equal(PhysicalSchema.MigrationLockHash, Convert.ToHexStringLower(hash.GetHashAndReset()));
        Assert.Equal(PhysicalSchema.HighestMigration, SchemaCompatibility.ApplicationSchemaVersion);
        Assert.Matches("^[0-9a-f]{64}$", PhysicalSchema.ManifestHash);
    }

    [Fact]
    public void ARowShapeBindsAndReadsATableRowExactlyAndFixesThePlanParameterKinds()
    {
        var table = PhysicalSchema.FindTable("identity_user");
        var shape = new RowShape(table, "user_id", "state", "created_at", "deletion_requested_at", "rev");
        var id = Guid.Parse("0198a7c0-1c3e-7d4a-9b1f-2e5d6a7b8c9d");
        var state = ColumnCodec.EnumByName(table.Column("state"), "pendingDeletion");
        var values = new Dictionary<string, PhysicalValue>(StringComparer.Ordinal)
        {
            ["user_id"] = PhysicalValue.FromId(id),
            ["state"] = state,
            ["created_at"] = PhysicalValue.FromInstant(new DateTimeOffset(2026, 10, 5, 12, 0, 0, TimeSpan.Zero).AddTicks(1230)),
            ["deletion_requested_at"] = PhysicalValue.Null,
            ["rev"] = PhysicalValue.FromInt64(9007199254740993),
        };
        var scalars = shape.Bind(values);
        var back = shape.Read(scalars);
        foreach (var (name, value) in values) Assert.True(value.Equals(back[name]), name);
        Assert.Equal(id, back["user_id"].AsId());
        Assert.Equal(new DateTimeOffset(2026, 10, 5, 12, 0, 0, TimeSpan.Zero).AddTicks(1230), back["created_at"].AsInstant());
        Assert.Equal([PlanKind.Text, PlanKind.Int64, PlanKind.Int64, PlanKind.Int64, PlanKind.Int64], shape.Params().Select(parameter => parameter.Kind));
        Assert.Equal([false, false, false, true, false], shape.Params().Select(parameter => parameter.Nullable));
        // A missing or extra value, an unknown column, a duplicate column and a null for a required column are refused.
        Assert.Throws<PhysicalValueException>(() => shape.Bind(values.Where(pair => pair.Key != "rev").ToDictionary(pair => pair.Key, pair => pair.Value)));
        Assert.Throws<PhysicalValueException>(() => new RowShape(table, "user_id", "nope"));
        Assert.Throws<PhysicalValueException>(() => new RowShape(table, "user_id", "user_id"));
        var nullRequired = new Dictionary<string, PhysicalValue>(values, StringComparer.Ordinal) { ["rev"] = PhysicalValue.Null };
        Assert.Throws<PhysicalValueException>(() => shape.Bind(nullRequired));
        Assert.Throws<PhysicalValueException>(() => shape.Read(scalars.Take(2).ToArray()));
    }

    [Fact]
    public void AnInstantIsWholeMicrosecondsAndTheRangeIsGuarded()
    {
        var epoch = DateTimeOffset.UnixEpoch;
        Assert.Equal(0, InstantMicroseconds.FromInstant(epoch));
        Assert.Equal(1, InstantMicroseconds.FromInstant(epoch.AddTicks(10)));
        Assert.Equal(-1, InstantMicroseconds.FromInstant(epoch.AddTicks(-10)));
        Assert.Throws<PhysicalValueException>(() => InstantMicroseconds.FromInstant(epoch.AddTicks(1)));
        Assert.Equal(DateTimeOffset.MaxValue.AddTicks(-9), InstantMicroseconds.ToInstant(253402300799999999));
        Assert.Throws<PhysicalValueException>(() => InstantMicroseconds.ToInstant(253402300800000000));
        Assert.Throws<PhysicalValueException>(() => InstantMicroseconds.ToInstant(long.MinValue));
        // A zone offset does not change the stored UTC instant.
        var offset = new DateTimeOffset(2026, 10, 5, 12, 0, 0, TimeSpan.FromHours(8));
        Assert.Equal(InstantMicroseconds.FromInstant(offset.ToUniversalTime()), InstantMicroseconds.FromInstant(offset));
    }
}
