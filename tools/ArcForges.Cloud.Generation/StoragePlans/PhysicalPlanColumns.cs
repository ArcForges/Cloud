// SPDX-License-Identifier: AGPL-3.0-only
// The physical columns the guard primitives are expanded against (CLOUD.84 U7; the table and column part of
// eng/verification/physical-schema.ts loadManifest and expandColumns). The Node validator stays the authority for the manifest
// (check:physical); this reader needs only the tables, the column names and the logical kinds.
using System.Text.Json;

namespace ArcForges.Cloud.Tools.Generation.StoragePlans;

public static class PhysicalPlanColumns
{
    /// <summary>The committed manifest directory, relative to the repository root.</summary>
    public const string ManifestDirectory = "src/ArcForges.Cloud.Storage.D1/Physical/manifest";

    /// <summary>Reads every manifest file (all JSON files except enums.json) and expands its tables.</summary>
    public static PhysicalManifest Load(string directory)
    {
        SqlText.Require(File.Exists(Path.Combine(directory, "enums.json")), "manifest: enums.json is missing");
        var files = Directory.GetFiles(directory, "*.json")
            .Select(Path.GetFileName)
            .Where(name => name is not null && name != "enums.json")
            .Select(name => name!)
            .Order(StringComparer.Ordinal);
        var tables = new List<PhysicalTableInfo>();
        foreach (var file in files)
        {
            using var document = JsonDocument.Parse(File.ReadAllText(Path.Combine(directory, file)));
            var root = document.RootElement;
            SqlText.Require(
                root.TryGetProperty("schemaVersion", out var version) && version.ValueKind == JsonValueKind.Number && version.GetInt32() == 1,
                $"{file}: schemaVersion");
            SqlText.Require(root.TryGetProperty("tables", out var tableList) && tableList.ValueKind == JsonValueKind.Array, $"{file}: tables");
            foreach (var table in tableList.EnumerateArray())
            {
                var name = table.GetProperty("name").GetString() ?? throw new PlanRefusal($"{file}: a table has no name");
                tables.Add(new PhysicalTableInfo(name, ExpandColumns(table)));
            }
        }

        return new PhysicalManifest(tables);
    }

    /// <summary>The physical columns of one table: money and aggregate references expand to their parts; every other column keeps its kind.</summary>
    public static IReadOnlyList<PhysicalColumnInfo> ExpandColumns(JsonElement table)
    {
        var columns = new List<PhysicalColumnInfo>();
        foreach (var column in table.GetProperty("columns").EnumerateArray())
        {
            var name = column.GetProperty("name").GetString() ?? string.Empty;
            var type = column.GetProperty("type").GetString() ?? string.Empty;
            switch (type)
            {
                case "money":
                    columns.Add(new PhysicalColumnInfo(name, "decimal"));
                    columns.Add(new PhysicalColumnInfo($"{name}_currency", "currency"));
                    break;
                case "aggregateRef":
                    columns.Add(new PhysicalColumnInfo($"{name}_kind", "key"));
                    columns.Add(new PhysicalColumnInfo($"{name}_id", "id"));
                    break;
                default:
                    columns.Add(new PhysicalColumnInfo(name, type));
                    break;
            }
        }

        return columns;
    }

    /// <summary>The plan parameter kind a physical column is bound and read as (physical-schema.ts planKindOf).</summary>
    public static string PlanKindOf(string kind) => kind switch
    {
        "bool" => "bool",
        "int" or "int64" or "rev" or "instant" or "enum" => "int64",
        "uint64" => "uint64",
        "decimal" => "decimal",
        "hash" or "bytes" or "proto" => "bytes",
        _ => "text",
    };
}
