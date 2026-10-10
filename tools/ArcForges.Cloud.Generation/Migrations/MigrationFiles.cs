// SPDX-License-Identifier: AGPL-3.0-only
// File access of the migration tool (CLOUD.84 U9, U10): it reads the migrations directory, the lock and the deployment files and writes
// the lock and the gate records. Every decision is made by the rules in src/ArcForges.Cloud.Storage.D1 (MigrationRunner and Deploy).
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ArcForges.Cloud.Storage.D1.Deploy;
using ArcForges.Cloud.Storage.D1.MigrationRunner;

namespace ArcForges.Cloud.Tools.Generation.Migrations;

public static class MigrationFiles
{
    public const string MigrationsPath = "src/ArcForges.Cloud.Storage.D1/Migrations";
    public const string PendingDirectory = "pending";

    private static readonly UTF8Encoding Utf8 = new(false);

    /// <summary>The text of a file as UTF-8, keeping a byte order mark as the TypeScript tooling did.</summary>
    public static string ReadText(string path) => Utf8.GetString(File.ReadAllBytes(path));

    /// <summary>The numbered and the pending files of the migrations directory, by name.</summary>
    public static List<SourceFile> ReadDirectory(string directory)
    {
        if (!Directory.Exists(directory)) return [];
        return Directory.GetFiles(directory)
            .Select(Path.GetFileName)
            .Where(name => name is not null && name.EndsWith(".sql", StringComparison.Ordinal))
            .Select(name => new SourceFile(name!, ReadText(Path.Combine(directory, name!))))
            .ToList();
    }

    public static List<SourceFile> ReadPending(string directory) =>
        ReadDirectory(Path.Combine(directory, PendingDirectory));

    /// <summary>The lock entries of migrations.lock.json; an absent lock is empty.</summary>
    public static List<LockEntry> ReadLock(string directory)
    {
        var file = Path.Combine(directory, MigrationCatalog.LockFileName);
        if (!File.Exists(file)) return [];
        return ParseLock(ReadText(file));
    }

    /// <summary>Parses the lock text (schemaVersion 1, a migrations array of entries).</summary>
    public static List<LockEntry> ParseLock(string text)
    {
        using var document = JsonDocument.Parse(text);
        var root = document.RootElement;
        if (!root.TryGetProperty("schemaVersion", out var version) || version.ValueKind != JsonValueKind.Number || version.GetInt32() != 1)
            throw new InvalidOperationException($"{MigrationCatalog.LockFileName}: schemaVersion");
        if (!root.TryGetProperty("migrations", out var migrations) || migrations.ValueKind != JsonValueKind.Array)
            throw new InvalidOperationException($"{MigrationCatalog.LockFileName}: migrations");
        return migrations.EnumerateArray().Select(entry => new LockEntry(
            entry.GetProperty("sequence").GetInt32(),
            entry.GetProperty("file").GetString() ?? string.Empty,
            entry.GetProperty("module").GetString() ?? string.Empty,
            entry.GetProperty("mode").GetString() ?? string.Empty,
            entry.GetProperty("sha256").GetString() ?? string.Empty)).ToList();
    }

    /// <summary>Writes the lock in the committed layout: two-space indentation, a trailing newline.</summary>
    public static void WriteLock(string directory, IReadOnlyList<LockEntry> entries)
    {
        var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = true }))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", 1);
            writer.WriteStartArray("migrations");
            foreach (var entry in entries)
            {
                writer.WriteStartObject();
                writer.WriteNumber("sequence", entry.Sequence);
                writer.WriteString("file", entry.File);
                writer.WriteString("module", entry.Module);
                writer.WriteString("mode", entry.Mode);
                writer.WriteString("sha256", entry.Sha256);
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
            writer.WriteEndObject();
        }

        var text = Utf8.GetString(buffer.ToArray()) + "\n";
        File.WriteAllBytes(Path.Combine(directory, MigrationCatalog.LockFileName), Utf8.GetBytes(text));
    }

    /// <summary>Reads a JSON file of the deployment (wrangler.json or the candidate manifest).</summary>
    public static JsonDocument ReadJson(string path) => JsonDocument.Parse(ReadText(path));

    /// <summary>The database bindings a deployment target declares in wrangler.json (the top level for production, env.proof for proof).</summary>
    public static List<D1Binding>? DeclaredDatabases(JsonElement config, string target)
    {
        JsonElement scope;
        if (target == "production") scope = config;
        else if (config.TryGetProperty("env", out var environments) && environments.TryGetProperty(target, out scope)) { }
        else return null;
        if (!scope.TryGetProperty("d1_databases", out var databases) || databases.ValueKind != JsonValueKind.Array) return null;
        return databases.EnumerateArray().Select(entry => new D1Binding(
            Text(entry, "binding"),
            Text(entry, "database_name"))).ToList();
    }

    private static string? Text(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    /// <summary>Writes one gate record for a target, as the job and promotion read it.</summary>
    public static void WriteGateRecord(string root, GateRecord record)
    {
        var directory = Path.Combine(root, "artifacts");
        Directory.CreateDirectory(directory);
        var document = new JsonObject
        {
            ["target"] = record.Target,
            ["revision"] = record.Revision,
            ["status"] = record.Status,
            ["detail"] = record.Detail,
        };
        var text = document.ToJsonString(new JsonSerializerOptions { WriteIndented = true }) + "\n";
        File.WriteAllBytes(Path.Combine(directory, $"migration-gate-{record.Target}.json"), Utf8.GetBytes(text));
    }
}
