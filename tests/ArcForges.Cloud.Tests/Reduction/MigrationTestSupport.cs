// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ArcForges.Cloud.Storage.D1.MigrationRunner;
using ArcForges.Cloud.Tools.Generation.Migrations;
using Xunit;

namespace ArcForges.Cloud.Tests.Reduction;

/// <summary>A clock in milliseconds that a test advances by hand (the engine's Now).</summary>
internal sealed class TestClock
{
    public long Now { get; private set; } = 1_790_000_000_000;

    public void Advance(long milliseconds) => Now += milliseconds;

    public Func<long> Read => () => Now;
}

/// <summary>A client whose batches are supplied by a delegate (spies, crash simulations).</summary>
internal sealed class DelegateClient(Func<IReadOnlyList<MigrationStatement>, CancellationToken, Task<IReadOnlyList<BatchResult>>> batch) : IMigrationClient
{
    public Task<IReadOnlyList<BatchResult>> BatchAsync(IReadOnlyList<MigrationStatement> statements, CancellationToken cancellationToken) =>
        batch(statements, cancellationToken);
}

/// <summary>Fixtures shared by the migration tests: the committed catalog, synthetic migrations and the scratch backfill.</summary>
internal static class MigrationTestSupport
{
    public static readonly CompatibilityInput Compat = new(
        "0123456789abcdef0123456789abcdef01234567",
        new string('p', 8),
        "abi-1",
        "net10.0");

    public const string Scratch = """
        CREATE TABLE "scratch_item" (
          "id" TEXT NOT NULL,
          "legacy" TEXT NOT NULL,
          "converted" TEXT,
          "rev" INTEGER NOT NULL CHECK ("rev" >= 0),
          CONSTRAINT "pk_scratch_item" PRIMARY KEY ("id")
        ) STRICT;
        """;

    public const string BackfillBody = """
        -- af-backfill: {"target":"scratch_item","key":"id","pageSize":100}
        -- section: page
        SELECT "id", CAST("rev" AS TEXT) FROM "scratch_item" WHERE "id" > ? AND "converted" IS NULL ORDER BY "id" LIMIT ?
        -- section: apply
        UPDATE "scratch_item" SET "converted" = upper("legacy") WHERE "id" = ? AND "rev" = CAST(? AS INTEGER) AND "converted" IS NULL
        -- section: verify
        SELECT COUNT(*) FROM "scratch_item" WHERE "converted" IS NULL OR "converted" <> upper("legacy")
        """;

    public static string MigrationsDirectory =>
        Path.Combine(ArcForges.Cloud.Tests.T.RepoRoot().FullName, MigrationFiles.MigrationsPath);

    /// <summary>The committed catalog, loaded and validated against its lock.</summary>
    public static IReadOnlyList<Migration> Baseline() =>
        MigrationCatalog.Load(MigrationFiles.ReadDirectory(MigrationsDirectory), MigrationFiles.ReadLock(MigrationsDirectory));

    /// <summary>A migration built from text, as the catalog builds one (the same header, checksum and statements).</summary>
    public static Migration Synthetic(int sequence, string module, MigrationMode mode, string body, string header = "")
    {
        var text = $"-- af-migration: module={module} mode={MigrationSql.ModeName(mode)}{header}\n{body}\n";
        var parsed = MigrationSql.ParseHeader(text);
        return new Migration(
            sequence,
            $"{sequence.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)}_{module}__test-{sequence}.sql",
            module,
            mode,
            parsed.Options,
            MigrationSql.ChecksumOf(text),
            text,
            mode == MigrationMode.Backfill ? [] : MigrationSql.SplitStatements(text));
    }

    public static RunOptions Options(
        IMigrationClient client,
        IReadOnlyList<Migration> migrations,
        string runner,
        TestClock time,
        long leaseMs = 60_000,
        int maxChunkStatements = 25,
        long maxChunkBytes = 60_000,
        int? stopAfter = null,
        bool allowContract = false,
        EngineHooks? hooks = null,
        int maxBackfillPasses = 10) => new()
        {
            Client = client,
            Migrations = migrations,
            Runner = runner,
            Now = time.Read,
            Compatibility = Compat,
            LeaseMs = leaseMs,
            MaxChunkStatements = maxChunkStatements,
            MaxChunkBytes = maxChunkBytes,
            StopAfter = stopAfter,
            AllowContract = allowContract,
            Hooks = hooks,
            MaxBackfillPasses = maxBackfillPasses,
        };

    /// <summary>A database with the scratch table, migrated through the expand and the seeded rows (the TypeScript seededScratch).</summary>
    public static async Task<(SqliteBatchOracle Client, TestClock Time, List<Migration> Chain)> SeededScratchAsync(int rows)
    {
        var client = new SqliteBatchOracle();
        var time = new TestClock();
        var chain = new List<Migration>
        {
            Baseline()[0],
            Synthetic(1, "scratch", MigrationMode.Expand, Scratch),
            Synthetic(2, "scratch", MigrationMode.Backfill, BackfillBody),
        };
        await MigrationEngine.ApplyPendingAsync(Options(client, chain, "seed", time, stopAfter: 1));
        for (var index = 0; index < rows; index++)
            client.Exec($"INSERT INTO scratch_item VALUES ('k{index:D5}', 'value-{index}', NULL, 1)");
        return (client, time, chain);
    }

    /// <summary>
    /// The physical comparison of the TypeScript runner tests (compareShapes over readShape and expectedShape), restored in the C# port
    /// (CLOUD.84 S42(4)). The migrated database and the physical manifest agree on the base-table set (virtual tables and their shadow
    /// tables are excluded, as readShape excludes them). Every column, in column order, has the manifest's SQLite type, its nullability
    /// (NOT NULL, or a primary-key column) and its primary-key position. Every index the migrations create (origin c) has the manifest's
    /// name, uniqueness, columns (DESC kept) and partial condition. The foreign keys, checks, triggers, index and trigger definitions and
    /// STRICT are compared only by the Node physical drift gate (eng/verification/physical-schema.ts, D4 and D5), not here.
    /// </summary>
    public static void AssertPhysicalShape(SqliteBatchOracle database)
    {
        var tables = database.Query("SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'");
        var virtualNames = tables
            .Where(row => row[1] is not null && row[1]!.StartsWith("CREATE VIRTUAL TABLE", StringComparison.OrdinalIgnoreCase))
            .Select(row => row[0] ?? string.Empty)
            .ToHashSet(StringComparer.Ordinal);
        var shadows = virtualNames
            .SelectMany(name => new[] { "_data", "_idx", "_content", "_docsize", "_config" }.Select(suffix => name + suffix))
            .ToHashSet(StringComparer.Ordinal);
        var migratedNames = tables
            .Select(row => row[0] ?? string.Empty)
            .Where(name => !virtualNames.Contains(name) && !shadows.Contains(name))
            .Order(StringComparer.Ordinal)
            .ToList();
        var manifestTables = ArcForges.Cloud.Storage.Physical.PhysicalSchema.Tables;
        Assert.Equal(manifestTables.Select(table => table.Name).Order(StringComparer.Ordinal).ToList(), migratedNames);

        var columnRows = database.Query(
            "SELECT m.name, p.name, p.type, p.\"notnull\", p.pk FROM sqlite_master m, pragma_table_info(m.name) p " +
            "WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%' ORDER BY m.name, p.cid");
        var migratedColumns = columnRows
            .GroupBy(row => row[0] ?? string.Empty, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.Select(row => $"{row[1]}|{row[2]}|{(row[3] == "1" || row[4] != "0" ? 1 : 0)}|{row[4]}").ToList(),
                StringComparer.Ordinal);
        foreach (var table in manifestTables)
        {
            var expected = table.Columns.Select(column =>
            {
                var keyIndex = table.PrimaryKey.ToList().IndexOf(column.Name);
                var notNull = !column.Nullable || keyIndex >= 0;
                return $"{column.Name}|{SqlTypeOf(column.Kind)}|{(notNull ? 1 : 0)}|{(keyIndex < 0 ? 0 : keyIndex + 1)}";
            }).ToList();
            Assert.True(migratedColumns.TryGetValue(table.Name, out var actual), $"{table.Name} is in the manifest but not in the migrations");
            Assert.Equal(expected, actual);
        }

        var indexRows = database.Query(
            "SELECT m.name, il.name, il.\"unique\", il.origin FROM sqlite_master m, pragma_index_list(m.name) il " +
            "WHERE m.type = 'table' AND m.name NOT LIKE 'sqlite_%' AND m.sql NOT LIKE 'CREATE VIRTUAL TABLE%'");
        var indexColumns = database.Query(
            "SELECT ix.name, xi.name, xi.\"desc\", xi.\"key\" FROM sqlite_master ix, pragma_index_xinfo(ix.name) xi " +
            "WHERE ix.type = 'index' AND xi.\"key\" = 1 ORDER BY ix.name, xi.seqno")
            .GroupBy(row => row[0] ?? string.Empty, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.Select(row => row[1] + (row[2] == "1" ? " DESC" : string.Empty)).ToList(),
                StringComparer.Ordinal);
        var indexSql = database.Query("SELECT name, sql FROM sqlite_master WHERE type = 'index'")
            .ToDictionary(row => row[0] ?? string.Empty, row => row[1] ?? string.Empty, StringComparer.Ordinal);
        var migratedIndexes = indexRows
            .Where(row => row[3] == "c")
            .GroupBy(row => row[0] ?? string.Empty, StringComparer.Ordinal)
            .ToDictionary(
                group => group.Key,
                group => group.Select(row =>
                {
                    var name = row[1] ?? string.Empty;
                    var columns = indexColumns.GetValueOrDefault(name) ?? [];
                    var where = Regex.Match(indexSql.GetValueOrDefault(name) ?? string.Empty, @"\sWHERE\s(.*)$", RegexOptions.IgnoreCase | RegexOptions.Singleline).Groups[1].Value;
                    return $"{name}|{(row[2] == "1" ? "unique" : "plain")}|{string.Join(",", columns)}|{where}";
                }).Order(StringComparer.Ordinal).ToList(),
                StringComparer.Ordinal);
        foreach (var (table, expected) in ManifestIndexes())
            Assert.Equal(expected, migratedIndexes.GetValueOrDefault(table) ?? []);
    }

    /// <summary>The SQLite storage type of a physical kind (the mapping of eng/verification/physical-schema.ts, sqliteType).</summary>
    private static string SqlTypeOf(ArcForges.Cloud.Storage.Physical.PhysicalKind kind) => kind switch
    {
        ArcForges.Cloud.Storage.Physical.PhysicalKind.Bool
            or ArcForges.Cloud.Storage.Physical.PhysicalKind.Int32
            or ArcForges.Cloud.Storage.Physical.PhysicalKind.Int64
            or ArcForges.Cloud.Storage.Physical.PhysicalKind.Rev
            or ArcForges.Cloud.Storage.Physical.PhysicalKind.Instant
            or ArcForges.Cloud.Storage.Physical.PhysicalKind.Enum => "INTEGER",
        ArcForges.Cloud.Storage.Physical.PhysicalKind.Hash
            or ArcForges.Cloud.Storage.Physical.PhysicalKind.Bytes
            or ArcForges.Cloud.Storage.Physical.PhysicalKind.Proto => "BLOB",
        _ => "TEXT",
    };

    /// <summary>
    /// The expected index entries of every table, read from the committed physical manifest (the generated schema carries no indexes).
    /// An index without an explicit name takes the manifest's generated name (ux_ or ix_, the table, and the columns without ASC or DESC).
    /// </summary>
    private static Dictionary<string, List<string>> ManifestIndexes()
    {
        var directory = Path.Combine(ArcForges.Cloud.Tests.T.RepoRoot().FullName, "src", "ArcForges.Cloud.Storage.D1", "Physical", "manifest");
        var entries = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var file in Directory.GetFiles(directory, "*.json").Where(file => Path.GetFileName(file) != "enums.json").Order(StringComparer.Ordinal))
        {
            using var document = JsonDocument.Parse(File.ReadAllText(file));
            foreach (var table in document.RootElement.GetProperty("tables").EnumerateArray())
            {
                var name = table.GetProperty("name").GetString() ?? string.Empty;
                var list = new List<string>();
                if (table.TryGetProperty("indexes", out var indexes))
                {
                    foreach (var index in indexes.EnumerateArray())
                    {
                        var columns = index.GetProperty("columns").EnumerateArray().Select(column => column.GetString() ?? string.Empty).ToList();
                        var unique = index.TryGetProperty("unique", out var uniqueValue) && uniqueValue.ValueKind == JsonValueKind.True;
                        var where = index.TryGetProperty("where", out var whereValue) ? whereValue.GetString() ?? string.Empty : string.Empty;
                        var indexName = index.TryGetProperty("name", out var nameValue)
                            ? nameValue.GetString() ?? string.Empty
                            : $"{(unique ? "ux" : "ix")}_{name}__{string.Join("_", columns.Select(column => Regex.Replace(column, @"\s+(?:ASC|DESC)$", string.Empty, RegexOptions.IgnoreCase)))}";
                        list.Add($"{indexName}|{(unique ? "unique" : "plain")}|{string.Join(",", columns)}|{where}");
                    }
                }

                entries[name] = list.Order(StringComparer.Ordinal).ToList();
            }
        }

        return entries;
    }

    /// <summary>A crash in the simulated process: every later batch fails as a client error.</summary>
    public static Task<IReadOnlyList<BatchResult>> Gone() =>
        Task.FromException<IReadOnlyList<BatchResult>>(new MigrationClientException("the migrator process is gone"));

    public static string Head(string text) => text.Length <= 12 ? text : text[..12];

    /// <summary>A copy of the committed catalog directory (the migrations and the lock) in a fresh root, for catalog tests.</summary>
    public static string CopyCatalogRoot()
    {
        var root = Directory.CreateTempSubdirectory("af-migrate-").FullName;
        var directory = Path.Combine(root, MigrationFiles.MigrationsPath);
        Directory.CreateDirectory(directory);
        foreach (var file in Directory.GetFiles(MigrationsDirectory))
        {
            var name = Path.GetFileName(file);
            if (name.EndsWith(".sql", StringComparison.Ordinal) || name == MigrationCatalog.LockFileName)
                File.Copy(file, Path.Combine(directory, name));
        }

        return root;
    }

    public static MigrateContext ContextFor(string root, StringWriter output, StringWriter error) =>
        new(root, new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase), output, error);

    public static string Utf8(byte[] bytes) => Encoding.UTF8.GetString(bytes);

}

/// <summary>A scripted HTTP handler for the D1 REST transport: it records each request body and answers from a script.</summary>
internal sealed class ScriptedHandler(Func<HttpRequestMessage, string, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    public List<string> Bodies { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Bodies.Add(body);
        return await respond(request, body).ConfigureAwait(false);
    }

    public static HttpResponseMessage Json(string json, int status = 200) =>
        new((HttpStatusCode)status) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
}
