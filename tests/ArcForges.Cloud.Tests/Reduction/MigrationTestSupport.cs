// SPDX-License-Identifier: AGPL-3.0-only
using System.Net;
using System.Text;
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

    /// <summary>Every table of the physical manifest exists with the manifest's columns, in order (the reduced column-level comparison).</summary>
    public static void AssertPhysicalColumns(SqliteBatchOracle database)
    {
        foreach (var table in ArcForges.Cloud.Storage.Physical.PhysicalSchema.Tables)
        {
            var columns = database.Query($"SELECT name FROM pragma_table_info('{table.Name}') ORDER BY cid")
                .Select(row => row[0] ?? string.Empty)
                .ToList();
            Assert.Equal(table.Columns.Select(column => column.Name).ToList(), columns);
        }
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
