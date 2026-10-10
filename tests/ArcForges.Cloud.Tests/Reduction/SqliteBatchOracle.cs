// SPDX-License-Identifier: AGPL-3.0-only
using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using ArcForges.Cloud.Storage.D1.MigrationRunner;

namespace ArcForges.Cloud.Tests.Reduction;

/// <summary>
/// The SQLite batch oracle of the migration tests (CLOUD.84 U9, D8): node:sqlite, the engine the TypeScript runner tests used, holds one
/// in-memory database and runs each batch as one atomic transaction (BEGIN IMMEDIATE ... COMMIT, or ROLLBACK on the first failure), the
/// same contract as the D1 client. It runs as a test-only child process that speaks one JSON line per request, so no SQLite package is
/// added to the solution. SQLite is not D1: this proves the engine's logic and SQL, not the provider's batch atomicity (a recorded live check).
/// </summary>
internal sealed class SqliteBatchOracle : IMigrationClient, IDisposable
{
    private const string Script =
        "import { DatabaseSync } from 'node:sqlite'; import { createInterface } from 'node:readline';" +
        "const db = new DatabaseSync(':memory:'); db.exec('PRAGMA foreign_keys = ON');" +
        "const bind = (values) => (values ?? []).map((value) => value ?? null);" +
        "function reply(request) {" +
        "  try {" +
        "    if (request.op === 'batch') {" +
        "      db.exec('BEGIN IMMEDIATE');" +
        "      try {" +
        "        const results = [];" +
        "        for (const statement of request.statements) {" +
        "          const prepared = db.prepare(statement.sql); const params = bind(statement.params);" +
        "          if (prepared.columns().length > 0) { prepared.setReturnArrays(true); results.push({ changes: 0, rows: prepared.all(...params) }); }" +
        "          else { const outcome = prepared.run(...params); results.push({ changes: Number(outcome.changes), rows: [] }); }" +
        "        }" +
        "        db.exec('COMMIT'); return { ok: true, results };" +
        "      } catch (error) { try { db.exec('ROLLBACK'); } catch { } return { ok: false, error: error.message }; }" +
        "    }" +
        "    if (request.op === 'exec') { db.exec(request.sql); return { ok: true }; }" +
        "    if (request.op === 'query') { const prepared = db.prepare(request.sql); prepared.setReturnArrays(true); return { ok: true, rows: prepared.all(...bind(request.params)) }; }" +
        "    return { ok: false, error: 'unknown request' };" +
        "  } catch (error) { return { ok: false, error: error.message }; }" +
        "}" +
        "createInterface({ input: process.stdin }).on('line', (line) => { process.stdout.write(JSON.stringify(reply(JSON.parse(line))) + '\\n'); });";

    private readonly Process process;

    public SqliteBatchOracle()
    {
        var info = new ProcessStartInfo("node")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            StandardInputEncoding = new UTF8Encoding(false),
            StandardOutputEncoding = new UTF8Encoding(false),
            StandardErrorEncoding = new UTF8Encoding(false),
        };
        info.ArgumentList.Add("--input-type=module");
        info.ArgumentList.Add("-e");
        info.ArgumentList.Add(Script);
        process = Process.Start(info) ?? throw new InvalidOperationException("node could not be started for the SQLite batch oracle.");
        process.ErrorDataReceived += (_, _) => { };
        process.BeginErrorReadLine();
    }

    /// <summary>Batches that were rolled back, for tests that assert an atomic refusal.</summary>
    public int Rollbacks { get; private set; }

    public Task<IReadOnlyList<BatchResult>> BatchAsync(IReadOnlyList<MigrationStatement> statements, CancellationToken cancellationToken)
    {
        var array = new JsonArray();
        foreach (var statement in statements) array.Add((JsonNode)new JsonObject { ["sql"] = statement.Sql, ["params"] = Parameters(statement.Params) });
        var reply = Send(new JsonObject { ["op"] = "batch", ["statements"] = array });
        if (reply["ok"]?.GetValue<bool>() != true)
        {
            Rollbacks++;
            throw new MigrationClientException(reply["error"]?.GetValue<string>() ?? "error");
        }

        var results = new List<BatchResult>();
        foreach (var entry in reply["results"]!.AsArray())
        {
            var rows = entry!["rows"]!.AsArray().Select(row => (IReadOnlyList<string?>)row!.AsArray().Select(Cell).ToList()).ToList();
            results.Add(new BatchResult(entry["changes"]!.GetValue<long>(), rows));
        }

        return Task.FromResult<IReadOnlyList<BatchResult>>(results);
    }

    /// <summary>Runs fixture SQL (test setup only): a failure throws.</summary>
    public void Exec(string sql)
    {
        var reply = Send(new JsonObject { ["op"] = "exec", ["sql"] = sql });
        if (reply["ok"]?.GetValue<bool>() != true) throw new InvalidOperationException(reply["error"]?.GetValue<string>());
    }

    /// <summary>Runs a statement that must fail and returns the database's refusal message (test assertions only).</summary>
    public string RefusalOf(string sql)
    {
        var reply = Send(new JsonObject { ["op"] = "exec", ["sql"] = sql });
        return reply["ok"]?.GetValue<bool>() == true
            ? throw new InvalidOperationException("The statement was not refused.")
            : reply["error"]!.GetValue<string>();
    }

    /// <summary>Reads rows as text (test assertions only); an integer is its decimal text, a null is null.</summary>
    public IReadOnlyList<IReadOnlyList<string?>> Query(string sql, params object?[] parameters)
    {
        var reply = Send(new JsonObject { ["op"] = "query", ["sql"] = sql, ["params"] = Parameters(parameters) });
        if (reply["ok"]?.GetValue<bool>() != true) throw new InvalidOperationException(reply["error"]?.GetValue<string>());
        return reply["rows"]!.AsArray().Select(row => (IReadOnlyList<string?>)row!.AsArray().Select(Cell).ToList()).ToList();
    }

    /// <summary>The first cell of the first row, as a 64-bit integer.</summary>
    public long Scalar(string sql, params object?[] parameters) =>
        long.Parse(Query(sql, parameters)[0][0]!, CultureInfo.InvariantCulture);

    /// <summary>A stable text of every schema object, for comparing two databases.</summary>
    public string SchemaSnapshot() => ToJsonText(Query("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name"));

    private static string ToJsonText(IReadOnlyList<IReadOnlyList<string?>> rows)
    {
        var array = new JsonArray();
        foreach (var row in rows)
        {
            var cells = new JsonArray();
            foreach (var cell in row) cells.Add(cell is null ? null : JsonValue.Create(cell));
            array.Add((JsonNode)cells);
        }

        return array.ToJsonString();
    }

    private static JsonArray Parameters(IEnumerable<object?> values)
    {
        var array = new JsonArray();
        foreach (var value in values)
        {
            JsonNode? node = value switch
            {
                null => null,
                string text => JsonValue.Create(text),
                long number => JsonValue.Create(number),
                _ => throw new InvalidOperationException("unsupported bind type"),
            };
            array.Add(node);
        }

        return array;
    }

    private static string? Cell(JsonNode? node) => node switch
    {
        null => null,
        JsonValue value when value.TryGetValue<string>(out var text) => text,
        _ => node.ToJsonString(),
    };

    private JsonObject Send(JsonObject request)
    {
        process.StandardInput.WriteLine(request.ToJsonString());
        process.StandardInput.Flush();
        var line = process.StandardOutput.ReadLine() ?? throw new InvalidOperationException("The SQLite batch oracle exited.");
        return JsonNode.Parse(line)!.AsObject();
    }

    public void Dispose()
    {
        try
        {
            if (!process.HasExited)
            {
                process.StandardInput.Close();
                if (!process.WaitForExit(3000)) process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
        }

        process.Dispose();
    }
}
