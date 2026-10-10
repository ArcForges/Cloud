// SPDX-License-Identifier: AGPL-3.0-only
// The D1 migration engine (Design D1 profile section 6; CLOUD.84 U9, S41(1)). It runs from the gated deployment jobs, never from the
// Container. One global sequence, applied in order with receipts. Every chunk is one atomic batch whose first statement advances the
// receipt under the current fence, so:
//   - an interrupted run resumes from `statements_done` and never repeats an applied statement;
//   - a stale migrator (its lease expired and another took over) cannot apply anything: its guard statement violates a CHECK and the
//     whole batch rolls back before a single DDL statement runs;
//   - a merged migration that was edited is refused, because its checksum is in the receipt.
// Modes: expand (additive DDL), backfill (guarded pages with checkpoints and a verify gate), cutover (one fenced switch of the read and
// write horizons) and contract (irreversible, after cutover and soak). Port of eng/migrations/runner.ts; the TypeScript runner is test
// support only from this unit on.
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace ArcForges.Cloud.Storage.D1.MigrationRunner;

public sealed record CompatibilityInput(string SourceRevision, string PlanManifestHash, string Abi, string Runtime);

public sealed record ChunkInfo(int Sequence, long From, long To);

public sealed record PageInfo(int Sequence, IReadOnlyList<string> Keys);

/// <summary>Test seams: a hook may throw to simulate a crash at that point.</summary>
public sealed class EngineHooks
{
    public Func<ChunkInfo, Task>? BeforeChunk { get; init; }
    public Func<ChunkInfo, Task>? AfterChunk { get; init; }
    public Func<PageInfo, Task>? AfterPageSelect { get; init; }
}

public sealed class RunOptions
{
    public required IMigrationClient Client { get; init; }
    public required IReadOnlyList<Migration> Migrations { get; init; }
    /// <summary>A unique identity of this run (for example the workflow run id).</summary>
    public required string Runner { get; init; }
    /// <summary>The clock in milliseconds since the Unix epoch.</summary>
    public required Func<long> Now { get; init; }
    public required CompatibilityInput Compatibility { get; init; }
    public long LeaseMs { get; init; } = 120_000;
    public int MaxChunkStatements { get; init; } = 25;
    public long MaxChunkBytes { get; init; } = 60_000;
    /// <summary>Stop after this sequence has been applied (to separate expand, backfill, cutover and contract).</summary>
    public int? StopAfter { get; init; }
    /// <summary>A contract migration is irreversible and is applied only when the deployment job says so.</summary>
    public bool AllowContract { get; init; }
    public EngineHooks? Hooks { get; init; }
    /// <summary>Safety bound on backfill passes.</summary>
    public int MaxBackfillPasses { get; init; } = 10;
    public CancellationToken CancellationToken { get; init; } = CancellationToken.None;
}

public sealed record AppliedMigration(
    int Sequence,
    string File,
    string Mode,
    int Statements,
    long? RowsConverted = null,
    long? RowsStale = null,
    int? Passes = null,
    int? Chunks = null);

public sealed record RunResult(long Fence, IReadOnlyList<AppliedMigration> Applied, int SchemaVersion, bool AlreadyCurrent);

public sealed record ReceiptStatus(int Sequence, string File, string State, long StatementsDone, long StatementCount);

/// <summary>Read-only status: what is applied, what an interrupted run left and what is still pending.</summary>
public sealed record MigrationStatus(
    bool Initialized,
    long DatabaseAhead,
    int SchemaVersion,
    int ReadHorizon,
    int WriteHorizon,
    long Fence,
    string? LeaseHolder,
    IReadOnlyList<ReceiptStatus> Receipts,
    IReadOnlyList<string> Pending);

public sealed record Verdict(bool CanRead, bool CanWrite, string Reason);

public static class MigrationEngine
{
    /// <summary>The enum numbers of the manifest (platform.migration_mode, platform.migration_state).</summary>
    public const int StateApplying = 1;
    public const int StateApplied = 2;

    private static readonly System.Text.RegularExpressions.Regex ReceiptRefusal = new(
        "ck_platform_migration_receipt__progress|af_immutable_platform_migration_receipt",
        RegexOptions.CultureInvariant);

    private static readonly System.Text.RegularExpressions.Regex CounterRefusal = new(
        "ck_platform_backfill_checkpoint__counters",
        RegexOptions.CultureInvariant);

    private sealed record Receipt(int Sequence, string File, string Checksum, int State, long StatementsDone, long StatementCount, long? AppliedAt);

    private sealed record SchemaState(long SchemaVersion, long ReadHorizon, long WriteHorizon, long Fence, string? LeaseHolder, long? LeaseExpiresAt);

    private sealed class Run(RunOptions options)
    {
        public RunOptions Options { get; } = options;
        public long Fence { get; set; }
        public long Now => Options.Now();
        public long LeaseMs => Options.LeaseMs;
        public CancellationToken Cancel => Options.CancellationToken;

        public object?[] GuardParams() => [Fence.ToString(CultureInfo.InvariantCulture), Options.Runner, Micros(Now)];
    }

    /// <summary>Microseconds as canonical decimal text (the engine never binds a 64-bit value as a number).</summary>
    public static string Micros(long milliseconds) => (milliseconds * 1000).ToString(CultureInfo.InvariantCulture);

    private static string Text(long value) => value.ToString(CultureInfo.InvariantCulture);

    private static async Task<IReadOnlyList<IReadOnlyList<string?>>> One(Run run, string sql, params object?[] parameters)
    {
        var results = await run.Options.Client.BatchAsync([new MigrationStatement(sql, parameters)], run.Cancel).ConfigureAwait(false);
        return results[0].Rows;
    }

    /// <summary>Equivalent of the TypeScript int(rows[row]?.[column]): a missing cell throws, a null cell is zero.</summary>
    private static long CellLong(IReadOnlyList<IReadOnlyList<string?>> rows, int row, int column)
    {
        if (row >= rows.Count || column >= rows[row].Count)
            throw new MigrationError("unexpected-value", "expected a safe integer, received undefined");
        return ParseSafeLong(rows[row][column]);
    }

    private static long ParseSafeLong(string? value)
    {
        if (value is null) return 0;
        if (!long.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var parsed) || Math.Abs(parsed) > 9_007_199_254_740_991L)
            throw new MigrationError("unexpected-value", $"expected a safe integer, received {value}");
        return parsed;
    }

    /// <summary>JavaScript Number(text) for the option values the engine reads: an integer text, or empty (zero). Null is not a number.</summary>
    private static bool TryJsInteger(string? text, out long value)
    {
        value = 0;
        if (text is null) return false;
        var trimmed = text.Trim();
        if (trimmed.Length == 0) return true;
        return long.TryParse(trimmed, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);
    }

    private static string Head12(string value) => MigrationSql.ShortChecksum(value);

    private static async Task<bool> TableExists(Run run)
    {
        var rows = await One(run, RunnerSql.Get("table-exists")).ConfigureAwait(false);
        return CellLong(rows, 0, 0) == 1;
    }

    private static async Task<SchemaState> ReadState(Run run)
    {
        var rows = await One(run, RunnerSql.Get("read-state")).ConfigureAwait(false);
        if (rows.Count == 0) throw new MigrationError("no-schema-state", "platform_schema_state has no row");
        var row = rows[0];
        return new SchemaState(
            ParseSafeLong(row[0]),
            ParseSafeLong(row[1]),
            ParseSafeLong(row[2]),
            ParseSafeLong(row[3]),
            row[4],
            row[5] is null ? null : long.Parse(row[5]!, CultureInfo.InvariantCulture));
    }

    private static async Task<List<Receipt>> ReadReceipts(Run run)
    {
        var rows = await One(run, RunnerSql.Get("read-receipts")).ConfigureAwait(false);
        var receipts = new List<Receipt>();
        foreach (var row in rows)
        {
            receipts.Add(new Receipt(
                (int)ParseSafeLong(row[0]),
                row[1] ?? "null",
                row[2] ?? "null",
                (int)ParseSafeLong(row[3]),
                ParseSafeLong(row[4]),
                ParseSafeLong(row[5]),
                row[6] is null ? null : long.Parse(row[6]!, CultureInfo.InvariantCulture)));
        }

        return receipts;
    }

    private static string CompatibilityJson(Run run, int schemaVersion)
    {
        var json = new JsonObject
        {
            ["sourceRevision"] = run.Options.Compatibility.SourceRevision,
            ["schemaVersion"] = schemaVersion,
            ["planManifestHash"] = run.Options.Compatibility.PlanManifestHash,
            ["abi"] = run.Options.Compatibility.Abi,
            ["runtime"] = run.Options.Compatibility.Runtime,
        };
        return json.ToJsonString();
    }

    private static MigrationStatement ReceiptInsert(Run run, Migration migration, long statementCount) => new(
        RunnerSql.Get("receipt-insert"),
        [
            Text(migration.Sequence),
            migration.File,
            migration.Module,
            (long)(int)migration.Mode,
            migration.Sha256,
            statementCount,
            run.Options.Runner,
            Text(run.Fence),
            Micros(run.Now),
            CompatibilityJson(run, migration.Sequence),
            .. run.GuardParams(),
        ]);

    /// <summary>Bootstrap: migration 0000 creates the bookkeeping tables, so its own receipt and the state row ride in its batch.</summary>
    private static async Task Bootstrap(Run run, Migration first)
    {
        if (first.Sequence != 0 || first.Mode != MigrationMode.Expand)
            throw new MigrationError("bad-bootstrap", "migration 0000 must be the expand migration that creates the bookkeeping tables");
        var now = Micros(run.Now);
        var compatibility = CompatibilityJson(run, 0);
        var statements = new List<MigrationStatement>();
        statements.AddRange(first.Statements.Select(statement => new MigrationStatement(statement.Sql, [])));
        statements.Add(new MigrationStatement(
            RunnerSql.Get("bootstrap-schema-state"),
            [run.Options.Runner, Micros(run.Now + run.LeaseMs), now]));
        statements.Add(new MigrationStatement(
            RunnerSql.Get("bootstrap-receipt"),
            [
                first.File,
                first.Module,
                (long)(int)first.Mode,
                first.Sha256,
                (long)first.Statements.Count,
                (long)first.Statements.Count,
                run.Options.Runner,
                now,
                now,
                compatibility,
            ]));
        await run.Options.Client.BatchAsync(statements, run.Cancel).ConfigureAwait(false);
        run.Fence = 1;
    }

    private static async Task AcquireLease(Run run)
    {
        var now = Micros(run.Now);
        var results = await run.Options.Client.BatchAsync([
            new MigrationStatement(
                RunnerSql.Get("acquire-lease"),
                [run.Options.Runner, Micros(run.Now + run.LeaseMs), now, now, run.Options.Runner]),
        ], run.Cancel).ConfigureAwait(false);
        if (results[0].Changes != 1)
        {
            var state = await ReadState(run).ConfigureAwait(false);
            throw new MigrationError(
                "lease-held",
                $"another migrator holds the lease ({state.LeaseHolder ?? "null"}) until {state.LeaseExpiresAt?.ToString(CultureInfo.InvariantCulture) ?? "null"}");
        }

        run.Fence = (await ReadState(run).ConfigureAwait(false)).Fence;
    }

    private static async Task ReleaseLease(Run run)
    {
        await run.Options.Client.BatchAsync([
            new MigrationStatement(
                RunnerSql.Get("release-lease"),
                [Micros(run.Now), Text(run.Fence), run.Options.Runner]),
        ], run.Cancel).ConfigureAwait(false);
    }

    /// <summary>Checks the receipts against the catalog: contiguous, the same files and checksums, and no unfinished migration before a finished one.</summary>
    private static void VerifyReceipts(IReadOnlyList<Receipt> receipts, IReadOnlyList<Migration> migrations, bool allowAhead = false)
    {
        for (var position = 0; position < receipts.Count; position++)
        {
            var receipt = receipts[position];
            if (receipt.Sequence != position)
                throw new MigrationError("receipt-gap", $"the receipts are not contiguous at sequence {position}");
            var migration = position < migrations.Count ? migrations[position] : null;
            // A database ahead of this release is a rolled-back release: status reports it, apply refuses it.
            if (migration is null && allowAhead) continue;
            if (migration is null)
                throw new MigrationError("database-ahead", $"the database has applied migration {receipt.File} that this release does not contain");
            if (receipt.Checksum != migration.Sha256 || receipt.File != migration.File)
                throw new MigrationError(
                    "checksum-mismatch",
                    $"migration {receipt.File} was edited after it was applied (receipt {Head12(receipt.Checksum)}, release {Head12(migration.Sha256)})");
            if (receipt.State == StateApplying && position != receipts.Count - 1)
                throw new MigrationError("receipt-order", $"migration {receipt.File} is unfinished but a later migration has a receipt");
        }
    }

    private static List<MigrationStatement> ChunkStatements(IReadOnlyList<MigrationStatement> statements, int from, int maxStatements, long maxBytes)
    {
        var chunk = new List<MigrationStatement>();
        long bytes = 0;
        for (var index = from; index < statements.Count && chunk.Count < maxStatements; index++)
        {
            var statement = statements[index];
            if (chunk.Count > 0 && bytes + statement.Sql.Length > maxBytes) break;
            chunk.Add(statement);
            bytes += statement.Sql.Length;
        }

        return chunk;
    }

    /// <summary>The progress statement of a chunk, followed by the lease renewal and the chunk's own statements.</summary>
    private static List<MigrationStatement> FenceGuardedProgress(
        Run run,
        Migration migration,
        long previous,
        long next,
        bool last,
        IEnumerable<MigrationStatement> extra,
        string extraCondition = "")
    {
        var now = Micros(run.Now);
        var progress = new MigrationStatement(
            RunnerSql.Get(
                "progress",
                ("extra", extraCondition),
                ("finish", last ? RunnerSql.Get("progress-finish") : string.Empty)),
            [
                Text(previous),
                .. run.GuardParams(),
                Text(next),
                .. (last ? new object?[] { now } : []),
                Text(migration.Sequence),
            ]);
        return [progress, RenewStatement(run), .. extra];
    }

    /// <summary>Keeps the lease alive from inside a guarded batch, after the guard statement, so a long run never outlives its lease.</summary>
    private static MigrationStatement RenewStatement(Run run) => new(
        RunnerSql.Get("renew-lease"),
        [Micros(run.Now + run.LeaseMs), Text(run.Fence), run.Options.Runner]);

    /// <summary>The verify queries of the backfills a cutover requires, as one condition of the cutover's own guard.</summary>
    private static (string Condition, List<string> Queries) CutoverVerification(Run run, Migration migration)
    {
        if (migration.Mode != MigrationMode.Cutover) return (string.Empty, []);
        var queries = new List<string>();
        foreach (var entry in (migration.Options.GetValueOrDefault("requires") ?? string.Empty).Split(',').Where(part => part.Length > 0))
        {
            var required = TryJsInteger(entry, out var sequence)
                ? run.Options.Migrations.FirstOrDefault(candidate => candidate.Sequence == sequence)
                : null;
            if (required?.Mode != MigrationMode.Backfill)
                throw new MigrationError("cutover-blocked", $"{migration.File} requires {entry}, which is not a backfill of this release");
            queries.Add(MigrationSql.ParseBackfill(required.Text).Verify);
        }

        return (string.Concat(queries.Select(query => $" AND ({query}) = 0")), queries);
    }

    private static List<MigrationStatement> SchemaVersionStatements(Run run, Migration migration)
    {
        var read = migration.Options.GetValueOrDefault("readHorizon");
        var write = migration.Options.GetValueOrDefault("writeHorizon");
        if (migration.Mode == MigrationMode.Cutover && (read is not null || write is not null))
            return
            [
                new MigrationStatement(
                    RunnerSql.Get("cutover-horizons"),
                    [read, write, Text(migration.Sequence), Micros(run.Now), Text(run.Fence)]),
            ];
        return
        [
            new MigrationStatement(
                RunnerSql.Get("schema-version"),
                [Text(migration.Sequence), Micros(run.Now), Text(run.Fence)]),
        ];
    }

    private static async Task<AppliedMigration> ApplyStatements(Run run, Migration migration, Receipt? receipt)
    {
        var statements = migration.Statements.Select(statement => new MigrationStatement(statement.Sql, [])).ToList();
        var done = receipt?.StatementsDone ?? 0;
        if (receipt is null)
        {
            var results = await run.Options.Client.BatchAsync([ReceiptInsert(run, migration, statements.Count)], run.Cancel).ConfigureAwait(false);
            if (results[0].Changes != 1)
                throw new MigrationError("stale-migrator", $"the lease was lost before {migration.File} could start");
        }

        var chunks = 0;
        var verification = CutoverVerification(run, migration);
        while (done < statements.Count)
        {
            var chunk = ChunkStatements(statements, (int)done, run.Options.MaxChunkStatements, run.Options.MaxChunkBytes);
            var next = done + chunk.Count;
            var last = next == statements.Count;
            var info = new ChunkInfo(migration.Sequence, done, next);
            if (run.Options.Hooks?.BeforeChunk is { } beforeChunk) await beforeChunk(info).ConfigureAwait(false);
            var batch = FenceGuardedProgress(
                run,
                migration,
                done,
                next,
                last,
                [.. chunk, .. (last ? SchemaVersionStatements(run, migration) : [])],
                verification.Condition);
            try
            {
                await run.Options.Client.BatchAsync(batch, run.Cancel).ConfigureAwait(false);
            }
            catch (MigrationClientException error) when (ReceiptRefusal.IsMatch(error.Message))
            {
                // Only the guard's own constraint (or the receipt's immutability once another migrator finished it) is a fence or progress failure.
                foreach (var query in verification.Queries)
                {
                    var remaining = CellLong(await One(run, query).ConfigureAwait(false), 0, 0);
                    if (remaining != 0)
                        throw new MigrationError(
                            "cutover-blocked",
                            $"{migration.File}: {remaining} rows are unconverted or dirty at the moment of cutover");
                }

                throw new MigrationError("stale-migrator", $"the fence or the receipt moved under {migration.File}: {error.Message}");
            }

            chunks++;
            done = next;
            if (run.Options.Hooks?.AfterChunk is { } afterChunk) await afterChunk(info).ConfigureAwait(false);
        }

        return new AppliedMigration(migration.Sequence, migration.File, MigrationSql.ModeName(migration.Mode), statements.Count, Chunks: chunks);
    }

    private static async Task RequireVerifiedBackfills(Run run, Migration migration, IReadOnlyList<Receipt> receipts)
    {
        foreach (var entry in (migration.Options.GetValueOrDefault("requires") ?? string.Empty).Split(',').Where(part => part.Length > 0))
        {
            var found = TryJsInteger(entry, out var sequence) ? receipts.FirstOrDefault(item => item.Sequence == sequence) : null;
            if (found is null || found.State != StateApplied)
                throw new MigrationError("cutover-blocked", $"{migration.File} requires backfill {entry} to be applied");
            var rows = await One(run, RunnerSql.Get("checkpoint-verified-select"), Text(sequence)).ConfigureAwait(false);
            if (CellLong(rows, 0, 0) != 1)
                throw new MigrationError("cutover-blocked", $"{migration.File} requires backfill {entry} to be verified");
        }
    }

    private static void RequireSoak(Run run, Migration migration, IReadOnlyList<Receipt> receipts)
    {
        if (!run.Options.AllowContract)
            throw new MigrationError("contract-refused", $"{migration.File} is irreversible and is applied only with allowContract");
        var afterText = migration.Options.GetValueOrDefault("after");
        var soakText = migration.Options.GetValueOrDefault("soak");
        if (!TryJsInteger(afterText, out var after) || !TryJsInteger(soakText, out var soakSeconds) || soakSeconds < 0)
            throw new MigrationError("contract-refused", $"{migration.File} must declare after=<cutover sequence> and soak=<seconds>");
        var cutover = receipts.FirstOrDefault(entry => entry.Sequence == after);
        if (cutover is null || cutover.State != StateApplied || cutover.AppliedAt is null)
            throw new MigrationError("contract-refused", $"{migration.File} follows cutover {after}, which is not applied");
        var due = cutover.AppliedAt.Value + soakSeconds * 1_000_000L;
        if (run.Now * 1000 < due)
            throw new MigrationError(
                "contract-refused",
                $"{migration.File} may run only after the soak of {soakSeconds} seconds that follows cutover {after}");
    }

    private static async Task<AppliedMigration> ApplyBackfill(Run run, Migration migration, Receipt? receipt)
    {
        var spec = MigrationSql.ParseBackfill(migration.Text);
        if (receipt is null)
        {
            var results = await run.Options.Client.BatchAsync([
                ReceiptInsert(run, migration, 1),
                new MigrationStatement(
                    RunnerSql.Get("checkpoint-insert"),
                    [Text(migration.Sequence), Micros(run.Now), .. run.GuardParams()]),
            ], run.Cancel).ConfigureAwait(false);
            if (results[0].Changes != 1)
                throw new MigrationError("stale-migrator", $"the lease was lost before {migration.File} could start");
        }

        var maxPasses = run.Options.MaxBackfillPasses;
        var passes = 0;
        long rowsConverted = 0;
        long rowsStale = 0;
        for (;;)
        {
            passes++;
            if (passes > maxPasses)
                throw new MigrationError("backfill-not-converging", $"{migration.File} did not converge in {maxPasses} passes");
            var checkpoint = await One(run, RunnerSql.Get("checkpoint-state"), Text(migration.Sequence)).ConfigureAwait(false);
            var cursor = checkpoint.Count == 0 || checkpoint[0][0] is null ? string.Empty : checkpoint[0][0]!;
            var beforeConverted = CellLong(checkpoint, 0, 1);
            var beforeStale = CellLong(checkpoint, 0, 2);
            for (;;)
            {
                var page = await One(run, spec.Page, cursor, (long)spec.PageSize).ConfigureAwait(false);
                if (page.Count == 0) break;
                var keys = page.Select(row => row[0] ?? "null").ToList();
                if (run.Options.Hooks?.AfterPageSelect is { } afterPageSelect)
                    await afterPageSelect(new PageInfo(migration.Sequence, keys)).ConfigureAwait(false);
                var lastKey = keys[^1];
                var statements = new List<MigrationStatement>
                {
                    new(
                        RunnerSql.Get("checkpoint-page"),
                        [cursor, .. run.GuardParams(), lastKey, Micros(run.Now), Text(migration.Sequence)]),
                    // After the guard and before any apply statement: changes() below reads the apply statement that precedes it.
                    RenewStatement(run),
                };
                foreach (var row in page)
                {
                    statements.Add(new MigrationStatement(spec.Apply, [row[0] ?? "null", row[1] ?? "null"]));
                    statements.Add(new MigrationStatement(
                        RunnerSql.Get("checkpoint-counters"),
                        [Text(migration.Sequence)]));
                }

                try
                {
                    await run.Options.Client.BatchAsync(statements, run.Cancel).ConfigureAwait(false);
                }
                catch (MigrationClientException error) when (CounterRefusal.IsMatch(error.Message))
                {
                    throw new MigrationError("stale-migrator", $"the fence or the checkpoint moved under {migration.File}: {error.Message}");
                }

                cursor = lastKey;
            }

            var verify = await One(run, spec.Verify).ConfigureAwait(false);
            var remaining = CellLong(verify, 0, 0);
            var after = await One(run, RunnerSql.Get("checkpoint-counts"), Text(migration.Sequence)).ConfigureAwait(false);
            rowsConverted = CellLong(after, 0, 0);
            rowsStale = CellLong(after, 0, 1);
            if (remaining == 0) break;
            var progressed = rowsConverted - beforeConverted > 0 || rowsStale - beforeStale > 0;
            if (!progressed)
                throw new MigrationError("backfill-not-converging", $"{migration.File}: {remaining} rows remain unconverted and a pass converted none");
            // The dirty rows (written after they were read) are picked up by another pass from the start of the key range.
            try
            {
                await run.Options.Client.BatchAsync([
                    new MigrationStatement(
                        RunnerSql.Get("checkpoint-restart"),
                        [.. run.GuardParams(), Micros(run.Now), Text(migration.Sequence)]),
                    RenewStatement(run),
                ], run.Cancel).ConfigureAwait(false);
            }
            catch (MigrationClientException error) when (CounterRefusal.IsMatch(error.Message))
            {
                throw new MigrationError("stale-migrator", $"the fence moved under {migration.File}: {error.Message}");
            }
        }

        await run.Options.Client.BatchAsync(
            FenceGuardedProgress(run, migration, 0, 1, true,
            [
                new MigrationStatement(
                    RunnerSql.Get("checkpoint-verified"),
                    [Micros(run.Now), Text(migration.Sequence)]),
                .. SchemaVersionStatements(run, migration),
            ]),
            run.Cancel).ConfigureAwait(false);
        return new AppliedMigration(migration.Sequence, migration.File, "backfill", 1, rowsConverted, rowsStale, passes);
    }

    /// <summary>Applies every pending migration in order under the lease; resumes an unfinished one.</summary>
    public static async Task<RunResult> ApplyPendingAsync(RunOptions options)
    {
        var run = new Run(options);
        var migrations = options.Migrations;
        var first = migrations.Count > 0 ? migrations[0] : null;
        if (first is null) throw new MigrationError("empty-catalog", "the migration catalog is empty");
        if (!await TableExists(run).ConfigureAwait(false))
            await Bootstrap(run, first).ConfigureAwait(false);
        else
            await AcquireLease(run).ConfigureAwait(false);
        var applied = new List<AppliedMigration>();
        try
        {
            var receipts = await ReadReceipts(run).ConfigureAwait(false);
            VerifyReceipts(receipts, migrations);
            var highest = receipts.Count(entry => entry.State == StateApplied) - 1;
            foreach (var migration in migrations)
            {
                if (migration.Sequence <= highest) continue;
                if (options.StopAfter is { } stopAfter && migration.Sequence > stopAfter) break;
                var receipt = receipts.FirstOrDefault(entry => entry.Sequence == migration.Sequence);
                // Renew the lease so a long run keeps its fence; a lease that expired was taken over and the guard refuses us.
                if (migration.Mode == MigrationMode.Cutover) await RequireVerifiedBackfills(run, migration, receipts).ConfigureAwait(false);
                if (migration.Mode == MigrationMode.Contract) RequireSoak(run, migration, receipts);
                var outcome = migration.Mode == MigrationMode.Backfill
                    ? await ApplyBackfill(run, migration, receipt).ConfigureAwait(false)
                    : await ApplyStatements(run, migration, receipt).ConfigureAwait(false);
                applied.Add(outcome);
                receipts = await ReadReceipts(run).ConfigureAwait(false);
                highest = migration.Sequence;
            }
        }
        finally
        {
            // Release only a lease still ours; a stale migrator's release matches nothing.
            try
            {
                await ReleaseLease(run).ConfigureAwait(false);
            }
            catch (MigrationClientException)
            {
                // The lease expires on its own.
            }
        }

        var state = await ReadState(run).ConfigureAwait(false);
        return new RunResult(run.Fence, applied, (int)state.SchemaVersion, applied.Count == 0);
    }

    /// <summary>Read-only status of the database against the catalog.</summary>
    public static async Task<MigrationStatus> StatusAsync(
        IMigrationClient client,
        IReadOnlyList<Migration> migrations,
        Func<long>? now = null,
        CancellationToken cancellationToken = default)
    {
        var run = new Run(new RunOptions
        {
            Client = client,
            Migrations = migrations,
            Runner = "status",
            Now = now ?? (() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()),
            Compatibility = new CompatibilityInput("local", string.Empty, string.Empty, string.Empty),
            CancellationToken = cancellationToken,
        });
        if (!await TableExists(run).ConfigureAwait(false))
            return new MigrationStatus(
                false, 0, -1, 0, 0, 0, null, [],
                migrations.Select(entry => entry.File).ToList());
        var state = await ReadState(run).ConfigureAwait(false);
        var receipts = await ReadReceipts(run).ConfigureAwait(false);
        VerifyReceipts(receipts, migrations, allowAhead: true);
        return new MigrationStatus(
            true,
            Math.Max(0, receipts.Count - migrations.Count),
            (int)state.SchemaVersion,
            (int)state.ReadHorizon,
            (int)state.WriteHorizon,
            state.Fence,
            state.LeaseHolder,
            receipts.Select(entry => new ReceiptStatus(
                entry.Sequence,
                entry.File,
                entry.State == StateApplied ? "applied" : "applying",
                entry.StatementsDone,
                entry.StatementCount)).ToList(),
            migrations
                .Where(entry => !receipts.Any(receipt => receipt.Sequence == entry.Sequence && receipt.State == StateApplied))
                .Select(entry => entry.File)
                .ToList());
    }

    /// <summary>
    /// Whether an application build may use the database (readiness, and the compatible-rollback rule): it must not be newer than the
    /// applied schema, and the horizons name the oldest builds that may still read and write.
    /// </summary>
    public static Verdict Compatibility(int stateSchemaVersion, int readHorizon, int writeHorizon, int applicationSchemaVersion)
    {
        if (applicationSchemaVersion > stateSchemaVersion)
            return new Verdict(false, false, "the application expects a newer schema than the database has applied");
        var canRead = applicationSchemaVersion >= readHorizon;
        var canWrite = applicationSchemaVersion >= writeHorizon;
        return new Verdict(canRead, canWrite, canWrite ? "compatible" : canRead ? "the build is below the write horizon" : "the build is below the read horizon");
    }
}
