// SPDX-License-Identifier: AGPL-3.0-only
using System.Text.Json.Nodes;
using ArcForges.Cloud.Storage.D1.MigrationRunner;
using ArcForges.Cloud.Storage.Physical;
using ArcForges.Cloud.Tools.Generation.Migrations;
using Xunit;
using static ArcForges.Cloud.Tests.Reduction.MigrationTestSupport;

namespace ArcForges.Cloud.Tests.Reduction;

/// <summary>
/// CLOUD.84 U9: one-for-one C# replacement of tests/worker/d1-migration-runner.test.ts (30 test blocks). The same cases, negatives and
/// limits run against the C# engine in src/ArcForges.Cloud.Storage.D1/MigrationRunner, on the SQLite batch oracle (D8). The column-level
/// comparison of the physical manifest is reduced to table and column names and order; the full definitions stay checked by the physical
/// drift gate (eng/verification/physical-schema.ts, Node build tooling under D4 and D5).
/// </summary>
public sealed class MigrationRunnerTests
{
    [Fact]
    public void EnumNumbersAreTheManifestRegistryNumbers()
    {
        var mode = PhysicalSchema.Enums.Single(entry => entry.Name == "platform.migration_mode");
        var state = PhysicalSchema.Enums.Single(entry => entry.Name == "platform.migration_state");
        foreach (var (name, number) in new[] { ("expand", (int)MigrationMode.Expand), ("backfill", (int)MigrationMode.Backfill), ("cutover", (int)MigrationMode.Cutover), ("contract", (int)MigrationMode.Contract) })
            Assert.Equal(number, mode.Members.Single(member => member.Name == name).Number);
        Assert.Equal(MigrationEngine.StateApplying, state.Members.Single(member => member.Name == "applying").Number);
        Assert.Equal(MigrationEngine.StateApplied, state.Members.Single(member => member.Name == "applied").Number);
    }

    [Fact]
    public async Task FreshDatabaseReceivesEveryMigrationInOrderWithReceiptsAndEqualsTheManifest()
    {
        var baseline = Baseline();
        using var client = new SqliteBatchOracle();
        var time = new TestClock();
        var result = await MigrationEngine.ApplyPendingAsync(Options(client, baseline, "run-1", time));
        Assert.False(result.AlreadyCurrent);
        Assert.Equal(baseline.Count - 1, result.SchemaVersion);
        Assert.Equal(baseline.Count - 1, result.Applied.Count);
        var receipts = client.Query("SELECT sequence, file_name, checksum, state, statements_done, statement_count, runner FROM platform_migration_receipt ORDER BY sequence");
        Assert.Equal(baseline.Count, receipts.Count);
        for (var index = 0; index < receipts.Count; index++)
        {
            var migration = baseline[index];
            Assert.Equal(index.ToString(System.Globalization.CultureInfo.InvariantCulture), receipts[index][0]);
            Assert.Equal(migration.File, receipts[index][1]);
            Assert.Equal(migration.Sha256, receipts[index][2]);
            Assert.Equal(MigrationEngine.StateApplied.ToString(System.Globalization.CultureInfo.InvariantCulture), receipts[index][3]);
            Assert.Equal(migration.Statements.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), receipts[index][4]);
            Assert.Equal(migration.Statements.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), receipts[index][5]);
        }

        var state = client.Query("SELECT schema_version, fence, lease_holder FROM platform_schema_state");
        Assert.Equal((baseline.Count - 1).ToString(System.Globalization.CultureInfo.InvariantCulture), state[0][0]);
        Assert.Null(state[0][2]);
        AssertPhysicalColumns(client);
        Assert.Empty(client.Query("PRAGMA foreign_key_check"));
        var compatibilityRecord = JsonNode.Parse(client.Query("SELECT compatibility FROM platform_migration_receipt WHERE sequence = 3")[0][0]!)!;
        var expected = JsonNode.Parse($$"""
            {"sourceRevision":"{{Compat.SourceRevision}}","schemaVersion":3,"planManifestHash":"{{Compat.PlanManifestHash}}","abi":"{{Compat.Abi}}","runtime":"{{Compat.Runtime}}"}
            """)!;
        Assert.True(JsonNode.DeepEquals(expected, compatibilityRecord));
    }

    [Fact]
    public async Task SecondRunAppliesNothingTakesAHigherFenceAndReleasesTheLease()
    {
        using var client = new SqliteBatchOracle();
        var time = new TestClock();
        var first = await MigrationEngine.ApplyPendingAsync(Options(client, Baseline(), "run-1", time));
        var second = await MigrationEngine.ApplyPendingAsync(Options(client, Baseline(), "run-2", time));
        Assert.True(second.AlreadyCurrent);
        Assert.Empty(second.Applied);
        Assert.True(second.Fence > first.Fence);
        var report = await MigrationEngine.StatusAsync(client, Baseline(), time.Read, TestContext.Current.CancellationToken);
        Assert.Empty(report.Pending);
        Assert.Null(report.LeaseHolder);
    }

    [Fact]
    public async Task RunInterruptedAtAnyChunkBoundaryResumesFromItsReceiptAndEndsWithTheSameSchema()
    {
        var baseline = Baseline();
        using var reference = new SqliteBatchOracle();
        var chunks = 0;
        await MigrationEngine.ApplyPendingAsync(Options(reference, baseline, "reference", new TestClock(), maxChunkStatements: 6,
            hooks: new EngineHooks { AfterChunk = _ => { chunks++; return Task.CompletedTask; } }));
        Assert.True(chunks > 30, $"expected many chunks, saw {chunks}");
        var referenceSnapshot = reference.SchemaSnapshot();
        for (var crashAt = 1; crashAt <= chunks; crashAt += Math.Max(1, chunks / 14))
        {
            using var live = new SqliteBatchOracle();
            var dead = false;
            var crashing = new DelegateClient((statements, token) => dead ? Gone() : live.BatchAsync(statements, token));
            var time = new TestClock();
            var seen = 0;
            var failure = await Assert.ThrowsAsync<MigrationClientException>(() => MigrationEngine.ApplyPendingAsync(Options(crashing, baseline, "crashing", time,
                maxChunkStatements: 6,
                hooks: new EngineHooks
                {
                    AfterChunk = _ =>
                    {
                        if (++seen == crashAt)
                        {
                            dead = true;
                            throw new MigrationClientException("crash after a committed chunk");
                        }

                        return Task.CompletedTask;
                    },
                })));
            Assert.Matches("crash after a committed chunk", failure.Message);
            // The crashed process never released its lease; the next run starts after it expired and resumes from the receipt.
            time.Advance(120_000);
            var resumed = await MigrationEngine.ApplyPendingAsync(Options(live, baseline, "resumed", time, maxChunkStatements: 6));
            Assert.Equal(baseline.Count - 1, resumed.SchemaVersion);
            Assert.Equal(referenceSnapshot, live.SchemaSnapshot());
            Assert.Equal(0L, live.Scalar($"SELECT COUNT(*) FROM platform_migration_receipt WHERE state = {MigrationEngine.StateApplying}"));
        }
    }

    [Fact]
    public async Task CrashBeforeAChunkLeavesTheReceiptWhereItWasAndTheResumeRepeatsNothing()
    {
        using var live = new SqliteBatchOracle();
        var time = new TestClock();
        var dead = false;
        var crashing = new DelegateClient((statements, token) => dead ? Gone() : live.BatchAsync(statements, token));
        var seen = 0;
        var failure = await Assert.ThrowsAsync<MigrationClientException>(() => MigrationEngine.ApplyPendingAsync(Options(crashing, Baseline(), "a", time,
            maxChunkStatements: 4,
            hooks: new EngineHooks
            {
                BeforeChunk = info =>
                {
                    if (info.Sequence == 3 && ++seen == 2)
                    {
                        dead = true;
                        throw new MigrationClientException("crash before");
                    }

                    return Task.CompletedTask;
                },
            })));
        Assert.Matches("crash before", failure.Message);
        var partial = live.Query("SELECT statements_done, statement_count FROM platform_migration_receipt WHERE sequence = 3")[0];
        Assert.Equal("4", partial[0]);
        Assert.True(long.Parse(partial[1]!, System.Globalization.CultureInfo.InvariantCulture) > 4);
        time.Advance(120_000);
        await MigrationEngine.ApplyPendingAsync(Options(live, Baseline(), "b", time, maxChunkStatements: 4));
        AssertPhysicalColumns(live);
    }

    [Fact]
    public async Task StaleMigratorCannotApplyAnythingAfterAnotherMigratorTookOver()
    {
        var baseline = Baseline();
        using var client = new SqliteBatchOracle();
        var time = new TestClock();
        var takeover = false;
        var error = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(client, baseline, "stale-a", time,
            leaseMs: 1_000,
            maxChunkStatements: 3,
            hooks: new EngineHooks
            {
                AfterChunk = async info =>
                {
                    if (info.Sequence == 6 && info.To == 3 && !takeover)
                    {
                        takeover = true;
                        time.Advance(5_000);
                        // B starts after A's lease expired, takes a higher fence and finishes the whole catalog.
                        await MigrationEngine.ApplyPendingAsync(Options(client, baseline, "takeover-b", time, maxChunkStatements: 3));
                    }
                },
            })));
        Assert.Equal("stale-migrator", error.Code);
        // The stale migrator's chunk rolled back as a whole: nothing partial, and B's schema is intact and complete.
        AssertPhysicalColumns(client);
        Assert.Equal(baseline.Count.ToString(System.Globalization.CultureInfo.InvariantCulture), client.Query("SELECT COUNT(*) FROM platform_migration_receipt")[0][0]);
        var runners = client.Query("SELECT DISTINCT runner FROM platform_migration_receipt WHERE sequence > 0 ORDER BY runner").Select(row => row[0]).ToList();
        Assert.Contains("takeover-b", runners);
    }

    [Fact]
    public async Task SecondMigratorIsRefusedWhileTheFirstHoldsALiveLease()
    {
        using var client = new SqliteBatchOracle();
        var time = new TestClock();
        var baseline = Baseline();
        await MigrationEngine.ApplyPendingAsync(Options(client, baseline, "init", time, stopAfter: 1));
        MigrationError? refused = null;
        await MigrationEngine.ApplyPendingAsync(Options(client, baseline, "holder", time, stopAfter: 3,
            hooks: new EngineHooks
            {
                AfterChunk = async info =>
                {
                    if (info.Sequence != 2 || refused is not null) return;
                    try
                    {
                        await MigrationEngine.ApplyPendingAsync(Options(client, baseline, "intruder", time));
                    }
                    catch (MigrationError error)
                    {
                        refused = error;
                    }
                },
            }));
        Assert.NotNull(refused);
        Assert.Equal("lease-held", refused.Code);
    }

    [Fact]
    public async Task EditedMergedMigrationIsRefusedByItsReceiptChecksumAndDatabaseAheadIsRefused()
    {
        using var client = new SqliteBatchOracle();
        var time = new TestClock();
        var baseline = Baseline();
        await MigrationEngine.ApplyPendingAsync(Options(client, baseline, "r1", time, stopAfter: 5));
        var edited = baseline.Select(migration => migration.Sequence == 3
            ? migration with { Sha256 = MigrationSql.ChecksumOf($"{migration.Text}\n-- edited\n") }
            : migration).ToList();
        var mismatch = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(client, edited, "r2", time)));
        Assert.Equal("checksum-mismatch", mismatch.Code);
        var ahead = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(client, baseline.Take(4).ToList(), "r3", time)));
        Assert.Equal("database-ahead", ahead.Code);
    }

    [Fact]
    public void EveryModeAcceptsOnlyItsOwnStatementsAndNoMigrationControlsTransactionsOrPragmas()
    {
        static List<SqlStatement> Split(string sql) => MigrationSql.SplitStatements(sql);
        Assert.Empty(MigrationSql.ModeViolations(MigrationMode.Expand, Split("CREATE TABLE a (x TEXT) STRICT; CREATE INDEX i ON a (x); ALTER TABLE a ADD COLUMN y TEXT;")));
        Assert.Single(MigrationSql.ModeViolations(MigrationMode.Expand, Split("DROP TABLE a")));
        Assert.Single(MigrationSql.ModeViolations(MigrationMode.Expand, Split("ALTER TABLE a DROP COLUMN y")));
        Assert.Single(MigrationSql.ModeViolations(MigrationMode.Expand, Split("ALTER TABLE a RENAME TO b")));
        Assert.Single(MigrationSql.ModeViolations(MigrationMode.Expand, Split("UPDATE a SET x = 1")));
        Assert.Single(MigrationSql.ModeViolations(MigrationMode.Expand, Split("INSERT INTO a VALUES (1)")));
        foreach (var mode in new[] { MigrationMode.Expand, MigrationMode.Cutover, MigrationMode.Contract })
        {
            Assert.Single(MigrationSql.ModeViolations(mode, Split("BEGIN")));
            Assert.Single(MigrationSql.ModeViolations(mode, Split("COMMIT")));
            Assert.Single(MigrationSql.ModeViolations(mode, Split("PRAGMA foreign_keys = OFF")));
            Assert.Single(MigrationSql.ModeViolations(mode, Split("ATTACH DATABASE 'x' AS y")));
            Assert.Single(MigrationSql.ModeViolations(mode, Split("VACUUM")));
        }

        Assert.Empty(MigrationSql.ModeViolations(MigrationMode.Contract, Split("PRAGMA defer_foreign_keys = ON")));
        Assert.Empty(MigrationSql.ModeViolations(MigrationMode.Contract, Split("DROP TABLE a; ALTER TABLE b DROP COLUMN c;")));
        Assert.Empty(MigrationSql.ModeViolations(MigrationMode.Cutover, Split("UPDATE a SET x = 1; INSERT INTO a VALUES (2); DELETE FROM a WHERE x = 9;")));
        Assert.Single(MigrationSql.ModeViolations(MigrationMode.Cutover, Split("DROP TABLE a")));
    }

    [Fact]
    public void TheStatementSplitterKeepsTriggerBodiesStringsAndCommentsWhole()
    {
        const string sql = "-- header ; with a semicolon\nCREATE TABLE a (x TEXT DEFAULT 'a;b'); /* ; */\nCREATE TRIGGER t BEFORE UPDATE ON a BEGIN SELECT CASE WHEN 1 THEN 2 END; SELECT RAISE(ABORT, 'x;y'); END;\nCREATE TABLE \"q;\" (x TEXT);";
        var parts = MigrationSql.SplitStatements(sql);
        Assert.Equal(3, parts.Count);
        Assert.Matches("^CREATE TRIGGER t[\\s\\S]*END$", parts[1].Sql);
        Assert.All(parts, part => Assert.Equal("CREATE", part.Head[0]));
        Assert.Matches("unterminated trigger", Assert.Throws<MigrationError>(() => MigrationSql.SplitStatements("CREATE TRIGGER t BEFORE UPDATE ON a BEGIN SELECT 1;")).Message);
        Assert.Matches("unterminated", Assert.Throws<MigrationError>(() => MigrationSql.SplitStatements("SELECT 'x")).Message);
    }

    private const string BackfillHeader = "-- af-migration: module=x mode=backfill\n";

    [Fact]
    public async Task BackfillConvertsBoundedPagesCountsARowWrittenAfterItWasReadAsStaleAndNeverOverwritesIt()
    {
        var (client, time, chain) = await SeededScratchAsync(250);
        using (client)
        {
            var widths = new List<int>();
            var spy = new DelegateClient((statements, token) =>
            {
                if (statements.Any(statement => statement.Sql.Contains("UPDATE \"scratch_item\" SET \"converted\"", StringComparison.Ordinal)))
                    widths.Add(statements.Count(statement => statement.Sql.Contains("UPDATE \"scratch_item\" SET \"converted\"", StringComparison.Ordinal)));
                return client.BatchAsync(statements, token);
            });
            var injected = false;
            var result = await MigrationEngine.ApplyPendingAsync(Options(spy, chain, "backfiller", time, hooks: new EngineHooks
            {
                AfterPageSelect = info =>
                {
                    if (!injected)
                    {
                        injected = true;
                        // A concurrent writer changes a selected row after the page read it: the row's revision moves.
                        client.Exec($"UPDATE scratch_item SET legacy = 'fresh-value', rev = rev + 1 WHERE id = '{info.Keys[3]}'");
                    }

                    return Task.CompletedTask;
                },
            }));
            var backfill = result.Applied.Single(entry => entry.Mode == "backfill");
            Assert.Equal(1L, backfill.RowsStale);
            Assert.Equal(250L, backfill.RowsConverted);
            Assert.True(backfill.Passes >= 2, "the stale row needs a second pass");
            Assert.True(widths.Max() <= 100, $"a page converts at most 100 rows, saw {widths.Max()}");
            Assert.Single(client.Query("SELECT legacy, converted, rev FROM scratch_item WHERE converted = 'FRESH-VALUE'"));
            Assert.Equal(0L, client.Scalar("SELECT COUNT(*) FROM scratch_item WHERE converted IS NULL OR converted <> upper(legacy)"));
            var checkpoint = client.Query("SELECT verified, rows_converted, rows_stale FROM platform_backfill_checkpoint WHERE sequence = 2")[0];
            Assert.Equal(new[] { "1", "250", "1" }, checkpoint.ToArray());
        }
    }

    [Fact]
    public async Task BackfillInterruptedBetweenPagesResumesFromItsCheckpointAndConvertsEveryRowExactlyOnce()
    {
        var (client, time, chain) = await SeededScratchAsync(250);
        using (client)
        {
            var dead = false;
            var crashing = new DelegateClient((statements, token) => dead ? Gone() : client.BatchAsync(statements, token));
            var pages = 0;
            var failure = await Assert.ThrowsAsync<MigrationClientException>(() => MigrationEngine.ApplyPendingAsync(Options(crashing, chain, "first", time, hooks: new EngineHooks
            {
                AfterPageSelect = _ =>
                {
                    if (++pages == 2)
                    {
                        dead = true;
                        throw new MigrationClientException("crash during the second page");
                    }

                    return Task.CompletedTask;
                },
            })));
            Assert.Matches("crash during the second page", failure.Message);
            var mid = client.Query("SELECT last_key, rows_converted FROM platform_backfill_checkpoint WHERE sequence = 2")[0];
            Assert.Equal("100", mid[1]);
            Assert.NotNull(mid[0]);
            time.Advance(120_000);
            var result = await MigrationEngine.ApplyPendingAsync(Options(client, chain, "second", time));
            Assert.Equal(250L, result.Applied.Single(entry => entry.Mode == "backfill").RowsConverted);
            Assert.Equal(0L, client.Scalar("SELECT COUNT(*) FROM scratch_item WHERE converted IS NULL"));
        }
    }

    [Fact]
    public async Task BackfillThatCannotConvergeIsRefusedInsteadOfLooping()
    {
        var (client, time, _) = await SeededScratchAsync(3);
        using (client)
        {
            var never = BackfillBody.Replace("\"converted\" = upper(\"legacy\")", "\"legacy\" = \"legacy\"", StringComparison.Ordinal);
            var chain = new List<Migration>
            {
                Baseline()[0],
                Synthetic(1, "scratch", MigrationMode.Expand, Scratch),
                Synthetic(2, "scratch", MigrationMode.Backfill, never),
            };
            var error = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(client, chain, "loop", time)));
            Assert.Equal("backfill-not-converging", error.Code);
        }
    }

    [Fact]
    public void TheBackfillSectionsAreValidatedOneStatementEachRevisionGuardKeyCursorAndAtMost100Rows()
    {
        Assert.Equal(100, MigrationSql.ParseBackfill(BackfillHeader + BackfillBody).PageSize);
        Assert.Matches("pageSize", Assert.Throws<MigrationError>(() => MigrationSql.ParseBackfill(BackfillHeader + BackfillBody.Replace("\"pageSize\":100", "\"pageSize\":101", StringComparison.Ordinal))).Message);
        Assert.Matches("revision", Assert.Throws<MigrationError>(() => MigrationSql.ParseBackfill(BackfillHeader + BackfillBody.Replace("AND \"rev\" = CAST(? AS INTEGER)", "AND ? IS NOT NULL", StringComparison.Ordinal))).Message);
        Assert.Matches("ordered|parameters", Assert.Throws<MigrationError>(() => MigrationSql.ParseBackfill(BackfillHeader + BackfillBody.Replace("ORDER BY \"id\" LIMIT ?", string.Empty, StringComparison.Ordinal))).Message);
        Assert.Matches("verify", Assert.Throws<MigrationError>(() => MigrationSql.ParseBackfill(BackfillHeader + BackfillBody.Replace("-- section: verify", "-- section: other", StringComparison.Ordinal))).Message);
    }

    [Fact]
    public async Task CutoverWaitsForItsVerifiedBackfillsAndMovesTheHorizonsAndAContractWaitsForSoakAndConsent()
    {
        var (client, time, _) = await SeededScratchAsync(5);
        using (client)
        {
            var chain = new List<Migration>
            {
                Baseline()[0],
                Synthetic(1, "scratch", MigrationMode.Expand, Scratch),
                Synthetic(2, "scratch", MigrationMode.Backfill, BackfillBody),
                Synthetic(3, "scratch", MigrationMode.Cutover, "UPDATE \"scratch_item\" SET \"rev\" = \"rev\" WHERE 0;", " requires=2 readHorizon=1 writeHorizon=3"),
                Synthetic(4, "scratch", MigrationMode.Contract, "ALTER TABLE \"scratch_item\" DROP COLUMN \"legacy\";", " after=3 soak=3600"),
            };
            // Before the backfill ran, a cutover is refused.
            await MigrationEngine.ApplyPendingAsync(Options(client, chain, "early", time, stopAfter: 1));
            var early = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(client,
                new List<Migration>
                {
                    chain[0],
                    chain[1],
                    Synthetic(2, "scratch", MigrationMode.Cutover, "UPDATE \"scratch_item\" SET \"rev\" = \"rev\" WHERE 0;", " requires=7"),
                },
                "x",
                time)));
            Assert.Equal("cutover-blocked", early.Code);
        }

        // Fresh database for the real chain.
        var (fresh, freshTime, chainFresh) = await SeededScratchAsync(5);
        using (fresh)
        {
            var chain = new List<Migration>
            {
                chainFresh[0],
                chainFresh[1],
                chainFresh[2],
                Synthetic(3, "scratch", MigrationMode.Cutover, "UPDATE \"scratch_item\" SET \"rev\" = \"rev\" WHERE 0;", " requires=2 readHorizon=1 writeHorizon=3"),
                Synthetic(4, "scratch", MigrationMode.Contract, "ALTER TABLE \"scratch_item\" DROP COLUMN \"legacy\";", " after=3 soak=3600"),
            };
            await MigrationEngine.ApplyPendingAsync(Options(fresh, chain, "main", freshTime, stopAfter: 3));
            var state = fresh.Query("SELECT schema_version, read_horizon, write_horizon FROM platform_schema_state")[0];
            Assert.Equal(new[] { "3", "1", "3" }, state.ToArray());
            // The compatible-rollback rule: a build older than the write horizon is refused after the cutover, newer ones are fine.
            var older = MigrationEngine.Compatibility(3, 1, 3, 2);
            Assert.False(older.CanWrite);
            Assert.True(older.CanRead);
            Assert.True(MigrationEngine.Compatibility(3, 1, 3, 3).CanWrite);
            // The contract: no consent, then no soak, then applied.
            var noConsent = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(fresh, chain, "c1", freshTime)));
            Assert.Equal("contract-refused", noConsent.Code);
            Assert.Matches("allowContract", noConsent.Message);
            var noSoak = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(fresh, chain, "c2", freshTime, allowContract: true)));
            Assert.Equal("contract-refused", noSoak.Code);
            Assert.Matches("soak", noSoak.Message);
            freshTime.Advance(3_600_000 + 1);
            var done = await MigrationEngine.ApplyPendingAsync(Options(fresh, chain, "c3", freshTime, allowContract: true));
            Assert.Equal(4, done.SchemaVersion);
            Assert.Equal("4", fresh.Query("SELECT schema_version FROM platform_schema_state")[0][0]);
            Assert.Equal(0L, fresh.Scalar("SELECT COUNT(*) FROM pragma_table_info('scratch_item') WHERE name = 'legacy'"));
        }
    }

    [Fact]
    public async Task TheHorizonsCannotBeSetInconsistently()
    {
        var (client, _, _) = await SeededScratchAsync(1);
        using (client)
        {
            Assert.Matches("ck_platform_schema_state__horizons", client.RefusalOf("UPDATE platform_schema_state SET write_horizon = 99"));
            Assert.Matches("af_monotonic_platform_schema_state_schema_version", client.RefusalOf("UPDATE platform_schema_state SET schema_version = 0"));
        }
    }

    [Fact]
    public void TheCommittedCatalogIsGaplessLockedAndParsesInItsModes()
    {
        var catalog = Baseline();
        Assert.Equal(0, catalog[0].Sequence);
        Assert.Equal("platform", catalog[0].Module);
        var lockEntries = MigrationFiles.ReadLock(MigrationsDirectory);
        Assert.Equal(catalog.Count - 1, MigrationCatalog.LockIdentity(lockEntries).Highest);
        Assert.All(catalog, migration => Assert.Equal(MigrationMode.Expand, migration.Mode));
        // Locking the committed numbered files again changes nothing.
        Assert.Equal(lockEntries, MigrationCatalog.LockNumbered(lockEntries, MigrationFiles.ReadDirectory(MigrationsDirectory)));
    }

    [Fact]
    public void EditingALockedMigrationLeavingAGapOrMismatchingAHeaderIsRefused()
    {
        var files = MigrationFiles.ReadDirectory(MigrationsDirectory);
        var locked = MigrationFiles.ReadLock(MigrationsDirectory);
        var tampered = files.Select(file => file.Name == "0003_identity__baseline.sql" ? file with { Text = file.Text + "\n-- tamper\n" } : file).ToList();
        Assert.Matches("edited after it was locked", Assert.Throws<MigrationError>(() => MigrationCatalog.Load(tampered, locked)).Message);
        Assert.NotEmpty(MigrationCatalog.Load(files, locked));
        var gap = files.Where(file => file.Name != "0004_device__baseline.sql").ToList();
        Assert.Matches("gap or duplicate|migration files", Assert.Throws<MigrationError>(() => MigrationCatalog.Load(gap, locked)).Message);
        var renamed = files.Select(file => file.Name == "0005_workspace__baseline.sql" ? file with { Text = file.Text.Replace("module=workspace", "module=device", StringComparison.Ordinal) } : file).ToList();
        Assert.Matches("header module", Assert.Throws<MigrationError>(() => MigrationCatalog.Load(renamed, locked)).Message);
    }

    [Fact]
    public async Task TheIntegrationOwnerNumbersPendingMigrationsInOrderAndLocksThemAndTheLockStaysAppendOnlyAgainstItsBase()
    {
        var baseline = Baseline();
        var sequenceOffset = (int offset) => (baseline.Count + offset).ToString("D4", System.Globalization.CultureInfo.InvariantCulture);
        var root = CopyCatalogRoot();
        try
        {
            var directory = Path.Combine(root, MigrationFiles.MigrationsPath);
            var baseLock = MigrationFiles.ReadLock(directory);
            Directory.CreateDirectory(Path.Combine(directory, MigrationFiles.PendingDirectory));
            File.WriteAllText(Path.Combine(directory, MigrationFiles.PendingDirectory, "identity__add-nickname.sql"),
                "-- af-migration: module=identity mode=expand\nALTER TABLE \"identity_user\" ADD COLUMN \"nickname\" TEXT;\n");
            File.WriteAllText(Path.Combine(directory, MigrationFiles.PendingDirectory, "chat__add-pin.sql"),
                "-- af-migration: module=chat mode=expand\nALTER TABLE \"chat_conversation\" ADD COLUMN \"pinned\" INTEGER;\n");
            using (var output = new StringWriter())
            using (var error = new StringWriter())
            {
                Assert.Equal(0, await MigrateCommand.RunAsync(["check"], ContextFor(root, output, error)));
                Assert.Equal(0, await MigrateCommand.RunAsync(["assign"], ContextFor(root, output, error)));
                Assert.Contains($"assigned 2: {sequenceOffset(0)}_chat__add-pin.sql, {sequenceOffset(1)}_identity__add-nickname.sql", output.ToString(), StringComparison.Ordinal);
            }

            var lockEntries = MigrationFiles.ReadLock(directory);
            Assert.Equal(baseline.Count + 2, lockEntries.Count);
            Assert.Empty(MigrationCatalog.AppendOnlyProblems(baseLock, lockEntries));
            // The same lock with a base entry edited is not append-only.
            var tampered = lockEntries.Select((entry, index) => index == 2 ? entry with { Sha256 = new string('0', 64) } : entry).ToList();
            Assert.Single(MigrationCatalog.AppendOnlyProblems(baseLock, tampered));
            Assert.True(MigrationCatalog.AppendOnlyProblems(baseLock, lockEntries.Take(5).ToList()).Count > 0, "removing a merged migration is refused");
            // A pending file that breaks its mode is refused before it is numbered.
            var dropText = "-- af-migration: module=chat mode=expand\nDROP TABLE \"chat_conversation\";\n";
            Assert.Matches("expand migration may only", Assert.Throws<MigrationError>(() => MigrationCatalog.CheckPendingFile("chat__drop-it.sql", dropText)).Message);
            Assert.Equal(baseline.Count + 2, MigrationCatalog.Load(MigrationFiles.ReadDirectory(directory), MigrationFiles.ReadLock(directory)).Count);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task AnExtendedCatalogAppliesOnTopOfAnAlreadyMigratedDatabaseInOrder()
    {
        var baseline = Baseline();
        var root = CopyCatalogRoot();
        using var client = new SqliteBatchOracle();
        try
        {
            var time = new TestClock();
            await MigrationEngine.ApplyPendingAsync(Options(client, baseline, "base", time));
            var directory = Path.Combine(root, MigrationFiles.MigrationsPath);
            Directory.CreateDirectory(Path.Combine(directory, MigrationFiles.PendingDirectory));
            File.WriteAllText(Path.Combine(directory, MigrationFiles.PendingDirectory, "identity__add-nickname.sql"),
                "-- af-migration: module=identity mode=expand\nALTER TABLE \"identity_user\" ADD COLUMN \"nickname\" TEXT;\n");
            using (var output = new StringWriter())
            using (var error = new StringWriter())
                Assert.Equal(0, await MigrateCommand.RunAsync(["assign"], ContextFor(root, output, error)));
            var extended = MigrationCatalog.Load(MigrationFiles.ReadDirectory(directory), MigrationFiles.ReadLock(directory));
            var result = await MigrationEngine.ApplyPendingAsync(Options(client, extended, "next", time));
            Assert.Equal(new[] { $"{baseline.Count.ToString("D4", System.Globalization.CultureInfo.InvariantCulture)}_identity__add-nickname.sql" }, result.Applied.Select(entry => entry.File).ToArray());
            Assert.Equal(1L, client.Scalar("SELECT COUNT(*) FROM pragma_table_info('identity_user') WHERE name = 'nickname'"));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task TheRestClientPostsOneBatchWithTheBearerSecretAndMapsResultsAndFailuresNeverEchoTheSecret()
    {
        var secret = string.Join("-", "alpha", "beta", "gamma");
        var handler = new ScriptedHandler((request, body) =>
        {
            Assert.Equal("https://api.cloudflare.com/client/v4/accounts/acc/d1/database/db/query", request.RequestUri!.ToString());
            Assert.Equal($"Bearer {secret}", request.Headers.Authorization!.ToString());
            return Task.FromResult(ScriptedHandler.Json("""{"success": true, "result": [{"results": [{"a": "1", "b": 2}], "meta": {"changes": 0}}, {"results": [], "meta": {"changes": 3}}]}"""));
        });
        var ok = new D1RestClient("acc", "db", secret, handler);
        var results = await ok.BatchAsync(
            [new MigrationStatement("SELECT 1", ["x"]), new MigrationStatement("UPDATE t SET a = 1", [])],
            TestContext.Current.CancellationToken);
        Assert.Equal(0, results[0].Changes);
        Assert.Equal(new[] { "1", "2" }, results[0].Rows[0].ToArray());
        Assert.Equal(3, results[1].Changes);
        Assert.Empty(results[1].Rows);
        var sent = JsonNode.Parse(handler.Bodies[0])!;
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse("""{"batch":[{"sql":"SELECT 1","params":["x"]},{"sql":"UPDATE t SET a = 1","params":[]}]}"""), sent));

        var refused = new D1RestClient("acc", "db", secret, new ScriptedHandler((request, body) =>
            Task.FromResult(ScriptedHandler.Json("""{"success": false, "errors": [{"message": "CHECK constraint failed: x"}]}""", 400))));
        var refusal = await Assert.ThrowsAsync<MigrationClientException>(() => refused.BatchAsync([new MigrationStatement("x", [])], TestContext.Current.CancellationToken));
        Assert.Matches("CHECK constraint failed: x", refusal.Message);
        Assert.DoesNotContain(secret, refusal.Message, StringComparison.Ordinal);

        var broken = new D1RestClient("acc", "db", secret, new ScriptedHandler((request, body) =>
            throw new HttpRequestException($"network down for {secret}")));
        var unknown = await Assert.ThrowsAsync<MigrationClientException>(() => broken.BatchAsync([new MigrationStatement("x", [])], TestContext.Current.CancellationToken));
        Assert.Matches("outcome unknown", unknown.Message);
        Assert.DoesNotContain(secret, unknown.Message, StringComparison.Ordinal);

        var empty = new D1RestClient("acc", "db", secret, new ScriptedHandler((request, body) =>
            Task.FromResult(ScriptedHandler.Json("""{"success": true, "result": []}"""))));
        var shortfall = await Assert.ThrowsAsync<MigrationClientException>(() => empty.BatchAsync([new MigrationStatement("x", [])], TestContext.Current.CancellationToken));
        Assert.Matches("different number of results", shortfall.Message);
    }

    [Fact]
    public async Task ABackfillLongerThanItsLeaseRenewsItPageByPageAndIsNeverMistakenForAStaleMigrator()
    {
        var (client, time, chain) = await SeededScratchAsync(500);
        using (client)
        {
            var result = await MigrationEngine.ApplyPendingAsync(Options(client, chain, "slow", time, leaseMs: 1_000, hooks: new EngineHooks
            {
                AfterPageSelect = _ =>
                {
                    time.Advance(300);
                    return Task.CompletedTask;
                },
            }));
            Assert.Equal(500L, result.Applied.Single(entry => entry.Mode == "backfill").RowsConverted);
            Assert.Equal(0L, client.Scalar("SELECT COUNT(*) FROM scratch_item WHERE converted IS NULL"));
        }
    }

    [Fact]
    public async Task AConstraintOfTheMigrationsOwnStatementIsReportedAsItIsNotAsAStaleMigrator()
    {
        var (client, time, _) = await SeededScratchAsync(3);
        using (client)
        {
            var broken = BackfillBody.Replace("\"converted\" = upper(\"legacy\")", "\"rev\" = -1", StringComparison.Ordinal);
            var chain = new List<Migration>
            {
                Baseline()[0],
                Synthetic(1, "scratch", MigrationMode.Expand, Scratch),
                Synthetic(2, "scratch", MigrationMode.Backfill, broken),
            };
            var failure = await Assert.ThrowsAsync<MigrationClientException>(() => MigrationEngine.ApplyPendingAsync(Options(client, chain, "bad", time)));
            Assert.Matches("CHECK constraint failed", failure.Message);
        }

        using var mixed = new SqliteBatchOracle();
        var failing = Synthetic(1, "scratch", MigrationMode.Expand,
            "CREATE TABLE \"scratch_other\" (\"x\" INTEGER NOT NULL CHECK (\"x\" > 0)) STRICT;\nCREATE TRIGGER \"tr_scratch_other\" AFTER INSERT ON \"scratch_other\" BEGIN SELECT RAISE(ABORT, 'CHECK constraint failed: own'); END;");
        await MigrationEngine.ApplyPendingAsync(Options(mixed, [Baseline()[0], failing], "ok", new TestClock()));
        mixed.Exec("DROP TRIGGER tr_scratch_other");
    }

    [Fact]
    public async Task ACutoverReverifiesTheBackfillInsideItsOwnFencedBatchARowWrittenAfterTheBackfillBlocksIt()
    {
        var (client, time, _) = await SeededScratchAsync(5);
        using (client)
        {
            var chain = new List<Migration>
            {
                Baseline()[0],
                Synthetic(1, "scratch", MigrationMode.Expand, Scratch),
                Synthetic(2, "scratch", MigrationMode.Backfill, BackfillBody),
                Synthetic(3, "scratch", MigrationMode.Cutover, "UPDATE \"scratch_item\" SET \"rev\" = \"rev\" WHERE 0;", " requires=2 readHorizon=1 writeHorizon=3"),
            };
            await MigrationEngine.ApplyPendingAsync(Options(client, chain, "backfill", time, stopAfter: 2));
            Assert.Equal(1L, client.Scalar("SELECT verified FROM platform_backfill_checkpoint WHERE sequence = 2"));
            client.Exec("INSERT INTO scratch_item VALUES ('late-row', 'late', NULL, 1)");
            var blocked = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(client, chain, "cutover", time)));
            Assert.Equal("cutover-blocked", blocked.Code);
            Assert.Equal(new[] { "2", "0" }, client.Query("SELECT schema_version, write_horizon FROM platform_schema_state")[0].ToArray());
            client.Exec("UPDATE scratch_item SET converted = upper(legacy) WHERE converted IS NULL");
            var done = await MigrationEngine.ApplyPendingAsync(Options(client, chain, "cutover-2", time));
            Assert.Equal(3, done.SchemaVersion);
        }
    }

    [Fact]
    public async Task AnExpiredLeaseAloneStopsAMigratorEvenWithNoCompetitor()
    {
        using var client = new SqliteBatchOracle();
        var time = new TestClock();
        var failure = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(client, Baseline(), "slow-a", time,
            leaseMs: 1_000,
            maxChunkStatements: 3,
            hooks: new EngineHooks
            {
                AfterChunk = info =>
                {
                    if (info.Sequence == 3 && info.To == 3) time.Advance(5_000);
                    return Task.CompletedTask;
                },
            })));
        Assert.Equal("stale-migrator", failure.Code);
        Assert.Equal("3", client.Query("SELECT statements_done FROM platform_migration_receipt WHERE sequence = 3")[0][0]);
    }

    [Fact]
    public async Task AReceiptWhoseProgressMovedUnderTheMigratorStopsIt()
    {
        using var client = new SqliteBatchOracle();
        var time = new TestClock();
        var failure = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(client, Baseline(), "moved", time,
            maxChunkStatements: 3,
            hooks: new EngineHooks
            {
                AfterChunk = info =>
                {
                    if (info.Sequence == 3 && info.To == 3)
                        client.Exec("UPDATE platform_migration_receipt SET statements_done = 5 WHERE sequence = 3");
                    return Task.CompletedTask;
                },
            })));
        Assert.Equal("stale-migrator", failure.Code);
    }

    [Fact]
    public async Task AContractWaitsForTheWholeSoakOneMillisecondShortIsRefusedTheFullSoakIsAccepted()
    {
        var (client, time, _) = await SeededScratchAsync(2);
        using (client)
        {
            var chain = new List<Migration>
            {
                Baseline()[0],
                Synthetic(1, "scratch", MigrationMode.Expand, Scratch),
                Synthetic(2, "scratch", MigrationMode.Backfill, BackfillBody),
                Synthetic(3, "scratch", MigrationMode.Cutover, "UPDATE \"scratch_item\" SET \"rev\" = \"rev\" WHERE 0;", " requires=2 readHorizon=1 writeHorizon=3"),
                Synthetic(4, "scratch", MigrationMode.Contract, "ALTER TABLE \"scratch_item\" DROP COLUMN \"legacy\";", " after=3 soak=3600"),
            };
            await MigrationEngine.ApplyPendingAsync(Options(client, chain, "main", time, stopAfter: 3));
            time.Advance(3_600_000 - 1);
            var early = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(client, chain, "early", time, allowContract: true)));
            Assert.Matches("soak", early.Message);
            time.Advance(1);
            Assert.Equal(4, (await MigrationEngine.ApplyPendingAsync(Options(client, chain, "due", time, allowContract: true))).SchemaVersion);
        }
    }

    [Fact]
    public async Task ReceiptsWithAGapOrAnUnfinishedMigrationBeforeAFinishedOneAreRefused()
    {
        var time = new TestClock();
        var baseline = Baseline();
        using var gap = new SqliteBatchOracle();
        await MigrationEngine.ApplyPendingAsync(Options(gap, baseline, "g", time, stopAfter: 5));
        gap.Exec("DROP TRIGGER \"tr_platform_migration_receipt__immutable_delete\"");
        gap.Exec("DELETE FROM platform_migration_receipt WHERE sequence = 3");
        var missing = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(gap, baseline, "g2", time)));
        Assert.Equal("receipt-gap", missing.Code);

        using var order = new SqliteBatchOracle();
        await MigrationEngine.ApplyPendingAsync(Options(order, baseline, "o", time, stopAfter: 5));
        order.Exec("DROP TRIGGER \"tr_platform_migration_receipt__limited_update\"");
        order.Exec("UPDATE platform_migration_receipt SET state = 1, applied_at = NULL, statements_done = 0 WHERE sequence = 3");
        var unfinished = await Assert.ThrowsAsync<MigrationError>(() => MigrationEngine.ApplyPendingAsync(Options(order, baseline, "o2", time)));
        Assert.Equal("receipt-order", unfinished.Code);
    }

    [Fact]
    public async Task TheChunkSizeLimitsInStatementsAndInBytesAreHonoured()
    {
        using var byBytes = new SqliteBatchOracle();
        var result = await MigrationEngine.ApplyPendingAsync(Options(byBytes, Baseline(), "bytes", new TestClock(), maxChunkBytes: 1, stopAfter: 3));
        var third = result.Applied.Single(entry => entry.Sequence == 3);
        Assert.Equal(third.Statements, third.Chunks);
        using var byCount = new SqliteBatchOracle();
        var counted = await MigrationEngine.ApplyPendingAsync(Options(byCount, Baseline(), "count", new TestClock(), maxChunkStatements: 4, stopAfter: 3));
        var again = counted.Applied.Single(entry => entry.Sequence == 3);
        Assert.Equal((int)Math.Ceiling(again.Statements / 4.0), again.Chunks);
    }

    [Fact]
    public void LineEndingsDoNotChangeAChecksumOrTheStatements()
    {
        const string lf = "-- af-migration: module=x mode=expand\nCREATE TABLE a (x TEXT) STRICT;\nCREATE INDEX i ON a (x);\n";
        var crlf = lf.Replace("\n", "\r\n", StringComparison.Ordinal);
        Assert.Equal(MigrationSql.ChecksumOf(lf), MigrationSql.ChecksumOf(crlf));
        var fromCrlf = MigrationSql.SplitStatements(crlf);
        var fromLf = MigrationSql.SplitStatements(lf);
        Assert.Equal(fromLf.Select(statement => statement.Sql), fromCrlf.Select(statement => statement.Sql));
        Assert.Equal(fromLf.Select(statement => statement.Head), fromCrlf.Select(statement => statement.Head));
    }
}
