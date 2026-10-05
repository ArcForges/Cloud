// SPDX-License-Identifier: AGPL-3.0-only
// The D1 migration runner against SQLite as the real-SQL oracle: ordering, receipts, idempotency, interruption at every chunk
// boundary, a stale migrator after takeover, edited merged migrations, the four modes (expand, backfill with a concurrent writer,
// fenced cutover, contract after soak) and the compatible-rollback rule. SQLite is not D1: this proves the runner's logic and the
// SQL, not the provider's batch atomicity over its REST API (a recorded live check).
import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
  copyFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { DatabaseSync } from "node:sqlite";
import test from "node:test";
import {
  appendOnlyProblems,
  assignPending,
  checkPending,
  defaultMigrationsDirectory,
  loadCatalog,
  lockIdentity,
  lockNumbered,
  readLock,
  type Migration,
} from "../../eng/migrations/catalog.ts";
import {
  MigrationClientError,
  RestMigrationClient,
  SqliteMigrationClient,
  type BatchResult,
  type MigrationClient,
  type MigrationStatement,
} from "../../eng/migrations/clients.ts";
import {
  applyPending,
  compatibility,
  MigrationError,
  modeNumber,
  stateApplied,
  stateApplying,
  status,
  type RunOptions,
} from "../../eng/migrations/runner.ts";
import {
  checksumOf,
  modeViolations,
  parseBackfill,
  parseHeader,
  splitStatements,
} from "../../eng/migrations/sql.ts";
import {
  compareShapes,
  enumMap,
  expectedShape,
  loadManifest,
  readShape,
} from "../../eng/verification/physical-schema.ts";

const baseline = loadCatalog();
const schema = loadManifest();
const compat = {
  sourceRevision: "0123456789abcdef0123456789abcdef01234567",
  planManifestHash: "p".repeat(8),
  abi: "abi-1",
  runtime: "net10.0",
};

function clock(start = 1_790_000_000_000) {
  const state = { now: start };
  return { read: () => state.now, advance: (ms: number) => (state.now += ms) };
}

function options(
  client: MigrationClient,
  migrations: readonly Migration[],
  runner: string,
  time: { read: () => number },
  extra: Partial<RunOptions> = {},
): RunOptions {
  return {
    client,
    migrations,
    runner,
    now: time.read,
    compatibility: compat,
    leaseMs: 60_000,
    ...extra,
  };
}

function synthetic(
  sequence: number,
  module: string,
  mode: "expand" | "backfill" | "cutover" | "contract",
  body: string,
  header = "",
): Migration {
  const text = `-- af-migration: module=${module} mode=${mode}${header}\n${body}\n`;
  const parsed = parseHeader(text);
  return {
    sequence,
    file: `${String(sequence).padStart(4, "0")}_${module}__test-${sequence}.sql`,
    module,
    mode,
    options: parsed.options,
    sha256: checksumOf(text),
    text,
    statements: mode === "backfill" ? [] : splitStatements(text),
  };
}

const scalar = (database: DatabaseSync, sql: string, ...params: (string | number)[]) =>
  Object.values(database.prepare(sql).get(...params) as Record<string, unknown>)[0];

test("the runner's enum numbers are the manifest's registry numbers", () => {
  const registry = enumMap(schema);
  const mode = registry.get("platform.migration_mode");
  const state = registry.get("platform.migration_state");
  assert(mode && state);
  for (const [name, number] of Object.entries(modeNumber))
    assert.equal(mode.members.find((member) => member.name === name)?.number, number, name);
  assert.equal(state.members.find((member) => member.name === "applying")?.number, stateApplying);
  assert.equal(state.members.find((member) => member.name === "applied")?.number, stateApplied);
});

test("a fresh database receives every migration in order with a receipt, and equals the manifest", async () => {
  const client = new SqliteMigrationClient();
  const time = clock();
  const result = await applyPending(options(client, baseline, "run-1", time));
  assert.equal(result.alreadyCurrent, false);
  assert.equal(result.schemaVersion, baseline.length - 1);
  assert.equal(result.applied.length, baseline.length - 1);
  const db = client.database;
  const receipts = db
    .prepare(
      "SELECT sequence, file_name, checksum, state, statements_done, statement_count, runner FROM platform_migration_receipt ORDER BY sequence",
    )
    .all() as {
    sequence: number;
    file_name: string;
    checksum: string;
    state: number;
    statements_done: number;
    statement_count: number;
    runner: string;
  }[];
  assert.equal(receipts.length, baseline.length);
  receipts.forEach((receipt, index) => {
    const migration = baseline[index] as Migration;
    assert.equal(receipt.sequence, index);
    assert.equal(receipt.file_name, migration.file);
    assert.equal(receipt.checksum, migration.sha256);
    assert.equal(receipt.state, stateApplied);
    assert.equal(receipt.statements_done, migration.statements.length);
    assert.equal(receipt.statement_count, migration.statements.length);
  });
  const state = db
    .prepare("SELECT schema_version, fence, lease_holder FROM platform_schema_state")
    .get() as { schema_version: number; fence: number; lease_holder: string | null };
  assert.equal(state.schema_version, baseline.length - 1);
  assert.equal(state.lease_holder, null, "the lease is released at the end of the run");
  assert.deepEqual(compareShapes(readShape(db), expectedShape(schema)), []);
  assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(), []);
  const compatibilityRecord = JSON.parse(
    String(scalar(db, "SELECT compatibility FROM platform_migration_receipt WHERE sequence = 3")),
  ) as Record<string, unknown>;
  assert.deepEqual(compatibilityRecord, {
    sourceRevision: compat.sourceRevision,
    schemaVersion: 3,
    planManifestHash: compat.planManifestHash,
    abi: compat.abi,
    runtime: compat.runtime,
  });
});

test("a second run applies nothing, takes a higher fence and releases the lease", async () => {
  const client = new SqliteMigrationClient();
  const time = clock();
  const first = await applyPending(options(client, baseline, "run-1", time));
  const second = await applyPending(options(client, baseline, "run-2", time));
  assert.equal(second.alreadyCurrent, true);
  assert.equal(second.applied.length, 0);
  assert(second.fence > first.fence);
  const report = await status(client, baseline, time.read);
  assert.deepEqual(report.pending, []);
  assert.equal(report.leaseHolder, null);
});

test("a run interrupted at any chunk boundary resumes from its receipt and ends with the same schema", async () => {
  const reference = new SqliteMigrationClient();
  const probe = { chunks: 0 };
  await applyPending(
    options(reference, baseline, "reference", clock(), {
      maxChunkStatements: 6,
      hooks: { afterChunk: () => void probe.chunks++ },
    }),
  );
  assert(probe.chunks > 30, `expected many chunks, saw ${probe.chunks}`);
  const referenceShape = JSON.stringify(readShape(reference.database));
  for (
    let crashAt = 1;
    crashAt <= probe.chunks;
    crashAt += Math.max(1, Math.floor(probe.chunks / 14))
  ) {
    const live = new SqliteMigrationClient();
    let dead = false;
    const crashing: MigrationClient = {
      batch: (statements) =>
        dead
          ? Promise.reject(new MigrationClientError("the migrator process is gone"))
          : live.batch(statements),
    };
    const time = clock();
    let seen = 0;
    await assert.rejects(
      applyPending(
        options(crashing, baseline, "crashing", time, {
          maxChunkStatements: 6,
          hooks: {
            afterChunk: () => {
              if (++seen === crashAt) {
                dead = true;
                throw new MigrationClientError("crash after a committed chunk");
              }
            },
          },
        }),
      ),
      /crash after a committed chunk/u,
    );
    // The crashed process never released its lease; the next run starts after it expired and resumes from the receipt.
    time.advance(120_000);
    const resumed = await applyPending(
      options(live, baseline, "resumed", time, { maxChunkStatements: 6 }),
    );
    assert.equal(resumed.schemaVersion, baseline.length - 1);
    assert.equal(
      JSON.stringify(readShape(live.database)),
      referenceShape,
      `crash at chunk ${crashAt}`,
    );
    const open = scalar(
      live.database,
      `SELECT COUNT(*) FROM platform_migration_receipt WHERE state = ${stateApplying}`,
    );
    assert.equal(open, 0);
  }
});

test("a crash before a chunk is sent leaves the receipt where it was and the resume repeats nothing", async () => {
  const live = new SqliteMigrationClient();
  const time = clock();
  let dead = false;
  const crashing: MigrationClient = {
    batch: (statements) =>
      dead ? Promise.reject(new MigrationClientError("gone")) : live.batch(statements),
  };
  let seen = 0;
  await assert.rejects(
    applyPending(
      options(crashing, baseline, "a", time, {
        maxChunkStatements: 4,
        hooks: {
          beforeChunk: ({ sequence }) => {
            if (sequence === 3 && ++seen === 2) {
              dead = true;
              throw new MigrationClientError("crash before");
            }
          },
        },
      }),
    ),
    /crash before/u,
  );
  const partial = live.database
    .prepare(
      `SELECT statements_done, statement_count FROM platform_migration_receipt WHERE sequence = 3`,
    )
    .get() as { statements_done: number; statement_count: number };
  assert.equal(partial.statements_done, 4, "exactly the first chunk is recorded");
  assert(partial.statement_count > 4);
  time.advance(120_000);
  await applyPending(options(live, baseline, "b", time, { maxChunkStatements: 4 }));
  assert.deepEqual(compareShapes(readShape(live.database), expectedShape(schema)), []);
});

test("a stale migrator cannot apply anything after another migrator took over", async () => {
  const client = new SqliteMigrationClient();
  const time = clock();
  const takeover: { done: boolean } = { done: false };
  let afterTakeover: Promise<unknown> | undefined;
  const a = applyPending(
    options(client, baseline, "stale-a", time, {
      leaseMs: 1_000,
      maxChunkStatements: 3,
      hooks: {
        afterChunk: async ({ sequence, to }) => {
          if (sequence === 6 && to === 3 && !takeover.done) {
            takeover.done = true;
            time.advance(5_000);
            // B starts after A's lease expired, takes a higher fence and finishes the whole catalog.
            await applyPending(
              options(client, baseline, "takeover-b", time, { maxChunkStatements: 3 }),
            );
            afterTakeover = Promise.resolve();
          }
        },
      },
    }),
  );
  await assert.rejects(a, (error: unknown) => {
    assert(error instanceof MigrationError, String(error));
    assert.equal(error.code, "stale-migrator");
    return true;
  });
  await afterTakeover;
  // The stale migrator's chunk rolled back as a whole: nothing partial, and B's schema is intact and complete.
  assert.deepEqual(compareShapes(readShape(client.database), expectedShape(schema)), []);
  const receipts = scalar(client.database, "SELECT COUNT(*) FROM platform_migration_receipt");
  assert.equal(receipts, baseline.length);
  const runners = client.database
    .prepare(
      "SELECT DISTINCT runner FROM platform_migration_receipt WHERE sequence > 0 ORDER BY runner",
    )
    .all() as { runner: string }[];
  assert(runners.some((row) => row.runner === "takeover-b"));
});

test("a second migrator is refused while the first holds a live lease", async () => {
  const client = new SqliteMigrationClient();
  const time = clock();
  await applyPending(options(client, baseline, "init", time, { stopAfter: 1 }));
  let refused: unknown;
  await applyPending(
    options(client, baseline, "holder", time, {
      stopAfter: 3,
      hooks: {
        afterChunk: async ({ sequence }) => {
          if (sequence !== 2 || refused) return;
          try {
            await applyPending(options(client, baseline, "intruder", time));
          } catch (error) {
            refused = error;
          }
        },
      },
    }),
  );
  assert(refused instanceof MigrationError);
  assert.equal(refused.code, "lease-held");
});

test("an edited merged migration is refused by its receipt checksum, and a database ahead of the release is refused", async () => {
  const client = new SqliteMigrationClient();
  const time = clock();
  await applyPending(options(client, baseline, "r1", time, { stopAfter: 5 }));
  const edited = baseline.map((migration) =>
    migration.sequence === 3
      ? { ...migration, sha256: checksumOf(`${migration.text}\n-- edited\n`) }
      : migration,
  );
  await assert.rejects(
    applyPending(options(client, edited, "r2", time)),
    (error: unknown) => error instanceof MigrationError && error.code === "checksum-mismatch",
  );
  await assert.rejects(
    applyPending(options(client, baseline.slice(0, 4), "r3", time)),
    (error: unknown) => error instanceof MigrationError && error.code === "database-ahead",
  );
});

test("every mode accepts only its own statements and no migration controls transactions or pragmas", () => {
  const statements = (sql: string) => splitStatements(sql);
  assert.deepEqual(
    modeViolations(
      "expand",
      statements(
        "CREATE TABLE a (x TEXT) STRICT; CREATE INDEX i ON a (x); ALTER TABLE a ADD COLUMN y TEXT;",
      ),
    ),
    [],
  );
  assert.equal(modeViolations("expand", statements("DROP TABLE a")).length, 1);
  assert.equal(modeViolations("expand", statements("ALTER TABLE a DROP COLUMN y")).length, 1);
  assert.equal(modeViolations("expand", statements("ALTER TABLE a RENAME TO b")).length, 1);
  assert.equal(modeViolations("expand", statements("UPDATE a SET x = 1")).length, 1);
  assert.equal(modeViolations("expand", statements("INSERT INTO a VALUES (1)")).length, 1);
  for (const mode of ["expand", "cutover", "contract"] as const) {
    assert.equal(modeViolations(mode, statements("BEGIN")).length, 1);
    assert.equal(modeViolations(mode, statements("COMMIT")).length, 1);
    assert.equal(modeViolations(mode, statements("PRAGMA foreign_keys = OFF")).length, 1);
    assert.equal(modeViolations(mode, statements("ATTACH DATABASE 'x' AS y")).length, 1);
    assert.equal(modeViolations(mode, statements("VACUUM")).length, 1);
  }
  assert.deepEqual(modeViolations("contract", statements("PRAGMA defer_foreign_keys = ON")), []);
  assert.deepEqual(
    modeViolations("contract", statements("DROP TABLE a; ALTER TABLE b DROP COLUMN c;")),
    [],
  );
  assert.deepEqual(
    modeViolations(
      "cutover",
      statements("UPDATE a SET x = 1; INSERT INTO a VALUES (2); DELETE FROM a WHERE x = 9;"),
    ),
    [],
  );
  assert.equal(modeViolations("cutover", statements("DROP TABLE a")).length, 1);
});

test("the statement splitter keeps trigger bodies, strings and comments whole", () => {
  const sql = `-- header ; with a semicolon\nCREATE TABLE a (x TEXT DEFAULT 'a;b'); /* ; */\nCREATE TRIGGER t BEFORE UPDATE ON a BEGIN SELECT CASE WHEN 1 THEN 2 END; SELECT RAISE(ABORT, 'x;y'); END;\nCREATE TABLE "q;" (x TEXT);`;
  const parts = splitStatements(sql);
  assert.equal(parts.length, 3);
  assert.match(parts[1]?.sql ?? "", /^CREATE TRIGGER t[\s\S]*END$/u);
  assert.deepEqual(
    parts.map((part) => part.head[0]),
    ["CREATE", "CREATE", "CREATE"],
  );
  assert.throws(
    () => splitStatements("CREATE TRIGGER t BEFORE UPDATE ON a BEGIN SELECT 1;"),
    /unterminated trigger/u,
  );
  assert.throws(() => splitStatements("SELECT 'x"), /unterminated/u);
});

const scratch = `CREATE TABLE "scratch_item" (
  "id" TEXT NOT NULL,
  "legacy" TEXT NOT NULL,
  "converted" TEXT,
  "rev" INTEGER NOT NULL CHECK ("rev" >= 0),
  CONSTRAINT "pk_scratch_item" PRIMARY KEY ("id")
) STRICT;`;
const backfillBody = `-- af-backfill: {"target":"scratch_item","key":"id","pageSize":100}
-- section: page
SELECT "id", CAST("rev" AS TEXT) FROM "scratch_item" WHERE "id" > ? AND "converted" IS NULL ORDER BY "id" LIMIT ?
-- section: apply
UPDATE "scratch_item" SET "converted" = upper("legacy") WHERE "id" = ? AND "rev" = CAST(? AS INTEGER) AND "converted" IS NULL
-- section: verify
SELECT COUNT(*) FROM "scratch_item" WHERE "converted" IS NULL OR "converted" <> upper("legacy")`;

async function seededScratch(rows: number, extra: Partial<RunOptions> = {}) {
  const client = new SqliteMigrationClient();
  const time = clock();
  const chain = [
    baseline[0] as Migration,
    synthetic(1, "scratch", "expand", scratch),
    synthetic(2, "scratch", "backfill", backfillBody),
  ];
  await applyPending(options(client, chain, "seed", time, { stopAfter: 1 }));
  for (let index = 0; index < rows; index++)
    client.database
      .prepare("INSERT INTO scratch_item VALUES (?, ?, NULL, 1)")
      .run(`k${String(index).padStart(5, "0")}`, `value-${index}`);
  return { client, time, chain, extra };
}

test("a backfill converts bounded pages, counts a row written after it was read as stale and never overwrites it", async () => {
  const { client, time, chain } = await seededScratch(250);
  const widths: number[] = [];
  const spy: MigrationClient = {
    batch: (statements: readonly MigrationStatement[]): Promise<BatchResult[]> => {
      if (
        statements.some((statement) =>
          statement.sql.includes('UPDATE "scratch_item" SET "converted"'),
        )
      )
        widths.push(
          statements.filter((statement) =>
            statement.sql.includes('UPDATE "scratch_item" SET "converted"'),
          ).length,
        );
      return client.batch(statements);
    },
  };
  let injected = false;
  const result = await applyPending(
    options(spy, chain, "backfiller", time, {
      hooks: {
        afterPageSelect: ({ keys }) => {
          if (injected) return;
          injected = true;
          // A concurrent writer changes a selected row after the page read it: the row's revision moves.
          client.database
            .prepare("UPDATE scratch_item SET legacy = 'fresh-value', rev = rev + 1 WHERE id = ?")
            .run(keys[3] as string);
        },
      },
    }),
  );
  const backfill = result.applied.find((entry) => entry.mode === "backfill");
  assert(backfill);
  assert.equal(backfill.rowsStale, 1);
  assert.equal(backfill.rowsConverted, 250);
  assert(backfill.passes && backfill.passes >= 2, "the stale row needs a second pass");
  assert(
    Math.max(...widths) <= 100,
    `a page converts at most 100 rows, saw ${Math.max(...widths)}`,
  );
  const db = client.database;
  const stale = db
    .prepare("SELECT legacy, converted, rev FROM scratch_item WHERE converted = 'FRESH-VALUE'")
    .all() as { legacy: string; converted: string; rev: number }[];
  assert.equal(
    stale.length,
    1,
    "the row written during the backfill was converted from its new value",
  );
  assert.equal(
    scalar(
      db,
      "SELECT COUNT(*) FROM scratch_item WHERE converted IS NULL OR converted <> upper(legacy)",
    ),
    0,
  );
  const checkpoint = db
    .prepare(
      "SELECT verified, rows_converted, rows_stale FROM platform_backfill_checkpoint WHERE sequence = 2",
    )
    .get() as { verified: number; rows_converted: number; rows_stale: number };
  assert.deepEqual({ ...checkpoint }, { verified: 1, rows_converted: 250, rows_stale: 1 });
});

test("a backfill interrupted between pages resumes from its checkpoint and converts every row exactly once", async () => {
  const { client, time, chain } = await seededScratch(250);
  let dead = false;
  const crashing: MigrationClient = {
    batch: (statements) =>
      dead ? Promise.reject(new MigrationClientError("gone")) : client.batch(statements),
  };
  let pages = 0;
  await assert.rejects(
    applyPending(
      options(crashing, chain, "first", time, {
        hooks: {
          afterPageSelect: () => {
            if (++pages === 2) {
              dead = true;
              throw new MigrationClientError("crash during the second page");
            }
          },
        },
      }),
    ),
    /crash during the second page/u,
  );
  const mid = client.database
    .prepare("SELECT last_key, rows_converted FROM platform_backfill_checkpoint WHERE sequence = 2")
    .get() as { last_key: string | null; rows_converted: number };
  assert.equal(mid.rows_converted, 100, "exactly the first page is recorded");
  assert(mid.last_key);
  time.advance(120_000);
  const result = await applyPending(options(client, chain, "second", time));
  assert.equal(result.applied.find((entry) => entry.mode === "backfill")?.rowsConverted, 250);
  assert.equal(
    scalar(client.database, "SELECT COUNT(*) FROM scratch_item WHERE converted IS NULL"),
    0,
  );
});

test("a backfill that cannot converge is refused instead of looping", async () => {
  const { client, time } = await seededScratch(3);
  const never = backfillBody.replace(`"converted" = upper("legacy")`, `"legacy" = "legacy"`);
  const chain = [
    baseline[0] as Migration,
    synthetic(1, "scratch", "expand", scratch),
    synthetic(2, "scratch", "backfill", never),
  ];
  await assert.rejects(
    applyPending(options(client, chain, "loop", time)),
    (error: unknown) => error instanceof MigrationError && error.code === "backfill-not-converging",
  );
});

test("the backfill sections are validated: one statement each, a revision guard, a key cursor and at most 100 rows", () => {
  assert.equal(
    parseBackfill(`-- af-migration: module=x mode=backfill\n${backfillBody}`).pageSize,
    100,
  );
  assert.throws(
    () =>
      parseBackfill(
        `-- af-migration: module=x mode=backfill\n${backfillBody.replace('"pageSize":100', '"pageSize":101')}`,
      ),
    /pageSize/u,
  );
  assert.throws(
    () =>
      parseBackfill(
        `-- af-migration: module=x mode=backfill\n${backfillBody.replace('AND "rev" = CAST(? AS INTEGER)', "AND ? IS NOT NULL")}`,
      ),
    /revision/u,
  );
  assert.throws(
    () =>
      parseBackfill(
        `-- af-migration: module=x mode=backfill\n${backfillBody.replace('ORDER BY "id" LIMIT ?', "")}`,
      ),
    /ordered|parameters/u,
  );
  assert.throws(
    () =>
      parseBackfill(
        `-- af-migration: module=x mode=backfill\n${backfillBody.replace("-- section: verify", "-- section: other")}`,
      ),
    /verify/u,
  );
});

test("a cutover waits for its verified backfills, moves the horizons in one fenced step, and a contract waits for soak and consent", async () => {
  const { client, time } = await seededScratch(5);
  const chain = [
    baseline[0] as Migration,
    synthetic(1, "scratch", "expand", scratch),
    synthetic(2, "scratch", "backfill", backfillBody),
    synthetic(
      3,
      "scratch",
      "cutover",
      `UPDATE "scratch_item" SET "rev" = "rev" WHERE 0;`,
      " requires=2 readHorizon=1 writeHorizon=3",
    ),
    synthetic(
      4,
      "scratch",
      "contract",
      `ALTER TABLE "scratch_item" DROP COLUMN "legacy";`,
      " after=3 soak=3600",
    ),
  ];
  // Before the backfill ran, a cutover is refused.
  await assert.rejects(
    applyPending(options(client, chain, "early", time, { stopAfter: 1 })).then(() =>
      applyPending(
        options(
          client,
          [
            chain[0] as Migration,
            chain[1] as Migration,
            synthetic(
              2,
              "scratch",
              "cutover",
              `UPDATE "scratch_item" SET "rev" = "rev" WHERE 0;`,
              " requires=7",
            ),
          ],
          "x",
          time,
        ),
      ),
    ),
    (error: unknown) => error instanceof MigrationError && error.code === "cutover-blocked",
  );
  // Fresh database for the real chain.
  const fresh = await seededScratch(5);
  await applyPending(options(fresh.client, chain, "main", fresh.time, { stopAfter: 3 }));
  let state = fresh.client.database
    .prepare("SELECT schema_version, read_horizon, write_horizon FROM platform_schema_state")
    .get() as { schema_version: number; read_horizon: number; write_horizon: number };
  assert.deepEqual({ ...state }, { schema_version: 3, read_horizon: 1, write_horizon: 3 });
  // The compatible-rollback rule: a build older than the write horizon is refused after the cutover, newer ones are fine.
  assert.equal(
    compatibility(
      {
        schemaVersion: state.schema_version,
        readHorizon: state.read_horizon,
        writeHorizon: state.write_horizon,
      },
      { schemaVersion: 2 },
    ).canWrite,
    false,
  );
  assert.equal(
    compatibility(
      {
        schemaVersion: state.schema_version,
        readHorizon: state.read_horizon,
        writeHorizon: state.write_horizon,
      },
      { schemaVersion: 2 },
    ).canRead,
    true,
  );
  assert.equal(
    compatibility(
      {
        schemaVersion: state.schema_version,
        readHorizon: state.read_horizon,
        writeHorizon: state.write_horizon,
      },
      { schemaVersion: 3 },
    ).canWrite,
    true,
  );
  // The contract: no consent, then no soak, then applied.
  await assert.rejects(
    applyPending(options(fresh.client, chain, "c1", fresh.time)),
    (error: unknown) =>
      error instanceof MigrationError &&
      error.code === "contract-refused" &&
      /allowContract/u.test(error.message),
  );
  await assert.rejects(
    applyPending(options(fresh.client, chain, "c2", fresh.time, { allowContract: true })),
    (error: unknown) =>
      error instanceof MigrationError &&
      error.code === "contract-refused" &&
      /soak/u.test(error.message),
  );
  fresh.time.advance(3_600_000 + 1);
  const done = await applyPending(
    options(fresh.client, chain, "c3", fresh.time, { allowContract: true }),
  );
  assert.equal(done.schemaVersion, 4);
  state = fresh.client.database
    .prepare("SELECT schema_version, read_horizon, write_horizon FROM platform_schema_state")
    .get() as typeof state;
  assert.equal(state.schema_version, 4);
  assert.equal(
    scalar(
      fresh.client.database,
      "SELECT COUNT(*) FROM pragma_table_info('scratch_item') WHERE name = 'legacy'",
    ),
    0,
  );
});

test("the horizons cannot be set inconsistently: the database refuses a write horizon above the schema version", async () => {
  const { client } = await seededScratch(1);
  assert.throws(
    () => client.database.prepare("UPDATE platform_schema_state SET write_horizon = 99").run(),
    /ck_platform_schema_state__horizons/u,
  );
  assert.throws(
    () => client.database.prepare("UPDATE platform_schema_state SET schema_version = 0").run(),
    /af_monotonic_platform_schema_state_schema_version/u,
  );
});

// ---------------------------------------------------------------------------------------------------------------------
// catalog: numbering, lock, assignment and the merged-migration rule
// ---------------------------------------------------------------------------------------------------------------------

function copyCatalog(): string {
  const directory = mkdtempSync(path.join(tmpdir(), "af-migrations-"));
  for (const file of readdirSync(defaultMigrationsDirectory))
    if (file.endsWith(".sql") || file === "migrations.lock.json")
      copyFileSync(path.join(defaultMigrationsDirectory, file), path.join(directory, file));
  return directory;
}

test("the committed catalog is gapless, locked and parses in its modes", () => {
  const catalog = loadCatalog();
  assert.equal(catalog[0]?.sequence, 0);
  assert.equal(catalog[0]?.module, "platform");
  assert.equal(lockIdentity(readLock(defaultMigrationsDirectory)).highest, catalog.length - 1);
  assert(catalog.every((migration) => migration.mode === "expand"));
});

test("editing a locked migration, leaving a gap or mismatching a header is refused", () => {
  const directory = copyCatalog();
  try {
    const target = path.join(directory, "0003_identity__baseline.sql");
    const original = readFileSync(target, "utf8");
    writeFileSync(target, `${original}\n-- tamper\n`);
    assert.throws(() => loadCatalog(directory), /edited after it was locked/u);
    writeFileSync(target, original);
    assert.doesNotThrow(() => loadCatalog(directory));
    rmSync(path.join(directory, "0004_device__baseline.sql"));
    assert.throws(() => loadCatalog(directory), /gap or duplicate|migration files/u);
    copyFileSync(
      path.join(defaultMigrationsDirectory, "0004_device__baseline.sql"),
      path.join(directory, "0004_device__baseline.sql"),
    );
    writeFileSync(
      path.join(directory, "0005_workspace__baseline.sql"),
      readFileSync(path.join(directory, "0005_workspace__baseline.sql"), "utf8").replace(
        "module=workspace",
        "module=device",
      ),
    );
    assert.throws(() => loadCatalog(directory), /header module/u);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("the integration owner numbers pending migrations in order and locks them; the lock stays append-only against its base", () => {
  const directory = copyCatalog();
  try {
    const baseLock = readFileSync(path.join(directory, "migrations.lock.json"), "utf8");
    mkdirSync(path.join(directory, "pending"));
    writeFileSync(
      path.join(directory, "pending", "identity__add-nickname.sql"),
      `-- af-migration: module=identity mode=expand\nALTER TABLE "identity_user" ADD COLUMN "nickname" TEXT;\n`,
    );
    writeFileSync(
      path.join(directory, "pending", "chat__add-pin.sql"),
      `-- af-migration: module=chat mode=expand\nALTER TABLE "chat_conversation" ADD COLUMN "pinned" INTEGER;\n`,
    );
    assert.doesNotThrow(() => checkPending(directory));
    const assigned = assignPending(directory);
    assert.deepEqual(assigned, ["0022_chat__add-pin.sql", "0023_identity__add-nickname.sql"]);
    const lock = readLock(directory);
    assert.equal(lock.length, 24);
    assert.deepEqual(appendOnlyProblems(baseLock, lock), []);
    // The same lock with a base entry edited is not append-only.
    const tampered = lock.map((entry, index) =>
      index === 2 ? { ...entry, sha256: "0".repeat(64) } : entry,
    );
    assert.equal(appendOnlyProblems(baseLock, tampered).length, 1);
    assert.equal(
      appendOnlyProblems(baseLock, lock.slice(0, 5)).length > 0,
      true,
      "removing a merged migration is refused",
    );
    // A pending file that breaks its mode is refused before it is numbered.
    writeFileSync(
      path.join(directory, "pending", "chat__drop-it.sql"),
      `-- af-migration: module=chat mode=expand\nDROP TABLE "chat_conversation";\n`,
    );
    assert.throws(() => checkPending(directory), /expand migration may only/u);
    // Applying the extended catalog on top of an applied baseline adds exactly the two migrations.
    rmSync(path.join(directory, "pending", "chat__drop-it.sql"));
    lockNumbered(directory);
    const extended = loadCatalog(directory);
    assert.equal(extended.length, 24);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("an extended catalog applies on top of an already migrated database in order", async () => {
  const directory = copyCatalog();
  try {
    const client = new SqliteMigrationClient();
    const time = clock();
    await applyPending(options(client, baseline, "base", time));
    mkdirSync(path.join(directory, "pending"));
    writeFileSync(
      path.join(directory, "pending", "identity__add-nickname.sql"),
      `-- af-migration: module=identity mode=expand\nALTER TABLE "identity_user" ADD COLUMN "nickname" TEXT;\n`,
    );
    assignPending(directory);
    const extended = loadCatalog(directory);
    const result = await applyPending(options(client, extended, "next", time));
    assert.deepEqual(
      result.applied.map((entry) => entry.file),
      ["0022_identity__add-nickname.sql"],
    );
    assert.equal(
      scalar(
        client.database,
        "SELECT COUNT(*) FROM pragma_table_info('identity_user') WHERE name = 'nickname'",
      ),
      1,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------------------------------------------------
// the REST client (shape only: its live behaviour is a deferred check)
// ---------------------------------------------------------------------------------------------------------------------

test("the REST client posts one batch with the bearer secret and maps results; failures never echo the secret", async () => {
  const secret = ["alpha", "beta", "gamma"].join("-");
  const calls: { url: string; init: RequestInit }[] = [];
  const respond =
    (body: unknown, status = 200) =>
    async (url: string | URL | Request, init?: RequestInit) => {
      calls.push({ url: String(url), init: init ?? {} });
      return new Response(JSON.stringify(body), { status });
    };
  const ok = new RestMigrationClient({
    accountId: "acc",
    databaseId: "db",
    apiToken: secret,
    fetch: respond({
      success: true,
      result: [
        { results: [{ a: "1", b: 2 }], meta: { changes: 0 } },
        { results: [], meta: { changes: 3 } },
      ],
    }) as typeof fetch,
  });
  const results = await ok.batch([
    { sql: "SELECT 1", params: ["x"] },
    { sql: "UPDATE t SET a = 1" },
  ]);
  assert.deepEqual(results, [
    { changes: 0, rows: [["1", 2]] },
    { changes: 3, rows: [] },
  ]);
  assert.equal(
    calls[0]?.url,
    "https://api.cloudflare.com/client/v4/accounts/acc/d1/database/db/query",
  );
  assert.equal(new Headers(calls[0]?.init.headers).get("authorization"), `Bearer ${secret}`);
  assert.deepEqual(JSON.parse(String(calls[0]?.init.body)), {
    batch: [
      { sql: "SELECT 1", params: ["x"] },
      { sql: "UPDATE t SET a = 1", params: [] },
    ],
  });
  const refused = new RestMigrationClient({
    accountId: "acc",
    databaseId: "db",
    apiToken: secret,
    fetch: respond(
      { success: false, errors: [{ message: "CHECK constraint failed: x" }] },
      400,
    ) as typeof fetch,
  });
  await assert.rejects(refused.batch([{ sql: "x" }]), (error: Error) => {
    assert.match(error.message, /CHECK constraint failed: x/u);
    assert(!error.message.includes(secret));
    return true;
  });
  const broken = new RestMigrationClient({
    accountId: "acc",
    databaseId: "db",
    apiToken: secret,
    fetch: (async () => {
      throw new TypeError(`network down for ${secret}`);
    }) as typeof fetch,
  });
  await assert.rejects(broken.batch([{ sql: "x" }]), (error: Error) => {
    assert.match(error.message, /outcome unknown/u);
    assert(!error.message.includes(secret));
    return true;
  });
  const short = new RestMigrationClient({
    accountId: "acc",
    databaseId: "db",
    apiToken: secret,
    fetch: respond({ success: true, result: [] }) as typeof fetch,
  });
  await assert.rejects(short.batch([{ sql: "x" }]), /different number of results/u);
});

test("a backfill that runs longer than its lease renews it page by page and is never mistaken for a stale migrator", async () => {
  const { client, time, chain } = await seededScratch(500);
  const result = await applyPending(
    options(client, chain, "slow", time, {
      leaseMs: 1_000,
      hooks: { afterPageSelect: () => void time.advance(300) },
    }),
  );
  assert.equal(result.applied.find((entry) => entry.mode === "backfill")?.rowsConverted, 500);
  assert.equal(
    scalar(client.database, "SELECT COUNT(*) FROM scratch_item WHERE converted IS NULL"),
    0,
  );
});

test("a constraint of the migration's own statement is reported as it is, not as a stale migrator", async () => {
  const { client, time } = await seededScratch(3);
  const broken = backfillBody.replace(`"converted" = upper("legacy")`, `"rev" = -1`);
  const chain = [
    baseline[0] as Migration,
    synthetic(1, "scratch", "expand", scratch),
    synthetic(2, "scratch", "backfill", broken),
  ];
  await assert.rejects(applyPending(options(client, chain, "bad", time)), (error: unknown) => {
    assert(!(error instanceof MigrationError), "a real constraint failure must not be relabelled");
    assert.match((error as Error).message, /CHECK constraint failed/u);
    return true;
  });
  const failing = synthetic(
    1,
    "scratch",
    "expand",
    `CREATE TABLE "scratch_other" ("x" INTEGER NOT NULL CHECK ("x" > 0)) STRICT;\nCREATE TRIGGER "tr_scratch_other" AFTER INSERT ON "scratch_other" BEGIN SELECT RAISE(ABORT, 'CHECK constraint failed: own'); END;`,
  );
  const mixed = new SqliteMigrationClient();
  await applyPending(options(mixed, [baseline[0] as Migration, failing], "ok", clock()));
  mixed.database.exec("DROP TRIGGER tr_scratch_other");
});

test("a cutover re-verifies the backfill inside its own fenced batch: a row written after the backfill finished blocks it", async () => {
  const { client, time } = await seededScratch(5);
  const chain = [
    baseline[0] as Migration,
    synthetic(1, "scratch", "expand", scratch),
    synthetic(2, "scratch", "backfill", backfillBody),
    synthetic(
      3,
      "scratch",
      "cutover",
      `UPDATE "scratch_item" SET "rev" = "rev" WHERE 0;`,
      " requires=2 readHorizon=1 writeHorizon=3",
    ),
  ];
  await applyPending(options(client, chain, "backfill", time, { stopAfter: 2 }));
  assert.equal(
    scalar(client.database, "SELECT verified FROM platform_backfill_checkpoint WHERE sequence = 2"),
    1,
    "the stored flag still says verified",
  );
  client.database.prepare("INSERT INTO scratch_item VALUES ('late-row', 'late', NULL, 1)").run();
  await assert.rejects(
    applyPending(options(client, chain, "cutover", time)),
    (error: unknown) => error instanceof MigrationError && error.code === "cutover-blocked",
  );
  const state = client.database
    .prepare("SELECT schema_version, write_horizon FROM platform_schema_state")
    .get() as { schema_version: number; write_horizon: number };
  assert.deepEqual(
    { ...state },
    { schema_version: 2, write_horizon: 0 },
    "the horizons did not move",
  );
  client.database
    .prepare("UPDATE scratch_item SET converted = upper(legacy) WHERE converted IS NULL")
    .run();
  const done = await applyPending(options(client, chain, "cutover-2", time));
  assert.equal(done.schemaVersion, 3);
});

test("an expired lease alone stops a migrator, even with no competitor", async () => {
  const client = new SqliteMigrationClient();
  const time = clock();
  await assert.rejects(
    applyPending(
      options(client, baseline, "slow-a", time, {
        leaseMs: 1_000,
        maxChunkStatements: 3,
        hooks: {
          afterChunk: ({ sequence, to }) => {
            if (sequence === 3 && to === 3) time.advance(5_000);
          },
        },
      }),
    ),
    (error: unknown) => error instanceof MigrationError && error.code === "stale-migrator",
  );
  assert.equal(
    scalar(
      client.database,
      "SELECT statements_done FROM platform_migration_receipt WHERE sequence = 3",
    ),
    3,
  );
});

test("a receipt whose progress moved under the migrator stops it (the previous-progress term of the guard)", async () => {
  const client = new SqliteMigrationClient();
  const time = clock();
  await assert.rejects(
    applyPending(
      options(client, baseline, "moved", time, {
        maxChunkStatements: 3,
        hooks: {
          afterChunk: ({ sequence, to }) => {
            if (sequence === 3 && to === 3)
              client.database.exec(
                "UPDATE platform_migration_receipt SET statements_done = 5 WHERE sequence = 3",
              );
          },
        },
      }),
    ),
    (error: unknown) => error instanceof MigrationError && error.code === "stale-migrator",
  );
});

test("a contract waits for the whole soak: one millisecond short is refused, the full soak is accepted", async () => {
  const { client, time } = await seededScratch(2);
  const chain = [
    baseline[0] as Migration,
    synthetic(1, "scratch", "expand", scratch),
    synthetic(2, "scratch", "backfill", backfillBody),
    synthetic(
      3,
      "scratch",
      "cutover",
      `UPDATE "scratch_item" SET "rev" = "rev" WHERE 0;`,
      " requires=2 readHorizon=1 writeHorizon=3",
    ),
    synthetic(
      4,
      "scratch",
      "contract",
      `ALTER TABLE "scratch_item" DROP COLUMN "legacy";`,
      " after=3 soak=3600",
    ),
  ];
  await applyPending(options(client, chain, "main", time, { stopAfter: 3 }));
  time.advance(3_600_000 - 1);
  await assert.rejects(
    applyPending(options(client, chain, "early", time, { allowContract: true })),
    (error: unknown) => error instanceof MigrationError && /soak/u.test(error.message),
  );
  time.advance(1);
  assert.equal(
    (await applyPending(options(client, chain, "due", time, { allowContract: true })))
      .schemaVersion,
    4,
  );
});

test("receipts with a gap or an unfinished migration before a finished one are refused", async () => {
  const time = clock();
  const gap = new SqliteMigrationClient();
  await applyPending(options(gap, baseline, "g", time, { stopAfter: 5 }));
  gap.database.exec('DROP TRIGGER "tr_platform_migration_receipt__immutable_delete"');
  gap.database.exec("DELETE FROM platform_migration_receipt WHERE sequence = 3");
  await assert.rejects(
    applyPending(options(gap, baseline, "g2", time)),
    (error: unknown) => error instanceof MigrationError && error.code === "receipt-gap",
  );
  const order = new SqliteMigrationClient();
  await applyPending(options(order, baseline, "o", time, { stopAfter: 5 }));
  order.database.exec('DROP TRIGGER "tr_platform_migration_receipt__limited_update"');
  order.database.exec(
    "UPDATE platform_migration_receipt SET state = 1, applied_at = NULL, statements_done = 0 WHERE sequence = 3",
  );
  await assert.rejects(
    applyPending(options(order, baseline, "o2", time)),
    (error: unknown) => error instanceof MigrationError && error.code === "receipt-order",
  );
});

test("the chunk size limits in statements and in bytes are honoured", async () => {
  const byBytes = new SqliteMigrationClient();
  const result = await applyPending(
    options(byBytes, baseline, "bytes", clock(), { maxChunkBytes: 1, stopAfter: 3 }),
  );
  const third = result.applied.find((entry) => entry.sequence === 3);
  assert.equal(
    third?.chunks,
    third?.statements,
    "one statement per chunk when no two fit the byte limit",
  );
  const byCount = new SqliteMigrationClient();
  const counted = await applyPending(
    options(byCount, baseline, "count", clock(), { maxChunkStatements: 4, stopAfter: 3 }),
  );
  const again = counted.applied.find((entry) => entry.sequence === 3);
  assert.equal(again?.chunks, Math.ceil((again?.statements ?? 0) / 4));
});

test("line endings do not change a checksum or the statements", () => {
  const lf =
    "-- af-migration: module=x mode=expand\nCREATE TABLE a (x TEXT) STRICT;\nCREATE INDEX i ON a (x);\n";
  const crlf = lf.replaceAll("\n", "\r\n");
  assert.equal(checksumOf(crlf), checksumOf(lf));
  assert.deepEqual(splitStatements(crlf), splitStatements(lf));
});
