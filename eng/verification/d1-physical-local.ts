// SPDX-License-Identifier: AGPL-3.0-only
// Explicit local opt-in run (npm run test:d1:local): the physical schema, the exact-value rules, FTS5, the migration runner and its
// failure cases against workerd's D1 under Miniflare, the closest engine to D1 that exists without a Cloudflare account. It proves the
// SQL, the constraints, the triggers and the binding's value handling (including that it hands a JavaScript number to a reader that
// asked for a large integer), and it reruns the runner's interruption, stale-migrator and stale-backfill cases on that engine.
// It is NOT a Cloudflare provider result: no deployed D1, no network path, no provider limit, no provider export and no REST batch
// are exercised. Never CI; it starts local workerd, reads no credential and writes an evidence file under artifacts/.
import assert from "node:assert/strict";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { loadCatalog, type Migration } from "../migrations/catalog.ts";
import {
  type D1BindingLike,
  D1BindingMigrationClient,
  MigrationClientError,
  type MigrationClient,
} from "../migrations/clients.ts";
import { applyPending, compatibility } from "../migrations/runner.ts";
import { checksumOf, parseHeader, splitStatements } from "../migrations/sql.ts";
import {
  columnCheck,
  enumMap,
  loadManifest,
  planKindOf,
  type PhysicalColumn,
  type PhysicalKind,
} from "./physical-schema.ts";

const root = path.resolve(import.meta.dirname, "../..");
const schema = loadManifest();
const enums = enumMap(schema);
const compat = {
  sourceRevision: process.env.SOURCE_REVISION ?? "local",
  planManifestHash: "local",
  abi: "local",
  runtime: "workerd-local",
};

interface Result {
  name: string;
  status: "passed" | "failed";
  detail: string;
  millis: number;
}
const results: Result[] = [];

async function scenario(name: string, run: () => Promise<string>): Promise<void> {
  const started = Date.now();
  try {
    const detail = await run();
    results.push({ name, status: "passed", detail, millis: Date.now() - started });
  } catch (error) {
    results.push({
      name,
      status: "failed",
      detail: error instanceof Error ? error.message : String(error),
      millis: Date.now() - started,
    });
  }
}

type D1 = D1BindingLike & {
  exec(sql: string): Promise<unknown>;
  prepare(sql: string): {
    bind(...values: unknown[]): {
      run(): Promise<unknown>;
      raw(): Promise<unknown[][]>;
      all(): Promise<{ results: unknown[] }>;
    };
  };
};

async function raw(db: D1, sql: string, ...params: unknown[]): Promise<unknown[][]> {
  return db
    .prepare(sql)
    .bind(...params)
    .raw();
}

function clock() {
  const state = { now: Date.now() };
  return { read: () => state.now, advance: (ms: number) => (state.now += ms) };
}

const baseline = loadCatalog();

async function freshDatabase(mf: Miniflare, name: string): Promise<D1> {
  return (await mf.getD1Database(name)) as unknown as D1;
}

/** Table list, column list and index list through pragmas only, as workerd's D1 returns them. */
async function shapeOf(db: D1): Promise<string> {
  // D1 keeps its own _cf_ tables in the database and refuses to describe them.
  const tables = (
    await raw(
      db,
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '\\_cf\\_%' ESCAPE '\\' AND name NOT LIKE '%\\_fts\\_%' ESCAPE '\\' AND name NOT LIKE '%_fts' ORDER BY name",
    )
  ).map((row) => String(row[0]));
  const parts: string[] = [];
  for (const table of tables) {
    const columns = await raw(
      db,
      `SELECT name, type, "notnull", pk FROM pragma_table_info('${table}') ORDER BY cid`,
    );
    parts.push(`${table}:${columns.map((column) => column.join("/")).join(",")}`);
    const indexes = await raw(
      db,
      `SELECT name, "unique" FROM pragma_index_list('${table}') WHERE origin = 'c' ORDER BY name`,
    );
    parts.push(`${table}#${indexes.map((entry) => entry.join("/")).join(",")}`);
  }
  const triggers = (
    await raw(db, "SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name")
  ).map((row) => String(row[0]));
  parts.push(`triggers:${triggers.join(",")}`);
  return parts.join("\n");
}

function oracleShape(): string {
  // The same structure from the SQLite oracle with the same migrations, to compare with workerd's.
  const oracle = new DatabaseSync(":memory:");
  for (const migration of baseline) oracle.exec(migration.text);
  const all = (sql: string) => {
    const statement = oracle.prepare(sql);
    statement.setReturnArrays(true);
    return statement.all() as unknown as unknown[][];
  };
  const tables = all(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '%\\_fts\\_%' ESCAPE '\\' AND name NOT LIKE '%_fts' ORDER BY name",
  ).map((row) => String(row[0]));
  const parts: string[] = [];
  for (const table of tables) {
    parts.push(
      `${table}:${all(
        `SELECT name, type, "notnull", pk FROM pragma_table_info('${table}') ORDER BY cid`,
      )
        .map((column) => column.join("/"))
        .join(",")}`,
    );
    parts.push(
      `${table}#${all(
        `SELECT name, "unique" FROM pragma_index_list('${table}') WHERE origin = 'c' ORDER BY name`,
      )
        .map((entry) => entry.join("/"))
        .join(",")}`,
    );
  }
  parts.push(
    `triggers:${all("SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name")
      .map((row) => String(row[0]))
      .join(",")}`,
  );
  return parts.join("\n");
}

interface VectorCase {
  name: string;
  column: { kind: string; nullable: boolean; enum?: string; jsonRoot?: "object" | "array" };
  scalar: { kind: string; value?: unknown };
  roundTrip: boolean;
  sqlAccepts?: boolean;
  bridgeOnly?: boolean;
}

const sqlTypeOf: Record<string, "TEXT" | "INTEGER" | "BLOB"> = {
  id: "TEXT",
  text: "TEXT",
  key: "TEXT",
  productId: "TEXT",
  modelId: "TEXT",
  currency: "TEXT",
  json: "TEXT",
  uint64: "TEXT",
  decimal: "TEXT",
  bool: "INTEGER",
  int: "INTEGER",
  int64: "INTEGER",
  rev: "INTEGER",
  instant: "INTEGER",
  enum: "INTEGER",
  hash: "BLOB",
  bytes: "BLOB",
  proto: "BLOB",
};

function physical(column: VectorCase["column"]): PhysicalColumn {
  const out: PhysicalColumn = {
    name: "v",
    kind: column.kind as PhysicalKind,
    sqlType: sqlTypeOf[column.kind] as PhysicalColumn["sqlType"],
    nullable: column.nullable,
    monotonic: false,
  };
  if (column.enum) out.enumName = column.enum;
  if (column.jsonRoot) out.jsonRoot = column.jsonRoot;
  return out;
}

export async function main(): Promise<void> {
  assert.notEqual(process.env.CI, "true", "The local D1 run is opt-in, never CI.");
  const started = new Date().toISOString();
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: "export default { fetch() { return new Response('ok'); } };",
      compatibilityDate: "2026-09-15",
      host: "127.0.0.1",
      port: 0,
      d1Databases: {
        PHYSICAL: "physical-proof",
        INTERRUPT: "physical-interrupt",
        STALE: "physical-stale",
        SCRATCH: "physical-scratch",
        TYPES: "physical-types",
      },
    }),
  );
  try {
    await mf.ready;

    await scenario("migrations-apply-and-equal-the-oracle", async () => {
      const db = await freshDatabase(mf, "PHYSICAL");
      const client = new D1BindingMigrationClient(db);
      const run = await applyPending({
        client,
        migrations: baseline,
        runner: "local-1",
        now: Date.now,
        compatibility: compat,
      });
      assert.equal(run.schemaVersion, baseline.length - 1);
      const receipts = await raw(
        db,
        "SELECT CAST(COUNT(*) AS TEXT), CAST(SUM(state = 2) AS TEXT) FROM platform_migration_receipt",
      );
      assert.deepEqual(receipts[0], [String(baseline.length), String(baseline.length)]);
      assert.equal(
        await shapeOf(db),
        oracleShape(),
        "workerd's D1 and the SQLite oracle disagree on the migrated structure",
      );
      const fts = await raw(
        db,
        "SELECT COUNT(*) FROM sqlite_master WHERE name = 'search_search_document_fts'",
      );
      assert.equal(Number(fts[0]?.[0]), 1);
      return `${baseline.length} migrations applied with receipts; structure equals the oracle (${(await shapeOf(db)).split("\n").length} lines)`;
    });

    await scenario("exact-int64-and-the-number-hazard", async () => {
      const db = await freshDatabase(mf, "TYPES");
      await db.exec(
        "CREATE TABLE IF NOT EXISTS i64 (n INTEGER NOT NULL PRIMARY KEY, v INTEGER NOT NULL) STRICT",
      );
      const values = [
        "-9223372036854775808",
        "-9007199254740993",
        "-1",
        "0",
        "1",
        "9007199254740993",
        "9223372036854775807",
      ];
      for (const [index, value] of values.entries())
        await db.prepare("INSERT INTO i64 VALUES (?, CAST(? AS INTEGER))").bind(index, value).run();
      const exact = (await raw(db, "SELECT CAST(v AS TEXT) FROM i64 ORDER BY n")).map((row) =>
        String(row[0]),
      );
      assert.deepEqual(exact, values);
      const lossy = (await raw(db, "SELECT v FROM i64 WHERE n = 5"))[0]?.[0];
      assert.equal(typeof lossy, "number");
      return `exact text round trip of ${values.length} values; a plain read of 9007199254740993 returned the number ${String(lossy)} (precision lost, which is why plans read CAST(column AS TEXT))`;
    });

    await scenario("column-vectors-on-workerd-d1", async () => {
      const db = await freshDatabase(mf, "TYPES");
      const file = JSON.parse(
        await readFile(
          path.join(root, "tests/ArcForges.Cloud.Tests/Vectors/physical-columns.json"),
          "utf8",
        ),
      ) as { cases: VectorCase[] };
      let accepted = 0;
      let refused = 0;
      for (const vector of file.cases) {
        const column = physical(vector.column);
        const check = columnCheck(column, enums);
        await db.exec("DROP TABLE IF EXISTS vec");
        await db.exec(
          `CREATE TABLE vec (id INTEGER NOT NULL PRIMARY KEY, v ${column.sqlType}${column.nullable ? "" : " NOT NULL"}${check ? ` CHECK (${check.replaceAll("\n", " ")})` : ""}) STRICT`,
        );
        const kind = planKindOf(column.kind);
        const scalar = vector.scalar;
        let value: unknown;
        let bindable = true;
        if (scalar.kind === "null") value = null;
        else if (kind === "bool" && scalar.kind === "boolean") value = scalar.value ? 1 : 0;
        else if (
          (kind === "int64" && scalar.kind === "int64") ||
          (kind === "uint64" && scalar.kind === "uint64") ||
          (kind === "decimal" && scalar.kind === "decimal") ||
          (kind === "text" && scalar.kind === "text")
        )
          value = String(scalar.value);
        else if (kind === "bytes" && scalar.kind === "bytes")
          value = [...Buffer.from(String(scalar.value), "base64url")];
        else bindable = false;
        const marks = column.sqlType === "INTEGER" && kind === "int64" ? "CAST(? AS INTEGER)" : "?";
        if (vector.roundTrip) {
          assert(bindable, vector.name);
          await db.prepare(`INSERT INTO vec VALUES (1, ${marks})`).bind(value).run();
          const select =
            column.sqlType === "INTEGER" && column.kind !== "bool" ? "CAST(v AS TEXT)" : "v";
          const stored = (await raw(db, `SELECT ${select} FROM vec`))[0]?.[0];
          if (scalar.kind === "null") assert.equal(stored, null, vector.name);
          else if (scalar.kind === "bytes")
            assert.deepEqual(
              Array.isArray(stored)
                ? Buffer.from(stored as number[]).toString("base64url")
                : stored,
              scalar.value,
              vector.name,
            );
          else if (scalar.kind === "boolean") assert.equal(stored === 1, scalar.value, vector.name);
          else assert.equal(String(stored), String(scalar.value), vector.name);
          accepted++;
        } else if (bindable && !vector.bridgeOnly && column.sqlType !== "INTEGER") {
          if (vector.sqlAccepts)
            await db.prepare(`INSERT INTO vec VALUES (1, ${marks})`).bind(value).run();
          else
            await assert.rejects(
              db.prepare(`INSERT INTO vec VALUES (1, ${marks})`).bind(value).run(),
              undefined,
              `${vector.name} was accepted`,
            );
          refused++;
        }
      }
      return `${accepted} values stored and returned exactly, ${refused} refused by the column checks, on workerd's D1`;
    });

    await scenario("json-and-fts5-on-workerd-d1", async () => {
      const db = await freshDatabase(mf, "PHYSICAL");
      const vectors = JSON.parse(
        await readFile(
          path.join(root, "tests/ArcForges.Cloud.Tests/Vectors/physical-fts5.json"),
          "utf8",
        ),
      ) as {
        documents: {
          id: string;
          workspaceId: string;
          productId: string;
          title: string;
          body: string;
        }[];
        queries: { name: string; match: string; expectedIds: string[] }[];
      };
      await db.exec("PRAGMA foreign_keys = OFF");
      for (const doc of vectors.documents)
        await db
          .prepare(
            "INSERT INTO search_search_document (search_doc_id, workspace_id, product_id, source_kind, source_id, source_version, title, body, indexed_at, scope_key) VALUES (?, ?, ?, 'chat.message', ?, '{}', ?, ?, CAST('1790000000000000' AS INTEGER), ?)",
          )
          .bind(
            doc.id,
            doc.workspaceId,
            doc.productId,
            doc.id,
            doc.title,
            doc.body,
            `${doc.workspaceId.replaceAll("-", "")}x${doc.productId}`,
          )
          .run();
      for (const query of vectors.queries) {
        const rows = await raw(
          db,
          "SELECT d.search_doc_id FROM search_search_document_fts f JOIN search_search_document d ON d.rowid = f.rowid WHERE search_search_document_fts MATCH ? ORDER BY d.search_doc_id",
          query.match,
        );
        assert.deepEqual(
          rows.map((row) => String(row[0])),
          query.expectedIds,
          query.name,
        );
      }
      const invalidJson = db
        .prepare(
          "INSERT INTO search_search_document (search_doc_id, workspace_id, product_id, source_kind, source_id, source_version, title, body, indexed_at, scope_key) VALUES (?, ?, 'arcscope', 'k', ?, 'not json', 't', 'b', CAST('1' AS INTEGER), ?)",
        )
        .bind(
          "0198a7c0-1c3e-7d4a-9b1f-0000000009ff",
          vectors.documents[0]?.workspaceId,
          "0198a7c0-1c3e-7d4a-9b1f-0000000009ff",
          `${vectors.documents[0]?.workspaceId.replaceAll("-", "")}xarcscope`,
        );
      await assert.rejects(
        invalidJson.run(),
        undefined,
        "invalid JSON must be refused by json_valid",
      );
      return `${vectors.queries.length} scope-first FTS5 queries returned exactly the expected documents; malformed JSON refused`;
    });

    await scenario("every-table-roundtrips-an-extreme-row-on-workerd-d1", async () => {
      const db = await freshDatabase(mf, "SCRATCH");
      const client = new D1BindingMigrationClient(db);
      await applyPending({
        client,
        migrations: baseline,
        runner: "local-rows",
        now: Date.now,
        compatibility: compat,
      });
      const rows = await import("../../tests/worker/support/physical-rows.ts");
      const oracle = new DatabaseSync(":memory:");
      for (const migration of baseline) oracle.exec(migration.text);
      oracle.exec("PRAGMA foreign_keys = OFF");
      let serial = 40_000;
      let count = 0;
      for (const table of schema.tables) {
        if (table.bootstrap) continue;
        const built = rows.buildAcceptedRow(oracle, schema, table, { boundary: true }, serial++);
        const params = rows
          .bindRow(table, built.row)
          .map((value) => (value instanceof Uint8Array ? [...value] : value));
        const statement = rows.insertStatement(table);
        // D1 enforces foreign keys and cannot switch them off: defer them for one batch, read the row back inside it and delete it
        // before the batch commits, so the parent rows this check does not build are never required.
        // The scratch database drops the delete-refusing trigger of an append-only table so that the check row can be removed again;
        // the triggers themselves are proven by the oracle suite and by the runner scenarios below.
        if (table.mutability.delete === "none")
          await db.exec(`DROP TRIGGER IF EXISTS "tr_${table.name}__immutable_delete"`);
        const keyWhere = table.primaryKey
          .map(
            (name) =>
              `"${name}" = ${table.columns.find((column) => column.name === name)?.sqlType === "INTEGER" ? "CAST(? AS INTEGER)" : "?"}`,
          )
          .join(" AND ");
        const keyParams = table.primaryKey.map(
          (name) => params[table.columns.findIndex((column) => column.name === name)],
        );
        const batch = (await db.batch([
          db.prepare("PRAGMA defer_foreign_keys = on"),
          db.prepare(statement.sql).bind(...params),
          db.prepare(rows.selectStatement(table)),
          db.prepare(`DELETE FROM "${table.name}" WHERE ${keyWhere}`).bind(...keyParams),
        ] as never)) as { results?: Record<string, unknown>[] }[];
        const stored = (batch[2]?.results ?? []).map((row) => Object.values(row));
        assert.equal(stored.length, 1, table.name);
        table.columns.forEach((column, index) => {
          const expected = built.row[column.name];
          const value = stored[0]?.[index];
          if (expected === null) assert.equal(value, null, `${table.name}.${column.name}`);
          else if (expected instanceof Uint8Array)
            assert.deepEqual(
              Array.isArray(value) ? value : [...(value as Uint8Array)],
              [...expected],
              `${table.name}.${column.name}`,
            );
          else if (typeof expected === "bigint")
            assert.equal(BigInt(String(value)), expected, `${table.name}.${column.name}`);
          else assert.equal(String(value), String(expected), `${table.name}.${column.name}`);
        });
        count++;
      }
      return `${count} tables accepted an extreme valid row and returned every field exactly (the bookkeeping tables are covered by the runner scenarios)`;
    });

    await scenario("batch-atomicity-for-ddl-and-data", async () => {
      const db = await freshDatabase(mf, "TYPES");
      await db.exec("DROP TABLE IF EXISTS atomic_a");
      await assert.rejects(
        db.batch([
          db.prepare("CREATE TABLE atomic_a (x INTEGER NOT NULL CHECK (x > 0)) STRICT"),
          db.prepare("INSERT INTO atomic_a VALUES (1)"),
          db.prepare("INSERT INTO atomic_a VALUES (-1)"),
        ] as never),
      );
      const exists = await raw(db, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'atomic_a'");
      assert.equal(Number(exists[0]?.[0]), 0, "a failed batch must leave no table behind");
      return "a batch holding a CREATE TABLE and a violating INSERT rolled back as a whole, leaving no table (workerd's D1; the provider REST path is a deferred live check)";
    });

    const crashable = (
      client: D1BindingMigrationClient,
      flag: { dead: boolean },
    ): MigrationClient => ({
      batch: (statements) =>
        flag.dead
          ? Promise.reject(new MigrationClientError("the migrator process is gone"))
          : client.batch(statements),
    });

    await scenario("interrupted-migration-resumes-on-workerd-d1", async () => {
      const db = await freshDatabase(mf, "INTERRUPT");
      const client = new D1BindingMigrationClient(db);
      const flag = { dead: false };
      const time = clock();
      let seen = 0;
      await assert.rejects(
        applyPending({
          client: crashable(client, flag),
          migrations: baseline,
          runner: "crash",
          now: time.read,
          compatibility: compat,
          leaseMs: 1_000,
          maxChunkStatements: 5,
          hooks: {
            afterChunk: () => {
              if (++seen === 7) {
                flag.dead = true;
                throw new MigrationClientError("crash after chunk 7");
              }
            },
          },
        }),
        /crash after chunk 7/u,
      );
      const open = await raw(
        db,
        "SELECT sequence, statements_done, statement_count FROM platform_migration_receipt WHERE state = 1",
      );
      assert.equal(open.length, 1, "exactly one migration is unfinished");
      time.advance(5_000);
      const resumed = await applyPending({
        client,
        migrations: baseline,
        runner: "resume",
        now: time.read,
        compatibility: compat,
        maxChunkStatements: 5,
      });
      assert.equal(resumed.schemaVersion, baseline.length - 1);
      assert.equal(await shapeOf(db), oracleShape());
      return `crash after chunk 7 left migration ${String(open[0]?.[0])} at ${String(open[0]?.[1])} of ${String(open[0]?.[2])} statements; the resume completed with the same structure`;
    });

    await scenario("stale-migrator-is-refused-on-workerd-d1", async () => {
      const db = await freshDatabase(mf, "STALE");
      const client = new D1BindingMigrationClient(db);
      const time = clock();
      let takeover = false;
      let refusedCode = "";
      try {
        await applyPending({
          client,
          migrations: baseline,
          runner: "stale-a",
          now: time.read,
          compatibility: compat,
          leaseMs: 1_000,
          maxChunkStatements: 3,
          hooks: {
            afterChunk: async ({ sequence, to }) => {
              if (sequence === 6 && to === 3 && !takeover) {
                takeover = true;
                time.advance(5_000);
                await applyPending({
                  client,
                  migrations: baseline,
                  runner: "takeover-b",
                  now: time.read,
                  compatibility: compat,
                  maxChunkStatements: 3,
                });
              }
            },
          },
        });
      } catch (error) {
        refusedCode = (error as { code?: string }).code ?? String(error);
      }
      assert.equal(refusedCode, "stale-migrator");
      assert.equal(await shapeOf(db), oracleShape());
      return "the stale migrator's next chunk violated its guard and rolled back as a whole; the takeover's schema is complete";
    });

    await scenario("stale-backfill-and-compatible-rollback-on-workerd-d1", async () => {
      const db = await freshDatabase(mf, "TYPES");
      for (const dropped of [
        "platform_backfill_checkpoint",
        "platform_migration_receipt",
        "platform_schema_state",
        "scratch_item",
      ])
        await db.exec(`DROP TABLE IF EXISTS ${dropped}`);
      const client = new D1BindingMigrationClient(db);
      const time = clock();
      const mk = (
        sequence: number,
        mode: Migration["mode"],
        body: string,
        header = "",
      ): Migration => {
        const text = `-- af-migration: module=scratch mode=${mode}${header}\n${body}\n`;
        const parsed = parseHeader(text);
        return {
          sequence,
          file: `${String(sequence).padStart(4, "0")}_scratch__s${sequence}.sql`,
          module: "scratch",
          mode,
          options: parsed.options,
          sha256: checksumOf(text),
          text,
          statements: mode === "backfill" ? [] : splitStatements(text),
        };
      };
      const table = `CREATE TABLE "scratch_item" ("id" TEXT NOT NULL, "legacy" TEXT NOT NULL, "converted" TEXT, "rev" INTEGER NOT NULL CHECK ("rev" >= 0), CONSTRAINT "pk_scratch_item" PRIMARY KEY ("id")) STRICT;`;
      const backfill = `-- af-backfill: {"target":"scratch_item","key":"id","pageSize":100}
-- section: page
SELECT "id", CAST("rev" AS TEXT) FROM "scratch_item" WHERE "id" > ? AND "converted" IS NULL ORDER BY "id" LIMIT ?
-- section: apply
UPDATE "scratch_item" SET "converted" = upper("legacy") WHERE "id" = ? AND "rev" = CAST(? AS INTEGER) AND "converted" IS NULL
-- section: verify
SELECT COUNT(*) FROM "scratch_item" WHERE "converted" IS NULL OR "converted" <> upper("legacy")`;
      const chain = [
        baseline[0] as Migration,
        mk(1, "expand", table),
        mk(2, "backfill", backfill),
        mk(
          3,
          "cutover",
          'UPDATE "scratch_item" SET "rev" = "rev" WHERE 0;',
          " requires=2 readHorizon=1 writeHorizon=3",
        ),
      ];
      await applyPending({
        client,
        migrations: chain,
        runner: "seed",
        now: time.read,
        compatibility: compat,
        stopAfter: 1,
      });
      for (let index = 0; index < 250; index++)
        await db
          .prepare("INSERT INTO scratch_item VALUES (?, ?, NULL, 1)")
          .bind(`k${String(index).padStart(5, "0")}`, `value-${index}`)
          .run();
      let injected = false;
      const run = await applyPending({
        client,
        migrations: chain,
        runner: "backfill",
        now: time.read,
        compatibility: compat,
        hooks: {
          afterPageSelect: async ({ keys }) => {
            if (injected) return;
            injected = true;
            await db
              .prepare("UPDATE scratch_item SET legacy = 'fresh-value', rev = rev + 1 WHERE id = ?")
              .bind(keys[3])
              .run();
          },
        },
      });
      const backfillResult = run.applied.find((entry) => entry.mode === "backfill");
      assert.equal(backfillResult?.rowsStale, 1);
      assert.equal(backfillResult?.rowsConverted, 250);
      const fresh = await raw(
        db,
        "SELECT converted FROM scratch_item WHERE legacy = 'fresh-value'",
      );
      assert.equal(
        fresh[0]?.[0],
        "FRESH-VALUE",
        "the row written during the backfill was converted from its new value, not overwritten with a stale one",
      );
      const state = await raw(
        db,
        "SELECT CAST(schema_version AS TEXT), CAST(read_horizon AS TEXT), CAST(write_horizon AS TEXT) FROM platform_schema_state",
      );
      const horizons = {
        schemaVersion: Number(state[0]?.[0]),
        readHorizon: Number(state[0]?.[1]),
        writeHorizon: Number(state[0]?.[2]),
      };
      assert.deepEqual(horizons, { schemaVersion: 3, readHorizon: 1, writeHorizon: 3 });
      assert.equal(compatibility(horizons, { schemaVersion: 2 }).canWrite, false);
      assert.equal(compatibility(horizons, { schemaVersion: 3 }).canWrite, true);
      return `250 rows converted in bounded pages, 1 stale row re-converted from its new value in a second pass; after the cutover a build below the write horizon is refused`;
    });
  } finally {
    await mf.dispose();
  }

  const failed = results.filter((entry) => entry.status === "failed");
  const report = {
    startedAt: started,
    finishedAt: new Date().toISOString(),
    kind: "local-emulation",
    emulated: "workerd D1 (SQLite) under Miniflare",
    notEmulated:
      "Cloudflare provider network path, REST batch semantics, real D1 limits, provider export of virtual tables",
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    results,
  };
  const outDirectory = path.join(root, "artifacts", "d1-physical-local");
  await mkdir(outDirectory, { recursive: true });
  await writeFile(path.join(outDirectory, "evidence.json"), `${JSON.stringify(report, null, 2)}\n`);
  for (const entry of results)
    process.stdout.write(
      `${entry.status === "passed" ? "PASS" : "FAIL"} ${entry.name} (${entry.millis} ms): ${entry.detail}\n`,
    );
  if (failed.length > 0) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === import.meta.filename) {
  main().catch((error: unknown) => {
    process.stderr.write(
      `${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`,
    );
    process.exitCode = 1;
  });
}
