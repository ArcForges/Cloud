// SPDX-License-Identifier: AGPL-3.0-only
// Test support only (CLOUD.84 U9, S41, S42(2)): the TypeScript migration module is kept for the offline local drivers and the
// TypeScript suites that still import it. C# (src/ArcForges.Cloud.Storage.D1/MigrationRunner) is authoritative for every decision.
// The D1 migration runner (Design D1 profile section 6). It runs from the gated deployment job, never from the
// Container. One global sequence, applied in order with receipts. Every chunk is one atomic batch whose first
// statement advances the receipt under the current fence, so:
//   - an interrupted run resumes from `statements_done` and never repeats an applied statement;
//   - a stale migrator (its lease expired and another took over) cannot apply anything: its guard statement
//     violates a CHECK and the whole batch rolls back before a single DDL statement runs;
//   - a merged migration that was edited is refused, because its checksum is in the receipt.
// Modes: expand (additive DDL), backfill (guarded 100-row pages with checkpoints and a verify gate), cutover
// (one fenced switch of the read and write horizons) and contract (irreversible, after cutover and soak).
// The live D1 path is C# and no TypeScript REST transport remains; deleting this file is an open residual (D13, S42(2)).
import type { BatchResult, MigrationClient, MigrationStatement } from "./clients.ts";
import type { Migration } from "./catalog.ts";
import { type BackfillSpec, parseBackfill } from "./sql.ts";

/** The enum numbers of the manifest (platform.migration_mode, platform.migration_state); a test pins them. */
export const modeNumber = { expand: 1, backfill: 2, cutover: 3, contract: 4 } as const;
export const stateApplying = 1;
export const stateApplied = 2;

export class MigrationError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export interface CompatibilityInput {
  /** The 40-hex source commit, or "local" for a developer database. */
  sourceRevision: string;
  planManifestHash: string;
  abi: string;
  runtime: string;
}

export interface RunnerHooks {
  /** Called before a chunk batch is sent; throwing simulates a crash before the chunk. */
  beforeChunk?: (info: { sequence: number; from: number; to: number }) => void | Promise<void>;
  /** Called after a chunk batch committed; throwing simulates a crash after the chunk. */
  afterChunk?: (info: { sequence: number; from: number; to: number }) => void | Promise<void>;
  /** Called after a backfill page was selected and before it is applied (a concurrent writer can act here). */
  afterPageSelect?: (info: { sequence: number; keys: string[] }) => void | Promise<void>;
}

export interface RunOptions {
  client: MigrationClient;
  migrations: readonly Migration[];
  /** A unique identity of this run (for example the workflow run id). */
  runner: string;
  now: () => number;
  compatibility: CompatibilityInput;
  leaseMs?: number;
  maxChunkStatements?: number;
  maxChunkBytes?: number;
  /** Stop after this sequence has been applied (to separate expand, backfill, cutover and contract). */
  stopAfter?: number;
  /** A contract migration is irreversible and is applied only when the deployment job says so. */
  allowContract?: boolean;
  hooks?: RunnerHooks;
  /** Safety bound on backfill passes. */
  maxBackfillPasses?: number;
}

export interface AppliedMigration {
  sequence: number;
  file: string;
  mode: Migration["mode"];
  statements: number;
  /** Backfill only. */
  rowsConverted?: number;
  rowsStale?: number;
  passes?: number;
  chunks?: number;
}
export interface RunResult {
  fence: number;
  applied: AppliedMigration[];
  /** Highest applied sequence after the run. */
  schemaVersion: number;
  alreadyCurrent: boolean;
}

interface Receipt {
  sequence: number;
  file: string;
  checksum: string;
  state: number;
  statementsDone: number;
  statementCount: number;
  appliedAt: bigint | null;
}
interface SchemaState {
  schemaVersion: number;
  readHorizon: number;
  writeHorizon: number;
  fence: number;
  leaseHolder: string | null;
  leaseExpiresAt: bigint | null;
}

const micros = (milliseconds: number) => (BigInt(Math.trunc(milliseconds)) * 1000n).toString();
const int = (value: unknown): number => {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed))
    throw new MigrationError(
      "unexpected-value",
      `expected a safe integer, received ${String(value)}`,
    );
  return parsed;
};
const bigint = (value: unknown): bigint | null =>
  value === null || value === undefined ? null : BigInt(String(value));

/** The lease-and-fence guard shared by every write statement of a run. Binds: fence, holder, now (microseconds). */
const guardSql = `EXISTS (SELECT 1 FROM platform_schema_state WHERE singleton = 1 AND fence = CAST(? AS INTEGER) AND lease_holder = ? AND lease_expires_at > CAST(? AS INTEGER))`;

class Run {
  readonly options: RunOptions;
  fence = 0;
  constructor(options: RunOptions) {
    this.options = options;
  }
  get client(): MigrationClient {
    return this.options.client;
  }
  get now(): number {
    return this.options.now();
  }
  get leaseMs(): number {
    return this.options.leaseMs ?? 120_000;
  }
  guardParams(): [string, string, string] {
    return [String(this.fence), this.options.runner, micros(this.now)];
  }
  async one(sql: string, params: MigrationStatement["params"] = []): Promise<unknown[][]> {
    const [result] = await this.client.batch([{ sql, params }]);
    return (result as BatchResult).rows;
  }
}

async function tableExists(run: Run): Promise<boolean> {
  const rows = await run.one(
    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'platform_schema_state'",
  );
  return int(rows[0]?.[0]) === 1;
}

async function readState(run: Run): Promise<SchemaState> {
  const rows = await run.one(
    "SELECT CAST(schema_version AS TEXT), CAST(read_horizon AS TEXT), CAST(write_horizon AS TEXT), CAST(fence AS TEXT), lease_holder, CAST(lease_expires_at AS TEXT) FROM platform_schema_state WHERE singleton = 1",
  );
  const row = rows[0];
  if (!row) throw new MigrationError("no-schema-state", "platform_schema_state has no row");
  return {
    schemaVersion: int(row[0]),
    readHorizon: int(row[1]),
    writeHorizon: int(row[2]),
    fence: int(row[3]),
    leaseHolder: row[4] === null ? null : String(row[4]),
    leaseExpiresAt: bigint(row[5]),
  };
}

async function readReceipts(run: Run): Promise<Receipt[]> {
  const rows = await run.one(
    "SELECT CAST(sequence AS TEXT), file_name, checksum, state, statements_done, statement_count, CAST(applied_at AS TEXT) FROM platform_migration_receipt ORDER BY sequence",
  );
  return rows.map((row) => ({
    sequence: int(row[0]),
    file: String(row[1]),
    checksum: String(row[2]),
    state: int(row[3]),
    statementsDone: int(row[4]),
    statementCount: int(row[5]),
    appliedAt: bigint(row[6]),
  }));
}

function receiptInsert(run: Run, migration: Migration, statementCount: number): MigrationStatement {
  const compatibility = JSON.stringify({
    sourceRevision: run.options.compatibility.sourceRevision,
    schemaVersion: migration.sequence,
    planManifestHash: run.options.compatibility.planManifestHash,
    abi: run.options.compatibility.abi,
    runtime: run.options.compatibility.runtime,
  });
  return {
    sql: `INSERT INTO platform_migration_receipt (sequence, file_name, module, mode, checksum, state, statement_count, statements_done, runner, fence, started_at, applied_at, compatibility)
SELECT CAST(? AS INTEGER), ?, ?, ?, ?, ${stateApplying}, ?, 0, ?, CAST(? AS INTEGER), CAST(? AS INTEGER), NULL, ? WHERE ${guardSql}`,
    params: [
      String(migration.sequence),
      migration.file,
      migration.module,
      modeNumber[migration.mode],
      migration.sha256,
      statementCount,
      run.options.runner,
      String(run.fence),
      micros(run.now),
      compatibility,
      ...run.guardParams(),
    ],
  };
}

/** Bootstrap: migration 0000 creates the bookkeeping tables, so its own receipt and the state row ride in its batch. */
async function bootstrap(run: Run, first: Migration): Promise<void> {
  if (first.sequence !== 0 || first.mode !== "expand")
    throw new MigrationError(
      "bad-bootstrap",
      "migration 0000 must be the expand migration that creates the bookkeeping tables",
    );
  const now = micros(run.now);
  const compatibility = JSON.stringify({
    sourceRevision: run.options.compatibility.sourceRevision,
    schemaVersion: 0,
    planManifestHash: run.options.compatibility.planManifestHash,
    abi: run.options.compatibility.abi,
    runtime: run.options.compatibility.runtime,
  });
  const statements: MigrationStatement[] = [
    ...first.statements.map((statement) => ({ sql: statement.sql })),
    {
      sql: "INSERT INTO platform_schema_state (singleton, schema_version, read_horizon, write_horizon, fence, lease_holder, lease_expires_at, rev, updated_at) VALUES (1, 0, 0, 0, 1, ?, CAST(? AS INTEGER), 1, CAST(? AS INTEGER))",
      params: [run.options.runner, micros(run.now + run.leaseMs), now],
    },
    {
      sql: `INSERT INTO platform_migration_receipt (sequence, file_name, module, mode, checksum, state, statement_count, statements_done, runner, fence, started_at, applied_at, compatibility)
VALUES (0, ?, ?, ?, ?, ${stateApplied}, ?, ?, ?, 1, CAST(? AS INTEGER), CAST(? AS INTEGER), ?)`,
      params: [
        first.file,
        first.module,
        modeNumber[first.mode],
        first.sha256,
        first.statements.length,
        first.statements.length,
        run.options.runner,
        now,
        now,
        compatibility,
      ],
    },
  ];
  await run.client.batch(statements);
  run.fence = 1;
}

async function acquireLease(run: Run): Promise<void> {
  const now = micros(run.now);
  const [result] = await run.client.batch([
    {
      sql: `UPDATE platform_schema_state SET fence = fence + 1, lease_holder = ?, lease_expires_at = CAST(? AS INTEGER), rev = rev + 1, updated_at = CAST(? AS INTEGER)
WHERE singleton = 1 AND (lease_holder IS NULL OR lease_expires_at <= CAST(? AS INTEGER) OR lease_holder = ?)`,
      params: [run.options.runner, micros(run.now + run.leaseMs), now, now, run.options.runner],
    },
  ]);
  if ((result as BatchResult).changes !== 1) {
    const state = await readState(run);
    throw new MigrationError(
      "lease-held",
      `another migrator holds the lease (${state.leaseHolder}) until ${state.leaseExpiresAt}`,
    );
  }
  run.fence = (await readState(run)).fence;
}

async function releaseLease(run: Run): Promise<void> {
  await run.client.batch([
    {
      sql: "UPDATE platform_schema_state SET lease_holder = NULL, lease_expires_at = NULL, rev = rev + 1, updated_at = CAST(? AS INTEGER) WHERE singleton = 1 AND fence = CAST(? AS INTEGER) AND lease_holder = ?",
      params: [micros(run.now), String(run.fence), run.options.runner],
    },
  ]);
}

function verifyReceipts(
  receipts: Receipt[],
  migrations: readonly Migration[],
  allowAhead = false,
): void {
  receipts.forEach((receipt, position) => {
    if (receipt.sequence !== position)
      throw new MigrationError(
        "receipt-gap",
        `the receipts are not contiguous at sequence ${position}`,
      );
    const migration = migrations[position];
    // A database ahead of this release is a rolled-back release: status reports it, apply refuses it.
    if (!migration && allowAhead) return;
    if (!migration)
      throw new MigrationError(
        "database-ahead",
        `the database has applied migration ${receipt.file} that this release does not contain`,
      );
    if (receipt.checksum !== migration.sha256 || receipt.file !== migration.file)
      throw new MigrationError(
        "checksum-mismatch",
        `migration ${receipt.file} was edited after it was applied (receipt ${receipt.checksum.slice(0, 12)}, release ${migration.sha256.slice(0, 12)})`,
      );
    if (receipt.state === stateApplying && position !== receipts.length - 1)
      throw new MigrationError(
        "receipt-order",
        `migration ${receipt.file} is unfinished but a later migration has a receipt`,
      );
  });
}

function chunkStatements(
  statements: readonly { sql: string }[],
  from: number,
  maxStatements: number,
  maxBytes: number,
): { sql: string }[] {
  const chunk: { sql: string }[] = [];
  let bytes = 0;
  for (let index = from; index < statements.length && chunk.length < maxStatements; index++) {
    const statement = statements[index] as { sql: string };
    if (chunk.length > 0 && bytes + statement.sql.length > maxBytes) break;
    chunk.push(statement);
    bytes += statement.sql.length;
  }
  return chunk;
}

function fenceGuardedProgress(
  run: Run,
  migration: Migration,
  previous: number,
  next: number,
  last: boolean,
  extra: MigrationStatement[],
  extraCondition = "",
): MigrationStatement[] {
  const now = micros(run.now);
  const progress: MigrationStatement = {
    sql: `UPDATE platform_migration_receipt SET statements_done = CASE WHEN statements_done = CAST(? AS INTEGER) AND state = ${stateApplying} AND ${guardSql}${extraCondition} THEN CAST(? AS INTEGER) ELSE -1 END${last ? `, state = ${stateApplied}, applied_at = CAST(? AS INTEGER)` : ""} WHERE sequence = CAST(? AS INTEGER)`,
    params: [
      String(previous),
      ...run.guardParams(),
      String(next),
      ...(last ? [now] : []),
      String(migration.sequence),
    ],
  };
  return [progress, renewStatement(run), ...extra];
}

/** Keeps the lease alive from inside a guarded batch, after the guard statement, so a long run never outlives its lease. */
function renewStatement(run: Run): MigrationStatement {
  return {
    sql: "UPDATE platform_schema_state SET lease_expires_at = CAST(? AS INTEGER) WHERE singleton = 1 AND fence = CAST(? AS INTEGER) AND lease_holder = ?",
    params: [micros(run.now + run.leaseMs), String(run.fence), run.options.runner],
  };
}

/**
 * The verify queries of the backfills a cutover requires, as one condition of the cutover's own guard: the unconverted-row count is
 * evaluated inside the same batch, under the fence, that moves the horizons, so a row written after the backfill finished blocks the cutover.
 */
function cutoverVerification(
  run: Run,
  migration: Migration,
): { condition: string; queries: string[] } {
  if (migration.mode !== "cutover") return { condition: "", queries: [] };
  const queries = (migration.options.requires ?? "")
    .split(",")
    .filter(Boolean)
    .map((entry) => {
      const required = run.options.migrations.find(
        (candidate) => candidate.sequence === Number(entry),
      );
      if (required?.mode !== "backfill")
        throw new MigrationError(
          "cutover-blocked",
          `${migration.file} requires ${entry}, which is not a backfill of this release`,
        );
      return parseBackfill(required.text).verify;
    });
  return { condition: queries.map((query) => ` AND (${query}) = 0`).join(""), queries };
}

function schemaVersionStatements(run: Run, migration: Migration): MigrationStatement[] {
  const horizons = [migration.options.readHorizon, migration.options.writeHorizon];
  const statements: MigrationStatement[] = [];
  if (migration.mode === "cutover" && (horizons[0] !== undefined || horizons[1] !== undefined)) {
    statements.push({
      sql: `UPDATE platform_schema_state SET read_horizon = COALESCE(CAST(? AS INTEGER), read_horizon), write_horizon = COALESCE(CAST(? AS INTEGER), write_horizon), schema_version = CAST(? AS INTEGER), rev = rev + 1, updated_at = CAST(? AS INTEGER) WHERE singleton = 1 AND fence = CAST(? AS INTEGER)`,
      params: [
        horizons[0] ?? null,
        horizons[1] ?? null,
        String(migration.sequence),
        micros(run.now),
        String(run.fence),
      ],
    });
  } else {
    statements.push({
      sql: "UPDATE platform_schema_state SET schema_version = CAST(? AS INTEGER), rev = rev + 1, updated_at = CAST(? AS INTEGER) WHERE singleton = 1 AND fence = CAST(? AS INTEGER)",
      params: [String(migration.sequence), micros(run.now), String(run.fence)],
    });
  }
  return statements;
}

async function applyStatements(
  run: Run,
  migration: Migration,
  receipt: Receipt | null,
): Promise<AppliedMigration> {
  const statements = migration.statements;
  let done = receipt?.statementsDone ?? 0;
  if (!receipt) {
    const [result] = await run.client.batch([receiptInsert(run, migration, statements.length)]);
    if ((result as BatchResult).changes !== 1)
      throw new MigrationError(
        "stale-migrator",
        `the lease was lost before ${migration.file} could start`,
      );
  }
  let chunks = 0;
  const verification = cutoverVerification(run, migration);
  while (done < statements.length) {
    const chunk = chunkStatements(
      statements,
      done,
      run.options.maxChunkStatements ?? 25,
      run.options.maxChunkBytes ?? 60_000,
    );
    const next = done + chunk.length;
    const last = next === statements.length;
    const info = { sequence: migration.sequence, from: done, to: next };
    await run.options.hooks?.beforeChunk?.(info);
    const batch = fenceGuardedProgress(
      run,
      migration,
      done,
      next,
      last,
      [
        ...chunk.map((statement) => ({ sql: statement.sql })),
        ...(last ? schemaVersionStatements(run, migration) : []),
      ],
      verification.condition,
    );
    try {
      await run.client.batch(batch);
    } catch (error) {
      // Only the guard's own constraint (or the receipt's immutability once another migrator finished it) is a fence or progress failure; a constraint of the migration's own statements is a real failure.
      if (
        error instanceof Error &&
        /ck_platform_migration_receipt__progress|af_immutable_platform_migration_receipt/u.test(
          error.message,
        )
      ) {
        for (const query of verification.queries) {
          const remaining = int((await run.one(query))[0]?.[0]);
          if (remaining !== 0)
            throw new MigrationError(
              "cutover-blocked",
              `${migration.file}: ${remaining} rows are unconverted or dirty at the moment of cutover`,
            );
        }
        throw new MigrationError(
          "stale-migrator",
          `the fence or the receipt moved under ${migration.file}: ${error.message}`,
        );
      }
      throw error;
    }
    chunks++;
    done = next;
    await run.options.hooks?.afterChunk?.(info);
  }
  return {
    sequence: migration.sequence,
    file: migration.file,
    mode: migration.mode,
    statements: statements.length,
    chunks,
  };
}

async function requireVerifiedBackfills(
  run: Run,
  migration: Migration,
  receipts: Receipt[],
): Promise<void> {
  const required = (migration.options.requires ?? "").split(",").filter(Boolean).map(Number);
  for (const sequence of required) {
    const receipt = receipts.find((entry) => entry.sequence === sequence);
    if (!receipt || receipt.state !== stateApplied)
      throw new MigrationError(
        "cutover-blocked",
        `${migration.file} requires backfill ${sequence} to be applied`,
      );
    const rows = await run.one(
      "SELECT verified FROM platform_backfill_checkpoint WHERE sequence = CAST(? AS INTEGER)",
      [String(sequence)],
    );
    if (int(rows[0]?.[0]) !== 1)
      throw new MigrationError(
        "cutover-blocked",
        `${migration.file} requires backfill ${sequence} to be verified`,
      );
  }
}

async function requireSoak(run: Run, migration: Migration, receipts: Receipt[]): Promise<void> {
  if (!run.options.allowContract)
    throw new MigrationError(
      "contract-refused",
      `${migration.file} is irreversible and is applied only with allowContract`,
    );
  const after = Number(migration.options.after);
  const soakSeconds = Number(migration.options.soak);
  if (!Number.isInteger(after) || !Number.isInteger(soakSeconds) || soakSeconds < 0)
    throw new MigrationError(
      "contract-refused",
      `${migration.file} must declare after=<cutover sequence> and soak=<seconds>`,
    );
  const cutover = receipts.find((entry) => entry.sequence === after);
  if (!cutover || cutover.state !== stateApplied || cutover.appliedAt === null)
    throw new MigrationError(
      "contract-refused",
      `${migration.file} follows cutover ${after}, which is not applied`,
    );
  const due = cutover.appliedAt + BigInt(soakSeconds) * 1_000_000n;
  if (BigInt(micros(run.now)) < due)
    throw new MigrationError(
      "contract-refused",
      `${migration.file} may run only after the soak of ${soakSeconds} seconds that follows cutover ${after}`,
    );
}

async function applyBackfill(
  run: Run,
  migration: Migration,
  receipt: Receipt | null,
): Promise<AppliedMigration> {
  const spec: BackfillSpec = parseBackfill(migration.text);
  if (!receipt) {
    const [first] = await run.client.batch([
      receiptInsert(run, migration, 1),
      {
        sql: `INSERT INTO platform_backfill_checkpoint (sequence, last_key, pages_done, rows_converted, rows_stale, verified, updated_at)
SELECT CAST(? AS INTEGER), NULL, 0, 0, 0, 0, CAST(? AS INTEGER) WHERE ${guardSql}`,
        params: [String(migration.sequence), micros(run.now), ...run.guardParams()],
      },
    ]);
    if ((first as BatchResult).changes !== 1)
      throw new MigrationError(
        "stale-migrator",
        `the lease was lost before ${migration.file} could start`,
      );
  }
  const maxPasses = run.options.maxBackfillPasses ?? 10;
  let passes = 0;
  let rowsConverted = 0;
  let rowsStale = 0;
  for (;;) {
    passes++;
    if (passes > maxPasses)
      throw new MigrationError(
        "backfill-not-converging",
        `${migration.file} did not converge in ${maxPasses} passes`,
      );
    const checkpoint = await run.one(
      "SELECT last_key, CAST(rows_converted AS TEXT), CAST(rows_stale AS TEXT) FROM platform_backfill_checkpoint WHERE sequence = CAST(? AS INTEGER)",
      [String(migration.sequence)],
    );
    let cursor =
      checkpoint[0]?.[0] === null || checkpoint[0]?.[0] === undefined
        ? ""
        : String(checkpoint[0]?.[0]);
    const before = { converted: int(checkpoint[0]?.[1]), stale: int(checkpoint[0]?.[2]) };
    for (;;) {
      const page = await run.one(spec.page, [cursor, spec.pageSize]);
      if (page.length === 0) break;
      const keys = page.map((row) => String(row[0]));
      await run.options.hooks?.afterPageSelect?.({ sequence: migration.sequence, keys });
      const lastKey = keys[keys.length - 1] as string;
      const statements: MigrationStatement[] = [
        {
          sql: `UPDATE platform_backfill_checkpoint SET pages_done = CASE WHEN COALESCE(last_key, '') = ? AND verified = 0 AND ${guardSql} THEN pages_done + 1 ELSE -1 END, last_key = ?, updated_at = CAST(? AS INTEGER) WHERE sequence = CAST(? AS INTEGER)`,
          params: [
            cursor,
            ...run.guardParams(),
            lastKey,
            micros(run.now),
            String(migration.sequence),
          ],
        },
        // After the guard and before any apply statement: changes() below reads the apply statement that precedes it.
        renewStatement(run),
      ];
      for (const row of page) {
        statements.push({ sql: spec.apply, params: [String(row[0]), String(row[1])] });
        statements.push({
          sql: "UPDATE platform_backfill_checkpoint SET rows_converted = rows_converted + changes(), rows_stale = rows_stale + (1 - changes()) WHERE sequence = CAST(? AS INTEGER)",
          params: [String(migration.sequence)],
        });
      }
      try {
        await run.client.batch(statements);
      } catch (error) {
        if (
          error instanceof Error &&
          /ck_platform_backfill_checkpoint__counters/u.test(error.message)
        )
          throw new MigrationError(
            "stale-migrator",
            `the fence or the checkpoint moved under ${migration.file}: ${error.message}`,
          );
        throw error;
      }
      cursor = lastKey;
    }
    const verify = await run.one(spec.verify);
    const remaining = int(verify[0]?.[0]);
    const after = await run.one(
      "SELECT CAST(rows_converted AS TEXT), CAST(rows_stale AS TEXT) FROM platform_backfill_checkpoint WHERE sequence = CAST(? AS INTEGER)",
      [String(migration.sequence)],
    );
    rowsConverted = int(after[0]?.[0]);
    rowsStale = int(after[0]?.[1]);
    if (remaining === 0) break;
    const progressed = rowsConverted - before.converted > 0 || rowsStale - before.stale > 0;
    if (!progressed)
      throw new MigrationError(
        "backfill-not-converging",
        `${migration.file}: ${remaining} rows remain unconverted and a pass converted none`,
      );
    // The dirty rows (written after they were read) are picked up by another pass from the start of the key range.
    try {
      await run.client.batch([
        {
          sql: `UPDATE platform_backfill_checkpoint SET pages_done = CASE WHEN ${guardSql} THEN pages_done ELSE -1 END, last_key = NULL, updated_at = CAST(? AS INTEGER) WHERE sequence = CAST(? AS INTEGER)`,
          params: [...run.guardParams(), micros(run.now), String(migration.sequence)],
        },
        renewStatement(run),
      ]);
    } catch (error) {
      if (
        error instanceof Error &&
        /ck_platform_backfill_checkpoint__counters/u.test(error.message)
      )
        throw new MigrationError(
          "stale-migrator",
          `the fence moved under ${migration.file}: ${error.message}`,
        );
      throw error;
    }
  }
  await run.client.batch(
    fenceGuardedProgress(run, migration, 0, 1, true, [
      {
        sql: "UPDATE platform_backfill_checkpoint SET verified = 1, updated_at = CAST(? AS INTEGER) WHERE sequence = CAST(? AS INTEGER)",
        params: [micros(run.now), String(migration.sequence)],
      },
      ...schemaVersionStatements(run, migration),
    ]),
  );
  return {
    sequence: migration.sequence,
    file: migration.file,
    mode: "backfill",
    statements: 1,
    rowsConverted,
    rowsStale,
    passes,
  };
}

/** Applies every pending migration in order under the lease; resumes an unfinished one. */
export async function applyPending(options: RunOptions): Promise<RunResult> {
  const run = new Run(options);
  const migrations = options.migrations;
  const first = migrations[0];
  if (!first) throw new MigrationError("empty-catalog", "the migration catalog is empty");
  const exists = await tableExists(run);
  if (!exists) {
    await bootstrap(run, first);
  } else {
    await acquireLease(run);
  }
  const applied: AppliedMigration[] = [];
  try {
    let receipts = await readReceipts(run);
    verifyReceipts(receipts, migrations);
    let highest = receipts.filter((entry) => entry.state === stateApplied).length - 1;
    for (const migration of migrations) {
      if (migration.sequence <= highest) continue;
      if (options.stopAfter !== undefined && migration.sequence > options.stopAfter) break;
      const receipt = receipts.find((entry) => entry.sequence === migration.sequence) ?? null;
      // Renew the lease so a long run keeps its fence; a lease that expired was taken over and the guard refuses us.
      if (migration.mode === "cutover") await requireVerifiedBackfills(run, migration, receipts);
      if (migration.mode === "contract") await requireSoak(run, migration, receipts);
      const outcome =
        migration.mode === "backfill"
          ? await applyBackfill(run, migration, receipt)
          : await applyStatements(run, migration, receipt);
      applied.push(outcome);
      receipts = await readReceipts(run);
      highest = migration.sequence;
    }
  } finally {
    // Release only a lease still ours; a stale migrator's release matches nothing.
    try {
      await releaseLease(run);
    } catch {
      // The lease expires on its own.
    }
  }
  const state = await readState(run);
  return {
    fence: run.fence,
    applied,
    schemaVersion: state.schemaVersion,
    alreadyCurrent: applied.length === 0,
  };
}

export interface MigrationStatus {
  initialized: boolean;
  /** Receipts of migrations this release does not contain (the release was rolled back). */
  databaseAhead: number;
  schemaVersion: number;
  readHorizon: number;
  writeHorizon: number;
  fence: number;
  leaseHolder: string | null;
  receipts: {
    sequence: number;
    file: string;
    state: "applying" | "applied";
    statementsDone: number;
    statementCount: number;
  }[];
  pending: string[];
}

/** Read-only status: what is applied, what an interrupted run left and what is still pending. */
export async function status(
  client: MigrationClient,
  migrations: readonly Migration[],
  now: () => number = Date.now,
): Promise<MigrationStatus> {
  const run = new Run({
    client,
    migrations,
    runner: "status",
    now,
    compatibility: { sourceRevision: "local", planManifestHash: "", abi: "", runtime: "" },
  });
  if (!(await tableExists(run)))
    return {
      initialized: false,
      databaseAhead: 0,
      schemaVersion: -1,
      readHorizon: 0,
      writeHorizon: 0,
      fence: 0,
      leaseHolder: null,
      receipts: [],
      pending: migrations.map((entry) => entry.file),
    };
  const state = await readState(run);
  const receipts = await readReceipts(run);
  verifyReceipts(receipts, migrations, true);
  return {
    initialized: true,
    databaseAhead: Math.max(0, receipts.length - migrations.length),
    schemaVersion: state.schemaVersion,
    readHorizon: state.readHorizon,
    writeHorizon: state.writeHorizon,
    fence: state.fence,
    leaseHolder: state.leaseHolder,
    receipts: receipts.map((entry) => ({
      sequence: entry.sequence,
      file: entry.file,
      state: entry.state === stateApplied ? "applied" : "applying",
      statementsDone: entry.statementsDone,
      statementCount: entry.statementCount,
    })),
    pending: migrations
      .filter(
        (entry) =>
          !receipts.some(
            (receipt) => receipt.sequence === entry.sequence && receipt.state === stateApplied,
          ),
      )
      .map((entry) => entry.file),
  };
}

export interface ApplicationSchema {
  /** The highest migration the application was built for. */
  schemaVersion: number;
}
export interface Compatibility {
  canRead: boolean;
  canWrite: boolean;
  reason: string;
}

/**
 * Whether an application build may use the database (readiness, and the compatible-rollback rule): it must not be
 * newer than the applied schema, and the horizons name the oldest builds that may still read and write. After a
 * cutover the old build is refused, which is why a rollback before cutover is compatible and after it is not.
 */
export function compatibility(
  state: { schemaVersion: number; readHorizon: number; writeHorizon: number },
  application: ApplicationSchema,
): Compatibility {
  if (application.schemaVersion > state.schemaVersion)
    return {
      canRead: false,
      canWrite: false,
      reason: "the application expects a newer schema than the database has applied",
    };
  const canRead = application.schemaVersion >= state.readHorizon;
  const canWrite = application.schemaVersion >= state.writeHorizon;
  return {
    canRead,
    canWrite,
    reason: canWrite
      ? "compatible"
      : canRead
        ? "the build is below the write horizon"
        : "the build is below the read horizon",
  };
}
