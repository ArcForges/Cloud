// SPDX-License-Identifier: AGPL-3.0-only
// An SQLite stand-in for the D1 binding used by the offline plan vectors. D1 is SQLite, so these
// vectors exercise the real plan SQL, the real constraints and the real batch rollback, but they do
// not exercise Cloudflare's network path, limits or primary-read behavior (those need the live proof).
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { readFileSync } from "node:fs";
import path from "node:path";
import type { D1Like, D1PreparedStatement, D1RunResult } from "../../../worker/storage/d1.ts";

export const repositoryRoot = path.resolve(import.meta.dirname, "../../..");

function toSqlite(value: unknown): SQLInputValue {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return value as SQLInputValue;
}

class Statement implements D1PreparedStatement {
  readonly database: DatabaseSync;
  readonly sql: string;
  readonly values: unknown[];
  constructor(database: DatabaseSync, sql: string, values: unknown[] = []) {
    this.database = database;
    this.sql = sql;
    this.values = values;
  }
  bind(...values: unknown[]): Statement {
    return new Statement(this.database, this.sql, values);
  }
  raw(): Promise<unknown[][]> {
    const statement = this.database.prepare(this.sql);
    statement.setReturnArrays(true);
    return Promise.resolve(statement.all(...this.values.map(toSqlite)) as unknown as unknown[][]);
  }
  run(): { changes: number } {
    const result = this.database.prepare(this.sql).run(...this.values.map(toSqlite));
    return { changes: Number(result.changes) };
  }
}

export interface SqliteD1 extends D1Like {
  readonly database: DatabaseSync;
  /** Number of batches that were rolled back. */
  readonly rollbacks: () => number;
}

export function createSqliteD1(
  migration = readFileSync(
    path.join(repositoryRoot, "worker/proof-migrations/0001_foundation_probe.sql"),
    "utf8",
  ),
): SqliteD1 {
  const database = new DatabaseSync(":memory:");
  database.exec(migration);
  let rolledBack = 0;
  return {
    database,
    rollbacks: () => rolledBack,
    prepare: (sql) => new Statement(database, sql),
    async batch(statements: D1PreparedStatement[]): Promise<D1RunResult[]> {
      database.exec("BEGIN");
      try {
        const results = statements.map((statement) => ({ meta: (statement as Statement).run() }));
        database.exec("COMMIT");
        return results;
      } catch (error) {
        rolledBack++;
        database.exec("ROLLBACK");
        throw error;
      }
    },
  };
}
