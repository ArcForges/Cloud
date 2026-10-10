// SPDX-License-Identifier: AGPL-3.0-only
// Test support only (CLOUD.84 U9, S41, S42(2)): the narrow surface of the TypeScript migration runner, used by the offline local drivers
// (eng/verification/d1-*-local.ts). The live D1 REST transport is C# (tools/ArcForges.Cloud.Generation/Migrations/D1RestClient.cs);
// C# is authoritative for every migration decision.
// The narrow surface the migration runner needs from a D1 database: one atomic batch of positional-bind
// statements. Two implementations here: node:sqlite (the offline real-SQL oracle) and a D1 binding (Miniflare for the
// local opt-in runtime test, or a Worker binding).
// 64-bit values are never bound or read as JavaScript numbers: the runner binds canonical decimal text with
// CAST(? AS INTEGER) and reads CAST(column AS TEXT), exactly as the named-plan bridge does.
// The live D1 path is C# and no TypeScript REST transport remains; deleting this file is an open residual (D13, S42(2)).
import { DatabaseSync, type SQLInputValue } from "node:sqlite";

export type Bind = string | number | null | Uint8Array;
export interface MigrationStatement {
  sql: string;
  params?: readonly Bind[];
}
export interface BatchResult {
  /** Rows changed by a write statement (SQLite changes()). */
  changes: number;
  /** Rows of a SELECT as arrays in column order. */
  rows: unknown[][];
}
export interface MigrationClient {
  /** Runs the statements in order as one atomic transaction: all commit or none does. */
  batch(statements: readonly MigrationStatement[]): Promise<BatchResult[]>;
}

/** An error thrown by a client carries no credential: the message is the database's, never a request header. */
export class MigrationClientError extends Error {}

export class SqliteMigrationClient implements MigrationClient {
  readonly database: DatabaseSync;
  /** Number of batches rolled back, for tests. */
  rollbacks = 0;
  constructor(database = new DatabaseSync(":memory:")) {
    this.database = database;
    this.database.exec("PRAGMA foreign_keys = ON");
  }
  batch(statements: readonly MigrationStatement[]): Promise<BatchResult[]> {
    const results: BatchResult[] = [];
    this.database.exec("BEGIN IMMEDIATE");
    try {
      for (const statement of statements) {
        const prepared = this.database.prepare(statement.sql);
        const params = (statement.params ?? []) as SQLInputValue[];
        if (prepared.columns().length > 0) {
          prepared.setReturnArrays(true);
          results.push({ changes: 0, rows: prepared.all(...params) as unknown as unknown[][] });
        } else {
          const outcome = prepared.run(...params);
          results.push({ changes: Number(outcome.changes), rows: [] });
        }
      }
      this.database.exec("COMMIT");
      return Promise.resolve(results);
    } catch (error) {
      this.rollbacks++;
      try {
        this.database.exec("ROLLBACK");
      } catch {
        // The transaction was already ended by SQLite.
      }
      return Promise.reject(
        error instanceof Error ? new MigrationClientError(error.message) : error,
      );
    }
  }
}

/** The part of a D1Database binding the client uses (Miniflare's and a Worker's both satisfy it). */
export interface D1BindingLike {
  prepare(sql: string): { bind(...values: unknown[]): unknown };
  batch(
    statements: unknown[],
  ): Promise<{ results?: Record<string, unknown>[]; meta?: { changes?: number } }[]>;
}

export class D1BindingMigrationClient implements MigrationClient {
  readonly binding: D1BindingLike;
  constructor(binding: D1BindingLike) {
    this.binding = binding;
  }
  async batch(statements: readonly MigrationStatement[]): Promise<BatchResult[]> {
    const prepared = statements.map((statement) =>
      this.binding.prepare(statement.sql).bind(...(statement.params ?? [])),
    );
    let results: Awaited<ReturnType<D1BindingLike["batch"]>>;
    try {
      results = await this.binding.batch(prepared);
    } catch (error) {
      throw error instanceof Error ? new MigrationClientError(error.message) : error;
    }
    return results.map((entry) => ({
      changes: entry.meta?.changes ?? 0,
      rows: (entry.results ?? []).map((row) => Object.values(row)),
    }));
  }
}
