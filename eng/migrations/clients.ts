// SPDX-License-Identifier: AGPL-3.0-only
// The narrow surface the migration runner needs from a D1 database: one atomic batch of positional-bind
// statements. Three implementations: node:sqlite (the offline real-SQL oracle), a D1 binding (Miniflare for the
// local opt-in runtime test, or a Worker binding) and the Cloudflare D1 REST API (the gated deployment job).
// 64-bit values are never bound or read as JavaScript numbers: the runner binds canonical decimal text with
// CAST(? AS INTEGER) and reads CAST(column AS TEXT), exactly as the named-plan bridge does.
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

export interface RestOptions {
  accountId: string;
  databaseId: string;
  /** Read by the deployment job from its secret environment; never printed. */
  apiToken: string;
  fetch?: typeof fetch;
  baseUrl?: string;
  timeoutMs?: number;
}

/**
 * The Cloudflare D1 REST client: POST /accounts/{account}/d1/database/{database}/query with a `batch` of
 * statements. It assumes the provider runs a batch as one atomic transaction, as the Worker binding does;
 * that assumption is the deferred live check recorded for CLOUD.03.
 */
export class RestMigrationClient implements MigrationClient {
  readonly options: RestOptions;
  constructor(options: RestOptions) {
    this.options = options;
  }
  async batch(statements: readonly MigrationStatement[]): Promise<BatchResult[]> {
    const { accountId, databaseId, apiToken } = this.options;
    const doFetch = this.options.fetch ?? fetch;
    const base = this.options.baseUrl ?? "https://api.cloudflare.com/client/v4";
    const url = `${base}/accounts/${encodeURIComponent(accountId)}/d1/database/${encodeURIComponent(databaseId)}/query`;
    const body = JSON.stringify({
      batch: statements.map((statement) => ({
        sql: statement.sql,
        params: statement.params ?? [],
      })),
    });
    let response: Response;
    try {
      response = await doFetch(url, {
        method: "POST",
        headers: { authorization: `Bearer ${apiToken}`, "content-type": "application/json" },
        body,
        signal: AbortSignal.timeout(this.options.timeoutMs ?? 60_000),
      });
    } catch (error) {
      // The outcome is unknown: the runner re-reads the receipt, which is the ground truth.
      throw new MigrationClientError(
        `D1 request failed (outcome unknown): ${error instanceof Error ? error.name : "error"}`,
      );
    }
    let value: {
      success?: boolean;
      errors?: { message?: string }[];
      result?: { results?: Record<string, unknown>[]; meta?: { changes?: number } }[];
    };
    try {
      value = (await response.json()) as typeof value;
    } catch {
      throw new MigrationClientError(`D1 returned HTTP ${response.status} without a JSON body`);
    }
    if (!response.ok || value.success === false) {
      const message = (value.errors ?? []).map((entry) => entry.message ?? "error").join("; ");
      throw new MigrationClientError(`D1 refused the batch (HTTP ${response.status}): ${message}`);
    }
    const results = value.result ?? [];
    if (results.length !== statements.length)
      throw new MigrationClientError("D1 returned a different number of results than statements");
    return results.map((entry) => ({
      changes: entry.meta?.changes ?? 0,
      rows: (entry.results ?? []).map((row) => Object.values(row)),
    }));
  }
}
