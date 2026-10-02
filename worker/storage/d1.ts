// SPDX-License-Identifier: AGPL-3.0-only
// The narrow D1 surface the named-plan executor needs. The real D1Database binding satisfies it and
// the offline tests satisfy it with an SQLite shim, so the executor never imports Worker types.

export interface D1Meta {
  readonly changes?: number;
}

export interface D1RunResult {
  readonly meta?: D1Meta;
}

export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  /** Rows as arrays in column order (the order of the SELECT list). */
  raw(): Promise<unknown[][]>;
}

export interface D1Like {
  prepare(sql: string): D1PreparedStatement;
  /** One atomic transaction: if any statement fails the whole batch is rolled back. */
  batch(statements: D1PreparedStatement[]): Promise<D1RunResult[]>;
}
