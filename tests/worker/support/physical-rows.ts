// SPDX-License-Identifier: AGPL-3.0-only
// Row construction for the physical-schema conformance tests: a valid row of every table of the manifest built from the
// column kinds, a small search over the columns that table-level checks mention, exact insert (64-bit values bound as decimal
// text through CAST, exactly as the named-plan bridge does) and exact read-back (CAST(column AS TEXT) for integers).
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import {
  type PhysicalColumn,
  type PhysicalSchema,
  type PhysicalTable,
  type ResolvedEnum,
  columnGroupChecks,
  planKindOf,
} from "../../../eng/verification/physical-schema.ts";

export type RowValue = string | bigint | number | Uint8Array | null;
export type Row = Record<string, RowValue>;

const instantBase = 1_790_000_000_123_456n;

export function uuid(index: number): string {
  return `0198a7c0-1c3e-7d4a-9b1f-${index.toString(16).padStart(12, "0")}`;
}

export const isIntegerColumn = (column: PhysicalColumn) => column.sqlType === "INTEGER";

interface Variant {
  /** Use the extreme valid value of every kind instead of a typical one. */
  boundary: boolean;
}

const bytes = (length: number, seed: number) =>
  Uint8Array.from({ length }, (_, index) => (index * 7 + seed) & 255);

/** A typical or extreme valid value for one column. */
export function valueFor(
  column: PhysicalColumn,
  enums: Map<string, ResolvedEnum>,
  serial: number,
  variant: Variant,
): RowValue {
  switch (column.kind) {
    case "id":
      return uuid(serial);
    case "text":
      return variant.boundary ? "A中😀".repeat(8) : `text-${serial}`;
    case "key":
      return variant.boundary ? `k${"a".repeat(127)}` : `key.${serial}`;
    case "productId":
      return variant.boundary ? "companion" : "arcscope";
    case "modelId":
      return variant.boundary ? `@cf/${"m".repeat(250)}` : "@cf/openai/gpt-oss-120b";
    case "currency":
      return "USD";
    case "bool":
      return variant.boundary ? 1 : 0;
    case "int":
      return variant.boundary ? 2147483647n : 7n;
    case "int64":
      return variant.boundary ? 9223372036854775807n : 7n;
    case "rev":
      return variant.boundary ? 9223372036854775807n : 1n;
    case "instant":
      return variant.boundary ? 253402300799999999n : instantBase;
    case "uint64":
      return variant.boundary ? "18446744073709551615" : "9007199254740993";
    case "decimal":
      return variant.boundary ? "9999999999999999999.999999999" : "1.5";
    case "hash":
      return bytes(32, serial);
    case "bytes":
    case "proto":
      return variant.boundary ? bytes(4096, serial) : bytes(5, serial);
    case "json":
      return column.jsonRoot === "array" ? '["a","b"]' : '{"a":1,"b":[true,null,"x"]}';
    case "enum": {
      const registered = enums.get(column.enumName ?? "");
      const members = registered?.members ?? [];
      return BigInt(
        variant.boundary ? (members[members.length - 1]?.number ?? 1) : (members[0]?.number ?? 1),
      );
    }
    default:
      throw new Error(`no value for kind ${String(column.kind)}`);
  }
}

/** Values to try for a column that a table-level check mentions. */
export function candidatesFor(
  column: PhysicalColumn,
  enums: Map<string, ResolvedEnum>,
  serial: number,
  literals: { text: string[]; numbers: bigint[] },
): RowValue[] {
  const out: RowValue[] = [];
  const add = (value: RowValue) => {
    if (
      !out.some(
        (existing) => String(existing) === String(value) && typeof existing === typeof value,
      )
    )
      out.push(value);
  };
  switch (column.kind) {
    case "instant":
      for (const delta of [0n, 1_000_000n, 2_000_000n, 900_000_000n, 1_000_000_000n])
        add(instantBase + delta);
      break;
    case "int":
    case "int64":
    case "rev": {
      for (const value of [0n, 1n, 2n, 5n]) add(value);
      for (const value of literals.numbers) {
        add(value);
        add(value + 1n);
        if (value > 0n) add(value - 1n);
      }
      break;
    }
    case "bool":
      add(0);
      add(1);
      break;
    case "enum":
      for (const member of enums.get(column.enumName ?? "")?.members ?? [])
        add(BigInt(member.number));
      break;
    case "text":
    case "key":
      for (const literal of literals.text) add(literal);
      add(valueFor(column, enums, serial, { boundary: false }));
      break;
    case "decimal":
      for (const value of ["0", "1", "1.5"]) add(value);
      break;
    case "uint64":
      for (const value of ["0", "1"]) add(value);
      break;
    default:
      add(valueFor(column, enums, serial, { boundary: false }));
  }
  if (column.nullable) add(null);
  return out;
}

const quoted = /"([a-z][a-z0-9_]*)"/gu;

export function checkColumns(table: PhysicalTable, checkSql: string): string[] {
  const names = new Set(table.columns.map((column) => column.name));
  return [...new Set([...checkSql.matchAll(quoted)].map((match) => match[1] ?? ""))].filter(
    (name) => names.has(name),
  );
}

export function insertStatement(table: PhysicalTable): { sql: string } {
  const names = table.columns.map((column) => `"${column.name}"`).join(", ");
  const marks = table.columns
    .map((column) => (isIntegerColumn(column) ? "CAST(? AS INTEGER)" : "?"))
    .join(", ");
  return { sql: `INSERT INTO "${table.name}" (${names}) VALUES (${marks})` };
}

/** Binds a row the way the bridge does: integers as exact decimal text, booleans as 0/1, bytes as bytes. */
export function bindRow(table: PhysicalTable, row: Row): SQLInputValue[] {
  return table.columns.map((column) => {
    const value = row[column.name];
    if (value === undefined) throw new Error(`row for ${table.name} has no ${column.name}`);
    if (value === null) return null;
    if (isIntegerColumn(column)) return String(value);
    return value as SQLInputValue;
  });
}

export function selectStatement(table: PhysicalTable): string {
  const names = table.columns
    .map((column) =>
      isIntegerColumn(column) ? `CAST("${column.name}" AS TEXT)` : `"${column.name}"`,
    )
    .join(", ");
  const keys = table.primaryKey.map((name) => `"${name}"`).join(", ");
  return `SELECT ${names} FROM "${table.name}" ORDER BY ${keys}`;
}

export function readBack(database: DatabaseSync, table: PhysicalTable): Row[] {
  const statement = database.prepare(selectStatement(table));
  statement.setReturnArrays(true);
  return (statement.all() as unknown as unknown[][]).map((values) => {
    const row: Row = {};
    table.columns.forEach((column, index) => {
      const value = values[index];
      row[column.name] =
        (isIntegerColumn(column) && value !== null ? BigInt(String(value)) : (value as RowValue)) ??
        null;
    });
    return row;
  });
}

function sameValue(left: RowValue | undefined, right: RowValue | undefined): boolean {
  if (left instanceof Uint8Array && right instanceof Uint8Array)
    return left.length === right.length && left.every((byte, index) => byte === right[index]);
  if (typeof left === "number" || typeof right === "number")
    return BigInt(Number(left)) === BigInt(Number(right));
  return left === right;
}
export const rowsEqual = (table: PhysicalTable, left: Row, right: Row) =>
  table.columns.every((column) => sameValue(left[column.name], right[column.name]));

export interface BuiltRow {
  row: Row;
  /** Attempts needed to satisfy the table-level checks. */
  attempts: number;
}

function generatedValue(database: DatabaseSync, column: PhysicalColumn, row: Row): RowValue {
  const names = [
    ...new Set([...(column.generated ?? "").matchAll(quoted)].map((match) => match[1] ?? "")),
  ];
  const cte = `WITH r(${names.map((name) => `"${name}"`).join(", ")}) AS (VALUES (${names.map(() => "?").join(", ")})) SELECT ${column.generated} FROM r`;
  const result = database.prepare(cte).get(...names.map((name) => String(row[name]))) as Record<
    string,
    unknown
  >;
  return Object.values(result)[0] as RowValue;
}

/**
 * Builds one row that the table accepts: defaults per kind, then a search over the columns that a table-level check names
 * (every candidate combination, bounded). Foreign keys are not satisfied (the test database has them off): the row proves the
 * column and table checks, not the parent rows.
 */
export function buildAcceptedRow(
  database: DatabaseSync,
  schema: PhysicalSchema,
  table: PhysicalTable,
  variant: Variant,
  serial: number,
): BuiltRow {
  const enums = new Map(schema.enums.map((entry) => [entry.name, entry]));
  const base: Row = {};
  table.columns.forEach((column, index) => {
    base[column.name] =
      column.nullable && !variant.boundary
        ? null
        : valueFor(column, enums, serial * 100 + index, variant);
  });
  const quotaProfile = JSON.stringify([
    variant.boundary ? `${"中😀".repeat(9361)}aaaaa` : "典型😀",
  ]);
  const quotaProfileHash = bytes(32, serial);
  // Columns whose table check demands a shape no kind default can guess (a hex digest in a text column).
  const patterned: Record<string, Record<string, RowValue>> = {
    platform_migration_receipt: { checksum: "a".repeat(64) },
    entitlement_quota_definition_profile: {
      canonical_profile: quotaProfile,
      artifact_length: BigInt(Buffer.byteLength(quotaProfile, "utf8")),
      profile_hash: quotaProfileHash,
      artifact_hash: quotaProfileHash,
    },
  };
  for (const [name, value] of Object.entries(patterned[table.name] ?? {})) base[name] = value;
  const generatedColumns = table.columns.filter((column) => column.generated);
  const settle = (row: Row) => {
    for (const column of generatedColumns) row[column.name] = generatedValue(database, column, row);
  };
  const checks = [...columnGroupChecks(table), ...table.checks].map((check) => check.sql);
  const mentioned = new Set<string>();
  for (const sql of checks) for (const name of checkColumns(table, sql)) mentioned.add(name);
  for (const index of table.indexes)
    if (index.where) for (const name of checkColumns(table, index.where)) mentioned.add(name);
  const literals = { text: [] as string[], numbers: [] as bigint[] };
  for (const sql of checks) {
    for (const match of sql.matchAll(/'([^']*)'/gu)) literals.text.push(match[1] ?? "");
    for (const match of sql.matchAll(/(?<![\w"])(\d+)(?![\w"])/gu))
      literals.numbers.push(BigInt(match[1] ?? "0"));
  }
  const columns = table.columns.filter(
    (column) =>
      mentioned.has(column.name) &&
      !column.generated &&
      !(column.name in (patterned[table.name] ?? {})),
  );
  const options = columns.map((column, index) =>
    candidatesFor(column, enums, serial * 100 + 50 + index, literals),
  );
  const insert = insertStatement(table);
  let attempts = 0;
  const pick = (selection: number[]): Row => {
    const row = { ...base };
    selection.forEach((choice, index) => {
      row[(columns[index] as PhysicalColumn).name] = (options[index] as RowValue[])[
        choice
      ] as RowValue;
    });
    settle(row);
    return row;
  };
  const tryRow = (row: Row): boolean => {
    attempts++;
    database.exec("SAVEPOINT attempt");
    try {
      database.prepare(insert.sql).run(...bindRow(table, row));
      database.exec("ROLLBACK TO attempt");
      database.exec("RELEASE attempt");
      return true;
    } catch {
      database.exec("ROLLBACK TO attempt");
      database.exec("RELEASE attempt");
      return false;
    }
  };
  const sizes = options.map((entry) => entry.length);
  const total = sizes.reduce((product, size) => product * size, 1);
  if (total > 200_000) throw new Error(`${table.name}: the check search is too large (${total})`);
  const selection = sizes.map(() => 0);
  for (let count = 0; count < total; count++) {
    const row = pick(selection);
    if (tryRow(row)) return { row, attempts };
    for (let position = 0; position < selection.length; position++) {
      selection[position] = (selection[position] ?? 0) + 1;
      if ((selection[position] ?? 0) < (sizes[position] ?? 1)) break;
      selection[position] = 0;
    }
  }
  throw new Error(`${table.name}: no candidate row satisfies the table checks (${total} tried)`);
}

export function insertRow(database: DatabaseSync, table: PhysicalTable, row: Row): void {
  database.prepare(insertStatement(table).sql).run(...bindRow(table, row));
}

/** A value the column's own check must refuse, or null when the column has no check beyond its type. */
export function violatingValue(
  column: PhysicalColumn,
  enums: Map<string, ResolvedEnum>,
): RowValue | undefined {
  switch (column.kind) {
    case "id":
      return "0198A7C0-1C3E-7D4A-9B1F-2E5D6A7B8C9D";
    case "key":
      return "";
    case "productId":
      return "arcnotes";
    case "modelId":
      return "";
    case "currency":
      return "usd";
    case "bool":
      return 2;
    case "int":
      return 2147483648n;
    case "rev":
      return -1n;
    case "uint64":
      return "01";
    case "decimal":
      return "1.10";
    case "hash":
      return new Uint8Array(31);
    case "json":
      return column.jsonRoot === "array" ? "{}" : column.jsonRoot === "object" ? "[]" : "{";
    case "enum":
      return enums.get(column.enumName ?? "") ? 0n : undefined;
    default:
      return undefined;
  }
}

export const planKind = planKindOf;
