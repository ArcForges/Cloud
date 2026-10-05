// SPDX-License-Identifier: AGPL-3.0-only
// The exact-value vectors of the physical columns, run through the real Worker bind and result adapters (worker/storage/scalars.ts)
// and a real SQLite column built by the same generator as the production tables. The same vector file drives the C# adapters
// (tests/ArcForges.Cloud.Tests/Physical/ColumnCodecVectorTests.cs), so the host and the Worker agree on every accepted and refused value.
// SQLite is not D1: this proves the SQL, the CHECK expressions and the exact text forms, not Cloudflare's driver.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import path from "node:path";
import test from "node:test";
import type { D1Scalar } from "@arcforges/ai-internal";
import {
  columnCheck,
  enumMap,
  loadManifest,
  planKindOf,
  type PhysicalColumn,
  type PhysicalKind,
} from "../../eng/verification/physical-schema.ts";
import { base64UrlDecode } from "../../worker/private/encoding.ts";
import { bindValue, encodeResult } from "../../worker/storage/scalars.ts";

interface VectorColumn {
  kind: string;
  nullable: boolean;
  enum?: string;
  jsonRoot?: "object" | "array";
}
interface Vector {
  name: string;
  column: VectorColumn;
  value?: Record<string, unknown>;
  scalar: { kind: string; value?: unknown };
  roundTrip: boolean;
  sqlAccepts?: boolean;
  /** Refused by the scalar kind alone; the stored value would be valid. */
  bridgeOnly?: boolean;
}
const file = JSON.parse(
  readFileSync(
    path.resolve(import.meta.dirname, "../ArcForges.Cloud.Tests/Vectors/physical-columns.json"),
    "utf8",
  ),
) as { cases: Vector[]; planKinds: Record<string, string> };

const schema = loadManifest();
const enums = enumMap(schema);
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

function physical(column: VectorColumn): PhysicalColumn {
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

function tableFor(column: PhysicalColumn): DatabaseSync {
  const database = new DatabaseSync(":memory:");
  const check = columnCheck(column, enums);
  database.exec(
    `CREATE TABLE t (id INTEGER NOT NULL PRIMARY KEY, "v" ${column.sqlType}${column.nullable ? "" : " NOT NULL"}${check ? ` CHECK (${check})` : ""}) STRICT`,
  );
  return database;
}

/** What the bridge binds and reads for a column: integers as exact text through CAST, everything else as is. */
function insert(database: DatabaseSync, column: PhysicalColumn, bound: unknown): void {
  const marks = column.sqlType === "INTEGER" ? "CAST(? AS INTEGER)" : "?";
  const value = bound instanceof ArrayBuffer ? new Uint8Array(bound) : bound;
  database.prepare(`INSERT INTO t (id, "v") VALUES (1, ${marks})`).run(value as SQLInputValue);
}

/** The raw value a plan would bind if it skipped the bridge's validation, for refused cases that a CHECK (not a type) must stop. */
function rawValue(vector: Vector, column: PhysicalColumn): SQLInputValue | undefined {
  const scalar = vector.scalar;
  if (scalar.kind === "null") return null;
  if (
    column.sqlType === "TEXT" &&
    (scalar.kind === "text" || scalar.kind === "uint64" || scalar.kind === "decimal")
  )
    return String(scalar.value);
  if (column.sqlType === "BLOB" && scalar.kind === "bytes")
    return base64UrlDecode(String(scalar.value)) ?? undefined;
  if (
    column.sqlType === "INTEGER" &&
    scalar.kind === "int64" &&
    column.kind !== "int64" &&
    column.kind !== "instant"
  ) {
    const text = String(scalar.value);
    if (!/^-?[0-9]+$/u.test(text)) return undefined;
    const value = BigInt(text);
    return value >= -(2n ** 63n) && value < 2n ** 63n ? value : undefined;
  }
  return undefined;
}

function rawInsert(database: DatabaseSync, column: PhysicalColumn, value: SQLInputValue): void {
  void column;
  database.prepare('INSERT INTO t (id, "v") VALUES (1, ?)').run(value);
}

function readBack(database: DatabaseSync, column: PhysicalColumn): unknown {
  // A boolean is read raw (0 or 1); every other integer column is read as exact text.
  const select =
    column.sqlType === "INTEGER" && column.kind !== "bool" ? 'CAST("v" AS TEXT)' : '"v"';
  const statement = database.prepare(`SELECT ${select} FROM t`);
  statement.setReturnArrays(true);
  return (statement.all() as unknown as unknown[][])[0]?.[0];
}

const kindOfPlan = (column: PhysicalColumn) =>
  ({ kind: planKindOf(column.kind), nullable: column.nullable }) as Parameters<typeof bindValue>[1];

test("every vector kind maps to the plan kind the C# adapter uses", () => {
  const kinds = new Set(file.cases.map((entry) => entry.column.kind));
  for (const kind of kinds)
    assert.equal(planKindOf(kind as PhysicalKind), file.planKinds[kind], kind);
  assert.deepEqual([...kinds].sort(), Object.keys(file.planKinds).sort());
});

for (const vector of file.cases) {
  test(`physical column vector: ${vector.name}`, () => {
    const column = physical(vector.column);
    const database = tableFor(column);
    const param = kindOfPlan(column);
    const scalar = vector.scalar as unknown as D1Scalar;
    const bound = bindValue(scalar, param, "scope");
    if (vector.roundTrip) {
      assert(bound.ok, "the bridge must accept the scalar");
      insert(database, column, bound.value);
      const stored = readBack(database, column);
      // Read it back as the Worker does: integers as text, bytes as bytes, text as is.
      const result = encodeResult(
        column.sqlType === "BLOB" ? (stored instanceof Uint8Array ? stored : null) : stored,
        param,
      );
      assert.deepEqual(result, scalar);
      return;
    }
    // A refused value is refused by the bridge's bind validation or, past it, by the column's own CHECK.
    if (vector.sqlAccepts) {
      assert(bound.ok, "this value passes the bridge and the database; only the host refuses it");
      insert(database, column, bound.value);
      return;
    }
    if (bound.ok)
      assert.throws(
        () => insert(database, column, bound.value),
        /CHECK constraint failed|NOT NULL constraint failed|cannot store/u,
      );
    // Past the bridge: the column's own CHECK must refuse the raw value too, so a plan that bypassed validation still cannot store it.
    const raw = vector.bridgeOnly ? undefined : rawValue(vector, column);
    if (raw !== undefined)
      assert.throws(
        () => rawInsert(database, column, raw),
        /CHECK constraint failed|NOT NULL constraint failed|cannot store/u,
        "the database accepted a value it must refuse",
      );
  });
}

test("SQLite saturates an out-of-range integer CAST, so the bridge range check is the guard for 64-bit columns", () => {
  const database = new DatabaseSync(":memory:");
  const row = database
    .prepare("SELECT CAST(CAST('9223372036854775808' AS INTEGER) AS TEXT) AS v")
    .get() as { v: string };
  assert.equal(
    BigInt(row.v),
    9223372036854775807n,
    "documented SQLite behaviour that makes unchecked text unsafe",
  );
  const column = physical({ kind: "int64", nullable: false });
  assert.equal(
    bindValue(
      { kind: "int64", value: "9223372036854775808" } as D1Scalar,
      kindOfPlan(column),
      "scope",
    ).ok,
    false,
  );
});

test("a JavaScript number cannot hold the values an int64 column stores: the exact text path is the only safe read", () => {
  assert.notEqual(BigInt(Number("9007199254740993")), 9007199254740993n);
  const database = new DatabaseSync(":memory:");
  database.exec("CREATE TABLE t (v INTEGER NOT NULL) STRICT");
  database.prepare("INSERT INTO t VALUES (CAST(? AS INTEGER))").run("9007199254740993");
  const raw = database.prepare("SELECT CAST(v AS TEXT) AS v FROM t").get() as { v: string };
  assert.equal(raw.v, "9007199254740993");
  assert.deepEqual(encodeResult(raw.v, { kind: "int64", nullable: false }), {
    kind: "int64",
    value: "9007199254740993",
  });
  // An integer that arrives as a number is refused by the result adapter.
  assert.throws(() => encodeResult(9007199254740992, { kind: "int64", nullable: false }));
});

test("canonical decimal and uint64 text ordering is not numeric: the sort key is what SQL may order by", () => {
  assert("10" < "9", "text order differs from numeric order");
  assert("-1" < "-2", "...and for negative values, where the order is reversed");
});

test("base64url bytes decode exactly for every byte value", () => {
  const every = Uint8Array.from({ length: 256 }, (_, index) => index);
  const text = Buffer.from(every).toString("base64url");
  assert.deepEqual(base64UrlDecode(text), every);
});
