// SPDX-License-Identifier: AGPL-3.0-only
// Order-preserving sort keys and the compatible-rollback rule, against SQLite and the shared vector files that also pin the C# side
// (SortKeyTests.cs, SchemaCompatibilityTests.cs).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { compatibility } from "../../eng/migrations/runner.ts";

const dir = path.resolve(import.meta.dirname, "../ArcForges.Cloud.Tests/Vectors");
const keys = JSON.parse(
  readFileSync(path.join(dir, "physical-order-bytes.json"), "utf8"),
) as Record<string, { value: string; orderHex: string }[]>;
const rule = JSON.parse(readFileSync(path.join(dir, "physical-compatibility.json"), "utf8")) as {
  cases: {
    state: { schemaVersion: number; readHorizon: number; writeHorizon: number };
    application: number;
    expected: { canRead: boolean; canWrite: boolean; reason: string };
  }[];
};

for (const kind of ["uint64", "int64", "decimal"]) {
  test(`${kind} sort keys are strictly ascending as unsigned bytes, in SQLite as well, where the canonical text is not`, () => {
    const list = keys[kind] as { value: string; orderHex: string }[];
    const db = new DatabaseSync(":memory:");
    db.exec(
      "CREATE TABLE k (n INTEGER NOT NULL PRIMARY KEY, key BLOB NOT NULL, text TEXT NOT NULL) STRICT",
    );
    // Insert in reverse so that insertion order cannot explain the result.
    for (const [index, entry] of [...list].reverse().entries())
      db.prepare("INSERT INTO k VALUES (?, ?, ?)").run(
        index,
        Buffer.from(entry.orderHex, "hex"),
        entry.value,
      );
    const ordered = db.prepare("SELECT text FROM k ORDER BY key").all() as { text: string }[];
    assert.deepEqual(
      ordered.map((row) => row.text),
      list.map((entry) => entry.value),
    );
    for (let index = 1; index < list.length; index++)
      assert(
        Buffer.compare(
          Buffer.from((list[index - 1] as { orderHex: string }).orderHex, "hex"),
          Buffer.from((list[index] as { orderHex: string }).orderHex, "hex"),
        ) < 0,
        `${list[index - 1]?.value} < ${list[index]?.value}`,
      );
    if (kind !== "int64") {
      const byText = db.prepare("SELECT text FROM k ORDER BY text").all() as { text: string }[];
      assert.notDeepEqual(
        byText.map((row) => row.text),
        list.map((entry) => entry.value),
        "the canonical text order differs from the numeric order",
      );
    }
  });
}

test("the compatible-rollback rule agrees with the shared vectors", () => {
  assert(rule.cases.length > 20);
  for (const entry of rule.cases)
    assert.deepEqual(
      compatibility(entry.state, { schemaVersion: entry.application }),
      entry.expected,
      JSON.stringify(entry),
    );
});
