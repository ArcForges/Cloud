// SPDX-License-Identifier: AGPL-3.0-only
// CLOUD.75's real Platform-owned bounded read runs through the production Worker plan executor over every numbered migration.
// SQLite proves named SQL and exact result encoding, not the provider's network path, deployment or OS isolation.
import assert from "node:assert/strict";
import test from "node:test";
import { buildManifest, referencedTables } from "../../eng/verification/storage-plans.ts";
import { commitDatabase, execute } from "./support/commit-support.ts";
import { txt } from "./support/plan-calls.ts";
import { repositoryRoot } from "./support/sqlite-d1.ts";

const realm = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const other = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const read = (db: ReturnType<typeof commitDatabase>, id = realm) =>
  execute(db, "platform.recovery-current", [[txt(id)]], "platform");

test("recovery authority has exactly one bounded Platform-owned read and no mutation", () => {
  const plan = buildManifest(repositoryRoot).plans.find(
    (candidate) => candidate.id === "platform.recovery-current",
  );
  assert(plan);
  assert.equal(plan.access, "read");
  assert.equal(plan.maxRows, 1);
  assert.equal(plan.statements.length, 1);
  assert.deepEqual(referencedTables(plan.statements[0].sql, plan.id), ["platform_recovery_epoch"]);
});

test("current authority is realm-scoped, absent is empty, every durable state and version is freshly visible", async () => {
  const db = commitDatabase();
  assert.deepEqual((await read(db)).rows, []);
  db.database.exec(
    `INSERT INTO platform_recovery_epoch VALUES ('${realm}',0,'fixture',zeroblob(32),4,1,1)`,
  );
  assert.deepEqual((await read(db)).rows, [[realm, "0", "4", "1"]]);
  assert.deepEqual((await read(db, other)).rows, []);
  for (const state of [1, 2, 3, 4]) {
    db.database.exec(`UPDATE platform_recovery_epoch SET state=${state}, rev=rev+1`);
    assert.deepEqual((await read(db)).rows, [[realm, "0", String(state), String(state + 1)]]);
  }
  db.database.exec(
    "UPDATE platform_recovery_epoch SET recovery_generation=9223372036854775807, rev=6",
  );
  assert.deepEqual((await read(db)).rows, [[realm, "9223372036854775807", "4", "6"]]);
  db.database.close();
});

test("concurrent read calls are side-effect free and return exact current authority", async () => {
  const db = commitDatabase();
  db.database.exec(
    `INSERT INTO platform_recovery_epoch VALUES ('${realm}',7,'fixture',zeroblob(32),4,1,2)`,
  );
  const outcomes = await Promise.all(Array.from({ length: 12 }, () => read(db)));
  for (const outcome of outcomes) {
    assert.equal(outcome.ok, true);
    assert.deepEqual(outcome.rows, [[realm, "7", "4", "2"]]);
  }
  assert.equal(db.database.prepare("SELECT COUNT(*) AS n FROM platform_command").get()?.n, 0);
  db.database.close();
});
