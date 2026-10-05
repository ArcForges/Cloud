// SPDX-License-Identifier: AGPL-3.0-only
// No module write plan writes a table that only the commit tail may write, whatever its header says and however the statement is spelled.
// The write targets come from the generator's own tokenizer, so these variants (found by review against a first, anchored implementation)
// are all seen.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { reservedTables } from "../../eng/verification/commit-tail.ts";
import { buildManifest, writeTargets } from "../../eng/verification/storage-plans.ts";
import { fixturePlanText } from "./support/commit-support.ts";
import { repositoryRoot } from "./support/sqlite-d1.ts";

function withRoot(file: string, content: string, run: (root: string) => void) {
  const root = mkdtempSync(path.join(tmpdir(), "commit-writes-"));
  try {
    mkdirSync(path.join(root, "storage/plans/entitlement"), { recursive: true });
    writeFileSync(
      path.join(root, "storage/plans/owners.json"),
      readFileSync(path.join(repositoryRoot, "storage/plans/owners.json")),
    );
    writeFileSync(path.join(root, "storage/plans", file), content);
    run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const variants: [string, string, string][] = [
  ["plain insert", "INSERT INTO platform_command (command_id) VALUES (?)", "platform_command"],
  ["lower case", "insert into platform_command (command_id) values (?)", "platform_command"],
  [
    "mixed case and spacing",
    "InSeRt   \n INTO\tplatform_sequence_stream (stream_key) VALUES (?)",
    "platform_sequence_stream",
  ],
  [
    "a block comment",
    "INSERT /* x */ INTO platform_outbox_position (outbox_id) VALUES (?)",
    "platform_outbox_position",
  ],
  [
    "a line comment",
    "INSERT INTO -- hide\n platform_change_archive (command_id) VALUES (?)",
    "platform_change_archive",
  ],
  [
    "OR REPLACE",
    "INSERT OR REPLACE INTO platform_command (command_id) VALUES (?)",
    "platform_command",
  ],
  ["REPLACE INTO", "REPLACE INTO platform_inbox (source) VALUES (?)", "platform_inbox"],
  ["OR IGNORE", "INSERT OR IGNORE INTO platform_outbox (outbox_id) VALUES (?)", "platform_outbox"],
  [
    "update",
    "UPDATE platform_sequence_stream SET last_sequence = last_sequence + 5 WHERE stream_key = ?",
    "platform_sequence_stream",
  ],
  [
    "update or replace",
    "UPDATE OR REPLACE platform_command SET status = 2 WHERE command_id = ?",
    "platform_command",
  ],
  [
    "delete",
    "DELETE FROM platform_outbox_position WHERE outbox_id = ?",
    "platform_outbox_position",
  ],
  [
    "upsert into a tail table",
    "INSERT INTO platform_sequence_stream (stream_key) VALUES (?) ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 9",
    "platform_sequence_stream",
  ],
  [
    "a CTE-led insert",
    "WITH cte_a AS (SELECT 1) INSERT INTO platform_outbox_position (outbox_id) SELECT ? FROM cte_a",
    "platform_outbox_position",
  ],
  [
    "a nested CTE",
    "WITH cte_a AS (WITH cte_b AS (SELECT 1) SELECT * FROM cte_b) INSERT INTO platform_command (command_id) SELECT ? FROM cte_a",
    "platform_command",
  ],
  [
    "a CTE-led update",
    "WITH cte_a AS (SELECT 1) UPDATE platform_sequence_stream SET fence = 9 WHERE stream_key = ?",
    "platform_sequence_stream",
  ],
  [
    "a CTE-led delete",
    "WITH cte_a AS (SELECT 1) DELETE FROM platform_change_archive WHERE archive_sequence = ?",
    "platform_change_archive",
  ],
];

test("the write targets of a statement come from the generator's tokenizer, in every spelling", () => {
  for (const [name, sql, table] of variants)
    assert(writeTargets(sql, name).includes(table), `${name}: ${table} is a write target`);
  assert.deepEqual(writeTargets("SELECT * FROM platform_command", "read"), []);
  assert.deepEqual(
    writeTargets("INSERT INTO entitlement_fixture_item SELECT * FROM platform_command", "copy"),
    ["entitlement_fixture_item"],
  );
});

test("no module write plan writes a tail table, with a declared tail or with none", () => {
  for (const [name, sql] of variants) {
    const params = Array.from({ length: (sql.match(/[?]/gu) ?? []).length }, () => "text").join(
      ",",
    );
    const statement = `-- statement: params=${params}\n${sql};\n`;
    // A declared tail: the statement sits among the owner statements, before the canonical tail.
    const base = fixturePlanText("forged", { events: 1, inbox: false });
    const marker = "-- statement: params=text,text?,text,text,text,text,int64,int64,int64";
    assert(base.includes(marker));
    withRoot("entitlement/forged.sql", base.replace(marker, `${statement}${marker}`), (root) =>
      assert.throws(
        () => buildManifest(root),
        /only the commit tail may write|comments are not allowed|forbidden SQL/u,
        `declared tail: ${name}`,
      ),
    );
    // No tail: the same statement in a 'none' plan.
    const none = `-- plan: entitlement.forged
-- version: 1
-- access: write
-- tail: none a plan that must not write the tail tables
${statement}`;
    withRoot("entitlement/forged.sql", none, (root) =>
      assert.throws(
        () => buildManifest(root),
        /only the commit tail may write|comments are not allowed|forbidden SQL/u,
        `none: ${name}`,
      ),
    );
  }
});

test("reading a tail table inside a write plan is not a write", () => {
  const none = `-- plan: entitlement.reader
-- version: 1
-- access: write
-- tail: none the fixture copies an id from a receipt it reads
-- statement: params=scope,text
INSERT INTO entitlement_fixture_item (scope, id, revision, value) SELECT ?, command_id, 1, 'x' FROM platform_command WHERE command_id = ?;
`;
  withRoot("entitlement/reader.sql", none, (root) =>
    assert.doesNotThrow(() => buildManifest(root)),
  );
});

test("the reserved tables are exactly the six the tail writes", () => {
  assert.deepEqual([...reservedTables].sort(), [
    "platform_change_archive",
    "platform_command",
    "platform_inbox",
    "platform_outbox",
    "platform_outbox_position",
    "platform_sequence_stream",
  ]);
});
