// SPDX-License-Identifier: AGPL-3.0-only
// Module persistence ownership (Design CM-01 to CM-03) at the only place SQL enters the Worker dictionary:
// a plan of one owner can never name another owner's table: every table position is either a plain table name that
// is checked against the owner, or an allow-listed construct, or the plan is refused.
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import test from "node:test";
import {
  assertOwnership,
  buildManifest,
  fromEnders,
  ownerRegistry,
  parseOwnerRegistry,
  parsePlanFile,
  referencedTables,
  renderCSharp,
} from "../../eng/verification/storage-plans.ts";
import { repositoryRoot } from "./support/sqlite-d1.ts";

const registry = () =>
  parseOwnerRegistry(readFileSync(path.join(repositoryRoot, ownerRegistry), "utf8"));
const header = (id: string, access = "write") =>
  `-- plan: ${id}\n-- version: 1\n-- access: ${access}\n`;
const plan = (id: string, sql: string) =>
  parsePlanFile(
    `${header(id)}-- statement: params=scope\n${sql}\n`,
    `storage/plans/${id.replace(".", "/")}.sql`,
  );

test("the owner registry lists the nineteen module owners, the shared platform and the proof owner", () => {
  const owners = registry().owners;
  assert.equal(owners.filter((entry) => entry.kind === "module").length, 19);
  assert.deepEqual(
    owners.filter((entry) => entry.kind !== "module").map((entry) => entry.owner),
    ["platform", "foundation"],
  );
  for (const entry of owners.filter((candidate) => candidate.kind === "module"))
    assert.equal(entry.tablePrefix, `${entry.owner.replaceAll("-", "_")}_`);
  // A CTE name must start with cte_, so no owner prefix may: a CTE can never stand in for an owned table.
  for (const entry of owners) assert(!entry.tablePrefix.startsWith("cte_"), entry.owner);
});

test("a malformed owner registry is refused", () => {
  const good = JSON.parse(readFileSync(path.join(repositoryRoot, ownerRegistry), "utf8")) as {
    schemaVersion: number;
    owners: Record<string, string>[];
  };
  const refused: [string, (value: typeof good) => void, RegExp][] = [
    [
      "schema version",
      (value) => void Object.assign(value, { schemaVersion: 2 }),
      /schemaVersion/u,
    ],
    [
      "duplicate owner",
      (value) => void Object.assign(value.owners[1] ?? {}, { owner: "identity" }),
      /duplicate owner/u,
    ],
    [
      "duplicate class",
      (value) => void Object.assign(value.owners[1] ?? {}, { className: "Identity" }),
      /duplicate class/u,
    ],
    [
      "duplicate prefix",
      (value) => void Object.assign(value.owners[1] ?? {}, { tablePrefix: "identity_" }),
      /duplicate table prefix/u,
    ],
    [
      "module prefix that is not its schema",
      (value) => void Object.assign(value.owners[1] ?? {}, { tablePrefix: "ws_" }),
      /is its schema/u,
    ],
    [
      "a prefix that contains another",
      (value) =>
        void value.owners.push(
          { owner: "form", className: "Form", kind: "module", tablePrefix: "form_" },
          { owner: "form-a", className: "FormA", kind: "module", tablePrefix: "form_a_" },
        ),
      /contains/u,
    ],
    [
      "unknown field",
      (value) => void Object.assign(value.owners[0] ?? {}, { extra: "x" }),
      /fields of/u,
    ],
    [
      "unknown kind",
      (value) => void Object.assign(value.owners[0] ?? {}, { kind: "other" }),
      /kind of/u,
    ],
    [
      "bad owner name",
      (value) => void Object.assign(value.owners[0] ?? {}, { owner: "Identity" }),
      /invalid owner/u,
    ],
    [
      "second platform",
      (value) =>
        void value.owners.push({
          owner: "platform",
          className: "Platform2",
          kind: "platform",
          tablePrefix: "platform_",
        }),
      /duplicate/u,
    ],
  ];
  for (const [label, mutate, pattern] of refused) {
    const value = structuredClone(good);
    mutate(value);
    assert.throws(() => parseOwnerRegistry(JSON.stringify(value)), pattern, label);
  }
});

test("table references are found through every statement form and hidden ones are refused", () => {
  const tables = (sql: string) => referencedTables(sql, "t");
  assert.deepEqual(tables("SELECT a FROM chat_message WHERE b = ?;"), ["chat_message"]);
  assert.deepEqual(tables("INSERT INTO chat_message (a, b) VALUES (?, ?);"), ["chat_message"]);
  assert.deepEqual(tables("UPDATE chat_message SET a = ? WHERE b = ?;"), ["chat_message"]);
  assert.deepEqual(tables("DELETE FROM chat_message WHERE a = ?;"), ["chat_message"]);
  assert.deepEqual(
    tables("INSERT OR IGNORE INTO chat_message (a) SELECT a FROM platform_outbox;"),
    ["chat_message", "platform_outbox"],
  );
  assert.deepEqual(
    tables(
      "SELECT a FROM chat_message m JOIN platform_command c ON c.id = m.id LEFT JOIN task_x t ON 1;",
    ),
    ["chat_message", "platform_command", "task_x"],
  );
  // CTE names and table-valued functions are not tables, and an upsert names no second table.
  assert.deepEqual(
    tables(
      "WITH cte_r AS (SELECT a FROM chat_message), cte_s(x) AS MATERIALIZED (SELECT 1) SELECT a FROM cte_r JOIN json_each(?) ON 1;",
    ),
    ["chat_message"],
  );
  assert.deepEqual(
    tables("INSERT INTO chat_message (a) VALUES (?) ON CONFLICT (a) DO UPDATE SET a = excluded.a;"),
    ["chat_message"],
  );
  assert.deepEqual(tables("SELECT a IS NOT DISTINCT FROM b FROM chat_message;"), ["chat_message"]);
  // A string literal cannot hide or fake a table.
  assert.deepEqual(tables("SELECT 'FROM other_table' FROM chat_message;"), ["chat_message"]);
  const hidden: [string, string, RegExp][] = [
    ["quoted identifier", 'SELECT a FROM "identity_user";', /quoted identifiers/u],
    ["backtick identifier", "SELECT a FROM `identity_user`;", /quoted identifiers/u],
    ["bracket identifier", "SELECT a FROM [identity_user];", /quoted identifiers/u],
    ["schema qualification", "SELECT a FROM main.identity_user;", /schema-qualified/u],
    ["temp schema", "INSERT INTO temp.x (a) VALUES (?);", /schema-qualified/u],
    ["comma join", "SELECT a FROM chat_message, identity_user;", /comma join/u],
    ["comma join with alias", "SELECT a FROM chat_message m, identity_user u;", /comma join/u],
    ["unknown table function", "SELECT a FROM pragma_table_info(?);", /table-valued function/u],
  ];
  for (const [label, sql, pattern] of hidden) assert.throws(() => tables(sql), pattern, label);
});

// Each statement below is accepted by SQLite (node:sqlite is the oracle) and reaches the foreign table `secret_t`. The
// check must refuse it, or report the table so that the ownership rule refuses it. Comments, case, tabs, newlines and
// non-ASCII text must not change that.
test("every accepted spelling of a foreign table is refused (SQLite is the oracle)", () => {
  const database = new DatabaseSync(":memory:");
  database.exec(
    "CREATE TABLE secret_t (a, b); CREATE TABLE chat_message (a, b); CREATE TABLE platform_outbox (a, b);",
  );
  const bypasses: [string, string][] = [
    ["single-quoted FROM", "SELECT a FROM 'secret_t';"],
    ["single-quoted JOIN", "SELECT m.a FROM chat_message m JOIN 'secret_t' s ON 1;"],
    ["single-quoted INSERT INTO", "INSERT INTO 'secret_t' (a) VALUES (?);"],
    ["single-quoted UPDATE", "UPDATE 'secret_t' SET a = ?;"],
    ["single-quoted DELETE", "DELETE FROM 'secret_t';"],
    [
      "comma join after a JOIN",
      "SELECT 1 FROM chat_message m JOIN platform_outbox o ON 1, secret_t;",
    ],
    ["comma join after a subquery", "SELECT 1 FROM (SELECT a FROM chat_message), secret_t;"],
    ["comma join after json_each", "SELECT 1 FROM json_each(?), secret_t;"],
    ["comma join after an alias", "SELECT 1 FROM chat_message AS m, secret_t AS s;"],
    ["parenthesised FROM", "SELECT a FROM (secret_t);"],
    ["parenthesised JOIN", "SELECT 1 FROM chat_message m JOIN (secret_t) ON 1;"],
    ["doubly parenthesised", "SELECT a FROM ((secret_t));"],
    ["unscoped CTE name collision", "WITH secret_t AS (SELECT 1 AS a) SELECT a FROM secret_t;"],
    [
      "CTE name collision through a window name",
      "SELECT sum(a) OVER secret_t FROM secret_t WINDOW secret_t AS (ORDER BY a);",
    ],
    [
      "CTE declared after use",
      "SELECT 1 FROM secret_t, (WITH secret_t AS (SELECT 1 AS a) SELECT a FROM secret_t);",
    ],
    ["mixed case", "sElEcT a fRoM Secret_T;"],
    ["tabs and newlines", "SELECT\ta\nFROM\r\n\t'secret_t'\t;"],
    ["block comment between tokens", "SELECT a FROM/**/secret_t;"],
    ["line comment between tokens", "SELECT a FROM -- note\nsecret_t;"],
    ["comment before a comma join", "SELECT 1 FROM chat_message/**/,/**/secret_t;"],
  ];
  for (const [label, sql] of bypasses) {
    // The oracle accepts it (the placeholders are bound where there are any).
    assert(database.prepare(sql), `${label}: SQLite accepts the statement`);
    let verdict: string[] | "refused";
    try {
      verdict = referencedTables(sql, label).map((table) => table.toLowerCase());
    } catch {
      verdict = "refused";
    }
    assert(
      verdict === "refused" || verdict.includes("secret_t"),
      `${label}: neither refused nor reported (${JSON.stringify(verdict)})`,
    );
  }
  // The same statements are refused by the ownership rule itself, whichever way the check answered.
  for (const [label, sql] of bypasses)
    assert.throws(
      () =>
        assertOwnership(
          {
            id: "chat.bypass",
            version: 1,
            access: "write",
            maxRows: 0,
            statements: [{ sql, params: [], returns: null }],
            sha256: "",
          },
          registry(),
        ),
      Error,
      label,
    );
});

test("unaccounted table positions are refused, and constructs plans use stay accepted", () => {
  const tables = (sql: string) => referencedTables(sql, "t");
  const refused: [string, string, RegExp][] = [
    ["number in a table position", "SELECT a FROM 1;", /plain table name/u],
    ["keyword in a table position", "SELECT a FROM select;", /plain table name/u],
    ["nothing after FROM", "SELECT a FROM", /plain table name/u],
    ["CTE not starting with the reserved prefix", "WITH r AS (SELECT 1) SELECT 1 FROM r;", /cte_/u],
    [
      "CTE as a write target",
      "WITH cte_r AS (SELECT 1) INSERT INTO cte_r (a) VALUES (1);",
      /not a write target/u,
    ],
    ["CTE without AS", "WITH cte_r (SELECT 1) SELECT 1;", /defined with AS/u],
    ["unterminated string", "SELECT a FROM chat_message WHERE a = 'x;", /unterminated string/u],
    ["unterminated comment", "SELECT a FROM chat_message /* x;", /unterminated comment/u],
    ["unbalanced parenthesis", "SELECT a FROM (SELECT a FROM chat_message;", /unbalanced/u],
    ["update with a column list", "UPDATE chat_message (a) SET a = 1;", /not followed by a list/u],
    [
      "subquery comma join",
      "SELECT 1 WHERE a IN (SELECT a FROM chat_message, secret_t);",
      /comma join/u,
    ],
  ];
  for (const [label, sql, pattern] of refused) assert.throws(() => tables(sql), pattern, label);
  // A non-ASCII spelling is its own table for SQLite: it is reported as written and refused by the owner prefix.
  assert.deepEqual(tables("SELECT a FROM ſecret_t;"), ["ſecret_t"]);
  assert.throws(
    () =>
      assertOwnership(
        plan("chat.unicode", "UPDATE ſecret_t SET a = 1 WHERE scope = ?;"),
        registry(),
      ),
    /not owned by chat/u,
  );
  assert.deepEqual(tables("SELECT a FROM chat_message ORDER BY a, b LIMIT ?, ?;"), [
    "chat_message",
  ]);
  assert.deepEqual(tables("SELECT 1 FROM chat_message GROUP BY a, b HAVING count(*) > 1;"), [
    "chat_message",
  ]);
  assert.deepEqual(
    tables(
      "INSERT INTO chat_message (a, b) SELECT value, 2 FROM json_each(?) ON CONFLICT (a, b) DO UPDATE SET a = excluded.a, b = excluded.b;",
    ),
    ["chat_message"],
  );
  assert.deepEqual(
    tables(
      "UPDATE chat_message SET a = ?, b = (SELECT x FROM platform_outbox WHERE y = ?) WHERE c = ?;",
    ),
    ["chat_message", "platform_outbox"],
  );
  assert.deepEqual(tables("SELECT 'a, b' FROM chat_message WHERE b = 'JOIN x';"), ["chat_message"]);
  assert.deepEqual(tables("SELECT a FROM chat_message AS m /* c */ WHERE a = 1;"), [
    "chat_message",
  ]);
});

// The guard against comma joins must not depend on a word list that SQLite itself lets a plan use as a name. The words
// below are the clause enders of the check plus every word SQLite accepts as an identifier through its fallback rules
// (and a few ordinary clause words); each is tried as a table alias and as a column name, and whatever SQLite accepts
// must be refused or must report the foreign table.
test("no word that SQLite accepts as a name can reset the comma-join guard (SQLite is the oracle)", () => {
  const database = new DatabaseSync(":memory:");
  database.exec(
    "CREATE TABLE secret_t (a, b); CREATE TABLE identity_u (a, b, key, do, conflict, window, filter, over, replace, abort, action, after, asc, desc, end, fail, ignore, match, no, of, offset, plan, query, row, rows, temp, view, virtual, within, first, last, nulls, current, following, partition, preceding, range, unbounded, exclude, groups, others, ties, generated, always, materialized, rename, restrict, cascade, by, cast, database, deferred, each, exclusive, explain, for, immediate, initially, instead, raise, recursive, release, rollback, savepoint, trigger, vacuum, without, analyze, attach, before, begin, detach, pragma); CREATE TABLE platform_r (a, b);",
  );
  const accepted = (sql: string) => {
    try {
      database.prepare(sql);
      return true;
    } catch {
      return false;
    }
  };
  const verdict = (sql: string) => {
    try {
      return referencedTables(sql, sql).includes("secret_t") ? "reported" : "missed";
    } catch {
      return "refused";
    }
  };
  const words = [
    ...fromEnders,
    "do",
    "conflict",
    "window",
    "key",
    "filter",
    "over",
    "replace",
    "abort",
    "action",
    "after",
    "asc",
    "desc",
    "end",
    "fail",
    "ignore",
    "match",
    "no",
    "of",
    "offset",
    "plan",
    "query",
    "row",
    "rows",
    "temp",
    "view",
    "virtual",
    "within",
    "first",
    "last",
    "nulls",
    "current",
    "following",
    "partition",
    "preceding",
    "range",
    "unbounded",
    "exclude",
    "groups",
    "others",
    "ties",
    "generated",
    "always",
    "materialized",
    "rename",
    "restrict",
    "cascade",
    "by",
    "cast",
    "database",
    "deferred",
    "each",
    "exclusive",
    "explain",
    "for",
    "immediate",
    "initially",
    "instead",
    "raise",
    "recursive",
    "release",
    "rollback",
    "savepoint",
    "trigger",
    "vacuum",
    "without",
    "analyze",
    "attach",
    "before",
    "begin",
    "detach",
    "pragma",
    "left",
    "inner",
    "cross",
    "natural",
    "outer",
    "with",
    "not",
    "like",
    "glob",
    "regexp",
    "escape",
    "values",
  ];
  const shapes: ((word: string) => string)[] = [
    (word) => `SELECT 1 FROM identity_u ${word}, secret_t`,
    (word) => `SELECT 1 FROM identity_u AS ${word}, secret_t`,
    (word) => `SELECT 1 FROM identity_u a JOIN platform_r p ON a.${word} = 1, secret_t`,
    (word) => `SELECT 1 FROM identity_u AS ${word} JOIN platform_r p ON ${word}.a = 1, secret_t`,
    (word) => `SELECT 1 FROM identity_u a JOIN platform_r p ON p.a = a.${word} WHERE 1, secret_t`,
  ];
  let accepting = 0;
  for (const word of words)
    for (const shape of shapes) {
      const sql = shape(word);
      if (!accepted(sql)) continue;
      accepting++;
      assert.notEqual(verdict(sql), "missed", sql);
    }
  assert(accepting > 30, `the oracle accepted only ${accepting} statements`);
  // The four statements and the AS variants of the review, spelled out.
  for (const sql of [
    "SELECT 1 FROM identity_u do, secret_t",
    "SELECT 1 FROM identity_u AS conflict, secret_t",
    "SELECT 1 FROM identity_u window, secret_t",
    "SELECT 1 FROM identity_u a JOIN platform_r p ON a.conflict = 1, secret_t",
    "SELECT 1 FROM identity_u a JOIN platform_r p ON a.do = 1, secret_t",
    "SELECT 1 FROM identity_u AS window, secret_t",
    "SELECT 1 FROM identity_u AS do, secret_t",
  ]) {
    assert(accepted(sql), `SQLite accepts: ${sql}`);
    assert.equal(verdict(sql), "refused", sql);
  }
  // A clause ender is a reserved word: SQLite refuses it as an alias and as a column, so it can only start a clause.
  for (const word of fromEnders) {
    assert(!accepted(`SELECT 1 FROM identity_u AS ${word}`), `${word} is accepted as an alias`);
    assert(
      !accepted(`SELECT 1 FROM identity_u ${word}`) || word === "where",
      `${word} is accepted as an alias`,
    );
    assert(!accepted(`SELECT ${word} FROM identity_u`), `${word} is accepted as a column`);
  }
});

test("a plan may touch its own tables and the shared platform tables only", () => {
  assertOwnership(
    plan("chat.own", "INSERT INTO chat_message (a) SELECT a FROM chat_draft WHERE scope = ?;"),
    registry(),
  );
  assertOwnership(
    plan(
      "chat.shared",
      "INSERT INTO platform_outbox (a) SELECT a FROM chat_draft WHERE scope = ?;",
    ),
    registry(),
  );
  const foreign: [string, string][] = [
    ["UPDATE chat_message SET a = (SELECT a FROM identity_user WHERE scope = ?);", "identity_user"],
    ["INSERT INTO sync_change (a) VALUES (?);", "sync_change"],
    ["DELETE FROM task_item WHERE scope = ?;", "task_item"],
    // A name that merely starts like the owner's prefix is not the owner's table.
    ["UPDATE chatty_draft SET a = 1 WHERE scope = ?;", "chatty_draft"],
    ["UPDATE chat SET a = 1 WHERE scope = ?;", "chat"],
  ];
  for (const [sql, table] of foreign)
    assert.throws(
      () => assertOwnership(plan("chat.foreign", sql), registry()),
      new RegExp(`table ${table} is not owned by chat`, "u"),
      sql,
    );
  assert.throws(
    () =>
      assertOwnership(
        plan("platform.sample", "DELETE FROM chat_message WHERE scope = ?;"),
        registry(),
      ),
    /not owned by platform/u,
  );
  assert.throws(
    () =>
      assertOwnership(
        plan("foundation.sample", "DELETE FROM platform_outbox WHERE scope = ?;"),
        registry(),
      ),
    /not owned by foundation/u,
  );
  assert.throws(
    () =>
      assertOwnership(plan("unknown.sample", "DELETE FROM unknown_x WHERE scope = ?;"), registry()),
    /not in storage\/plans\/owners\.json/u,
  );
});

test("the manifest builder refuses an unregistered owner directory, a foreign root file and a foreign table", () => {
  const root = mkdtempSync(path.join(tmpdir(), "plans-"));
  const sample = `${header("foundation.sample")}-- statement: params=scope\nDELETE FROM probe_t WHERE scope = ?;\n`;
  try {
    mkdirSync(path.join(root, "storage/plans/foundation"), { recursive: true });
    cpSync(path.join(repositoryRoot, ownerRegistry), path.join(root, ownerRegistry));
    writeFileSync(path.join(root, "storage/plans/foundation/sample.sql"), sample);
    assert.equal(buildManifest(root).plans.length, 1);
    mkdirSync(path.join(root, "storage/plans/stranger"));
    assert.throws(() => buildManifest(root), /not an owner/u);
    rmSync(path.join(root, "storage/plans/stranger"), { recursive: true });
    writeFileSync(path.join(root, "storage/plans/notes.md"), "x");
    assert.throws(() => buildManifest(root), /foreign file/u);
    rmSync(path.join(root, "storage/plans/notes.md"));
    writeFileSync(
      path.join(root, "storage/plans/foundation/sample.sql"),
      sample.replace("probe_t", "identity_user"),
    );
    assert.throws(() => buildManifest(root), /not owned by foundation/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("plans of different owners may share a name without clashing in the C# definitions", () => {
  const root = mkdtempSync(path.join(tmpdir(), "plans-"));
  try {
    mkdirSync(path.join(root, "storage/plans"), { recursive: true });
    cpSync(path.join(repositoryRoot, ownerRegistry), path.join(root, ownerRegistry));
    for (const owner of ["chat", "task"]) {
      mkdirSync(path.join(root, "storage/plans", owner));
      writeFileSync(
        path.join(root, "storage/plans", owner, "get.sql"),
        `${header(`${owner}.get`, "read")}-- maxRows: 1\n-- statement: params=scope returns=int64\nSELECT CAST(a AS TEXT) FROM ${owner}_x WHERE scope = ?;\n`,
      );
    }
    const source = renderCSharp(buildManifest(root));
    assert.match(
      source,
      /internal static class Chat\b[\s\S]*PlanDefinition Get = new\(\s*"chat\.get"/u,
    );
    assert.match(
      source,
      /internal static class Task\b[\s\S]*PlanDefinition Get = new\(\s*"task\.get"/u,
    );
    assert.match(source, /All = \[Chat\.Get, Task\.Get\]/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("every checked-in plan satisfies the ownership rule of its owner directory", () => {
  const manifest = buildManifest(repositoryRoot);
  // A shared family plan is not an owner plan: the family grammar checks it statement by statement (docs/shared-families.md).
  const owned = manifest.plans.filter((entry) => entry.family === undefined);
  for (const definition of owned) assertOwnership(definition, manifest.registry);
  assert.deepEqual(
    [...new Set(owned.map((entry) => entry.id.split(".")[0]))],
    ["entitlement", "foundation", "identity", "platform"],
  );
  assert.deepEqual(
    manifest.plans.filter((entry) => entry.family !== undefined).map((entry) => entry.id),
    ["families.account-enrollment.create-user"],
  );
});
