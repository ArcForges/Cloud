// SPDX-License-Identifier: AGPL-3.0-only
// The plan generator is the only way SQL reaches the Worker dictionary and the C# definitions.
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  buildManifest,
  generate,
  manifestHashOf,
  normalizePlanText,
  ownerRegistry,
  parsePlanFile,
} from "../../eng/verification/storage-plans.ts";
import { manifestHash, plans } from "../../worker/storage/plans.generated.ts";
import { repositoryRoot } from "./support/sqlite-d1.ts";

const file = "storage/plans/foundation/sample.sql";
const read = `-- plan: foundation.sample
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope,int64,text returns=int64,text?
SELECT CAST(a AS TEXT), b FROM t WHERE scope = ? AND a = CAST(? AS INTEGER) AND b = ?;
`;
const write = `-- plan: foundation.sample
-- version: 2
-- access: write
-- statement: params=int64,scope
UPDATE t SET a = CAST(? AS INTEGER) WHERE scope = ?;
`;

test("a valid read plan parses into typed parameters and results", () => {
  const plan = parsePlanFile(read, file);
  assert.equal(plan.id, "foundation.sample");
  assert.equal(plan.access, "read");
  assert.deepEqual(plan.statements[0]?.params, [
    { kind: "scope", nullable: false },
    { kind: "int64", nullable: false },
    { kind: "text", nullable: false },
  ]);
  assert.deepEqual(plan.statements[0]?.returns, [
    { kind: "int64", nullable: false },
    { kind: "text", nullable: true },
  ]);
});

test("every rule of the plan format is enforced", () => {
  const refused: [string, string, RegExp][] = [
    [
      "comment inside a statement",
      read.replace("WHERE", "-- note\nWHERE"),
      /comments|unknown comment/u,
    ],
    ["two statements in one block", read.replace(";\n", "; SELECT 1;\n"), /exactly one statement/u],
    ["DDL", read.replace("SELECT", "CREATE TABLE x AS SELECT"), /forbidden SQL|only DML/u],
    [
      "PRAGMA",
      read.replace("SELECT CAST", "PRAGMA foreign_keys; SELECT CAST"),
      /forbidden SQL|exactly one/u,
    ],
    ["RETURNING", write.replace(";", " RETURNING a;"), /forbidden SQL/u],
    ["sqlite internals", read.replace("FROM t", "FROM sqlite_master"), /forbidden SQL/u],
    ["named placeholder", read.replace("b = ?", "b = :name"), /anonymous/u],
    ["numbered placeholder", read.replace("b = ?", "b = ?1"), /anonymous/u],
    ["int64 argument not cast", read.replace("CAST(? AS INTEGER)", "?"), /must be wrapped/u],
    [
      "non-int64 argument cast",
      read.replace("scope = ?", "scope = CAST(? AS INTEGER)"),
      /must not be wrapped/u,
    ],
    [
      "placeholder count differs",
      read.replace("params=scope,int64,text", "params=scope,int64"),
      /placeholder count/u,
    ],
    ["unknown kind", read.replace("int64,text", "int64,float"), /unknown parameter kind/u],
    [
      "scope as a result column",
      read.replace("returns=int64,text?", "returns=int64,scope"),
      /cannot have kind scope/u,
    ],
    ["nullable scope", read.replace("params=scope,", "params=scope?,"), /never null/u],
    [
      "nullable int64 parameter",
      read.replace("scope,int64,text", "scope,int64?,text"),
      /nullable int64/u,
    ],
    [
      "write plan with results",
      write.replace("params=int64,scope", "params=int64,scope returns=int64"),
      /returns no rows/u,
    ],
    [
      "read plan without results",
      read.replace(" returns=int64,text?", ""),
      /declares its returned columns/u,
    ],
    ["read plan without maxRows", read.replace("-- maxRows: 1\n", ""), /maxRows/u],
    [
      "read plan with an update",
      read.replace("SELECT CAST(a AS TEXT), b FROM t WHERE", "UPDATE t SET b = 'x' WHERE"),
      /SELECT|only DML/u,
    ],
    ["maxRows too large", read.replace("maxRows: 1", "maxRows: 201"), /maxRows/u],
    ["bad plan id", read.replace("foundation.sample", "Foundation"), /invalid plan id/u],
    ["file name differs", read.replace("foundation.sample", "foundation.other"), /file name/u],
    ["wrong module directory", read.replace("foundation.sample", "other.sample"), /directory/u],
    ["version zero", read.replace("version: 1", "version: 0"), /version/u],
    ["unknown access", read.replace("access: read", "access: admin"), /access/u],
    [
      "SQL before any statement block",
      `${read.split("\n").slice(0, 4).join("\n")}\nSELECT 1;\n`,
      /outside a statement/u,
    ],
    [
      "unknown statement field",
      read.replace("params=", "bogus=1 params="),
      /unknown statement field/u,
    ],
  ];
  for (const [label, text, pattern] of refused)
    assert.throws(() => parsePlanFile(text, file), pattern, label);
  const many = `${write.split("\n").slice(0, 3).join("\n")}\n${Array.from({ length: 101 }, () => "-- statement: params=int64,scope\nUPDATE t SET a = CAST(? AS INTEGER) WHERE scope = ?;").join("\n")}\n`;
  assert.throws(() => parsePlanFile(many, file), /statement count/u);
  const wide = `-- plan: foundation.sample\n-- version: 1\n-- access: write\n-- statement: params=${Array(101).fill("text").join(",")}\nUPDATE t SET a = ${Array(101).fill("?").join(", ")};\n`;
  assert.throws(() => parsePlanFile(wide, file), /too many parameters/u);
});

test("string literals cannot hide placeholders or forbidden words", () => {
  const text = read.replace("b = ?", "b = ? AND c = '?' AND d = 'DROP; --'");
  assert.equal(parsePlanFile(text, file).statements[0]?.params.length, 3);
});

test("the manifest hash is deterministic, order independent and sensitive to every byte", () => {
  const a = parsePlanFile(read, file);
  const b = parsePlanFile(write, file);
  assert.equal(manifestHashOf([a, b]), manifestHashOf([b, a]));
  assert.equal(parsePlanFile(read.replaceAll("\n", "\r\n"), file).sha256, a.sha256);
  assert.equal(normalizePlanText("x  \r\n\r\n"), "x\n");
  assert.notEqual(parsePlanFile(read.replace("b = ?", "b <> ?"), file).sha256, a.sha256);
  assert.notEqual(manifestHashOf([a]), manifestHashOf([a, b]));
});

test("the checked-in dictionary equals a fresh generation from the plan files", async () => {
  const manifest = buildManifest(repositoryRoot);
  assert.equal(manifest.manifestHash, manifestHash);
  assert.equal(manifest.plans.length, plans.length);
  assert.deepEqual(await generate(repositoryRoot, true), {
    manifestHash,
    plans: plans.length,
    rewritten: [],
  });
});

test("stale or missing generated output fails the check and is repaired by generation", async () => {
  const root = mkdtempSync(path.join(tmpdir(), "plans-"));
  try {
    for (const relative of ["storage/plans", "worker/storage", "src/ArcForges.Cloud.Storage.D1"])
      mkdirSync(path.join(root, relative), { recursive: true });
    cpSync(path.join(repositoryRoot, "storage/plans"), path.join(root, "storage/plans"), {
      recursive: true,
    });
    await assert.rejects(generate(root, true), /stale/u);
    const first = await generate(root, false);
    assert.equal(first.manifestHash, manifestHash);
    assert.equal((await generate(root, true)).rewritten.length, 0);
    // Editing a plan without regenerating is caught.
    const target = path.join(root, "storage/plans/foundation/readiness.sql");
    writeFileSync(
      target,
      readFileSync(target, "utf8").replace("probe_schema", "probe_schema WHERE 1 = 1"),
    );
    await assert.rejects(generate(root, true), /stale/u);
    // Editing a generated file by hand is caught too.
    await generate(root, false);
    const generated = path.join(root, "worker/storage/plans.generated.ts");
    writeFileSync(generated, `${readFileSync(generated, "utf8")}\n// edited\n`);
    await assert.rejects(generate(root, true), /stale/u);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("foreign files in the plan directory are refused", async () => {
  const root = mkdtempSync(path.join(tmpdir(), "plans-"));
  try {
    const directory = path.join(root, "storage/plans/foundation");
    mkdirSync(directory, { recursive: true });
    cpSync(path.join(repositoryRoot, ownerRegistry), path.join(root, ownerRegistry));
    writeFileSync(path.join(directory, "sample.sql"), read.replace("FROM t", "FROM probe_t"));
    writeFileSync(path.join(directory, "notes.txt"), "x");
    assert.throws(() => buildManifest(root), /end with \.sql/u);
    rmSync(path.join(directory, "notes.txt"));
    assert.equal(buildManifest(root).plans.length, 1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("every checked-in plan is DML-only, scoped and exact", () => {
  for (const plan of plans) {
    for (const statement of plan.statements) {
      assert(!/\b(?:pragma|attach|create|drop|alter)\b/iu.test(statement.sql), plan.id);
      const casts = (statement.sql.match(/CAST\(\?\s+AS\s+INTEGER\)/gu) ?? []).length;
      assert.equal(
        casts,
        statement.params.filter((param) => param.kind === "int64").length,
        plan.id,
      );
    }
    // Every plan names the owner scope in at least one parameter, except the schema probe.
    if (plan.id !== "foundation.readiness")
      assert(
        plan.statements.some((statement) =>
          statement.params.some((param) => param.kind === "scope"),
        ),
        `${plan.id} is not scoped`,
      );
  }
});
