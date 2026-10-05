// SPDX-License-Identifier: AGPL-3.0-only
// The commit tail (CLOUD.04) is one definition: the canonical statements, the plan header that declares it and the generator rule that holds
// every module write plan to it. These tests prove the rule refuses each way a plan could publish without its receipt, outbox rows or archive row,
// number its own outbox rows, or drift from the text the C# builder and the vectors assume.
import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  archiveStreamKey,
  canonicalTail,
  collapse,
  formatTail,
  maxTailEvents,
  parseTailHeader,
  releaseStatement,
  renderVectors,
  reservedTables,
  vectorFile,
} from "../../eng/verification/commit-tail.ts";
import {
  assertCommitTail,
  buildManifest,
  parseOwnerRegistry,
  parsePlanFile,
} from "../../eng/verification/storage-plans.ts";
import { fixturePlanText, parseFixturePlan } from "./support/commit-support.ts";
import { repositoryRoot } from "./support/sqlite-d1.ts";

test("the canonical tail has the documented shape for every option", () => {
  for (const inbox of [false, true])
    for (const events of [0, 1, 2, maxTailEvents]) {
      const tail = canonicalTail({ events, inbox });
      assert.equal(tail.length, (inbox ? 1 : 0) + 1 + 3 * events + 2);
      // The release is not part of the tail: it ends every plan that uses guard rows, including family plans that generate it.
      assert.equal(tail.at(-1)?.role, "archive");
      assert.equal(tail.at(-2)?.role, "archive-stream");
      assert.equal(releaseStatement.role, "guard-release");
      assert.equal(tail.filter((statement) => statement.role === "outbox").length, events);
      assert.equal(tail.filter((statement) => statement.role === "inbox").length, inbox ? 1 : 0);
      // Every position statement follows its own stream allocation and outbox insert, so a sequence is read right after it is allocated.
      tail.forEach((statement, index) => {
        if (statement.role === "position") {
          assert.equal(tail[index - 1]?.role, "outbox");
          assert.equal(tail[index - 2]?.role, "stream");
        }
      });
    }
  assert.throws(() => canonicalTail({ events: maxTailEvents + 1, inbox: false }));
  assert.throws(() => canonicalTail({ events: -1, inbox: false }));
  // The statement budget of one D1 batch (100) leaves room for a plan's own statements at the largest tail.
  assert(canonicalTail({ events: maxTailEvents, inbox: true }).length <= 60);
});

test("the shared vector file is current and names every kind a C# builder must bind", async () => {
  assert.equal(readFileSync(vectorFile, "utf8").replaceAll("\r\n", "\n"), await renderVectors());
  const vectors = JSON.parse(await renderVectors()) as {
    archiveStreamKey: string;
    variants: unknown[];
  };
  assert.equal(vectors.archiveStreamKey, archiveStreamKey);
  assert.equal(vectors.variants.length, 10);
});

test("the archive stream key is outside every owner scope and is the only platform stream", () => {
  assert(archiveStreamKey.startsWith("platform:"));
  const archive = canonicalTail({ events: 0, inbox: false }).find(
    (statement) => statement.role === "archive-stream",
  );
  assert(archive?.sql.includes(`'${archiveStreamKey}'`));
});

test("a tail header is v1 with options or none with a reason, and nothing else", () => {
  assert.deepEqual(parseTailHeader("v1", "x"), { kind: "v1", events: 0, inbox: false });
  assert.deepEqual(parseTailHeader("v1 events=3 inbox", "x"), {
    kind: "v1",
    events: 3,
    inbox: true,
  });
  assert.deepEqual(parseTailHeader("v1 inbox events=16", "x"), {
    kind: "v1",
    events: 16,
    inbox: true,
  });
  assert.deepEqual(parseTailHeader("none a lease claim writes no business fact", "x"), {
    kind: "none",
    reason: "a lease claim writes no business fact",
  });
  for (const refused of [
    "",
    "v2",
    "v1 events=17",
    "v1 events=1 events=2",
    "v1 inbox inbox",
    "v1 events=x",
    "v1 outbox",
    "none",
    "none short",
    "tail",
  ])
    assert.throws(() => parseTailHeader(refused, "x"), `'${refused}' is refused`);
});

const registryFile = "storage/plans/owners.json";

function parseFixturePlanText(text: string, name: string) {
  const plan = parsePlanFile(text, `storage/plans/entitlement/${name}.sql`);
  assertCommitTail(
    plan,
    parseOwnerRegistry(readFileSync(path.join(repositoryRoot, registryFile), "utf8")),
  );
  return plan;
}

test("a plan generated from the formatter passes for every option and survives whitespace changes", () => {
  for (const events of [0, 1, 4])
    for (const inbox of [false, true])
      assert.doesNotThrow(() => parseFixturePlan(`p${events}`, { events, inbox }));
  const text = fixturePlanText("whitespace", { events: 1, inbox: false });
  // The comparison ignores whitespace and line breaks, never tokens.
  const squashed = text.replace("VALUES (?, ?, (SELECT", "VALUES\n    (?,   ?,\n      (SELECT");
  assert.notEqual(squashed, text);
  assert.doesNotThrow(() => parseFixturePlanText(squashed, "whitespace"));
  assert.equal(collapse("a \n  b\t c"), "a b c");
});

/** A temporary repository root with the real owner registry and the given plan files. */
function withRoot(files: Record<string, string>, run: (root: string) => void) {
  const root = mkdtempSync(path.join(tmpdir(), "commit-tail-"));
  try {
    mkdirSync(path.join(root, "storage/plans"), { recursive: true });
    writeFileSync(
      path.join(root, registryFile),
      readFileSync(path.join(repositoryRoot, registryFile)),
    );
    for (const [relative, content] of Object.entries(files)) {
      mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
      writeFileSync(path.join(root, relative), content);
    }
    run(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

const good = (name: string, events = 1) => fixturePlanText(name, { events, inbox: false });

test("a module write plan must declare its tail or why it has none", () => {
  const withoutHeader = good("bare").replace(/^-- tail: .*\n/mu, "");
  withRoot({ "storage/plans/entitlement/bare.sql": withoutHeader }, (root) =>
    assert.throws(() => buildManifest(root), /declares its commit tail/u),
  );
  const bare = good("none").replace(
    /^-- tail: .*$/mu,
    "-- tail: none a one-off administrative repair of the fixture row",
  );
  // 'none' means no tail at all: the guard, the mutation and the release remain and no tail table is written.
  const lines = bare.split("\n");
  const cut = lines.findIndex((line) => line.startsWith("INSERT INTO platform_command ("));
  const none = [...lines.slice(0, cut - 1), ...lines.slice(-3)].join("\n");
  assert(none.includes("DELETE FROM platform_command_guard"));
  assert(!none.includes("INSERT INTO platform_command ("));
  withRoot({ "storage/plans/entitlement/none.sql": none }, (root) =>
    assert.doesNotThrow(() => buildManifest(root)),
  );
  // A 'none' plan that carries the tail statements anyway writes tables only the tail may write.
  withRoot({ "storage/plans/entitlement/none.sql": bare }, (root) =>
    assert.throws(() => buildManifest(root), /only the commit tail may write/u),
  );
  // A platform plan and a read plan declare nothing.
  withRoot(
    {
      "storage/plans/platform/stream-read.sql": `-- plan: platform.stream-read
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope returns=int64
SELECT CAST(last_sequence AS TEXT) FROM platform_sequence_stream WHERE stream_key = ?;
`,
      "storage/plans/entitlement/read.sql": `-- plan: entitlement.read
-- version: 1
-- access: read
-- maxRows: 1
-- statement: params=scope returns=int64
SELECT CAST(revision AS TEXT) FROM entitlement_fixture_item WHERE scope = ?;
`,
    },
    (root) => assert.doesNotThrow(() => buildManifest(root)),
  );
});

test("a declared tail is verified statement by statement", () => {
  const base = good("check", 2);
  const refusals: [string, string, RegExp][] = [
    [
      "a tail statement dropped",
      base.replace(
        /-- statement: params=text\nDELETE FROM platform_command_guard WHERE command_id = \?;\n$/u,
        "",
      ),
      /differs|missing|owner statement/u,
    ],
    [
      "the receipt status changed to failed",
      base.replace("?, 2, ?, NULLIF", "?, 3, ?, NULLIF"),
      /receipt/u,
    ],
    [
      "the receipt revision sentinel removed",
      base.replace("NULLIF(CAST(? AS INTEGER), -1)", "CAST(? AS INTEGER)"),
      /receipt/u,
    ],
    [
      "the outbox row starts dispatched",
      base.replace(
        "?, ?, ?, ?, ?, 1, 0, CAST(? AS INTEGER), NULL)",
        "?, ?, ?, ?, ?, 2, 0, CAST(? AS INTEGER), NULL)",
      ),
      /outbox/u,
    ],
    [
      "the sequence allocation does not increment",
      base.replaceAll("last_sequence = last_sequence + 1", "last_sequence = last_sequence"),
      /stream/u,
    ],
    [
      "the position reads another stream",
      base.replaceAll("WHERE stream_key = ?));", "WHERE stream_key = 'other'));"),
      /position|params/u,
    ],
    [
      "a stream parameter that is not the owner scope",
      base.replace(
        "-- statement: params=scope,int64\nINSERT INTO platform_sequence_stream",
        "-- statement: params=text,int64\nINSERT INTO platform_sequence_stream",
      ),
      /stream|params/u,
    ],
    [
      "the archive record hash is not bytes",
      base.replace("params=text,int64,text,bytes,int64", "params=text,int64,text,text,int64"),
      /archive|params|differs/u,
    ],
    [
      "the archive writes another stream",
      base.replaceAll(archiveStreamKey, "platform:other"),
      /archive/u,
    ],
  ];
  for (const [name, text, expected] of refusals)
    withRoot({ "storage/plans/entitlement/check.sql": text }, (root) =>
      assert.throws(() => buildManifest(root), expected, name),
    );
});

test("a plan with a tail starts with the guard and has an owner statement of its own", () => {
  const unguarded = good("noguard").replace(
    "INSERT INTO platform_command_guard (command_id, guard_key, allowed)",
    "INSERT INTO platform_command_guard (guard_key, command_id, allowed)",
  );
  withRoot({ "storage/plans/entitlement/noguard.sql": unguarded }, (root) =>
    assert.throws(() => buildManifest(root), /statement 1 must be/u),
  );
  // The guard statement is required to bind the command id first, so it matches the receipt.
  const wrongKind = good("guardkind").replace(
    "-- statement: params=text,scope,text,int64\nINSERT INTO platform_command_guard",
    "-- statement: params=scope,scope,text,int64\nINSERT INTO platform_command_guard",
  );
  withRoot({ "storage/plans/entitlement/guardkind.sql": wrongKind }, (root) =>
    assert.throws(() => buildManifest(root), /command id as its first parameter/u),
  );
  // Only the guard and the tail: no owner mutation means there is nothing for the receipt to record.
  const hollow = good("hollow").replace(
    /-- statement: params=scope,text,int64,text\nINSERT INTO entitlement_fixture_item[\s\S]*?excluded\.value;\n/u,
    "",
  );
  withRoot({ "storage/plans/entitlement/hollow.sql": hollow }, (root) =>
    assert.throws(() => buildManifest(root), /at least one owner statement/u),
  );
});

test("a plan may carry several guards, all before the mutations, each with a literal guard key", () => {
  const base = good("guards", 1);
  const lines = base.split("\n");
  const start = lines.findIndex((line) => line.startsWith("INSERT INTO platform_command_guard"));
  // The guard statement is the header line before the insert, the insert and the SELECT line.
  const guard = `${lines.slice(start - 1, start + 2).join("\n")}\n`;
  assert(guard.includes("THEN 1 ELSE 0 END;"));
  const second = guard.replace("'entitlement.guards'", "'entitlement.guards-lease'");
  assert.notEqual(second, guard);
  withRoot(
    { "storage/plans/entitlement/guards.sql": base.replace(guard, guard + second) },
    (root) => assert.doesNotThrow(() => buildManifest(root)),
  );
  // A guard written after a mutation would let the mutation run unguarded in the middle of the plan.
  const mutation =
    "ON CONFLICT (scope, id) DO UPDATE SET revision = excluded.revision, value = excluded.value;\n";
  const afterMutation = base.replace(mutation, mutation + second);
  assert.notEqual(afterMutation, base);
  withRoot({ "storage/plans/entitlement/guards.sql": afterMutation }, (root) =>
    assert.throws(() => buildManifest(root), /guards come first/u),
  );
  // The guard key is a literal in the statement, not a parameter, and has the Key alphabet.
  const bound = base
    .replace("SELECT ?, 'entitlement.guards', CASE", "SELECT ?, ?, CASE")
    .replace(
      "params=text,scope,text,int64\nINSERT INTO platform_command_guard",
      "params=text,text,scope,text,int64\nINSERT INTO platform_command_guard",
    );
  withRoot({ "storage/plans/entitlement/guards.sql": bound }, (root) =>
    assert.throws(() => buildManifest(root), /must be a guard insert/u),
  );
  const badKey = base.replace("'entitlement.guards'", "'bad key'");
  withRoot({ "storage/plans/entitlement/guards.sql": badKey }, (root) =>
    assert.throws(() => buildManifest(root), /must be a guard insert/u),
  );
});

test("no owner statement may write a table that only the tail writes", () => {
  for (const table of reservedTables) {
    const forged = good("forged").replace(
      "ON CONFLICT (scope, id) DO UPDATE SET revision = excluded.revision, value = excluded.value;\n",
      `ON CONFLICT (scope, id) DO UPDATE SET revision = excluded.revision, value = excluded.value;\n-- statement: params=text\nDELETE FROM ${table} WHERE ${table === "platform_inbox" ? "source" : table === "platform_sequence_stream" ? "stream_key" : table === "platform_command" ? "command_id" : table === "platform_outbox" ? "outbox_id" : table === "platform_outbox_position" ? "outbox_id" : "command_id"} = ?;\n`,
    );
    withRoot({ "storage/plans/entitlement/forged.sql": forged }, (root) =>
      assert.throws(() => buildManifest(root), /only the commit tail may write/u, table),
    );
  }
  // Reading them is fine: a guard may look at a receipt or a stream.
  const reads = good("reads")
    .replace(
      "WHEN COALESCE(",
      "WHEN NOT EXISTS (SELECT 1 FROM platform_command WHERE command_id = ?) AND COALESCE(",
    )
    .replace(
      "-- statement: params=text,scope,text,int64\nINSERT INTO platform_command_guard",
      "-- statement: params=text,text,scope,text,int64\nINSERT INTO platform_command_guard",
    );
  withRoot({ "storage/plans/entitlement/reads.sql": reads }, (root) =>
    assert.doesNotThrow(() => buildManifest(root)),
  );
});

test("only a write plan carries a tail", () => {
  const read = `-- plan: entitlement.tailed-read
-- version: 1
-- access: read
-- maxRows: 1
-- tail: v1
-- statement: params=scope returns=int64
SELECT CAST(revision AS TEXT) FROM entitlement_fixture_item WHERE scope = ?;
`;
  withRoot({ "storage/plans/entitlement/tailed-read.sql": read }, (root) =>
    assert.throws(() => buildManifest(root), /only a write plan declares a tail/u),
  );
});

test("every checked-in plan satisfies the tail rule, and the shipped platform plans stay out of module scope", () => {
  const manifest = buildManifest(repositoryRoot);
  const platform = manifest.plans.filter((plan) => plan.id.startsWith("platform."));
  assert(platform.length >= 14);
  for (const plan of platform)
    for (const statement of plan.statements) assert(!/\bsqlite_/iu.test(statement.sql), plan.id);
  assert.equal(formatTail({ events: 0, inbox: false }).split("-- statement:").length - 1, 4);
});
