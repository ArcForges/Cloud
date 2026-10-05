// SPDX-License-Identifier: AGPL-3.0-only
// The commit tail (Design D1 profile section 4, CLOUD.04): the fixed statements that every guarded write of a module appends to its own
// mutations so that the owner receipt, the outbox rows, the change-archive row and the optional inbox claim commit in the same D1 batch.
// A plan is: guard statements (platform_command_guard rows, one per guard), the module's own mutations, the tail, and the guard release.
// This file is the one definition of the tail and of the release. The plan generator (storage-plans.ts) verifies that a module write plan
// declares a tail in its header and ends with exactly these statements; the C# CommitTail builder and
// tests/ArcForges.Cloud.Tests/Vectors/commit-tail.json are checked against the same definition. The guard table and the guard primitives
// that generate the guard statements are the shared-family engine's (CLOUD.06); the tail never writes a guard row, it only follows them.
//
//   node eng/verification/commit-tail.ts print [--events N] [--inbox]    print the canonical tail as plan-file statement blocks
//   node eng/verification/commit-tail.ts --emit-vectors                  rewrite the shared vector file
//   node eng/verification/commit-tail.ts --check-vectors                 fail when the vector file is stale
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { format } from "prettier";
import type { PlanKind, PlanParam } from "../../worker/storage/plan-types.ts";

export interface TailStatement {
  /** What the statement does, for the generated documentation and error messages. */
  readonly role:
    | "inbox"
    | "receipt"
    | "stream"
    | "outbox"
    | "position"
    | "archive-stream"
    | "archive"
    | "guard-release";
  readonly sql: string;
  readonly params: readonly PlanParam[];
}

/** The change archive is the one stream whose key starts with this prefix; an owner scope never does. */
export const platformStreamPrefix = "platform:";
export const archiveStreamKey = "platform:change-archive";
export const maxTailEvents = 16;
/** Every leading statement of a plan that declares a tail starts with this, followed by `SELECT ?, '<guard key>',`. */
export const guardInsertPrefix =
  "INSERT INTO platform_command_guard (command_id, guard_key, allowed)";
const guardStatement =
  /^INSERT INTO platform_command_guard \(command_id, guard_key, allowed\) SELECT \?, '[A-Za-z0-9._:/-]{1,128}', /u;
/**
 * Tables only a tail (or a platform plan) may write: a module write plan never names one as a write target, with or without a tail
 * (storage-plans.ts applies this to every module write plan from the generator's own tokenizer). The guard table is the family engine's.
 */
export const reservedTables: readonly string[] = [
  "platform_command",
  "platform_inbox",
  "platform_outbox",
  "platform_outbox_position",
  "platform_sequence_stream",
  "platform_change_archive",
];

const p = (kind: PlanKind, nullable = false): PlanParam => ({ kind, nullable });
const text = p("text");
const int64 = p("int64");
const scope = p("scope");

const inboxStatement: TailStatement = {
  role: "inbox",
  sql: `INSERT INTO platform_inbox (source, message_id, received_at, processed_at, outcome, expires_at)
VALUES (?, ?, CAST(? AS INTEGER), CAST(? AS INTEGER), 1, CAST(? AS INTEGER));`,
  params: [text, text, int64, int64, int64],
};

const receiptStatement: TailStatement = {
  role: "receipt",
  sql: `INSERT INTO platform_command (command_id, workspace_id, actor_ref, operation, request_hash, status, result_payload, result_rev, error_code, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, 2, ?, NULLIF(CAST(? AS INTEGER), -1), NULL, CAST(? AS INTEGER), CAST(? AS INTEGER));`,
  params: [text, p("text", true), text, text, text, text, int64, int64, int64],
};

const streamStatement: TailStatement = {
  role: "stream",
  sql: `INSERT INTO platform_sequence_stream (stream_key, last_sequence, published_watermark, publish_rev, fence, ack_receipt, updated_at)
VALUES (?, 1, 0, 0, 0, NULL, CAST(? AS INTEGER))
ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 1, updated_at = excluded.updated_at;`,
  params: [scope, int64],
};

const outboxStatement: TailStatement = {
  role: "outbox",
  sql: `INSERT INTO platform_outbox (outbox_id, aggregate_kind, aggregate_id, aggregate_rev, event_type, payload, workspace_id, correlation_id, causation_id, state, attempts, created_at, dispatched_at)
VALUES (?, ?, ?, CAST(? AS INTEGER), ?, ?, ?, ?, ?, 1, 0, CAST(? AS INTEGER), NULL);`,
  params: [text, text, text, int64, text, text, p("text", true), text, p("text", true), int64],
};

const positionStatement: TailStatement = {
  role: "position",
  sql: `INSERT INTO platform_outbox_position (outbox_id, stream_key, sequence)
VALUES (?, ?, (SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = ?));`,
  params: [text, scope, scope],
};

const archiveStreamStatement: TailStatement = {
  role: "archive-stream",
  sql: `INSERT INTO platform_sequence_stream (stream_key, last_sequence, published_watermark, publish_rev, fence, ack_receipt, updated_at)
VALUES ('${archiveStreamKey}', 1, 0, 0, 0, NULL, CAST(? AS INTEGER))
ON CONFLICT (stream_key) DO UPDATE SET last_sequence = last_sequence + 1, updated_at = excluded.updated_at;`,
  params: [int64],
};

const archiveStatement: TailStatement = {
  role: "archive",
  sql: `INSERT INTO platform_change_archive (archive_sequence, command_id, schema_version, record, record_hash, created_at)
VALUES ((SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = '${archiveStreamKey}'), ?, CAST(? AS INTEGER), ?, ?, CAST(? AS INTEGER));`,
  params: [text, int64, text, p("bytes"), int64],
};

/** The last statement of every plan that uses guard rows: no committed state holds one. */
export const releaseStatement: TailStatement = {
  role: "guard-release",
  sql: "DELETE FROM platform_command_guard WHERE command_id = ?;",
  params: [text],
};

export interface TailOptions {
  readonly events: number;
  readonly inbox: boolean;
}

/** The statements, in order, that follow a plan's own mutations and precede the release. Statement parameter order is the order of the arguments. */
export function canonicalTail(options: TailOptions): TailStatement[] {
  assert(
    Number.isInteger(options.events) && options.events >= 0 && options.events <= maxTailEvents,
    `a tail carries 0 to ${maxTailEvents} outbox events`,
  );
  const statements: TailStatement[] = [];
  if (options.inbox) statements.push(inboxStatement);
  statements.push(receiptStatement);
  for (let event = 0; event < options.events; event++)
    statements.push(streamStatement, outboxStatement, positionStatement);
  statements.push(archiveStreamStatement, archiveStatement);
  return statements;
}

/** Whitespace-insensitive comparison form of one statement. */
export const collapse = (sql: string) => sql.replaceAll(/\s+/gu, " ").trim();

export type TailDeclaration =
  | { readonly kind: "v1"; readonly events: number; readonly inbox: boolean }
  | { readonly kind: "none"; readonly reason: string };

/** `v1 [events=N] [inbox]` or `none <reason of at least ten characters>`. */
export function parseTailHeader(value: string, where: string): TailDeclaration {
  if (value.startsWith("none")) {
    const reason = value.slice(4).trim();
    assert(
      reason.length >= 10,
      `${where}: '-- tail: none' states the reason in at least ten characters`,
    );
    return { kind: "none", reason };
  }
  const parts = value.split(/\s+/u).filter(Boolean);
  assert.equal(
    parts[0],
    "v1",
    `${where}: a tail header is 'v1 [events=N] [inbox]' or 'none <reason>'`,
  );
  let events = 0;
  let inbox = false;
  let seenEvents = false;
  for (const part of parts.slice(1)) {
    const match = /^events=(\d{1,2})$/u.exec(part);
    if (match) {
      assert(!seenEvents, `${where}: duplicate events`);
      seenEvents = true;
      events = Number(match[1]);
    } else {
      assert(part === "inbox" && !inbox, `${where}: unknown tail option '${part}'`);
      inbox = true;
    }
  }
  assert(events <= maxTailEvents, `${where}: at most ${maxTailEvents} outbox events`);
  return { kind: "v1", events, inbox };
}

export interface TailPlanView {
  readonly id: string;
  readonly access: "read" | "write";
  readonly statements: readonly {
    readonly sql: string;
    readonly params: readonly PlanParam[];
  }[];
}

const sameParams = (a: readonly PlanParam[], b: readonly PlanParam[]) =>
  a.length === b.length &&
  a.every((value, index) => value.kind === b[index]?.kind && value.nullable === b[index]?.nullable);

/**
 * A plan that declares a tail starts with one or more guard inserts (`platform_command_guard` rows with a literal guard key), holds at
 * least one owner statement, and ends with exactly the canonical tail for its options followed by the guard release. No owner statement
 * writes one of the reserved platform tables (so no plan can number its own outbox rows, forge a receipt, write the archive or write a
 * guard row after its mutations). A plan that declares none states why.
 */
export function assertTail(
  plan: TailPlanView,
  declaration: TailDeclaration,
): { ownerStart: number; ownerEnd: number } | undefined {
  if (declaration.kind === "none") return undefined;
  assert.equal(plan.access, "write", `${plan.id}: only a write plan carries a commit tail`);
  const suffix = [...canonicalTail(declaration), releaseStatement];
  let guards = 0;
  while (
    guards < plan.statements.length &&
    guardStatement.test(collapse(plan.statements[guards]?.sql ?? ""))
  ) {
    assert(
      plan.statements[guards]?.params[0]?.kind === "text",
      `${plan.id}: guard statement ${guards + 1} binds the command id as its first parameter`,
    );
    guards++;
  }
  assert(
    guards >= 1,
    `${plan.id}: statement 1 must be a guard insert '${guardInsertPrefix} SELECT ?, '<guard key>', ...'`,
  );
  const ownerEnd = plan.statements.length - suffix.length;
  assert(
    ownerEnd - guards >= 1,
    `${plan.id}: a plan with a tail has at least one guard, at least one owner statement and the ${suffix.length} tail and release statements`,
  );
  suffix.forEach((expected, index) => {
    const actual = plan.statements[ownerEnd + index];
    const where = `${plan.id}: tail statement ${index + 1} (${expected.role}), plan statement ${ownerEnd + index + 1}`;
    assert(actual !== undefined, `${where} is missing`);
    assert(
      collapse(actual.sql) === collapse(expected.sql),
      `${where} differs from the canonical text; run node eng/verification/commit-tail.ts print`,
    );
    assert(sameParams(actual.params, expected.params), `${where} has different parameter kinds`);
  });
  plan.statements.slice(guards, ownerEnd).forEach((statement, index) => {
    assert(
      !guardStatement.test(collapse(statement.sql)),
      `${plan.id}: owner statement ${guards + index + 1} is a guard insert after a mutation: guards come first`,
    );
  });
  return { ownerStart: guards, ownerEnd };
}

/** The statement blocks to paste after a plan's own mutations: the tail and then the guard release. */
export function formatTail(options: TailOptions): string {
  return [...canonicalTail(options), releaseStatement]
    .map((statement) => {
      const kinds = statement.params
        .map((param) => `${param.kind}${param.nullable ? "?" : ""}`)
        .join(",");
      return `-- statement: params=${kinds}
${statement.sql}
`;
    })
    .join("");
}

// ---------------------------------------------------------------------------------------------------------------
// Shared vectors: the parameter kinds of every variant, read by the C# CommitTail tests
// ---------------------------------------------------------------------------------------------------------------

export const vectorFile = path.resolve(
  import.meta.dirname,
  "../../tests/ArcForges.Cloud.Tests/Vectors/commit-tail.json",
);

export function tailVectors() {
  const variants: {
    events: number;
    inbox: boolean;
    statements: { role: string; params: string[] }[];
  }[] = [];
  for (const inbox of [false, true])
    for (const events of [0, 1, 2, 3, maxTailEvents])
      variants.push({
        events,
        inbox,
        statements: canonicalTail({ events, inbox }).map((statement) => ({
          role: statement.role,
          params: statement.params.map((param) => `${param.kind}${param.nullable ? "?" : ""}`),
        })),
      });
  return {
    schemaVersion: 1,
    archiveStreamKey,
    maxEvents: maxTailEvents,
    release: {
      role: releaseStatement.role,
      params: releaseStatement.params.map((param) => param.kind),
    },
    variants,
  };
}

export const renderVectors = () =>
  format(JSON.stringify(tailVectors()), { parser: "json", printWidth: 100 });

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  if (argv.includes("--emit-vectors")) writeFileSync(vectorFile, await renderVectors());
  else if (argv.includes("--check-vectors")) {
    const actual = readFileSync(vectorFile, "utf8").replaceAll("\r\n", "\n");
    assert.equal(
      actual,
      await renderVectors(),
      "tests/ArcForges.Cloud.Tests/Vectors/commit-tail.json is stale; run node eng/verification/commit-tail.ts --emit-vectors",
    );
  } else if (argv[0] === "print") {
    const at = argv.indexOf("--events");
    process.stdout.write(
      formatTail({ events: at >= 0 ? Number(argv[at + 1]) : 0, inbox: argv.includes("--inbox") }),
    );
  } else {
    process.stderr.write(
      "usage: commit-tail.ts print [--events N] [--inbox] | --emit-vectors | --check-vectors\n",
    );
    process.exitCode = 2;
  }
}
