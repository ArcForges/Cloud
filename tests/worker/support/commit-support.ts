// SPDX-License-Identifier: AGPL-3.0-only
// Support for the receipts, outbox, inbox and change-archive tests (CLOUD.04): a database with every committed migration, a fixture
// module whose write plans carry the canonical commit tail, builders for the tail arguments that mirror the C# CommitTail, and a runner
// that executes plans through the production executor. SQLite is the oracle; none of this is evidence about Cloudflare's D1 service.
import type { D1Scalar } from "@arcforges/ai-internal";
import { createHash } from "node:crypto";
import path from "node:path";
import { formatTail, type TailOptions } from "../../../eng/verification/commit-tail.ts";
import { loadCatalog } from "../../../eng/migrations/catalog.ts";
import {
  assertCommitTail,
  parseOwnerRegistry,
  parsePlanFile,
} from "../../../eng/verification/storage-plans.ts";
import { readFileSync } from "node:fs";
import type { PlanDefinition } from "../../../worker/storage/plan-types.ts";
import { executePlan, planKey } from "../../../worker/storage/execute-plan.ts";
import { plans as generatedPlans } from "../../../worker/storage/plans.generated.ts";
import { base64UrlEncode } from "../../../worker/private/encoding.ts";
import type { D1Like } from "../../../worker/storage/d1.ts";
import { createSqliteD1, repositoryRoot, type SqliteD1 } from "./sqlite-d1.ts";
import { bytes, depsFor, i64, nul, planRequest, txt, uuid, type Outcome } from "./plan-calls.ts";

export const fixtureTable = "entitlement_fixture_item";
const fixtureDdl = `CREATE TABLE ${fixtureTable} (scope TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY (scope, id)) STRICT;\n`;
const registry = parseOwnerRegistry(
  readFileSync(path.join(repositoryRoot, "storage/plans/owners.json"), "utf8"),
);

/** The migrated schema of the repository (every locked migration, in order) plus the fixture module's table. */
export function commitDatabase(): SqliteD1 {
  const sql = loadCatalog()
    .map((migration) => migration.text)
    .join("\n");
  return createSqliteD1(`${sql}\n${fixtureDdl}`);
}

/** A module write plan: the guard, one mutation of the fixture table and the canonical tail for its options. */
export function fixturePlanText(
  name: string,
  options: TailOptions,
  headerOverride?: string,
): string {
  const header = headerOverride ?? `v1 events=${options.events}${options.inbox ? " inbox" : ""}`;
  return `-- plan: entitlement.${name}
-- version: 1
-- access: write
-- tail: ${header}
-- statement: params=text,scope,text,int64
INSERT INTO platform_command_guard (command_id, guard_key, allowed)
SELECT ?, 'entitlement.${name}', CASE WHEN COALESCE((SELECT revision FROM ${fixtureTable} WHERE scope = ? AND id = ?), 0) = CAST(? AS INTEGER) THEN 1 ELSE 0 END;
-- statement: params=scope,text,int64,text
INSERT INTO ${fixtureTable} (scope, id, revision, value) VALUES (?, ?, CAST(? AS INTEGER) + 1, ?)
ON CONFLICT (scope, id) DO UPDATE SET revision = excluded.revision, value = excluded.value;
${formatTail(options)}`;
}

export function parseFixturePlan(
  name: string,
  options: TailOptions,
  headerOverride?: string,
): PlanDefinition {
  const plan = parsePlanFile(
    fixturePlanText(name, options, headerOverride),
    `storage/plans/entitlement/${name}.sql`,
  );
  assertCommitTail(plan, registry);
  return plan;
}

export const fixtureOptions = {
  "item-store": { events: 2, inbox: false },
  "item-store-one": { events: 1, inbox: false },
  "item-store-none": { events: 0, inbox: false },
  "item-consume": { events: 1, inbox: true },
} as const satisfies Record<string, TailOptions>;

const fixturePlans = Object.entries(fixtureOptions).map(([name, options]) =>
  parseFixturePlan(name, options),
);
export const planIndexWithFixtures = new Map<string, PlanDefinition>(
  [...generatedPlans, ...fixturePlans].map((plan) => [planKey(plan.id, plan.version), plan]),
);

export const stream = "workspace:fixture-a";
export const otherStream = "workspace:fixture-b";

export interface EventInput {
  outboxId: string;
  aggregateKind?: string;
  aggregateId?: string;
  aggregateRevision?: number;
  eventType?: string;
  payload?: string;
  workspaceId?: string | null;
  correlationId?: string;
  causationId?: string | null;
}
export interface TailInput {
  commandId: string;
  workspaceId?: string | null;
  actor?: string;
  operation?: string;
  requestHash?: string;
  resultPayload?: string;
  resultRevision?: number | bigint | null;
  createdAt?: number;
  expiresAt?: number;
  events?: EventInput[];
  schemaVersion?: number;
  record?: string;
  inbox?: { source: string; messageId: string; expiresAt?: number };
}

export const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest();
const maybe = (value: string | null | undefined): D1Scalar => (value ? txt(value) : nul());

/** The arguments of the canonical tail statements (mirrors CommitTail.Arguments in C#). */
export function tailArguments(scope: string, input: TailInput): D1Scalar[][] {
  const now = input.createdAt ?? 1_000_000;
  const list: D1Scalar[][] = [];
  if (input.inbox)
    list.push([
      txt(input.inbox.source),
      txt(input.inbox.messageId),
      i64(now),
      i64(now),
      i64(input.inbox.expiresAt ?? now + 86_400_000_000),
    ]);
  list.push([
    txt(input.commandId),
    maybe(input.workspaceId),
    txt(input.actor ?? "actor-1"),
    txt(input.operation ?? "fixture.store"),
    txt(input.requestHash ?? "hash-1"),
    txt(input.resultPayload ?? '{"ok":true}'),
    i64(input.resultRevision ?? -1),
    i64(now),
    i64(input.expiresAt ?? now + 604_800_000_000),
  ]);
  for (const event of input.events ?? []) {
    list.push([{ kind: "text", value: scope }, i64(now)]);
    list.push([
      txt(event.outboxId),
      txt(event.aggregateKind ?? "fixture"),
      txt(event.aggregateId ?? uuid()),
      i64(event.aggregateRevision ?? 1),
      txt(event.eventType ?? "fixture.changed"),
      txt(event.payload ?? '{"n":1}'),
      maybe(event.workspaceId),
      txt(event.correlationId ?? uuid()),
      maybe(event.causationId),
      i64(now),
    ]);
    list.push([
      txt(event.outboxId),
      { kind: "text", value: scope },
      { kind: "text", value: scope },
    ]);
  }
  list.push([i64(now)]);
  const record = input.record ?? `{"id":"${input.commandId}"}`;
  list.push([
    txt(input.commandId),
    i64(input.schemaVersion ?? 23),
    txt(record),
    bytes(sha256(record)),
    i64(now),
  ]);
  list.push([txt(input.commandId)]);
  return list;
}

export interface CommitInput extends TailInput {
  plan?: keyof typeof fixtureOptions;
  scope?: string;
  itemId?: string;
  expectedRevision?: number;
  value?: string;
}

export function commitArguments(input: CommitInput): D1Scalar[][] {
  const scope = input.scope ?? stream;
  const id = input.itemId ?? "item-1";
  return [
    [
      txt(input.commandId),
      { kind: "text", value: scope },
      txt(id),
      i64(input.expectedRevision ?? 0),
    ],
    [
      { kind: "text", value: scope },
      txt(id),
      i64(input.expectedRevision ?? 0),
      txt(input.value ?? "v"),
    ],
    ...tailArguments(scope, input),
  ];
}

export async function execute(
  db: D1Like,
  planId: string,
  args: D1Scalar[][],
  ownerScope = stream,
): Promise<Outcome> {
  const response = await executePlan(
    planRequest(planId, args, { ownerScope }),
    depsFor(db, { plans: planIndexWithFixtures }),
  );
  if ("failure" in response) return { ok: false, failure: response.failure };
  return {
    ok: true,
    rows: response.rows.map((row) =>
      row.map((value) => ("value" in value ? String(value.value) : "null")),
    ),
    changes: response.changes,
  };
}

/** One guarded commit of the fixture module through the canonical tail. */
export function commit(db: D1Like, input: CommitInput): Promise<Outcome> {
  return execute(
    db,
    `entitlement.${input.plan ?? "item-store"}`,
    commitArguments(input),
    input.scope ?? stream,
  );
}

export function event(outboxId = uuid(), overrides: Partial<EventInput> = {}): EventInput {
  return { outboxId, ...overrides };
}

export const count = (db: SqliteD1, table: string, where = "1 = 1") =>
  Number(
    (
      db.database.prepare(`SELECT COUNT(*) FROM ${table} WHERE ${where}`).get() as {
        "COUNT(*)": number;
      }
    )["COUNT(*)"],
  );

export const rows = (db: SqliteD1, sql: string): unknown[][] => {
  const statement = db.database.prepare(sql);
  statement.setReturnArrays(true);
  return statement.all() as unknown as unknown[][];
};

export const b64 = (value: Uint8Array) => base64UrlEncode(value);
