// SPDX-License-Identifier: AGPL-3.0-only
// A fixture family for the shared-family engine tests. It is not a Design family: the closed registry of the repository ships empty
// (the module tasks append their own), so the generator, the guard primitives and the order rule are proven on this fixture, built
// into a temporary root over the real physical manifest and run on the real migrations.
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { D1Scalar } from "@arcforges/ai-internal";
import { base64UrlEncode } from "../../../worker/private/encoding.ts";
import type { D1Like, D1PreparedStatement, D1RunResult } from "../../../worker/storage/d1.ts";
import { executePlan, planKey, type ExecuteDeps } from "../../../worker/storage/execute-plan.ts";
import type { PlanDefinition as WorkerPlan } from "../../../worker/storage/plan-types.ts";
import { type PlanManifest, buildManifest } from "../../../eng/verification/storage-plans.ts";
import { migrationsDirectory } from "../../../eng/verification/physical-schema.ts";
import { repositoryRoot } from "./sqlite-d1.ts";

export const fixtureFamilyId = "fixture-pair";
export const fixturePlanId = "families.fixture-pair.commit";

export const fixtureRegistry = {
  schemaVersion: 1,
  families: [
    {
      family: fixtureFamilyId,
      title: "Fixture family for the shared-family engine tests",
      source: "test fixture, not a Design family",
      participants: [
        { module: "config", requirement: "required" },
        { module: "workspace", requirement: "required" },
        { module: "entitlement", requirement: "required" },
        { module: "policy", requirement: "conditional", when: "when a source policy applies" },
        { module: "notification", requirement: "required" },
      ],
    },
  ],
};

/**
 * Guards: the platform lease first, then by SU-04 module (config, workspace, entitlement revision then balance, policy, notification);
 * mutations: the entitlement bucket and revision, the notification record, then the platform receipt; the release is generated.
 */
export const fixturePlan = `-- plan: ${fixturePlanId}
-- version: 1
-- access: write
-- guard: kind=lease module=platform key=job-lease table=platform_job_lease by=job_id holder=holder fence=fence_token until=leased_until
-- guard: kind=policy module=config key=active-config table=config_revision by=config_revision_id match=state,content_hash
-- guard: kind=authorization module=workspace key=owner table=workspace_workspace by=scope:workspace_id match=owner_user_id,state
-- guard: kind=revision module=entitlement key=workspace-revision table=entitlement_revision by=scope:workspace_id rev=rev
-- guard: kind=balance module=entitlement key=quota table=entitlement_quota_budget by=scope_kind,scope_id,quota_key,period_key rev=rev exact=used,held
-- guard: kind=policy module=policy key=source-policy table=policy_source_policy by=workspace_id,target_kind,target_id match=revision
-- guard: kind=revision module=notification key=suppression table=notification_suppression by=recipient_hash,stream rev=rev
-- statement: module=entitlement class=bucket key=quota params=int64,int64,int64,text,text,text
UPDATE entitlement_quota_budget SET used = CAST(? AS INTEGER), held = CAST(? AS INTEGER), rev = rev + 1
WHERE scope_kind = CAST(? AS INTEGER) AND scope_id = ? AND quota_key = ? AND period_key = ?;
-- statement: module=entitlement class=record key=revision params=int64,scope
UPDATE entitlement_revision SET rev = rev + 1, updated_at = CAST(? AS INTEGER) WHERE workspace_id = ?;
-- statement: module=notification class=record key=suppression params=text,int64,int64,int64
INSERT INTO notification_suppression (recipient_hash, stream, reason, provider_event_id, created_at, cleared_at, rev)
VALUES (?, CAST(? AS INTEGER), CAST(? AS INTEGER), NULL, CAST(? AS INTEGER), NULL, 1);
-- statement: module=platform class=record key=receipt params=text,scope,text,text,text,int64,int64,int64,int64
INSERT INTO platform_command (command_id, workspace_id, actor_ref, operation, request_hash, status, result_payload, result_rev, error_code, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, CAST(? AS INTEGER), NULL, CAST(? AS INTEGER), NULL, CAST(? AS INTEGER), CAST(? AS INTEGER));
`;

/** A temporary root that holds the repository's owner registry, the fixture registry and the given family plans. */
export function fixtureRoot(
  plans: Record<string, string> = { [`${fixtureFamilyId}.commit.sql`]: fixturePlan },
  registry: unknown = fixtureRegistry,
): string {
  const root = mkdtempSync(path.join(tmpdir(), "families-"));
  mkdirSync(path.join(root, "storage/plans/families"), { recursive: true });
  cpSync(
    path.join(repositoryRoot, "storage/plans/owners.json"),
    path.join(root, "storage/plans/owners.json"),
  );
  writeFileSync(path.join(root, "storage/plans/families.json"), JSON.stringify(registry));
  // buildManifest needs at least one plan; the foundation readiness plan stands for the ordinary owner plans.
  mkdirSync(path.join(root, "storage/plans/foundation"), { recursive: true });
  cpSync(
    path.join(repositoryRoot, "storage/plans/foundation/readiness.sql"),
    path.join(root, "storage/plans/foundation/readiness.sql"),
  );
  for (const [file, text] of Object.entries(plans))
    writeFileSync(path.join(root, "storage/plans/families", file), text);
  return root;
}

export const physicalDirectory = path.join(
  repositoryRoot,
  "src/ArcForges.Cloud.Storage.D1/Physical/manifest",
);

export function fixtureManifest(plans?: Record<string, string>, registry?: unknown): PlanManifest {
  return buildManifest(fixtureRoot(plans, registry), { physicalDirectory });
}

/** The Worker-side dictionary of a manifest: the shape `renderTypeScript` emits (the family roles stay out of it), and the manifest identity. */
export function workerDictionary(manifest: PlanManifest) {
  const plans: WorkerPlan[] = manifest.plans.map((plan) => ({
    id: plan.id,
    version: plan.version,
    access: plan.access,
    maxRows: plan.maxRows,
    statements: plan.statements.map(({ sql, params, returns }) => ({ sql, params, returns })),
  }));
  return {
    plans: new Map(plans.map((plan) => [planKey(plan.id, plan.version), plan])),
    manifestHash: manifest.manifestHash,
  };
}

// ---------------------------------------------------------------------------------------------------------------------------
// An SQLite stand-in for D1 over the real numbered migrations, optionally a shared file so that two handles can contend.
// ---------------------------------------------------------------------------------------------------------------------------

function toSqlite(value: unknown): SQLInputValue {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return value as SQLInputValue;
}
class Statement implements D1PreparedStatement {
  readonly database: DatabaseSync;
  readonly sql: string;
  readonly values: unknown[];
  constructor(database: DatabaseSync, sql: string, values: unknown[] = []) {
    this.database = database;
    this.sql = sql;
    this.values = values;
  }
  bind(...values: unknown[]): Statement {
    return new Statement(this.database, this.sql, values);
  }
  raw(): Promise<unknown[][]> {
    const statement = this.database.prepare(this.sql);
    statement.setReturnArrays(true);
    return Promise.resolve(statement.all(...this.values.map(toSqlite)) as unknown as unknown[][]);
  }
  run(): { changes: number } {
    const result = this.database.prepare(this.sql).run(...this.values.map(toSqlite));
    return { changes: Number(result.changes) };
  }
}
export interface FamilyD1 extends D1Like {
  readonly database: DatabaseSync;
  /** Number of batches that were rolled back on this handle. */
  readonly rollbacks: () => number;
}

/** One handle on a database. A batch is `BEGIN IMMEDIATE`, every statement, `COMMIT`; any error rolls the whole batch back. */
export function openFamilyD1(file = ":memory:", migrate = true): FamilyD1 {
  const database = new DatabaseSync(file);
  database.exec("PRAGMA busy_timeout = 5000");
  if (migrate) {
    for (const name of readdirSync(migrationsDirectory)
      .filter((entry) => /^\d{4}_.+\.sql$/u.test(entry))
      .sort())
      database.exec(readFileSync(path.join(migrationsDirectory, name), "utf8"));
  }
  let rolledBack = 0;
  return {
    database,
    rollbacks: () => rolledBack,
    prepare: (sql) => new Statement(database, sql),
    async batch(statements: D1PreparedStatement[]): Promise<D1RunResult[]> {
      database.exec("BEGIN IMMEDIATE");
      try {
        const results = statements.map((statement) => ({ meta: (statement as Statement).run() }));
        database.exec("COMMIT");
        return results;
      } catch (error) {
        rolledBack++;
        database.exec("ROLLBACK");
        throw error;
      }
    },
  };
}

// ---------------------------------------------------------------------------------------------------------------------------
// Typed plan calls over a fixture dictionary.
// ---------------------------------------------------------------------------------------------------------------------------

export const i64 = (value: string | bigint | number): D1Scalar => ({
  kind: "int64",
  value: String(value),
});
export const txt = (value: string): D1Scalar => ({ kind: "text", value });
export const byt = (value: Uint8Array): D1Scalar => ({
  kind: "bytes",
  value: base64UrlEncode(value),
});
export const nowMs = Date.UTC(2026, 9, 5, 12, 0, 0);

let counter = 0;
export function uuid(): string {
  counter++;
  return `0198a7c0-1c3e-7d4a-9b1f-${counter.toString(16).padStart(12, "0")}`;
}

export type FamilyOutcome = { ok: true; changes: string } | { ok: false; failure: string };

/** Runs one family plan through the production executor over a fixture dictionary. */
export async function runFamily(
  db: D1Like,
  dictionary: { plans: ReadonlyMap<string, WorkerPlan>; manifestHash: string },
  args: D1Scalar[][],
  scope: string,
  overrides: { planId?: string; recoveryGeneration?: string } = {},
): Promise<FamilyOutcome> {
  const deps: ExecuteDeps = {
    db,
    plans: dictionary.plans,
    manifestHash: dictionary.manifestHash,
    recoveryGeneration: "0",
    nowMs: () => nowMs,
  };
  const response = await executePlan(
    {
      planId: overrides.planId ?? fixturePlanId,
      planVersion: 1,
      manifestHash: dictionary.manifestHash,
      requestId: uuid(),
      recoveryGeneration: overrides.recoveryGeneration ?? "0",
      ownerScope: scope,
      arguments: args,
      deadlineUtc: new Date(nowMs + 5_000).toISOString().replace(/\.(\d{3})Z$/u, ".$10000Z"),
    },
    deps,
  );
  if ("failure" in response) return { ok: false, failure: response.failure };
  return { ok: true, changes: response.changes };
}

// ---------------------------------------------------------------------------------------------------------------------------
// Seeds and the arguments of the fixture plan.
// ---------------------------------------------------------------------------------------------------------------------------

export interface FixtureIds {
  workspace: string;
  user: string;
  job: string;
  configRevision: string;
  recipientHash: string;
  policyTarget: string;
}

export const ids: FixtureIds = {
  workspace: "0198a7c0-1c3e-7d4a-9b1f-0000000a0001",
  user: "0198a7c0-1c3e-7d4a-9b1f-0000000a0002",
  job: "0198a7c0-1c3e-7d4a-9b1f-0000000a0003",
  configRevision: "0198a7c0-1c3e-7d4a-9b1f-0000000a0004",
  recipientHash: "recipient-hash-1",
  policyTarget: "0198a7c0-1c3e-7d4a-9b1f-0000000a0005",
};

export const contentHash = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
/** The lease expires 10 minutes after the fixed clock, in UTC microseconds. */
export const nowMicros = BigInt(nowMs) * 1000n;
export const leaseUntil = nowMicros + 600_000_000n;

/** Seeds the rows the fixture plan guards. Every value is explicit; the migrations' own checks accept them. */
export interface SeedOverrides {
  used?: string;
  held?: string;
  budgetRev?: string;
  revision?: string;
  leaseHolder?: string;
  leaseFence?: string;
  leaseUntilMicros?: string;
}

/** The seed rows as (SQL, values) pairs, so that the SQLite oracle and the workerd D1 run seed exactly the same state. */
export function seedStatements(overrides: SeedOverrides = {}): [string, SQLInputValue[]][] {
  const statements: [string, SQLInputValue[]][] = [];
  const run = (sql: string, ...values: SQLInputValue[]) => statements.push([sql, values]);
  run(
    "INSERT INTO identity_user (user_id, realm_id, display_name, state, created_at, deletion_requested_at, rev) VALUES (?, ?, 'Fixture', 1, CAST(? AS INTEGER), NULL, 1)",
    ids.user,
    "0198a7c0-1c3e-7d4a-9b1f-0000000a00ff",
    String(nowMicros),
  );
  run(
    "INSERT INTO workspace_workspace (workspace_id, realm_id, owner_user_id, name, data_region, protection_profile, state, created_at, rev) VALUES (?, ?, ?, 'W', 'eu', 1, 1, CAST(? AS INTEGER), 1)",
    ids.workspace,
    "0198a7c0-1c3e-7d4a-9b1f-0000000a00ff",
    ids.user,
    String(nowMicros),
  );
  run(
    "INSERT INTO entitlement_revision (workspace_id, rev, updated_at) VALUES (?, CAST(? AS INTEGER), CAST(? AS INTEGER))",
    ids.workspace,
    overrides.revision ?? "7",
    String(nowMicros),
  );
  run(
    "INSERT INTO entitlement_quota_budget (scope_kind, scope_id, quota_key, period_key, unit, \"limit\", used, held, policy_version, rev) VALUES (1, ?, 'storage', 'gauge', 'byte', 9000000000000000000, CAST(? AS INTEGER), CAST(? AS INTEGER), 1, CAST(? AS INTEGER))",
    ids.workspace,
    overrides.used ?? "10",
    overrides.held ?? "2",
    overrides.budgetRev ?? "3",
  );
  run(
    "INSERT INTO policy_source_policy (workspace_id, target_kind, target_id, revision, searchable, cloud_index_allowed, ai_retrieval_allowed, managed_ai_processing_allowed, updated_by, updated_at, command_id) VALUES (?, 'project', ?, 4, 1, 1, 1, 1, ?, CAST(? AS INTEGER), ?)",
    ids.workspace,
    ids.policyTarget,
    ids.user,
    String(nowMicros),
    "0198a7c0-1c3e-7d4a-9b1f-0000000a0006",
  );
  run(
    "INSERT INTO platform_job_lease (job_id, job_type, holder, leased_until, attempts, fence_token, state, payload, available_at) VALUES (?, 'fixture', ?, CAST(? AS INTEGER), 1, CAST(? AS INTEGER), 2, '{}', CAST(? AS INTEGER))",
    ids.job,
    overrides.leaseHolder ?? "container-a",
    overrides.leaseUntilMicros ?? String(leaseUntil),
    overrides.leaseFence ?? "5",
    String(nowMicros),
  );
  run(
    "INSERT INTO config_revision (config_revision_id, schema_version, revision_identity, content_hash, environment, realm_id, effective_at, activated_at, state, document) VALUES (?, '1', 'r1', ?, 'test', ?, CAST(? AS INTEGER), CAST(? AS INTEGER), 2, '{}')",
    ids.configRevision,
    contentHash,
    "0198a7c0-1c3e-7d4a-9b1f-0000000a00ff",
    String(nowMicros),
    String(nowMicros),
  );
  return statements;
}

export function seed(db: FamilyD1, overrides: SeedOverrides = {}) {
  for (const [sql, values] of seedStatements(overrides)) db.database.prepare(sql).run(...values);
}

export interface FixtureValues {
  command: string;
  holder: string;
  fence: string;
  now: string;
  configState: string;
  workspaceState: string;
  revision: string;
  budgetRev: string;
  usedBefore: string;
  heldBefore: string;
  usedAfter: string;
  heldAfter: string;
  policyRevision: string;
  suppressionRev: string;
  /** The recipient whose suppression row the batch guards absent and inserts. */
  recipient: string;
  requestHash: string;
}

export const defaults = (command = uuid()): FixtureValues => ({
  command,
  holder: "container-a",
  fence: "5",
  now: String(nowMicros),
  configState: "2",
  workspaceState: "1",
  revision: "7",
  budgetRev: "3",
  usedBefore: "10",
  heldBefore: "2",
  usedAfter: "13",
  heldAfter: "2",
  policyRevision: "4",
  suppressionRev: "0",
  recipient: ids.recipientHash,
  requestHash: "hash-of-request",
});

/** The arguments of every statement of the fixture plan, in plan order, for the given decided values. */
export function fixtureArguments(v: FixtureValues): D1Scalar[][] {
  const cmd = txt(v.command);
  return [
    [cmd, txt(ids.job), txt(v.holder), i64(v.fence), i64(v.now)],
    [cmd, txt(ids.configRevision), i64(v.configState), byt(contentHash)],
    [cmd, txt(ids.workspace), txt(ids.user), i64(v.workspaceState)],
    [cmd, txt(ids.workspace), i64(v.revision)],
    [
      cmd,
      i64(1),
      txt(ids.workspace),
      txt("storage"),
      txt("gauge"),
      i64(v.budgetRev),
      i64(v.usedBefore),
      i64(v.heldBefore),
    ],
    [cmd, txt(ids.workspace), txt("project"), txt(ids.policyTarget), i64(v.policyRevision)],
    [cmd, txt(v.recipient), i64(1), i64(v.suppressionRev)],
    [i64(v.usedAfter), i64(v.heldAfter), i64(1), txt(ids.workspace), txt("storage"), txt("gauge")],
    [i64(v.now), txt(ids.workspace)],
    [txt(v.recipient), i64(1), i64(1), i64(v.now)],
    [
      txt(v.command),
      txt(ids.workspace),
      txt("actor"),
      txt("fixture.commit"),
      txt(v.requestHash),
      i64(2),
      i64(Number(v.revision) + 1),
      i64(v.now),
      i64(String(nowMicros + 86_400_000_000n)),
    ],
    [cmd],
  ];
}

/** What the fixture plan can change, as queries: before/after equality on the oracle and on workerd's D1. */
export const snapshotQueries: Record<string, string> = {
  budget:
    "SELECT CAST(used AS TEXT), CAST(held AS TEXT), CAST(rev AS TEXT) FROM entitlement_quota_budget",
  revision: "SELECT CAST(rev AS TEXT) FROM entitlement_revision",
  suppression:
    "SELECT recipient_hash, CAST(rev AS TEXT) FROM notification_suppression ORDER BY recipient_hash",
  commands: "SELECT command_id, request_hash FROM platform_command ORDER BY command_id",
  guards: "SELECT command_id, guard_key FROM platform_command_guard ORDER BY command_id, guard_key",
  lease: "SELECT holder, CAST(fence_token AS TEXT) FROM platform_job_lease",
};

export function snapshot(db: FamilyD1): unknown {
  const read = (sql: string) => {
    const statement = db.database.prepare(sql);
    statement.setReturnArrays(true);
    return statement.all();
  };
  return Object.fromEntries(
    Object.entries(snapshotQueries).map(([name, sql]) => [name, read(sql)]),
  );
}
