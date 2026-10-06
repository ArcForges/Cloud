// SPDX-License-Identifier: AGPL-3.0-only
// Support for the identity core tests (CLOUD.11): argument builders for the identity plans and the enrollment family that mirror the
// C# IdentityStatements (the shared vector tests/ArcForges.Cloud.Tests/Vectors/identity-plan-calls.json holds both to the same
// arguments), a runner through the production Worker executor on the real numbered migrations, and row helpers. SQLite is the oracle;
// none of this is evidence about Cloudflare's D1 service.
import type { D1Scalar } from "@arcforges/ai-internal";
import { DatabaseSync } from "node:sqlite";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { base64UrlDecode } from "../../../worker/private/encoding.ts";
import { migrationsDirectory } from "../../../eng/verification/physical-schema.ts";
import type { D1Like, D1PreparedStatement, D1RunResult } from "../../../worker/storage/d1.ts";
import { executePlan, planKey, type ExecuteDeps } from "../../../worker/storage/execute-plan.ts";
import { manifestHash, plans } from "../../../worker/storage/plans.generated.ts";
import { sha256, tailArguments, type EventInput } from "./commit-support.ts";
import { bytes, i64, nul, txt } from "./plan-calls.ts";

export const identityPlans = new Map(plans.map((plan) => [planKey(plan.id, plan.version), plan]));
export const nowMs = Date.UTC(2026, 9, 5, 12, 0, 0);
export const nowMicros = nowMs * 1000;

let counter = 0;
/** A canonical lower-case UUID, distinct per call. */
export function uid(): string {
  counter++;
  return `00000000-0000-4000-8000-${counter.toString(16).padStart(12, "0")}`;
}

export const realmA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const realmB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

export interface PasskeyInput {
  publicKey: string;
  userHandle: string;
  backupEligible: boolean | null;
  backupState: boolean | null;
  transports: string | null;
  signCount: number | null;
}

export interface CredentialInput {
  credentialId: string;
  user: string;
  realm: string;
  provider: string;
  /** The stored method number: passkey 1, emailCode 2, password 3, oidc 4. */
  method: number;
  subject: string;
  label: string | null;
  passkey: PasskeyInput | null;
  password: string | null;
  createdAt: number;
}

export interface TailInputs {
  command: string;
  now: number;
  outbox: string;
  correlation: string;
  causation: string | null;
  schema: number;
}

const maybeText = (value: string | null): D1Scalar => (value === null ? nul() : txt(value));
const flag = (value: boolean | null): D1Scalar => i64(value === null ? -1 : value ? 1 : 0);
function mustDecode(text: string): Uint8Array {
  const value = base64UrlDecode(text);
  if (value === null) throw new Error("not base64url");
  return value;
}
const retention = 7 * 24 * 60 * 60 * 1_000_000;

/** The arguments of the credential insert, in the placeholder order of the plans. */
export function credentialRow(c: CredentialInput): D1Scalar[] {
  const p = c.passkey;
  return [
    txt(c.credentialId),
    txt(c.user),
    i64(c.method),
    txt(c.subject),
    p ? bytes(mustDecode(p.publicKey)) : nul(),
    p ? bytes(mustDecode(p.userHandle)) : nul(),
    flag(p?.backupEligible ?? null),
    flag(p?.backupState ?? null),
    maybeText(p?.transports ?? null),
    i64(p?.signCount ?? -1),
    maybeText(c.label),
    i64(c.createdAt),
    txt(c.realm),
    txt(c.provider),
    maybeText(c.password),
  ];
}

function eventFor(
  tail: TailInputs,
  type: string,
  aggregateId: string,
  revision: number,
  payload: string,
  scope: string,
  aggregateKind = "identity.user",
): EventInput {
  return {
    outboxId: tail.outbox,
    aggregateKind,
    aggregateId,
    aggregateRevision: revision,
    eventType: type,
    payload,
    workspaceId: scope,
    correlationId: tail.correlation,
    causationId: tail.causation,
  };
}

const json = (value: unknown) => JSON.stringify(value);

/** Mirrors IdentityStatements.Tail: the receipt, events and change record carry identifiers and numbers only. */
function tail(
  scope: string,
  tailInputs: TailInputs,
  operation: string,
  user: string,
  realm: string,
  requestHash: string,
  resultRevision: number,
  events: EventInput[],
  changeFields: Record<string, unknown>,
  enrollment?: { actor: string; result: string },
): D1Scalar[][] {
  const record = json({ operation, realmId: realm, userId: user, ...changeFields });
  return tailArguments(scope, {
    commandId: tailInputs.command,
    workspaceId: enrollment ? null : scope,
    actor: enrollment?.actor ?? `user:${user}`,
    operation,
    requestHash,
    resultPayload: enrollment?.result ?? '{"ok":true}',
    resultRevision,
    createdAt: tailInputs.now,
    expiresAt: tailInputs.now + retention,
    events,
    schemaVersion: tailInputs.schema,
    record,
  });
}

/** The same canonical request text and SHA-256 as IdentityStatements.Tail (hex, lower case). */
export function requestHash(
  operation: string,
  kind: string,
  scope: string,
  realm: string,
  user: string,
  shape: (string | number)[],
): string {
  const text = [operation, kind, scope, realm, user, shape.join("\n")].join("\n");
  return sha256(text).toString("hex");
}

export interface EnrollInputs extends TailInputs {
  realm: string;
  user: string;
  workspace: string;
  credential: CredentialInput;
  displayName: string;
  workspaceName: string;
  region: string;
}

/** The sealed argument list of families.account-enrollment.create-user (the command identity in front of every guard and the release). */
export function enrollArguments(e: EnrollInputs): D1Scalar[][] {
  const c = e.credential;
  const fingerprint = (fields: (string | null)[]) =>
    sha256(
      fields
        .map((value) => (value === null ? "~" : Buffer.from(value, "utf8").toString("base64")))
        .join("\n"),
    ).toString("hex");
  const p = c.passkey;
  const hash = fingerprint([
    "identity.account.enroll.v1",
    e.realm,
    e.displayName,
    c.provider,
    String(c.method),
    c.subject,
    c.label,
    c.password,
    p ? Buffer.from(mustDecode(p.publicKey)).toString("base64") : null,
    p ? Buffer.from(mustDecode(p.userHandle)).toString("base64") : null,
    p?.backupEligible == null ? null : p.backupEligible ? "True" : "False",
    p?.backupState == null ? null : p.backupState ? "True" : "False",
    p?.transports ?? null,
    p?.signCount == null ? null : String(p.signCount),
  ]);
  const own: D1Scalar[][] = [
    [txt(e.command), txt(c.credentialId), i64(0)],
    [txt(e.command), txt(e.realm), txt(c.provider), txt(c.subject), i64(0)],
    [txt(e.command), txt(e.realm), txt(e.user), i64(0)],
    [txt(e.command), txt(e.realm), txt(e.user), i64(0)],
    [txt(e.command), txt(e.workspace), i64(0)],
    [txt(e.user), txt(e.realm), txt(e.displayName), i64(e.now)],
    credentialRow(c),
    [txt(e.workspace), txt(e.realm), txt(e.user), txt(e.workspaceName), txt(e.region), i64(e.now)],
  ];
  const payload = json({ authIdentityId: c.credentialId, method: c.method, userId: e.user });
  return [
    ...own,
    ...tail(
      e.workspace,
      e,
      "identity.account.enroll",
      e.user,
      e.realm,
      hash,
      1,
      [eventFor(e, "identity.user.enrolled", e.user, 1, payload, e.workspace)],
      {
        userId: e.user,
        workspaceId: e.workspace,
        authIdentityId: c.credentialId,
        method: c.method,
      },
      {
        actor: "enrollment:" + fingerprint([e.realm, c.provider, c.subject]),
        result: json({
          schemaVersion: 1,
          userId: e.user,
          authIdentityId: c.credentialId,
          workspaceId: e.workspace,
        }),
      },
    ),
  ];
}

export interface AddInputs extends TailInputs {
  realm: string;
  user: string;
  scope: string;
  expectedUserRevision: number;
  credential: CredentialInput;
}

export function addArguments(a: AddInputs): D1Scalar[][] {
  const c = a.credential;
  const rev = a.expectedUserRevision;
  const hash = requestHash("identity.credential.add", "AddCredential", a.scope, a.realm, a.user, [
    c.provider,
    c.method,
    c.subject,
    c.label ?? "\u0001",
    rev,
  ]);
  const payload = json({ authIdentityId: c.credentialId, method: c.method, userId: a.user });
  return [
    [
      txt(a.command),
      txt(a.realm),
      txt(a.user),
      i64(rev),
      txt(a.realm),
      txt(c.provider),
      txt(c.subject),
    ],
    credentialRow(c),
    [txt(a.realm), txt(a.user), i64(rev)],
    ...tail(
      a.scope,
      a,
      "identity.credential.add",
      a.user,
      a.realm,
      hash,
      rev + 1,
      [eventFor(a, "identity.auth_identity.added", a.user, rev + 1, payload, a.scope)],
      { authIdentityId: c.credentialId, method: c.method, userRevision: rev + 1 },
    ),
  ];
}

export interface RevokeInputs extends TailInputs {
  realm: string;
  user: string;
  scope: string;
  target: string;
  expectedCredentialRevision: number;
  expectedUserRevision: number;
  at: number;
}

export function revokeArguments(r: RevokeInputs): D1Scalar[][] {
  const hash = requestHash(
    "identity.credential.revoke",
    "RevokeCredential",
    r.scope,
    r.realm,
    r.user,
    [r.target, r.expectedCredentialRevision, r.expectedUserRevision],
  );
  const payload = json({ authIdentityId: r.target, userId: r.user });
  return [
    [
      txt(r.command),
      txt(r.realm),
      txt(r.target),
      txt(r.user),
      i64(r.expectedCredentialRevision),
      txt(r.realm),
      txt(r.user),
      i64(r.expectedUserRevision),
      txt(r.realm),
      txt(r.user),
      txt(r.target),
      txt(r.user),
    ],
    [i64(r.at), txt(r.realm), txt(r.target), txt(r.user), i64(r.expectedCredentialRevision)],
    [txt(r.realm), txt(r.user), i64(r.expectedUserRevision)],
    ...tail(
      r.scope,
      r,
      "identity.credential.revoke",
      r.user,
      r.realm,
      hash,
      r.expectedUserRevision + 1,
      [
        eventFor(
          r,
          "identity.auth_identity.revoked",
          r.user,
          r.expectedUserRevision + 1,
          payload,
          r.scope,
        ),
      ],
      {
        authIdentityId: r.target,
        credentialRevision: r.expectedCredentialRevision + 1,
        userRevision: r.expectedUserRevision + 1,
      },
    ),
  ];
}

export interface RelabelInputs extends TailInputs {
  realm: string;
  user: string;
  scope: string;
  target: string;
  expectedCredentialRevision: number;
  label: string | null;
}

export function relabelArguments(r: RelabelInputs): D1Scalar[][] {
  const hash = requestHash(
    "identity.credential.relabel",
    "RelabelCredential",
    r.scope,
    r.realm,
    r.user,
    [r.target, r.label ?? "\u0001", r.expectedCredentialRevision],
  );
  return [
    [
      txt(r.command),
      txt(r.realm),
      txt(r.target),
      txt(r.user),
      i64(r.expectedCredentialRevision),
      txt(r.realm),
      txt(r.user),
    ],
    [
      maybeText(r.label),
      txt(r.realm),
      txt(r.target),
      txt(r.user),
      i64(r.expectedCredentialRevision),
    ],
    ...tail(
      r.scope,
      r,
      "identity.credential.relabel",
      r.user,
      r.realm,
      hash,
      r.expectedCredentialRevision + 1,
      [
        eventFor(
          r,
          "identity.auth_identity.relabeled",
          r.target,
          r.expectedCredentialRevision + 1,
          json({ authIdentityId: r.target, userId: r.user }),
          r.scope,
          "identity.auth_identity",
        ),
      ],
      { authIdentityId: r.target, credentialRevision: r.expectedCredentialRevision + 1 },
    ),
  ];
}

export interface RenameInputs extends TailInputs {
  realm: string;
  user: string;
  scope: string;
  expectedUserRevision: number;
  displayName: string;
}

export function renameArguments(r: RenameInputs): D1Scalar[][] {
  const hash = requestHash("identity.user.rename", "RenameUser", r.scope, r.realm, r.user, [
    r.displayName,
    r.expectedUserRevision,
  ]);
  return [
    [txt(r.command), txt(r.realm), txt(r.user), i64(r.expectedUserRevision)],
    [txt(r.displayName), txt(r.realm), txt(r.user), i64(r.expectedUserRevision)],
    ...tail(
      r.scope,
      r,
      "identity.user.rename",
      r.user,
      r.realm,
      hash,
      r.expectedUserRevision + 1,
      [
        eventFor(
          r,
          "identity.user.renamed",
          r.user,
          r.expectedUserRevision + 1,
          json({ userId: r.user }),
          r.scope,
        ),
      ],
      {
        userRevision: r.expectedUserRevision + 1,
      },
    ),
  ];
}

// ---------------------------------------------------------------------------------------------------------------------------
// The database and the runner
// ---------------------------------------------------------------------------------------------------------------------------

class Stmt implements D1PreparedStatement {
  readonly database: DatabaseSync;
  readonly sql: string;
  readonly values: unknown[];
  constructor(database: DatabaseSync, sql: string, values: unknown[] = []) {
    this.database = database;
    this.sql = sql;
    this.values = values;
  }
  bind(...values: unknown[]): Stmt {
    return new Stmt(this.database, this.sql, values);
  }
  raw(): Promise<unknown[][]> {
    const statement = this.database.prepare(this.sql);
    statement.setReturnArrays(true);
    return Promise.resolve(statement.all(...this.values.map(conv)) as unknown as unknown[][]);
  }
  run(): { changes: number } {
    const result = this.database.prepare(this.sql).run(...this.values.map(conv));
    return { changes: Number(result.changes) };
  }
}
const conv = (value: unknown) =>
  (value instanceof ArrayBuffer ? new Uint8Array(value) : value) as never;

export interface IdentityD1 extends D1Like {
  readonly database: DatabaseSync;
  readonly rollbacks: () => number;
}

/** A database with every locked migration, as the migration runner would leave it. Pass a file to let two handles share one database. */
export function openIdentityD1(file = ":memory:", migrate = true): IdentityD1 {
  const database = new DatabaseSync(file);
  database.exec("PRAGMA busy_timeout = 5000");
  if (file !== ":memory:") database.exec("PRAGMA synchronous = OFF");
  if (migrate)
    for (const name of readdirSync(migrationsDirectory)
      .filter((entry) => /^\d{4}_.+\.sql$/u.test(entry))
      .sort())
      database.exec(readFileSync(path.join(migrationsDirectory, name), "utf8"));
  let rolledBack = 0;
  return {
    database,
    rollbacks: () => rolledBack,
    prepare: (sql) => new Stmt(database, sql),
    async batch(statements: D1PreparedStatement[]): Promise<D1RunResult[]> {
      database.exec("BEGIN IMMEDIATE");
      try {
        const results = statements.map((statement) => ({ meta: (statement as Stmt).run() }));
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

export type RunOutcome =
  { ok: true; changes: string; rows: string[][] } | { ok: false; failure: string };

export async function runPlan(
  db: D1Like,
  planId: string,
  args: D1Scalar[][],
  ownerScope: string,
): Promise<RunOutcome> {
  const deps: ExecuteDeps = {
    db,
    plans: identityPlans,
    manifestHash,
    recoveryGeneration: "0",
    nowMs: () => nowMs,
  };
  const response = await executePlan(
    {
      planId,
      planVersion: plans.find((plan) => plan.id === planId)!.version,
      manifestHash,
      requestId: uid(),
      recoveryGeneration: "0",
      ownerScope,
      arguments: args,
      deadlineUtc: new Date(nowMs + 5_000).toISOString().replace(/\.(\d{3})Z$/u, ".$10000Z"),
    },
    deps,
  );
  if ("failure" in response) return { ok: false, failure: response.failure };
  return {
    ok: true,
    changes: response.changes,
    rows: response.rows.map((row) =>
      row.map((value) => ("value" in value ? String(value.value) : "null")),
    ),
  };
}

export const enrollmentPlan = "families.account-enrollment.create-user";

// ---------------------------------------------------------------------------------------------------------------------------
// Scenario helpers
// ---------------------------------------------------------------------------------------------------------------------------

export interface Account {
  realm: string;
  user: string;
  workspace: string;
  credential: CredentialInput;
}

export function tailInputs(overrides: Partial<TailInputs> = {}): TailInputs {
  return {
    command: uid(),
    now: nowMicros,
    outbox: uid(),
    correlation: uid(),
    causation: null,
    schema: 23,
    ...overrides,
  };
}

export function credential(
  user: string,
  realm: string,
  subject: string,
  overrides: Partial<CredentialInput> = {},
): CredentialInput {
  return {
    credentialId: uid(),
    user,
    realm,
    provider: "official-email",
    method: 2,
    subject,
    label: null,
    passkey: null,
    password: null,
    createdAt: nowMicros,
    ...overrides,
  };
}

export function enrollInputs(
  realm: string,
  subject: string,
  overrides: Partial<EnrollInputs> = {},
): EnrollInputs {
  const user = overrides.user ?? uid();
  return {
    ...tailInputs(),
    realm,
    user,
    workspace: uid(),
    credential: credential(user, realm, subject),
    displayName: "Ada",
    workspaceName: "Personal",
    region: "Automatic",
    ...overrides,
  };
}

/** Enrolls an account through the family and returns what the tests need to continue from it. */
export async function enroll(
  db: D1Like,
  realm: string,
  subject: string,
  overrides: Partial<EnrollInputs> = {},
): Promise<Account> {
  const inputs = enrollInputs(realm, subject, overrides);
  const result = await runPlan(db, enrollmentPlan, enrollArguments(inputs), inputs.workspace);
  if (!result.ok) throw new Error(`enrollment refused: ${result.failure}`);
  return {
    realm,
    user: inputs.user,
    workspace: inputs.workspace,
    credential: inputs.credential,
  };
}

export const count = (db: IdentityD1, table: string, where = "1 = 1") =>
  Number(
    (
      db.database.prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE ${where}`).get() as {
        n: number;
      }
    ).n,
  );

export const rows = (db: IdentityD1, sql: string): unknown[][] => {
  const statement = db.database.prepare(sql);
  statement.setReturnArrays(true);
  return statement.all() as unknown as unknown[][];
};

/** Every identity and workspace row as plain text, to compare "nothing changed". */
export function snapshotIdentity(db: IdentityD1): unknown {
  const q = (sql: string) => rows(db, sql);
  return {
    users: q("SELECT * FROM identity_user ORDER BY user_id"),
    credentials: q("SELECT * FROM identity_auth_identity ORDER BY auth_identity_id"),
    workspaces: q("SELECT * FROM workspace_workspace ORDER BY workspace_id"),
    commands: q(
      "SELECT command_id, operation, request_hash FROM platform_command ORDER BY command_id",
    ),
    outbox: q("SELECT outbox_id, event_type, payload FROM platform_outbox ORDER BY outbox_id"),
    archive: q(
      "SELECT archive_sequence, command_id FROM platform_change_archive ORDER BY archive_sequence",
    ),
    guards: q("SELECT * FROM platform_command_guard"),
  };
}
