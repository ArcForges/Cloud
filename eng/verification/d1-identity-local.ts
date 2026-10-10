// SPDX-License-Identifier: AGPL-3.0-only
// Explicit local opt-in run (npm run test:d1:identity:local): the identity core plans and the enrollment family executed through the
// production Worker executor against workerd's D1 under Miniflare, on the real numbered migrations applied by the real runner. It is
// the closest engine to D1 that exists without a Cloudflare account, and it repeats the cases that depend on the engine: a family
// batch whose statements run in the fixed order under D1's immediate foreign-key enforcement (the user row before its credential and
// workspace), the whole-batch rollback of a false guard, and simultaneous writers through the binding (several "Containers" enrolling
// or linking the same credential, revoking a user's last two credentials) committing exactly once.
// Transcript mode (CLOUD.72): the identity store's plan calls exactly as C# built them, recorded with the SQLite oracle's answers by
// tests/ArcForges.Cloud.Tests/Identity/IdentityStoreTranscriptTests.cs into tests/ArcForges.Cloud.Tests/Identity/Vectors/
// identity-store-transcript.json, are executed in order through the same production Worker executor on a fresh workerd D1, and each
// answer (status, changes, rows) and the row counts after each step are compared with the recorded ones generically; a concurrent group
// is executed simultaneously and compared as a multiset. The transcript carries no TypeScript business assertion: what the calls mean is
// decided and asserted in C#; this run only shows that workerd's D1 answers C#-built calls as the oracle did.
// It is NOT a Cloudflare provider result: no deployed D1, no network path, no provider limit and no REST batch are exercised (the
// provider's REST batch atomicity stays a deferred live check under the RES-cloud-deployment lease, and CLOUD.70 owns the deployment
// migration step). Never CI; it starts local workerd, reads no credential and writes an evidence file under artifacts/.
import assert from "node:assert/strict";
import type { D1Scalar, ExecutePlanResponse } from "@arcforges/ai-internal";
import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { loadCatalog } from "../migrations/catalog.ts";
import { D1BindingMigrationClient, type D1BindingLike } from "../migrations/clients.ts";
import { applyPending } from "../migrations/runner.ts";
import type { D1Like } from "../../worker/storage/d1.ts";
import { executePlan, planKey } from "../../worker/storage/execute-plan.ts";
import { manifestHash, plans } from "../../worker/storage/plans.generated.ts";
import {
  addArguments,
  credential,
  enrollArguments,
  enrollInputs,
  enrollmentPlan,
  nowMicros,
  realmA,
  realmB,
  revokeArguments,
  runPlan,
  tailInputs,
  uid,
  type Account,
} from "../../tests/worker/support/identity-support.ts";

const root = path.resolve(import.meta.dirname, "../..");
const compat = {
  sourceRevision: process.env.SOURCE_REVISION ?? "local",
  planManifestHash: "local",
  abi: "local",
  runtime: "workerd-local",
};
const migrations = loadCatalog();

interface Result {
  name: string;
  status: "passed" | "failed";
  detail: string;
  millis: number;
}
const results: Result[] = [];

async function scenario(name: string, run: () => Promise<string>): Promise<void> {
  const started = Date.now();
  try {
    const detail = await run();
    results.push({ name, status: "passed", detail, millis: Date.now() - started });
  } catch (error) {
    results.push({
      name,
      status: "failed",
      detail: error instanceof Error ? error.message : String(error),
      millis: Date.now() - started,
    });
  }
}

type D1 = D1BindingLike & {
  prepare(sql: string): {
    bind(...values: unknown[]): {
      run(): Promise<unknown>;
      raw(): Promise<unknown[][]>;
    };
  };
  batch(statements: unknown[]): Promise<unknown[]>;
};

async function database(mf: Miniflare, binding: string): Promise<D1> {
  const db = (await mf.getD1Database(binding)) as unknown as D1;
  await applyPending({
    client: new D1BindingMigrationClient(db),
    migrations,
    runner: `local-${binding}`,
    now: Date.now,
    compatibility: compat,
  });
  return db;
}

const count = async (db: D1, table: string, where = "1 = 1") =>
  Number((await db.prepare(`SELECT COUNT(*) FROM ${table} WHERE ${where}`).bind().raw())[0]?.[0]);

const refused = { ok: false, failure: "precondition" } as const;

async function enroll(db: D1, subject: string, realm = realmA): Promise<Account> {
  const inputs = enrollInputs(realm, subject);
  const result = await runPlan(
    db as never,
    enrollmentPlan,
    enrollArguments(inputs),
    inputs.workspace,
  );
  assert.equal(result.ok, true, JSON.stringify(result));
  return { realm, user: inputs.user, workspace: inputs.workspace, credential: inputs.credential };
}

function addCall(account: Account, subject: string, userRevision: number) {
  const next = credential(account.user, account.realm, subject);
  return {
    next,
    args: addArguments({
      ...tailInputs(),
      realm: account.realm,
      user: account.user,
      scope: account.workspace,
      expectedUserRevision: userRevision,
      credential: next,
    }),
  };
}

// ---------------------------------------------------------------------------------------------------------------------------
// Transcript mode: C#-built calls replayed generically
// ---------------------------------------------------------------------------------------------------------------------------

export const transcriptPath = path.join(
  root,
  "tests",
  "ArcForges.Cloud.Tests",
  "Identity",
  "Vectors",
  "identity-store-transcript.json",
);

export interface TranscriptCall {
  plan: string;
  version: number;
  ownerScope: string;
  recoveryGeneration: string;
  arguments: D1Scalar[][];
}

export type TranscriptOutcome =
  { status: "ok"; changes: string; rows: D1Scalar[][] } | { status: string };

export interface TranscriptStep {
  scenario: string;
  call?: TranscriptCall;
  expect?: TranscriptOutcome;
  group?: TranscriptCall[];
  outcomes?: TranscriptOutcome[];
  counts: number[];
}

export interface Transcript {
  schemaVersion: number;
  recoveryGeneration: string;
  tables: string[];
  steps: TranscriptStep[];
}

const plainIdentifier = /^[a-z][a-z0-9_]*$/u;

/** Structural checks only: the shape the C# generator writes, and table names that can be counted safely. */
export function parseTranscript(text: string): Transcript {
  const value = JSON.parse(text) as Transcript;
  assert.equal(value.schemaVersion, 1, "unknown transcript schema version");
  assert.match(value.recoveryGeneration, /^\d+$/u);
  assert.ok(
    Array.isArray(value.tables) && value.tables.length > 0,
    "the transcript names no table",
  );
  for (const table of value.tables) assert.match(table, plainIdentifier);
  assert.ok(Array.isArray(value.steps) && value.steps.length > 0, "the transcript has no step");
  for (const [index, step] of value.steps.entries()) {
    const single = step.call !== undefined && step.expect !== undefined;
    const group = Array.isArray(step.group) && Array.isArray(step.outcomes);
    assert.ok(single !== group, `step ${index} is neither one call nor one group`);
    if (group) assert.equal(step.group?.length, step.outcomes?.length, `step ${index}`);
    assert.equal(step.counts.length, value.tables.length, `step ${index} counts`);
  }
  return value;
}

/** Key-sorted JSON, so outcomes compare as values whichever side serialized them. */
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`)
      .join(",")}}`;
  return JSON.stringify(value);
}

function outcomeOf(response: ExecutePlanResponse): TranscriptOutcome {
  return "failure" in response
    ? { status: response.failure }
    : { status: "ok", changes: response.changes, rows: response.rows };
}

const transcriptPlans = new Map(plans.map((plan) => [planKey(plan.id, plan.version), plan]));

async function executeCall(
  db: D1Like,
  call: TranscriptCall,
  generation: string,
): Promise<TranscriptOutcome> {
  const response = await executePlan(
    {
      planId: call.plan,
      planVersion: call.version,
      manifestHash,
      requestId: randomUUID(),
      recoveryGeneration: call.recoveryGeneration,
      ownerScope: call.ownerScope,
      arguments: call.arguments,
      deadlineUtc: new Date(Date.now() + 5_000).toISOString().replace(/\.(\d{3})Z$/u, ".$10000Z"),
    },
    { db, plans: transcriptPlans, manifestHash, recoveryGeneration: generation, nowMs: Date.now },
  );
  return outcomeOf(response);
}

async function tableCounts(db: D1Like, tables: string[]): Promise<number[]> {
  const row = (
    await db
      .prepare(`SELECT ${tables.map((table) => `(SELECT COUNT(*) FROM ${table})`).join(", ")}`)
      .bind()
      .raw()
  )[0];
  return (row ?? []).map(Number);
}

/** Replays every step on the database and fails at the first answer or count that differs from the transcript. */
export async function replayTranscript(db: D1Like, transcript: Transcript): Promise<string> {
  let calls = 0;
  let groups = 0;
  for (const [index, step] of transcript.steps.entries()) {
    const where = `step ${index} (${step.scenario})`;
    if (step.call && step.expect) {
      const actual = await executeCall(db, step.call, transcript.recoveryGeneration);
      assert.equal(canonical(actual), canonical(step.expect), `${where} ${step.call.plan}`);
      calls++;
    } else {
      const members = step.group ?? [];
      const actual = await Promise.all(
        members.map((call) => executeCall(db, call, transcript.recoveryGeneration)),
      );
      assert.deepEqual(
        actual.map(canonical).sort(),
        (step.outcomes ?? []).map(canonical).sort(),
        `${where}: concurrent group of ${members.length}`,
      );
      calls += members.length;
      groups++;
    }
    assert.deepEqual(await tableCounts(db, transcript.tables), step.counts, `${where} row counts`);
  }
  return `${calls} C#-built plan calls in ${transcript.steps.length} steps (${groups} concurrent groups) answered with the recorded statuses, changes and rows, and the row counts of ${transcript.tables.length} tables matched after every step`;
}

export async function main(): Promise<void> {
  assert.notEqual(process.env.CI, "true", "The local D1 run is opt-in, never CI.");
  const started = new Date().toISOString();
  const mf = new Miniflare(
    convertV4MiniflareOptions({
      modules: true,
      script: "export default { fetch() { return new Response('ok'); } };",
      compatibilityDate: "2026-09-15",
      host: "127.0.0.1",
      port: 0,
      d1Databases: {
        BASIC: "identity-basic",
        ENROLL: "identity-enroll",
        LINK: "identity-link",
        REVOKE: "identity-revoke",
        TRANSCRIPT: "identity-transcript",
      },
    }),
  );
  try {
    await mf.ready;

    await scenario(
      "an-enrollment-commits-in-family-order-under-immediate-foreign-keys",
      async () => {
        const db = await database(mf, "BASIC");
        const account = await enroll(db, "ada@example.test");
        assert.equal(await count(db, "identity_user", `user_id = '${account.user}'`), 1);
        assert.equal(await count(db, "identity_auth_identity", `user_id = '${account.user}'`), 1);
        assert.equal(
          await count(db, "workspace_workspace", `owner_user_id = '${account.user}'`),
          1,
        );
        assert.equal(await count(db, "platform_command"), 1);
        assert.equal(await count(db, "platform_outbox"), 1);
        assert.equal(await count(db, "platform_change_archive"), 1);
        assert.equal(await count(db, "platform_command_guard"), 0, "the release left no guard row");
        const again = enrollInputs(realmA, "ada@example.test");
        assert.deepEqual(
          await runPlan(db as never, enrollmentPlan, enrollArguments(again), again.workspace),
          refused,
        );
        const otherRealm = await enroll(db, "ada@example.test", realmB);
        assert.notEqual(otherRealm.user, account.user);
        assert.equal(await count(db, "identity_user"), 2);
        assert.equal(await count(db, "platform_command_guard"), 0);
        return "the user row precedes its credential and workspace in one batch under D1's immediate foreign keys; a second enrollment of the credential is refused whole as precondition; the same subject in another realm enrolls separately";
      },
    );

    await scenario("simultaneous-enrollments-of-one-credential-commit-exactly-once", async () => {
      const db = await database(mf, "ENROLL");
      const rounds = 25;
      const contenders = 4;
      for (let round = 0; round < rounds; round++) {
        const subject = `race-${round}@example.test`;
        const outcomes = await Promise.all(
          Array.from({ length: contenders }, () => {
            const inputs = enrollInputs(realmA, subject);
            return runPlan(db as never, enrollmentPlan, enrollArguments(inputs), inputs.workspace);
          }),
        );
        assert.equal(
          outcomes.filter((o) => o.ok).length,
          1,
          `round ${round}: ${JSON.stringify(outcomes)}`,
        );
        assert.equal(
          outcomes.filter((o) => !o.ok && o.failure === "precondition").length,
          contenders - 1,
        );
        assert.equal(await count(db, "identity_auth_identity", `subject = '${subject}'`), 1);
      }
      assert.equal(await count(db, "identity_user"), rounds);
      assert.equal(await count(db, "workspace_workspace"), rounds);
      assert.equal(await count(db, "platform_command_guard"), 0);
      return `${rounds} rounds of ${contenders} simultaneous enrollments of one credential: ${rounds} users and ${rounds} workspaces, ${rounds * (contenders - 1)} whole-batch precondition refusals`;
    });

    await scenario("simultaneous-links-of-one-credential-to-two-users-commit-once", async () => {
      const db = await database(mf, "LINK");
      const ada = await enroll(db, "ada@example.test");
      const bob = await enroll(db, "bob@example.test");
      const rounds = 25;
      for (let round = 0; round < rounds; round++) {
        const subject = `shared-${round}`;
        const [first, second] = [
          addCall(ada, subject, 1 + round),
          addCall(bob, subject, 1 + round),
        ];
        // Both decided from the same read: each user's revision is the one it holds now, and only one writer may take the subject.
        const outcomes = await Promise.all([
          runPlan(db as never, "identity.credential-add", first.args, ada.workspace),
          runPlan(db as never, "identity.credential-add", second.args, bob.workspace),
        ]);
        assert.equal(
          outcomes.filter((o) => o.ok).length,
          1,
          `round ${round}: ${JSON.stringify(outcomes)}`,
        );
        const winner = outcomes[0]?.ok ? ada : bob;
        const loser = winner === ada ? bob : ada;
        const loserRev = Number(
          (
            await db
              .prepare(`SELECT rev FROM identity_user WHERE user_id = '${loser.user}'`)
              .bind()
              .raw()
          )[0]?.[0],
        );
        // Bring the loser's revision in step so the next round's expectations hold for both users.
        const catchUp = addCall(loser, `catch-up-${round}`, loserRev);
        assert.equal(
          (await runPlan(db as never, "identity.credential-add", catchUp.args, loser.workspace)).ok,
          true,
        );
        assert.equal(await count(db, "identity_auth_identity", `subject = '${subject}'`), 1);
      }
      return `${rounds} rounds of two users linking one credential from the same read: exactly one owner every time, never two`;
    });

    await scenario("simultaneous-revocations-never-leave-a-user-without-a-credential", async () => {
      const db = await database(mf, "REVOKE");
      const rounds = 25;
      for (let round = 0; round < rounds; round++) {
        const account = await enroll(db, `revoke-${round}@example.test`);
        const second = addCall(account, `second-${round}`, 1);
        assert.equal(
          (await runPlan(db as never, "identity.credential-add", second.args, account.workspace))
            .ok,
          true,
        );
        const revoke = (target: string) =>
          runPlan(
            db as never,
            "identity.credential-revoke",
            revokeArguments({
              ...tailInputs(),
              realm: account.realm,
              user: account.user,
              scope: account.workspace,
              target,
              expectedCredentialRevision: 1,
              expectedUserRevision: 2,
              at: nowMicros + 1_000_000,
            }),
            account.workspace,
          );
        const outcomes = await Promise.all([
          revoke(account.credential.credentialId),
          revoke(second.next.credentialId),
        ]);
        assert.equal(
          outcomes.filter((o) => o.ok).length,
          1,
          `round ${round}: ${JSON.stringify(outcomes)}`,
        );
        assert.equal(
          await count(
            db,
            "identity_auth_identity",
            `user_id = '${account.user}' AND revoked_at IS NULL`,
          ),
          1,
        );
      }
      // The last credential is refused even when every guard reads current values.
      const solo = await enroll(db, "solo@example.test");
      const last = await runPlan(
        db as never,
        "identity.credential-revoke",
        revokeArguments({
          ...tailInputs(),
          realm: solo.realm,
          user: solo.user,
          scope: solo.workspace,
          target: solo.credential.credentialId,
          expectedCredentialRevision: 1,
          expectedUserRevision: 1,
          at: nowMicros,
        }),
        solo.workspace,
      );
      assert.deepEqual(last, refused);
      assert.equal(await count(db, "platform_command_guard"), 0);
      void uid;
      return `${rounds} rounds of two simultaneous revocations of a user's only two credentials: one committed, one refused, one credential always remained; the last credential is refused`;
    });

    await scenario(
      "the-csharp-store-transcript-replays-on-workerd-d1-as-on-the-oracle",
      async () => {
        const transcript = parseTranscript(await readFile(transcriptPath, "utf8"));
        return replayTranscript((await database(mf, "TRANSCRIPT")) as never, transcript);
      },
    );
  } finally {
    await mf.dispose();
  }

  const failed = results.filter((entry) => entry.status === "failed");
  const report = {
    startedAt: started,
    finishedAt: new Date().toISOString(),
    kind: "local-emulation",
    cloudflareResult: false,
    sourceRevision: compat.sourceRevision,
    transcriptSha256: createHash("sha256")
      .update(await readFile(transcriptPath))
      .digest("hex"),
    emulated: "workerd D1 (SQLite) under Miniflare through the production Worker plan executor",
    notEmulated:
      "Cloudflare provider network path, REST batch semantics, real D1 limits and latency, a deployed database",
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    results,
  };
  const outDirectory = path.join(root, "artifacts", "d1-identity-local");
  await mkdir(outDirectory, { recursive: true });
  await writeFile(path.join(outDirectory, "evidence.json"), `${JSON.stringify(report, null, 2)}\n`);
  for (const entry of results)
    process.stdout.write(
      `${entry.status === "passed" ? "PASS" : "FAIL"} ${entry.name} (${entry.millis} ms): ${entry.detail}\n`,
    );
  if (failed.length > 0) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === import.meta.filename) {
  main().catch((error: unknown) => {
    process.stderr.write(
      `${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`,
    );
    process.exitCode = 1;
  });
}
