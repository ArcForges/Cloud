// SPDX-License-Identifier: AGPL-3.0-only
// Explicit local opt-in run (npm run test:d1:identity:local): the identity core plans and the enrollment family executed through the
// production Worker executor against workerd's D1 under Miniflare, on the real numbered migrations applied by the real runner. It is
// the closest engine to D1 that exists without a Cloudflare account, and it repeats the cases that depend on the engine: a family
// batch whose statements run in the fixed order under D1's immediate foreign-key enforcement (the user row before its credential and
// workspace), the whole-batch rollback of a false guard, and simultaneous writers through the binding (several "Containers" enrolling
// or linking the same credential, revoking a user's last two credentials) committing exactly once.
// It is NOT a Cloudflare provider result: no deployed D1, no network path, no provider limit and no REST batch are exercised (the
// provider's REST batch atomicity stays a deferred live check under the RES-cloud-deployment lease, and CLOUD.70 owns the deployment
// migration step). Never CI; it starts local workerd, reads no credential and writes an evidence file under artifacts/.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { loadCatalog } from "../migrations/catalog.ts";
import { D1BindingMigrationClient, type D1BindingLike } from "../migrations/clients.ts";
import { applyPending } from "../migrations/runner.ts";
import { i64, txt } from "../../tests/worker/support/plan-calls.ts";
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
        const found = await runPlan(
          db as never,
          "identity.credential-find",
          [[txt(realmA), txt(account.credential.provider), txt(account.credential.subject)]],
          realmA,
        );
        assert.equal(found.ok, true);
        if (found.ok)
          assert.equal(found.rows[0]?.length, 23, "the complete credential and user projection");
        const listed = await runPlan(
          db as never,
          "identity.credential-list",
          [[txt(realmA), txt(account.user), i64("-9223372036854775808"), txt("")]],
          realmA,
        );
        assert.equal(listed.ok, true);
        if (listed.ok)
          assert.equal(listed.rows[0]?.length, 18, "the complete credential page projection");
        const home = await runPlan(
          db as never,
          "workspace.workspace-load",
          [[txt(realmA), txt(account.workspace)]],
          account.workspace,
        );
        assert.equal(home.ok, true);
        if (home.ok) assert.equal(home.rows[0]?.length, 8, "the complete workspace projection");
        const foreign = await runPlan(
          db as never,
          "workspace.workspace-by-owner",
          [[txt(realmB), txt(account.user)]],
          realmB,
        );
        assert.deepEqual(foreign, { ok: true, changes: "0", rows: [] });
        const recovery = await runPlan(
          db as never,
          "identity.recovery-active",
          [[txt(realmA), txt(account.user)]],
          realmA,
        );
        assert.deepEqual(recovery, { ok: true, changes: "0", rows: [["false"]] });
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
  } finally {
    await mf.dispose();
  }

  const failed = results.filter((entry) => entry.status === "failed");
  const report = {
    startedAt: started,
    finishedAt: new Date().toISOString(),
    kind: "local-emulation",
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
