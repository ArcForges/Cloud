// SPDX-License-Identifier: AGPL-3.0-only
// Explicit local opt-in run (npm run test:d1:entitlement:local): the Entitlement named plans (COM.16) and the real numbered migrations
// executed through the production Worker executor against workerd's D1 under Miniflare, the closest engine to D1 that exists without a
// Cloudflare account. It proves on that engine the atomic commit of records, snapshot, receipt, outbox row and change record, that a stale
// revision commits nothing, that simultaneous first commits and simultaneous writers on one revision commit exactly once, that a
// constraint anywhere in the batch (a foreign key, the GR-05 reason column) rolls everything back, the append-only triggers and the
// keyset paging of a long history.
// It is NOT a Cloudflare provider result: no deployed D1, no network path, no provider limit and no REST batch are exercised (the
// provider's REST batch atomicity stays a deferred live check under the RES-cloud-deployment lease, with CLOUD.70). Never CI; it starts
// local workerd, reads no credential and writes an evidence file under artifacts/.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { loadCatalog } from "../migrations/catalog.ts";
import { D1BindingMigrationClient, type D1BindingLike } from "../migrations/clients.ts";
import { applyPending } from "../migrations/runner.ts";
import { execute } from "../../tests/worker/support/commit-support.ts";
import { i64, txt } from "../../tests/worker/support/plan-calls.ts";
import {
  commitArguments,
  grant,
  id,
  workspace,
  type Records,
} from "../../tests/worker/support/entitlement-fixtures.ts";

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

const raw = async (db: D1, sql: string) => db.prepare(sql).bind().raw();
const count = async (db: D1, table: string, where = "1 = 1") =>
  Number((await raw(db, `SELECT COUNT(*) FROM ${table} WHERE ${where}`))[0]?.[0]);
const run = (db: D1, args: ReturnType<typeof commitArguments>) =>
  execute(db as never, "entitlement.commit", args, workspace);
const revisionOf = async (db: D1) =>
  Number((await raw(db, `SELECT COALESCE((SELECT rev FROM entitlement_revision), 0)`))[0]?.[0]);

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
        ATOMIC: "entitlement-atomic",
        FIRST: "entitlement-first",
        CONTEND: "entitlement-contend",
        ROLLBACK: "entitlement-rollback",
        PAGES: "entitlement-pages",
      },
    }),
  );
  try {
    await mf.ready;

    await scenario(
      "a-commit-writes-records-snapshot-receipt-outbox-and-archive-together",
      async () => {
        const db = await database(mf, "ATOMIC");
        const records: Records = {
          grants: [
            grant(1, {
              source: 5,
              reason: "operator action for ticket 42",
              sourceRef: "ticket-42",
            }),
          ],
          activations: [{ version: "bundle-1", activatedAt: "10" }],
          facts: [
            {
              id: id(0x82),
              recordedAt: "11",
              status: 2,
              autoRenew: 0,
              purchasePending: 1,
              sourceRef: "status-1",
            },
          ],
        };
        const outcome = await run(db, commitArguments(workspace, id(0x1001), 0, records));
        assert.equal(outcome.ok, true, JSON.stringify(outcome));
        assert.equal(await count(db, "entitlement_grant"), 1);
        assert.equal(await count(db, "entitlement_snapshot"), 1);
        assert.equal(await count(db, "platform_command", "result_rev = 1"), 1);
        assert.equal(await count(db, "platform_outbox"), 1);
        assert.equal(await count(db, "platform_outbox_position", `stream_key = '${workspace}'`), 1);
        assert.equal(await count(db, "platform_change_archive"), 1);
        assert.equal(await count(db, "platform_command_guard"), 0, "the release left no guard row");
        assert.equal(await revisionOf(db), 1);
        const reason = await raw(db, "SELECT reason FROM entitlement_grant");
        assert.equal(reason[0]?.[0], "operator action for ticket 42");
        return "grant with its reason, activation, status fact, snapshot, receipt, outbox row, position and change record committed in one batch; revision 1; no guard row left";
      },
    );

    await scenario("a-stale-revision-commits-nothing", async () => {
      const db = await database(mf, "ATOMIC");
      const before = await count(db, "platform_command");
      const stale = await run(
        db,
        commitArguments(workspace, id(0x1002), 0, { grants: [grant(2)] }),
      );
      assert.deepEqual(stale, { ok: false, failure: "precondition" });
      assert.equal(await count(db, "entitlement_grant"), 1);
      assert.equal(await count(db, "platform_command"), before);
      assert.equal(await count(db, "platform_command_guard"), 0);
      const phantom = await run(
        db,
        commitArguments(workspace, id(0x1003), 9, { grants: [grant(3)] }),
      );
      assert.deepEqual(phantom, { ok: false, failure: "precondition" });
      return "a writer that read revision 0 after revision 1 existed, and one that named a revision that never existed, were each refused whole as a precondition";
    });

    await scenario("simultaneous-first-commits-create-the-revision-row-exactly-once", async () => {
      const db = await database(mf, "FIRST");
      assert.equal(await count(db, "entitlement_revision"), 0);
      const contenders = 4;
      const outcomes = await Promise.all(
        Array.from({ length: contenders }, (_, index) =>
          run(
            db,
            commitArguments(workspace, id(0x2000 + index), 0, { grants: [grant(0x10 + index)] }),
          ),
        ),
      );
      const wins = outcomes.filter((outcome) => outcome.ok).length;
      const refused = outcomes.filter(
        (outcome) => !outcome.ok && outcome.failure === "precondition",
      ).length;
      assert.equal(wins, 1, JSON.stringify(outcomes));
      assert.equal(refused, contenders - 1);
      assert.equal(await revisionOf(db), 1);
      assert.equal(await count(db, "entitlement_grant"), 1);
      assert.equal(await count(db, "platform_command"), 1);
      return `${contenders} simultaneous first commits of an empty workspace: one created the row and committed, ${contenders - 1} were refused as a precondition`;
    });

    await scenario("concurrent-writers-commit-exactly-once-per-revision", async () => {
      const db = await database(mf, "CONTEND");
      const rounds = 25;
      const contenders = 4;
      let committed = 0;
      let serial = 0x100;
      for (let round = 0; round < rounds; round++) {
        const state = await revisionOf(db);
        const outcomes = await Promise.all(
          Array.from({ length: contenders }, (_, _index) => {
            const n = ++serial;
            return run(
              db,
              commitArguments(workspace, id(0x3000 + n), state, { grants: [grant(n)] }),
            );
          }),
        );
        const wins = outcomes.filter((outcome) => outcome.ok).length;
        const refused = outcomes.filter(
          (outcome) => !outcome.ok && outcome.failure === "precondition",
        ).length;
        assert.equal(wins, 1, `round ${round}: ${JSON.stringify(outcomes)}`);
        assert.equal(refused, contenders - 1, `round ${round}`);
        assert.equal(await revisionOf(db), state + 1);
        committed += wins;
      }
      assert.equal(await count(db, "platform_command"), committed);
      assert.equal(await count(db, "entitlement_grant"), committed);
      assert.equal(await count(db, "platform_command_guard"), 0);
      return `${rounds} rounds of ${contenders} simultaneous writers on one revision: ${committed} commits, ${rounds * (contenders - 1)} whole-batch precondition refusals, no lost or doubled grant`;
    });

    await scenario("a-constraint-anywhere-in-the-batch-rolls-everything-back", async () => {
      const db = await database(mf, "ROLLBACK");
      const tables = [
        "entitlement_grant",
        "entitlement_revocation",
        "entitlement_snapshot",
        "entitlement_revision",
        "platform_command",
        "platform_outbox",
        "platform_change_archive",
        "platform_command_guard",
      ];
      const orphan = {
        id: id(0x50),
        grantId: id(0xdead),
        reasonCode: "refund",
        from: "6",
        actor: "operator",
        createdAt: "6",
      };
      assert.deepEqual(
        await run(
          db,
          commitArguments(workspace, id(0x4001), 0, { grants: [grant(1)], revocations: [orphan] }),
        ),
        { ok: false, failure: "constraint" },
      );
      for (const source of [5, 6, 7])
        assert.deepEqual(
          await run(
            db,
            commitArguments(workspace, id(0x4002), 0, {
              grants: [grant(2, { source, reason: null, sourceRef: "t" })],
            }),
          ),
          { ok: false, failure: "constraint" },
          `source ${source} needs a reason`,
        );
      assert.deepEqual(
        await run(
          db,
          commitArguments(workspace, id(0x4003), 0, {
            grants: [grant(3, { source: 5, reason: "x".repeat(513), sourceRef: "t" })],
          }),
        ),
        { ok: false, failure: "constraint" },
      );
      const stranger = id(0xb9);
      const term = {
        id: id(0x71),
        realmId: id(0xc1),
        kind: 1,
        subscriptionRef: "s",
        periodRef: "p",
        startsAt: "0",
        endsAt: "10",
        graceEndsAt: null,
        supersedesId: null,
        offerId: id(0xc2),
        offerSnapshotId: id(0xc3),
        authorizedAt: "0",
        selectionPriority: "0",
        createdAt: "1",
      };
      assert.deepEqual(
        await execute(
          db as never,
          "entitlement.commit",
          commitArguments(stranger, id(0x4004), 0, { terms: [term] }),
          stranger,
        ),
        { ok: false, failure: "constraint" },
        "D1 enforces the foreign key to the workspace",
      );
      for (const table of tables) assert.equal(await count(db, table), 0, table);
      return "an orphan revocation, each operator source without a reason, an over-long reason and a term of an unknown workspace each rolled the whole batch back as a constraint; every table stayed empty";
    });

    await scenario("append-only-triggers-refuse-update-and-delete", async () => {
      const db = await database(mf, "ATOMIC");
      for (const statement of [
        "UPDATE entitlement_grant SET subject = 'x'",
        "DELETE FROM entitlement_grant",
        "UPDATE entitlement_definitions_activation SET definitions_version = 'x'",
        "DELETE FROM entitlement_workspace_status_fact",
      ]) {
        await assert.rejects(db.prepare(statement).bind().run(), /af_immutable/u, statement);
      }
      assert.equal(await count(db, "entitlement_grant"), 1);
      return "update and delete of grants, activations and status facts refused by the append-only triggers";
    });

    await scenario("a-long-history-pages-by-keyset-without-skipping-or-repeating", async () => {
      const db = await database(mf, "PAGES");
      let revision = 0;
      let serial = 0;
      for (const batch of [100, 100, 30]) {
        const grants = Array.from({ length: batch }, () => {
          const n = ++serial;
          return grant(0x5000 + n, {
            from: String(n),
            sourceRef: `bulk-${n}`,
            source: 6,
            reason: "bulk",
          });
        });
        const outcome = await run(
          db,
          commitArguments(workspace, id(0x6000 + revision), revision, { grants }),
        );
        assert.equal(outcome.ok, true, JSON.stringify(outcome));
        revision++;
      }
      const seen: string[] = [];
      let cursor = { kind: 0, from: "-9223372036854775808", grantId: "" };
      for (;;) {
        const page = await execute(
          db as never,
          "entitlement.grants-load",
          [
            [
              { kind: "text", value: workspace },
              i64(cursor.kind),
              i64(cursor.from),
              txt(cursor.grantId),
            ],
          ],
          workspace,
        );
        assert.equal(page.ok, true);
        const rows = page.ok ? page.rows : [];
        seen.push(...rows.map((row) => row[0] as string));
        if (rows.length < 100) break;
        const last = rows[rows.length - 1] as string[];
        cursor = { kind: Number(last[1]), from: last[6] as string, grantId: last[0] as string };
      }
      assert.equal(seen.length, 230);
      assert.equal(new Set(seen).size, 230);
      assert.deepEqual(
        [...seen].sort(),
        Array.from({ length: 230 }, (_, i) => id(0x5000 + i + 1)).sort(),
      );
      return "230 grants read in three keyset pages in plan order, none skipped and none repeated";
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
  const outDirectory = path.join(root, "artifacts", "d1-entitlement-local");
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
