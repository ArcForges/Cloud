// SPDX-License-Identifier: AGPL-3.0-only
// Explicit local opt-in run (npm run test:d1:families:local): a fixture shared family (generated guards and mutations, the guard table
// and the real numbered migrations) executed through the production Worker executor against workerd's D1 under Miniflare, the closest
// engine to D1 that exists without a Cloudflare account. It proves on that engine that a false guard rolls the whole batch back and is
// classified as a failed precondition, that a constraint after passing guards rolls the guarded mutations back, that concurrent
// writers through the binding commit exactly once per revision (two or more "Containers" contend), that a stale lease holder cannot
// finalize and that balances compare exactly above 2^53.
// It is NOT a Cloudflare provider result: no deployed D1, no network path, no provider limit and no REST batch are exercised (the
// provider's REST batch atomicity stays a deferred live check under the RES-cloud-deployment lease). Never CI; it starts local workerd,
// reads no credential and writes an evidence file under artifacts/. The fixture family is a test fixture, not a Design family.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { loadCatalog } from "../migrations/catalog.ts";
import { D1BindingMigrationClient, type D1BindingLike } from "../migrations/clients.ts";
import { applyPending } from "../migrations/runner.ts";
import {
  defaults,
  fixtureArguments,
  fixtureManifest,
  ids,
  nowMicros,
  runFamily,
  seedStatements,
  snapshotQueries,
  workerDictionary,
  type FixtureValues,
  type SeedOverrides,
} from "../../tests/worker/support/family-fixtures.ts";

const root = path.resolve(import.meta.dirname, "../..");
const compat = {
  sourceRevision: process.env.SOURCE_REVISION ?? "local",
  planManifestHash: "local",
  abi: "local",
  runtime: "workerd-local",
};
const dictionary = workerDictionary(fixtureManifest());
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

const toD1 = (value: unknown): unknown =>
  value instanceof Uint8Array
    ? value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength)
    : value;

async function database(
  mf: Miniflare,
  binding: string,
  overrides: SeedOverrides = {},
): Promise<D1> {
  const db = (await mf.getD1Database(binding)) as unknown as D1;
  await applyPending({
    client: new D1BindingMigrationClient(db),
    migrations,
    runner: `local-${binding}`,
    now: Date.now,
    compatibility: compat,
  });
  await db.batch(
    seedStatements(overrides).map(([sql, values]) => db.prepare(sql).bind(...values.map(toD1))),
  );
  return db;
}

async function snapshot(db: D1): Promise<string> {
  const parts: Record<string, unknown[][]> = {};
  for (const [name, sql] of Object.entries(snapshotQueries))
    parts[name] = await db.prepare(sql).bind().raw();
  return JSON.stringify(parts);
}

const attempt = (db: D1, values: FixtureValues) =>
  runFamily(db as never, dictionary, fixtureArguments(values), ids.workspace);
const count = async (db: D1, table: string) =>
  Number((await db.prepare(`SELECT COUNT(*) FROM ${table}`).bind().raw())[0]?.[0]);

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
        GUARDS: "families-guards",
        ATOMIC: "families-atomic",
        CONTEND: "families-contend",
        LEASE: "families-lease",
        EXACT: "families-exact",
      },
    }),
  );
  try {
    await mf.ready;

    await scenario("a-guard-table-refuses-a-false-guard-as-a-precondition", async () => {
      const db = await database(mf, "GUARDS");
      const check = await db
        .prepare("SELECT sql FROM sqlite_master WHERE name = 'platform_command_guard'")
        .bind()
        .raw();
      assert.match(String(check[0]?.[0]), /af_guard_failed/u);
      const ok = await attempt(db, defaults());
      assert.equal(ok.ok, true, JSON.stringify(ok));
      assert.equal(await count(db, "platform_command_guard"), 0, "the release left no guard row");
      const cases: [string, Partial<FixtureValues>][] = [
        ["lease holder", { holder: "container-b" }],
        ["lease fence", { fence: "4" }],
        ["lease expiry", { now: String(nowMicros + 700_000_000n) }],
        ["configuration state", { configState: "1" }],
        ["workspace state", { workspaceState: "2" }],
        ["entitlement revision", { revision: "6" }],
        ["balance revision", { budgetRev: "2" }],
        ["captured used", { usedBefore: "9" }],
        ["captured held", { heldBefore: "3" }],
        ["source policy revision", { policyRevision: "3" }],
      ];
      // The first batch committed, so every value below is now stale or wrong by construction; the state must not move at all.
      const before = await snapshot(db);
      const current = {
        revision: "8",
        budgetRev: "4",
        usedBefore: "13",
        usedAfter: "16",
        recipient: "other",
      };
      for (const [name, change] of cases) {
        const outcome = await attempt(db, { ...defaults(), ...current, ...change });
        assert.deepEqual(outcome, { ok: false, failure: "precondition" }, name);
      }
      assert.equal(await snapshot(db), before, "no table changed under any false guard");
      assert.equal(await count(db, "platform_command_guard"), 0);
      return `${cases.length} false guards each refused whole as precondition; state unchanged; guard table empty`;
    });

    await scenario("a-constraint-after-the-guards-rolls-the-guarded-mutations-back", async () => {
      const db = await database(mf, "ATOMIC");
      const first = defaults();
      assert.equal((await attempt(db, first)).ok, true);
      const before = await snapshot(db);
      const replay = await attempt(db, {
        ...first,
        revision: "8",
        budgetRev: "4",
        usedBefore: "13",
        usedAfter: "16",
        recipient: "recipient-replay",
      });
      assert.deepEqual(replay, { ok: false, failure: "constraint" });
      assert.equal(
        await snapshot(db),
        before,
        "the quota and revision updates of the failed batch were rolled back",
      );
      const broken = await attempt(db, {
        ...defaults(),
        revision: "8",
        budgetRev: "4",
        usedBefore: "13",
        usedAfter: "-1",
        recipient: "recipient-neg",
      });
      assert.deepEqual(broken, { ok: false, failure: "constraint" });
      assert.equal(await snapshot(db), before);
      return "a duplicate receipt key and a CHECK violation after passing guards both rolled the whole batch back; both are constraint, never precondition";
    });

    await scenario("concurrent-containers-commit-exactly-once-per-revision", async () => {
      const db = await database(mf, "CONTEND");
      const rounds = 25;
      const contenders = 4;
      let committed = 0;
      for (let round = 0; round < rounds; round++) {
        const read = async () => {
          const revision = Number(
            (
              await db
                .prepare(snapshotQueries.revision as string)
                .bind()
                .raw()
            )[0]?.[0],
          );
          const budget =
            (
              await db
                .prepare(snapshotQueries.budget as string)
                .bind()
                .raw()
            )[0] ?? [];
          return {
            revision,
            used: Number(budget[0]),
            held: Number(budget[1]),
            budgetRev: Number(budget[2]),
          };
        };
        const state = await read();
        // Every contender read the same state, then all submit at once through the binding.
        const outcomes = await Promise.all(
          Array.from({ length: contenders }, (_, index) =>
            attempt(db, {
              ...defaults(),
              revision: String(state.revision),
              budgetRev: String(state.budgetRev),
              usedBefore: String(state.used),
              usedAfter: String(state.used + 3),
              recipient: `container-${round}-${index}`,
              requestHash: `hash-${round}-${index}`,
            }),
          ),
        );
        const wins = outcomes.filter((outcome) => outcome.ok).length;
        const refused = outcomes.filter(
          (outcome) => !outcome.ok && outcome.failure === "precondition",
        ).length;
        assert.equal(
          wins,
          1,
          `round ${round}: exactly one container commits (${JSON.stringify(outcomes)})`,
        );
        assert.equal(
          refused,
          contenders - 1,
          `round ${round}: every other container is refused as a precondition`,
        );
        const after = await read();
        assert.equal(after.revision, state.revision + 1);
        assert.equal(after.used, state.used + 3, "the quota moved exactly once");
        assert.equal(after.budgetRev, state.budgetRev + 1);
        committed += wins;
      }
      assert.equal(await count(db, "platform_command"), committed);
      assert.equal(await count(db, "notification_suppression"), committed);
      assert.equal(await count(db, "platform_command_guard"), 0);
      return `${rounds} rounds of ${contenders} simultaneous writers on one revision: ${committed} commits, ${rounds * (contenders - 1)} whole-batch precondition refusals, no lost or doubled update`;
    });

    await scenario("a-stale-lease-holder-cannot-finalize", async () => {
      const db = await database(mf, "LEASE");
      await db
        .prepare("UPDATE platform_job_lease SET holder = 'container-b', fence_token = 6")
        .bind()
        .run();
      const before = await snapshot(db);
      assert.deepEqual(await attempt(db, defaults()), { ok: false, failure: "precondition" });
      assert.deepEqual(await attempt(db, { ...defaults(), fence: "6" }), {
        ok: false,
        failure: "precondition",
      });
      assert.deepEqual(await attempt(db, { ...defaults(), holder: "container-b" }), {
        ok: false,
        failure: "precondition",
      });
      assert.equal(await snapshot(db), before, "the stale holder changed nothing");
      assert.equal(
        (await attempt(db, { ...defaults(), holder: "container-b", fence: "6" })).ok,
        true,
      );
      // Racing: the old holder and the new holder submit together; only the one that holds the lease commits.
      const [oldHolder, newHolder] = await Promise.all([
        attempt(db, {
          ...defaults(),
          revision: "8",
          budgetRev: "4",
          usedBefore: "13",
          usedAfter: "14",
          recipient: "old",
        }),
        attempt(db, {
          ...defaults(),
          holder: "container-b",
          fence: "6",
          revision: "8",
          budgetRev: "4",
          usedBefore: "13",
          usedAfter: "15",
          recipient: "new",
        }),
      ]);
      assert.deepEqual(oldHolder, { ok: false, failure: "precondition" });
      assert.equal(newHolder.ok, true);
      return "old holder refused after takeover (holder, fence and both mixed); the new holder commits; racing together only the holder commits";
    });

    await scenario("balances-compare-exactly-above-2-to-the-53", async () => {
      const db = await database(mf, "EXACT", { used: "9007199254740993", held: "2" });
      const wrong = ["9007199254740992", "9007199254740994"];
      for (const used of wrong)
        assert.deepEqual(
          await attempt(db, { ...defaults(), usedBefore: used, usedAfter: "9007199254740995" }),
          { ok: false, failure: "precondition" },
          used,
        );
      const ok = await attempt(db, {
        ...defaults(),
        usedBefore: "9007199254740993",
        usedAfter: "9223372036854775807",
      });
      assert.equal(ok.ok, true, JSON.stringify(ok));
      const stored = await db
        .prepare("SELECT CAST(used AS TEXT) FROM entitlement_quota_budget")
        .bind()
        .raw();
      assert.equal(stored[0]?.[0], "9223372036854775807");
      return "2^53 + 1 matched exactly, its two neighbours were refused, and the int64 maximum was stored exactly";
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
  const outDirectory = path.join(root, "artifacts", "d1-families-local");
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
