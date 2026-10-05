// SPDX-License-Identifier: AGPL-3.0-only
// Explicit local opt-in run (npm run test:d1:receipts:local): the commit tail, the receipts, the inbox, the contiguous outbox publisher and the
// change archive (CLOUD.04) against workerd's D1 under Miniflare, the closest engine to D1 that exists without a Cloudflare account. It runs the real
// migrations through the real runner and the real plans through the production plan executor, and repeats on that engine the scenarios of
// tests/worker/d1-receipts.test.ts that depend on the engine: batch atomicity and rollback, the guard constraint classification, foreign keys,
// the append-only triggers, the window function behind the byte-bounded pages, blob binding and the largest tail in one batch.
// It is NOT a Cloudflare provider result: no deployed D1, no network path, no provider limit and no REST batch are exercised. Never CI; it starts
// local workerd, reads no credential and writes an evidence file under artifacts/.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import type { D1Scalar } from "@arcforges/ai-internal";
import { loadCatalog } from "../migrations/catalog.ts";
import { D1BindingMigrationClient, type D1BindingLike } from "../migrations/clients.ts";
import { applyPending } from "../migrations/runner.ts";
import type { D1Like } from "../../worker/storage/d1.ts";
import {
  commit,
  event,
  execute,
  otherStream,
  parseFixturePlan,
  planIndexWithFixtures,
  stream,
  tailArguments,
} from "../../tests/worker/support/commit-support.ts";
import { i64, txt, uuid } from "../../tests/worker/support/plan-calls.ts";

const root = path.resolve(import.meta.dirname, "../..");
/** One database per scenario, so no scenario sees another's rows. */
const scenarioDatabases = 10;
const sc = (value: string): D1Scalar => ({ kind: "text", value });

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

type D1 = D1Like &
  D1BindingLike & {
    exec(sql: string): Promise<unknown>;
    prepare(sql: string): {
      bind(...values: unknown[]): { run(): Promise<unknown>; raw(): Promise<unknown[][]> };
    };
  };

const raw = (db: D1, sql: string, ...params: unknown[]): Promise<unknown[][]> =>
  db
    .prepare(sql)
    .bind(...params)
    .raw();
const count = async (db: D1, table: string, where = "1 = 1") =>
  Number((await raw(db, `SELECT COUNT(*) FROM ${table} WHERE ${where}`))[0]?.[0]);
const sequences = async (db: D1, key = stream) =>
  (
    await raw(
      db,
      `SELECT sequence FROM platform_outbox_position WHERE stream_key = '${key}' ORDER BY sequence`,
    )
  ).map((row) => Number(row[0]));
const gapless = (values: number[]) => values.every((value, index) => value === index + 1);

async function freshDatabase(mf: Miniflare, name: string): Promise<D1> {
  const db = (await mf.getD1Database(name)) as unknown as D1;
  const client = new D1BindingMigrationClient(db);
  const migrations = loadCatalog();
  await applyPending({
    client,
    migrations,
    runner: "receipts-local",
    now: Date.now,
    compatibility: {
      sourceRevision: process.env.SOURCE_REVISION ?? "local",
      planManifestHash: "local",
      abi: "local",
      runtime: "workerd-local",
    },
  });
  await db
    .prepare(
      "CREATE TABLE entitlement_fixture_item (scope TEXT NOT NULL, id TEXT NOT NULL, revision INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY (scope, id)) STRICT",
    )
    .bind()
    .run();
  return db;
}

const ackArguments = (
  guard: string,
  after: number,
  through: number,
  revision: number,
  fence: number,
  receipt: string,
): D1Scalar[][] => [
  [
    txt(guard),
    sc(stream),
    i64(after),
    i64(revision),
    i64(fence),
    i64(through),
    sc(stream),
    i64(after),
    i64(through),
    i64(through - after),
  ],
  [i64(2_000_000), sc(stream), i64(after), i64(through)],
  [i64(through), txt(receipt), i64(2_000_000), sc(stream), i64(after), i64(revision), i64(fence)],
  [txt(guard)],
];
const ack = (db: D1, after: number, through: number, revision = 0, fence = 0, receipt = "run-1") =>
  execute(
    db,
    "platform.outbox-ack",
    ackArguments(uuid(), after, through, revision, fence, receipt),
    stream,
  );

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
      d1Databases: Object.fromEntries(
        Array.from({ length: scenarioDatabases }, (_, index) => [
          `S${index + 1}`,
          `receipts-s${index + 1}`,
        ]),
      ),
    }),
  );
  try {
    await mf.ready;

    await scenario("commit-tail-writes-every-row-in-one-batch", async () => {
      const db = await freshDatabase(mf, "S1");
      const command = uuid();
      const events = [event(), event()];
      const outcome = await commit(db, {
        commandId: command,
        events,
        resultRevision: 9_007_199_254_740_993n,
      });
      assert(outcome.ok, JSON.stringify(outcome));
      assert.deepEqual(await sequences(db), [1, 2]);
      assert.equal(await count(db, "platform_change_archive"), 1);
      assert.equal(await count(db, "platform_command_guard"), 0);
      const receipt = await raw(
        db,
        `SELECT CAST(status AS TEXT), CAST(result_rev AS TEXT) FROM platform_command WHERE command_id = '${command}'`,
      );
      assert.deepEqual(receipt[0], ["2", "9007199254740993"]);
      const archived = await raw(db, "SELECT record, record_hash FROM platform_change_archive");
      assert.equal(
        Buffer.from(archived[0]?.[1] as number[]).toString("hex"),
        createHash("sha256").update(String(archived[0]?.[0])).digest("hex"),
      );
      return "effect, receipt, two outbox rows with sequences 1 and 2, the archive row and its SHA-256 committed in one batch; no guard row remains; revision 2^53+1 stored exactly";
    });

    await scenario(
      "guard-failure-rolls-back-all-rows-and-is-classified-as-a-precondition",
      async () => {
        const db = await freshDatabase(mf, "S2");
        assert(
          (
            await commit(db, {
              commandId: uuid(),
              itemId: "g",
              plan: "item-store-one",
              events: [event()],
            })
          ).ok,
        );
        const before = [
          await count(db, "platform_command"),
          await count(db, "platform_outbox"),
          await count(db, "platform_change_archive"),
        ];
        const stale = await commit(db, {
          commandId: uuid(),
          itemId: "g",
          expectedRevision: 5,
          events: [event(), event()],
        });
        assert.deepEqual(stale, { ok: false, failure: "precondition" });
        assert.deepEqual(
          [
            await count(db, "platform_command"),
            await count(db, "platform_outbox"),
            await count(db, "platform_change_archive"),
          ],
          before,
        );
        assert.equal(await count(db, "platform_command_guard"), 0);
        // The sequence the failed attempt would have used is still free: the next commit takes it.
        assert(
          (
            await commit(db, {
              commandId: uuid(),
              itemId: "g",
              expectedRevision: 1,
              plan: "item-store-one",
              events: [event()],
            })
          ).ok,
        );
        assert(gapless(await sequences(db)));
        return "a stale revision violates the guard constraint, which workerd reports with the name the Worker classifies as a failed precondition; the receipt, outbox rows and change record roll back and no sequence is consumed";
      },
    );

    await scenario("a-violation-deep-in-the-tail-undoes-the-whole-batch", async () => {
      const db = await freshDatabase(mf, "S3");
      const bad = await commit(db, {
        commandId: uuid(),
        itemId: "d",
        events: [event(), event(uuid(), { payload: "{not json" })],
      });
      assert.deepEqual(bad, { ok: false, failure: "constraint" });
      const arrayRecord = await commit(db, {
        commandId: uuid(),
        itemId: "d",
        plan: "item-store-one",
        events: [event()],
        record: "[1]",
      });
      assert.deepEqual(arrayRecord, { ok: false, failure: "constraint" });
      for (const table of [
        "entitlement_fixture_item",
        "platform_command",
        "platform_outbox",
        "platform_outbox_position",
        "platform_change_archive",
        "platform_sequence_stream",
      ])
        assert.equal(await count(db, table), 0, table);
      return "an invalid event payload (second event) and a change record that is not an object each leave every table empty, including the stream counters";
    });

    await scenario("duplicate-command-and-inbox-key-commit-nothing-twice", async () => {
      const db = await freshDatabase(mf, "S4");
      const command = uuid();
      assert(
        (
          await commit(db, {
            commandId: command,
            itemId: "dup",
            plan: "item-store-one",
            events: [event()],
          })
        ).ok,
      );
      const replay = await commit(db, {
        commandId: command,
        itemId: "dup",
        expectedRevision: 1,
        plan: "item-store-one",
        events: [event()],
      });
      assert.deepEqual(replay, { ok: false, failure: "constraint" });
      assert.equal(await count(db, "platform_outbox"), 1);
      const consume = (item: string) =>
        commit(db, {
          commandId: uuid(),
          itemId: item,
          plan: "item-consume",
          events: [event()],
          inbox: { source: "consumer", messageId: "evt@0" },
        });
      assert((await consume("c1")).ok);
      assert.deepEqual(await consume("c2"), { ok: false, failure: "constraint" });
      assert.equal(await count(db, "entitlement_fixture_item", "id = 'c2'"), 0);
      return "a repeated command id and a redelivered inbox key are refused by their primary keys and roll the whole batch back: no second effect, outbox row or change record";
    });

    await scenario("publisher-guard-contention-lost-acknowledgement-and-fence", async () => {
      const db = await freshDatabase(mf, "S5");
      for (let index = 0; index < 4; index++)
        assert(
          (
            await commit(db, {
              commandId: uuid(),
              itemId: `p${index}`,
              plan: "item-store-one",
              events: [event()],
            })
          ).ok,
        );
      assert((await ack(db, 0, 2, 0, 0, "P")).ok);
      assert.deepEqual(await ack(db, 0, 3, 0, 0, "Q"), { ok: false, failure: "precondition" });
      const states = await raw(
        db,
        "SELECT o.state FROM platform_outbox_position p JOIN platform_outbox o ON o.outbox_id = p.outbox_id ORDER BY p.sequence",
      );
      assert.deepEqual(
        states.map((row) => Number(row[0])),
        [2, 2, 1, 1],
      );
      // The same acknowledgement again (a lost response) is refused and shows as applied on reread.
      assert.deepEqual(await ack(db, 0, 2, 0, 0, "P"), { ok: false, failure: "precondition" });
      const state = await raw(
        db,
        `SELECT CAST(published_watermark AS TEXT), CAST(publish_rev AS TEXT), ack_receipt FROM platform_sequence_stream WHERE stream_key = '${stream}'`,
      );
      assert.deepEqual(state[0], ["2", "1", "P"]);
      // A fence advance fails every earlier selection.
      const guard = uuid();
      assert(
        (
          await execute(
            db,
            "platform.stream-fence",
            [[txt(guard), sc(stream), i64(0)], [i64(3_000_000), sc(stream), i64(0)], [txt(guard)]],
            stream,
          )
        ).ok,
      );
      assert.deepEqual(await ack(db, 2, 4, 1, 0, "stale"), { ok: false, failure: "precondition" });
      assert((await ack(db, 2, 4, 2, 1, "fresh")).ok);
      return "two publishers with the same selection: the second's compare-and-swap matches nothing and marks nothing; a repeated acknowledgement is refused and the stream shows it applied; a fence advance makes an earlier selection fail";
    });

    await scenario("a-dead-letter-stops-the-watermark-until-requeued", async () => {
      const db = await freshDatabase(mf, "S6");
      for (let index = 0; index < 3; index++)
        assert(
          (
            await commit(db, {
              commandId: uuid(),
              itemId: `q${index}`,
              plan: "item-store-one",
              events: [event()],
            })
          ).ok,
        );
      const second = String(
        (
          await raw(db, "SELECT outbox_id FROM platform_outbox_position WHERE sequence = 2")
        )[0]?.[0],
      );
      const guarded = (plan: string, build: (guard: string) => D1Scalar[][]) => {
        const guard = uuid();
        return execute(db, plan, build(guard), stream);
      };
      assert(
        (
          await guarded("platform.outbox-dead-letter", (g) => [
            [txt(g), txt(second), sc(stream), i64(0), i64(0)],
            [txt(second), i64(0)],
            [txt(g)],
          ])
        ).ok,
      );
      assert((await ack(db, 0, 1)).ok);
      assert.deepEqual(await ack(db, 1, 3, 1), { ok: false, failure: "precondition" });
      assert(
        (
          await guarded("platform.outbox-requeue", (g) => [
            [txt(g), txt(second), sc(stream), i64(0)],
            [txt(second)],
            [txt(g)],
          ])
        ).ok,
      );
      assert((await ack(db, 1, 3, 1)).ok);
      return "the watermark advanced over sequence 1, was refused over the dead-lettered sequence 2, and passed it after the requeue";
    });

    await scenario("append-only-triggers-foreign-keys-and-checks", async () => {
      const db = await freshDatabase(mf, "S7");
      assert(
        (
          await commit(db, {
            commandId: uuid(),
            itemId: "t",
            plan: "item-store-one",
            events: [event()],
          })
        ).ok,
      );
      const refuse = async (sql: string, pattern: RegExp) => {
        await assert.rejects(() => db.prepare(sql).bind().run(), pattern, sql);
      };
      await refuse(
        "UPDATE platform_outbox_position SET sequence = 9",
        /af_immutable_platform_outbox_position/u,
      );
      await refuse(
        "UPDATE platform_change_archive SET record = '{}'",
        /af_immutable_platform_change_archive/u,
      );
      await refuse(
        "UPDATE platform_sequence_stream SET published_watermark = 5",
        /watermark_within_allocation/u,
      );
      await refuse(
        "INSERT INTO platform_outbox_position (outbox_id, stream_key, sequence) VALUES ('00000000-0000-4000-8000-0000000000ff', 'workspace:fixture-a', 9)",
        /FOREIGN KEY/u,
      );
      return "updates of positions and archive rows, deletes of a stream, a watermark beyond the allocation and a position without its outbox row are refused by workerd's D1 (deleting positions and archive rows is the purge plans' job, see the purge scenario)";
    });

    await scenario("purge-is-clamped-to-the-acknowledged-watermark", async () => {
      const db = await freshDatabase(mf, "S10");
      for (let index = 0; index < 6; index++)
        assert(
          (
            await commit(db, {
              commandId: uuid(),
              itemId: `u${index}`,
              plan: "item-store-one",
              events: [event()],
            })
          ).ok,
        );
      assert((await ack(db, 0, 2)).ok);
      const guard = uuid();
      // The guard passes for 2 while the DELETE is bound to 6: the plan's own clamp keeps everything above the watermark.
      const outcome = await execute(
        db,
        "platform.outbox-purge",
        [
          [txt(guard), sc(stream), i64(2)],
          [sc(stream), i64(6), sc(stream), i64(9_000_000)],
          [i64(9_000_000)],
          [txt(guard)],
        ],
        stream,
      );
      assert(outcome.ok, JSON.stringify(outcome));
      assert.deepEqual(await sequences(db), [3, 4, 5, 6]);
      assert.equal(await count(db, "platform_outbox"), 4);
      const archiveGuard = uuid();
      assert(
        (
          await execute(
            db,
            "platform.archive-ack",
            [
              [txt(archiveGuard), i64(0), i64(0), i64(0), i64(2), i64(0), i64(2), i64(2)],
              [i64(2), txt("r"), i64(5_000_000), i64(0), i64(0), i64(0)],
              [txt(archiveGuard)],
            ],
            "platform",
          )
        ).ok,
      );
      const purgeGuard = uuid();
      assert(
        (
          await execute(
            db,
            "platform.archive-purge",
            [[txt(purgeGuard), i64(2)], [i64(6), i64(9_000_000)], [txt(purgeGuard)]],
            "platform",
          )
        ).ok,
      );
      assert.equal(await count(db, "platform_change_archive"), 4);
      return "a purge whose DELETE is bound beyond its guard deletes only rows at or below the acknowledged watermark (positions 1-2 and their outbox rows, archive records 1-2); sequences 3-6 stay";
    });

    await scenario("archive-pages-are-byte-bounded-and-hashes-survive-blob-binding", async () => {
      const db = await freshDatabase(mf, "S8");
      const filler = (size: number) => JSON.stringify({ filler: "y".repeat(size) });
      for (let index = 0; index < 5; index++)
        assert(
          (
            await commit(db, {
              commandId: uuid(),
              itemId: `a${index}`,
              plan: "item-store-none",
              record: filler(40_000),
            })
          ).ok,
        );
      const page = async (after: number, through: number) => {
        const outcome = await execute(
          db,
          "platform.archive-select",
          [[i64(after), i64(through)]],
          "platform",
        );
        assert(outcome.ok, JSON.stringify(outcome));
        return outcome.rows;
      };
      assert.deepEqual(
        (await page(0, 5)).map((row) => row[0]),
        ["1", "2"],
      );
      assert.deepEqual(
        (await page(2, 5)).map((row) => row[0]),
        ["3", "4"],
      );
      for (const row of await page(0, 5))
        assert.equal(
          Buffer.from(String(row[4]), "base64url").toString("hex"),
          createHash("sha256").update(String(row[3])).digest("hex"),
        );
      const guard = uuid();
      const ackOutcome = await execute(
        db,
        "platform.archive-ack",
        [
          [txt(guard), i64(0), i64(0), i64(0), i64(2), i64(0), i64(2), i64(2)],
          [i64(2), txt("receipt-1"), i64(5_000_000), i64(0), i64(0), i64(0)],
          [txt(guard)],
        ],
        "platform",
      );
      assert(ackOutcome.ok, JSON.stringify(ackOutcome));
      return "the window-function page returns whole records within 96 KiB (two of five 40 KB records), every returned record hashes to the stored SHA-256 through the blob binding, and the watermark advances under its guard";
    });

    await scenario("the-largest-tail-fits-one-batch-and-sequences-stay-gapless", async () => {
      const db = await freshDatabase(mf, "S9");
      const plan = parseFixturePlan("item-max", { events: 16, inbox: true });
      planIndexWithFixtures.set(`${plan.id}@${plan.version}`, plan);
      const command = uuid();
      const events = Array.from({ length: 16 }, () => event());
      const outcome = await execute(
        db,
        "entitlement.item-max",
        [
          [txt(command), sc(stream), txt("max"), i64(0)],
          [sc(stream), txt("max"), i64(0), txt("v")],
          ...tailArguments(stream, {
            commandId: command,
            events,
            inbox: { source: "bulk", messageId: "m@0" },
          }),
        ],
        stream,
      );
      assert(outcome.ok, JSON.stringify(outcome));
      assert.deepEqual(
        await sequences(db),
        Array.from({ length: 16 }, (_, index) => index + 1),
      );
      // Interleaved streams, stale writers and replays keep each stream's sequences gapless.
      for (let step = 0; step < 40; step++) {
        const scope = step % 3 === 0 ? otherStream : stream;
        const result = await commit(db, {
          commandId: uuid(),
          scope,
          itemId: `s${step % 5}`,
          expectedRevision: step % 7 === 0 ? 99 : 0,
          plan: "item-store-one",
          events: [event()],
        });
        assert(result.ok || (!result.ok && result.failure === "precondition"));
      }
      assert(gapless(await sequences(db)));
      assert(gapless(await sequences(db, otherStream)));
      const archive = (
        await raw(
          db,
          "SELECT archive_sequence FROM platform_change_archive ORDER BY archive_sequence",
        )
      ).map((row) => Number(row[0]));
      assert(gapless(archive));
      return `sixteen events with the inbox claim and the plan's own statements (${plan.statements.length} statements) commit in one batch; ${archive.length} archive rows and the sequences of two streams are gapless after 40 interleaved attempts with stale writers`;
    });
  } finally {
    await mf.dispose();
  }

  const failed = results.filter((entry) => entry.status === "failed");
  const report = {
    startedAt: started,
    finishedAt: new Date().toISOString(),
    kind: "local-emulation",
    emulated: "workerd D1 (SQLite) under Miniflare",
    notEmulated:
      "Cloudflare provider network path, REST batch semantics, real D1 limits and latency, provider export and Time Travel",
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    results,
  };
  const outDirectory = path.join(root, "artifacts", "d1-receipts-local");
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
