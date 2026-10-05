// SPDX-License-Identifier: AGPL-3.0-only
// Receipts, outbox, inbox and change archive (CLOUD.04, WP-21.04) against the real migrations and the real plans through the production plan
// executor, on SQLite as the oracle. They prove the SQL, the constraints, the triggers and the batch rollback; the workerd run (npm run
// test:d1:local:receipts) repeats the central scenarios on the closest local D1 engine. Neither is a Cloudflare provider result.
import assert from "node:assert/strict";
import test from "node:test";
import type { D1Scalar } from "@arcforges/ai-internal";
import { canonicalTail } from "../../eng/verification/commit-tail.ts";
import { executePlan } from "../../worker/storage/execute-plan.ts";
import { depsFor, i64, planRequest, txt, uuid } from "./support/plan-calls.ts";
import {
  commit,
  commitDatabase,
  count,
  event,
  execute,
  otherStream,
  planIndexWithFixtures,
  rows,
  sha256,
  stream,
  tailArguments,
} from "./support/commit-support.ts";
import type { SqliteD1 } from "./support/sqlite-d1.ts";

const sc = (value: string): D1Scalar => ({ kind: "text", value });
const num = (value: unknown) => Number(value);

// --- reads of the stored state, directly, to assert what the plans did ---
const streamRow = (db: SqliteD1, key = stream) =>
  rows(
    db,
    `SELECT last_sequence, published_watermark, publish_rev, fence, ack_receipt FROM platform_sequence_stream WHERE stream_key = '${key}'`,
  )[0];
const positions = (db: SqliteD1, key = stream) =>
  rows(
    db,
    `SELECT sequence FROM platform_outbox_position WHERE stream_key = '${key}' ORDER BY sequence`,
  ).map((row) => num(row[0]));
const archiveSequences = (db: SqliteD1) =>
  rows(db, "SELECT archive_sequence FROM platform_change_archive ORDER BY archive_sequence").map(
    (row) => num(row[0]),
  );
const outboxState = (db: SqliteD1, id: string) =>
  rows(db, `SELECT state, attempts FROM platform_outbox WHERE outbox_id = '${id}'`)[0]?.map(num);
const snapshot = (db: SqliteD1) =>
  JSON.stringify(
    [
      "entitlement_fixture_item",
      "platform_command",
      "platform_outbox",
      "platform_outbox_position",
      "platform_sequence_stream",
      "platform_change_archive",
      "platform_inbox",
      "platform_command_guard",
    ].map((table) =>
      rows(db, `SELECT * FROM ${table} ORDER BY 1, 2`).map((row) =>
        row.map((cell) => (cell instanceof Uint8Array ? Buffer.from(cell).toString("hex") : cell)),
      ),
    ),
  );

// --- the publisher side of the plans, as the C# OutboxPublisher binds them ---
async function selectRows(db: SqliteD1, after: number, through: number, key = stream) {
  const outcome = await execute(
    db,
    "platform.outbox-select",
    [[sc(key), i64(after), i64(through)]],
    key,
  );
  assert(outcome.ok, JSON.stringify(outcome));
  return outcome.rows;
}
const ackArguments = (
  guard: string,
  after: number,
  through: number,
  revision: number,
  fence: number,
  receipt: string,
  key = stream,
): D1Scalar[][] => [
  [
    txt(guard),
    sc(key),
    i64(after),
    i64(revision),
    i64(fence),
    i64(through),
    sc(key),
    i64(after),
    i64(through),
    i64(through - after),
  ],
  [i64(2_000_000), sc(key), i64(after), i64(through)],
  [i64(through), txt(receipt), i64(2_000_000), sc(key), i64(after), i64(revision), i64(fence)],
  [txt(guard)],
];
const ack = (
  db: SqliteD1,
  after: number,
  through: number,
  revision = 0,
  fence = 0,
  receipt = "run-1",
  key = stream,
) =>
  execute(
    db,
    "platform.outbox-ack",
    ackArguments(uuid(), after, through, revision, fence, receipt, key),
    key,
  );

const batches = new WeakMap<object, number>();
async function commits(db: SqliteD1, total: number, eventsEach = 1) {
  const batch = batches.get(db) ?? 0;
  batches.set(db, batch + 1);
  for (let index = 0; index < total; index++) {
    const result = await commit(db, {
      commandId: uuid(),
      itemId: `item-${batch}-${index}`,
      plan:
        eventsEach === 1 ? "item-store-one" : eventsEach === 0 ? "item-store-none" : "item-store",
      events: Array.from({ length: eventsEach }, () => event()),
    });
    assert(result.ok, JSON.stringify(result));
  }
}

test("one commit writes the effect, the receipt, its outbox rows with allocated sequences and the change record, and leaves no guard row", async () => {
  const db = commitDatabase();
  const command = uuid();
  const first = event();
  const second = event(undefined, { workspaceId: uuid(), causationId: uuid() });
  const result = await commit(db, {
    commandId: command,
    events: [first, second],
    resultRevision: 7,
    workspaceId: second.workspaceId,
  });
  assert(result.ok);
  assert.equal(count(db, "entitlement_fixture_item"), 1);
  assert.deepEqual(positions(db), [1, 2]);
  assert.deepEqual(archiveSequences(db), [1]);
  assert.deepEqual(
    rows(
      db,
      `SELECT outbox_id, state, attempts FROM platform_outbox ORDER BY created_at, outbox_id`,
    ).map((row) => [row[1], row[2]]),
    [
      [1, 0],
      [1, 0],
    ],
  );
  assert.deepEqual(streamRow(db)?.map(num).slice(0, 4), [2, 0, 0, 0]);
  assert.deepEqual(
    rows(
      db,
      "SELECT last_sequence FROM platform_sequence_stream WHERE stream_key = 'platform:change-archive'",
    ),
    [[1]],
  );
  const receipt = rows(
    db,
    `SELECT status, result_rev, error_code, actor_ref, operation FROM platform_command WHERE command_id = '${command}'`,
  )[0];
  assert.deepEqual(receipt, [2, 7, null, "actor-1", "fixture.store"]);
  assert.equal(count(db, "platform_command_guard"), 0);
  // The first event is sequence 1 and the second sequence 2, in the order the plan wrote them.
  assert.deepEqual(
    rows(db, `SELECT outbox_id FROM platform_outbox_position ORDER BY sequence`).map(
      (row) => row[0],
    ),
    [first.outboxId, second.outboxId],
  );
  // The change record is the one the hash covers.
  const archived = rows(db, "SELECT record, record_hash FROM platform_change_archive")[0] as [
    string,
    Uint8Array,
  ];
  assert.deepEqual(Buffer.from(archived[1]), sha256(archived[0]));
});

test("a null resulting revision is stored as NULL and a given one exactly, even beyond 2^53", async () => {
  const db = commitDatabase();
  const none = uuid();
  const big = uuid();
  assert((await commit(db, { commandId: none, plan: "item-store-none", itemId: "a" })).ok);
  assert(
    (
      await commit(db, {
        commandId: big,
        plan: "item-store-none",
        itemId: "b",
        resultRevision: 9_007_199_254_740_993n,
      })
    ).ok,
  );
  assert.equal(
    rows(db, `SELECT result_rev FROM platform_command WHERE command_id = '${none}'`)[0]?.[0],
    null,
  );
  assert.equal(
    rows(
      db,
      `SELECT CAST(result_rev AS TEXT) FROM platform_command WHERE command_id = '${big}'`,
    )[0]?.[0],
    "9007199254740993",
  );
});

test("committed sequences are 1, 2, 3 and so on without a gap, per stream and for the archive, across failures", async () => {
  const db = commitDatabase();
  await commits(db, 5, 2);
  // A stale revision, a malformed event payload and a duplicate command each roll back and consume nothing.
  const before = snapshot(db);
  const stale = await commit(db, {
    commandId: uuid(),
    itemId: "item-0-0",
    expectedRevision: 0,
    events: [event(), event()],
  });
  assert.deepEqual(stale, { ok: false, failure: "precondition" });
  const badPayload = await commit(db, {
    commandId: uuid(),
    itemId: "fresh",
    events: [event(uuid(), { payload: "{not json" }), event()],
  });
  assert.deepEqual(badPayload, { ok: false, failure: "constraint" });
  assert.equal(snapshot(db), before);
  await commits(db, 3, 2);
  assert.deepEqual(
    positions(db),
    Array.from({ length: 16 }, (_, index) => index + 1),
  );
  assert.deepEqual(
    archiveSequences(db),
    Array.from({ length: 8 }, (_, index) => index + 1),
  );
  assert.deepEqual(streamRow(db)?.map(num).slice(0, 2), [16, 0]);
  // Another stream numbers from 1 independently.
  const other = await commit(db, {
    commandId: uuid(),
    scope: otherStream,
    itemId: "x",
    plan: "item-store-one",
    events: [event()],
  });
  assert(other.ok);
  assert.deepEqual(positions(db, otherStream), [1]);
  assert.deepEqual(
    positions(db),
    Array.from({ length: 16 }, (_, index) => index + 1),
  );
});

test("constraint-guard failure rolls back all rows", async () => {
  const db = commitDatabase();
  await commits(db, 1, 1);
  const before = snapshot(db);
  const rollbacks = db.rollbacks();
  const command = uuid();
  // The owner revision moved: the guard row violates its constraint and the batch, with its receipt, outbox rows and change record, rolls back.
  const stale = await commit(db, {
    commandId: command,
    itemId: "item-0-0",
    expectedRevision: 5,
    plan: "item-store",
    events: [event(), event()],
  });
  assert.deepEqual(stale, { ok: false, failure: "precondition" });
  assert.equal(db.rollbacks(), rollbacks + 1);
  assert.equal(snapshot(db), before);
  assert.equal(count(db, "platform_command", `command_id = '${command}'`), 0);
  assert.equal(count(db, "platform_command_guard"), 0);
  // A violation deep in the tail (an archive record that is not an object) undoes the owner mutation and the earlier tail rows too.
  const record = JSON.stringify([1, 2]);
  const badRecord = await commit(db, {
    commandId: uuid(),
    itemId: "fresh",
    plan: "item-store-one",
    events: [event()],
    record,
  });
  assert.deepEqual(badRecord, { ok: false, failure: "constraint" });
  assert.equal(snapshot(db), before);
  // And one beyond the 64 KiB bound of a change record.
  const oversized = await commit(db, {
    commandId: uuid(),
    itemId: "fresh",
    plan: "item-store-one",
    events: [event()],
    record: JSON.stringify({ filler: "x".repeat(65_600) }),
  });
  assert.deepEqual(oversized, { ok: false, failure: "constraint" });
  assert.equal(snapshot(db), before);
  // The same command id, now with the current revision, still commits: nothing was left behind by the failed attempts.
  assert(
    (
      await commit(db, {
        commandId: command,
        itemId: "item-0-0",
        expectedRevision: 1,
        plan: "item-store",
        events: [event(), event()],
      })
    ).ok,
  );
  assert.deepEqual(positions(db), [1, 2, 3]);
});

test("zero-row CAS cannot publish: a stale owner revision commits no receipt, outbox row or change record", async () => {
  const db = commitDatabase();
  assert(
    (
      await commit(db, {
        commandId: uuid(),
        itemId: "cas",
        plan: "item-store-one",
        events: [event()],
      })
    ).ok,
  );
  const row = () =>
    rows(db, "SELECT revision, value FROM entitlement_fixture_item WHERE id = 'cas'")[0];
  assert.deepEqual(row(), [1, "v"]);
  // Two writers read revision 1; the first commits, the second's compare-and-swap would match no row.
  const winner = await commit(db, {
    commandId: uuid(),
    itemId: "cas",
    expectedRevision: 1,
    value: "winner",
    plan: "item-store-one",
    events: [event()],
  });
  const loser = await commit(db, {
    commandId: uuid(),
    itemId: "cas",
    expectedRevision: 1,
    value: "loser",
    plan: "item-store-one",
    events: [event()],
  });
  assert(winner.ok);
  assert.deepEqual(loser, { ok: false, failure: "precondition" });
  assert.deepEqual(row(), [2, "winner"]);
  assert.equal(count(db, "platform_command"), 2);
  assert.deepEqual(positions(db), [1, 2]);
  assert.deepEqual(archiveSequences(db), [1, 2]);
});

test("a duplicate command id commits nothing twice, whatever the owner revision says", async () => {
  const db = commitDatabase();
  const command = uuid();
  assert(
    (
      await commit(db, {
        commandId: command,
        itemId: "d",
        plan: "item-store-one",
        events: [event()],
      })
    ).ok,
  );
  const before = snapshot(db);
  // Same content, the owner revision still current for the retry's guard: only the receipt's primary key stops it.
  const replay = await commit(db, {
    commandId: command,
    itemId: "d",
    expectedRevision: 1,
    value: "other",
    plan: "item-store-one",
    events: [event()],
  });
  assert.deepEqual(replay, { ok: false, failure: "constraint" });
  assert.equal(snapshot(db), before);
  // The same retry with the original expectation fails at the guard instead; either way nothing changed and the receipt tells the caller.
  const stale = await commit(db, {
    commandId: command,
    itemId: "d",
    plan: "item-store-one",
    events: [event()],
  });
  assert.deepEqual(stale, { ok: false, failure: "precondition" });
  assert.equal(snapshot(db), before);
  const load = await execute(db, "platform.command-load", [[txt(command)]], "platform");
  assert(load.ok);
  assert.deepEqual(load.rows[0]?.slice(0, 2), ["hash-1", "2"]);
});

test("the receipt read returns what replay needs and the failure record replays a refusal", async () => {
  const db = commitDatabase();
  const command = uuid();
  const workspace = uuid();
  assert(
    (
      await commit(db, {
        commandId: command,
        itemId: "r",
        plan: "item-store-none",
        workspaceId: workspace,
        resultRevision: 4,
        resultPayload: '{"a":[1,2]}',
      })
    ).ok,
  );
  const loaded = await execute(db, "platform.command-load", [[txt(command)]], "platform");
  assert(loaded.ok);
  assert.deepEqual(loaded.rows, [
    [
      "hash-1",
      "2",
      '{"a":[1,2]}',
      "4",
      "null",
      String(1_000_000 + 604_800_000_000),
      "actor-1",
      "fixture.store",
      workspace,
    ],
  ]);
  assert.deepEqual(await execute(db, "platform.command-load", [[txt(uuid())]], "platform"), {
    ok: true,
    rows: [],
    changes: "0",
  });
  const refused = uuid();
  const failureArguments = [
    [
      txt(refused),
      { kind: "null" } as D1Scalar,
      txt("actor-1"),
      txt("fixture.store"),
      txt("hash-2"),
      txt("validation.invalid_request"),
      i64(5),
      i64(5 + 100),
    ],
  ];
  assert((await execute(db, "platform.command-record-failure", failureArguments, "platform")).ok);
  const failed = await execute(db, "platform.command-load", [[txt(refused)]], "platform");
  assert(failed.ok);
  assert.deepEqual(failed.rows[0], [
    "hash-2",
    "3",
    "null",
    "null",
    "validation.invalid_request",
    "105",
    "actor-1",
    "fixture.store",
    "null",
  ]);
  assert.deepEqual(
    await execute(db, "platform.command-record-failure", failureArguments, "platform"),
    { ok: false, failure: "constraint" },
  );
  // A failed receipt must name its code (the table's check), so a refusal can never be recorded without one.
  assert.throws(
    () =>
      db.database
        .prepare(
          "INSERT INTO platform_command (command_id, actor_ref, operation, request_hash, status, created_at, expires_at) VALUES (?, 'a', 'o', 'h', 3, 1, 2)",
        )
        .run(uuid()),
    /failed_has_error_code/u,
  );
});

test("inbox dedup makes a redelivery a no-op and a new recovery generation a fresh message", async () => {
  const db = commitDatabase();
  const consume = (message: string, generation: number, command = uuid(), item = "inbox-item") =>
    commit(db, {
      commandId: command,
      itemId: item,
      plan: "item-consume",
      events: [event()],
      inbox: { source: "billing-consumer", messageId: `${message}@${generation}` },
    });
  assert((await consume("evt-1", 0)).ok);
  const after = snapshot(db);
  // The same message again, with a new command id (a consumer's own): the inbox key stops it and the batch, effect included, rolls back.
  const duplicate = await consume("evt-1", 0, uuid(), "inbox-item-2");
  assert.deepEqual(duplicate, { ok: false, failure: "constraint" });
  // The consumer's guard may also have moved by then; either way the redelivery changes nothing.
  assert.deepEqual(await consume("evt-1", 0, uuid(), "inbox-item"), {
    ok: false,
    failure: "precondition",
  });
  assert.equal(snapshot(db), after);
  assert.deepEqual(rows(db, "SELECT source, message_id, outcome FROM platform_inbox"), [
    ["billing-consumer", "evt-1@0", 1],
  ]);
  // Another source with the same message id is a different message.
  const other = await commit(db, {
    commandId: uuid(),
    itemId: "i2",
    plan: "item-consume",
    events: [event()],
    inbox: { source: "other-consumer", messageId: "evt-1@0" },
  });
  assert(other.ok);
  // After a restore the recovery generation is part of the key, so the message applies again.
  assert((await consume("evt-1", 1, uuid(), "i3")).ok);
  assert.equal(count(db, "platform_inbox"), 3);
  const seen = await execute(
    db,
    "platform.inbox-load",
    [[txt("billing-consumer"), txt("evt-1@0")]],
    "platform",
  );
  assert(seen.ok);
  assert.deepEqual(seen.rows, [["1", "1000000"]]);
  assert.deepEqual(
    await execute(db, "platform.inbox-load", [[txt("billing-consumer"), txt("never")]], "platform"),
    { ok: true, rows: [], changes: "0" },
  );
});

test("a poison message is recorded as rejected and its redelivery is a no-op", async () => {
  const db = commitDatabase();
  const rejected = [
    [txt("provider-events"), txt("evt-bad@0"), i64(10), i64(10), i64(3), i64(1_000)],
  ];
  assert((await execute(db, "platform.inbox-record", rejected, "platform")).ok);
  assert.deepEqual(await execute(db, "platform.inbox-record", rejected, "platform"), {
    ok: false,
    failure: "constraint",
  });
  assert.deepEqual(rows(db, "SELECT outcome, processed_at FROM platform_inbox"), [[3, 10]]);
  // The applying consumer then cannot claim the message either.
  const applying = await commit(db, {
    commandId: uuid(),
    plan: "item-consume",
    events: [event()],
    inbox: { source: "provider-events", messageId: "evt-bad@0" },
  });
  assert.deepEqual(applying, { ok: false, failure: "constraint" });
  assert.equal(count(db, "entitlement_fixture_item"), 0);
});

test("outbox positions, change records and streams are append-only and bounded by their own checks", async () => {
  const db = commitDatabase();
  await commits(db, 2, 1);
  const refuse = (sql: string, pattern: RegExp) =>
    assert.throws(() => db.database.prepare(sql).run(), pattern, sql);
  refuse(
    "UPDATE platform_outbox_position SET sequence = 99",
    /af_immutable_platform_outbox_position/u,
  );
  refuse(
    "UPDATE platform_change_archive SET record = '{}'",
    /af_immutable_platform_change_archive/u,
  );
  refuse("DELETE FROM platform_sequence_stream", /af_immutable_platform_sequence_stream/u);
  refuse(
    "UPDATE platform_sequence_stream SET last_sequence = 1",
    /af_monotonic_platform_sequence_stream_last_sequence/u,
  );
  refuse(
    "UPDATE platform_sequence_stream SET published_watermark = 3",
    /watermark_within_allocation/u,
  );
  refuse(
    "UPDATE platform_sequence_stream SET fence = -1",
    /af_monotonic_platform_sequence_stream_fence|watermark_within_allocation/u,
  );
  db.database
    .prepare(
      "UPDATE platform_sequence_stream SET published_watermark = 2, last_sequence = 2 WHERE stream_key = ?",
    )
    .run(stream);
  refuse(
    "UPDATE platform_sequence_stream SET published_watermark = 1",
    /af_monotonic_platform_sequence_stream_published_watermark/u,
  );
  // A position needs its outbox row and its stream, an owner stream is never the platform's, and a sequence is allocated once.
  const lone = uuid();
  const insert = (outboxId: string, key: string, sequence: number) => () =>
    db.database
      .prepare(
        "INSERT INTO platform_outbox_position (outbox_id, stream_key, sequence) VALUES (?, ?, ?)",
      )
      .run(outboxId, key, sequence);
  assert.throws(insert(lone, stream, 3), /FOREIGN KEY/u);
  const existing = rows(db, "SELECT outbox_id FROM platform_outbox LIMIT 1")[0]?.[0] as string;
  assert.throws(insert(existing, "platform:change-archive", 1), /owner_stream|UNIQUE|PRIMARY/u);
  assert.throws(
    () =>
      db.database
        .prepare(
          "INSERT INTO platform_outbox_position (outbox_id, stream_key, sequence) VALUES (?, ?, 0)",
        )
        .run(existing, stream),
    /sequence_positive|UNIQUE|PRIMARY/u,
  );
});

test("a commit whose owner scope and event stream disagree is refused before any SQL runs", async () => {
  const db = commitDatabase();
  const args = [
    [txt(uuid()), sc(stream), txt("x"), i64(0)],
    [sc(stream), txt("x"), i64(0), txt("v")],
    ...tailArguments(otherStream, {
      commandId: "00000000-0000-4000-8000-0000000000aa",
      events: [event()],
    }),
  ];
  args[0] = [txt("00000000-0000-4000-8000-0000000000aa"), sc(stream), txt("x"), i64(0)];
  const outcome = await execute(db, "entitlement.item-store-one", args, stream);
  assert.deepEqual(outcome, { ok: false, failure: "invalidPlan" });
  assert.equal(count(db, "entitlement_fixture_item"), 0);
  assert.equal(count(db, "platform_command"), 0);
});

test("a commit under a stale recovery generation commits nothing", async () => {
  const db = commitDatabase();
  const response = await executePlan(
    planRequest(
      "entitlement.item-store-one",
      [
        [txt("00000000-0000-4000-8000-0000000000bb"), sc(stream), txt("g"), i64(0)],
        [sc(stream), txt("g"), i64(0), txt("v")],
        ...tailArguments(stream, {
          commandId: "00000000-0000-4000-8000-0000000000bb",
          events: [event()],
        }),
      ],
      { ownerScope: stream, recoveryGeneration: "1" },
    ),
    depsFor(db, { plans: planIndexWithFixtures }),
  );
  assert.deepEqual("failure" in response && response.failure, "staleGeneration");
  assert.equal(count(db, "platform_command"), 0);
});

test("the largest tail fits one batch: sixteen events, the inbox claim and the plan's own statements", async () => {
  const db = commitDatabase();
  const { parseFixturePlan } = await import("./support/commit-support.ts");
  const plan = parseFixturePlan("item-max", { events: 16, inbox: true });
  planIndexWithFixtures.set(`${plan.id}@${plan.version}`, plan);
  // guard, own mutation, the tail and the release
  assert.equal(plan.statements.length, 2 + canonicalTail({ events: 16, inbox: true }).length + 1);
  assert(plan.statements.length <= 100);
  const command = uuid();
  const events = Array.from({ length: 16 }, () => event());
  const args = [
    [txt(command), sc(stream), txt("max"), i64(0)],
    [sc(stream), txt("max"), i64(0), txt("v")],
    ...tailArguments(stream, {
      commandId: command,
      events,
      inbox: { source: "bulk", messageId: "m@0" },
    }),
  ];
  const outcome = await execute(db, "entitlement.item-max", args, stream);
  assert(outcome.ok, JSON.stringify(outcome));
  assert.deepEqual(
    positions(db),
    Array.from({ length: 16 }, (_, index) => index + 1),
  );
  assert.deepEqual(
    rows(db, "SELECT outbox_id FROM platform_outbox_position ORDER BY sequence").map(
      (row) => row[0],
    ),
    events.map((entry) => entry.outboxId),
  );
});

// ---------------------------------------------------------------------------------------------------------------------
// publication
// ---------------------------------------------------------------------------------------------------------------------

test("the publisher selects the contiguous pending rows and one guarded batch dispatches them and advances the watermark", async () => {
  const db = commitDatabase();
  await commits(db, 4, 1);
  const selected = await selectRows(db, 0, 3);
  assert.equal(selected.length, 3);
  assert.deepEqual(
    selected.map((row) => row[0]),
    ["1", "2", "3"],
  );
  assert.deepEqual(
    selected.map((row) => row[10]),
    ["1", "1", "1"],
  );
  assert((await ack(db, 0, 3)).ok);
  assert.deepEqual(
    streamRow(db)?.map((cell) => (typeof cell === "string" ? cell : num(cell))),
    [4, 3, 1, 0, "run-1"],
  );
  assert.deepEqual(
    rows(
      db,
      "SELECT state FROM platform_outbox_position p JOIN platform_outbox o ON o.outbox_id = p.outbox_id ORDER BY p.sequence",
    ).map((row) => row[0]),
    [2, 2, 2, 1],
  );
  assert.equal(count(db, "platform_command_guard"), 0);
  // The remaining row is next, from the new watermark.
  assert.deepEqual(
    (await selectRows(db, 3, 4)).map((row) => row[0]),
    ["4"],
  );
});

test("a lost acknowledgement is reconciled by rereading: the retry is refused and the stream shows it applied", async () => {
  const db = commitDatabase();
  await commits(db, 3, 1);
  assert((await ack(db, 0, 3, 0, 0, "run-A")).ok);
  const before = snapshot(db);
  // The publisher never saw the response and sends the same acknowledgement again: nothing is numbered or marked twice.
  assert.deepEqual(await ack(db, 0, 3, 0, 0, "run-A"), { ok: false, failure: "precondition" });
  assert.equal(snapshot(db), before);
  assert.deepEqual(
    streamRow(db)?.map((cell) => (typeof cell === "string" ? cell : num(cell))),
    [3, 3, 1, 0, "run-A"],
  );
  // The acknowledgement that did not apply (the batch never ran) leaves the stream exactly as selected.
  const db2 = commitDatabase();
  await commits(db2, 3, 1);
  const untouched = snapshot(db2);
  assert.deepEqual(streamRow(db2)?.map(num).slice(0, 3), [3, 0, 0]);
  assert.equal(snapshot(db2), untouched);
  assert((await ack(db2, 0, 3, 0, 0, "run-B")).ok);
});

test("two publishers contend: the loser's compare-and-swap matches nothing and publishes nothing", async () => {
  const db = commitDatabase();
  await commits(db, 4, 1);
  // P and Q both read watermark 0, revision 0, fence 0 and select the same rows.
  const winner = await ack(db, 0, 2, 0, 0, "P");
  const loser = await ack(db, 0, 3, 0, 0, "Q");
  assert(winner.ok);
  assert.deepEqual(loser, { ok: false, failure: "precondition" });
  assert.deepEqual(
    streamRow(db)?.map((cell) => (typeof cell === "string" ? cell : num(cell))),
    [4, 2, 1, 0, "P"],
  );
  assert.deepEqual(
    rows(
      db,
      "SELECT o.state FROM platform_outbox_position p JOIN platform_outbox o ON o.outbox_id = p.outbox_id ORDER BY p.sequence",
    ).map((row) => row[0]),
    [2, 2, 1, 1],
  );
  // Q rereads (watermark 2, revision 1) and publishes the rest.
  assert((await ack(db, 2, 4, 1, 0, "Q")).ok);
  assert.deepEqual(
    streamRow(db)?.map((cell) => (typeof cell === "string" ? cell : num(cell))),
    [4, 4, 2, 0, "Q"],
  );
});

test("an unrelated commit between selection and acknowledgement does not invalidate the selection", async () => {
  const db = commitDatabase();
  await commits(db, 2, 1);
  const state = streamRow(db)?.map(num) ?? [];
  await commits(db, 1, 1); // E commits after C and D were selected
  assert((await ack(db, 0, 2, state[2], state[3])).ok);
  assert.deepEqual(
    streamRow(db)?.map((cell) => (typeof cell === "string" ? cell : num(cell))),
    [3, 2, 1, 0, "run-1"],
  );
  assert.deepEqual(
    rows(
      db,
      "SELECT o.state FROM platform_outbox_position p JOIN platform_outbox o ON o.outbox_id = p.outbox_id ORDER BY p.sequence",
    ).map((row) => row[0]),
    [2, 2, 1],
  );
});

test("the watermark cannot pass a row that is missing or not pending, so no skipped row is hidden", async () => {
  const db = commitDatabase();
  await commits(db, 3, 1);
  // A phantom allocation (last_sequence ahead of the rows: a corrupted stream) cannot be acknowledged over.
  db.database
    .prepare("UPDATE platform_sequence_stream SET last_sequence = 4 WHERE stream_key = ?")
    .run(stream);
  assert.deepEqual(await ack(db, 0, 4), { ok: false, failure: "precondition" });
  assert.deepEqual(
    (await selectRows(db, 0, 4)).map((row) => row[0]),
    ["1", "2", "3"],
  );
  assert((await ack(db, 0, 3)).ok);
  // A dispatched row is not pending either: a range that overlaps the acknowledged one cannot be acknowledged again.
  assert.deepEqual(await ack(db, 2, 3, 1), { ok: false, failure: "precondition" });
});

test("a dead-lettered row stops the watermark until it is requeued", async () => {
  const db = commitDatabase();
  await commits(db, 3, 1);
  const second = rows(
    db,
    "SELECT outbox_id FROM platform_outbox_position WHERE sequence = 2",
  )[0]?.[0] as string;
  // The guard id of the first statement must be the one the last statement deletes: build the call the way the publisher does.
  const guardedCall = async (plan: string, statements: (guard: string) => D1Scalar[][]) => {
    const guard = uuid();
    return execute(db, plan, statements(guard), stream);
  };
  const record = (attempts: number, fence = 0) =>
    guardedCall("platform.outbox-attempt", (guard) => [
      [txt(guard), txt(second), sc(stream), i64(attempts), i64(fence)],
      [txt(second), i64(attempts)],
      [txt(guard)],
    ]);
  assert((await record(0)).ok);
  assert((await record(1)).ok);
  assert.deepEqual(outboxState(db, second), [1, 2]);
  // A stale attempt count and a wrong fence are refused.
  assert.deepEqual(await record(1), { ok: false, failure: "precondition" });
  assert.deepEqual(await record(2, 9), { ok: false, failure: "precondition" });
  const deadLetter = (attempts: number, fence = 0) =>
    guardedCall("platform.outbox-dead-letter", (guard) => [
      [txt(guard), txt(second), sc(stream), i64(attempts), i64(fence)],
      [txt(second), i64(attempts)],
      [txt(guard)],
    ]);
  assert((await deadLetter(2)).ok);
  assert.deepEqual(outboxState(db, second), [3, 2]);
  // The first row can still be published, but the watermark stops before the dead letter.
  assert((await ack(db, 0, 1)).ok);
  assert.deepEqual(await ack(db, 1, 3, 1), { ok: false, failure: "precondition" });
  assert.deepEqual(await ack(db, 1, 2, 1), { ok: false, failure: "precondition" });
  assert.deepEqual(
    (await selectRows(db, 1, 3)).map((row) => [row[0], row[10]]),
    [
      ["2", "3"],
      ["3", "1"],
    ],
  );
  // A requeue needs the dead-lettered state and restarts the attempts.
  const requeue = (fence = 0) =>
    guardedCall("platform.outbox-requeue", (guard) => [
      [txt(guard), txt(second), sc(stream), i64(fence)],
      [txt(second)],
      [txt(guard)],
    ]);
  assert.deepEqual(await requeue(5), { ok: false, failure: "precondition" });
  assert((await requeue()).ok);
  assert.deepEqual(outboxState(db, second), [1, 0]);
  assert.deepEqual(await requeue(), { ok: false, failure: "precondition" });
  assert((await ack(db, 1, 3, 1)).ok);
  assert.deepEqual(
    streamRow(db)
      ?.map((cell) => (typeof cell === "string" ? cell : num(cell)))
      .slice(0, 3),
    [3, 3, 2],
  );
  // A dispatched row can neither be attempted nor dead-lettered.
  assert.deepEqual(await record(0), { ok: false, failure: "precondition" });
  assert.deepEqual(await deadLetter(0), { ok: false, failure: "precondition" });
});

test("a fence advance makes every earlier selection fail its guard", async () => {
  const db = commitDatabase();
  await commits(db, 3, 1);
  const fence = (expected: number) => {
    const guard = uuid();
    return execute(
      db,
      "platform.stream-fence",
      [
        [txt(guard), sc(stream), i64(expected)],
        [i64(3_000_000), sc(stream), i64(expected)],
        [txt(guard)],
      ],
      stream,
    );
  };
  assert((await fence(0)).ok);
  assert.deepEqual(await fence(0), { ok: false, failure: "precondition" });
  // The publisher that selected under fence 0 is stale; the one that rereads (revision 1, fence 1) publishes.
  assert.deepEqual(await ack(db, 0, 3, 0, 0, "stale"), { ok: false, failure: "precondition" });
  assert.deepEqual(await ack(db, 0, 3, 1, 0, "stale"), { ok: false, failure: "precondition" });
  assert((await ack(db, 0, 3, 1, 1, "fresh")).ok);
  const state = await execute(db, "platform.stream-load", [[sc(stream)]], stream);
  assert(state.ok);
  assert.deepEqual(state.rows, [["3", "3", "2", "1", "fresh"]]);
  assert.deepEqual(
    await execute(db, "platform.stream-load", [[sc("workspace:none")]], "workspace:none"),
    { ok: true, rows: [], changes: "0" },
  );
});

test("a publisher acknowledging another stream's range, or the archive through an owner stream, publishes nothing", async () => {
  const db = commitDatabase();
  await commits(db, 2, 1);
  assert(
    (
      await commit(db, {
        commandId: uuid(),
        scope: otherStream,
        itemId: "o",
        plan: "item-store-one",
        events: [event()],
      })
    ).ok,
  );
  // The other stream's sequence 1 is not stream A's; the scope of the call is the stream, so it cannot be named.
  assert((await ack(db, 0, 1, 0, 0, "x", otherStream)).ok);
  assert.deepEqual(streamRow(db)?.map(num).slice(0, 2), [2, 0]);
  const wrongScope = await execute(
    db,
    "platform.outbox-ack",
    ackArguments(uuid(), 0, 1, 0, 0, "x", otherStream),
    stream,
  );
  assert.deepEqual(wrongScope, { ok: false, failure: "invalidPlan" });
  assert.deepEqual(streamRow(db)?.map(num).slice(0, 2), [2, 0]);
});

// ---------------------------------------------------------------------------------------------------------------------
// change archive
// ---------------------------------------------------------------------------------------------------------------------

const archiveAck = (
  db: SqliteD1,
  after: number,
  through: number,
  revision = 0,
  fence = 0,
  receipt = "s3-receipt-1",
) => {
  const guard = uuid();
  return execute(
    db,
    "platform.archive-ack",
    [
      [
        txt(guard),
        i64(after),
        i64(revision),
        i64(fence),
        i64(through),
        i64(after),
        i64(through),
        i64(through - after),
      ],
      [i64(through), txt(receipt), i64(5_000_000), i64(after), i64(revision), i64(fence)],
      [txt(guard)],
    ],
    "platform",
  );
};
const archiveSelect = async (db: SqliteD1, after: number, through: number) => {
  const outcome = await execute(
    db,
    "platform.archive-select",
    [[i64(after), i64(through)]],
    "platform",
  );
  assert(outcome.ok, JSON.stringify(outcome));
  return outcome.rows;
};

test("the change archive is read contiguously by sequence with every record's hash, and acknowledged only over a complete range", async () => {
  const db = commitDatabase();
  await commits(db, 5, 1);
  const state = await execute(db, "platform.archive-state", [[]], "platform");
  assert(state.ok);
  assert.deepEqual(state.rows, [["5", "0", "0", "0", "null"]]);
  const selected = await archiveSelect(db, 0, 5);
  assert.deepEqual(
    selected.map((row) => row[0]),
    ["1", "2", "3", "4", "5"],
  );
  for (const row of selected)
    assert.equal(
      Buffer.from(String(row[4]), "base64url").toString("hex"),
      sha256(String(row[3])).toString("hex"),
    );
  assert((await archiveAck(db, 0, 3)).ok);
  assert.deepEqual(
    rows(
      db,
      "SELECT published_watermark, publish_rev, ack_receipt FROM platform_sequence_stream WHERE stream_key = 'platform:change-archive'",
    ),
    [[3, 1, "s3-receipt-1"]],
  );
  // A stale watermark, a stale revision, a phantom sequence and a repeat are all refused.
  assert.deepEqual(await archiveAck(db, 0, 3), { ok: false, failure: "precondition" });
  assert.deepEqual(await archiveAck(db, 3, 5, 0), { ok: false, failure: "precondition" });
  db.database
    .prepare(
      "UPDATE platform_sequence_stream SET last_sequence = 6 WHERE stream_key = 'platform:change-archive'",
    )
    .run();
  assert.deepEqual(await archiveAck(db, 3, 6, 1), { ok: false, failure: "precondition" });
  assert((await archiveAck(db, 3, 5, 1, 0, "s3-receipt-2")).ok);
});

test("the archive page is bounded by bytes so a response never exceeds the plan limit, and a record is never split", async () => {
  const db = commitDatabase();
  const filler = (size: number) => JSON.stringify({ filler: "y".repeat(size) });
  for (let index = 0; index < 5; index++)
    assert(
      (
        await commit(db, {
          commandId: uuid(),
          itemId: `big-${index}`,
          plan: "item-store-none",
          record: filler(40_000),
        })
      ).ok,
    );
  // 40 KB records: two fit the 96 KiB budget, a third would exceed it.
  assert.deepEqual(
    (await archiveSelect(db, 0, 5)).map((row) => row[0]),
    ["1", "2"],
  );
  assert.deepEqual(
    (await archiveSelect(db, 2, 5)).map((row) => row[0]),
    ["3", "4"],
  );
  assert.deepEqual(
    (await archiveSelect(db, 4, 5)).map((row) => row[0]),
    ["5"],
  );
  // The largest allowed record (64 KiB) is always the first of its page.
  const biggest = await commit(db, {
    commandId: uuid(),
    itemId: "biggest",
    plan: "item-store-none",
    record: filler(65_500),
  });
  assert(biggest.ok);
  assert.deepEqual(
    (await archiveSelect(db, 5, 6)).map((row) => row[0]),
    ["6"],
  );
});

test("tampering with an archived record is visible to its hash, and the table refuses the edit unless a trigger is removed", async () => {
  const db = commitDatabase();
  await commits(db, 2, 0);
  assert.throws(
    () =>
      db.database
        .prepare(
          "UPDATE platform_change_archive SET record = '{\"forged\":true}' WHERE archive_sequence = 1",
        )
        .run(),
    /af_immutable_platform_change_archive/u,
  );
  // Storage-level corruption (outside the table's rules) is caught by the recorded hash, which a reader recomputes.
  db.database.exec("DROP TRIGGER tr_platform_change_archive__immutable_update");
  db.database
    .prepare(
      "UPDATE platform_change_archive SET record = '{\"forged\":true}' WHERE archive_sequence = 1",
    )
    .run();
  const selected = await archiveSelect(db, 0, 2);
  const [forged, intact] = selected;
  assert.notEqual(
    Buffer.from(String(forged?.[4]), "base64url").toString("hex"),
    sha256(String(forged?.[3])).toString("hex"),
  );
  assert.equal(
    Buffer.from(String(intact?.[4]), "base64url").toString("hex"),
    sha256(String(intact?.[3])).toString("hex"),
  );
});

test("random interleavings of commits, stale writers, replays, publishers and fences keep every sequence gapless and every row accounted for", async () => {
  // A seeded generator makes the interleaving reproducible. The invariants are the ones the plans promise whatever the order.
  let seed = 0x2545f491;
  const next = () => {
    seed ^= seed << 13;
    seed ^= seed >>> 17;
    seed ^= seed << 5;
    return (seed >>> 0) / 2 ** 32;
  };
  const db = commitDatabase();
  const revisions = new Map<string, number>();
  const committedCommands: string[] = [];
  let committedEvents = 0;
  let watermark = 0;
  let publishRevision = 0;
  for (let step = 0; step < 220; step++) {
    const roll = next();
    const streamKey = next() < 0.7 ? stream : otherStream;
    if (roll < 0.55) {
      const item = `i${Math.floor(next() * 6)}`;
      const key = `${streamKey}/${item}`;
      const eventsCount = Math.floor(next() * 3);
      const plan =
        (["item-store-none", "item-store-one", "item-store"] as const)[eventsCount] ??
        "item-store-none";
      const command = uuid();
      const stale = next() < 0.25;
      const expected = (revisions.get(key) ?? 0) + (stale ? 1 : 0);
      const outcome = await commit(db, {
        commandId: command,
        scope: streamKey,
        itemId: item,
        expectedRevision: expected,
        plan,
        events: Array.from({ length: eventsCount }, () => event()),
      });
      if (stale) assert.deepEqual(outcome, { ok: false, failure: "precondition" });
      else {
        assert(outcome.ok, JSON.stringify(outcome));
        revisions.set(key, expected + 1);
        committedCommands.push(command);
        committedEvents += streamKey === stream ? eventsCount : 0;
      }
    } else if (roll < 0.65 && committedCommands.length > 0) {
      // A replay of an earlier command id never commits again.
      const replay = await commit(db, {
        commandId: committedCommands[Math.floor(next() * committedCommands.length)] ?? uuid(),
        itemId: "replay",
        plan: "item-store-one",
        events: [event()],
      });
      assert(!replay.ok);
    } else if (roll < 0.9) {
      const last = num(streamRow(db)?.[0] ?? 0);
      if (last > watermark) {
        const through = Math.min(last, watermark + 1 + Math.floor(next() * 4));
        assert((await ack(db, watermark, through, publishRevision, 0, `p${step}`)).ok);
        watermark = through;
        publishRevision++;
      }
    } else {
      // A publisher holding an old selection can never move the watermark.
      if (watermark > 0)
        assert.deepEqual(await ack(db, 0, 1, publishRevision, 0, "stale"), {
          ok: false,
          failure: "precondition",
        });
    }
  }
  const allocated = num(streamRow(db)?.[0] ?? 0);
  assert.equal(allocated, committedEvents);
  assert.deepEqual(
    positions(db),
    Array.from({ length: allocated }, (_, index) => index + 1),
  );
  assert.deepEqual(
    archiveSequences(db),
    Array.from({ length: committedCommands.length }, (_, index) => index + 1),
  );
  assert.equal(count(db, "platform_command"), committedCommands.length);
  assert.equal(count(db, "platform_command_guard"), 0);
  assert.equal(num(streamRow(db)?.[1] ?? -1), watermark);
  // Dispatched rows are exactly those at or below the watermark.
  assert.deepEqual(
    rows(
      db,
      `SELECT p.sequence <= ${watermark}, o.state = 2 FROM platform_outbox_position p JOIN platform_outbox o ON o.outbox_id = p.outbox_id WHERE p.stream_key = '${stream}'`,
    ).filter((row) => row[0] !== row[1]),
    [],
  );
  assert.equal(count(db, "platform_outbox"), count(db, "platform_outbox_position"));
});

test("retention purges only acknowledged rows past the cutoff, positions before outbox rows, and never opens a gap above the watermark", async () => {
  const db = commitDatabase();
  await commits(db, 5, 1);
  assert((await ack(db, 0, 3)).ok);
  const purge = (through: number, cutoff: number) => {
    const guard = uuid();
    return execute(
      db,
      "platform.outbox-purge",
      [
        [txt(guard), sc(stream), i64(through)],
        [sc(stream), i64(through), i64(cutoff)],
        [i64(cutoff)],
        [txt(guard)],
      ],
      stream,
    );
  };
  // Above the acknowledged watermark nothing may be purged; before the cutoff nothing is old enough.
  assert.deepEqual(await purge(5, 9_000_000), { ok: false, failure: "precondition" });
  assert((await purge(3, 1_000_000)).ok);
  assert.equal(count(db, "platform_outbox"), 5);
  // Positions go first, then their dispatched outbox rows (the foreign key never blocks), and the pending rows stay.
  assert((await purge(3, 9_000_000)).ok);
  assert.deepEqual(positions(db), [4, 5]);
  assert.equal(count(db, "platform_outbox"), 2);
  assert.deepEqual(
    (await selectRows(db, 3, 5)).map((row) => row[0]),
    ["4", "5"],
  );
  assert((await ack(db, 3, 5, 1)).ok);
  // The next commit continues the sequence after the purged range.
  assert(
    (
      await commit(db, {
        commandId: uuid(),
        itemId: "after",
        plan: "item-store-one",
        events: [event()],
      })
    ).ok,
  );
  assert.deepEqual(positions(db), [4, 5, 6]);
  // The archive: acknowledged records only, past the backup cutoff.
  const archivePurge = (through: number, cutoff: number) => {
    const guard = uuid();
    return execute(
      db,
      "platform.archive-purge",
      [[txt(guard), i64(through)], [i64(through), i64(cutoff)], [txt(guard)]],
      "platform",
    );
  };
  assert.deepEqual(await archivePurge(3, 9_000_000), { ok: false, failure: "precondition" });
  assert((await archiveAck(db, 0, 4)).ok);
  assert((await archivePurge(3, 1_000_000)).ok);
  assert.deepEqual(archiveSequences(db), [1, 2, 3, 4, 5, 6]);
  assert((await archivePurge(3, 9_000_000)).ok);
  assert.deepEqual(archiveSequences(db), [4, 5, 6]);
  assert.deepEqual(
    (await archiveSelect(db, 4, 6)).map((row) => row[0]),
    ["5", "6"],
  );
});
