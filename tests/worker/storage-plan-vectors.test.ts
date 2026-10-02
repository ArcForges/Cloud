// SPDX-License-Identifier: AGPL-3.0-only
// Executable vectors for the reviewed foundation plans. They run the real plan SQL, constraints and
// batch rollback through the production executor on an SQLite stand-in for D1. They are not
// evidence about Cloudflare's network path, limits or provider behavior.
import assert from "node:assert/strict";
import test from "node:test";
import { createSqliteD1, type SqliteD1 } from "./support/sqlite-d1.ts";
import { bytes, i64, nul, run, sc, txt, u64, dec, uuid } from "./support/plan-calls.ts";

const hash = "a".repeat(64);
const count = async (db: SqliteD1, table: string, where = "1 = 1") =>
  Number((await db.prepare(`SELECT COUNT(*) FROM ${table} WHERE ${where}`).raw())[0]?.[0]);

function exactStore(
  id: string,
  signed: string,
  unsigned: string,
  decimal: string,
  payload: Uint8Array | null,
  expectedRevision: string,
  command = uuid(),
) {
  return [
    [txt(command), sc(), txt(id), i64(expectedRevision)],
    [
      sc(),
      txt(id),
      i64(signed),
      u64(unsigned),
      dec(decimal),
      payload ? bytes(payload) : nul(),
      i64(expectedRevision),
    ],
    [sc(), txt(command), txt(hash), txt('{"stored":true}')],
    [txt(command)],
  ];
}
const exactLoad = (db: SqliteD1, id: string) => run(db, "foundation.exact-load", [[sc(), txt(id)]]);

test("readiness reports the schema version through an exact int64 text", async () => {
  const db = createSqliteD1();
  assert.deepEqual(await run(db, "foundation.readiness", [[]]), {
    ok: true,
    rows: [["1"]],
    changes: "0",
  });
});

test("64-bit and decimal values round-trip exactly, including values a JavaScript number cannot hold", async () => {
  const everyByte = Uint8Array.from({ length: 256 }, (_, index) => index);
  const vectors = [
    ["-9223372036854775808", "18446744073709551615", "-1234567890123456789.123456789"],
    ["9223372036854775807", "9007199254740993", "9999999999999999999.999999999"],
    ["9007199254740993", "0", "0"],
    ["-9007199254740993", "9223372036854775808", "-0.000000001"],
    ["0", "1", "123456789012345678901234567"],
  ] as const;
  for (const [index, [signed, unsigned, decimal]] of vectors.entries()) {
    const db = createSqliteD1();
    const id = `vector-${index}`;
    const stored = await run(
      db,
      "foundation.exact-store",
      exactStore(id, signed, unsigned, decimal, everyByte, "0"),
    );
    assert.equal(stored.ok, true);
    const loaded = await exactLoad(db, id);
    assert.deepEqual(loaded.ok && loaded.rows[0]?.slice(0, 3), [signed, unsigned, decimal]);
    assert.equal(loaded.ok && loaded.rows[0]?.[4], "1");
    // The bytes survive too, and SQLite really stored an integer, not a rounded real.
    const direct = await db
      .prepare(
        "SELECT typeof(signed_value), CAST(signed_value AS TEXT), length(payload) FROM probe_exact",
      )
      .raw();
    assert.deepEqual(direct[0], ["integer", signed, 256]);
    assert.equal(await count(db, "probe_guard"), 0);
  }
});

test("an int64 outside the signed range is refused before SQL can saturate it", async () => {
  const db = createSqliteD1();
  // SQLite CAST would silently store 9223372036854775807 for this text.
  const result = await run(
    db,
    "foundation.exact-store",
    exactStore("big", "9223372036854775808", "1", "1", null, "0"),
  );
  assert.deepEqual(result, { ok: false, failure: "invalidPlan" });
  assert.equal(await count(db, "probe_exact"), 0);
  assert.equal(await count(db, "probe_receipt"), 0);
  const below = await run(
    db,
    "foundation.exact-store",
    exactStore("big", "-9223372036854775809", "1", "1", null, "0"),
  );
  assert.deepEqual(below, { ok: false, failure: "invalidPlan" });
  const unsigned = await run(
    db,
    "foundation.exact-store",
    exactStore("big", "1", "18446744073709551616", "1", null, "0"),
  );
  assert.deepEqual(unsigned, { ok: false, failure: "invalidPlan" });
});

test("a stale revision violates the guard and rolls the whole batch back", async () => {
  const db = createSqliteD1();
  assert.equal(
    (await run(db, "foundation.exact-store", exactStore("r", "5", "5", "5", null, "0"))).ok,
    true,
  );
  const rollbacksBefore = db.rollbacks();
  const stale = await run(db, "foundation.exact-store", exactStore("r", "6", "6", "6", null, "0"));
  assert.deepEqual(stale, { ok: false, failure: "precondition" });
  assert.equal(db.rollbacks(), rollbacksBefore + 1);
  const loaded = await exactLoad(db, "r");
  assert.deepEqual(loaded.ok && loaded.rows[0]?.slice(0, 3), ["5", "5", "5"]);
  assert.equal(await count(db, "probe_receipt"), 1);
  assert.equal(await count(db, "probe_guard"), 0);
  // The next legitimate revision succeeds and increments exactly once.
  assert.equal(
    (await run(db, "foundation.exact-store", exactStore("r", "7", "7", "7", null, "1"))).ok,
    true,
  );
  assert.equal(((await exactLoad(db, "r")) as { rows: string[][] }).rows[0]?.[4], "2");
});

test("a duplicate command receipt is a constraint failure that undoes the mutation", async () => {
  const db = createSqliteD1();
  const command = uuid();
  assert.equal(
    (await run(db, "foundation.exact-store", exactStore("d", "1", "1", "1", null, "0", command)))
      .ok,
    true,
  );
  const replay = await run(
    db,
    "foundation.exact-store",
    exactStore("d", "2", "2", "2", null, "1", command),
  );
  assert.deepEqual(replay, { ok: false, failure: "constraint" });
  const loaded = await exactLoad(db, "d");
  assert.deepEqual(
    loaded.ok && loaded.rows[0]?.slice(0, 3),
    ["1", "1", "1"],
    "the second write must not survive",
  );
  assert.equal(loaded.ok && loaded.rows[0]?.[4], "1");
});

function seedAccount(db: SqliteD1, id: string, balance: string) {
  return run(db, "foundation.account-seed", [[sc(), txt(id), i64(balance)]]);
}
function transfer(
  from: string,
  to: string,
  amount: string,
  expFrom: string,
  expTo: string,
  command = uuid(),
) {
  return [
    [txt(command), sc(), txt(from), i64(expFrom), i64(amount), sc(), txt(to), i64(expTo)],
    [i64(amount), sc(), txt(from), i64(expFrom)],
    [i64(amount), sc(), txt(to), i64(expTo)],
    [sc(), txt(command), txt(hash), txt('{"moved":true}')],
    [sc(), txt(command), txt("transfer.committed"), txt("{}")],
    [txt(command)],
  ];
}
const account = async (db: SqliteD1, id: string) =>
  (await run(db, "foundation.account-load", [[sc(), txt(id)]])) as { rows: string[][] };
const outbox = async (db: SqliteD1) =>
  (await run(db, "foundation.outbox-state", [[sc()]])) as { rows: string[][] };

test("a guarded transfer commits balances, receipt and outbox atomically with exact 64-bit arithmetic", async () => {
  const db = createSqliteD1();
  assert.equal((await seedAccount(db, "a", "9223372036854775000")).ok, true);
  assert.equal((await seedAccount(db, "b", "100")).ok, true);
  // Seeding again is idempotent and never overwrites.
  assert.equal((await seedAccount(db, "a", "5")).ok, true);
  assert.deepEqual((await account(db, "a")).rows, [["9223372036854775000", "1"]]);
  const moved = await run(
    db,
    "foundation.transfer",
    transfer("a", "b", "9223372036854774900", "1", "1"),
  );
  assert.equal(moved.ok, true);
  assert.deepEqual((await account(db, "a")).rows, [["100", "2"]]);
  assert.deepEqual((await account(db, "b")).rows, [["9223372036854775000", "2"]]);
  assert.deepEqual((await outbox(db)).rows, [["1", "1"]]);
});

test("a failed transfer guard rolls back both balances, the receipt and the outbox row", async () => {
  const db = createSqliteD1();
  await seedAccount(db, "a", "50");
  await seedAccount(db, "b", "10");
  const attempts: [string, string, string, string][] = [
    ["stale source revision", "5", "9", "1"],
    ["stale target revision", "5", "1", "9"],
    ["insufficient balance", "51", "1", "1"],
  ];
  for (const [label, amount, expFrom, expTo] of attempts) {
    const command = uuid();
    const before = [await account(db, "a"), await account(db, "b"), await outbox(db)];
    const result = await run(
      db,
      "foundation.transfer",
      transfer("a", "b", amount, expFrom, expTo, command),
    );
    assert.deepEqual(result, { ok: false, failure: "precondition" }, label);
    assert.deepEqual(
      [await account(db, "a"), await account(db, "b"), await outbox(db)],
      before,
      label,
    );
    assert.equal(await count(db, "probe_receipt", `command_id = '${command}'`), 0, label);
    assert.equal(await count(db, "probe_guard"), 0, label);
  }
});

test("a credit that would overflow int64 is a constraint failure and the debit is undone", async () => {
  const db = createSqliteD1();
  await seedAccount(db, "a", "10");
  await seedAccount(db, "b", "9223372036854775807");
  const result = await run(db, "foundation.transfer", transfer("a", "b", "1", "1", "1"));
  assert.deepEqual(result, { ok: false, failure: "constraint" });
  assert.deepEqual((await account(db, "a")).rows, [["10", "1"]]);
  assert.deepEqual((await account(db, "b")).rows, [["9223372036854775807", "1"]]);
  assert.deepEqual((await outbox(db)).rows, [["0", "0"]]);
});

test("a replayed transfer command is a constraint failure and moves nothing a second time", async () => {
  const db = createSqliteD1();
  await seedAccount(db, "a", "100");
  await seedAccount(db, "b", "0");
  const command = uuid();
  assert.equal(
    (await run(db, "foundation.transfer", transfer("a", "b", "10", "1", "1", command))).ok,
    true,
  );
  // The command id replay carries current revisions, so only the receipt key can stop it.
  const replay = await run(db, "foundation.transfer", transfer("a", "b", "10", "2", "2", command));
  assert.deepEqual(replay, { ok: false, failure: "constraint" });
  assert.deepEqual((await account(db, "a")).rows, [["90", "2"]]);
  const receipt = await run(db, "foundation.receipt-load", [[sc(), txt(command)]]);
  assert.deepEqual(receipt, { ok: true, rows: [[hash, '{"moved":true}']], changes: "0" });
});

test("rows are visible only through their own owner scope", async () => {
  const db = createSqliteD1();
  await seedAccount(db, "a", "5");
  const other = "proof/other";
  const foreign = await run(db, "foundation.account-load", [[sc(other), txt("a")]], {
    ownerScope: other,
  });
  assert.deepEqual(foreign, { ok: true, rows: [], changes: "0" });
  // A scope argument that differs from the declared owner scope is refused outright.
  const forged = await run(db, "foundation.account-load", [[sc(other), txt("a")]]);
  assert.deepEqual(forged, { ok: false, failure: "invalidPlan" });
});

const nowMicros = 1_790_000_000_000_000n;
function sessionCreate(sessionId: string, handleHash: Uint8Array, offset = 0n) {
  return [
    [
      sc(),
      txt(sessionId),
      bytes(handleHash),
      txt("11111111-1111-4111-8111-111111111111"),
      txt("22222222-2222-4222-8222-222222222222"),
      txt('["33333333-3333-4333-8333-333333333333"]'),
      i64(0),
      i64(1),
      i64(nowMicros + offset),
      i64(nowMicros + offset + 43_200_000_000n),
      i64(nowMicros + offset + 1_800_000_000n),
      i64(nowMicros + offset),
    ],
    [sc(), txt(uuid()), txt("session.created"), txt("{}")],
  ];
}
const load = (db: SqliteD1, handleHash: Uint8Array) =>
  run(db, "foundation.session-load", [[sc(), bytes(handleHash)]]);
const handleHashOf = (seed: number) =>
  Uint8Array.from({ length: 32 }, (_, index) => (index * 7 + seed) & 255);

test("a session is stored and found only by the hash of its handle and revocation is guarded", async () => {
  const db = createSqliteD1();
  const hashed = handleHashOf(1);
  assert.equal((await run(db, "foundation.session-create", sessionCreate("s1", hashed))).ok, true);
  const found = await load(db, hashed);
  assert.deepEqual(found.ok && found.rows[0]?.slice(0, 6), [
    "s1",
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222",
    '["33333333-3333-4333-8333-333333333333"]',
    "0",
    "1",
  ]);
  assert.deepEqual(found.ok && found.rows[0]?.slice(10), ["null", "null"]);
  assert.deepEqual(await load(db, handleHashOf(2)), { ok: true, rows: [], changes: "0" });
  // The same handle hash cannot be registered twice.
  assert.deepEqual(await run(db, "foundation.session-create", sessionCreate("s2", hashed)), {
    ok: false,
    failure: "constraint",
  });
  assert.equal(await count(db, "probe_session"), 1);
  assert.equal(
    await count(db, "probe_outbox"),
    1,
    "the failed batch must not leave its outbox row",
  );

  const revoke = (command = uuid()) => [
    [txt(command), sc(), txt("s1")],
    [i64(nowMicros + 5n), txt("logout"), sc(), txt("s1")],
    [sc(), txt(command), txt("session.revoked"), txt("{}")],
    [txt(command)],
  ];
  assert.equal((await run(db, "foundation.session-revoke", revoke())).ok, true);
  const revoked = await load(db, hashed);
  assert.deepEqual(revoked.ok && revoked.rows[0]?.slice(10), [String(nowMicros + 5n), "logout"]);
  // A second revoke finds no active session: the guard fails and nothing is written.
  assert.deepEqual(await run(db, "foundation.session-revoke", revoke()), {
    ok: false,
    failure: "precondition",
  });
  assert.equal(await count(db, "probe_outbox", "event_key = 'session.revoked'"), 1);
  // An unknown session cannot be revoked either.
  const unknown = [
    [txt(uuid()), sc(), txt("missing")],
    [i64(nowMicros), txt("logout"), sc(), txt("missing")],
    [sc(), txt(uuid()), txt("session.revoked"), txt("{}")],
    [txt(uuid())],
  ];
  assert.deepEqual(await run(db, "foundation.session-revoke", unknown), {
    ok: false,
    failure: "precondition",
  });
});

test("idle renewal moves only an active, unexpired, unrevoked session", async () => {
  const db = createSqliteD1();
  const hashed = handleHashOf(3);
  await run(db, "foundation.session-create", sessionCreate("s1", hashed));
  const touch = (now: bigint, idle: bigint) =>
    run(db, "foundation.session-touch", [
      [i64(now), i64(idle), sc(), bytes(hashed), i64(now), i64(now)],
    ]);
  const renewed = await touch(nowMicros + 60n, nowMicros + 1_800_000_060n);
  assert.deepEqual(renewed, { ok: true, rows: [], changes: "1" });
  const row = await load(db, hashed);
  assert.deepEqual(row.ok && row.rows[0]?.slice(8, 10), [
    String(nowMicros + 1_800_000_060n),
    String(nowMicros + 60n),
  ]);
  // After the idle expiry nothing changes (zero rows is reported as zero changes).
  assert.deepEqual(await touch(nowMicros + 1_800_000_061n, nowMicros + 9n), {
    ok: true,
    rows: [],
    changes: "0",
  });
  // After the absolute expiry nothing changes.
  assert.deepEqual(await touch(nowMicros + 43_200_000_001n, nowMicros + 9n), {
    ok: true,
    rows: [],
    changes: "0",
  });
});

function jobCommit(opts: {
  command?: string;
  job: string;
  fence: string;
  owner: string;
  cursor: string;
  now: bigint;
  items: string;
  next: string;
  checksum: string;
  event: string;
}) {
  const command = opts.command ?? uuid();
  return [
    [
      txt(command),
      sc(),
      txt(opts.job),
      i64(opts.fence),
      txt(opts.owner),
      i64(opts.cursor),
      i64(opts.now),
    ],
    [sc(), txt(opts.job), txt(opts.items)],
    [i64(opts.next), u64(opts.checksum), i64(opts.next), sc(), txt(opts.job), i64(opts.fence)],
    [sc(), txt(opts.event), i64(0)],
    [sc(), txt(command), txt("job.slice"), txt("{}")],
    [txt(command)],
  ];
}
const jobClaim = (job: string, owner: string, now: bigint, leaseUntil: bigint) => {
  const command = uuid();
  return [
    [txt(command), sc(), txt(job), i64(now), txt(owner)],
    [txt(owner), i64(leaseUntil), sc(), txt(job)],
    [txt(command)],
  ];
};
const jobLoad = async (db: SqliteD1, job: string) =>
  ((await run(db, "foundation.job-load", [[sc(), txt(job)]])) as { rows: string[][] }).rows[0];
const items = (from: number, to: number) =>
  JSON.stringify(
    Array.from({ length: to - from }, (_, index) => ({
      n: String(from + index),
      a: String(BigInt(from + index + 1) * 4_611_686_018_427n),
    })),
  );

test("a job slice is claimed under a lease, fenced and committed once with exact sums", async () => {
  const db = createSqliteD1();
  const job = "job-1";
  const start = await run(db, "foundation.job-start", [
    [sc(), txt(job), i64("10")],
    [sc(), txt(uuid()), txt("job.started"), txt("{}")],
  ]);
  assert.equal(start.ok, true);
  const now = 1_000n;
  const lease = now + 60_000_000n;
  assert.equal(
    (await run(db, "foundation.job-claim", jobClaim(job, "worker-a", now, lease))).ok,
    true,
  );
  assert.deepEqual((await jobLoad(db, job))?.slice(0, 5), [
    "10",
    "0",
    "1",
    "worker-a",
    String(lease),
  ]);

  // A second holder cannot claim while the lease is live, but the same owner can renew.
  assert.deepEqual(
    await run(db, "foundation.job-claim", jobClaim(job, "worker-b", now + 1n, lease + 1n)),
    {
      ok: false,
      failure: "precondition",
    },
  );
  const sum = (from: number, to: number) =>
    Array.from({ length: to - from }, (_, i) => BigInt(from + i + 1) * 4_611_686_018_427n).reduce(
      (a, b) => a + b,
      0n,
    );
  const wrong = [
    ["wrong fence", { fence: "2" }],
    ["wrong owner", { owner: "worker-b" }],
    ["wrong cursor", { cursor: "1" }],
    ["expired lease", { now: lease + 1n }],
  ] as const;
  for (const [label, override] of wrong) {
    const before = await jobLoad(db, job);
    const result = await run(
      db,
      "foundation.job-commit",
      jobCommit({
        job,
        fence: "1",
        owner: "worker-a",
        cursor: "0",
        now: 2_000n,
        items: items(0, 4),
        next: "4",
        checksum: String(sum(0, 4)),
        event: uuid(),
        ...override,
      }),
    );
    assert.deepEqual(result, { ok: false, failure: "precondition" }, label);
    assert.deepEqual(await jobLoad(db, job), before, label);
    assert.equal(await count(db, "probe_job_item"), 0, label);
    assert.equal(await count(db, "probe_inbox"), 0, label);
  }

  const event = uuid();
  const good = jobCommit({
    job,
    fence: "1",
    owner: "worker-a",
    cursor: "0",
    now: 2_000n,
    items: items(0, 4),
    next: "4",
    checksum: String(sum(0, 4)),
    event,
  });
  assert.equal((await run(db, "foundation.job-commit", good)).ok, true);
  assert.deepEqual((await jobLoad(db, job))?.slice(1, 2), ["4"]);
  assert.deepEqual(await run(db, "foundation.job-items", [[sc(), txt(job)]]), {
    ok: true,
    rows: [["4", String(sum(0, 4))]],
    changes: "0",
  });
  // Delivering the same event again is stopped by the inbox row and undoes the whole slice.
  const duplicate = jobCommit({
    job,
    fence: "1",
    owner: "worker-a",
    cursor: "4",
    now: 2_001n,
    items: items(4, 8),
    next: "8",
    checksum: String(sum(0, 8)),
    event,
  });
  assert.deepEqual(await run(db, "foundation.job-commit", duplicate), {
    ok: false,
    failure: "constraint",
  });
  assert.deepEqual((await jobLoad(db, job))?.slice(1, 2), ["4"]);
  assert.equal(await count(db, "probe_job_item"), 4);
  const seen = await run(db, "foundation.inbox-seen", [[sc(), txt(event), i64(0)]]);
  assert.deepEqual(seen, { ok: true, rows: [["1"]], changes: "0" });
});

test("a stale holder cannot finalize after its lease is taken over, and the job completes exactly once", async () => {
  const db = createSqliteD1();
  const job = "job-2";
  await run(db, "foundation.job-start", [
    [sc(), txt(job), i64("3")],
    [sc(), txt(uuid()), txt("job.started"), txt("{}")],
  ]);
  await run(db, "foundation.job-claim", jobClaim(job, "old", 10n, 20n));
  // The lease expired, so another worker takes over with a higher fence.
  assert.equal((await run(db, "foundation.job-claim", jobClaim(job, "new", 21n, 90n))).ok, true);
  assert.equal((await jobLoad(db, job))?.[2], "2");
  const stale = await run(
    db,
    "foundation.job-commit",
    jobCommit({
      job,
      fence: "1",
      owner: "old",
      cursor: "0",
      now: 15n,
      items: items(0, 3),
      next: "3",
      checksum: "1",
      event: uuid(),
    }),
  );
  assert.deepEqual(stale, { ok: false, failure: "precondition" });
  const fresh = await run(
    db,
    "foundation.job-commit",
    jobCommit({
      job,
      fence: "2",
      owner: "new",
      cursor: "0",
      now: 30n,
      items: items(0, 3),
      next: "3",
      checksum: String(4_611_686_018_427n * 6n),
      event: uuid(),
    }),
  );
  assert.equal(fresh.ok, true);
  const row = await jobLoad(db, job);
  assert.deepEqual(
    [row?.[1], row?.[5], row?.[6]],
    ["3", "complete", String(4_611_686_018_427n * 6n)],
  );
  // A completed job can no longer be claimed or committed.
  assert.deepEqual(await run(db, "foundation.job-claim", jobClaim(job, "new", 31n, 91n)), {
    ok: false,
    failure: "precondition",
  });
});

test("a cursor beyond the job total violates the table constraint and undoes the slice", async () => {
  const db = createSqliteD1();
  const job = "job-3";
  await run(db, "foundation.job-start", [
    [sc(), txt(job), i64("2")],
    [sc(), txt(uuid()), txt("job.started"), txt("{}")],
  ]);
  await run(db, "foundation.job-claim", jobClaim(job, "w", 1n, 1_000n));
  const result = await run(
    db,
    "foundation.job-commit",
    jobCommit({
      job,
      fence: "1",
      owner: "w",
      cursor: "0",
      now: 2n,
      items: items(0, 3),
      next: "3",
      checksum: "1",
      event: uuid(),
    }),
  );
  assert.deepEqual(result, { ok: false, failure: "constraint" });
  assert.equal(await count(db, "probe_job_item"), 0);
});
