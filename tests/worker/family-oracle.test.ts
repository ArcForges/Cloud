// SPDX-License-Identifier: AGPL-3.0-only
// The generated family SQL run on the real numbered migrations in node:sqlite (the oracle), through the production Worker executor.
// It proves the guard primitives, the whole-batch rollback, a stale writer, a stale lease holder and exact 64-bit comparison on the
// engine SQLite shares with D1. SQLite is not D1: workerd's D1 run (npm run test:d1:families:local) repeats the contention cases on
// the closest local engine, and the provider's REST batch atomicity stays a deferred live check.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  defaults,
  fixtureArguments,
  fixtureManifest,
  ids,
  i64,
  nowMicros,
  openFamilyD1,
  runFamily,
  seed,
  snapshot,
  uuid,
  workerDictionary,
  type FixtureValues,
} from "./support/family-fixtures.ts";

const dictionary = workerDictionary(fixtureManifest());
type Db = ReturnType<typeof openFamilyD1>;
const attempt = (db: Db, values: FixtureValues) =>
  runFamily(db, dictionary, fixtureArguments(values), ids.workspace);
const guardRows = (db: Db) =>
  Number(db.database.prepare("SELECT COUNT(*) AS n FROM platform_command_guard").get()?.["n"]);
type State = Record<string, unknown[][]>;

function seeded(overrides: Parameters<typeof seed>[1] = {}) {
  const db = openFamilyD1();
  seed(db, overrides);
  return db;
}

test("a batch whose guards all hold commits every mutation and the receipt and leaves no guard row", async () => {
  const db = seeded();
  const result = await attempt(db, defaults());
  assert.equal(result.ok, true);
  const state = snapshot(db) as State;
  assert.deepEqual(state["budget"], [["13", "2", "4"]]);
  assert.deepEqual(state["revision"], [["8"]]);
  assert.deepEqual(state["suppression"], [[ids.recipientHash, "1"]]);
  assert.equal(state["commands"]?.length, 1);
  assert.deepEqual(state["guards"], []);
  assert.equal(db.rollbacks(), 0);
});

/** Every case: one decided value is wrong, so exactly one guard is false and the whole batch must roll back. */
const refusals: [string, Partial<FixtureValues>][] = [
  ["a lease holder that is not the current holder", { holder: "container-b" }],
  ["a lease fence that differs from the stored fence", { fence: "4" }],
  ["a lease that expired at the trusted instant", { now: String(nowMicros + 700_000_000n) }],
  ["a configuration revision in another state", { configState: "1" }],
  ["a workspace in another state", { workspaceState: "2" }],
  ["a stale entitlement revision", { revision: "6" }],
  ["a balance revision that moved", { budgetRev: "2" }],
  ["a captured used balance that differs", { usedBefore: "9" }],
  ["a captured held balance that differs", { heldBefore: "3" }],
  ["a source policy whose revision moved", { policyRevision: "3" }],
  ["a suppression row that already exists where none was expected", { suppressionRev: "1" }],
];
for (const [name, change] of refusals) {
  test(`a false guard rolls everything back: ${name}`, async () => {
    const db = seeded();
    if (change.suppressionRev === "1")
      db.database
        .prepare(
          "INSERT INTO notification_suppression (recipient_hash, stream, reason, provider_event_id, created_at, cleared_at, rev) VALUES (?, 1, 1, NULL, CAST(? AS INTEGER), NULL, 1)",
        )
        .run(ids.recipientHash, String(nowMicros));
    const before = snapshot(db);
    // The row that exists makes the expectation of absence false: the caller expected revision zero.
    const values =
      change.suppressionRev === "1"
        ? { ...defaults(), suppressionRev: "0" }
        : { ...defaults(), ...change };
    const result = await attempt(db, values);
    assert.deepEqual(result, { ok: false, failure: "precondition" });
    assert.deepEqual(snapshot(db), before, "no table changed");
    assert.equal(guardRows(db), 0, "no guard row survives a rollback");
    assert.equal(db.rollbacks(), 1);
  });
}

test("a constraint that fails after every guard passed still rolls the guarded mutations back", async () => {
  const db = seeded();
  const first = defaults();
  assert.equal((await attempt(db, first)).ok, true);
  // The same command id again with the recalculated, now current values: the receipt key is a duplicate, so the batch fails at its
  // last mutation, after the quota and revision updates ran.
  const before = snapshot(db);
  const replay = await attempt(db, {
    ...first,
    revision: "8",
    budgetRev: "4",
    usedBefore: "13",
    usedAfter: "16",
    suppressionRev: "0",
    recipient: "recipient-replay",
  });
  assert.deepEqual(replay, { ok: false, failure: "constraint" });
  assert.deepEqual(snapshot(db), before, "nothing of the failed replay remains");
  assert.equal(guardRows(db), 0);
});

test("a guard is classified as a failed precondition and any other CHECK keeps the constraint class", async () => {
  const db = seeded();
  assert.deepEqual(await attempt(db, { ...defaults(), revision: "99" }), {
    ok: false,
    failure: "precondition",
  });
  // Every guard holds, and the bucket update then breaks the used-is-nonnegative CHECK of its own table.
  assert.deepEqual(await attempt(db, { ...defaults(), usedAfter: "-1" }), {
    ok: false,
    failure: "constraint",
  });
});

test("two writers that read the same revision: one commits, the other is refused whole and succeeds after rereading", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "family-contention-"));
  const file = path.join(directory, "d1.sqlite");
  const first = openFamilyD1(file);
  seed(first);
  // The second container is a second handle on the same database, as two Containers share one D1.
  const second = openFamilyD1(file, false);
  const a = { ...defaults(), usedAfter: "13", recipient: "recipient-a" };
  const b = { ...defaults(), usedAfter: "15", recipient: "recipient-b" };
  assert.equal((await attempt(first, a)).ok, true);
  const afterFirst = snapshot(second);
  assert.deepEqual(await attempt(second, b), { ok: false, failure: "precondition" });
  assert.deepEqual(snapshot(second), afterFirst, "the stale writer changed nothing");
  assert.equal(second.rollbacks(), 1);
  // It rereads the committed state (revision 8, budget revision 4, used 13) and recalculates under its own command.
  const reread = { ...b, revision: "8", budgetRev: "4", usedBefore: "13", usedAfter: "15" };
  assert.equal((await attempt(second, reread)).ok, true);
  const state = snapshot(first) as State;
  assert.deepEqual(state["budget"], [["15", "2", "5"]]);
  assert.deepEqual(state["revision"], [["9"]]);
  assert.equal(state["commands"]?.length, 2, "each command is recorded once");
  assert.deepEqual(state["suppression"]?.map((row) => row[0]).sort(), [
    "recipient-a",
    "recipient-b",
  ]);
});

test("a lost response replayed under the same command applies nothing twice, whether its values are stale or current", async () => {
  const db = seeded();
  const command = defaults();
  assert.equal((await attempt(db, command)).ok, true);
  const committed = snapshot(db);
  // The caller never saw the answer and resubmits the very same request: its guards are stale ...
  assert.deepEqual(await attempt(db, command), { ok: false, failure: "precondition" });
  // ... and recalculated against current state it meets the receipt key (the receipt lookup then returns the original result).
  const current = {
    ...command,
    revision: "8",
    budgetRev: "4",
    usedBefore: "13",
    usedAfter: "16",
    recipient: "recipient-other",
  };
  assert.deepEqual(await attempt(db, current), { ok: false, failure: "constraint" });
  assert.deepEqual(snapshot(db), committed);
});

test("a stale lease holder cannot finalize after takeover, and the new holder can", async () => {
  const db = seeded();
  // Container B took the lease over: a higher fence and its own identity.
  db.database
    .prepare("UPDATE platform_job_lease SET holder = 'container-b', fence_token = 6")
    .run();
  const before = snapshot(db);
  assert.deepEqual(await attempt(db, defaults()), { ok: false, failure: "precondition" });
  assert.deepEqual(snapshot(db), before);
  // The old holder with the new fence still is not the holder; the new holder with the old fence is stale.
  assert.deepEqual(await attempt(db, { ...defaults(), fence: "6" }), {
    ok: false,
    failure: "precondition",
  });
  assert.deepEqual(await attempt(db, { ...defaults(), holder: "container-b" }), {
    ok: false,
    failure: "precondition",
  });
  assert.equal((await attempt(db, { ...defaults(), holder: "container-b", fence: "6" })).ok, true);
});

test("an expiry is exclusive: a lease valid until the instant is no longer valid at it", async () => {
  const until = String(nowMicros + 1000n);
  const exactly = seeded({ leaseUntilMicros: until });
  assert.deepEqual(await attempt(exactly, { ...defaults(), now: until }), {
    ok: false,
    failure: "precondition",
  });
  const justBefore = seeded({ leaseUntilMicros: until });
  assert.equal(
    (await attempt(justBefore, { ...defaults(), now: String(nowMicros + 999n) })).ok,
    true,
  );
});

test("balances compare exactly above 2^53 and at the int64 bound, never through a float", async () => {
  const exact = "9007199254740993";
  const db = seeded({ used: exact, held: "2" });
  assert.deepEqual(
    await attempt(db, {
      ...defaults(),
      usedBefore: "9007199254740992",
      usedAfter: "9007199254740994",
    }),
    { ok: false, failure: "precondition" },
  );
  assert.deepEqual(
    await attempt(db, {
      ...defaults(),
      usedBefore: "9007199254740994",
      usedAfter: "9007199254740995",
    }),
    { ok: false, failure: "precondition" },
  );
  assert.equal(
    (await attempt(db, { ...defaults(), usedBefore: exact, usedAfter: "9223372036854775807" })).ok,
    true,
  );
  assert.deepEqual((snapshot(db) as State)["budget"], [["9223372036854775807", "2", "4"]]);
  // One past the signed range never reaches SQL: the bridge refuses it before anything runs.
  const refused = seeded();
  const before = snapshot(refused);
  assert.deepEqual(await attempt(refused, { ...defaults(), usedAfter: "9223372036854775808" }), {
    ok: false,
    failure: "invalidPlan",
  });
  assert.deepEqual(snapshot(refused), before);
});

test("the owner scope must equal the scope-bound key of every guard and receipt", async () => {
  const db = seeded();
  const before = snapshot(db);
  const result = await runFamily(db, dictionary, fixtureArguments(defaults()), "another-workspace");
  assert.deepEqual(result, { ok: false, failure: "invalidPlan" });
  assert.deepEqual(snapshot(db), before);
});

test("a call that omits a statement or sends the wrong argument kind is refused before SQL runs", async () => {
  const db = seeded();
  const before = snapshot(db);
  const full = fixtureArguments(defaults());
  assert.deepEqual(await runFamily(db, dictionary, full.slice(0, -1), ids.workspace), {
    ok: false,
    failure: "invalidPlan",
  });
  const wrongKind = full.map((row) => [...row]);
  wrongKind[2] = [wrongKind[2]?.[0] ?? i64(0), wrongKind[2]?.[1] ?? i64(0), i64(5), i64(1)];
  assert.deepEqual(await runFamily(db, dictionary, wrongKind, ids.workspace), {
    ok: false,
    failure: "invalidPlan",
  });
  assert.deepEqual(snapshot(db), before);
});

test("guard rows are keyed by command: another command's leftover row neither blocks nor is released", async () => {
  const db = seeded();
  // Rows of another command (as a non-atomic provider path could leave them) do not block this command, and the release keeps them.
  db.database
    .prepare(
      "INSERT INTO platform_command_guard (command_id, guard_key, allowed) VALUES (?, 'entitlement.quota', 1)",
    )
    .run(uuid());
  assert.equal((await attempt(db, defaults())).ok, true);
  assert.equal(guardRows(db), 1, "only the foreign row remains; this command's rows were released");
});
