// SPDX-License-Identifier: AGPL-3.0-only
// Real migrated SQLite evidence for the Identity lifecycle; this is not deployed D1/provider/OS acceptance.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { defaultMigrationsDirectory, loadCatalog } from "../../eng/migrations/catalog.ts";
import { commitDatabase, execute } from "./support/commit-support.ts";
import { txt } from "./support/plan-calls.ts";
import { expandGuard } from "../../eng/verification/storage-plans.ts";
import { loadManifest } from "../../eng/verification/physical-schema.ts";

// Own future-consumer composition against the actual Git-merged CLOUD78 compiler.
// No production family registration, standalone deletion commit or provider acceptance is implied.
const ownSchema = loadManifest();
const userLink = expandGuard(
  "kind=authorization module=identity key=deletion-user table=identity_user by=realm_id,user_id match=state,deletion_requested_at,rev",
  ownSchema,
  "CLOUD79 original request",
  "account-security",
  "cancel-deletion",
);
const currentHeader =
  "kind=authorization module=identity key=deletion-current table=identity_account_deletion by=deletion_id,realm_id,user_id match=requested_at,policy_version,state securityExpiry=grace_ends_at";

test("actual original-request user linkage fences lifecycle cancellation and rolls back earlier owner effects", () => {
  const lifecycleGuard = expandGuard(
    currentHeader,
    ownSchema,
    "CLOUD79 cancel",
    "account-security",
    "cancel-deletion",
  );
  const lifecycleRevision = expandGuard(
    "kind=revision module=identity key=deletion-revision table=identity_account_deletion by=deletion_id rev=rev",
    ownSchema,
    "CLOUD79 current lifecycle",
    "account-security",
    "cancel-deletion",
  );
  for (const changed of [
    "none",
    "request",
    "revision",
    "lifecycle-revision",
    "state",
    "expired",
    "tail",
  ] as const) {
    const db = database();
    const now = Date.now() * 1000;
    const ends = now + (changed === "expired" ? -1_000_000 : 60_000_000);
    const original = ends - 120_000_000;
    try {
      db.prepare(
        "UPDATE identity_user SET state=4,deletion_requested_at=?,rev=7 WHERE user_id=?",
      ).run(original, user);
      db.prepare(
        "INSERT INTO identity_account_deletion VALUES (?,?,?,?,?,'policy.v1',120,3,1,NULL,NULL,1)",
      ).run(deletion, realm, user, original, ends);
      if (changed === "request")
        db.prepare("UPDATE identity_user SET deletion_requested_at=? WHERE user_id=?").run(
          original + 1,
          user,
        );
      if (changed === "revision") db.exec("UPDATE identity_user SET rev=8");
      if (changed === "lifecycle-revision") db.exec("UPDATE identity_account_deletion SET rev=2");
      if (changed === "state") db.exec("UPDATE identity_user SET state=3");
      const beforeUser = db.prepare("SELECT * FROM identity_user").all();
      const beforeLife = db.prepare("SELECT * FROM identity_account_deletion").all();
      db.exec("BEGIN IMMEDIATE");
      const apply = () => {
        db.prepare(lifecycleGuard.sql).run(
          nextDeletion,
          deletion,
          realm,
          user,
          original,
          "policy.v1",
          1,
          changed === "expired" ? ends - 1 : now,
        );
        db.prepare(userLink.sql).run(nextDeletion, realm, user, 4, original, 7);
        db.prepare(lifecycleRevision.sql).run(nextDeletion, deletion, 1);
        db.prepare(
          "UPDATE identity_account_deletion SET state=2,cancelled_at=?,rev=rev+1 WHERE deletion_id=?",
        ).run(now, deletion);
        db.prepare(
          "UPDATE identity_user SET state=3,deletion_requested_at=NULL,rev=rev+1 WHERE user_id=?",
        ).run(user);
        if (changed === "tail")
          db.prepare(
            "INSERT INTO platform_command_guard VALUES (?, 'identity.deletion-user',1)",
          ).run(nextDeletion);
      };
      if (changed === "none") {
        apply();
        db.exec("COMMIT");
        assert.equal(db.prepare("SELECT state FROM identity_account_deletion").get()?.state, 2);
        assert.equal(db.prepare("SELECT state FROM identity_user").get()?.state, 3);
      } else {
        assert.throws(apply);
        db.exec("ROLLBACK");
        assert.deepEqual(db.prepare("SELECT * FROM identity_user").all(), beforeUser);
        assert.deepEqual(db.prepare("SELECT * FROM identity_account_deletion").all(), beforeLife);
      }
    } finally {
      db.close();
    }
  }
});

test("actual own due roles refuse a future immutable deadline without any caller clock parameter", () => {
  for (const [key, plan, state] of [
    ["deletion-due", "begin-deletion-purge", 1],
    ["deletion-purging", "complete-deletion-purge", 3],
  ] as const) {
    const guard = expandGuard(
      `kind=authorization module=identity key=${key} table=identity_account_deletion by=deletion_id,realm_id,user_id match=requested_at,policy_version,state securityDue=grace_ends_at`,
      ownSchema,
      "CLOUD79 due",
      "account-security",
      plan,
    );
    assert.equal(guard.meta.securityExpiry?.capturedParamIndex, null);
    for (const due of [false, true]) {
      const db = database();
      const ends = Date.now() * 1000 + (due ? -1_000_000 : 60_000_000);
      const original = ends - 120_000_000;
      try {
        db.prepare(
          "INSERT INTO identity_account_deletion VALUES (?,?,?,?,?,'policy.v1',120,3,?,NULL,NULL,1)",
        ).run(deletion, realm, user, original, ends, state);
        const args = [nextDeletion, deletion, realm, user, original, "policy.v1", state];
        db.exec("BEGIN IMMEDIATE");
        if (due) db.prepare(guard.sql).run(...args);
        else assert.throws(() => db.prepare(guard.sql).run(...args), /CHECK constraint failed/u);
        assert.throws(() => db.prepare(guard.sql).run(...args, Number.MAX_SAFE_INTEGER));
        db.exec("ROLLBACK");
        assert.equal(db.prepare("SELECT count(*) AS n FROM platform_command_guard").get()?.n, 0);
      } finally {
        db.close();
      }
    }
  }
});

test("actual active-state revision absence permits retained terminal history and denies pending or purging rows", () => {
  const empty = ["deletion-pending-empty", "deletion-purging-empty"].map((key) =>
    expandGuard(
      `kind=revision module=identity key=${key} table=identity_account_deletion by=user_id,state rev=rev`,
      ownSchema,
      "CLOUD79 request",
      "account-security",
      "request-deletion",
    ),
  );
  const [pendingEmpty, purgingEmpty] = empty;
  assert(pendingEmpty && purgingEmpty);
  for (const state of [2, 1, 3]) {
    const db = database();
    try {
      insert(db);
      if (state === 2)
        db.exec("UPDATE identity_account_deletion SET state=2,cancelled_at=500,rev=rev+1");
      if (state === 3) db.exec("UPDATE identity_account_deletion SET state=3,rev=rev+1");
      db.exec("BEGIN IMMEDIATE");
      const run = () => {
        db.prepare(pendingEmpty.sql).run(nextDeletion, user, 1, 0);
        db.prepare(purgingEmpty.sql).run(nextDeletion, user, 3, 0);
      };
      if (state === 2) run();
      else assert.throws(run, /CHECK constraint failed/u);
      db.exec("ROLLBACK");
      assert.equal(db.prepare("SELECT count(*) AS n FROM platform_command_guard").get()?.n, 0);
    } finally {
      db.close();
    }
  }
});

const realm = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const user = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const deletion = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const nextDeletion = "dddddddd-dddd-dddd-dddd-dddddddddddd";
const requested = 100;
const deadline = 1_000_100;

function database(file = ":memory:"): DatabaseSync {
  const db = new DatabaseSync(file);
  db.exec("PRAGMA foreign_keys=ON");
  for (const migration of loadCatalog()) db.exec(migration.text);
  const pending = path.join(defaultMigrationsDirectory, "pending/identity__deletion-lifecycle.sql");
  if (existsSync(pending)) db.exec(readFileSync(pending, "utf8"));
  db.prepare("INSERT INTO identity_user VALUES (?, ?, ?, ?, ?, NULL, 1)").run(
    user,
    realm,
    "Original",
    3,
    0,
  );
  return db;
}

function insert(db: DatabaseSync, id = deletion, at = requested, duration = 1): void {
  db.prepare(
    "INSERT INTO identity_account_deletion VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, 1)",
  ).run(id, realm, user, at, at + duration * 1_000_000, "policy.v1", duration, 3, 1);
}

test("one active lifecycle, immutable disclosure, retained cancelled history and previous state", () => {
  const db = database();
  try {
    insert(db);
    assert.throws(() => insert(db, nextDeletion), /UNIQUE/);
    for (const change of [
      "grace_ends_at=grace_ends_at+1",
      "policy_version='policy.v2'",
      "grace_seconds=2",
      "previous_user_state=1",
      "requested_at=101",
      `realm_id='${nextDeletion}'`,
    ])
      assert.throws(() => db.exec(`UPDATE identity_account_deletion SET ${change}`), /constraint/i);
    db.prepare(
      "UPDATE identity_account_deletion SET state=2, cancelled_at=?, rev=rev+1 WHERE deletion_id=?",
    ).run(999, deletion);
    const row = db
      .prepare(
        "SELECT previous_user_state, policy_version, grace_ends_at FROM identity_account_deletion WHERE deletion_id=?",
      )
      .get(deletion);
    assert.deepEqual(
      { ...row },
      { previous_user_state: 3, policy_version: "policy.v1", grace_ends_at: deadline },
    );
    assert.throws(() => db.exec("UPDATE identity_account_deletion SET rev=rev+1"), /constraint/i);
    assert.throws(() => db.exec("DELETE FROM identity_account_deletion"), /constraint/i);
    insert(db, nextDeletion, 2_000_000);
    assert.equal(db.prepare("SELECT count(*) AS n FROM identity_account_deletion").get()?.n, 2);
    assert.deepEqual(db.prepare("PRAGMA foreign_key_check").all(), []);
  } finally {
    db.close();
  }
});

test("checked integer duration and exact terminal fact constraints refuse malformed rows", () => {
  const db = database();
  try {
    const statement = db.prepare(
      "INSERT INTO identity_account_deletion VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)",
    );
    const invalid: [number, number, number, number, number, number | null, number | null][] = [
      [requested, deadline + 1, 1, 3, 1, null, null],
      [requested, deadline, 0, 3, 1, null, null],
      [requested, deadline, 1, 4, 1, null, null],
      [requested, deadline, 1, 3, 1, 999, null],
      [requested, deadline, 1, 3, 2, null, null],
      [requested, deadline, 1, 3, 2, deadline, null],
      [requested, deadline, 1, 3, 3, null, deadline],
      [requested, deadline, 1, 3, 4, null, deadline - 1],
    ];
    for (const [at, until, duration, previous, state, cancelled, completed] of invalid)
      assert.throws(
        () =>
          statement.run(
            deletion,
            realm,
            user,
            at,
            until,
            "policy.v1",
            duration,
            previous,
            state,
            cancelled,
            completed,
          ),
        /constraint/i,
      );
    assert.throws(
      () =>
        statement.run(
          deletion,
          realm,
          user,
          9223372036854775806n,
          9223372036854775807n,
          "policy.v1",
          1,
          3,
          1,
          null,
          null,
        ),
      /constraint/i,
    );
    assert.equal(db.prepare("SELECT count(*) AS n FROM identity_account_deletion").get()?.n, 0);
  } finally {
    db.close();
  }
});

test("purge records are not completed before deadline and preserve original disclosure", () => {
  const db = database();
  try {
    insert(db);
    db.exec("UPDATE identity_account_deletion SET state=3, rev=rev+1");
    assert.throws(() => insert(db, nextDeletion), /UNIQUE/);
    assert.throws(
      () =>
        db
          .prepare("UPDATE identity_account_deletion SET state=4, completed_at=?, rev=rev+1")
          .run(deadline - 1),
      /constraint/i,
    );
    db.prepare("UPDATE identity_account_deletion SET state=4, completed_at=?, rev=rev+1").run(
      deadline,
    );
    assert.deepEqual(
      {
        ...db
          .prepare("SELECT state, rev, completed_at, policy_version FROM identity_account_deletion")
          .get(),
      },
      { state: 4, rev: 3, completed_at: deadline, policy_version: "policy.v1" },
    );
    assert.throws(() => db.exec("UPDATE identity_account_deletion SET rev=rev+1"), /constraint/i);
  } finally {
    db.close();
  }
});

test("deadline survives actual database close/reopen without any current configuration", () => {
  const directory = mkdtempSync(path.join(tmpdir(), "arcforges-deletion-"));
  const file = path.join(directory, "lifecycle.sqlite");
  let db = database(file);
  try {
    insert(db);
    db.close();
    db = new DatabaseSync(file);
    assert.deepEqual(
      {
        ...db
          .prepare(
            "SELECT requested_at, grace_ends_at, policy_version, grace_seconds, previous_user_state FROM identity_account_deletion",
          )
          .get(),
      },
      {
        requested_at: requested,
        grace_ends_at: deadline,
        policy_version: "policy.v1",
        grace_seconds: 1,
        previous_user_state: 3,
      },
    );
  } finally {
    db.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("failed guarded transition rolls back both actual lifecycle and user state", () => {
  const db = database();
  try {
    insert(db);
    db.exec("BEGIN IMMEDIATE");
    db.exec("UPDATE identity_user SET state=4, deletion_requested_at=100, rev=rev+1");
    assert.throws(
      () =>
        db.exec("UPDATE identity_account_deletion SET state=2, cancelled_at=1000100, rev=rev+1"),
      /constraint/i,
    );
    db.exec("ROLLBACK");
    assert.deepEqual(
      { ...db.prepare("SELECT state, rev, deletion_requested_at FROM identity_user").get() },
      { state: 3, rev: 1, deletion_requested_at: null },
    );
    assert.deepEqual(
      { ...db.prepare("SELECT state, rev FROM identity_account_deletion").get() },
      { state: 1, rev: 1 },
    );
  } finally {
    db.close();
  }
});

test("actual registered Worker read is realm-scoped, typed, fresh and side-effect free under concurrent calls", async () => {
  const db = commitDatabase();
  try {
    db.database
      .prepare("INSERT INTO identity_user VALUES (?, ?, ?, 4, 0, 100, 7)")
      .run(user, realm, "Original");
    insert(db.database);
    const read = () => execute(db, "identity.deletion-current", [[txt(realm), txt(user)]], realm);
    const outcomes = await Promise.all(Array.from({ length: 12 }, read));
    for (const outcome of outcomes) {
      assert(outcome.ok);
      assert.deepEqual(outcome.rows, [
        [
          deletion,
          realm,
          user,
          "100",
          "1000100",
          "policy.v1",
          "1",
          "3",
          "1",
          "null",
          "null",
          "1",
          "4",
          "7",
          "100",
        ],
      ]);
    }
    assert.equal(db.database.prepare("SELECT count(*) AS n FROM platform_command").get()?.n, 0);
    db.database.exec("UPDATE identity_user SET rev=8");
    const fresh = await read();
    assert(fresh.ok);
    assert.equal(fresh.rows[0]?.[13], "8");
    db.database.exec("UPDATE identity_account_deletion SET state=3, rev=rev+1");
    const purging = await read();
    assert(purging.ok);
    assert.equal(purging.rows[0]?.[8], "3");
    assert.equal(purging.rows[0]?.[11], "2");
  } finally {
    db.database.close();
  }
});

test("actual Worker refuses mismatched ownerScope and other-user or realm reads remain empty", async () => {
  const db = commitDatabase();
  try {
    db.database
      .prepare("INSERT INTO identity_user VALUES (?, ?, ?, 4, 0, 100, 7)")
      .run(user, realm, "Original");
    insert(db.database);
    assert.deepEqual(
      await execute(db, "identity.deletion-current", [[txt(realm), txt(user)]], nextDeletion),
      { ok: false, failure: "invalidPlan" },
    );
    const anotherUser = await execute(
      db,
      "identity.deletion-current",
      [[txt(realm), txt(nextDeletion)]],
      realm,
    );
    assert(anotherUser.ok);
    assert.deepEqual(anotherUser.rows, []);
    const anotherRealm = await execute(
      db,
      "identity.deletion-current",
      [[txt(nextDeletion), txt(user)]],
      nextDeletion,
    );
    assert(anotherRealm.ok);
    assert.deepEqual(anotherRealm.rows, []);
  } finally {
    db.database.close();
  }
});

test("actual transition reads capture current user and immutable cancelled lifecycle without granting authority", async () => {
  const db = commitDatabase();
  try {
    db.database
      .prepare("INSERT INTO identity_user VALUES (?, ?, ?, 3, 0, NULL, 9)")
      .run(user, realm, "Original");
    insert(db.database);
    db.database
      .prepare(
        "UPDATE identity_account_deletion SET state=2, cancelled_at=500, rev=rev+1 WHERE deletion_id=?",
      )
      .run(deletion);
    const currentUser = await execute(
      db,
      "identity.deletion-user",
      [[txt(realm), txt(user)]],
      realm,
    );
    assert(currentUser.ok);
    assert.deepEqual(currentUser.rows, [[realm, user, "3", "null", "9"]]);
    const lifecycle = await execute(
      db,
      "identity.deletion-state",
      [[txt(realm), txt(user), txt(deletion)]],
      realm,
    );
    assert(lifecycle.ok);
    assert.equal(lifecycle.rows.length, 1);
    assert(lifecycle.rows[0]);
    assert.deepEqual(lifecycle.rows[0].slice(7), ["3", "2", "500", "null", "2", "3", "9", "null"]);
    db.database.prepare("UPDATE identity_user SET rev=rev+1 WHERE user_id=?").run(user);
    const reread = await execute(
      db,
      "identity.deletion-state",
      [[txt(realm), txt(user), txt(deletion)]],
      realm,
    );
    assert(reread.ok);
    assert(reread.rows[0]);
    assert.deepEqual(reread.rows[0][13], "10");
    assert.deepEqual(
      await execute(db, "identity.deletion-user", [[txt(realm), txt(user)]], nextDeletion),
      { ok: false, failure: "invalidPlan" },
    );
    assert.deepEqual(
      await execute(
        db,
        "identity.deletion-state",
        [[txt(realm), txt(user), txt(deletion)]],
        nextDeletion,
      ),
      { ok: false, failure: "invalidPlan" },
    );
    const foreign = await execute(
      db,
      "identity.deletion-state",
      [[txt(realm), txt(nextDeletion), txt(deletion)]],
      realm,
    );
    assert(foreign.ok);
    assert.deepEqual(foreign.rows, []);
    assert.equal(db.database.prepare("SELECT COUNT(*) AS n FROM platform_command").get()?.n, 0);
  } finally {
    db.database.close();
  }
});
