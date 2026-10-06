// SPDX-License-Identifier: AGPL-3.0-only
// Real migrated SQLite evidence for the Identity lifecycle; this is not deployed D1/provider/OS acceptance.
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { defaultMigrationsDirectory, loadCatalog } from "../../eng/migrations/catalog.ts";

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
    const invalid = [
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
