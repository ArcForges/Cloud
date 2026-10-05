// SPDX-License-Identifier: AGPL-3.0-only
// The identity core plans (storage/plans/identity) and the enrollment family (families.account-enrollment.create-user) run on the real
// numbered migrations in node:sqlite through the production Worker executor (CLOUD.11, WP-22.00). It proves, on the engine SQLite shares
// with D1: user continuity across credential changes, the single-owner workspace, the last-credential rule, realm isolation, tenant
// leakage refusals and the stale-writer races of linking and revoking. SQLite is not D1: workerd's D1 run
// (npm run test:d1:identity:local) repeats the engine-dependent cases, and the provider's REST batch stays a deferred live check.
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  addArguments,
  count,
  credential,
  enroll,
  enrollArguments,
  enrollInputs,
  enrollmentPlan,
  nowMicros,
  openIdentityD1,
  realmA,
  realmB,
  relabelArguments,
  renameArguments,
  revokeArguments,
  rows,
  runPlan,
  snapshotIdentity,
  tailInputs,
  uid,
  type Account,
  type IdentityD1,
} from "./support/identity-support.ts";
import { i64, txt } from "./support/plan-calls.ts";

type Database = IdentityD1;

const userRow = (db: Database, user: string) =>
  rows(
    db,
    `SELECT user_id, realm_id, display_name, CAST(state AS TEXT), CAST(created_at AS TEXT), CAST(deletion_requested_at AS TEXT), CAST(rev AS TEXT) FROM identity_user WHERE user_id = '${user}'`,
  )[0];
const workspaceRows = (db: Database) =>
  rows(
    db,
    "SELECT workspace_id, realm_id, owner_user_id, name, data_region, CAST(state AS TEXT), CAST(rev AS TEXT) FROM workspace_workspace ORDER BY workspace_id",
  );
const guards = (db: Database) => count(db, "platform_command_guard");

async function add(
  db: Database,
  account: Account,
  subject: string,
  userRevision: number,
  overrides: { realm?: string; user?: string; provider?: string } = {},
) {
  const realm = overrides.realm ?? account.realm;
  const user = overrides.user ?? account.user;
  const next = credential(account.user, account.realm, subject, {
    ...(overrides.provider ? { provider: overrides.provider } : {}),
  });
  const outcome = await runPlan(
    db,
    "identity.credential-add",
    addArguments({
      ...tailInputs(),
      realm,
      user,
      scope: account.workspace,
      expectedUserRevision: userRevision,
      credential: next,
    }),
    account.workspace,
  );
  return { outcome, credential: next };
}

async function revoke(
  db: Database,
  account: Account,
  target: string,
  credentialRevision: number,
  userRevision: number,
  overrides: { user?: string; realm?: string } = {},
) {
  return runPlan(
    db,
    "identity.credential-revoke",
    revokeArguments({
      ...tailInputs(),
      realm: overrides.realm ?? account.realm,
      user: overrides.user ?? account.user,
      scope: account.workspace,
      target,
      expectedCredentialRevision: credentialRevision,
      expectedUserRevision: userRevision,
      at: nowMicros + 1_000_000,
    }),
    account.workspace,
  );
}

const refused = { ok: false, failure: "precondition" } as const;
const changesOf = (outcome: Awaited<ReturnType<typeof runPlan>>) =>
  outcome.ok ? outcome.changes : outcome.failure;

test("an enrollment creates the user, the credential and exactly one personal workspace owned by the user, with one receipt, one event and one change record", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  assert.deepEqual(userRow(db, account.user), [
    account.user,
    realmA,
    "Ada",
    "1",
    String(nowMicros),
    null,
    "1",
  ]);
  assert.deepEqual(workspaceRows(db), [
    [account.workspace, realmA, account.user, "Personal", "Automatic", "1", "1"],
  ]);
  assert.equal(
    count(
      db,
      "identity_auth_identity",
      `user_id = '${account.user}' AND rev = 1 AND revoked_at IS NULL`,
    ),
    1,
  );
  assert.equal(count(db, "platform_command"), 1);
  assert.equal(count(db, "platform_outbox", "event_type = 'identity.user.enrolled'"), 1);
  assert.equal(count(db, "platform_change_archive"), 1);
  assert.equal(guards(db), 0, "no guard row survives a commit");
});

test("the outbox and change record of an enrollment carry identifiers and numbers and never the subject, the display name or a secret", async () => {
  const db = openIdentityD1();
  const user = uid();
  await enroll(db, realmA, "marker-subject-alpha", {
    user,
    displayName: "Private Display Name",
    credential: credential(user, realmA, "marker-subject-alpha", { label: "private-label-x" }),
  });
  const stored = JSON.stringify([
    rows(db, "SELECT payload FROM platform_outbox"),
    rows(db, "SELECT record FROM platform_change_archive"),
    rows(db, "SELECT actor_ref, operation, request_hash, result_payload FROM platform_command"),
  ]);
  for (const secret of ["marker-subject-alpha", "Private Display Name", "private-label-x"])
    assert.equal(
      stored.includes(secret),
      false,
      `${secret} must not reach a receipt, event or archive record`,
    );
});
test("a second enrollment of the same credential is refused whole and creates no second user, workspace or credential", async () => {
  const db = openIdentityD1();
  await enroll(db, realmA, "ada@example.test");
  const before = snapshotIdentity(db);
  const again = enrollInputs(realmA, "ada@example.test");
  assert.deepEqual(
    await runPlan(db, enrollmentPlan, enrollArguments(again), again.workspace),
    refused,
  );
  assert.deepEqual(snapshotIdentity(db), before, "nothing changed");
  assert.equal(guards(db), 0);
});

test("the same subject in another realm is another identity: it enrolls, with its own user and workspace, and neither sees the other", async () => {
  const db = openIdentityD1();
  const a = await enroll(db, realmA, "ada@example.test");
  const b = await enroll(db, realmB, "ada@example.test");
  assert.notEqual(a.user, b.user);
  assert.equal(count(db, "identity_auth_identity", "subject = 'ada@example.test'"), 2);
  assert.deepEqual(
    workspaceRows(db)
      .map((row) => [row[1], row[2]])
      .sort(),
    [
      [realmA, a.user],
      [realmB, b.user],
    ].sort(),
  );
  // A lookup is always scoped by realm.
  const found = await runPlan(
    db,
    "identity.credential-find",
    [[txt(realmB), txt("official-email"), txt("ada@example.test")]],
    realmB,
  );
  assert.equal(found.ok && found.rows[0]?.[1], b.user);
  const missing = await runPlan(db, "identity.user-load", [[txt(realmB), txt(a.user)]], realmB);
  assert.deepEqual(missing.ok && missing.rows, [], "a user of another realm is not found");
});

test("an enrollment whose user id already exists in another realm is refused, so a user id is never shared across realms", async () => {
  const db = openIdentityD1();
  const a = await enroll(db, realmA, "ada@example.test");
  const clash = enrollInputs(realmB, "other@example.test", { user: a.user });
  assert.deepEqual(await runPlan(db, enrollmentPlan, enrollArguments(clash), clash.workspace), {
    ok: false,
    failure: "constraint",
  });
  assert.equal(count(db, "identity_user"), 1);
});

test("two enrollments decided from the same read of an unknown credential commit exactly once, whichever order they arrive in", async () => {
  const file = path.join(mkdtempSync(path.join(tmpdir(), "identity-")), "race.db");
  const first = openIdentityD1(file);
  const second = openIdentityD1(file, false);
  const left = enrollInputs(realmA, "race@example.test");
  const right = enrollInputs(realmA, "race@example.test");
  const [a, b] = await Promise.all([
    runPlan(first, enrollmentPlan, enrollArguments(left), left.workspace),
    runPlan(second, enrollmentPlan, enrollArguments(right), right.workspace),
  ]);
  assert.equal([a, b].filter((result) => result.ok).length, 1);
  assert.deepEqual(
    [a, b].find((result) => !result.ok),
    refused,
  );
  assert.equal(count(first, "identity_user"), 1);
  assert.equal(count(first, "workspace_workspace"), 1);
  assert.equal(count(first, "identity_auth_identity"), 1);
});

test("a user that already owns a workspace in the realm cannot be given a second one: the owner guard and the unique index both refuse", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  // The family refuses a new workspace for an existing owner through the owner guard when a new credential tries to reuse the user id.
  const duplicate = enrollInputs(realmA, "second@example.test", { user: account.user });
  assert.equal(
    (await runPlan(db, enrollmentPlan, enrollArguments(duplicate), duplicate.workspace)).ok,
    false,
  );
  // Even a direct insert (a defect elsewhere) meets the unique index on (realm, owner).
  assert.throws(
    () =>
      db.database
        .prepare(
          "INSERT INTO workspace_workspace (workspace_id, realm_id, owner_user_id, name, data_region, protection_profile, state, created_at, rev) VALUES (?, ?, ?, 'Second', 'Automatic', 1, 1, 1, 1)",
        )
        .run(uid(), realmA, account.user),
    /UNIQUE/u,
  );
  assert.equal(workspaceRows(db).length, 1);
});

test("a workspace is single-owner in the schema: no membership, role or seat column exists to add a second principal", () => {
  const db = openIdentityD1();
  const columns = rows(db, "SELECT name FROM pragma_table_info('workspace_workspace')").map((row) =>
    String(row[0]),
  );
  assert.deepEqual(columns.sort(), [
    "created_at",
    "data_region",
    "name",
    "owner_user_id",
    "protection_profile",
    "realm_id",
    "rev",
    "state",
    "workspace_id",
  ]);
  const foreignKeys = rows(
    db,
    "SELECT \"table\" FROM pragma_foreign_key_list('workspace_workspace')",
  ).map((row) => String(row[0]));
  assert.deepEqual(foreignKeys, ["identity_user"]);
});

// ---------------------------------------------------------------------------------------------------------------------------
// Linking
// ---------------------------------------------------------------------------------------------------------------------------

test("linking a second credential changes neither the user, the user's identity, nor the workspace; only the credential list and the user revision move", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  const userBefore = userRow(db, account.user) as unknown[];
  const workspaceBefore = workspaceRows(db);
  const { outcome } = await add(db, account, "ada-passkey", 1, { provider: "official-passkey" });
  assert.equal(outcome.ok, true);
  const userAfter = userRow(db, account.user) as unknown[];
  assert.deepEqual(
    userAfter.slice(0, 6),
    userBefore.slice(0, 6),
    "user_id, realm, name, state and times are unchanged",
  );
  assert.equal(userAfter[6], "2", "only the credential-lifecycle revision moved");
  assert.deepEqual(workspaceRows(db), workspaceBefore, "the workspace row is byte-identical");
  assert.equal(count(db, "identity_auth_identity", `user_id = '${account.user}'`), 2);
  assert.equal(count(db, "platform_outbox", "event_type = 'identity.auth_identity.added'"), 1);
  assert.equal(guards(db), 0);
});

test("a credential already linked to anyone in the realm cannot be linked again, and the refusal does not say whose it is", async () => {
  const db = openIdentityD1();
  const ada = await enroll(db, realmA, "ada@example.test");
  const bob = await enroll(db, realmA, "bob@example.test");
  const before = snapshotIdentity(db);
  // Bob tries to link Ada's credential; Ada tries to link her own again: the same refusal.
  const steal = await add(db, bob, "ada@example.test", 1);
  const own = await add(db, ada, "ada@example.test", 1);
  assert.deepEqual(steal.outcome, refused);
  assert.deepEqual(own.outcome, refused);
  assert.deepEqual(snapshotIdentity(db), before);
});

test("linking in another realm to a user of this realm is refused: a user is found only in its own realm", async () => {
  const db = openIdentityD1();
  const ada = await enroll(db, realmA, "ada@example.test");
  const before = snapshotIdentity(db);
  const { outcome } = await add(db, ada, "other", 1, { realm: realmB });
  assert.deepEqual(outcome, refused);
  assert.deepEqual(snapshotIdentity(db), before);
});

test("a stale user revision refuses the link; a link decided before a concurrent link committed cannot overwrite it", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  const firstLink = await add(db, account, "one", 1);
  assert.equal(firstLink.outcome.ok, true);
  const stale = await add(db, account, "two", 1);
  assert.deepEqual(stale.outcome, refused);
  assert.equal(count(db, "identity_auth_identity", `user_id = '${account.user}'`), 2);
  const current = await add(db, account, "two", 2);
  assert.equal(current.outcome.ok, true);
});

test("two links of the same credential to two users decided from the same read commit exactly once", async () => {
  const file = path.join(mkdtempSync(path.join(tmpdir(), "identity-")), "link.db");
  const one = openIdentityD1(file);
  const two = openIdentityD1(file, false);
  const ada = await enroll(one, realmA, "ada@example.test");
  const bob = await enroll(one, realmA, "bob@example.test");
  const [a, b] = await Promise.all([
    add(one, ada, "shared-subject", 1),
    add(two, bob, "shared-subject", 1),
  ]);
  assert.equal([a.outcome, b.outcome].filter((o) => o.ok).length, 1);
  assert.equal(count(one, "identity_auth_identity", "subject = 'shared-subject'"), 1);
});

test("a restricted, suspended or deleted user cannot link a credential", async () => {
  for (const state of [2, 3, 5]) {
    const db = openIdentityD1();
    const account = await enroll(db, realmA, "ada@example.test");
    db.database
      .prepare("UPDATE identity_user SET state = ? WHERE user_id = ?")
      .run(state, account.user);
    const { outcome } = await add(db, account, "new", 1);
    assert.deepEqual(outcome, refused, `state ${state}`);
  }
});

test("a passkey credential needs its user handle and a password credential its verifier: the physical checks refuse a malformed row", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  const bad = credential(account.user, account.realm, "pk", {
    method: 1,
    provider: "official-passkey",
    passkey: null,
  });
  const result = await runPlan(
    db,
    "identity.credential-add",
    addArguments({
      ...tailInputs(),
      realm: account.realm,
      user: account.user,
      scope: account.workspace,
      expectedUserRevision: 1,
      credential: bad,
    }),
    account.workspace,
  );
  assert.deepEqual(result, { ok: false, failure: "constraint" });
  assert.equal(
    count(db, "identity_auth_identity", "subject = 'pk'"),
    0,
    "the whole commit rolled back",
  );
  assert.equal(userRow(db, account.user)?.[6], "1", "the user revision did not move");
});

// ---------------------------------------------------------------------------------------------------------------------------
// Revoking and the last-credential rule
// ---------------------------------------------------------------------------------------------------------------------------

test("a credential can be revoked while another usable one remains, and the user, the workspace and attached data are unchanged", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  const second = await add(db, account, "second", 1);
  assert.equal(second.outcome.ok, true);
  const userBefore = userRow(db, account.user) as unknown[];
  const workspaceBefore = workspaceRows(db);
  const outcome = await revoke(db, account, account.credential.credentialId, 1, 2);
  assert.equal(outcome.ok, true);
  const userAfter = userRow(db, account.user) as unknown[];
  assert.deepEqual(userAfter.slice(0, 6), userBefore.slice(0, 6));
  assert.equal(userAfter[6], "3");
  assert.deepEqual(workspaceRows(db), workspaceBefore);
  assert.equal(
    count(db, "identity_auth_identity", `user_id = '${account.user}' AND revoked_at IS NULL`),
    1,
  );
  assert.equal(
    count(db, "identity_auth_identity", `user_id = '${account.user}'`),
    2,
    "a revoked credential keeps its row and its subject",
  );
});

test("the last usable credential cannot be revoked without an active recovery path (identity.last_credential)", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  const before = snapshotIdentity(db);
  assert.deepEqual(await revoke(db, account, account.credential.credentialId, 1, 1), refused);
  assert.deepEqual(snapshotIdentity(db), before);
  // A live recovery-code set is an active recovery path: then the removal is admitted.
  db.database
    .prepare(
      "INSERT INTO identity_recovery_code (code_hash, set_id, user_id, issued_at, consumed_at, invalidated_at) VALUES (randomblob(32), ?, ?, 1, NULL, NULL)",
    )
    .run(uid(), account.user);
  assert.equal((await revoke(db, account, account.credential.credentialId, 1, 1)).ok, true);
});

test("a consumed or invalidated recovery code is not a recovery path", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  db.database
    .prepare(
      "INSERT INTO identity_recovery_code (code_hash, set_id, user_id, issued_at, consumed_at, invalidated_at) VALUES (randomblob(32), ?, ?, 1, 2, NULL), (randomblob(32), ?, ?, 1, NULL, 3)",
    )
    .run(uid(), account.user, uid(), account.user);
  assert.deepEqual(await revoke(db, account, account.credential.credentialId, 1, 1), refused);
});

test("two revocations of a user's two credentials decided from the same read never leave the user without a credential", async () => {
  const file = path.join(mkdtempSync(path.join(tmpdir(), "identity-")), "revoke.db");
  const one = openIdentityD1(file);
  const two = openIdentityD1(file, false);
  const account = await enroll(one, realmA, "ada@example.test");
  const second = await add(one, account, "second", 1);
  assert.equal(second.outcome.ok, true);
  const [a, b] = await Promise.all([
    revoke(one, account, account.credential.credentialId, 1, 2),
    revoke(two, account, second.credential.credentialId, 1, 2),
  ]);
  assert.equal(
    [a, b].filter((o) => o.ok).length,
    1,
    "the second writer read a revision that the first moved",
  );
  assert.equal(
    count(one, "identity_auth_identity", `user_id = '${account.user}' AND revoked_at IS NULL`),
    1,
  );
});

test("even with the revision guard satisfied, revoking the only remaining credential is refused by the rule itself", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  const second = await add(db, account, "second", 1);
  assert.equal((await revoke(db, account, account.credential.credentialId, 1, 2)).ok, true);
  // The user revision is now 3 and the credential revision of the second is 1: all guards read current values, only the rule remains.
  assert.deepEqual(await revoke(db, account, second.credential.credentialId, 1, 3), refused);
});

test("a revoked credential cannot be revoked twice, and a credential of another user or realm is not revocable by this user", async () => {
  const db = openIdentityD1();
  const ada = await enroll(db, realmA, "ada@example.test");
  const bob = await enroll(db, realmA, "bob@example.test");
  const adaSecond = await add(db, ada, "ada-second", 1);
  assert.equal(adaSecond.outcome.ok, true);
  const bobSecond = await add(db, bob, "bob-second", 1);
  assert.equal(bobSecond.outcome.ok, true);
  const before = snapshotIdentity(db);
  // Ada names Bob's credential with her own revisions.
  assert.deepEqual(await revoke(db, ada, bobSecond.credential.credentialId, 1, 2), refused);
  // Ada names her credential but another realm.
  assert.deepEqual(
    await revoke(db, ada, ada.credential.credentialId, 1, 2, { realm: realmB }),
    refused,
  );
  assert.deepEqual(snapshotIdentity(db), before);
  assert.equal((await revoke(db, ada, ada.credential.credentialId, 1, 2)).ok, true);
  assert.deepEqual(
    await revoke(db, ada, ada.credential.credentialId, 2, 3),
    refused,
    "already revoked",
  );
});

test("a revoked credential keeps its subject reserved: it cannot be linked again by anyone, so a credential never moves between users", async () => {
  const db = openIdentityD1();
  const ada = await enroll(db, realmA, "ada@example.test");
  const bob = await enroll(db, realmA, "bob@example.test");
  const second = await add(db, ada, "ada-second", 1);
  assert.equal(second.outcome.ok, true);
  assert.equal((await revoke(db, ada, ada.credential.credentialId, 1, 2)).ok, true);
  assert.deepEqual((await add(db, bob, "ada@example.test", 1)).outcome, refused);
});

// ---------------------------------------------------------------------------------------------------------------------------
// Relabel, rename, continuity
// ---------------------------------------------------------------------------------------------------------------------------

test("relabelling and renaming move only their own revisions; the user identifier, realm, creation time and workspace never change", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  const workspaceBefore = workspaceRows(db);
  const relabel = await runPlan(
    db,
    "identity.credential-relabel",
    relabelArguments({
      ...tailInputs(),
      realm: account.realm,
      user: account.user,
      scope: account.workspace,
      target: account.credential.credentialId,
      expectedCredentialRevision: 1,
      label: "work laptop",
    }),
    account.workspace,
  );
  assert.equal(relabel.ok, true);
  const rename = await runPlan(
    db,
    "identity.user-rename",
    renameArguments({
      ...tailInputs(),
      realm: account.realm,
      user: account.user,
      scope: account.workspace,
      expectedUserRevision: 1,
      displayName: "Ada Lovelace",
    }),
    account.workspace,
  );
  assert.equal(rename.ok, true);
  const user = userRow(db, account.user) as unknown[];
  assert.deepEqual(
    [user[0], user[1], user[3], user[4]],
    [account.user, realmA, "1", String(nowMicros)],
  );
  assert.deepEqual([user[2], user[6]], ["Ada Lovelace", "2"]);
  assert.deepEqual(workspaceRows(db), workspaceBefore);
  assert.deepEqual(
    rows(
      db,
      `SELECT label, CAST(rev AS TEXT) FROM identity_auth_identity WHERE auth_identity_id = '${account.credential.credentialId}'`,
    ),
    [["work laptop", "2"]],
  );
  // A stale revision is refused.
  const stale = await runPlan(
    db,
    "identity.user-rename",
    renameArguments({
      ...tailInputs(),
      realm: account.realm,
      user: account.user,
      scope: account.workspace,
      expectedUserRevision: 1,
      displayName: "Stale",
    }),
    account.workspace,
  );
  assert.deepEqual(stale, refused);
});

test("a long sequence of linking, relabelling and revoking leaves the user and the workspace exactly as enrolled, apart from the lifecycle revision", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  const userBefore = userRow(db, account.user) as unknown[];
  const workspaceBefore = workspaceRows(db);
  let userRevision = 1;
  const linked: string[] = [];
  for (let index = 0; index < 6; index++) {
    const result = await add(db, account, `extra-${index}`, userRevision);
    assert.equal(result.outcome.ok, true);
    userRevision++;
    linked.push(result.credential.credentialId);
  }
  for (const id of [account.credential.credentialId, ...linked.slice(0, 4)]) {
    assert.equal((await revoke(db, account, id, 1, userRevision)).ok, true);
    userRevision++;
  }
  const userAfter = userRow(db, account.user) as unknown[];
  assert.deepEqual(userAfter.slice(0, 6), userBefore.slice(0, 6));
  assert.equal(userAfter[6], String(userRevision));
  assert.deepEqual(workspaceRows(db), workspaceBefore);
  assert.equal(
    count(db, "identity_auth_identity", `user_id = '${account.user}' AND revoked_at IS NULL`),
    2,
  );
  assert.equal(count(db, "workspace_workspace"), 1);
});

test("credential touch only moves the last-use instant forward and never changes a revision", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  const touch = (at: number, realm = account.realm) =>
    runPlan(
      db,
      "identity.credential-touch",
      [[i64(at), txt(realm), txt(account.credential.credentialId), i64(at)]],
      account.workspace,
    );
  assert.equal((await touch(10)).ok, true);
  assert.equal(changesOf(await touch(5)), "0", "an earlier instant changes nothing");
  assert.equal(changesOf(await touch(20, realmB)), "0", "another realm changes nothing");
  assert.deepEqual(
    rows(
      db,
      `SELECT CAST(last_used_at AS TEXT), CAST(rev AS TEXT) FROM identity_auth_identity WHERE auth_identity_id = '${account.credential.credentialId}'`,
    ),
    [["10", "1"]],
  );
});

// ---------------------------------------------------------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------------------------------------------------------

test("the read plans are scoped by realm: a credential list or a lookup of another realm returns nothing", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  const own = await runPlan(
    db,
    "identity.credential-list",
    [[txt(realmA), txt(account.user)]],
    realmA,
  );
  assert.equal(own.ok && own.rows.length, 1);
  const foreign = await runPlan(
    db,
    "identity.credential-list",
    [[txt(realmB), txt(account.user)]],
    realmB,
  );
  assert.deepEqual(foreign.ok && foreign.rows, []);
  const lookup = await runPlan(
    db,
    "identity.credential-find",
    [[txt(realmB), txt("official-email"), txt("ada@example.test")]],
    realmB,
  );
  assert.deepEqual(lookup.ok && lookup.rows, [], "the same subject is unknown in another realm");
});

test("every write plan leaves no guard row behind after a refusal or a commit", async () => {
  const db = openIdentityD1();
  const account = await enroll(db, realmA, "ada@example.test");
  await add(db, account, "x", 99);
  await revoke(db, account, account.credential.credentialId, 1, 1);
  assert.equal(guards(db), 0);
  assert.equal(db.rollbacks(), 2);
});
