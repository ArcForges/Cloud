// SPDX-License-Identifier: AGPL-3.0-only
// Actual COM.18 owner SQL and Worker executor; SQLite is not Cloudflare D1 or operator approval.
import assert from "node:assert/strict";
import test from "node:test";
import { commitDatabase, count, execute, sha256, tailArguments } from "./support/commit-support.ts";
import { bytes, i64, txt, uuid } from "./support/plan-calls.ts";

// Integration assigned migration0027; the real complete numbered prefix owns these tables.
const database = commitDatabase;
const args = (realm: string, version: string, unit = 1, mode = 1, combination = 1) => {
  const command = uuid();
  const unitNames = ["bytes", "microseconds", "samples", "count"];
  const modeNames = ["Gauge", "EntitlementPeriod"];
  const combinations = ["Sum", "Max", "PriorityReplace"];
  const canonical = JSON.stringify({
    definitions: [
      {
        combination: combinations[combination - 1],
        key: "storage",
        mode: modeNames[mode - 1],
        unit: unitNames[unit - 1],
      },
    ],
    definitionsVersion: version,
    schemaVersion: "entitlement.quota-definitions.v1",
  });
  const hash = sha256(canonical);
  const entries = JSON.stringify([{ key: "storage", unit, mode, combination }]);
  return [
    [
      txt(command),
      txt(realm),
      txt(version),
      bytes(hash),
      txt(canonical),
      txt(`artifact:${version}`),
      bytes(hash),
      i64(Buffer.byteLength(canonical)),
      txt(entries),
    ],
    [
      txt(realm),
      txt(version),
      bytes(hash),
      txt(canonical),
      txt(`artifact:${version}`),
      bytes(hash),
      i64(Buffer.byteLength(canonical)),
      i64(1_000_000),
    ],
    [txt(realm), txt(version), txt(entries)],
    ...tailArguments(realm, {
      commandId: command,
      actor: "config:publisher",
      operation: "entitlement.quota-definition-publish",
      requestHash: hash.toString("hex"),
      resultPayload: JSON.stringify({
        realmId: realm,
        definitionsVersion: version,
        hash: hash.toString("hex"),
      }),
      schemaVersion: 1,
    }),
  ];
};

test("bounded indexed compatibility is read-only and refuses established meanings before publication", async () => {
  const db = database();
  const realm = uuid();
  const compatible = async (version: string, unit = 1, mode = 1, combination = 1) => {
    const [candidate] = args(realm, version, unit, mode, combination);
    assert(candidate);
    const entries = candidate.at(8);
    assert(entries);
    const result = await execute(
      db,
      "entitlement.quota-definition-compatible",
      [[...candidate.slice(1, 5), entries]],
      realm,
    );
    assert(result.ok);
    assert.equal(result.changes, "0");
    return result.rows;
  };
  try {
    assert.deepEqual(await compatible("initial"), [["1"]]);
    assert.equal(count(db, "platform_command"), 0);
    assert.equal(
      (await execute(db, "entitlement.quota-definition-publish", args(realm, "initial"), realm)).ok,
      true,
    );
    for (const [unit, mode, combination] of [
      [4, 1, 1],
      [1, 2, 1],
      [1, 1, 2],
    ]) {
      assert.deepEqual(await compatible("later", unit, mode, combination), [["0"]]);
    }
    assert.deepEqual(await compatible("later"), [["1"]]);
    assert.equal(count(db, "entitlement_quota_definition_profile"), 1);
    assert.equal(count(db, "platform_change_archive"), 1);
  } finally {
    db.database.close();
  }
});

test("recursive-trigger-disabled replacement cannot change accepted profile or stable key provenance", async () => {
  const db = database();
  const realm = uuid();
  try {
    assert.equal(
      (await execute(db, "entitlement.quota-definition-publish", args(realm, "original"), realm))
        .ok,
      true,
    );
    db.database.exec("PRAGMA recursive_triggers=OFF");
    assert.throws(
      () =>
        db.database.exec(`INSERT OR REPLACE INTO entitlement_quota_definition_profile
      SELECT realm_id, definitions_version, profile_hash, canonical_profile, artifact_id, artifact_hash, artifact_length, created_at+1
      FROM entitlement_quota_definition_profile`),
      /af_immutable_entitlement_quota_definition_profile/u,
    );
    assert.throws(
      () =>
        db.database.exec(`INSERT OR REPLACE INTO entitlement_quota_definition_key
      SELECT realm_id, quota_key, unit, mode, combination, 'different-first-version'
      FROM entitlement_quota_definition_key`),
      /af_immutable_entitlement_quota_definition_key/u,
    );
    assert.equal(
      db.database
        .prepare("SELECT first_definitions_version FROM entitlement_quota_definition_key")
        .get()?.first_definitions_version,
      "original",
    );
    assert.equal(count(db, "platform_change_archive"), 1);
  } finally {
    db.database.close();
  }
});

test("actual atomic quota publication retains indexed first meanings and refuses unit/mode/combination drift", async () => {
  const db = database();
  const realm = uuid();
  assert.equal(
    (await execute(db, "entitlement.quota-definition-publish", args(realm, "original"), realm)).ok,
    true,
  );
  for (const [version, unit, mode, combination] of [
    ["unit", 4, 1, 1],
    ["mode", 1, 2, 1],
    ["combination", 1, 1, 2],
  ] as const) {
    const result = await execute(
      db,
      "entitlement.quota-definition-publish",
      args(realm, version, unit, mode, combination),
      realm,
    );
    assert.deepEqual(result, { ok: false, failure: "precondition" });
  }
  assert.equal(count(db, "entitlement_quota_definition_profile"), 1);
  assert.equal(count(db, "entitlement_quota_definition_key"), 1);
  assert.equal(count(db, "platform_command"), 1);
  assert.equal(count(db, "platform_change_archive"), 1);
  assert.equal(count(db, "platform_command_guard"), 0);
  assert.equal(
    db.database
      .prepare("SELECT first_definitions_version FROM entitlement_quota_definition_key")
      .get()?.first_definitions_version,
    "original",
  );
  assert.throws(
    () => db.database.exec("UPDATE entitlement_quota_definition_key SET unit=4"),
    /af_immutable/u,
  );
  assert.throws(
    () => db.database.exec("DELETE FROM entitlement_quota_definition_profile"),
    /af_immutable/u,
  );
  db.database.close();
});

test("same definition version cannot alias different profile bytes and wrong realm scope causes no effect", async () => {
  const db = database();
  const realm = uuid();
  assert.equal(
    (await execute(db, "entitlement.quota-definition-publish", args(realm, "original"), realm)).ok,
    true,
  );
  assert.deepEqual(
    await execute(db, "entitlement.quota-definition-publish", args(realm, "original", 4), realm),
    { ok: false, failure: "precondition" },
  );
  assert.deepEqual(
    await execute(db, "entitlement.quota-definition-publish", args(realm, "new"), uuid()),
    { ok: false, failure: "invalidPlan" },
  );
  assert.equal(count(db, "entitlement_quota_definition_profile"), 1);
  assert.equal(count(db, "platform_change_archive"), 1);
  db.database.close();
});

test("actual quota profile DDL round-trips bounded correlated provenance and refuses inconsistent content facts", () => {
  const db = database();
  try {
    const insert = db.database.prepare(
      "INSERT INTO entitlement_quota_definition_profile VALUES (?,?,?,?,?,?,?,?)",
    );
    for (const boundary of [false, true]) {
      const realm = uuid();
      const version = boundary ? `v${"x".repeat(127)}` : "typical";
      const artifact = boundary ? `a${"y".repeat(127)}` : "artifact:typical";
      const canonical = JSON.stringify({
        definitions: [],
        definitionsVersion: version,
        schemaVersion: "entitlement.quota-definitions.v1",
      });
      const hash = sha256(canonical);
      const size = Buffer.byteLength(canonical, "utf8");
      const created = boundary ? 253402300799999999n : 1_000_000n;
      insert.run(realm, version, hash, canonical, artifact, hash, size, created);
      const read = db.database.prepare(
        "SELECT * FROM entitlement_quota_definition_profile WHERE realm_id=?",
      );
      read.setReadBigInts(true);
      const row = read.get(realm);
      assert(row);
      assert.equal(row.definitions_version, version);
      assert.equal(row.artifact_id, artifact);
      assert.equal(row.canonical_profile, canonical);
      assert.deepEqual(Buffer.from(row.profile_hash as Uint8Array), hash);
      assert.deepEqual(Buffer.from(row.artifact_hash as Uint8Array), hash);
      assert.equal(row.artifact_length, BigInt(size));
      assert.equal(row.created_at, created);
      assert.throws(
        () => insert.run(uuid(), version, hash, canonical, artifact, hash, size + 1, created),
        /artifact_length/u,
      );
      assert.throws(
        () =>
          insert.run(
            uuid(),
            version,
            hash,
            canonical,
            artifact,
            sha256("different"),
            size,
            created,
          ),
        /same_content_hash/u,
      );
      assert.throws(
        () => insert.run(uuid(), "", hash, canonical, artifact, hash, size, created),
        /version_nonempty/u,
      );
      assert.throws(
        () => insert.run(uuid(), version, hash, canonical, "", hash, size, created),
        /artifact_nonempty/u,
      );
    }
    assert.equal(count(db, "entitlement_quota_definition_profile"), 2);
    assert.throws(
      () => db.database.exec("UPDATE entitlement_quota_definition_profile SET created_at=0"),
      /af_immutable/u,
    );
    assert.throws(
      () =>
        db.database
          .prepare("INSERT INTO entitlement_quota_definition_key VALUES (?,?,?,?,?,?)")
          .run(uuid(), "storage", 0, 1, 1, "original"),
      /__unit/u,
    );
    assert.equal(count(db, "entitlement_quota_definition_key"), 0);
  } finally {
    db.database.close();
  }
});
