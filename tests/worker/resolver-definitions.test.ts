// SPDX-License-Identifier: AGPL-3.0-only
// Actual migrated SQLite and production Worker plans. These fixtures do not establish signed Config authority or D1 deployment.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import type { D1Scalar } from "@arcforges/ai-internal";
import { parseFamilyRegistry, parsePlanFile } from "../../eng/verification/storage-plans.ts";
import { loadManifest } from "../../eng/verification/physical-schema.ts";
import { commitDatabase, count, execute, tailArguments } from "./support/commit-support.ts";
import { commitArguments, workspace } from "./support/entitlement-fixtures.ts";
import { bytes, fixedNow, i64, txt } from "./support/plan-calls.ts";
import { repositoryRoot } from "./support/sqlite-d1.ts";

const realm = "a0000000-0000-4000-8000-000000000001";
const revision = (n: number) => `b0000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;
const command = (n: number) => `c0000000-0000-4000-8000-${n.toString(16).padStart(12, "0")}`;
const digest = (text: string) => createHash("sha256").update(text).digest();
const canonical = (paid = true) =>
  JSON.stringify({
    allowances: [{ key: "ai" }],
    capabilities: [{ featureGate: null, key: "assistant", requiresPaidTerm: paid }],
    definitionsVersion: "v1",
    quotas: [{ combination: "Sum", key: "bytes" }],
    schemaVersion: "entitlement.resolver-definitions.v1",
  });
function database() {
  const db = commitDatabase();
  const pending = path.join(
    repositoryRoot,
    "src/ArcForges.Cloud.Storage.D1/Migrations/pending/entitlement__resolver-definition-profile.sql",
  );
  if (existsSync(pending)) db.database.exec(readFileSync(pending, "utf8"));
  return db;
}
function args(n: number, paid = true, kind = 1): D1Scalar[][] {
  const profile = canonical(paid),
    hash = digest(profile),
    now = fixedNow * 1000;
  return [
    [
      txt(command(n)),
      txt(realm),
      txt("v1"),
      bytes(hash),
      txt(profile),
      txt("artifact:v1"),
      bytes(hash),
      i64(Buffer.byteLength(profile)),
      i64(kind),
    ],
    [
      txt(realm),
      txt("v1"),
      bytes(hash),
      txt(profile),
      txt("artifact:v1"),
      bytes(hash),
      i64(Buffer.byteLength(profile)),
      txt(revision(n)),
      bytes(digest("document")),
      i64(kind),
      txt("config:publisher"),
      i64(now),
    ],
    ...tailArguments(realm, {
      commandId: command(n),
      actor: "config:publisher",
      operation: "entitlement.resolver-definition-publish",
      createdAt: now,
      requestHash: digest(`request:${n}`).toString("hex"),
      resultPayload: JSON.stringify({
        realmId: realm,
        definitionsVersion: "v1",
        hash: hash.toString("hex"),
      }),
    }),
  ];
}

test("later approved identical materialization retains first provenance and exact owner receipt", async () => {
  const db = database();
  try {
    assert.equal(
      (await execute(db, "entitlement.resolver-definition-publish", args(1), realm)).ok,
      true,
    );
    assert.equal(
      (await execute(db, "entitlement.resolver-definition-publish", args(2), realm)).ok,
      true,
    );
    assert.equal(count(db, "entitlement_resolver_definition_profile"), 1);
    assert.equal(count(db, "platform_change_archive"), 2);
    const row = db.database
      .prepare("SELECT original_config_revision_id FROM entitlement_resolver_definition_profile")
      .get();
    assert.equal(row?.original_config_revision_id, revision(1));
    const receipt = await execute(
      db,
      "entitlement.resolver-definition-command",
      [[txt(command(1)), txt("config:publisher"), txt(realm)]],
      realm,
    );
    assert.equal(receipt.ok, true);
    assert.ok("rows" in receipt);
    assert.equal(receipt.rows[0]?.[2], digest("request:1").toString("hex"));
    assert.equal(count(db, "platform_change_archive"), 2);
    assert.throws(
      () => db.database.exec("UPDATE entitlement_resolver_definition_profile SET realm_kind=2"),
      /af_immutable/u,
    );
    assert.throws(
      () => db.database.exec("DELETE FROM entitlement_resolver_definition_profile"),
      /af_immutable/u,
    );
  } finally {
    db.database.close();
  }
});

test("same version changed semantics or realm kind refuses atomically without receipt or orphan guard", async () => {
  const db = database();
  try {
    assert.equal(
      (await execute(db, "entitlement.resolver-definition-publish", args(1), realm)).ok,
      true,
    );
    assert.deepEqual(
      await execute(db, "entitlement.resolver-definition-publish", args(2, false), realm),
      { ok: false, failure: "precondition" },
    );
    assert.deepEqual(
      await execute(db, "entitlement.resolver-definition-publish", args(3, true, 2), realm),
      { ok: false, failure: "precondition" },
    );
    assert.equal(count(db, "platform_command"), 1);
    assert.equal(count(db, "platform_change_archive"), 1);
    assert.equal(count(db, "platform_command_guard"), 0);
  } finally {
    db.database.close();
  }
});

test("closed current-definition family rejects a superseded head, persisted zero revision and stale recovery", async () => {
  const db = database();
  try {
    assert.equal(
      (await execute(db, "entitlement.resolver-definition-publish", args(1), realm)).ok,
      true,
    );
    db.database
      .prepare(
        "INSERT INTO config_revision VALUES (?, 'fixture', 'fixture-head', ?, 'test', ?, 1, 1, 2, '{}')",
      )
      .run(revision(1), digest("document"), realm);
    db.database.exec(
      `INSERT INTO platform_recovery_epoch VALUES ('${realm}',0,'fixture',zeroblob(32),4,1,1)`,
    );
    const value = canonical(),
      hash = digest(value),
      original = commitArguments(workspace, command(9), 0);
    const family: D1Scalar[][] = [
      [txt(command(9)), txt(realm), i64(0), i64(4), i64(1)],
      [txt(command(9)), txt(realm), txt(revision(1)), bytes(digest("document"))],
      original[0] ?? [],
      [
        txt(command(9)),
        txt(realm),
        txt("v1"),
        bytes(hash),
        txt("artifact:v1"),
        bytes(hash),
        i64(Buffer.byteLength(value)),
        i64(1),
      ],
      ...original.slice(1),
    ];
    db.database.exec("UPDATE config_revision SET state=3");
    assert.deepEqual(
      await execute(
        db,
        "families.entitlement-definition-resolution.commit-current",
        family,
        workspace,
      ),
      { ok: false, failure: "precondition" },
    );
    db.database.exec(
      `UPDATE config_revision SET state=2; INSERT INTO entitlement_revision VALUES ('${workspace}',0,1)`,
    );
    assert.deepEqual(
      await execute(
        db,
        "families.entitlement-definition-resolution.commit-current",
        family,
        workspace,
      ),
      { ok: false, failure: "precondition" },
    );
    db.database.exec(
      `DELETE FROM entitlement_revision; UPDATE platform_recovery_epoch SET state=1,rev=2`,
    );
    assert.deepEqual(
      await execute(
        db,
        "families.entitlement-definition-resolution.commit-current",
        family,
        workspace,
      ),
      { ok: false, failure: "precondition" },
    );
    assert.equal(count(db, "entitlement_grant"), 0);
    assert.equal(count(db, "entitlement_revision"), 0);
    assert.equal(count(db, "platform_command"), 1);
    assert.equal(count(db, "platform_command_guard"), 0);
  } finally {
    db.database.close();
  }
});

test("current head state is a closed Config role literal, never a supplied authorization argument", () => {
  const file = "storage/plans/families/entitlement-definition-resolution.commit-current.sql";
  const text = readFileSync(path.join(repositoryRoot, file), "utf8");
  const registry = parseFamilyRegistry(
    readFileSync(path.join(repositoryRoot, "storage/plans/families.json"), "utf8"),
  );
  assert.throws(
    () =>
      parsePlanFile(text.replace("match=content_hash", "match=content_hash,state"), file, {
        registry,
        schema: loadManifest,
      }),
    /exact Config-owned role/u,
  );
});
