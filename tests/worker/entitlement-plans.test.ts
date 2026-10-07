// SPDX-License-Identifier: AGPL-3.0-only
// The Entitlement owner's named plans (COM.16) on the real numbered migrations in node:sqlite (the oracle), through the production Worker
// executor: ownership, the guarded revision (including the first commit that creates the row), the atomic commit with its receipt, outbox
// row and change record, the keyset loads and the append-only rules. The C# store drives the same plans end to end in
// tests/ArcForges.Cloud.Tests/Entitlement; SQLite is not D1, and the workerd run repeats the engine-dependent cases.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import type { D1Scalar } from "@arcforges/ai-internal";
import { buildManifest, referencedTables } from "../../eng/verification/storage-plans.ts";
import { i64, txt } from "./support/plan-calls.ts";
import { commitDatabase, count, execute, rows } from "./support/commit-support.ts";
import {
  commitArguments,
  grant,
  id,
  other,
  workspace,
  type Records,
} from "./support/entitlement-fixtures.ts";
import { repositoryRoot } from "./support/sqlite-d1.ts";

const commit = (db: ReturnType<typeof commitDatabase>, args: D1Scalar[][], scope = workspace) =>
  execute(db, "entitlement.commit", args, scope);

const entitlementPlans = () =>
  buildManifest(repositoryRoot).plans.filter((plan) => plan.id.startsWith("entitlement."));

test("the Entitlement owner has its named plans and each names only entitlement_ and platform_ tables", () => {
  const plans = entitlementPlans();
  assert.deepEqual(plans.map((plan) => plan.id).sort(), [
    "entitlement.activations-load",
    "entitlement.commit",
    "entitlement.feature-release-append",
    "entitlement.feature-release-get",
    "entitlement.feature-releases-load",
    "entitlement.grants-load",
    "entitlement.quota-definition-command",
    "entitlement.quota-definition-get",
    "entitlement.quota-definition-publish",
    "entitlement.quota-kernel-budget",
    "entitlement.quota-kernel-cleanup",
    "entitlement.quota-kernel-command",
    "entitlement.quota-kernel-effect",
    "entitlement.quota-kernel-publish",
    "entitlement.quota-kernel-reservation",
    "entitlement.quota-kernel-reserve",
    "entitlement.quota-period-action-text",
    "entitlement.quota-period-actions",
    "entitlement.quota-period-snapshot-text",
    "entitlement.quota-period-state",
    "entitlement.quota-period-term-text",
    "entitlement.quota-period-terms",
    "entitlement.resolver-definition-command",
    "entitlement.resolver-definition-get",
    "entitlement.resolver-definition-publish",
    "entitlement.revision-load",
    "entitlement.revocations-load",
    "entitlement.snapshot-load",
    "entitlement.status-facts-load",
    "entitlement.term-actions-load",
    "entitlement.terms-load",
  ]);
  for (const plan of plans)
    plan.statements.forEach((statement, index) => {
      for (const table of referencedTables(statement.sql, `${plan.id} ${index + 1}`))
        assert(/^(?:entitlement|platform)_/u.test(table), `${plan.id}: ${table}`);
    });
  const checkedIn = readFileSync(
    path.join(repositoryRoot, "storage/plans/entitlement/commit.sql"),
    "utf8",
  );
  assert(checkedIn.includes("-- tail: v1 events=1"));
  assert(!/workspace_workspace|commerce_/u.test(checkedIn), "no other module's table");
});

test("the first commit creates the revision row, the batch commits whole and no guard row is left behind", async () => {
  const db = commitDatabase();
  assert.equal(count(db, "entitlement_revision"), 0);
  const result = await commit(
    db,
    commitArguments(workspace, id(0x1001), 0, {
      grants: [grant(1)],
      activations: [{ version: "bundle-1", activatedAt: "10" }],
    }),
  );
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.deepEqual(rows(db, "SELECT workspace_id, rev, updated_at FROM entitlement_revision"), [
    [workspace, 1, 10],
  ]);
  assert.equal(count(db, "entitlement_grant"), 1);
  assert.equal(count(db, "entitlement_definitions_activation"), 1);
  assert.equal(count(db, "entitlement_snapshot"), 1);
  assert.equal(
    count(db, "platform_command", "operation = 'entitlement.commit' AND result_rev = 1"),
    1,
  );
  assert.equal(count(db, "platform_outbox"), 1);
  assert.equal(
    count(db, "platform_outbox_position", `stream_key = '${workspace}' AND sequence = 1`),
    1,
  );
  assert.equal(count(db, "platform_change_archive"), 1);
  assert.equal(count(db, "platform_command_guard"), 0);
});

test("a stale or phantom revision fails the guard and commits nothing", async () => {
  const db = commitDatabase();
  assert.equal(
    (await commit(db, commitArguments(workspace, id(0x1001), 0, { grants: [grant(1)] }))).ok,
    true,
  );
  const before = count(db, "platform_command");

  // A second first commit (it read the absent row) and a writer that believes a later revision exists on an absent row.
  const stale = await commit(db, commitArguments(workspace, id(0x1002), 0, { grants: [grant(2)] }));
  assert.deepEqual(stale, { ok: false, failure: "precondition" });
  const phantom = await commit(
    db,
    commitArguments(other, id(0x1003), 5, { grants: [grant(3, { id: id(0x33) })] }),
    other,
  );
  assert.deepEqual(phantom, { ok: false, failure: "precondition" });

  assert.equal(count(db, "entitlement_grant"), 1);
  assert.equal(count(db, "platform_command"), before);
  assert.equal(count(db, "entitlement_revision", `workspace_id = '${other}'`), 0);
  assert.equal(count(db, "platform_command_guard"), 0);
  // The writer that read the current revision succeeds and the fence advances by exactly one.
  assert.equal(
    (await commit(db, commitArguments(workspace, id(0x1004), 1, { grants: [grant(4)] }))).ok,
    true,
  );
  assert.deepEqual(
    rows(db, `SELECT rev FROM entitlement_revision WHERE workspace_id = '${workspace}'`),
    [[2]],
  );
});

test("a constraint failure anywhere in the batch rolls back every row, the receipt and the outbox row", async () => {
  const db = commitDatabase();
  const orphan = {
    id: id(0x50),
    grantId: id(0xdead),
    reasonCode: "refund",
    from: "6",
    actor: "operator",
    createdAt: "6",
  };
  const result = await commit(
    db,
    commitArguments(workspace, id(0x1001), 0, { grants: [grant(1)], revocations: [orphan] }),
  );
  assert.deepEqual(result, { ok: false, failure: "constraint" });
  for (const table of [
    "entitlement_grant",
    "entitlement_revocation",
    "entitlement_snapshot",
    "entitlement_revision",
    "platform_command",
    "platform_outbox",
    "platform_change_archive",
    "platform_command_guard",
  ])
    assert.equal(count(db, table), 0, table);
});

test("the reason column is required for operator sources, shaped, and round-trips exactly", async () => {
  const operator = (n: number, source: number, reason: unknown) =>
    grant(n, { source, reason, sourceRef: `ticket-${n}` });
  const attempt = async (reason: unknown, source = 5) => {
    const db = commitDatabase();
    const result = await commit(
      db,
      commitArguments(workspace, id(0x1001), 0, { grants: [operator(1, source, reason)] }),
    );
    return { result, db };
  };
  for (const source of [5, 6, 7]) {
    assert.deepEqual((await attempt(null, source)).result, { ok: false, failure: "constraint" });
    assert.deepEqual((await attempt("", source)).result, { ok: false, failure: "constraint" });
  }
  assert.deepEqual((await attempt("x".repeat(513))).result, { ok: false, failure: "constraint" });
  assert.deepEqual((await attempt("line\nbreak")).result, { ok: false, failure: "constraint" });
  assert.deepEqual((await attempt("a reason", 1)).result, { ok: false, failure: "constraint" });
  const exact = "é".repeat(512);
  const accepted = await attempt(exact);
  assert.equal(accepted.result.ok, true);
  assert.deepEqual(rows(accepted.db, "SELECT reason, source FROM entitlement_grant"), [[exact, 5]]);
  const plain = commitDatabase();
  assert.equal(
    (await commit(plain, commitArguments(workspace, id(0x1001), 0, { grants: [grant(1)] }))).ok,
    true,
  );
  assert.deepEqual(rows(plain, "SELECT reason FROM entitlement_grant"), [[null]]);
});

test("every record kind is unpacked into its table with exact values and the snapshot is replaced in place", async () => {
  const db = commitDatabase();
  db.database.exec(
    `PRAGMA foreign_keys = OFF; INSERT INTO workspace_workspace (workspace_id, realm_id, owner_user_id, name, data_region, protection_profile, state, created_at, rev) VALUES ('${workspace}', '${id(0xa1)}', '${id(0xa2)}', 'w', 'eu', 1, 1, 1, 0); PRAGMA foreign_keys = ON;`,
  );
  const term = {
    id: id(0x71),
    realmId: id(0xc1),
    kind: 1,
    subscriptionRef: "sub-1",
    periodRef: "period-1",
    startsAt: "0",
    endsAt: "9007199254740993",
    graceEndsAt: null,
    supersedesId: null,
    offerId: id(0xc2),
    offerSnapshotId: id(0xc3),
    authorizedAt: "0",
    selectionPriority: "3",
    createdAt: "1",
  };
  const records: Records = {
    grants: [
      grant(1, { value: { limit: 5, priority: 2 }, kind: 2, subject: "cloud.storage.bytes" }),
    ],
    terms: [term],
    activations: [{ version: "bundle-1", activatedAt: "10" }],
    facts: [
      {
        id: id(0x82),
        recordedAt: "11",
        status: 2,
        autoRenew: 0,
        purchasePending: 1,
        sourceRef: "status-1",
      },
    ],
    validUntil: 99,
  };
  assert.equal((await commit(db, commitArguments(workspace, id(0x1001), 0, records))).ok, true);
  assert.deepEqual(rows(db, "SELECT kind, value FROM entitlement_grant"), [
    [2, '{"limit":5,"priority":2}'],
  ]);
  // An exact 64-bit instant above 2^53 survives the JSON text and the integer column.
  assert.deepEqual(
    rows(
      db,
      "SELECT CAST(ends_at AS TEXT), selection_priority, subscription_ref FROM entitlement_service_term",
    ),
    [["9007199254740993", 3, "sub-1"]],
  );
  assert.deepEqual(
    rows(db, "SELECT status, auto_renew, purchase_pending FROM entitlement_workspace_status_fact"),
    [[2, 0, 1]],
  );
  const action = {
    id: id(0x81),
    termId: id(0x71),
    kind: 2,
    effectiveAt: "50",
    recordedAt: "12",
    sourceRef: "action-1",
    replacementTermId: null,
  };
  assert.equal(
    (await commit(db, commitArguments(workspace, id(0x1002), 1, { actions: [action] }))).ok,
    true,
  );
  assert.deepEqual(rows(db, "SELECT kind, source_ref FROM entitlement_service_term_action"), [
    [2, "action-1"],
  ]);
  assert.equal(count(db, "entitlement_snapshot"), 1);
  assert.deepEqual(rows(db, "SELECT valid_until FROM entitlement_snapshot"), [[null]]);
  const first = rows(db, "SELECT entitlement_version FROM entitlement_snapshot");
  assert.deepEqual(first, [[2]]);
  // A repeated status reference or action reference is one append only.
  assert.deepEqual(
    await commit(
      db,
      commitArguments(workspace, id(0x1003), 2, { actions: [{ ...action, id: id(0x84) }] }),
    ),
    { ok: false, failure: "constraint" },
  );
});

test("the loads page by keyset in the plan's own order and a cursor is strictly exclusive", async () => {
  const db = commitDatabase();
  const grants = [
    grant(3, { from: "5" }),
    grant(1, { from: "5" }),
    grant(2, { from: "1" }),
    grant(4, {
      kind: 2,
      subject: "cloud.storage.bytes",
      value: { limit: 1, priority: 0 },
      from: "0",
    }),
  ];
  assert.equal((await commit(db, commitArguments(workspace, id(0x1001), 0, { grants }))).ok, true);
  const s = { kind: "text", value: workspace } as D1Scalar;
  const page = async (kind: number, from: string, grantId: string) => {
    const result = await execute(
      db,
      "entitlement.grants-load",
      [[s, i64(kind), i64(from), txt(grantId)]],
      workspace,
    );
    assert.equal(result.ok, true);
    return result.ok ? result.rows.map((row) => row[0]) : [];
  };
  // Order is (kind, effective_from, grant_id): capability grants by start then identifier, then the quota.
  assert.deepEqual(await page(0, "-9223372036854775808", ""), [id(2), id(1), id(3), id(4)]);
  assert.deepEqual(await page(1, "1", id(2)), [id(1), id(3), id(4)]);
  assert.deepEqual(await page(1, "5", id(3)), [id(4)]);
  assert.deepEqual(await page(2, "0", id(4)), []);
  // Another workspace sees nothing of it.
  const strange = await execute(
    db,
    "entitlement.grants-load",
    [[{ kind: "text", value: other } as D1Scalar, i64(0), i64("-9223372036854775808"), txt("")]],
    other,
  );
  assert.deepEqual(strange.ok && strange.rows, []);
  // The call's owner scope must equal the scope argument: a caller cannot read another workspace by naming it.
  const forged = await execute(
    db,
    "entitlement.grants-load",
    [[s, i64(0), i64(0), txt("")]],
    other,
  );
  assert.deepEqual(forged, { ok: false, failure: "invalidPlan" });
});

test("a feature release is appended once and never updated or deleted", async () => {
  const db = commitDatabase();
  const append = (feature: string, at: string) =>
    execute(
      db,
      "entitlement.feature-release-append",
      [[{ kind: "text", value: feature }, i64(at)]],
      feature,
    );
  assert.equal((await append("feature.ai", "50")).ok, true);
  assert.deepEqual(await append("feature.ai", "60"), { ok: false, failure: "constraint" });
  assert.deepEqual(rows(db, "SELECT feature_key, released_at FROM entitlement_feature_release"), [
    ["feature.ai", 50],
  ]);
  assert.throws(
    () => db.database.exec("UPDATE entitlement_feature_release SET released_at = 1"),
    /af_immutable/u,
  );
  assert.throws(() => db.database.exec("DELETE FROM entitlement_feature_release"), /af_immutable/u);
  const get = async (feature: string) => {
    const result = await execute(
      db,
      "entitlement.feature-release-get",
      [[{ kind: "text", value: feature }]],
      feature,
    );
    return result.ok ? result.rows : result.failure;
  };
  assert.deepEqual(await get("feature.ai"), [["50"]]);
  assert.deepEqual(await get("feature.none"), []);
  // The scope argument is the feature itself: a call that names another scope is refused by the Worker.
  assert.deepEqual(
    await execute(
      db,
      "entitlement.feature-release-append",
      [[{ kind: "text", value: "feature.x" }, i64("1")]],
      "feature.y",
    ),
    { ok: false, failure: "invalidPlan" },
  );
  // The global listing is called under its one scope, pages by feature key and returns nothing under any other.
  const listing = async (scope: string, cursor: string) => {
    const result = await execute(
      db,
      "entitlement.feature-releases-load",
      [[{ kind: "text", value: scope }, txt(cursor)]],
      scope,
    );
    return result.ok ? result.rows : result.failure;
  };
  assert.deepEqual(await listing("entitlement.global", ""), [["feature.ai", "50"]]);
  assert.deepEqual(await listing("entitlement.global", "feature.ai"), []);
  assert.deepEqual(await listing("elsewhere", ""), []);
});

test("the three resolver inputs and the grants are append-only and a null scope or empty array commits only the snapshot", async () => {
  const db = commitDatabase();
  assert.equal(
    (
      await commit(
        db,
        commitArguments(workspace, id(0x1001), 0, {
          grants: [grant(1)],
          activations: [{ version: "bundle-1", activatedAt: "10" }],
          facts: [
            {
              id: id(0x82),
              recordedAt: "11",
              status: 1,
              autoRenew: 1,
              purchasePending: 0,
              sourceRef: "s-1",
            },
          ],
        }),
      )
    ).ok,
    true,
  );
  for (const statement of [
    "UPDATE entitlement_grant SET subject = 'x'",
    "DELETE FROM entitlement_grant",
    "UPDATE entitlement_definitions_activation SET definitions_version = 'x'",
    "DELETE FROM entitlement_definitions_activation",
    "UPDATE entitlement_workspace_status_fact SET status = 2",
    "DELETE FROM entitlement_workspace_status_fact",
  ])
    assert.throws(() => db.database.exec(statement), /af_immutable/u, statement);
  const before = count(db, "entitlement_grant");
  assert.equal((await commit(db, commitArguments(workspace, id(0x1002), 1))).ok, true);
  assert.equal(count(db, "entitlement_grant"), before);
  assert.deepEqual(rows(db, "SELECT rev FROM entitlement_revision"), [[2]]);
});
