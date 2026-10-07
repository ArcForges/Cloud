// SPDX-License-Identifier: AGPL-3.0-only
// Real generated SQL and the production executor, over the repository's numbered SQLite migrations.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import type { SQLInputValue } from "node:sqlite";
import { Worker } from "node:worker_threads";
import {
  buildManifest,
  expandGuard,
  renderCSharp,
  securityNowUpperMicros,
  securityNowLowerMicros,
} from "../../eng/verification/storage-plans.ts";
import { loadManifest } from "../../eng/verification/physical-schema.ts";
import {
  fixtureRoot,
  i64,
  ids,
  openFamilyD1,
  physicalDirectory,
  runFamily,
  seed,
  txt,
  uuid,
  workerDictionary,
  type FamilyD1,
} from "./support/family-fixtures.ts";

const schema = loadManifest();
const nativeHeader =
  "kind=authorization module=identity key=actor-current table=identity_session by=session_id match=user_id,credential_kind securityExpiry=expires_at,access_expires_at";
const planId = "families.session-lifecycle.security-expiry";
const registry = {
  schemaVersion: 1,
  families: [
    {
      family: "session-lifecycle",
      title: "Security lifetime component",
      source: "CLOUD.78 component fixture",
      participants: [
        { module: "identity", requirement: "required" },
        { module: "device", requirement: "conditional", when: "when a device binding changes" },
      ],
    },
  ],
};
const receipt = `-- statement: module=platform class=record key=receipt params=text,scope,text,text,text,int64,int64,int64,int64
INSERT INTO platform_command (command_id, workspace_id, actor_ref, operation, request_hash, status, result_payload, result_rev, error_code, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, CAST(? AS INTEGER), NULL, CAST(? AS INTEGER), NULL, CAST(? AS INTEGER), CAST(? AS INTEGER));`;
const source = (header = nativeHeader) => `-- plan: ${planId}
-- version: 1
-- access: write
-- guard: ${header}
-- statement: module=identity class=record key=user params=text,text
UPDATE identity_user SET display_name = ? WHERE user_id = ?;
${receipt}
`;

function compiled(header = nativeHeader) {
  const root = fixtureRoot({ "session-lifecycle.security-expiry.sql": source(header) }, registry);
  try {
    return buildManifest(root, { physicalDirectory });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}
const manifest = compiled();
const dictionary = workerDictionary(manifest);
const session = "0198a7c0-1c3e-7d4a-9b1f-0000000b0001";
const device = "0198a7c0-1c3e-7d4a-9b1f-0000000b0002";

function seedSession(
  db: FamilyD1,
  expires: bigint,
  access: bigint | null,
  browser = false,
  idle: bigint | null = null,
) {
  seed(db);
  db.database
    .prepare(
      "INSERT INTO device_device (device_id,user_id,display_name,platform,trust_level,trust_raised_at,remote_enabled,first_seen_at,last_seen_at,revoked_at,rev) VALUES (?,?,'Device',1,1,NULL,0,1,1,NULL,1)",
    )
    .run(device, ids.user);
  db.database
    .prepare(
      `INSERT INTO identity_session
    (session_id,user_id,device_id,installation_id,issued_at,expires_at,revoked_at,credential_kind,refresh_token_hash,browser_handle_hash,browser_origin,idle_expires_at,last_activity_at,session_policy_version,refresh_generation,step_up_at,step_up_classes,access_token_hash,access_expires_at,csrf_hash,purpose,auth_epoch,recovery_generation,rev,family_id,product_id)
    VALUES (?,?,?,?,1,?,NULL,?,?,?,?,?,1,'p1',?,NULL,'[]',?,?,?,1,1,0,1,?,'arcscope')`,
    )
    .run(
      session,
      ids.user,
      device,
      "0198a7c0-1c3e-7d4a-9b1f-0000000b0003",
      expires,
      browser ? 2 : 1,
      browser ? null : "refresh",
      browser ? "handle" : null,
      browser ? "https://auth.example.test" : null,
      idle,
      browser ? null : 1,
      access === null ? null : "access",
      access,
      browser ? "csrf" : null,
      browser ? null : "0198a7c0-1c3e-7d4a-9b1f-0000000b0004",
    );
}

function argumentsFor(captured: bigint, command = uuid(), kind = 1) {
  return [
    [txt(command), txt(session), txt(ids.user), i64(kind), i64(captured)],
    [txt("Changed"), txt(ids.user)],
    [
      txt(command),
      txt(ids.workspace),
      txt(ids.user),
      txt("expiry.component"),
      txt("hash"),
      i64(2),
      i64(1),
      i64(captured),
      i64(captured + 86_400_000_000n),
    ],
    [txt(command)],
  ];
}

function snapshot(db: FamilyD1) {
  return [
    db.database.prepare("SELECT display_name FROM identity_user").all(),
    db.database.prepare("SELECT command_id FROM platform_command").all(),
    db.database.prepare("SELECT command_id FROM platform_command_guard").all(),
  ];
}

test("the registered native predicate, immutable metadata and generated C# share one definition", () => {
  const expanded = expandGuard(nativeHeader, schema, "native component", "session-lifecycle");
  assert.match(expanded.sql, /MIN\(expires_at, access_expires_at\) > MAX\(CAST\(\? AS INTEGER\),/u);
  assert.ok(expanded.sql.includes(securityNowUpperMicros));
  assert.ok(Object.isFrozen(expanded.meta.securityExpiry));
  assert.ok(Object.isFrozen(expanded.meta.securityExpiry?.columns));
  assert.equal(expanded.meta.securityExpiry?.capturedParamIndex, 4);
  assert.match(renderCSharp(manifest), /FamilySecurityExpiryProfile.NativeSession/u);
  assert.match(renderCSharp(manifest), /SecurityExpiryCatalog/u);
});

test("unknown, weakened and caller-selected security roles fail at compilation", () => {
  for (const [header, family] of [
    [nativeHeader.replace("module=identity", "module=device"), "session-lifecycle"],
    [nativeHeader.replace("key=actor-current", "key=arbitrary"), "session-lifecycle"],
    [nativeHeader.replace("expires_at,access_expires_at", "expires_at"), "session-lifecycle"],
    [
      nativeHeader.replace("expires_at,access_expires_at", "access_expires_at,expires_at"),
      "session-lifecycle",
    ],
    [
      nativeHeader.replace("expires_at,access_expires_at", "expires_at,expires_at"),
      "session-lifecycle",
    ],
    [`${nativeHeader} fresh=expires_at`, "session-lifecycle"],
    [`${nativeHeader} clock=caller`, "session-lifecycle"],
    [nativeHeader, "unknown-family"],
    [
      nativeHeader.replace("securityExpiry=expires_at,access_expires_at", "securityExpiry="),
      "session-lifecycle",
    ],
    [
      nativeHeader.replace("securityExpiry=expires_at,access_expires_at", "securityExpiry=rev"),
      "session-lifecycle",
    ],
  ] as const)
    assert.throws(() => expandGuard(header, schema, "closed component", family));
});

test("generic FRESH SQL remains byte-for-byte unchanged", () => {
  const old = expandGuard(
    "kind=authorization module=identity key=ordinary table=identity_session by=session_id match=user_id fresh=expires_at",
    schema,
    "old",
  );
  assert.equal(
    old.sql,
    "INSERT INTO platform_command_guard (command_id, guard_key, allowed)\nSELECT ?, 'identity.ordinary', CASE WHEN EXISTS (SELECT 1 FROM identity_session WHERE session_id = ? AND user_id = ? AND expires_at > CAST(? AS INTEGER)) THEN 1 ELSE 0 END;",
  );
  assert.equal(old.meta.securityExpiry, undefined);
});

test("actual SQLite authorization succeeds for a live native session and releases every guard", async () => {
  const db = openFamilyD1();
  try {
    const captured = BigInt(Date.now()) * 1000n;
    seedSession(db, captured + 60_000_000n, captured + 30_000_000n);
    assert.deepEqual(
      await runFamily(db, dictionary, argumentsFor(captured), ids.workspace, { planId }),
      { ok: true, changes: "4" },
    );
    assert.equal(
      db.database.prepare("SELECT COUNT(*) AS n FROM platform_command_guard").get()?.n,
      0,
    );
    assert.equal(
      db.database.prepare("SELECT display_name FROM identity_user").get()?.display_name,
      "Changed",
    );
  } finally {
    db.database.close();
  }
});

for (const [name, absoluteDelta, accessDelta] of [
  ["access expiry after an earlier captured observation", 60_000_000n, -1_000_000n],
  ["absolute expiry", -1_000_000n, 60_000_000n],
  ["null access expiry", 60_000_000n, null],
] as const)
  test(`real transaction refuses ${name} and rolls back owner write, receipt and guards`, async () => {
    const db = openFamilyD1();
    try {
      const now = BigInt(Date.now()) * 1000n;
      seedSession(db, now + absoluteDelta, accessDelta === null ? null : now + accessDelta);
      const before = snapshot(db);
      assert.deepEqual(
        await runFamily(db, dictionary, argumentsFor(now - 5_000_000n), ids.workspace, { planId }),
        { ok: false, failure: "precondition" },
      );
      assert.deepEqual(snapshot(db), before);
      assert.equal(db.rollbacks(), 1);
    } finally {
      db.database.close();
    }
  });

test("strict equality and a backward server clock cannot weaken the captured lower bound", async () => {
  for (const expiryOffset of [0n, -1n, 1n]) {
    const db = openFamilyD1();
    try {
      const captured = BigInt(Date.now()) * 1000n + 60_000_000n;
      seedSession(db, captured + 30_000_000n, captured + expiryOffset);
      const outcome = await runFamily(db, dictionary, argumentsFor(captured), ids.workspace, {
        planId,
      });
      assert.equal(outcome.ok, expiryOffset === 1n);
    } finally {
      db.database.close();
    }
  }
});

test("browser idle expiry uses the actual execution clock without revoking unrelated sessions", async () => {
  const header = nativeHeader.replace("expires_at,access_expires_at", "expires_at,idle_expires_at");
  const browserDictionary = workerDictionary(compiled(header));
  const db = openFamilyD1();
  try {
    const now = BigInt(Date.now()) * 1000n;
    seedSession(db, now + 60_000_000n, null, true, now - 1_000_000n);
    const before = snapshot(db);
    assert.equal(
      (
        await runFamily(
          db,
          browserDictionary,
          argumentsFor(now - 2_000_000n, uuid(), 2),
          ids.workspace,
          { planId },
        )
      ).ok,
      false,
    );
    assert.deepEqual(snapshot(db), before);
    assert.equal(
      db.database.prepare("SELECT revoked_at FROM identity_session").get()?.revoked_at,
      null,
    );
  } finally {
    db.database.close();
  }
});

test("a queued batch checks the real later statement time", async () => {
  const db = openFamilyD1();
  try {
    let captured = BigInt(Date.now()) * 1000n;
    seedSession(db, captured + 60_000_000n, captured + 30_000_000n);
    captured = BigInt(Date.now()) * 1000n;
    db.database.prepare("UPDATE identity_session SET access_expires_at=?").run(captured + 80_000n);
    assert.equal(
      db.database
        .prepare(
          `SELECT access_expires_at > ${securityNowUpperMicros} AS live FROM identity_session`,
        )
        .get()?.live,
      1,
    );
    const before = snapshot(db);
    const delayed = {
      prepare: db.prepare,
      batch: async (...args: Parameters<FamilyD1["batch"]>) => {
        await new Promise((resolve) => setTimeout(resolve, 130));
        return db.batch(...args);
      },
    };
    assert.equal(
      (await runFamily(delayed, dictionary, argumentsFor(captured), ids.workspace, { planId })).ok,
      false,
    );
    assert.deepEqual(snapshot(db), before);
  } finally {
    db.database.close();
  }
});

test("actual SQLite writer lock delay does not authorize an expired access credential", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "expiry-lock-"));
  const file = path.join(directory, "db.sqlite");
  const db = openFamilyD1(file);
  let worker: Worker | undefined;
  try {
    let captured = BigInt(Date.now()) * 1000n;
    seedSession(db, captured + 60_000_000n, captured + 30_000_000n);
    captured = BigInt(Date.now()) * 1000n;
    db.database
      .prepare("UPDATE identity_session SET access_expires_at=?")
      .run(captured + 1_000_000n);
    assert.equal(
      db.database
        .prepare(
          `SELECT access_expires_at > ${securityNowUpperMicros} AS live FROM identity_session`,
        )
        .get()?.live,
      1,
    );
    const before = snapshot(db);
    const lockedWorker = new Worker(
      `const {parentPort,workerData}=require('node:worker_threads'); const {DatabaseSync}=require('node:sqlite'); const db=new DatabaseSync(workerData); db.exec('BEGIN IMMEDIATE'); parentPort.postMessage('locked'); setTimeout(()=>{db.exec('COMMIT');db.close();},1200);`,
      { eval: true, workerData: file },
    );
    worker = lockedWorker;
    await new Promise<void>((resolve, reject) => {
      lockedWorker.once("message", () => resolve());
      lockedWorker.once("error", reject);
    });
    assert.equal(
      (await runFamily(db, dictionary, argumentsFor(captured), ids.workspace, { planId })).ok,
      false,
    );
    assert.deepEqual(snapshot(db), before);
  } finally {
    await worker?.terminate();
    db.database.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

const flow = "0198a7c0-1c3e-7d4a-9b1f-0000000b0005";
const profiles: {
  name: string;
  family: string;
  plan?: string;
  header: string;
  seed: (db: FamilyD1, expiry: bigint) => void;
  values: SQLInputValue[];
}[] = [
  {
    name: "native refresh absolute lifetime",
    family: "session-lifecycle",
    header:
      "kind=authorization module=identity key=refresh-current table=identity_session by=session_id match=user_id,credential_kind securityExpiry=expires_at",
    seed: (db, expiry) =>
      db.database.prepare("UPDATE identity_session SET expires_at=?").run(expiry),
    values: [session, ids.user, 1],
  },
  ...([2, 1] as const).map((state) => ({
    name: state === 2 ? "proved action challenge" : "pending challenge lifetime only",
    family: "account-security",
    plan: state === 1 ? "step-up-prove-native" : undefined,
    header: `kind=authorization module=identity key=${state === 1 ? "challenge-pending" : "action-proof"} table=identity_step_up_challenge by=challenge_id match=user_id,session_id,state securityExpiry=expires_at`,
    seed: (db: FamilyD1, expiry: bigint) => {
      db.database
        .prepare(
          "INSERT INTO identity_step_up_challenge (challenge_id,user_id,session_id,operation_class,target_hash,method,proof_hash,state,attempt_count,created_at,expires_at,consumed_at,auth_epoch,recovery_generation,rev) VALUES (?,?,?,'operation','target','passkey',?,?,0,1,?,NULL,1,0,1)",
        )
        .run(flow, ids.user, session, new Uint8Array(32), state, expiry);
    },
    values: [flow, ids.user, session, state] as SQLInputValue[],
  })),
  {
    name: "native authorization code and flow deadlines",
    family: "account-enrollment",
    header:
      "kind=authorization module=identity key=native-code-current table=identity_native_authorization by=flow_id match=realm_id,code_hash securityExpiry=expires_at,code_expires_at",
    seed: (db, expiry) => {
      db.database
        .prepare(
          "INSERT INTO identity_native_authorization (flow_id,realm_id,installation_id,client_id,redirect_uri,state_hash,pkce_challenge,code_hash,user_id,session_id,created_at,expires_at,code_expires_at,consumed_at,attempt_count,rev) VALUES (?,?,?,'client','https://auth.example.test','state','pkce','code',NULL,NULL,1,?,?,NULL,0,1)",
        )
        .run(flow, ids.workspace, device, expiry + 60_000_000n, expiry);
    },
    values: [flow, ids.workspace, "code"],
  },
  {
    name: "browser authentication flow",
    family: "account-enrollment",
    header:
      "kind=authorization module=identity key=browser-flow-current table=identity_browser_auth_flow by=flow_id match=origin,method securityExpiry=expires_at",
    seed: (db, expiry) => {
      db.database
        .prepare(
          "INSERT INTO identity_browser_auth_flow (flow_id,binding_hash,origin,method,purpose,challenge,created_at,expires_at,attempts,max_attempts,consumed_at,csrf_hash) VALUES (?,'binding','https://auth.example.test',1,1,'{}',1,?,0,5,NULL,'csrf')",
        )
        .run(flow, expiry);
    },
    values: [flow, "https://auth.example.test", 1],
  },
  {
    name: "enrollment security flow",
    family: "account-enrollment",
    header:
      "kind=authorization module=identity key=enrollment-flow-current table=identity_security_flow by=flow_id match=kind,purpose securityExpiry=expires_at",
    seed: (db, expiry) => {
      db.database
        .prepare(
          "INSERT INTO identity_security_flow (flow_id,kind,purpose,provider,user_id,installation_id,device_id,origin,proof_hash,target_payload_hash,expires_at,attempts,consumed_at,payload_proto) VALUES (?,'enrollment','enroll',NULL,NULL,NULL,NULL,NULL,?,?,?,0,NULL,?)",
        )
        .run(flow, new Uint8Array(32), new Uint8Array(32), expiry, new Uint8Array([1]));
    },
    values: [flow, "enrollment", "enroll"],
  },
];

for (const profile of profiles)
  test(`${profile.name} compiles and refuses at real statement time`, () => {
    const guard = expandGuard(profile.header, schema, profile.name, profile.family, profile.plan);
    for (const live of [true, false]) {
      const db = openFamilyD1();
      try {
        const captured = BigInt(Date.now()) * 1000n;
        seedSession(db, captured + 60_000_000n, captured + 30_000_000n);
        profile.seed(db, captured + (live ? 30_000_000n : -1_000_000n));
        const before = snapshot(db);
        db.database.exec("BEGIN IMMEDIATE");
        const run = () =>
          db.database.prepare(guard.sql).run(uuid(), ...profile.values, captured - 2_000_000n);
        if (live) {
          run();
          assert.equal(
            db.database.prepare("SELECT allowed FROM platform_command_guard").get()?.allowed,
            1,
          );
        } else assert.throws(run, /CHECK constraint failed/u);
        db.database.exec("ROLLBACK");
        assert.deepEqual(snapshot(db), before);
      } finally {
        db.database.close();
      }
    }
  });

test("pending challenges are not admitted to an arbitrary plan", () => {
  const pending = profiles.find((profile) => profile.plan)?.header;
  assert.ok(pending);
  assert.throws(
    () => expandGuard(pending, schema, "pending", "account-security", "consume-proof"),
    /not registered/u,
  );
});

function deletionOwnerSchema() {
  return schema.tables.some((table) => table.name === "identity_account_deletion")
    ? schema
    : { ...schema, tables: [...schema.tables, deletionPhysical] };
}

function ensureDeletionOwner(db: ReturnType<typeof openFamilyD1>) {
  const migrated = schema.tables.some((table) => table.name === "identity_account_deletion");
  const existing = db.database
    .prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='identity_account_deletion'",
    )
    .get();
  if (migrated) {
    assert.ok(existing, "The genuine deletion owner must come from its numbered migration");
    return;
  }
  assert.equal(existing, undefined, "An unmodeled deletion table is not the historical fixture");
  // Retain the exact historical pre-producer component; never recreate a migrated owner.
  db.database.exec(deletionDDL);
}

test("actual immutable deletion-owner DDL protects due and cancellation boundaries", () => {
  assert.equal(
    createHash("sha256").update(deletionDDL, "utf8").digest("hex"),
    "f19739b338cda9b9da8a85a1da9deaad35d70b4ffffd3aa55546ade84eb9c76a",
  );
  const futureSchema = deletionOwnerSchema();
  for (const [key, plan, state, annotation, live] of [
    ["deletion-due", "begin-deletion-purge", 1, "securityDue", true],
    ["deletion-due", "begin-deletion-purge", 1, "securityDue", false],
    ["deletion-purging", "complete-deletion-purge", 3, "securityDue", true],
    ["deletion-current", "cancel-deletion", 1, "securityExpiry", true],
    ["deletion-current", "cancel-deletion", 1, "securityExpiry", false],
  ] as const) {
    const header = `kind=authorization module=identity key=${key} table=identity_account_deletion by=deletion_id,realm_id match=user_id,state,rev ${annotation}=grace_ends_at`;
    const guard = expandGuard(
      header,
      futureSchema,
      "actual future owner",
      "account-security",
      plan,
    );
    assert.equal(
      guard.meta.securityExpiry?.capturedParamIndex === null,
      annotation === "securityDue",
    );
    const db = openFamilyD1();
    try {
      seed(db);
      ensureDeletionOwner(db);
      const captured = BigInt(Date.now()) * 1000n;
      const due = annotation === "securityDue";
      const deadline = captured + ((due ? !live : live) ? 30_000_000n : -1_000_000n);
      db.database
        .prepare(
          "INSERT INTO identity_account_deletion (deletion_id,realm_id,user_id,requested_at,grace_ends_at,policy_version,grace_seconds,previous_user_state,state,cancelled_at,completed_at,rev) VALUES (?,?,?,?,?,'p1',1,1,?,NULL,NULL,1)",
        )
        .run(flow, ids.workspace, ids.user, deadline - 1_000_000n, deadline, state);
      const values: SQLInputValue[] = [uuid(), flow, ids.workspace, ids.user, state, 1];
      if (!due) values.push(captured);
      const before = snapshot(db);
      db.database.exec("BEGIN IMMEDIATE");
      const run = () => db.database.prepare(guard.sql).run(...values);
      if (live) run();
      else assert.throws(run, /CHECK constraint failed/u);
      db.database.exec("ROLLBACK");
      assert.deepEqual(snapshot(db), before);
      if (due) {
        assert.ok(guard.sql.includes(securityNowLowerMicros));
        assert.ok(!guard.sql.includes("MAX("));
        assert.throws(() =>
          db.database.prepare(guard.sql).run(...values, captured + 1_000_000_000n),
        );
        assert.throws(
          () => expandGuard(header, futureSchema, "wrong plan", "account-security", "arbitrary"),
          /not registered/u,
        );
        assert.throws(() =>
          expandGuard(
            header + " fresh=grace_ends_at",
            futureSchema,
            "combined",
            "account-security",
            plan,
          ),
        );
        assert.throws(() =>
          expandGuard(
            header + " securityExpiry=grace_ends_at",
            futureSchema,
            "combined",
            "account-security",
            plan,
          ),
        );
      }
    } finally {
      db.database.close();
    }
  }
});

test("actual SQLite statement clock refuses expiry at its ceiling and accepts only ceiling plus one microsecond", () => {
  const guard = expandGuard(nativeHeader, schema, "SQLite ceiling boundary", "session-lifecycle");
  const db = openFamilyD1();
  try {
    seedSession(db, 60_000_000_000_000_000n, 60_000_000_000_000_000n);
    // A statement-local projection derives the fixture deadline from the real VFS clock.
    // Both this CTE and the unchanged compiled predicate execute in one sqlite3_step.
    const sql = `WITH clock AS MATERIALIZED (SELECT ${securityNowUpperMicros} + CAST(? AS INTEGER) AS deadline),
identity_session AS (
  SELECT current.session_id, current.user_id, current.credential_kind,
         clock.deadline AS expires_at, clock.deadline AS access_expires_at
  FROM main.identity_session AS current CROSS JOIN clock
)
${guard.sql}`;
    for (const delta of [-1, 0, 1]) {
      db.database.exec("BEGIN IMMEDIATE");
      try {
        const run = () => db.database.prepare(sql).run(delta, uuid(), session, ids.user, 1, 0);
        if (delta > 0) {
          run();
          assert.equal(
            db.database.prepare("SELECT allowed FROM platform_command_guard").get()?.allowed,
            1,
          );
        } else assert.throws(run, /CHECK constraint failed/u);
      } finally {
        db.database.exec("ROLLBACK");
      }
      assert.equal(
        db.database.prepare("SELECT COUNT(*) AS n FROM platform_command_guard").get()?.n,
        0,
      );
    }
  } finally {
    db.database.close();
  }
});

test("actual SQLite statement clock accepts deletion at its floor and refuses floor plus one microsecond", () => {
  const futureSchema = deletionOwnerSchema();
  const guard = expandGuard(
    "kind=authorization module=identity key=deletion-due table=identity_account_deletion by=deletion_id,realm_id match=user_id,state,rev securityDue=grace_ends_at",
    futureSchema,
    "SQLite floor boundary",
    "account-security",
    "begin-deletion-purge",
  );
  const db = openFamilyD1();
  try {
    seed(db);
    ensureDeletionOwner(db);
    db.database
      .prepare(
        "INSERT INTO identity_account_deletion (deletion_id,realm_id,user_id,requested_at,grace_ends_at,policy_version,grace_seconds,previous_user_state,state,cancelled_at,completed_at,rev) VALUES (?,?,?,0,1000000,'p1',1,1,1,NULL,NULL,1)",
      )
      .run(flow, ids.workspace, ids.user);
    // The projection changes only this boundary fixture, never the persisted immutable deadline.
    const sql = `WITH clock AS MATERIALIZED (SELECT ${securityNowLowerMicros} + CAST(? AS INTEGER) AS deadline),
identity_account_deletion AS (
  SELECT current.deletion_id, current.realm_id, current.user_id, current.state, current.rev,
         clock.deadline AS grace_ends_at
  FROM main.identity_account_deletion AS current CROSS JOIN clock
)
${guard.sql}`;
    for (const delta of [-1, 0, 1]) {
      db.database.exec("BEGIN IMMEDIATE");
      try {
        const run = () =>
          db.database.prepare(sql).run(delta, uuid(), flow, ids.workspace, ids.user, 1, 1);
        if (delta <= 0) {
          run();
          assert.equal(
            db.database.prepare("SELECT allowed FROM platform_command_guard").get()?.allowed,
            1,
          );
        } else assert.throws(run, /CHECK constraint failed/u);
      } finally {
        db.database.exec("ROLLBACK");
      }
    }
    assert.equal(
      db.database.prepare("SELECT grace_ends_at FROM identity_account_deletion").get()
        ?.grace_ends_at,
      1_000_000,
    );
  } finally {
    db.database.close();
  }
});

test("an injected unavailable SQLite clock refuses authorization and rolls back the actual Worker transaction", async () => {
  const db = openFamilyD1();
  try {
    const captured = BigInt(Date.now()) * 1000n;
    seedSession(db, captured + 60_000_000n, captured + 30_000_000n);
    const before = snapshot(db);
    // Only the unavailable clock dependency is injected; SQL, migrations and executor are real.
    db.database.function("strftime", { varargs: true }, () => null);
    assert.deepEqual(
      await runFamily(db, dictionary, argumentsFor(captured), ids.workspace, { planId }),
      { ok: false, failure: "precondition" },
    );
    assert.deepEqual(snapshot(db), before);
    assert.equal(db.rollbacks(), 1);
    ensureDeletionOwner(db);
    db.database
      .prepare(
        "INSERT INTO identity_account_deletion (deletion_id,realm_id,user_id,requested_at,grace_ends_at,policy_version,grace_seconds,previous_user_state,state,cancelled_at,completed_at,rev) VALUES (?,?,?,0,1000000,'p1',1,1,1,NULL,NULL,1)",
      )
      .run(flow, ids.workspace, ids.user);
    const due = expandGuard(
      "kind=authorization module=identity key=deletion-due table=identity_account_deletion by=deletion_id,realm_id match=user_id,state,rev securityDue=grace_ends_at",
      deletionOwnerSchema(),
      "unavailable clock",
      "account-security",
      "begin-deletion-purge",
    );
    db.database.exec("BEGIN IMMEDIATE");
    try {
      assert.throws(
        () => db.database.prepare(due.sql).run(uuid(), flow, ids.workspace, ids.user, 1, 1),
        /CHECK constraint failed/u,
      );
    } finally {
      db.database.exec("ROLLBACK");
    }
    assert.deepEqual(snapshot(db), before);
  } finally {
    db.database.close();
  }
});

test("concurrent stale snapshots refuse after a real commit with a lost transport reply and reopen", async () => {
  const directory = mkdtempSync(path.join(tmpdir(), "expiry-receipt-"));
  const file = path.join(directory, "db.sqlite");
  const first = openFamilyD1(file);
  const second = openFamilyD1(file, false);
  try {
    const captured = BigInt(Date.now()) * 1000n;
    seedSession(first, captured + 60_000_000n, captured + 30_000_000n);
    const text = source(
      nativeHeader.replace("match=user_id,credential_kind", "match=user_id,credential_kind,rev"),
    ).replace(
      "UPDATE identity_user SET display_name = ? WHERE user_id = ?;",
      "UPDATE identity_session SET rev = rev + 1 WHERE session_id = ? AND user_id = ?;",
    );
    const root = fixtureRoot({ "session-lifecycle.security-expiry.sql": text }, registry);
    let checked: ReturnType<typeof buildManifest>;
    try {
      checked = buildManifest(root, { physicalDirectory });
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
    const calls = (command: string) => {
      const values = argumentsFor(captured, command);
      const authorization = values[0];
      assert.ok(authorization);
      authorization.splice(4, 0, i64(1));
      values[1] = [txt(session), txt(ids.user)];
      return values;
    };
    const committed = uuid();
    const lostReply = {
      prepare: first.prepare,
      batch: async (...args: Parameters<FamilyD1["batch"]>) => {
        await first.batch(...args);
        throw new Error("Unavailable D1 reply after the real SQLite commit");
      },
    };
    const results = await Promise.all([
      runFamily(lostReply, workerDictionary(checked), calls(committed), ids.workspace, { planId }),
      runFamily(second, workerDictionary(checked), calls(uuid()), ids.workspace, { planId }),
    ]);
    assert.deepEqual(results, [
      { ok: false, failure: "unknownOutcome" },
      { ok: false, failure: "precondition" },
    ]);
    assert.equal(second.database.prepare("SELECT COUNT(*) AS n FROM platform_command").get()?.n, 1);
    assert.equal(second.database.prepare("SELECT rev FROM identity_session").get()?.rev, 2);
    const reopened = openFamilyD1(file, false);
    try {
      const receipt = reopened.database
        .prepare("SELECT status,request_hash FROM platform_command WHERE command_id=?")
        .get(committed);
      assert.equal(receipt?.status, 2);
      assert.equal(receipt?.request_hash, "hash");
      assert.equal(
        reopened.database.prepare("SELECT COUNT(*) AS n FROM platform_command_guard").get()?.n,
        0,
      );
    } finally {
      reopened.database.close();
    }
  } finally {
    first.database.close();
    second.database.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

// Frozen actual CLOUD.79 owner fixture 79c02dbcc18f0b7252b8debccddea5c5a89f35db; not an activated migration or deployment receipt.
const deletionDDL =
  '-- af-migration: module=identity mode=expand\n-- Actual immutable disclosed deletion lifecycle; accepted baselines remain unchanged.\nCREATE TABLE "identity_account_deletion" (\n  "deletion_id" TEXT NOT NULL CONSTRAINT "ck_identity_account_deletion__deletion_id" CHECK (length("deletion_id") = 36 AND "deletion_id" GLOB \'????????-????-????-????-????????????\' AND "deletion_id" NOT GLOB \'*[^0-9a-f-]*\'),\n  "realm_id" TEXT NOT NULL CONSTRAINT "ck_identity_account_deletion__realm_id" CHECK (length("realm_id") = 36 AND "realm_id" GLOB \'????????-????-????-????-????????????\' AND "realm_id" NOT GLOB \'*[^0-9a-f-]*\'),\n  "user_id" TEXT NOT NULL CONSTRAINT "ck_identity_account_deletion__user_id" CHECK (length("user_id") = 36 AND "user_id" GLOB \'????????-????-????-????-????????????\' AND "user_id" NOT GLOB \'*[^0-9a-f-]*\'),\n  "requested_at" INTEGER NOT NULL,\n  "grace_ends_at" INTEGER NOT NULL,\n  "policy_version" TEXT NOT NULL CONSTRAINT "ck_identity_account_deletion__policy_version" CHECK (length("policy_version") BETWEEN 1 AND 128 AND "policy_version" NOT GLOB \'*[^A-Za-z0-9._:/-]*\'),\n  "grace_seconds" INTEGER NOT NULL,\n  "previous_user_state" INTEGER NOT NULL CONSTRAINT "ck_identity_account_deletion__previous_user_state" CHECK ("previous_user_state" IN (1, 2, 3, 4, 5)),\n  "state" INTEGER NOT NULL CONSTRAINT "ck_identity_account_deletion__state" CHECK ("state" IN (1, 2, 3, 4)),\n  "cancelled_at" INTEGER,\n  "completed_at" INTEGER,\n  "rev" INTEGER NOT NULL CONSTRAINT "ck_identity_account_deletion__rev" CHECK ("rev" >= 0),\n  CONSTRAINT "pk_identity_account_deletion" PRIMARY KEY ("deletion_id"),\n  CONSTRAINT "fk_identity_account_deletion__user_id" FOREIGN KEY ("user_id") REFERENCES "identity_user" ("user_id") ON DELETE RESTRICT,\n  CONSTRAINT "ck_identity_account_deletion__deadline_duration" CHECK ("grace_seconds" > 0 AND "grace_seconds" <= 9223372036854 AND "requested_at" >= 0 AND "requested_at" <= 9223372036854775807 - "grace_seconds" * 1000000 AND "grace_ends_at" = "requested_at" + "grace_seconds" * 1000000 AND "grace_ends_at" > "requested_at"),\n  CONSTRAINT "ck_identity_account_deletion__previous_state" CHECK ("previous_user_state" IN (1, 2, 3)),\n  CONSTRAINT "ck_identity_account_deletion__terminal_facts" CHECK (("state" IN (1, 3) AND "cancelled_at" IS NULL AND "completed_at" IS NULL) OR ("state" = 2 AND "cancelled_at" IS NOT NULL AND "cancelled_at" >= "requested_at" AND "cancelled_at" < "grace_ends_at" AND "completed_at" IS NULL) OR ("state" = 4 AND "completed_at" IS NOT NULL AND "completed_at" >= "grace_ends_at" AND "cancelled_at" IS NULL))\n) STRICT;\n\nCREATE UNIQUE INDEX "ux_identity_account_deletion__user_id" ON "identity_account_deletion" ("user_id") WHERE "state" IN (1, 3);\n\nCREATE INDEX "ix_identity_account_deletion__state_grace_ends_at" ON "identity_account_deletion" ("state", "grace_ends_at");\n\nCREATE INDEX "ix_identity_account_deletion__user_id_requested_at" ON "identity_account_deletion" ("user_id", "requested_at");\n\nCREATE TRIGGER "tr_identity_account_deletion__limited_update" BEFORE UPDATE ON "identity_account_deletion"\nWHEN (OLD."deletion_id" IS NOT NEW."deletion_id" OR OLD."realm_id" IS NOT NEW."realm_id" OR OLD."user_id" IS NOT NEW."user_id" OR OLD."requested_at" IS NOT NEW."requested_at" OR OLD."grace_ends_at" IS NOT NEW."grace_ends_at" OR OLD."policy_version" IS NOT NEW."policy_version" OR OLD."grace_seconds" IS NOT NEW."grace_seconds" OR OLD."previous_user_state" IS NOT NEW."previous_user_state") OR NOT (OLD."state" IN (1, 3))\nBEGIN\n  SELECT RAISE(ABORT, \'CHECK constraint failed: af_immutable_identity_account_deletion\');\nEND;\n\nCREATE TRIGGER "tr_identity_account_deletion__immutable_delete" BEFORE DELETE ON "identity_account_deletion"\nBEGIN\n  SELECT RAISE(ABORT, \'CHECK constraint failed: af_immutable_identity_account_deletion\');\nEND;\n';
const deletionPhysical = {
  name: "identity_account_deletion",
  owner: "identity",
  model: "01 section 3 identity.account_deletion",
  columns: [
    { name: "deletion_id", kind: "id", sqlType: "TEXT", nullable: false, monotonic: false },
    { name: "realm_id", kind: "id", sqlType: "TEXT", nullable: false, monotonic: false },
    { name: "user_id", kind: "id", sqlType: "TEXT", nullable: false, monotonic: false },
    {
      name: "requested_at",
      kind: "instant",
      sqlType: "INTEGER",
      nullable: false,
      monotonic: false,
    },
    {
      name: "grace_ends_at",
      kind: "instant",
      sqlType: "INTEGER",
      nullable: false,
      monotonic: false,
    },
    { name: "policy_version", kind: "key", sqlType: "TEXT", nullable: false, monotonic: false },
    { name: "grace_seconds", kind: "int64", sqlType: "INTEGER", nullable: false, monotonic: false },
    {
      name: "previous_user_state",
      kind: "enum",
      sqlType: "INTEGER",
      nullable: false,
      monotonic: false,
      enumName: "identity.user_state",
    },
    {
      name: "state",
      kind: "enum",
      sqlType: "INTEGER",
      nullable: false,
      monotonic: false,
      enumName: "identity.deletion_state",
    },
    { name: "cancelled_at", kind: "instant", sqlType: "INTEGER", nullable: true, monotonic: false },
    { name: "completed_at", kind: "instant", sqlType: "INTEGER", nullable: true, monotonic: false },
    { name: "rev", kind: "rev", sqlType: "INTEGER", nullable: false, monotonic: false },
  ],
  primaryKey: ["deletion_id"],
  indexes: [
    {
      name: "ux_identity_account_deletion__user_id",
      columns: ["user_id"],
      path: "one active pending or purging lifecycle per user",
      unique: true,
      where: '"state" IN (1, 3)',
    },
    {
      name: "ix_identity_account_deletion__state_grace_ends_at",
      columns: ["state", "grace_ends_at"],
      path: "bounded deadline purge scheduling",
      unique: false,
    },
    {
      name: "ix_identity_account_deletion__user_id_requested_at",
      columns: ["user_id", "requested_at"],
      path: "retained user lifecycle history",
      unique: false,
    },
  ],
  foreignKeys: [
    {
      columns: ["user_id"],
      references: { table: "identity_user", columns: ["user_id"] },
      onDelete: "restrict",
    },
  ],
  checks: [
    {
      name: "deadline_duration",
      sql: '"grace_seconds" > 0 AND "grace_seconds" <= 9223372036854 AND "requested_at" >= 0 AND "requested_at" <= 9223372036854775807 - "grace_seconds" * 1000000 AND "grace_ends_at" = "requested_at" + "grace_seconds" * 1000000 AND "grace_ends_at" > "requested_at"',
    },
    { name: "previous_state", sql: '"previous_user_state" IN (1, 2, 3)' },
    {
      name: "terminal_facts",
      sql: '("state" IN (1, 3) AND "cancelled_at" IS NULL AND "completed_at" IS NULL) OR ("state" = 2 AND "cancelled_at" IS NOT NULL AND "cancelled_at" >= "requested_at" AND "cancelled_at" < "grace_ends_at" AND "completed_at" IS NULL) OR ("state" = 4 AND "completed_at" IS NOT NULL AND "completed_at" >= "grace_ends_at" AND "cancelled_at" IS NULL)',
    },
  ],
  mutability: {
    update: {
      columns: ["state", "cancelled_at", "completed_at", "rev"],
      when: 'OLD."state" IN (1, 3)',
    },
    delete: "none",
  },
  bootstrap: false,
} as (typeof schema.tables)[number];
