// SPDX-License-Identifier: AGPL-3.0-only
// The family grammar of the plan generator (Design D1 profile section 4, "Shared family plans and the guard table"): the registry, the
// five guard primitives expanded against the physical manifest, the SU-04 order and the participant, ownership and guard-coverage
// rules. The fixture family is a test fixture; the repository's own registry ships empty.
import assert from "node:assert/strict";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import {
  buildManifest,
  expandGuard,
  familyIdentity,
  renderFamilyExpansion,
  familyOrderProblems,
  generate,
  guardKinds,
  lockOrder,
  mutationClasses,
  parseFamilyRegistry,
  renderCSharp,
  renderTypeScript,
  sha256Hex,
  normalizePlanText,
  type FamilyStatementMeta,
} from "../../eng/verification/storage-plans.ts";
import { loadManifest } from "../../eng/verification/physical-schema.ts";
import {
  fixtureFamilyId,
  fixtureManifest,
  fixturePlan,
  fixturePlanId,
  fixtureRegistry,
  fixtureRoot,
  physicalDirectory,
} from "./support/family-fixtures.ts";
import { repositoryRoot } from "./support/sqlite-d1.ts";

const vectors = JSON.parse(
  readFileSync(
    path.join(repositoryRoot, "tests/ArcForges.Cloud.Tests/Vectors/family-lock-order.json"),
    "utf8",
  ),
) as {
  lockOrder: string[];
  guardClassOrder: string[];
  mutationClassOrder: string[];
  orderCases: { name: string; valid: boolean; roles: string[] }[];
  identity: { normalizedText: string; statementSql: string[]; sha256: string };
  fixturePlan: {
    id: string;
    family: string;
    participants: { module: string; required: boolean }[];
    statements: { role: string; params: string[] }[];
  };
};
const schema = loadManifest(physicalDirectory);

const parseRole = (text: string): FamilyStatementMeta => {
  const [phase, module, className, key] = text.split(" ");
  return {
    phase: phase as FamilyStatementMeta["phase"],
    module: module ?? "",
    class: className ?? "",
    key: key ?? "",
  };
};
const roleText = (meta: FamilyStatementMeta) =>
  `${meta.phase} ${meta.module} ${meta.class} ${meta.key}`;

test("the fixed SU-04 order, the class orders and the platform rule are the shared vector", () => {
  assert.deepEqual([...lockOrder], vectors.lockOrder);
  assert.deepEqual([...guardKinds], vectors.guardClassOrder);
  assert.deepEqual([...mutationClasses], vectors.mutationClassOrder);
});

for (const testCase of vectors.orderCases) {
  test(`order vector: ${testCase.name}`, () => {
    const problems = familyOrderProblems(testCase.roles.map(parseRole));
    assert.equal(problems.length === 0, testCase.valid, problems.join("; "));
  });
}

test("the order rule names the first rule a plan breaks", () => {
  const problems = familyOrderProblems(
    [
      "guard workspace revision a",
      "guard identity revision a",
      "mutation workspace record a",
      "release platform release release",
    ].map(parseRole),
  );
  assert.equal(problems.length, 1);
  assert.match(
    problems[0] ?? "",
    /module identity may not follow module workspace \(SU-04 order\)/u,
  );
});

// ---------------------------------------------------------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------------------------------------------------------

const registryWith = (change: (entry: Record<string, unknown>) => void) => {
  const entry = structuredClone(fixtureRegistry.families[0]) as Record<string, unknown>;
  change(entry);
  return JSON.stringify({ schemaVersion: 1, families: [entry] });
};

test("the repository registry parses and the fixture registry parses", () => {
  const real = parseFamilyRegistry(
    readFileSync(path.join(repositoryRoot, "storage/plans/families.json"), "utf8"),
  );
  assert(Array.isArray(real.families));
  const fixture = parseFamilyRegistry(JSON.stringify(fixtureRegistry));
  assert.deepEqual(
    fixture.families[0]?.participants.map((participant) => participant.module),
    ["config", "workspace", "entitlement", "policy", "notification"],
  );
  assert.equal(fixture.families[0]?.participants[3]?.when, "when a source policy applies");
});

test("a malformed registry is refused, and Support and TrustSafety cannot participate", () => {
  const participants = (entry: Record<string, unknown>) =>
    entry["participants"] as Record<string, unknown>[];
  const cases: [string, (entry: Record<string, unknown>) => void, RegExp][] = [
    [
      "a participant outside the SU-04 order (support)",
      (entry) => participants(entry).push({ module: "support", requirement: "required" }),
      /support has no position in the SU-04 order/u,
    ],
    [
      "a participant outside the SU-04 order (trustsafety)",
      (entry) => participants(entry).push({ module: "trustsafety", requirement: "required" }),
      /trustsafety has no position in the SU-04 order/u,
    ],
    [
      "the platform as a participant",
      (entry) => participants(entry).push({ module: "platform", requirement: "required" }),
      /platform has no position/u,
    ],
    [
      "a duplicate participant",
      (entry) => participants(entry).push({ module: "config", requirement: "required" }),
      /duplicate participant config/u,
    ],
    [
      "a conditional participant without its condition",
      (entry) => participants(entry).push({ module: "sync", requirement: "conditional" }),
      /states when/u,
    ],
    [
      "a required participant with a condition",
      (entry) => participants(entry).push({ module: "sync", requirement: "required", when: "x" }),
      /has no condition/u,
    ],
    [
      "an unknown requirement",
      (entry) => participants(entry).push({ module: "sync", requirement: "optional" }),
      /requirement of sync/u,
    ],
    [
      "an unknown participant field",
      (entry) => participants(entry).push({ module: "sync", requirement: "required", note: "x" }),
      /fields of participant sync/u,
    ],
    [
      "fewer than two participants",
      (entry) => (entry["participants"] = [{ module: "config", requirement: "required" }]),
      /at least two participants/u,
    ],
    [
      "no required participant",
      (entry) =>
        (entry["participants"] = [
          { module: "config", requirement: "conditional", when: "x" },
          { module: "sync", requirement: "conditional", when: "y" },
        ]),
      /needs a required participant/u,
    ],
    ["a malformed family id", (entry) => (entry["family"] = "Bad_Id"), /invalid family id/u],
    ["an extra family field", (entry) => (entry["owner"] = "x"), /fields of/u],
  ];
  for (const [name, change, expected] of cases)
    assert.throws(() => parseFamilyRegistry(registryWith(change)), expected, name);
  assert.throws(
    () => parseFamilyRegistry(JSON.stringify({ schemaVersion: 2, families: [] })),
    /schemaVersion/u,
  );
  const twice = {
    schemaVersion: 1,
    families: [fixtureRegistry.families[0], fixtureRegistry.families[0]],
  };
  assert.throws(() => parseFamilyRegistry(JSON.stringify(twice)), /duplicate family/u);
});

// ---------------------------------------------------------------------------------------------------------------------------
// The guard primitives
// ---------------------------------------------------------------------------------------------------------------------------

const expand = (header: string) => expandGuard(header, schema, "test");
const sqlOf = (header: string) => expand(header).sql.replace(/\s+/gu, " ");
const kinds = (header: string) => expand(header).params.map((param) => param.kind);

test("every primitive expands to exactly one guard statement over the guard table", () => {
  assert.equal(
    sqlOf(
      "kind=authorization module=workspace key=owner table=workspace_workspace by=scope:workspace_id match=owner_user_id,state",
    ),
    "INSERT INTO platform_command_guard (command_id, guard_key, allowed) SELECT ?, 'workspace.owner', CASE WHEN EXISTS (SELECT 1 FROM workspace_workspace WHERE workspace_id = ? AND owner_user_id = ? AND state = CAST(? AS INTEGER)) THEN 1 ELSE 0 END;",
  );
  assert.equal(
    sqlOf(
      "kind=policy module=policy key=source-policy table=policy_source_policy by=workspace_id,target_kind,target_id match=revision fresh=updated_at",
    ),
    "INSERT INTO platform_command_guard (command_id, guard_key, allowed) SELECT ?, 'policy.source-policy', CASE WHEN EXISTS (SELECT 1 FROM policy_source_policy WHERE workspace_id = ? AND target_kind = ? AND target_id = ? AND revision = CAST(? AS INTEGER) AND updated_at > CAST(? AS INTEGER)) THEN 1 ELSE 0 END;",
  );
  assert.equal(
    sqlOf(
      "kind=revision module=entitlement key=workspace-revision table=entitlement_revision by=scope:workspace_id rev=rev",
    ),
    "INSERT INTO platform_command_guard (command_id, guard_key, allowed) SELECT ?, 'entitlement.workspace-revision', CASE WHEN COALESCE((SELECT rev FROM entitlement_revision WHERE workspace_id = ?), 0) = CAST(? AS INTEGER) THEN 1 ELSE 0 END;",
  );
  assert.equal(
    sqlOf(
      "kind=balance module=entitlement key=quota table=entitlement_quota_budget by=scope_kind,scope_id,quota_key,period_key rev=rev exact=used,held",
    ),
    "INSERT INTO platform_command_guard (command_id, guard_key, allowed) SELECT ?, 'entitlement.quota', CASE WHEN EXISTS (SELECT 1 FROM entitlement_quota_budget WHERE scope_kind = CAST(? AS INTEGER) AND scope_id = ? AND quota_key = ? AND period_key = ? AND rev = CAST(? AS INTEGER) AND used = CAST(? AS INTEGER) AND held = CAST(? AS INTEGER)) THEN 1 ELSE 0 END;",
  );
  assert.equal(
    sqlOf(
      "kind=lease module=platform key=job-lease table=platform_job_lease by=job_id holder=holder fence=fence_token until=leased_until",
    ),
    "INSERT INTO platform_command_guard (command_id, guard_key, allowed) SELECT ?, 'platform.job-lease', CASE WHEN EXISTS (SELECT 1 FROM platform_job_lease WHERE job_id = ? AND holder = ? AND fence_token = CAST(? AS INTEGER) AND leased_until > CAST(? AS INTEGER)) THEN 1 ELSE 0 END;",
  );
});

test("the parameters follow the physical column kinds, the command id first and the owner scope for a scope key", () => {
  assert.deepEqual(
    kinds(
      "kind=authorization module=workspace key=owner table=workspace_workspace by=scope:workspace_id match=owner_user_id,state",
    ),
    ["text", "scope", "text", "int64"],
  );
  assert.deepEqual(
    kinds(
      "kind=policy module=config key=cfg table=config_revision by=config_revision_id match=content_hash",
    ),
    ["text", "text", "bytes"],
  );
  // uint64 and decimal columns travel as their canonical text kinds.
  const decimal = schema.tables
    .flatMap((table) => table.columns.map((column) => ({ table, column })))
    .find(({ column }) => column.kind === "decimal" && !column.nullable);
  assert(decimal, "the manifest has a decimal column");
  const keyColumn = decimal.table.primaryKey[0] ?? "";
  assert.deepEqual(
    kinds(
      `kind=authorization module=${decimal.table.owner} key=dec table=${decimal.table.name} by=${keyColumn} match=${decimal.column.name}`,
    ).slice(2),
    ["decimal"],
  );
});

test("a guard is refused unless every name resolves in the physical manifest and means what its primitive needs", () => {
  const cases: [string, string, RegExp][] = [
    [
      "an unknown kind",
      "kind=exists module=workspace key=k table=workspace_workspace by=workspace_id",
      /guard kind must be one of/u,
    ],
    [
      "an unknown field",
      "kind=revision module=entitlement key=k table=entitlement_revision by=workspace_id rev=rev match=x",
      /unknown field 'match=x'/u,
    ],
    [
      "a duplicate field",
      "kind=revision module=entitlement key=k table=entitlement_revision by=workspace_id by=workspace_id rev=rev",
      /duplicate by/u,
    ],
    [
      "no key columns",
      "kind=revision module=entitlement key=k table=entitlement_revision rev=rev",
      /needs by=/u,
    ],
    [
      "an unknown table",
      "kind=revision module=entitlement key=k table=entitlement_nothing by=workspace_id rev=rev",
      /not a table of the physical manifest/u,
    ],
    [
      "an unknown column",
      "kind=revision module=entitlement key=k table=entitlement_revision by=nothing rev=rev",
      /nothing is not a column/u,
    ],
    [
      "a revision on a column that is not a revision",
      "kind=revision module=entitlement key=k table=entitlement_revision by=workspace_id rev=updated_at",
      /must be rev, not instant/u,
    ],
    [
      "a reserved word as a column name",
      "kind=balance module=entitlement key=k table=entitlement_quota_budget by=scope_kind,scope_id,quota_key,period_key rev=rev exact=limit",
      /reserved SQL word/u,
    ],
    [
      "a JSON column",
      "kind=authorization module=config key=k table=config_revision by=config_revision_id match=document",
      /is a json column/u,
    ],
    [
      "a column used twice",
      "kind=authorization module=workspace key=k table=workspace_workspace by=workspace_id match=workspace_id",
      /used twice/u,
    ],
    [
      "a scope on a column that is not text",
      "kind=revision module=entitlement key=k table=entitlement_quota_budget by=scope:scope_kind rev=rev",
      /only a text key column can be the owner scope/u,
    ],
    [
      "no match column for an authorization",
      "kind=authorization module=workspace key=k table=workspace_workspace by=workspace_id",
      /needs match=/u,
    ],
    [
      "no exact column for a balance",
      "kind=balance module=entitlement key=k table=entitlement_quota_budget by=scope_kind,scope_id,quota_key,period_key rev=rev",
      /needs exact=/u,
    ],
    [
      "a lease holder of the wrong kind",
      "kind=lease module=platform key=k table=platform_job_lease by=job_id holder=attempts fence=fence_token until=leased_until",
      /holder column attempts must be/u,
    ],
    [
      "a lease expiry that is not an instant",
      "kind=lease module=platform key=k table=platform_job_lease by=job_id holder=holder fence=fence_token until=attempts",
      /expiry column attempts must be instant/u,
    ],
    [
      "a freshness column that is not an instant",
      "kind=authorization module=workspace key=k table=workspace_workspace by=workspace_id match=state fresh=name",
      /fresh column name must be instant/u,
    ],
    [
      "a key that is not lower-case words",
      "kind=revision module=entitlement key=Bad_Key table=entitlement_revision by=workspace_id rev=rev",
      /stable key is lower-case words/u,
    ],
    [
      "a module outside the order",
      "kind=revision module=support key=k table=support_support_case by=case_id rev=rev",
      /support has no position in the SU-04 order/u,
    ],
    [
      "too many key columns",
      "kind=authorization module=workspace key=k table=workspace_workspace by=workspace_id,realm_id,owner_user_id,name,data_region,protection_profile,state match=created_at",
      /at most 6 key columns/u,
    ],
  ];
  for (const [name, header, expected] of cases) assert.throws(() => expand(header), expected, name);
});

// ---------------------------------------------------------------------------------------------------------------------------
// The plan-level rules
// ---------------------------------------------------------------------------------------------------------------------------

const build = (text: string, registry?: unknown) =>
  fixtureManifest({ [`${fixtureFamilyId}.commit.sql`]: text }, registry);
test("the fixture plan generates exactly the statements, roles and parameters of the shared vector", () => {
  const manifest = fixtureManifest();
  const plan = manifest.plans.find((candidate) => candidate.id === fixturePlanId);
  assert(plan);
  assert.equal(plan.family, fixtureFamilyId);
  assert.equal(vectors.fixturePlan.id, plan.id);
  assert.deepEqual(
    plan.statements.map((statement) => roleText(statement.family as FamilyStatementMeta)),
    vectors.fixturePlan.statements.map((statement) => statement.role),
  );
  assert.deepEqual(
    plan.statements.map((statement) => statement.params.map((param) => param.kind)),
    vectors.fixturePlan.statements.map((statement) => statement.params),
  );
  assert.equal(
    plan.statements.at(-1)?.sql,
    "DELETE FROM platform_command_guard WHERE command_id = ?;",
  );
  assert.deepEqual(
    vectors.fixturePlan.participants,
    fixtureRegistry.families[0]?.participants.map((participant) => ({
      module: participant.module,
      required: participant.requirement === "required",
    })),
  );
});

test("a family plan's identity covers its generated statements, not only the authored text", () => {
  const plan = fixtureManifest().plans.find((candidate) => candidate.id === fixturePlanId);
  assert(plan);
  assert.notEqual(plan.sha256, sha256Hex(normalizePlanText(fixturePlan)));
  const changed = fixtureManifest({
    [`${fixtureFamilyId}.commit.sql`]: fixturePlan.replace(
      "by=scope:workspace_id rev=rev",
      "by=scope:workspace_id rev=rev ",
    ),
  }).plans.find((candidate) => candidate.id === fixturePlanId);
  assert.notEqual(changed?.sha256, plan.sha256, "any byte of the authored text changes it");
});

const planLines = fixturePlan.split("\n");
const lineWith = (fragment: string) => {
  const found = planLines.find((line) => line.includes(fragment));
  assert(found, `fixture line: ${fragment}`);
  return found;
};
const without = (...fragments: string[]) =>
  planLines.filter((line) => !fragments.some((fragment) => line.includes(fragment))).join("\n");
const swap = (first: string, second: string) =>
  planLines
    .map((line) =>
      line === lineWith(first)
        ? lineWith(second)
        : line === lineWith(second)
          ? lineWith(first)
          : line,
    )
    .join("\n");
const insertBefore = (anchor: string, text: string) =>
  planLines.flatMap((line) => (line.includes(anchor) ? [text, line] : [line])).join("\n");
const updateRevision =
  "UPDATE entitlement_revision SET rev = rev + 1, updated_at = CAST(? AS INTEGER) WHERE workspace_id = ?;";

const planRules: [string, string, RegExp, unknown?][] = [
  [
    "a guard after a mutation",
    insertBefore("module=platform class=record", lineWith("key=suppression table=")),
    /a guard statement may not follow a mutation statement/u,
  ],
  [
    "modules out of the SU-04 order",
    swap("key=active-config", "key=owner table=workspace_workspace"),
    /module config may not follow module workspace \(SU-04 order\)/u,
  ],
  [
    "balance before revision inside a module",
    swap("key=workspace-revision", "key=quota table="),
    /class revision may not follow class balance/u,
  ],
  [
    "a module that writes without a guard of its own",
    without("key=suppression table="),
    /module notification writes without a guard of its own/u,
  ],
  [
    "a participant outside the family",
    insertBefore(
      "module=entitlement key=workspace-revision",
      "-- guard: kind=revision module=device key=device table=device_device by=device_id rev=rev",
    ),
    /module device is not a participant of family fixture-pair/u,
  ],
  [
    "a required participant without a statement",
    without("key=active-config"),
    /required participant config has no statement/u,
  ],
  [
    "a mutation naming another module's table",
    fixturePlan.replace(
      updateRevision,
      "UPDATE workspace_workspace SET rev = rev + 1 WHERE created_at = CAST(? AS INTEGER) AND workspace_id = ?;",
    ),
    /table workspace_workspace is not owned by module entitlement/u,
  ],
  [
    "a mutation naming the guard table",
    fixturePlan
      .replace(
        updateRevision,
        "DELETE FROM platform_command_guard WHERE command_id = ? AND guard_key = ?;",
      )
      .replace(
        "class=record key=revision params=int64,scope",
        "class=record key=revision params=text,text",
      ),
    /only the generated guard and release statements name platform_command_guard/u,
  ],
  [
    "a mutation naming the migration bookkeeping",
    fixturePlan.replace(
      "INSERT INTO platform_command (command_id,",
      "INSERT INTO platform_schema_state (command_id,",
    ),
    /platform_schema_state is written only by the migration runner/u,
  ],
  [
    "an authored release statement",
    fixturePlan.replace("class=record key=receipt", "class=release key=release"),
    /a hand-written family statement is a mutation of class/u,
  ],
  [
    "an authored guard written as a statement",
    fixturePlan.replace(
      "module=notification class=record key=suppression",
      "module=notification class=revision key=suppression",
    ),
    /a hand-written family statement is a mutation of class/u,
  ],
  [
    "a SELECT as a family mutation",
    fixturePlan.replace(
      updateRevision,
      "SELECT 1 FROM entitlement_revision WHERE updated_at = CAST(? AS INTEGER) AND workspace_id = ?;",
    ),
    /an INSERT, UPDATE or DELETE/u,
  ],
  [
    "a statement without a class",
    fixturePlan.replace(
      "module=entitlement class=record key=revision",
      "module=entitlement key=revision",
    ),
    /names module=, class= and key=/u,
  ],
  [
    "an unknown statement field",
    fixturePlan.replace(
      "module=entitlement class=record key=revision",
      "module=entitlement class=record key=revision phase=guard",
    ),
    /unknown statement field 'phase=guard'/u,
  ],
  [
    "a duplicate guard key",
    insertBefore("key=workspace-revision", lineWith("key=workspace-revision")),
    /duplicate revision key workspace-revision in module entitlement/u,
  ],
  [
    "a read plan",
    fixturePlan.replace("-- access: write", "-- access: read"),
    /a family plan is a write plan/u,
  ],
  [
    "a plan id of the wrong shape",
    fixturePlan.replace("-- plan: families.fixture-pair.commit", "-- plan: families.fixture-pair"),
    /a family plan id is families/u,
  ],
  [
    "a plan of another family",
    fixturePlan.replace("-- plan: families.fixture-pair.commit", "-- plan: families.other.commit"),
    /file name must be <family>\.<name>/u,
  ],
  [
    "a plan for a family that is not in the registry",
    fixturePlan,
    /family fixture-pair is not in storage\/plans\/families\.json/u,
    { schemaVersion: 1, families: [] },
  ],
  [
    "a guard of a module outside the order",
    insertBefore(
      "module=entitlement key=workspace-revision",
      "-- guard: kind=revision module=support key=k table=support_support_case by=case_id rev=rev",
    ),
    /module support has no position in the SU-04 order/u,
  ],
  [
    "a mutation statement of a module outside the order",
    fixturePlan.replace(
      "module=notification class=record key=suppression",
      "module=support class=record key=suppression",
    ),
    /table notification_suppression is not owned by module support|has no position/u,
  ],
  [
    "a plan with no mutation",
    fixturePlan.split("\n-- statement:")[0] ?? "",
    /a family plan has at least one mutation/u,
  ],
  [
    "a plan with no guard",
    planLines.filter((line) => !line.startsWith("-- guard:")).join("\n"),
    /(module \w+ writes without a guard of its own|a family plan has at least one guard)/u,
  ],
  [
    "SQL outside a statement block",
    insertBefore("-- guard: kind=lease", "SELECT 1;"),
    /SQL outside a statement block/u,
  ],
  [
    "a comment directive that is not known",
    insertBefore("-- guard: kind=lease", "-- note: free text"),
    /SQL outside a statement block|unknown comment directive/u,
  ],
];
for (const [name, text, expected, registry] of planRules)
  test(`a family plan rule is enforced: ${name}`, () => {
    assert.throws(() => build(text, registry), expected);
  });

test("a family plan in the owner directories, and an owner plan named families, are refused", () => {
  const root = fixtureRoot();
  mkdirSync(path.join(root, "storage/plans/identity"), { recursive: true });
  writeFileSync(
    path.join(root, "storage/plans/identity/sample.sql"),
    "-- plan: families.fixture-pair.sample\n-- version: 1\n-- access: write\n-- statement: params=text\nUPDATE identity_user SET display_name = ? WHERE 1 = 0;\n",
  );
  assert.throws(
    () => buildManifest(root, { physicalDirectory }),
    /file name must match the plan id|reserved for family plans/u,
  );
  const registry = JSON.parse(
    readFileSync(path.join(repositoryRoot, "storage/plans/owners.json"), "utf8"),
  ) as { owners: unknown[] };
  registry.owners.push({
    owner: "families",
    className: "Families",
    kind: "module",
    tablePrefix: "families_",
  });
  const rootTwo = fixtureRoot();
  writeFileSync(path.join(rootTwo, "storage/plans/owners.json"), JSON.stringify(registry));
  assert.throws(() => buildManifest(rootTwo, { physicalDirectory }), /reserved for family plans/u);
});

// ---------------------------------------------------------------------------------------------------------------------------
// The generated outputs
// ---------------------------------------------------------------------------------------------------------------------------

test("the Worker dictionary keeps the one plan shape and carries no family role; the C# manifest carries roles and the catalog", async () => {
  const manifest = fixtureManifest();
  const worker = await renderTypeScript(manifest);
  assert(worker.includes(fixturePlanId));
  assert(
    !/family|"module"|phase/u.test(worker.slice(worker.indexOf("export const plans"))),
    "no role in the dictionary",
  );
  const csharp = renderCSharp(manifest);
  assert(csharp.includes("internal static class Families"));
  assert(csharp.includes("public static readonly PlanDefinition FixturePairCommit"));
  assert(
    csharp.includes('new("fixture-pair", "Fixture family for the shared-family engine tests"'),
  );
  assert(
    csharp.includes(
      'new(FamilyModule.Entitlement, FamilyPhase.Guard, FamilyClass.Revision, "workspace-revision")',
    ),
  );
  assert(
    csharp.includes(
      'new(FamilyModule.Platform, FamilyPhase.Release, FamilyClass.Release, "release")',
    ),
  );
  assert(csharp.includes("FamilyModule.Notification, true, null"));
  assert(csharp.includes('FamilyModule.Policy, false, "when a source policy applies"'));
  assert(
    csharp.includes("Foundation.Readiness, Families.FixturePairCommit"),
    "the family plan is part of All",
  );
});

test("generation over a root with a family writes both outputs, and a stale output fails the check", async () => {
  const root = fixtureRoot();
  mkdirSync(path.join(root, "worker/storage"), { recursive: true });
  mkdirSync(path.join(root, "src/ArcForges.Cloud.Storage.D1"), { recursive: true });
  cpSync(physicalDirectory, path.join(root, "src/ArcForges.Cloud.Storage.D1/Physical/manifest"), {
    recursive: true,
  });
  const result = await generate(root, false);
  assert.equal(result.plans, 2);
  await generate(root, true);
  const csharp = path.join(root, "src/ArcForges.Cloud.Storage.D1/PlanManifest.g.cs");
  writeFileSync(
    csharp,
    readFileSync(csharp, "utf8").replace("FamilyModule.Notification", "FamilyModule.Sync"),
  );
  await assert.rejects(() => generate(root, true), /stale/u);
  const empty = mkdtempSync(path.join(tmpdir(), "families-empty-"));
  assert(empty.length > 0);
});

test("the repository's checked-in registry and outputs are current", async () => {
  const manifest = buildManifest(repositoryRoot);
  for (const plan of manifest.plans.filter((candidate) => candidate.family !== undefined))
    assert(manifest.families.families.some((family) => family.family === plan.family));
  await generate(repositoryRoot, true);
});

test("the identity formula and the expansion listing are the shared vector", async () => {
  assert.equal(
    familyIdentity(vectors.identity.normalizedText, vectors.identity.statementSql),
    vectors.identity.sha256,
  );
  const manifest = fixtureManifest();
  const listing = JSON.parse(await renderFamilyExpansion(manifest)) as {
    plans: {
      id: string;
      sha256: string;
      family: string;
      statements: { role: string; sql: string; params: string[] }[];
    }[];
  };
  const plan = manifest.plans.find((candidate) => candidate.id === fixturePlanId);
  assert(plan);
  assert.equal(listing.plans.length, 1);
  assert.equal(listing.plans[0]?.sha256, plan.sha256);
  assert.deepEqual(
    listing.plans[0]?.statements.map((statement) => statement.sql),
    plan.statements.map((statement) => statement.sql),
  );
  assert.deepEqual(
    listing.plans[0]?.statements.map((statement) => statement.role),
    vectors.fixturePlan.statements.map((statement) => statement.role),
  );
  // The identity is recomputable from the authored file and the listed SQL alone, as the C# check does.
  assert.equal(
    familyIdentity(
      normalizePlanText(fixturePlan),
      listing.plans[0]?.statements.map((statement) => statement.sql) ?? [],
    ),
    plan.sha256,
  );
});
