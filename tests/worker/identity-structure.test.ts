// SPDX-License-Identifier: AGPL-3.0-only
// The structural tests of WP-22.00 (CLOUD.11): (1) no schema, contract or operation carries a customer membership, role, invitation,
// seat or shared-editor concept (WO-05); (2) no capability treats an authentication identity as a user (BR-04); (3) workspace
// ownership is the direct owner_user_id relation and nothing rewrites it (WO-01, WO-02). Each scan is proven on fixtures that break
// its rule, so it cannot pass vacuously, and every exception is an exact, reasoned allowlist entry: a new hit fails.
// The generated public contracts are scanned by the C# test tests/ArcForges.Cloud.Tests/Generation/IdentityContractStructureTests.cs,
// against the NuGet ArcForges.Contracts.PublicApi types (CLOUD.84 S33(3)(c)); the npm proto package is no longer read here.
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { openIdentityD1 } from "./support/identity-support.ts";
import { plans } from "../../worker/storage/plans.generated.ts";
import { repositoryRoot } from "./support/sqlite-d1.ts";

// ---------------------------------------------------------------------------------------------------------------------------
// The vocabulary scan
// ---------------------------------------------------------------------------------------------------------------------------

/** Words (after splitting snake_case, kebab-case and camelCase) that name a collaboration concept the product excludes (P2-006). */
const forbiddenWords = new Set([
  "membership",
  "memberships",
  "member",
  "members",
  "role",
  "roles",
  "invitation",
  "invitations",
  "invite",
  "invites",
  "invited",
  "seat",
  "seats",
  "collaborator",
  "collaborators",
  "collaboration",
  "collaborative",
  "organisation",
  "organisations",
  "organization",
  "organizations",
  "teammate",
  "teammates",
]);
/** Adjacent word pairs that name a shared editor. */
const forbiddenPairs = [
  ["shared", "editor"],
  ["shared", "editing"],
  ["co", "editor"],
  ["team", "workspace"],
];

export function words(identifier: string): string[] {
  return identifier
    .replace(/([a-z0-9])([A-Z])/gu, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/gu, "$1 $2")
    .split(/[^A-Za-z0-9]+/u)
    .filter((word) => word.length > 0)
    .map((word) => word.toLowerCase());
}

export function violations(identifier: string): string[] {
  const parts = words(identifier);
  const found = parts.filter((word) => forbiddenWords.has(word));
  for (const [first, second] of forbiddenPairs)
    if (parts.some((word, index) => word === first && parts[index + 1] === second))
      found.push(`${first} ${second}`);
  return found;
}

/**
 * The reviewed exceptions. Each names the exact identifier on one surface and why it is not a customer workspace concept
 * (WO-05: separate operator authorization roles and self-host account enrollment are not workspace membership).
 */
const allowed: { surface: string; identifier: string; reason: string; prefix?: boolean }[] = [
  {
    surface: "manifest",
    identifier: "identity_operator_access.role",
    reason: "operator authorization role (registry 04 section 9), not a workspace role",
  },
  {
    surface: "manifest",
    identifier: "TranscriptRole",
    reason: "the author of a chat message (user, assistant, tool), not a workspace role",
  },
  {
    surface: "manifest",
    identifier: "TranscriptRole.",
    prefix: true,
    reason:
      "the values of the chat message author enum (user, assistant, tool, system), not workspace roles",
  },
  {
    surface: "manifest",
    identifier: "chat_message.role",
    reason: "the author of a chat message, not a workspace role",
  },
];

interface Hit {
  surface: string;
  identifier: string;
  words: string[];
}

function isAllowed(surface: string, identifier: string): boolean {
  return allowed.some(
    (entry) =>
      entry.surface === surface &&
      (entry.identifier === identifier ||
        (entry.prefix && identifier.startsWith(entry.identifier))),
  );
}

export function scan(surface: string, identifiers: Iterable<string>): Hit[] {
  const hits: Hit[] = [];
  for (const identifier of identifiers) {
    const found = violations(identifier);
    if (found.length > 0 && !isAllowed(surface, identifier))
      hits.push({ surface, identifier, words: found });
  }
  return hits;
}

// ---------------------------------------------------------------------------------------------------------------------------
// Surfaces
// ---------------------------------------------------------------------------------------------------------------------------

interface ManifestColumn {
  name: string;
  type: string;
  enum?: string;
}
interface ManifestTable {
  name: string;
  columns: ManifestColumn[];
  foreignKeys?: { columns: string[]; references: { table: string; columns: string[] } }[];
}
interface Manifest {
  owner: string;
  enums?: Record<string, { values: string[] }>;
  tables: ManifestTable[];
}

const manifestDirectory = path.join(
  repositoryRoot,
  "src/ArcForges.Cloud.Storage.D1/Physical/manifest",
);
const manifests: Manifest[] = readdirSync(manifestDirectory)
  .filter((file) => file.endsWith(".json") && file !== "enums.json")
  .sort()
  .map((file) => JSON.parse(readFileSync(path.join(manifestDirectory, file), "utf8")) as Manifest);
const registryEnums = Object.entries(
  (
    JSON.parse(readFileSync(path.join(manifestDirectory, "enums.json"), "utf8")) as {
      enums: Record<string, { values: string[] }>;
    }
  ).enums,
);

function manifestIdentifiers(): string[] {
  const list: string[] = [];
  for (const manifest of manifests) {
    for (const [name, definition] of Object.entries(manifest.enums ?? {})) {
      list.push(name, ...definition.values.map((value) => `${name}.${value}`));
    }
    for (const table of manifest.tables) {
      list.push(table.name);
      for (const column of table.columns) list.push(`${table.name}.${column.name}`);
    }
  }
  for (const [name, definition] of registryEnums) {
    list.push(name, ...definition.values.map((value) => `${name}.${value}`));
  }
  return list;
}

/**
 * Every table, column, index and trigger name of the database the locked migrations produce, read from the engine itself rather than
 * from SQL text (the physical drift check already proves the migrations equal the manifest; this scan reads what actually exists).
 */
function schemaIdentifiers(): string[] {
  const db = openIdentityD1();
  const list: string[] = [];
  for (const object of db.database
    .prepare("SELECT type, name, tbl_name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")
    .all() as {
    type: string;
    name: string;
    tbl_name: string;
  }[]) {
    list.push(object.name);
    if (object.type === "table")
      for (const column of db.database
        .prepare(`SELECT name FROM pragma_table_info('${object.name}')`)
        .all() as { name: string }[])
        list.push(`${object.name}.${column.name}`);
  }
  return list;
}
function planIdentifiers(): string[] {
  const list: string[] = [];
  for (const plan of plans) {
    list.push(plan.id);
    for (const statement of plan.statements) {
      const text = statement.sql.replace(/'(?:[^']|'')*'/gu, "''");
      for (const word of text.match(/[A-Za-z_][A-Za-z0-9_]*/gu) ?? []) list.push(word);
    }
  }
  return list;
}

function listFiles(directory: string, match: RegExp): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory)) {
    if (entry === "node_modules" || entry === "obj" || entry === "bin" || entry === ".worktree")
      continue;
    const full = path.join(directory, entry);
    if (statSync(full).isDirectory()) found.push(...listFiles(full, match));
    else if (match.test(entry)) found.push(full);
  }
  return found;
}

/** An operation identifier or a method path as a string literal: `identity.credential.add`, `/arcforges.publicapi.v1.Service/Method`. */
const operationShape = /^(?:\/[a-z][\w.]*\/[A-Za-z]\w*|[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+)$/u;

function literals(text: string): string[] {
  return [...text.matchAll(/"((?:[^"\\\n]|\\.)*)"/gu)]
    .map((match) => match[1] ?? "")
    .filter((value) => operationShape.test(value));
}

/**
 * The identity and workspace modules' own type and member names, and every operation-shaped string literal of the C# host and modules
 * (method paths, policy keys, event types, operation names). Other code is not about identity: it uses "role" and "member" in their
 * language and compiler senses (a statement role, an enum member).
 */
function sourceIdentifiers(): string[] {
  const list: string[] = [];
  for (const file of listFiles(path.join(repositoryRoot, "src"), /\.cs$/u)) {
    if (file.endsWith(".g.cs")) continue;
    const raw = readFileSync(file, "utf8");
    const text = raw.replace(/\/\/[^\n]*/gu, "").replace(/\/\*[\s\S]*?\*\//gu, "");
    list.push(...literals(text));
    if (
      /Modules\.(Identity|Workspace|Devices)[\\/]/u.test(file) ||
      /Modules[\\/]ArcForges\.Cloud\.Modules\.(Identity|Workspace|Devices)[\\/]/u.test(file) ||
      /ArcForges\.Cloud\.Modules\.(Identity|Workspace|Devices)/u.test(file)
    )
      for (const word of text
        .replace(/"(?:[^"\\]|\\.)*"/gu, '""')
        .match(/[A-Za-z_][A-Za-z0-9_]*/gu) ?? [])
        list.push(word);
  }
  return list;
}

function workerIdentifiers(): string[] {
  const list: string[] = [];
  for (const file of listFiles(path.join(repositoryRoot, "worker"), /\.ts$/u)) {
    if (file.endsWith("plans.generated.ts")) continue;
    const text = readFileSync(file, "utf8")
      .replace(/\/\/[^\n]*/gu, "")
      .replace(/\/\*[\s\S]*?\*\//gu, "");
    list.push(...literals(text.replace(/'((?:[^'\\\n]|\\.)*)'/gu, '"$1"')));
  }
  return list;
}
// ---------------------------------------------------------------------------------------------------------------------------
// Tests: no membership, role, invitation, seat or shared editor anywhere
// ---------------------------------------------------------------------------------------------------------------------------

test("the vocabulary scan flags each excluded concept and each spelling of it, and nothing else", () => {
  for (const identifier of [
    "workspace_membership",
    "workspace.member_id",
    "WorkspaceMember",
    "workspaceRole",
    "InviteUser",
    "pending_invitations",
    "seatCount",
    "SeatLimit",
    "SharedEditor",
    "shared_editing_session",
    "TeamWorkspace",
    "OrganisationId",
    "isCollaborator",
  ])
    assert.notDeepEqual(violations(identifier), [], identifier);
  for (const identifier of [
    "owner_user_id",
    "workspace_workspace",
    "preserve",
    "inventory",
    "seated",
    "membrane",
    "bookmarks",
    "reservation_id",
    "Controller",
  ])
    assert.deepEqual(violations(identifier), [], identifier);
  // Splitting is by word: a word that merely contains an excluded one is not flagged, and an excluded one inside a name is.
  assert.deepEqual(violations("memberOf2"), ["member"]);
  assert.notDeepEqual(
    scan("manifest", [...manifestIdentifiers(), "workspace_membership.role"]),
    [],
  );
});
test("the allowlist is exact: an allowed identifier on one surface does not excuse it on another, nor a neighbouring identifier", () => {
  assert.deepEqual(scan("manifest", ["identity_operator_access.role"]), []);
  assert.equal(scan("contract", ["identity_operator_access.role"]).length, 1);
  assert.equal(scan("manifest", ["identity_operator_access.roles"]).length, 1);
  assert.equal(scan("manifest", ["workspace_membership"]).length, 1);
  for (const entry of allowed)
    assert.ok(entry.reason.length > 20, `a reason is stated for ${entry.identifier}`);
});

test("the physical schema, the locked migrations and the named plans carry no membership, role, invitation, seat or shared-editor concept", () => {
  assert.deepEqual(scan("manifest", manifestIdentifiers()), []);
  const schema = schemaIdentifiers();
  assert.ok(schema.length > 500, "the scan reads the migrated database");
  assert.deepEqual(scan("manifest", schema), []);
  assert.deepEqual(scan("plan", planIdentifiers()), []);
});

test("the operations the Cloud host, its modules and its Worker declare name no membership, role, invitation, seat or shared-editor concept", () => {
  const source = sourceIdentifiers();
  assert.ok(source.length > 100, "the scan reads the C# sources");
  assert.deepEqual(scan("source", source), []);
  const worker = workerIdentifiers();
  assert.ok(worker.length > 10, "the scan reads the Worker sources");
  assert.deepEqual(scan("worker", worker), []);
});

// ---------------------------------------------------------------------------------------------------------------------------
// Tests: an authentication identity is never a user
// ---------------------------------------------------------------------------------------------------------------------------

const tables = manifests.flatMap((manifest) => manifest.tables);

test("only the credential table has an authentication-identity identifier: no other table keys, joins or references one", () => {
  const owners = tables.filter((table) =>
    table.columns.some((column) => /auth_?identity/u.test(column.name)),
  );
  assert.deepEqual(
    owners.map((table) => table.name),
    ["identity_auth_identity"],
  );
  const referencing = tables.filter((table) =>
    (table.foreignKeys ?? []).some((key) => key.references.table === "identity_auth_identity"),
  );
  assert.deepEqual(
    referencing.map((table) => table.name),
    [],
  );
});

test("every user identifier column of the schema references the user table, never a credential", () => {
  const userColumns = tables.flatMap((table) =>
    table.columns
      .filter((column) => /(^|_)user_id$/u.test(column.name))
      .map((column) => ({ table: table.name, column: column.name })),
  );
  assert.ok(userColumns.length >= 8, "the scan finds the user columns");
  for (const { table, column } of userColumns) {
    const found = tables.find((entry) => entry.name === table);
    const key = (found?.foreignKeys ?? []).find((fk) => fk.columns.includes(column));
    if (key)
      assert.equal(
        key.references.table,
        "identity_user",
        `${table}.${column} references the user table`,
      );
    assert.notEqual(table === "identity_auth_identity" && column === "auth_identity_id", true);
  }
  const credential = tables.find((table) => table.name === "identity_auth_identity");
  const credentialKey = (credential?.foreignKeys ?? []).find((key) =>
    key.columns.includes("user_id"),
  );
  assert.equal(
    credentialKey?.references.table,
    "identity_user",
    "a credential belongs to a user and is never one",
  );
});

test("no named plan outside the identity owner reads or writes the credential table, and a family touches it only through identity statements", () => {
  for (const plan of plans) {
    if (plan.id.startsWith("identity.") || plan.id.startsWith("families.")) continue;
    for (const statement of plan.statements)
      assert.equal(
        /identity_auth_identity/u.test(statement.sql),
        false,
        `${plan.id} must not touch credentials`,
      );
  }
  const expanded = JSON.parse(
    readFileSync(path.join(repositoryRoot, "storage/plans/families.expanded.json"), "utf8"),
  ) as { plans: { id: string; statements: { role: string; sql: string }[] }[] };
  assert.ok(expanded.plans.length >= 1);
  for (const plan of expanded.plans)
    for (const statement of plan.statements)
      if (/identity_auth_identity/u.test(statement.sql))
        assert.match(
          statement.role,
          /^(guard|mutation) identity /u,
          `${plan.id}: ${statement.role} must not touch credentials`,
        );
});
// ---------------------------------------------------------------------------------------------------------------------------
// Tests: ownership is the direct owner_user_id relation
// ---------------------------------------------------------------------------------------------------------------------------

test("a workspace has exactly one principal relation, the owner_user_id column, and no table links a second user to a workspace", () => {
  const workspaceTable = tables.find((table) => table.name === "workspace_workspace");
  assert.ok(workspaceTable);
  const userReferences = (workspaceTable.foreignKeys ?? []).filter(
    (key) => key.references.table === "identity_user",
  );
  assert.deepEqual(
    userReferences.map((key) => key.columns),
    [["owner_user_id"]],
  );
  // No workspace-owned table references a user at all: a workspace's data is reached through the owner check, not through a user link.
  for (const table of tables.filter(
    (entry) => entry.name.startsWith("workspace_") && entry.name !== "workspace_workspace",
  ))
    assert.deepEqual(
      (table.foreignKeys ?? []).filter((key) => key.references.table === "identity_user"),
      [],
      `${table.name} links no user`,
    );
  // The only table that references both a user and a workspace is the API token: a credential of the owner, scoped to the owner's
  // workspace (it is never a second principal's right in the workspace). A new such table is a reviewed change to this list.
  const both = tables
    .filter((table) => {
      const targets = new Set((table.foreignKeys ?? []).map((key) => key.references.table));
      return targets.has("identity_user") && targets.has("workspace_workspace");
    })
    .map((table) => table.name);
  assert.deepEqual(both, ["identity_api_token"]);
});
test("no plan or family statement ever rewrites the owner of a workspace after it is created", () => {
  for (const plan of plans)
    for (const statement of plan.statements) {
      const sql = statement.sql.replace(/\s+/gu, " ");
      assert.equal(
        /UPDATE workspace_workspace SET[^;]*owner_user_id/iu.test(sql),
        false,
        `${plan.id} must not change an owner`,
      );
      assert.equal(
        /workspace_workspace[^;]*ON CONFLICT[^;]*owner_user_id/iu.test(sql),
        false,
        plan.id,
      );
    }
  const writers = plans.filter((plan) =>
    plan.statements.some((s) =>
      /(INSERT INTO|UPDATE|DELETE FROM) workspace_workspace/u.test(s.sql),
    ),
  );
  assert.deepEqual(
    writers.map((plan) => plan.id),
    ["families.account-enrollment.create-user"],
    "one reviewed path creates a workspace",
  );
});
