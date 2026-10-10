// SPDX-License-Identifier: AGPL-3.0-only
// TEST SUPPORT ONLY. The C# generator in tools/ArcForges.Cloud.Generation (`plans generate` and `plans check`, run by `npm run
// check:plans`) is authoritative for the reviewed Cloud-owned named D1 plans: it alone writes worker/storage/plans.generated.ts,
// storage/plans/families.expanded.json and src/ArcForges.Cloud.Storage.D1/PlanManifest.g.cs (CLOUD.84 S40(1)). This file keeps the
// parse and validate helpers that the remaining TypeScript tests and the local D1 drivers import. It has no generate, write or
// command-line entry point, and nothing here may decide a production plan. tests/worker/storage-plan-parity.test.ts proves that the
// manifest built here and its hash equal the C# outputs, so the two cannot drift apart.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import type { PlanKind, PlanParam } from "../../worker/storage/plan-types.ts";
import { assertTail, parseTailHeader, reservedTables } from "./commit-tail.ts";
import { loadManifest, planKindOf, type PhysicalSchema } from "./physical-schema.ts";

export interface PlanStatement {
  sql: string;
  params: PlanParam[];
  returns: PlanParam[] | null;
  /** Only in a shared family plan: the role of the statement in the guarded batch (never sent to the Worker). */
  family?: FamilyStatementMeta;
}
export interface PlanDefinition {
  id: string;
  version: number;
  access: "read" | "write";
  maxRows: number;
  statements: PlanStatement[];
  /** The raw `-- tail:` header (CLOUD.04): the commit tail a module write plan declares, or why it has none. */
  tail?: string;
  sha256: string;
  /** Only in a shared family plan: the family it belongs to. */
  family?: string;
}
export interface PlanManifest {
  manifestHash: string;
  plans: PlanDefinition[];
  registry: OwnerRegistry;
  families: FamilyRegistry;
}

export interface PlanOwner {
  owner: string;
  className: string;
  kind: "module" | "platform" | "proof";
  tablePrefix: string;
}
export interface OwnerRegistry {
  owners: PlanOwner[];
}
const ownerPattern = /^[a-z][a-z0-9-]*$/u;
const classPattern = /^[A-Z][A-Za-z0-9]*$/u;
/** The shared infrastructure schema every module plan may write beside its own tables (receipts, outbox, inbox, leases). */
export const sharedPrefix = "platform_";

export function parseOwnerRegistry(text: string): OwnerRegistry {
  const value = JSON.parse(text) as { schemaVersion?: number; owners?: PlanOwner[] };
  assert.equal(value.schemaVersion, 1, "owners.json: schemaVersion");
  assert(Array.isArray(value.owners) && value.owners.length > 0, "owners.json: owners");
  const seen = new Set<string>();
  const classes = new Set<string>();
  const prefixes = new Set<string>();
  for (const entry of value.owners) {
    assert.deepEqual(
      Object.keys(entry).sort(),
      ["className", "kind", "owner", "tablePrefix"],
      `owners.json: fields of ${entry.owner}`,
    );
    assert(ownerPattern.test(entry.owner), `owners.json: invalid owner ${entry.owner}`);
    assert.notEqual(
      entry.owner,
      familyOwner,
      `owners.json: ${familyOwner} is reserved for family plans`,
    );
    assert(
      classPattern.test(entry.className),
      `owners.json: invalid class name ${entry.className}`,
    );
    assert(
      ["module", "platform", "proof"].includes(entry.kind),
      `owners.json: kind of ${entry.owner}`,
    );
    assert(!seen.has(entry.owner), `owners.json: duplicate owner ${entry.owner}`);
    assert(!classes.has(entry.className), `owners.json: duplicate class ${entry.className}`);
    assert(
      !prefixes.has(entry.tablePrefix),
      `owners.json: duplicate table prefix ${entry.tablePrefix}`,
    );
    assert(
      !entry.tablePrefix.startsWith(cteNamePrefix),
      `owners.json: ${entry.owner} prefix collides with CTE names`,
    );
    seen.add(entry.owner);
    classes.add(entry.className);
    prefixes.add(entry.tablePrefix);
    if (entry.kind === "module")
      assert.equal(
        entry.tablePrefix,
        `${entry.owner.replaceAll("-", "_")}_`,
        `owners.json: the table prefix of module ${entry.owner} is its schema`,
      );
    if (entry.kind === "platform")
      assert(
        entry.owner === "platform" && entry.tablePrefix === sharedPrefix,
        "owners.json: platform",
      );
    if (entry.kind === "proof")
      assert.equal(entry.tablePrefix, "probe_", "owners.json: proof prefix");
  }
  // No prefix may be a prefix of another, or one owner's tables would also match the other's rule.
  for (const a of prefixes)
    for (const b of prefixes)
      assert(a === b || !b.startsWith(a), `owners.json: prefix ${a} contains ${b}`);
  assert.equal(
    value.owners.filter((entry) => entry.kind === "platform").length,
    1,
    "owners.json: exactly one platform owner",
  );
  return { owners: value.owners };
}

interface SqlToken {
  kind: "word" | "string" | "number" | "punct";
  /** Words are ASCII-lower-cased (SQLite folds only ASCII); everything else is kept as written. */
  value: string;
}
const isWordStart = (code: number) =>
  (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95 || code >= 128;
const isWordPart = (code: number) => isWordStart(code) || (code >= 48 && code <= 57) || code === 36;
const isDigit = (code: number) => code >= 48 && code <= 57;
const asciiLower = (text: string) => text.replaceAll(/[A-Z]+/gu, (match) => match.toLowerCase());

/**
 * Splits one SQL statement the way SQLite does for the constructs this check cares about: comments are
 * whitespace, string literals are single tokens, and every character at or above U+0080 belongs to a word.
 * Double-quoted, backtick and bracket identifiers are refused outright because they would name a table
 * without being a word; an unterminated literal or comment is refused too.
 */
export function tokenizeSql(sql: string, where: string): SqlToken[] {
  const tokens: SqlToken[] = [];
  let index = 0;
  while (index < sql.length) {
    const code = sql.charCodeAt(index);
    const char = sql.charAt(index);
    if (char === " " || char === "\t" || char === "\n" || char === "\r" || char === "\f") {
      index++;
    } else if (char === "-" && sql.charAt(index + 1) === "-") {
      const end = sql.indexOf("\n", index);
      index = end < 0 ? sql.length : end + 1;
    } else if (char === "/" && sql.charAt(index + 1) === "*") {
      const end = sql.indexOf("*/", index + 2);
      assert(end >= 0, `${where}: unterminated comment`);
      index = end + 2;
    } else if (char === "'") {
      let end = index + 1;
      for (;;) {
        const close = sql.indexOf("'", end);
        assert(close >= 0, `${where}: unterminated string literal`);
        if (sql.charAt(close + 1) === "'") end = close + 2;
        else {
          end = close + 1;
          break;
        }
      }
      tokens.push({ kind: "string", value: sql.slice(index, end) });
      index = end;
    } else if (char === '"' || char === "`" || char === "[" || char === "]") {
      assert.fail(`${where}: quoted identifiers are not allowed`);
    } else if (isWordStart(code)) {
      let end = index + 1;
      while (end < sql.length && isWordPart(sql.charCodeAt(end))) end++;
      tokens.push({ kind: "word", value: asciiLower(sql.slice(index, end)) });
      index = end;
    } else if (isDigit(code) || (char === "." && isDigit(sql.charCodeAt(index + 1)))) {
      let end = index + 1;
      while (end < sql.length && (isWordPart(sql.charCodeAt(end)) || sql.charAt(end) === "."))
        end++;
      tokens.push({ kind: "number", value: sql.slice(index, end) });
      index = end;
    } else {
      tokens.push({ kind: "punct", value: char });
      index++;
    }
  }
  return tokens;
}

// A FROM clause (and so a comma join) ends at one of these at the same nesting depth. Only words that SQLite reserves
// belong here: a word that SQLite also accepts as an alias or a column name (for example DO, CONFLICT, WINDOW, KEY,
// REPLACE, FILTER, OVER) would let a plan reset the comma-join guard by naming a table or column with it. The test
// storage-plan-ownership.test.ts proves with SQLite that none of these can be used as an alias or a column.
// Consequence, deliberate: after a FROM clause at the same depth a comma is refused until one of these appears, so an
// INSERT ... SELECT ... FROM ... ON CONFLICT ... DO UPDATE SET a = ?, b = ? is refused; use VALUES, or one assignment.
export const fromEnders = new Set([
  "where",
  "group",
  "order",
  "limit",
  "having",
  "union",
  "intersect",
  "except",
  "returning",
  "set",
]);
const notATable = new Set(["select", "with", "values", "where", "set", "on", "using"]);
/** CTE names must start with this, and no owner prefix may: a CTE can never shadow a physical table. */
export const cteNamePrefix = "cte_";

/** Index just past the parenthesised group that starts at `open`, or -1 when it is not closed. */
function skipGroup(tokens: SqlToken[], open: number) {
  let depth = 0;
  for (let index = open; index < tokens.length; index++) {
    if (tokens[index]?.value === "(" && tokens[index]?.kind === "punct") depth++;
    if (tokens[index]?.value === ")" && tokens[index]?.kind === "punct") depth--;
    if (depth === 0) return index + 1;
  }
  return -1;
}
const isPunct = (token: SqlToken | undefined, value: string) =>
  token?.kind === "punct" && token.value === value;

/** The CTE names a statement defines, each strictly in the form `WITH [RECURSIVE] name [(columns)] AS [[NOT] MATERIALIZED] (...)`. */
function definedCtes(tokens: SqlToken[], where: string) {
  const names = new Set<string>();
  tokens.forEach((token, start) => {
    if (token.kind !== "word" || token.value !== "with") return;
    let index = start + 1;
    if (tokens[index]?.value === "recursive") index++;
    for (;;) {
      const name = tokens[index];
      assert(
        name?.kind === "word" && name.value.startsWith(cteNamePrefix),
        `${where}: a CTE name starts with ${cteNamePrefix}`,
      );
      names.add(name.value);
      index++;
      if (isPunct(tokens[index], "(")) {
        index = skipGroup(tokens, index);
        assert(index > 0, `${where}: unbalanced CTE column list`);
      }
      assert(tokens[index]?.value === "as", `${where}: a CTE is defined with AS`);
      index++;
      if (tokens[index]?.value === "not") index++;
      if (tokens[index]?.value === "materialized") index++;
      assert(isPunct(tokens[index], "("), `${where}: a CTE body is parenthesised`);
      index = skipGroup(tokens, index);
      assert(index > 0, `${where}: unbalanced CTE body`);
      if (!isPunct(tokens[index], ",")) break;
      index++;
    }
  });
  return names;
}

/**
 * Every physical table a plan statement names. This is a closed grammar and fails closed: after FROM, JOIN, INTO and
 * UPDATE the next tokens must be one of
 *   - a bare word that is a table (a word that names a CTE of this statement is not a table),
 *   - for FROM and JOIN only, a table-valued function from an allow-list followed by `(`,
 *   - for FROM and JOIN only, `(` directly followed by SELECT, WITH or VALUES (a subquery, scanned like any other text),
 * and anything else (a string, a parenthesised table, a schema-qualified name, a number, a keyword) is refused. A comma join
 * is refused because the second table would not be in a table position. CTE names are accepted only in the exact form of
 * WITH lists and only with the `cte_` prefix that no owner may have, so a CTE can never stand in for a foreign table.
 */
export function referencedTables(sql: string, where: string): string[] {
  const tokens = tokenizeSql(sql, where);
  const ctes = definedCtes(tokens, where);
  const tables: string[] = [];
  const fromActive: boolean[] = [false];
  let depth = 0;
  for (let index = 0; index < tokens.length; index++) {
    const token = tokens[index];
    if (!token) continue;
    if (token.kind === "punct") {
      if (token.value === "(") fromActive[++depth] = false;
      else if (token.value === ")") {
        assert(depth > 0, `${where}: unbalanced parentheses`);
        fromActive[depth--] = false;
      } else if (token.value === ",")
        assert(!fromActive[depth], `${where}: use JOIN, a comma join would hide a table`);
      continue;
    }
    if (token.kind !== "word") continue;
    if (fromEnders.has(token.value)) fromActive[depth] = false;
    const previous = tokens[index - 1]?.value;
    const keyword = token.value;
    if (keyword === "from" && previous === "distinct") continue;
    if (keyword === "update" && tokens[index + 1]?.value === "set" && previous === "do") continue;
    if (!["from", "join", "into", "update"].includes(keyword)) continue;
    let at = index + 1;
    if (keyword === "update" && tokens[at]?.value === "or") at += 2;
    const target = tokens[at];
    const following = tokens[at + 1];
    const queryClause = keyword === "from" || keyword === "join";
    if (keyword === "from") fromActive[depth] = true;
    if (isPunct(target, "(")) {
      const inner = tokens[at + 1];
      assert(
        queryClause && inner?.kind === "word" && ["select", "with", "values"].includes(inner.value),
        `${where}: a parenthesised table is not allowed`,
      );
      continue;
    }
    assert(
      target?.kind === "word" && !notATable.has(target.value),
      `${where}: a table position after ${keyword} holds something that is not a plain table name`,
    );
    assert(
      !isPunct(following, "."),
      `${where}: a schema-qualified name is not allowed (${target.value})`,
    );
    if (isPunct(following, "(") && queryClause) {
      assert(
        tableFunctions.has(target.value),
        `${where}: unknown table-valued function ${target.value}`,
      );
      continue;
    }
    assert(
      !(isPunct(following, "(") && keyword === "update"),
      `${where}: a table name after update is not followed by a list`,
    );
    if (ctes.has(target.value)) {
      assert(queryClause, `${where}: a CTE is not a write target (${target.value})`);
      continue;
    }
    if (!tables.includes(target.value)) tables.push(target.value);
  }
  assert.equal(depth, 0, `${where}: unbalanced parentheses`);
  return tables;
}
/** A plan of `owner` may touch only its own tables, and the shared platform tables unless it is a proof owner. */
export function assertOwnership(plan: PlanDefinition, registry: OwnerRegistry) {
  const owner = plan.id.split(".")[0] ?? "";
  const entry = registry.owners.find((candidate) => candidate.owner === owner);
  assert(entry, `${plan.id}: owner ${owner} is not in ${ownerRegistry}`);
  const allowed = entry.kind === "module" ? [entry.tablePrefix, sharedPrefix] : [entry.tablePrefix];
  plan.statements.forEach((statement, index) => {
    const where = `${plan.id} statement ${index + 1}`;
    for (const table of referencedTables(statement.sql, where))
      assert(
        allowed.some((prefix) => table.startsWith(prefix)),
        `${where}: table ${table} is not owned by ${owner} (allowed prefixes: ${allowed.join(", ")})`,
      );
  });
}

/**
 * Every write plan of a module declares its commit tail (`-- tail: v1 [events=N] [inbox]`) or why it has none
 * (`-- tail: none <reason>`); a declared tail is verified statement by statement (commit-tail.ts). Read plans and
 * the platform and proof owners declare nothing unless they use the tail.
 */
export function assertCommitTail(plan: PlanDefinition, registry: OwnerRegistry) {
  const owner = registry.owners.find((entry) => entry.owner === plan.id.split(".")[0]);
  const where = `${plan.id}: -- tail`;
  let range: { ownerStart: number; ownerEnd: number } | undefined;
  if (plan.tail === undefined) {
    assert(
      !(owner?.kind === "module" && plan.access === "write"),
      `${plan.id}: a module write plan declares its commit tail ('-- tail: v1 events=N [inbox]') or '-- tail: none <reason>'`,
    );
  } else {
    assert(plan.access === "write", `${where}: only a write plan declares a tail`);
    range = assertTail(plan, parseTailHeader(plan.tail, where));
  }
  // Whatever the header says, no module plan writes a table that only the commit tail (or the platform owner) may write. The
  // targets come from the generator's own tokenizer, so a CTE-led statement, INSERT OR REPLACE, an upsert or a nested statement is seen.
  if (owner?.kind === "module" && plan.access === "write") {
    const from = range?.ownerStart ?? 0;
    const to = range?.ownerEnd ?? plan.statements.length;
    plan.statements.slice(from, to).forEach((statement, index) => {
      for (const target of writeTargets(statement.sql, `${plan.id} statement ${from + index + 1}`))
        assert(
          !reservedTables.includes(target),
          `${plan.id}: statement ${from + index + 1} writes ${target}, which only the commit tail may write`,
        );
    });
  }
}

/** Every table a statement inserts into, updates or deletes from, wherever it stands in the statement (CTEs, subqueries, upserts included). */
export function writeTargets(sql: string, where: string): string[] {
  const tokens = tokenizeSql(sql, where);
  const targets = new Set<string>();
  tokens.forEach((token, index) => {
    if (token.kind !== "word") return;
    const previous = tokens[index - 1]?.value;
    let at = index + 1;
    if (token.value === "into") {
      // INSERT INTO t, REPLACE INTO t, INSERT OR IGNORE INTO t
    } else if (token.value === "update") {
      if (previous === "do") return; // ON CONFLICT DO UPDATE SET
      if (tokens[at]?.value === "or") at += 2;
    } else if (token.value === "delete" && tokens[at]?.value === "from") at++;
    else return;
    const target = tokens[at];
    if (target?.kind === "word") targets.add(target.value);
  });
  return [...targets];
}

const kinds: readonly PlanKind[] = ["int64", "uint64", "decimal", "text", "bytes", "bool", "scope"];
const maxStatements = 100;
const maxParameters = 100;
const planIdPattern = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$/u;
const forbiddenSql =
  /\b(?:pragma|attach|detach|drop|alter|create|vacuum|reindex|returning|load_extension|replace\s+into)\b|\bsqlite_/iu;
export const planDirectory = "storage/plans";
export const ownerRegistry = "storage/plans/owners.json";
/** The expanded statements of every family plan, generated for review and for the independent C# identity check. */
const familyExpansionName = "families.expanded.json";
// SQLite table-valued functions a plan may read from; every other FROM or JOIN target is a physical table.
const tableFunctions = new Set(["json_each", "json_tree"]);

export function sha256Hex(text: string | Uint8Array) {
  return createHash("sha256").update(text).digest("hex");
}
export function normalizePlanText(text: string) {
  return `${text.replaceAll("\r\n", "\n").trimEnd()}\n`;
}
// ---------------------------------------------------------------------------------------------------------------
// Shared family plans (Design D1 profile section 4, "Shared family plans and the guard table")
// ---------------------------------------------------------------------------------------------------------------
// A shared unit of work is one named plan whose statements belong to several module owners (Design SU-01 to SU-07).
// The ownership rule above stays in force for every owner plan; a family plan is checked statement by statement
// instead: each statement names the one module that owns every table it names, the guards come first, then the
// mutations, in the fixed SU-04 module order, and the guard statements are generated from five primitives so that
// the predicate of a guard is written once, expanded against the physical manifest and proven once.

/** The reserved directory beside the owner directories: a family plan belongs to no single owner. */
export const familyOwner = "families";
export const familyRegistryFile = "storage/plans/families.json";
export const familyDirectory = `${planDirectory}/${familyOwner}`;
/** The table whose CHECK rolls a guarded batch back (Design model 01 platform.command_guard). */
export const guardTable = "platform_command_guard";
/** Receipts, outbox rows and leases: shared infrastructure, outside the SU-04 order. */
export const platformModule = "platform";
/** Design SU-04: the fixed order in which the modules of one guarded batch contribute their statements. */
export const lockOrder = [
  "config",
  "identity",
  "workspace",
  "device",
  "entitlement",
  "commerce",
  "policy",
  "agent",
  "chat",
  "scope",
  "task",
  "search",
  "package-catalog",
  "notification",
  "resource",
  "sync",
  "audit",
] as const;
/** Guard classes in their order within one module. */
export const guardKinds = ["authorization", "revision", "policy", "balance", "lease"] as const;
export type GuardKind = (typeof guardKinds)[number];
/** Mutation classes in their order within one module: quota buckets before reservations (SU-04). */
export const mutationClasses = ["bucket", "reservation", "record"] as const;
export type FamilyPhase = "guard" | "mutation" | "release";
export interface FamilyStatementMeta {
  module: string;
  phase: FamilyPhase;
  class: string;
  key: string;
}
export interface FamilyParticipant {
  module: string;
  requirement: "required" | "conditional";
  /** The stated condition of a conditional participant; null for a required one. */
  when: string | null;
}
export interface FamilyDefinition {
  family: string;
  title: string;
  /** The Design rule or table row that lists the family (SU-01). */
  source: string;
  participants: FamilyParticipant[];
}
export interface FamilyRegistry {
  families: FamilyDefinition[];
}
export interface FamilyParseContext {
  registry: FamilyRegistry;
  schema: () => PhysicalSchema;
}

const familyPattern = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u;
const stableKeyPattern = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u;
/** Tables only the migration runner writes; a family plan never names them. */
const bookkeepingTables = new Set([
  "platform_schema_state",
  "platform_migration_receipt",
  "platform_backfill_checkpoint",
]);
/** SQLite reserved words: a column with one of these names cannot be written without quoting, and plans never quote. */
const reservedWords = new Set(
  "add all alter and as autoincrement between case check collate commit constraint create default deferrable delete distinct drop else escape except exists foreign from group having in index insert intersect into is isnull join limit not notnull null on or order primary references select set table then to transaction union unique update using values when where".split(
    " ",
  ),
);

export const modulePrefix = (module: string) =>
  module === platformModule ? sharedPrefix : `${module.replaceAll("-", "_")}_`;

export function parseFamilyRegistry(text: string): FamilyRegistry {
  const value = JSON.parse(text) as { schemaVersion?: number; families?: unknown };
  assert.equal(value.schemaVersion, 1, `${familyRegistryFile}: schemaVersion`);
  assert(Array.isArray(value.families), `${familyRegistryFile}: families`);
  const seen = new Set<string>();
  const families: FamilyDefinition[] = [];
  for (const entry of value.families as Record<string, unknown>[]) {
    assert.deepEqual(
      Object.keys(entry).sort(),
      ["family", "participants", "source", "title"],
      `${familyRegistryFile}: fields of ${String(entry.family)}`,
    );
    const family = String(entry.family);
    assert(familyPattern.test(family), `${familyRegistryFile}: invalid family id ${family}`);
    assert(!seen.has(family), `${familyRegistryFile}: duplicate family ${family}`);
    seen.add(family);
    for (const field of ["title", "source"] as const) {
      const text = entry[field];
      assert(
        typeof text === "string" && text.length >= 1 && text.length <= 300,
        `${familyRegistryFile}: ${family} ${field}`,
      );
    }
    assert(Array.isArray(entry.participants), `${familyRegistryFile}: participants of ${family}`);
    const participants: FamilyParticipant[] = [];
    for (const raw of entry.participants as Record<string, unknown>[]) {
      const module = String(raw.module);
      assert(
        (lockOrder as readonly string[]).includes(module),
        `${familyRegistryFile}: ${family}: module ${module} has no position in the SU-04 order; the Architecture Owner must extend the order before it may participate`,
      );
      assert(
        !participants.some((participant) => participant.module === module),
        `${familyRegistryFile}: ${family}: duplicate participant ${module}`,
      );
      const requirement = raw.requirement;
      assert(
        requirement === "required" || requirement === "conditional",
        `${familyRegistryFile}: ${family}: requirement of ${module}`,
      );
      const when = raw.when;
      if (requirement === "conditional")
        assert(
          typeof when === "string" && when.length >= 1 && when.length <= 200,
          `${familyRegistryFile}: ${family}: a conditional participant states when (${module})`,
        );
      else
        assert(
          when === undefined,
          `${familyRegistryFile}: ${family}: ${module} is required, so it has no condition`,
        );
      assert.deepEqual(
        Object.keys(raw)
          .filter((field) => field !== "when")
          .sort(),
        ["module", "requirement"],
        `${familyRegistryFile}: ${family}: fields of participant ${module}`,
      );
      participants.push({
        module,
        requirement,
        when: typeof when === "string" ? when : null,
      });
    }
    assert(
      participants.length >= 2,
      `${familyRegistryFile}: ${family} needs at least two participants`,
    );
    assert(
      participants.some((participant) => participant.requirement === "required"),
      `${familyRegistryFile}: ${family} needs a required participant`,
    );
    families.push({
      family,
      title: String(entry.title),
      source: String(entry.source),
      participants,
    });
  }
  return { families };
}

const phaseRank: Record<FamilyPhase, number> = { guard: 0, mutation: 1, release: 2 };
function moduleRank(meta: FamilyStatementMeta) {
  if (meta.module === platformModule) return meta.phase === "guard" ? -1 : lockOrder.length;
  return (lockOrder as readonly string[]).indexOf(meta.module);
}
function classRank(meta: FamilyStatementMeta) {
  if (meta.phase === "guard") return (guardKinds as readonly string[]).indexOf(meta.class);
  if (meta.phase === "mutation") return (mutationClasses as readonly string[]).indexOf(meta.class);
  return meta.class === "release" ? 0 : -1;
}
const ordinal = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

/**
 * Design SU-04 as a rule over the statement roles of one family plan: every guard, then every mutation, then the one
 * release; inside a phase by module in the SU-04 order (`platform` first among guards and last among mutations), then
 * by class, then by stable key ascending, each combination at most once. Returns one message per violation.
 */
export function familyOrderProblems(metas: readonly FamilyStatementMeta[]): string[] {
  const problems: string[] = [];
  metas.forEach((meta, index) => {
    const where = `statement ${index + 1} (${meta.phase} ${meta.module}.${meta.key})`;
    if (meta.module !== platformModule && !(lockOrder as readonly string[]).includes(meta.module))
      problems.push(`${where}: module ${meta.module} has no position in the SU-04 order`);
    if (classRank(meta) < 0)
      problems.push(`${where}: class ${meta.class} does not belong to a ${meta.phase} statement`);
    if (meta.phase === "release" && (index !== metas.length - 1 || meta.module !== platformModule))
      problems.push(`${where}: the release is the one platform statement at the very end`);
    if (index === 0) return;
    const previous = metas[index - 1];
    if (!previous) return;
    if (phaseRank[meta.phase] < phaseRank[previous.phase]) {
      problems.push(
        `${where}: a ${meta.phase} statement may not follow a ${previous.phase} statement (guards, then mutations, then the release)`,
      );
      return;
    }
    if (meta.phase !== previous.phase) return;
    if (moduleRank(meta) < moduleRank(previous))
      problems.push(
        `${where}: module ${meta.module} may not follow module ${previous.module} (SU-04 order)`,
      );
    else if (moduleRank(meta) === moduleRank(previous)) {
      if (classRank(meta) < classRank(previous))
        problems.push(
          `${where}: class ${meta.class} may not follow class ${previous.class} within module ${meta.module}`,
        );
      else if (classRank(meta) === classRank(previous)) {
        const order = ordinal(meta.key, previous.key);
        if (order < 0)
          problems.push(
            `${where}: stable key ${meta.key} may not follow ${previous.key} (ascending within a class)`,
          );
        else if (order === 0)
          problems.push(
            `${where}: duplicate ${meta.class} key ${meta.key} in module ${meta.module}`,
          );
      }
    }
  });
  return problems;
}

type Fields = Map<string, string>;
function parseFields(header: string, allowed: readonly string[], where: string): Fields {
  const fields: Fields = new Map();
  for (const part of header.split(/\s+/u).filter(Boolean)) {
    const pair = /^([a-z]+)=(.*)$/u.exec(part);
    assert(pair && allowed.includes(pair[1] ?? ""), `${where}: unknown field '${part}'`);
    assert(!fields.has(pair[1] ?? ""), `${where}: duplicate ${pair[1]}`);
    fields.set(pair[1] ?? "", pair[2] ?? "");
  }
  return fields;
}
const guardFieldsOf: Record<GuardKind, readonly string[]> = {
  authorization: ["match", "fresh"],
  policy: ["match", "fresh"],
  revision: ["rev"],
  balance: ["rev", "exact"],
  lease: ["holder", "fence", "until"],
};

/**
 * Expands one `-- guard:` directive into the statement it stands for. The five primitives (Design model 04 section 4):
 * `authorization` and `policy` (a row found by its key columns whose named columns equal what the caller decided on,
 * optionally not past an expiry), `revision` (the row's revision equals the revision the caller read; absent equals zero),
 * `balance` (that revision and the captured exact balance columns equal what the checked C# arithmetic used) and `lease`
 * (holder, fence and an unexpired lease equal the caller's). Every column is read from the physical manifest, so a column
 * that does not exist, a JSON column or a column whose name SQLite reserves is refused.
 */
export function expandGuard(
  header: string,
  schema: PhysicalSchema,
  where: string,
): { sql: string; params: PlanParam[]; meta: FamilyStatementMeta } {
  const kindText = /(?:^|\s)kind=(\S+)/u.exec(header)?.[1] ?? "";
  assert(
    (guardKinds as readonly string[]).includes(kindText),
    `${where}: guard kind must be one of ${guardKinds.join(", ")}`,
  );
  const kind = kindText as GuardKind;
  const fields = parseFields(
    header,
    ["kind", "module", "key", "table", "by", ...guardFieldsOf[kind]],
    where,
  );
  const need = (name: string) => {
    const value = fields.get(name);
    assert(value !== undefined && value !== "", `${where}: a ${kind} guard needs ${name}=`);
    return value;
  };
  const module = need("module");
  assert(
    module === platformModule || (lockOrder as readonly string[]).includes(module),
    `${where}: module ${module} has no position in the SU-04 order`,
  );
  const key = need("key");
  assert(
    stableKeyPattern.test(key),
    `${where}: the stable key is lower-case words joined by hyphens`,
  );
  assert(`${module}.${key}`.length <= 128, `${where}: the guard key is at most 128 characters`);
  const tableName = need("table");
  const table = schema.tables.find((candidate) => candidate.name === tableName);
  assert(table, `${where}: ${tableName} is not a table of the physical manifest`);
  const column = (name: string, what: string, kinds?: readonly string[]) => {
    const found = table.columns.find((candidate) => candidate.name === name);
    assert(found, `${where}: ${what} ${name} is not a column of ${tableName}`);
    assert(
      !reservedWords.has(name),
      `${where}: column ${name} is a reserved SQL word, plans never quote a name`,
    );
    assert(
      found.kind !== "json" && found.kind !== "proto",
      `${where}: ${what} ${name} is a ${found.kind} column`,
    );
    if (kinds)
      assert(
        kinds.includes(found.kind),
        `${where}: ${what} ${name} must be ${kinds.join(" or ")}, not ${found.kind}`,
      );
    return found;
  };
  const used = new Set<string>();
  const once = (name: string) => {
    assert(!used.has(name), `${where}: column ${name} is used twice`);
    used.add(name);
  };
  const compare = (name: string, what: string, kinds?: readonly string[]) => {
    const found = column(name, what, kinds);
    once(name);
    const planKind = planKindOf(found.kind);
    return {
      sql: planKind === "int64" ? `${name} = CAST(? AS INTEGER)` : `${name} = ?`,
      param: { kind: planKind, nullable: false } as PlanParam,
    };
  };
  const list = (name: string) =>
    need(name)
      .split(",")
      .map((item) => {
        assert(item !== "", `${where}: empty item in ${name}=`);
        return item;
      });
  const byParts = list("by");
  assert(byParts.length <= 6, `${where}: at most 6 key columns`);
  const conditions: string[] = [];
  const params: PlanParam[] = [{ kind: "text", nullable: false }];
  for (const item of byParts) {
    const scoped = item.startsWith("scope:");
    const name = scoped ? item.slice("scope:".length) : item;
    const part = compare(name, "key column");
    if (scoped) {
      assert(
        part.param.kind === "text",
        `${where}: only a text key column can be the owner scope (${name})`,
      );
      part.param = { kind: "scope", nullable: false };
    }
    conditions.push(part.sql);
    params.push(part.param);
  }
  const byConditions = [...conditions];
  const add = (part: { sql: string; param: PlanParam }) => {
    conditions.push(part.sql);
    params.push(part.param);
  };
  const instant = (name: string, what: string) => {
    const found = column(name, what, ["instant"]);
    once(name);
    return found.name;
  };
  let predicate: string;
  switch (kind) {
    case "authorization":
    case "policy": {
      for (const item of list("match")) add(compare(item, "match column"));
      const fresh = fields.get("fresh");
      if (fresh !== undefined) {
        conditions.push(`${instant(fresh, "fresh column")} > CAST(? AS INTEGER)`);
        params.push({ kind: "int64", nullable: false });
      }
      predicate = `EXISTS (SELECT 1 FROM ${tableName} WHERE ${conditions.join(" AND ")})`;
      break;
    }
    case "revision": {
      const rev = need("rev");
      column(rev, "revision column", ["rev"]);
      once(rev);
      predicate = `COALESCE((SELECT ${rev} FROM ${tableName} WHERE ${byConditions.join(" AND ")}), 0) = CAST(? AS INTEGER)`;
      params.push({ kind: "int64", nullable: false });
      break;
    }
    case "balance": {
      add(compare(need("rev"), "revision column", ["rev"]));
      for (const item of list("exact")) add(compare(item, "exact column"));
      predicate = `EXISTS (SELECT 1 FROM ${tableName} WHERE ${conditions.join(" AND ")})`;
      break;
    }
    case "lease": {
      add(compare(need("holder"), "holder column", ["id", "text", "key"]));
      add(compare(need("fence"), "fence column", ["rev", "int", "int64"]));
      conditions.push(`${instant(need("until"), "expiry column")} > CAST(? AS INTEGER)`);
      params.push({ kind: "int64", nullable: false });
      predicate = `EXISTS (SELECT 1 FROM ${tableName} WHERE ${conditions.join(" AND ")})`;
      break;
    }
  }
  const sql = `INSERT INTO ${guardTable} (command_id, guard_key, allowed)\nSELECT ?, '${module}.${key}', CASE WHEN ${predicate} THEN 1 ELSE 0 END;`;
  return { sql, params, meta: { module, phase: "guard", class: kind, key } };
}

/**
 * The identity of a family plan: the normalized authored text and every expanded statement, in order. A guard is generated from
 * the physical manifest, so the authored text alone cannot identify the SQL the Worker runs; hashing the expansion too makes any
 * change of a column, a type or the expansion rules change the plan hash and with it the manifest identity both sides compare.
 */
export function familyIdentity(normalizedText: string, statementSql: readonly string[]) {
  return sha256Hex(`${normalizedText}\n-- expanded\n${statementSql.join("\n")}\n`);
}

/** The generated last statement of every family plan: no committed state holds a guard row. */
export const releaseStatement: PlanStatement = {
  sql: `DELETE FROM ${guardTable} WHERE command_id = ?;`,
  params: [{ kind: "text", nullable: false }],
  returns: null,
  family: { module: platformModule, phase: "release", class: "release", key: "release" },
};

/** The checks that need the whole plan and the registry; the grammar of single statements is checked while parsing. */
export function assertFamilyPlan(plan: PlanDefinition, registry: FamilyRegistry) {
  const familyId = plan.id.split(".")[1] ?? "";
  const definition = registry.families.find((candidate) => candidate.family === familyId);
  assert(definition, `${plan.id}: family ${familyId} is not in ${familyRegistryFile}`);
  const metas = plan.statements.map((statement) => {
    assert(statement.family, `${plan.id}: a statement has no family role`);
    return statement.family;
  });
  const problems = familyOrderProblems(metas);
  assert.equal(problems.length, 0, `${plan.id}: ${problems.join("; ")}`);
  assert(
    metas.some((meta) => meta.phase === "guard"),
    `${plan.id}: a family plan has at least one guard`,
  );
  assert(
    metas.some((meta) => meta.phase === "mutation"),
    `${plan.id}: a family plan has at least one mutation`,
  );
  const modules = new Set(
    metas.filter((meta) => meta.module !== platformModule).map((meta) => meta.module),
  );
  for (const module of modules)
    assert(
      definition.participants.some((participant) => participant.module === module),
      `${plan.id}: module ${module} is not a participant of family ${familyId} (a participant is added only through the Architecture Owner)`,
    );
  for (const participant of definition.participants)
    if (participant.requirement === "required")
      assert(
        modules.has(participant.module),
        `${plan.id}: required participant ${participant.module} has no statement`,
      );
  for (const module of modules) {
    const own = metas.filter((meta) => meta.module === module);
    if (own.some((meta) => meta.phase === "mutation"))
      assert(
        own.some((meta) => meta.phase === "guard"),
        `${plan.id}: module ${module} writes without a guard of its own (guard every pre-read revision and authorization row, SU-04)`,
      );
  }
  const guardKeys = new Set<string>();
  plan.statements.forEach((statement, index) => {
    const meta = statement.family;
    if (!meta) return;
    const where = `${plan.id} statement ${index + 1} (${meta.module}.${meta.key})`;
    if (meta.phase === "guard") {
      const guardKey = `${meta.module}.${meta.key}`;
      assert(!guardKeys.has(guardKey), `${where}: duplicate guard key`);
      guardKeys.add(guardKey);
    }
    const prefix = modulePrefix(meta.module);
    for (const table of referencedTables(statement.sql, where)) {
      assert(
        table.startsWith(prefix) ||
          (meta.module !== platformModule && table.startsWith(sharedPrefix)),
        `${where}: table ${table} is not owned by module ${meta.module} (allowed prefixes: ${meta.module === platformModule ? sharedPrefix : `${prefix}, ${sharedPrefix}`})`,
      );
      assert(
        !bookkeepingTables.has(table),
        `${where}: ${table} is written only by the migration runner`,
      );
      assert(
        table !== guardTable || meta.phase === "guard" || meta.phase === "release",
        `${where}: only the generated guard and release statements name ${guardTable}`,
      );
    }
  });
}

function parseKinds(list: string, where: string, allowScope: boolean): PlanParam[] {
  if (list === "") return [];
  return list.split(",").map((item) => {
    const nullable = item.endsWith("?");
    const kind = (nullable ? item.slice(0, -1) : item) as PlanKind;
    assert(kinds.includes(kind), `${where}: unknown parameter kind '${item}'`);
    assert(allowScope || kind !== "scope", `${where}: a result column cannot have kind scope`);
    assert(!(nullable && kind === "scope"), `${where}: the owner scope is never null`);
    return { kind, nullable };
  });
}
// Replace string literals so their text cannot contain placeholders or keywords.
function stripLiterals(sql: string) {
  return sql.replaceAll(/'(?:[^']|'')*'/gu, "''");
}
function placeholderCasts(sql: string, where: string): boolean[] {
  const stripped = stripLiterals(sql);
  assert(!/[:@$]\w|\?\d/u.test(stripped), `${where}: only anonymous ? placeholders are allowed`);
  const wrapped: boolean[] = [];
  for (let index = 0; index < stripped.length; index++) {
    if (stripped[index] !== "?") continue;
    const before = stripped.slice(0, index);
    const after = stripped.slice(index + 1);
    wrapped.push(/CAST\(\s*$/u.test(before) && /^\s*AS\s+INTEGER\s*\)/u.test(after));
  }
  return wrapped;
}
/** The checks every authored statement passes, whether it is written in an owner plan or in a family plan. */
function checkedStatement<T extends { params: PlanParam[] }>(
  sql: string,
  where: string,
  resolve: () => T,
): T {
  assert(
    sql.endsWith(";") && !stripLiterals(sql.slice(0, -1)).includes(";"),
    `${where}: exactly one statement`,
  );
  const stripped = stripLiterals(sql);
  assert(
    !stripped.includes("--") && !stripped.includes("/*"),
    `${where}: comments are not allowed in a statement`,
  );
  assert(!forbiddenSql.test(stripped), `${where}: forbidden SQL`);
  assert(
    /^(?:INSERT|UPDATE|DELETE|SELECT|WITH)\b/iu.test(stripped),
    `${where}: only DML and SELECT are allowed`,
  );
  const resolved = resolve();
  const { params } = resolved;
  const wrapped = placeholderCasts(sql, where);
  assert.equal(wrapped.length, params.length, `${where}: ? placeholder count differs from params`);
  assert(params.length <= maxParameters, `${where}: too many parameters`);
  params.forEach((param, index) => {
    assert.equal(
      wrapped[index],
      param.kind === "int64",
      `${where}: parameter ${index + 1} (${param.kind}) must ${param.kind === "int64" ? "be" : "not be"} wrapped as CAST(? AS INTEGER)`,
    );
    assert(
      !(param.nullable && param.kind === "int64"),
      `${where}: a nullable int64 parameter is not supported`,
    );
  });
  return resolved;
}

/**
 * Parses one plan file. A family plan (`families.<family>.<name>`, in `storage/plans/families`) is parsed with the
 * family context: its statements carry a module, class and stable key, a `-- guard:` directive stands for a generated
 * guard statement, and the generated release statement ends the plan.
 */
export function parsePlanFile(
  text: string,
  file: string,
  context?: FamilyParseContext,
): PlanDefinition {
  const normalized = normalizePlanText(text);
  const lines = normalized.split("\n");
  const header = new Map<string, string>();
  let cursor = 0;
  for (; cursor < lines.length; cursor++) {
    const line = lines[cursor] ?? "";
    const match = /^-- (plan|version|access|maxRows|tail): (.+)$/u.exec(line);
    if (!match) break;
    assert(!header.has(match[1] ?? ""), `${file}: duplicate header ${match[1]}`);
    header.set(match[1] ?? "", match[2] ?? "");
  }
  const id = header.get("plan") ?? "";
  assert(planIdPattern.test(id), `${file}: invalid plan id`);
  const segments = id.split(".");
  let familyId: string | undefined;
  if (context) {
    assert(
      segments.length === 3 && segments[0] === familyOwner,
      `${file}: a family plan id is ${familyOwner}.<family>.<name>`,
    );
    familyId = segments[1];
    assert.equal(
      path.basename(file, ".sql"),
      `${segments[1]}.${segments[2]}`,
      `${file}: file name must be <family>.<name>`,
    );
    assert.equal(
      path.basename(path.dirname(file)),
      familyOwner,
      `${file}: a family plan lives in ${familyDirectory}`,
    );
    assert(
      context.registry.families.some((candidate) => candidate.family === familyId),
      `${file}: family ${familyId} is not in ${familyRegistryFile}`,
    );
  } else {
    assert.notEqual(
      segments[0],
      familyOwner,
      `${file}: ${familyOwner} is reserved for family plans`,
    );
    assert.equal(
      path.basename(file, ".sql"),
      segments.slice(1).join("."),
      `${file}: file name must match the plan id`,
    );
    assert.equal(
      path.basename(path.dirname(file)),
      segments[0],
      `${file}: directory must be the owning module`,
    );
  }
  const version = Number(header.get("version"));
  assert(Number.isInteger(version) && version >= 1 && version <= 2147483647, `${file}: version`);
  const access = header.get("access");
  assert(access === "read" || access === "write", `${file}: access must be read or write`);
  assert(!(context && access !== "write"), `${file}: a family plan is a write plan`);
  const maxRows = header.has("maxRows") ? Number(header.get("maxRows")) : 0;
  assert(
    Number.isInteger(maxRows) && maxRows >= 0 && maxRows <= 200,
    `${file}: maxRows is at most 200`,
  );
  const statements: PlanStatement[] = [];
  let current: { header: string; lines: string[] } | undefined;
  const finish = () => {
    if (!current) return;
    const where = `${file}: statement ${statements.length + 1}`;
    const allowed = context
      ? ["params", "returns", "module", "class", "key"]
      : ["params", "returns"];
    const fields = new Map<string, string>();
    for (const part of current.header.split(/\s+/u).filter(Boolean)) {
      const pair = /^([a-z]+)=(.*)$/u.exec(part);
      assert(
        pair && allowed.includes(pair[1] ?? ""),
        `${where}: unknown statement field '${part}'`,
      );
      assert(!fields.has(pair[1] ?? ""), `${where}: duplicate ${pair[1]}`);
      fields.set(pair[1] ?? "", pair[2] ?? "");
    }
    const sql = current.lines.join("\n").trim();
    const { params, returns } = checkedStatement(sql, where, () => ({
      params: parseKinds(fields.get("params") ?? "", where, true),
      returns: fields.has("returns") ? parseKinds(fields.get("returns") ?? "", where, false) : null,
    }));
    const statement: PlanStatement = { sql, params, returns };
    if (context) {
      const module = fields.get("module") ?? "";
      const className = fields.get("class") ?? "";
      const key = fields.get("key") ?? "";
      assert(
        module !== "" && className !== "" && key !== "",
        `${where}: a family statement names module=, class= and key=`,
      );
      assert(
        stableKeyPattern.test(key),
        `${where}: the stable key is lower-case words joined by hyphens`,
      );
      assert(
        (mutationClasses as readonly string[]).includes(className),
        `${where}: a hand-written family statement is a mutation of class ${mutationClasses.join(", ")} (guards are the generated primitives)`,
      );
      assert(
        /^(?:INSERT|UPDATE|DELETE)\b/iu.test(sql),
        `${where}: a family mutation is an INSERT, UPDATE or DELETE`,
      );
      statement.family = { module, phase: "mutation", class: className, key };
    }
    statements.push(statement);
    current = undefined;
  };
  for (; cursor < lines.length; cursor++) {
    const line = lines[cursor] ?? "";
    const marker = /^-- statement:(.*)$/u.exec(line);
    const guard = /^-- guard:(.*)$/u.exec(line);
    if (marker) {
      finish();
      current = { header: marker[1] ?? "", lines: [] };
    } else if (guard && context) {
      finish();
      const where = `${file}: statement ${statements.length + 1}`;
      const expanded = expandGuard(guard[1] ?? "", context.schema(), where);
      checkedStatement(expanded.sql, where, () => expanded);
      statements.push({
        sql: expanded.sql,
        params: expanded.params,
        returns: null,
        family: expanded.meta,
      });
    } else if (!current && line === "" && cursor === lines.length - 1) {
      // The end of the file after the last guard directive: nothing follows it.
    } else {
      assert(current, `${file}:${cursor + 1}: SQL outside a statement block`);
      assert(!line.startsWith("--"), `${file}:${cursor + 1}: unknown comment directive`);
      current.lines.push(line);
    }
  }
  finish();
  if (context) statements.push(releaseStatement);
  assert(statements.length >= 1 && statements.length <= maxStatements, `${file}: statement count`);
  if (access === "read") {
    assert.equal(statements.length, 1, `${file}: a read plan has exactly one statement`);
    assert(statements[0]?.returns !== null, `${file}: a read plan declares its returned columns`);
    assert(maxRows >= 1, `${file}: a read plan declares maxRows`);
    assert(
      /^(?:SELECT|WITH)\b/iu.test(statements[0]?.sql ?? ""),
      `${file}: a read plan is a SELECT`,
    );
  } else {
    // A committed write is reported by its change count; results come from a separate read plan,
    // so an oversized result can never mask a commit.
    assert(
      statements.every((statement) => statement.returns === null),
      `${file}: a write plan returns no rows`,
    );
    assert.equal(maxRows, 0, `${file}: a write plan has no maxRows`);
  }
  const tail = header.get("tail");
  // A family plan's statements are partly generated from the physical manifest, so its identity covers the expanded text too:
  // a manifest change that alters a guard changes the plan hash and so the manifest identity both sides compare.
  const identity = context
    ? familyIdentity(
        normalized,
        statements.map((statement) => statement.sql),
      )
    : sha256Hex(normalized);
  return {
    id,
    version,
    access,
    maxRows,
    statements,
    sha256: identity,
    ...(tail === undefined ? {} : { tail }),
    ...(familyId === undefined ? {} : { family: familyId }),
  };
}
export function manifestHashOf(plans: readonly PlanDefinition[]) {
  const lines = plans
    .toSorted((a, b) => (a.id === b.id ? a.version - b.version : a.id < b.id ? -1 : 1))
    .map((plan) => `${plan.id}@${plan.version}:${plan.sha256}`);
  return sha256Hex(`${lines.join("\n")}\n`);
}
export interface BuildOptions {
  /** The physical manifest directory the guard primitives are expanded against; the repository's own by default. */
  physicalDirectory?: string;
}
export function buildManifest(root: string, options: BuildOptions = {}): PlanManifest {
  const base = path.join(root, planDirectory);
  const registry = parseOwnerRegistry(readFileSync(path.join(root, ownerRegistry), "utf8"));
  const families = existsSync(path.join(root, familyRegistryFile))
    ? parseFamilyRegistry(readFileSync(path.join(root, familyRegistryFile), "utf8"))
    : { families: [] };
  let schema: PhysicalSchema | undefined;
  const physical = () => {
    schema ??= options.physicalDirectory
      ? loadManifest(options.physicalDirectory)
      : loadManifest(path.join(root, "src/ArcForges.Cloud.Storage.D1/Physical/manifest"));
    return schema;
  };
  const plans: PlanDefinition[] = [];
  for (const owner of readdirSync(base, { withFileTypes: true })) {
    if (!owner.isDirectory()) {
      assert(
        owner.name === "owners.json" ||
          owner.name === "families.json" ||
          owner.name === familyExpansionName,
        `${planDirectory}/${owner.name}: foreign file`,
      );
      continue;
    }
    if (owner.name === familyOwner) {
      for (const file of readdirSync(path.join(base, owner.name)).sort()) {
        assert(file.endsWith(".sql"), `${owner.name}/${file}: plan files end with .sql`);
        const relative = `${familyDirectory}/${file}`;
        const plan = parsePlanFile(readFileSync(path.join(root, relative), "utf8"), relative, {
          registry: families,
          schema: physical,
        });
        assertFamilyPlan(plan, families);
        plans.push(plan);
      }
      continue;
    }
    assert(
      registry.owners.some((entry) => entry.owner === owner.name),
      `${planDirectory}/${owner.name}: the directory is not an owner in ${ownerRegistry}`,
    );
    for (const file of readdirSync(path.join(base, owner.name)).sort()) {
      assert(file.endsWith(".sql"), `${owner.name}/${file}: plan files end with .sql`);
      const relative = `${planDirectory}/${owner.name}/${file}`;
      const plan = parsePlanFile(readFileSync(path.join(root, relative), "utf8"), relative);
      assertOwnership(plan, registry);
      assertCommitTail(plan, registry);
      plans.push(plan);
    }
  }
  assert(plans.length > 0, "No storage plans found");
  const seen = new Set<string>();
  for (const plan of plans) {
    const key = `${plan.id}@${plan.version}`;
    assert(!seen.has(key), `Duplicate plan ${key}`);
    seen.add(key);
  }
  const ordered = plans.toSorted((a, b) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : a.version - b.version,
  );
  return { manifestHash: manifestHashOf(ordered), plans: ordered, registry, families };
}
