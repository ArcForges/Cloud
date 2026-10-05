// SPDX-License-Identifier: AGPL-3.0-only
// Reviewed Cloud-owned named D1 plans (Design D1 profile section 3) are the only SQL the private
// Worker binding may execute. This tool parses the plan files under storage/plans/<owner>/, validates
// their typed bind/result shape and the owner's table ownership (Design CM-01 to CM-03) and emits the
// Worker SQL dictionary and the C# typed definitions with one SHA-256 plan-manifest identity.
// `--check` fails when either generated file is stale (RES-cloud-storage-plans).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { format } from "prettier";
import type { PlanKind, PlanParam } from "../../worker/storage/plan-types.ts";

export interface PlanStatement {
  sql: string;
  params: PlanParam[];
  returns: PlanParam[] | null;
}
export interface PlanDefinition {
  id: string;
  version: number;
  access: "read" | "write";
  maxRows: number;
  statements: PlanStatement[];
  sha256: string;
}
export interface PlanManifest {
  manifestHash: string;
  plans: PlanDefinition[];
  registry: OwnerRegistry;
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

const kinds: readonly PlanKind[] = ["int64", "uint64", "decimal", "text", "bytes", "bool", "scope"];
const maxStatements = 100;
const maxParameters = 100;
const planIdPattern = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$/u;
const forbiddenSql =
  /\b(?:pragma|attach|detach|drop|alter|create|vacuum|reindex|returning|load_extension|replace\s+into)\b|\bsqlite_/iu;
export const planDirectory = "storage/plans";
export const ownerRegistry = "storage/plans/owners.json";
const typeScriptOutput = "worker/storage/plans.generated.ts";
const csharpOutput = "src/ArcForges.Cloud.Storage.D1/PlanManifest.g.cs";
// SQLite table-valued functions a plan may read from; every other FROM or JOIN target is a physical table.
const tableFunctions = new Set(["json_each", "json_tree"]);

export function sha256Hex(text: string | Uint8Array) {
  return createHash("sha256").update(text).digest("hex");
}
export function normalizePlanText(text: string) {
  return `${text.replaceAll("\r\n", "\n").trimEnd()}\n`;
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
export function parsePlanFile(text: string, file: string): PlanDefinition {
  const normalized = normalizePlanText(text);
  const lines = normalized.split("\n");
  const header = new Map<string, string>();
  let cursor = 0;
  for (; cursor < lines.length; cursor++) {
    const line = lines[cursor] ?? "";
    const match = /^-- (plan|version|access|maxRows): (.+)$/u.exec(line);
    if (!match) break;
    assert(!header.has(match[1] ?? ""), `${file}: duplicate header ${match[1]}`);
    header.set(match[1] ?? "", match[2] ?? "");
  }
  const id = header.get("plan") ?? "";
  assert(planIdPattern.test(id), `${file}: invalid plan id`);
  assert.equal(
    path.basename(file, ".sql"),
    id.split(".").slice(1).join("."),
    `${file}: file name must match the plan id`,
  );
  assert.equal(
    path.basename(path.dirname(file)),
    id.split(".")[0],
    `${file}: directory must be the owning module`,
  );
  const version = Number(header.get("version"));
  assert(Number.isInteger(version) && version >= 1 && version <= 2147483647, `${file}: version`);
  const access = header.get("access");
  assert(access === "read" || access === "write", `${file}: access must be read or write`);
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
    const fields = new Map<string, string>();
    for (const part of current.header.split(/\s+/u).filter(Boolean)) {
      const pair = /^(params|returns)=(.*)$/u.exec(part);
      assert(pair, `${where}: unknown statement field '${part}'`);
      assert(!fields.has(pair[1] ?? ""), `${where}: duplicate ${pair[1]}`);
      fields.set(pair[1] ?? "", pair[2] ?? "");
    }
    const sql = current.lines.join("\n").trim();
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
    const params = parseKinds(fields.get("params") ?? "", where, true);
    const returns = fields.has("returns")
      ? parseKinds(fields.get("returns") ?? "", where, false)
      : null;
    const wrapped = placeholderCasts(sql, where);
    assert.equal(
      wrapped.length,
      params.length,
      `${where}: ? placeholder count differs from params`,
    );
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
    statements.push({ sql, params, returns });
    current = undefined;
  };
  for (; cursor < lines.length; cursor++) {
    const line = lines[cursor] ?? "";
    const marker = /^-- statement:(.*)$/u.exec(line);
    if (marker) {
      finish();
      current = { header: marker[1] ?? "", lines: [] };
    } else {
      assert(current, `${file}:${cursor + 1}: SQL outside a statement block`);
      assert(!line.startsWith("--"), `${file}:${cursor + 1}: unknown comment directive`);
      current.lines.push(line);
    }
  }
  finish();
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
  return {
    id,
    version,
    access,
    maxRows,
    statements,
    sha256: sha256Hex(normalized),
  };
}
export function manifestHashOf(plans: readonly PlanDefinition[]) {
  const lines = plans
    .toSorted((a, b) => (a.id === b.id ? a.version - b.version : a.id < b.id ? -1 : 1))
    .map((plan) => `${plan.id}@${plan.version}:${plan.sha256}`);
  return sha256Hex(`${lines.join("\n")}\n`);
}
export function buildManifest(root: string): PlanManifest {
  const base = path.join(root, planDirectory);
  const registry = parseOwnerRegistry(readFileSync(path.join(root, ownerRegistry), "utf8"));
  const plans: PlanDefinition[] = [];
  for (const owner of readdirSync(base, { withFileTypes: true })) {
    if (!owner.isDirectory()) {
      assert.equal(owner.name, "owners.json", `${planDirectory}/${owner.name}: foreign file`);
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
  return { manifestHash: manifestHashOf(ordered), plans: ordered, registry };
}

export async function renderTypeScript(manifest: PlanManifest) {
  const body = manifest.plans.map((plan) => ({
    id: plan.id,
    version: plan.version,
    access: plan.access,
    maxRows: plan.maxRows,
    statements: plan.statements,
  }));
  const source = `// SPDX-License-Identifier: AGPL-3.0-only
// <auto-generated />
// Generated by eng/verification/storage-plans.ts from the reviewed plan files; do not edit.
import type { PlanDefinition } from "./plan-types.ts";

export const manifestHash = ${JSON.stringify(manifest.manifestHash)};

export const plans: readonly PlanDefinition[] = ${JSON.stringify(body)};
`;
  return format(source, { parser: "typescript", printWidth: 100 });
}
const csharpKind: Record<PlanKind, string> = {
  int64: "Int64",
  uint64: "Uint64",
  decimal: "Decimal",
  text: "Text",
  bytes: "Bytes",
  bool: "Bool",
  scope: "Scope",
};
const pascal = (text: string) =>
  text
    .split("-")
    .map((part) => `${part[0]?.toUpperCase()}${part.slice(1)}`)
    .join("");
/** The member name of a plan inside its owner's class: the id without the owner segment. */
const csharpName = (id: string) => pascal(id.split(".").slice(1).join("-"));
export function renderCSharp(manifest: PlanManifest) {
  const param = (value: PlanParam) =>
    `new(PlanKind.${csharpKind[value.kind]}${value.nullable ? ", true" : ""})`;
  const list = (values: PlanParam[]) => `[${values.map(param).join(", ")}]`;
  const member = (plan: PlanDefinition) => {
    const statements = plan.statements
      .map(
        (statement) =>
          `            new(${list(statement.params)}, ${statement.returns ? list(statement.returns) : "null"})`,
      )
      .join(",\n");
    return `        public static readonly PlanDefinition ${csharpName(plan.id)} = new(
            "${plan.id}",
            ${plan.version},
            PlanAccess.${plan.access === "read" ? "Read" : "Write"},
            ${plan.maxRows},
            [
${statements.replaceAll(/^/gmu, "    ")}
            ]);`;
  };
  // One nested class per owner that has plans: plans of different owners can share a name without clashing.
  const owners = manifest.registry.owners.filter((entry) =>
    manifest.plans.some((plan) => plan.id.startsWith(`${entry.owner}.`)),
  );
  const classes = owners.map((entry) => {
    const own = manifest.plans.filter((plan) => plan.id.startsWith(`${entry.owner}.`));
    const names = own.map((plan) => csharpName(plan.id));
    assert.equal(
      new Set(names).size,
      names.length,
      `${entry.owner}: two plans share a member name`,
    );
    return `    /// <summary>The reviewed plans of the ${entry.owner} owner (<c>storage/plans/${entry.owner}</c>).</summary>
    internal static class ${entry.className}
    {
${own.map(member).join("\n\n")}
    }`;
  });
  const all = owners.flatMap((entry) =>
    manifest.plans
      .filter((plan) => plan.id.startsWith(`${entry.owner}.`))
      .map((plan) => `${entry.className}.${csharpName(plan.id)}`),
  );
  return `// SPDX-License-Identifier: AGPL-3.0-only
// <auto-generated />
// Generated by eng/verification/storage-plans.ts from the reviewed plan files; do not edit.
#nullable enable
namespace ArcForges.Cloud.Storage;

/// <summary>Typed definitions of the reviewed named plans and their single manifest identity.</summary>
internal static class PlanManifest
{
    public const string Hash = "${manifest.manifestHash}";

${classes.join("\n\n")}

    public static readonly IReadOnlyList<PlanDefinition> All = [${all.join(", ")}];
}
`;
}
export async function generate(root: string, check: boolean) {
  const manifest = buildManifest(root);
  const outputs: [string, string][] = [
    [typeScriptOutput, await renderTypeScript(manifest)],
    [csharpOutput, renderCSharp(manifest)],
  ];
  const stale: string[] = [];
  for (const [file, expected] of outputs) {
    const target = path.join(root, file);
    let actual = "";
    try {
      actual = readFileSync(target, "utf8").replaceAll("\r\n", "\n");
    } catch {
      // Missing output is stale output.
    }
    if (actual !== expected) {
      stale.push(file);
      if (!check) writeFileSync(target, expected);
    }
  }
  assert.equal(
    check ? stale.length : 0,
    0,
    `Storage plan outputs are stale: ${stale.join(", ")}. Run node eng/verification/storage-plans.ts.`,
  );
  return {
    manifestHash: manifest.manifestHash,
    plans: manifest.plans.length,
    rewritten: check ? [] : stale,
  };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = await generate(process.cwd(), process.argv.includes("--check"));
  console.log(JSON.stringify(result));
}
