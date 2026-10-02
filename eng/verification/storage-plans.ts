// SPDX-License-Identifier: AGPL-3.0-only
// Reviewed Cloud-owned named D1 plans (Design D1 profile section 3) are the only SQL the private
// Worker binding may execute. This tool parses the plan files, validates their typed bind/result
// shape and emits the Worker SQL dictionary and the C# typed definitions with one SHA-256
// plan-manifest identity. `--check` fails when either generated file is stale (RES-cloud-storage-plans).
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
}

const kinds: readonly PlanKind[] = ["int64", "uint64", "decimal", "text", "bytes", "bool", "scope"];
const maxStatements = 100;
const maxParameters = 100;
const planIdPattern = /^[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9-]*)+$/u;
const forbiddenSql =
  /\b(?:pragma|attach|detach|drop|alter|create|vacuum|reindex|returning|load_extension|replace\s+into)\b|\bsqlite_/iu;
const planDirectory = "src/ArcForges.Cloud/Storage/Plans";
const typeScriptOutput = "worker/storage/plans.generated.ts";
const csharpOutput = "src/ArcForges.Cloud/Storage/PlanManifest.g.cs";

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
  const plans: PlanDefinition[] = [];
  for (const owner of readdirSync(base, { withFileTypes: true })) {
    if (!owner.isDirectory()) continue;
    for (const file of readdirSync(path.join(base, owner.name)).sort()) {
      assert(file.endsWith(".sql"), `${owner.name}/${file}: plan files end with .sql`);
      const relative = `${planDirectory}/${owner.name}/${file}`;
      plans.push(parsePlanFile(readFileSync(path.join(root, relative), "utf8"), relative));
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
  return { manifestHash: manifestHashOf(ordered), plans: ordered };
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
const csharpName = (id: string) =>
  id
    .split(".")
    .slice(1)
    .join("-")
    .split("-")
    .map((part) => `${part[0]?.toUpperCase()}${part.slice(1)}`)
    .join("");
export function renderCSharp(manifest: PlanManifest) {
  const param = (value: PlanParam) =>
    `new(PlanKind.${csharpKind[value.kind]}${value.nullable ? ", true" : ""})`;
  const list = (values: PlanParam[]) => `[${values.map(param).join(", ")}]`;
  const members = manifest.plans.map((plan) => {
    const statements = plan.statements
      .map(
        (statement) =>
          `            new(${list(statement.params)}, ${statement.returns ? list(statement.returns) : "null"})`,
      )
      .join(",\n");
    return `    public static readonly PlanDefinition ${csharpName(plan.id)} = new(
        "${plan.id}",
        ${plan.version},
        PlanAccess.${plan.access === "read" ? "Read" : "Write"},
        ${plan.maxRows},
        [
${statements}
        ]);`;
  });
  const names = manifest.plans.map((plan) => csharpName(plan.id)).join(", ");
  return `// SPDX-License-Identifier: AGPL-3.0-only
// <auto-generated />
// Generated by eng/verification/storage-plans.ts from the reviewed plan files; do not edit.
#nullable enable
namespace ArcForges.Cloud.Storage;

/// <summary>Typed definitions of the reviewed named plans and their single manifest identity.</summary>
internal static class PlanManifest
{
    public const string Hash = "${manifest.manifestHash}";

${members.join("\n\n")}

    public static readonly IReadOnlyList<PlanDefinition> All = [${names}];
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
