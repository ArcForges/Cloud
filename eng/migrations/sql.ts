// SPDX-License-Identifier: AGPL-3.0-only
// Test support only (CLOUD.84 U9, S41, S42(2)): the TypeScript migration module is kept for the offline local drivers and the
// TypeScript suites that still import it. C# (src/ArcForges.Cloud.Storage.D1/MigrationRunner) is authoritative for every decision.
// SQL text handling for the D1 migration runner: statement splitting that understands strings, quoted
// identifiers, comments and trigger bodies, the migration header, the statement classes each migration mode
// may contain, and the content checksum that locks a merged migration (RES-cloud-d1-migrations).
// The live D1 path is C# and no TypeScript REST transport remains; deleting this file is an open residual (D13, S42(2)).
import { createHash } from "node:crypto";

export const migrationModes = ["expand", "backfill", "cutover", "contract"] as const;
export type MigrationMode = (typeof migrationModes)[number];

/** Normalizes line endings so a checkout with CRLF has the same checksum as one with LF. */
export function normalizeNewlines(text: string): string {
  return text.replaceAll("\r\n", "\n");
}

export function checksumOf(text: string): string {
  return createHash("sha256").update(normalizeNewlines(text), "utf8").digest("hex");
}

interface Token {
  kind: "word" | "string" | "ident" | "number" | "punct" | "comment" | "space";
  text: string;
}

const isWordStart = (code: number) =>
  (code >= 65 && code <= 90) || (code >= 97 && code <= 122) || code === 95 || code >= 128;
const isWordPart = (code: number) => isWordStart(code) || (code >= 48 && code <= 57) || code === 36;

function tokenize(sql: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;
  while (index < sql.length) {
    const char = sql[index] as string;
    const code = sql.charCodeAt(index);
    if (char === " " || char === "\t" || char === "\n" || char === "\r") {
      const start = index;
      while (index < sql.length && " \t\n\r".includes(sql[index] as string)) index++;
      tokens.push({ kind: "space", text: sql.slice(start, index) });
    } else if (char === "-" && sql[index + 1] === "-") {
      const start = index;
      while (index < sql.length && sql[index] !== "\n") index++;
      tokens.push({ kind: "comment", text: sql.slice(start, index) });
    } else if (char === "/" && sql[index + 1] === "*") {
      const start = index;
      const end = sql.indexOf("*/", index + 2);
      index = end < 0 ? sql.length : end + 2;
      tokens.push({ kind: "comment", text: sql.slice(start, index) });
    } else if (char === "'" || char === '"' || char === "`") {
      const start = index;
      index++;
      let closed = false;
      while (index < sql.length) {
        if (sql[index] === char) {
          if (sql[index + 1] === char) {
            index += 2;
            continue;
          }
          index++;
          closed = true;
          break;
        }
        index++;
      }
      if (!closed) throw new Error("unterminated quoted text in SQL");
      tokens.push({ kind: char === "'" ? "string" : "ident", text: sql.slice(start, index) });
    } else if (char === "[") {
      const start = index;
      const end = sql.indexOf("]", index);
      if (end < 0) throw new Error("unterminated bracket identifier in SQL");
      index = end + 1;
      tokens.push({ kind: "ident", text: sql.slice(start, index) });
    } else if (isWordStart(code)) {
      const start = index;
      while (index < sql.length && isWordPart(sql.charCodeAt(index))) index++;
      tokens.push({ kind: "word", text: sql.slice(start, index) });
    } else if (code >= 48 && code <= 57) {
      const start = index;
      while (index < sql.length && (isWordPart(sql.charCodeAt(index)) || sql[index] === "."))
        index++;
      tokens.push({ kind: "number", text: sql.slice(start, index) });
    } else {
      tokens.push({ kind: "punct", text: char });
      index++;
    }
  }
  return tokens;
}

export interface Statement {
  /** The statement text without its terminating semicolon, comments and surrounding space trimmed. */
  sql: string;
  /** Upper-cased significant words that start the statement (up to three). */
  head: string[];
}

/**
 * Splits migration SQL into statements. A semicolon ends a statement unless it is inside a string, a
 * quoted identifier, a comment or a trigger body (the text between the trigger's BEGIN and its matching END,
 * where CASE ... END pairs nest).
 */
export function splitStatements(sql: string): Statement[] {
  const tokens = tokenize(normalizeNewlines(sql));
  const statements: Statement[] = [];
  let current: Token[] = [];
  let triggerDepth = 0;
  let inTrigger = false;
  const significant = () =>
    current.filter((token) => token.kind !== "space" && token.kind !== "comment");
  const flush = () => {
    const words = significant();
    if (words.length > 0) {
      const text = current
        .map((token) => token.text)
        .join("")
        .trim();
      // Drop leading comments from the statement text.
      const cleaned = trimLeadingComments(text);
      statements.push({
        sql: cleaned,
        head: words
          .filter((token) => token.kind === "word")
          .slice(0, 3)
          .map((token) => token.text.toUpperCase()),
      });
    }
    current = [];
    inTrigger = false;
    triggerDepth = 0;
  };
  for (const token of tokens) {
    if (token.kind === "punct" && token.text === ";" && triggerDepth === 0) {
      flush();
      continue;
    }
    current.push(token);
    if (token.kind !== "word") continue;
    const word = token.text.toUpperCase();
    if (!inTrigger) {
      const words = significant().filter((entry) => entry.kind === "word");
      if (words.length >= 2 && words[0]?.text.toUpperCase() === "CREATE") {
        const second = words[1]?.text.toUpperCase();
        const third = words[2]?.text.toUpperCase();
        if (
          second === "TRIGGER" ||
          ((second === "TEMP" || second === "TEMPORARY") && third === "TRIGGER")
        )
          inTrigger = true;
      }
    }
    if (inTrigger) {
      if (word === "BEGIN" || word === "CASE") triggerDepth++;
      else if (word === "END" && triggerDepth > 0) triggerDepth--;
    }
  }
  if (triggerDepth !== 0) throw new Error("unterminated trigger body in SQL");
  flush();
  return statements;
}

function trimLeadingComments(text: string): string {
  let rest = text;
  for (;;) {
    rest = rest.trimStart();
    if (rest.startsWith("--")) {
      const end = rest.indexOf("\n");
      rest = end < 0 ? "" : rest.slice(end + 1);
    } else if (rest.startsWith("/*")) {
      const end = rest.indexOf("*/");
      rest = end < 0 ? "" : rest.slice(end + 2);
    } else return rest;
  }
}

export interface MigrationHeader {
  module: string;
  mode: MigrationMode;
  /** Extra key=value pairs of the af-migration line (soak, after, requires, readHorizon, writeHorizon). */
  options: Record<string, string>;
}

const headerLine = /^--\s*af-migration:\s*(.+)$/mu;
const modulePattern = /^[a-z][a-z0-9-]*$/u;

export function parseHeader(sql: string): MigrationHeader {
  const match = headerLine.exec(normalizeNewlines(sql));
  if (!match) throw new Error("migration has no `-- af-migration:` header line");
  const pairs: Record<string, string> = {};
  for (const part of (match[1] ?? "").trim().split(/\s+/u)) {
    const equals = part.indexOf("=");
    if (equals <= 0) throw new Error(`malformed header option ${JSON.stringify(part)}`);
    const key = part.slice(0, equals);
    if (key in pairs) throw new Error(`duplicate header option ${key}`);
    pairs[key] = part.slice(equals + 1);
  }
  const { module, mode, ...options } = pairs;
  if (!module || !modulePattern.test(module))
    throw new Error("header module is missing or invalid");
  if (!mode || !(migrationModes as readonly string[]).includes(mode))
    throw new Error(`header mode must be one of ${migrationModes.join(", ")}`);
  return { module, mode: mode as MigrationMode, options };
}

const keywords = (statement: Statement) => statement.head.join(" ");

const baseForbidden = new Set([
  "PRAGMA",
  "ATTACH",
  "DETACH",
  "VACUUM",
  "BEGIN",
  "COMMIT",
  "ROLLBACK",
  "SAVEPOINT",
  "RELEASE",
  "END",
]);

/**
 * The statements one mode may contain. The runner owns transactions, so no migration controls them. An
 * expand migration only adds; a contract migration is the only one that may remove or rename.
 */
export function modeViolations(mode: MigrationMode, statements: Statement[]): string[] {
  const problems: string[] = [];
  statements.forEach((statement, position) => {
    const where = `statement ${position + 1} (${statement.head.join(" ")})`;
    const first = statement.head[0] ?? "";
    if (baseForbidden.has(first)) {
      if (
        first === "PRAGMA" &&
        /^PRAGMA\s+defer_foreign_keys\s*=\s*(?:ON|OFF|1|0)\s*$/iu.test(statement.sql)
      )
        return;
      problems.push(`${where}: ${first} is not allowed in a migration`);
      return;
    }
    const text = keywords(statement);
    const isCreate =
      /^CREATE (?:UNIQUE )?(?:TABLE|INDEX|TRIGGER|VIRTUAL TABLE)\b/u.test(text) ||
      /^CREATE (?:UNIQUE )?INDEX\b/u.test(text);
    if (mode === "expand") {
      if (isCreate) return;
      if (
        /^ALTER TABLE\b/u.test(text) &&
        /\bADD(?: COLUMN)?\b/iu.test(statement.sql) &&
        !/\b(?:DROP|RENAME)\b/iu.test(statement.sql.replace(/^ALTER\s+TABLE\s+\S+/iu, ""))
      )
        return;
      problems.push(
        `${where}: an expand migration may only create tables, indexes, triggers and virtual tables or add a column`,
      );
    } else if (mode === "contract") {
      if (isCreate || /^(?:DROP|ALTER)\b/u.test(text) || /^(?:INSERT|UPDATE|DELETE)\b/u.test(text))
        return;
      problems.push(`${where}: unsupported statement in a contract migration`);
    } else if (mode === "cutover") {
      if (/^(?:INSERT|UPDATE|DELETE)\b/u.test(text) || isCreate) return;
      problems.push(`${where}: a cutover migration contains data and index statements only`);
    }
  });
  return problems;
}

export interface BackfillSpec {
  /** The table whose rows are converted. */
  target: string;
  /** The key column of the page query (text). */
  key: string;
  pageSize: number;
  /** SELECT key, CAST(revision AS TEXT) ... WHERE key > ? [AND unconverted] ORDER BY key LIMIT ?  */
  page: string;
  /** The one guarded statement run per selected row with the binds (key, revision text). */
  apply: string;
  /** SELECT COUNT(*) of rows still unconverted or dirty; zero before the cutover. */
  verify: string;
}

const sectionMarker = /^--\s*section:\s*(page|apply|verify)\s*$/mu;
const backfillLine = /^--\s*af-backfill:\s*(\{.*\})\s*$/mu;

/** Parses the three named sections and the JSON option line of a backfill migration. */
export function parseBackfill(sql: string): BackfillSpec {
  const text = normalizeNewlines(sql);
  const options = backfillLine.exec(text);
  if (!options) throw new Error("backfill migration has no `-- af-backfill:` JSON line");
  const value = JSON.parse(options[1] ?? "{}") as {
    target?: string;
    key?: string;
    pageSize?: number;
  };
  if (!value.target || !/^[a-z][a-z0-9_]*$/u.test(value.target))
    throw new Error("backfill target is missing or invalid");
  if (!value.key || !/^[a-z][a-z0-9_]*$/u.test(value.key))
    throw new Error("backfill key is missing or invalid");
  const pageSize = value.pageSize ?? 100;
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 100)
    throw new Error("backfill pageSize must be 1..100 (Design D1 profile section 6)");
  const parts = text.split(sectionMarker);
  // parts: [preamble, name, body, name, body, ...]
  const sections = new Map<string, string>();
  for (let index = 1; index < parts.length; index += 2) {
    const name = parts[index] as string;
    if (sections.has(name)) throw new Error(`backfill section ${name} appears twice`);
    sections.set(name, (parts[index + 1] ?? "").trim());
  }
  const section = (name: string) => {
    const body = sections.get(name);
    if (!body) throw new Error(`backfill section ${name} is missing`);
    const statements = splitStatements(body);
    if (statements.length !== 1)
      throw new Error(`backfill section ${name} must hold exactly one statement`);
    return (statements[0] as Statement).sql;
  };
  const spec: BackfillSpec = {
    target: value.target,
    key: value.key,
    pageSize,
    page: section("page"),
    apply: section("apply"),
    verify: section("verify"),
  };
  if (!/^\s*SELECT\b/iu.test(spec.page)) throw new Error("backfill page must be a SELECT");
  if (!/^\s*SELECT\b/iu.test(spec.verify)) throw new Error("backfill verify must be a SELECT");
  if (!/^\s*UPDATE\b/iu.test(spec.apply)) throw new Error("backfill apply must be one UPDATE");
  if ((spec.page.match(/\?/gu) ?? []).length !== 2)
    throw new Error("backfill page takes exactly two parameters (the key cursor and the limit)");
  if (!/\bLIMIT\b/iu.test(spec.page) || !/\bORDER\s+BY\b/iu.test(spec.page))
    throw new Error("backfill page must be ordered by the key and limited");
  if ((spec.apply.match(/\?/gu) ?? []).length !== 2)
    throw new Error(
      "backfill apply takes exactly two parameters (the key and the expected revision)",
    );
  if (!/\brev(?:ision)?\b/iu.test(spec.apply))
    throw new Error("backfill apply must guard the owner revision");
  return spec;
}
