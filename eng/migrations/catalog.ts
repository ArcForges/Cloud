// SPDX-License-Identifier: AGPL-3.0-only
// Test support only (CLOUD.84 U9, S41): the TypeScript migration module is kept for the offline local drivers and the
// TypeScript suites that still import it. C# (src/ArcForges.Cloud.Storage.D1/MigrationRunner) is authoritative for every decision.
// The migration catalog: the numbered, checksum-locked D1 migrations of RES-cloud-d1-migrations. One global
// sequence; each module authors its migration as `pending/<module>__<slug>.sql` and the Cloud integration owner
// assigns the next number at merge (`assign`), which moves the file and appends its entry to the lock. A merged
// migration is never edited: the lock holds its checksum and `check --base` compares the lock with the base branch.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  checksumOf,
  type MigrationHeader,
  modeViolations,
  parseBackfill,
  parseHeader,
  type Statement,
  splitStatements,
} from "./sql.ts";

export const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const defaultMigrationsDirectory = path.join(
  repositoryRoot,
  "src/ArcForges.Cloud.Storage.D1/Migrations",
);
export const lockFileName = "migrations.lock.json";

export interface LockEntry {
  sequence: number;
  file: string;
  module: string;
  mode: string;
  sha256: string;
}
export interface Migration {
  sequence: number;
  file: string;
  module: string;
  mode: MigrationHeader["mode"];
  options: Record<string, string>;
  sha256: string;
  text: string;
  statements: Statement[];
}

const numberedFile = /^(\d{4})_([a-z][a-z0-9-]*)__([a-z0-9][a-z0-9-]*)\.sql$/u;
const pendingFile = /^([a-z][a-z0-9-]*)__([a-z0-9][a-z0-9-]*)\.sql$/u;

export function readLock(directory: string): LockEntry[] {
  const file = path.join(directory, lockFileName);
  if (!existsSync(file)) return [];
  const value = JSON.parse(readFileSync(file, "utf8")) as {
    schemaVersion?: number;
    migrations?: LockEntry[];
  };
  assert.equal(value.schemaVersion, 1, `${lockFileName}: schemaVersion`);
  assert(Array.isArray(value.migrations), `${lockFileName}: migrations`);
  return value.migrations;
}

export function writeLock(directory: string, entries: LockEntry[]): void {
  const text = `${JSON.stringify({ schemaVersion: 1, migrations: entries }, null, 2)}\n`;
  writeFileSync(path.join(directory, lockFileName), text);
}

/** SHA-256 over the ordered sequence and checksum of every locked migration: the schema identity of a release. */
export function lockIdentity(entries: LockEntry[]): { highest: number; hash: string } {
  const hash = createHash("sha256");
  for (const entry of entries) hash.update(`${entry.sequence}:${entry.sha256}\n`);
  return {
    highest: entries.length === 0 ? 0 : (entries[entries.length - 1] as LockEntry).sequence,
    hash: hash.digest("hex"),
  };
}

/** Loads and validates the numbered migrations of a directory against its lock. Throws on the first inconsistency. */
export function loadCatalog(directory = defaultMigrationsDirectory): Migration[] {
  const lock = readLock(directory);
  const files = readdirSync(directory)
    .filter((file) => file.endsWith(".sql"))
    .sort();
  const migrations: Migration[] = [];
  files.forEach((file, position) => {
    const match = numberedFile.exec(file);
    assert(match, `migration file ${file} does not match NNNN_<module>__<slug>.sql`);
    const sequence = Number(match[1]);
    assert.equal(
      sequence,
      position,
      `migrations must be numbered 0000.. without a gap or duplicate: ${file} is at position ${position}`,
    );
    const text = readFileSync(path.join(directory, file), "utf8");
    const header = parseHeader(text);
    assert.equal(
      header.module,
      match[2],
      `${file}: header module ${header.module} differs from the file name`,
    );
    let statements: Statement[];
    if (header.mode === "backfill") {
      parseBackfill(text);
      statements = [];
    } else {
      statements = splitStatements(text);
      assert(statements.length > 0, `${file}: no statements`);
      const problems = modeViolations(header.mode, statements);
      assert.equal(problems.length, 0, `${file}: ${problems.join("; ")}`);
    }
    migrations.push({
      sequence,
      file,
      module: header.module,
      mode: header.mode,
      options: header.options,
      sha256: checksumOf(text),
      text,
      statements,
    });
  });
  assert.equal(
    lock.length,
    migrations.length,
    `${lockFileName} has ${lock.length} entries for ${migrations.length} migration files`,
  );
  migrations.forEach((migration, position) => {
    const entry = lock[position] as LockEntry;
    assert.equal(
      entry.sequence,
      migration.sequence,
      `${lockFileName}: sequence at position ${position}`,
    );
    assert.equal(
      entry.file,
      migration.file,
      `${lockFileName}: file of sequence ${migration.sequence}`,
    );
    assert.equal(entry.module, migration.module, `${lockFileName}: module of ${migration.file}`);
    assert.equal(entry.mode, migration.mode, `${lockFileName}: mode of ${migration.file}`);
    assert.equal(
      entry.sha256,
      migration.sha256,
      `${migration.file} was edited after it was locked: a merged migration is never edited, add a new one`,
    );
  });
  return migrations;
}

/** Locks every numbered file that is not locked yet (used once for the baseline and by `assign`). */
export function lockNumbered(directory = defaultMigrationsDirectory): LockEntry[] {
  const lock = readLock(directory);
  const files = readdirSync(directory)
    .filter((file) => file.endsWith(".sql"))
    .sort();
  const entries = [...lock];
  files.forEach((file, position) => {
    if (position < entries.length) {
      assert.equal(entries[position]?.file, file, `${lockFileName} does not match ${file}`);
      return;
    }
    const match = numberedFile.exec(file);
    assert(match, `migration file ${file} does not match NNNN_<module>__<slug>.sql`);
    assert.equal(Number(match[1]), position, `${file}: sequence must be ${position}`);
    const text = readFileSync(path.join(directory, file), "utf8");
    const header = parseHeader(text);
    entries.push({
      sequence: position,
      file,
      module: header.module,
      mode: header.mode,
      sha256: checksumOf(text),
    });
  });
  writeLock(directory, entries);
  return entries;
}

export const pendingDirectoryName = "pending";

export function listPending(directory = defaultMigrationsDirectory): string[] {
  const dir = path.join(directory, pendingDirectoryName);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((file) => file.endsWith(".sql"))
    .sort();
}

/**
 * Integration-owner step at merge: gives each pending migration the next global sequence number, in the order
 * given (or alphabetical), moves it beside the numbered ones and locks it. Returns the new file names.
 */
export function assignPending(directory = defaultMigrationsDirectory, order?: string[]): string[] {
  const pending = order ?? listPending(directory);
  const assigned: string[] = [];
  for (const file of pending) {
    const match = pendingFile.exec(file);
    assert(match, `pending migration ${file} does not match <module>__<slug>.sql`);
    const source = path.join(directory, pendingDirectoryName, file);
    assert(existsSync(source), `pending migration ${file} does not exist`);
    const text = readFileSync(source, "utf8");
    const header = parseHeader(text);
    assert.equal(header.module, match[1], `${file}: header module differs from the file name`);
    const existing = readdirSync(directory).filter((entry) => numberedFile.test(entry)).length;
    const name = `${String(existing).padStart(4, "0")}_${file}`;
    renameSync(source, path.join(directory, name));
    assigned.push(name);
  }
  if (assigned.length > 0) {
    lockNumbered(directory);
    loadCatalog(directory);
  }
  return assigned;
}

/** Validates that every pending file parses and satisfies its mode, without assigning it. */
export function checkPending(directory = defaultMigrationsDirectory): void {
  for (const file of listPending(directory)) {
    const match = pendingFile.exec(file);
    assert(match, `pending migration ${file} does not match <module>__<slug>.sql`);
    const text = readFileSync(path.join(directory, pendingDirectoryName, file), "utf8");
    const header = parseHeader(text);
    assert.equal(header.module, match[1], `${file}: header module differs from the file name`);
    if (header.mode === "backfill") parseBackfill(text);
    else {
      const statements = splitStatements(text);
      assert(statements.length > 0, `${file}: no statements`);
      const problems = modeViolations(header.mode, statements);
      assert.equal(problems.length, 0, `${file}: ${problems.join("; ")}`);
    }
  }
}

/**
 * The lock of the base branch must be a prefix of this lock: a merged migration is never edited, removed
 * or renumbered. `baseLockText` is the content of migrations.lock.json at the base ref.
 */
export function appendOnlyProblems(baseLockText: string, current: LockEntry[]): string[] {
  const base = (JSON.parse(baseLockText) as { migrations: LockEntry[] }).migrations;
  const problems: string[] = [];
  base.forEach((entry, position) => {
    const now = current[position];
    if (!now) problems.push(`migration ${entry.file} was removed`);
    else if (
      now.file !== entry.file ||
      now.sha256 !== entry.sha256 ||
      now.sequence !== entry.sequence
    )
      problems.push(`merged migration ${entry.file} was edited or renumbered (${now.file})`);
  });
  return problems;
}

export function ensurePendingDirectory(directory = defaultMigrationsDirectory): void {
  mkdirSync(path.join(directory, pendingDirectoryName), { recursive: true });
}
