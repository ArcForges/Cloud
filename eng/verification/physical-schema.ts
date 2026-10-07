// SPDX-License-Identifier: AGPL-3.0-only
// The checked-in physical manifest (Design D1 profile section 2) is the executable form of the Cloud data model:
// one JSON file per owner under src/ArcForges.Cloud.Storage.D1/Physical/manifest plus the closed enum registry.
// This tool validates it, expands it to physical columns, emits the baseline D1 migrations and the C# column maps,
// and proves that the numbered migrations applied to an empty database equal the manifest (drift check).
//
//   node eng/verification/physical-schema.ts --check        validate, check the generated C# and the migration drift
//   node eng/verification/physical-schema.ts --emit-baseline   write the baseline migrations (once, before they are locked)
//   node eng/verification/physical-schema.ts                regenerate PhysicalSchema.g.cs
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { lockIdentity, readLock } from "../migrations/catalog.ts";

export const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const storageRoot = path.join(repositoryRoot, "src/ArcForges.Cloud.Storage.D1");
export const manifestDirectory = path.join(storageRoot, "Physical/manifest");
export const migrationsDirectory = path.join(storageRoot, "Migrations");
export const generatedCSharp = path.join(storageRoot, "Physical/PhysicalSchema.g.cs");
export const ownersFile = path.join(repositoryRoot, "storage/plans/owners.json");

export type ColumnType =
  | "id"
  | "text"
  | "key"
  | "productId"
  | "modelId"
  | "bool"
  | "int"
  | "int64"
  | "rev"
  | "instant"
  | "uint64"
  | "decimal"
  | "hash"
  | "bytes"
  | "proto"
  | "json"
  | "enum"
  | "currency"
  | "money"
  | "aggregateRef";

export interface ManifestColumn {
  name: string;
  type: ColumnType;
  nullable?: boolean;
  /** Registry enum name for type enum. */
  enum?: string;
  /** For json: the required root kind. */
  root?: "object" | "array" | "any";
  /** For text: a byte-length ceiling. */
  maxBytes?: number;
  /** An INTEGER column that may never decrease (enforced by a trigger). */
  monotonic?: boolean;
  /** A SQL expression, over this table's columns, that the column must equal (a derived column). */
  generated?: string;
  note?: string;
}
export interface ManifestIndex {
  name?: string;
  columns: string[];
  unique?: boolean;
  where?: string;
  /** The query path the index serves (Design QP-01). */
  path: string;
}
export interface ManifestForeignKey {
  columns: string[];
  references: { table: string; columns: string[] };
  onDelete?: "restrict" | "cascade" | "setNull";
}
export interface ManifestCheck {
  name: string;
  sql: string;
}
export interface ManifestMutability {
  /** Preserve a fully immutable primary-key row on duplicate insertion, including INSERT OR REPLACE with recursive triggers disabled. */
  insert?: "preserveExisting";
  /** none: the row can never be updated. An object limits updates to listed columns, optionally while a predicate over OLD holds. */
  update?: "none" | "any" | { columns: string[]; when?: string };
  delete?: "none" | "any";
}
export interface ManifestFts5 {
  /** The external-content FTS5 virtual table name; it must start with the owner prefix. */
  name: string;
  columns: string[];
  tokenize: string;
}
export interface ManifestTable {
  name: string;
  model: string;
  columns: ManifestColumn[];
  primaryKey: string[];
  indexes?: ManifestIndex[];
  foreignKeys?: ManifestForeignKey[];
  checks?: ManifestCheck[];
  mutability?: ManifestMutability;
  insertionInvariant?: "deletionLifecycleOriginal";
  fts5?: ManifestFts5;
  /** Created by the runner's bootstrap migration 0000, before any receipt can exist. */
  bootstrap?: boolean;
  note?: string;
}
export type EnumValues = string[] | Record<string, number>;
export interface ManifestEnum {
  source: string;
  values: EnumValues;
  /** An unknown stored number is preserved on read instead of refused. */
  preserveUnknown?: boolean;
}
export interface ManifestFile {
  schemaVersion: 1;
  owner: string;
  enums?: Record<string, ManifestEnum>;
  tables: ManifestTable[];
}
export interface EnumRegistryFile {
  schemaVersion: 1;
  enums: Record<string, ManifestEnum>;
}

export type PhysicalKind =
  | "id"
  | "text"
  | "key"
  | "productId"
  | "modelId"
  | "bool"
  | "int"
  | "int64"
  | "rev"
  | "instant"
  | "uint64"
  | "decimal"
  | "currency"
  | "hash"
  | "bytes"
  | "proto"
  | "json"
  | "enum";
export type SqlType = "TEXT" | "INTEGER" | "BLOB";
export interface PhysicalColumn {
  name: string;
  kind: PhysicalKind;
  sqlType: SqlType;
  nullable: boolean;
  enumName?: string;
  jsonRoot?: "object" | "array" | "any";
  maxBytes?: number;
  monotonic: boolean;
  generated?: string;
  /** The logical field this column belongs to when a field expands to several columns. */
  group?: { field: string; part: string };
}
export interface PhysicalTable {
  name: string;
  owner: string;
  model: string;
  columns: PhysicalColumn[];
  primaryKey: string[];
  indexes: (Required<Pick<ManifestIndex, "name" | "columns" | "path">> & {
    unique: boolean;
    where?: string;
  })[];
  foreignKeys: Required<ManifestForeignKey>[];
  checks: ManifestCheck[];
  mutability: {
    insert?: "preserveExisting";
    update: "none" | "any" | { columns: string[]; when?: string };
    delete: "none" | "any";
  };
  insertionInvariant?: "deletionLifecycleOriginal";
  fts5?: ManifestFts5;
  bootstrap: boolean;
}
export interface ResolvedEnum {
  name: string;
  source: string;
  members: { name: string; number: number }[];
  preserveUnknown: boolean;
}
export interface PhysicalSchema {
  owners: { owner: string; tablePrefix: string; kind: string }[];
  enums: ResolvedEnum[];
  tables: PhysicalTable[];
}

const sqliteType: Record<PhysicalKind, SqlType> = {
  id: "TEXT",
  text: "TEXT",
  key: "TEXT",
  productId: "TEXT",
  modelId: "TEXT",
  bool: "INTEGER",
  int: "INTEGER",
  int64: "INTEGER",
  rev: "INTEGER",
  instant: "INTEGER",
  uint64: "TEXT",
  decimal: "TEXT",
  currency: "TEXT",
  hash: "BLOB",
  bytes: "BLOB",
  proto: "BLOB",
  json: "TEXT",
  enum: "INTEGER",
};
const namePattern = /^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/u;
const maxName = 80;
export const productIds = ["arcscope", "companion"] as const;

const quote = (name: string) => `"${name}"`;
const sqlString = (value: string) => `'${value.replaceAll("'", "''")}'`;

function expandColumns(table: ManifestTable): PhysicalColumn[] {
  const out: PhysicalColumn[] = [];
  for (const column of table.columns) {
    const nullable = column.nullable === true;
    const base = { nullable, monotonic: column.monotonic === true } as const;
    switch (column.type) {
      case "money":
        out.push(
          {
            name: column.name,
            kind: "decimal",
            sqlType: "TEXT",
            ...base,
            group: { field: column.name, part: "amount" },
          },
          {
            name: `${column.name}_currency`,
            kind: "currency",
            sqlType: "TEXT",
            ...base,
            group: { field: column.name, part: "currency" },
          },
        );
        break;
      case "aggregateRef":
        out.push(
          {
            name: `${column.name}_kind`,
            kind: "key",
            sqlType: "TEXT",
            ...base,
            group: { field: column.name, part: "kind" },
          },
          {
            name: `${column.name}_id`,
            kind: "id",
            sqlType: "TEXT",
            ...base,
            group: { field: column.name, part: "id" },
          },
        );
        break;
      default: {
        const physical: PhysicalColumn = {
          name: column.name,
          kind: column.type,
          sqlType: sqliteType[column.type],
          ...base,
        };
        if (column.enum !== undefined) physical.enumName = column.enum;
        if (column.root !== undefined) physical.jsonRoot = column.root;
        if (column.maxBytes !== undefined) physical.maxBytes = column.maxBytes;
        if (column.generated !== undefined) physical.generated = column.generated;
        out.push(physical);
      }
    }
  }
  return out;
}

/** The CHECK expression that makes the stored value exactly the canonical form of its logical type. */
export function columnCheck(
  column: PhysicalColumn,
  enums: Map<string, ResolvedEnum>,
): string | null {
  const q = quote(column.name);
  switch (column.kind) {
    case "id":
      return `length(${q}) = 36 AND ${q} GLOB '????????-????-????-????-????????????' AND ${q} NOT GLOB '*[^0-9a-f-]*'`;
    case "key":
      return `length(${q}) BETWEEN 1 AND 128 AND ${q} NOT GLOB '*[^A-Za-z0-9._:/-]*'`;
    case "productId":
      return `${q} IN (${productIds.map(sqlString).join(", ")})`;
    case "modelId":
      return `length(${q}) BETWEEN 1 AND 256`;
    case "currency":
      return `length(${q}) = 3 AND ${q} NOT GLOB '*[^A-Z]*'`;
    case "text":
      return column.maxBytes === undefined
        ? null
        : `length(CAST(${q} AS BLOB)) <= ${column.maxBytes}`;
    case "bool":
      return `${q} IN (0, 1)`;
    case "int":
      return `${q} BETWEEN -2147483648 AND 2147483647`;
    case "rev":
      return `${q} >= 0`;
    case "uint64":
      return [
        `length(${q}) BETWEEN 1 AND 20`,
        `${q} NOT GLOB '*[^0-9]*'`,
        `(${q} = '0' OR ${q} NOT GLOB '0*')`,
        `(length(${q}) < 20 OR ${q} <= '18446744073709551615')`,
      ].join(" AND ");
    case "decimal":
      return [
        `length(${q}) BETWEEN 1 AND 30`,
        `${q} NOT GLOB '*[^0-9.-]*'`,
        `${q} NOT GLOB '*.*.*'`,
        `${q} NOT GLOB '*-*-*'`,
        `${q} NOT GLOB '*[0-9.]-*'`,
        `${q} NOT GLOB '.*'`,
        `${q} NOT GLOB '*.'`,
        `${q} NOT GLOB '-.*'`,
        `${q} NOT GLOB '-'`,
        `${q} NOT GLOB '0[0-9]*'`,
        `${q} NOT GLOB '-0[0-9]*'`,
        `${q} <> '-0'`,
        `${q} NOT GLOB '*.*0'`,
        // D1 refuses a LIKE or GLOB pattern longer than 50 bytes, so the fraction length is counted, not matched.
        `(instr(${q}, '.') = 0 OR length(${q}) - instr(${q}, '.') <= 9)`,
        `length(replace(replace(${q}, '-', ''), '.', '')) <= 28`,
      ].join(" AND ");
    case "hash":
      return `length(${q}) = 32`;
    case "json": {
      const root = column.jsonRoot ?? "any";
      return root === "any"
        ? `json_valid(${q})`
        : `CASE WHEN json_valid(${q}) THEN json_type(${q}) = ${sqlString(root)} ELSE 0 END`;
    }
    case "enum": {
      const registered = enums.get(column.enumName ?? "");
      assert(registered, `unknown enum ${column.enumName}`);
      return `${q} IN (${registered.members.map((member) => member.number).join(", ")})`;
    }
    case "int64":
    case "instant":
    case "bytes":
    case "proto":
      return null;
  }
}

export function loadOwners(): { owner: string; tablePrefix: string; kind: string }[] {
  const value = JSON.parse(readFileSync(ownersFile, "utf8")) as {
    owners: { owner: string; tablePrefix: string; kind: string }[];
  };
  return value.owners.filter((entry) => entry.kind !== "proof");
}

function resolveEnum(name: string, entry: ManifestEnum): ResolvedEnum {
  const members = Array.isArray(entry.values)
    ? entry.values.map((memberName, index) => ({ name: memberName, number: index + 1 }))
    : Object.entries(entry.values).map(([memberName, number]) => ({ name: memberName, number }));
  assert(members.length > 0, `enum ${name}: no members`);
  const names = new Set<string>();
  const numbers = new Set<number>();
  for (const member of members) {
    assert(/^[A-Za-z][A-Za-z0-9]*$/u.test(member.name), `enum ${name}: member name ${member.name}`);
    assert(
      Number.isInteger(member.number) && member.number >= 1 && member.number <= 65535,
      `enum ${name}: number of ${member.name}`,
    );
    assert(!names.has(member.name), `enum ${name}: duplicate member ${member.name}`);
    assert(!numbers.has(member.number), `enum ${name}: duplicate number ${member.number}`);
    names.add(member.name);
    numbers.add(member.number);
  }
  return {
    name,
    source: entry.source,
    members,
    preserveUnknown: entry.preserveUnknown === true,
  };
}

export function loadManifest(directory = manifestDirectory, partial = false): PhysicalSchema {
  const owners = loadOwners();
  const files = readdirSync(directory)
    .filter((file) => file.endsWith(".json"))
    .sort();
  assert(files.includes("enums.json"), "manifest: enums.json is missing");
  const registry = JSON.parse(
    readFileSync(path.join(directory, "enums.json"), "utf8"),
  ) as EnumRegistryFile;
  assert.equal(registry.schemaVersion, 1, "enums.json: schemaVersion");
  const enumEntries = new Map<string, ManifestEnum>();
  for (const [name, entry] of Object.entries(registry.enums)) enumEntries.set(name, entry);
  const manifests: ManifestFile[] = [];
  for (const file of files) {
    if (file === "enums.json") continue;
    const value = JSON.parse(readFileSync(path.join(directory, file), "utf8")) as ManifestFile;
    assert.equal(value.schemaVersion, 1, `${file}: schemaVersion`);
    assert.equal(`${value.owner}.json`, file, `${file}: owner must name the file`);
    for (const [name, entry] of Object.entries(value.enums ?? {})) {
      assert(!enumEntries.has(name), `${file}: enum ${name} is already registered`);
      assert(
        name.startsWith(`${value.owner}.`),
        `${file}: inline enum ${name} must be prefixed ${value.owner}.`,
      );
      enumEntries.set(name, entry);
    }
    manifests.push(value);
  }
  const ownerNames = new Set(owners.map((entry) => entry.owner));
  for (const manifest of manifests)
    assert(ownerNames.has(manifest.owner), `manifest: ${manifest.owner} is not a registered owner`);
  const enums = [...enumEntries.entries()]
    .map(([name, entry]) => resolveEnum(name, entry))
    .sort((a, b) => a.name.localeCompare(b.name, "en"));
  const tables: PhysicalTable[] = [];
  for (const manifest of manifests) {
    const owner = owners.find((entry) => entry.owner === manifest.owner);
    assert(owner);
    for (const table of manifest.tables)
      tables.push(toPhysicalTable(manifest.owner, owner.tablePrefix, table));
  }
  tables.sort((a, b) => a.name.localeCompare(b.name, "en"));
  const schema: PhysicalSchema = { owners, enums, tables };
  validateSchema(schema, partial);
  return schema;
}

function toPhysicalTable(owner: string, prefix: string, table: ManifestTable): PhysicalTable {
  assert(table.name.startsWith(prefix), `${table.name}: must start with ${prefix}`);
  const columns = expandColumns(table);
  const indexes = (table.indexes ?? []).map((index) => ({
    name:
      index.name ??
      `${index.unique ? "ux" : "ix"}_${table.name}__${index.columns.map((column) => column.replace(/\s+(?:ASC|DESC)$/iu, "")).join("_")}`,
    columns: index.columns,
    path: index.path,
    unique: index.unique === true,
    ...(index.where === undefined ? {} : { where: index.where }),
  }));
  const foreignKeys = (table.foreignKeys ?? []).map((fk) => ({
    columns: fk.columns,
    references: fk.references,
    onDelete: fk.onDelete ?? ("restrict" as const),
  }));
  return {
    name: table.name,
    owner,
    model: table.model,
    columns,
    primaryKey: table.primaryKey,
    indexes,
    foreignKeys,
    checks: table.checks ?? [],
    mutability: {
      ...(table.mutability?.insert === undefined ? {} : { insert: table.mutability.insert }),
      update: table.mutability?.update ?? "any",
      delete: table.mutability?.delete ?? "any",
    },
    ...(table.insertionInvariant === undefined
      ? {}
      : { insertionInvariant: table.insertionInvariant }),
    ...(table.fts5 === undefined ? {} : { fts5: table.fts5 }),
    bootstrap: table.bootstrap === true,
  };
}

const indexColumnName = (entry: string) => entry.replace(/\s+(?:ASC|DESC)$/iu, "");

/** A single fixed owner invariant; no table or SQL supplied by a marker is executable. */
function validateInsertionInvariant(table: PhysicalTable): void {
  if (table.insertionInvariant === undefined) return;
  const message = `${table.name}: invalid deletion lifecycle insertion invariant`;
  assert.equal(table.insertionInvariant, "deletionLifecycleOriginal", message);
  assert.equal(table.owner, "identity", message);
  assert.equal(table.name, "identity_account_deletion", message);
  assert.deepEqual(table.primaryKey, ["deletion_id"], message);
  for (const name of ["deletion_id", "user_id"]) {
    const column = table.columns.find((entry) => entry.name === name);
    assert(
      column &&
        column.kind === "id" &&
        column.sqlType === "TEXT" &&
        !column.nullable &&
        column.generated === undefined,
      message,
    );
  }
  const state = table.columns.find((entry) => entry.name === "state");
  assert(
    state &&
      state.kind === "enum" &&
      state.sqlType === "INTEGER" &&
      !state.nullable &&
      state.enumName === "identity.deletion_state" &&
      state.generated === undefined,
    message,
  );
  const unique = table.indexes.filter((entry) => entry.unique);
  assert.equal(unique.length, 1, message);
  const index = unique[0];
  assert(index && index.name === "ux_identity_account_deletion__user_id", message);
  assert.deepEqual(index.columns, ["user_id"], message);
  assert.equal(index.where, '"state" IN (1, 3)', message);
  assert.equal(table.mutability.delete, "none", message);
  const update = table.mutability.update;
  assert(typeof update === "object", message);
  assert.deepEqual(update.columns, ["state", "cancelled_at", "completed_at", "rev"], message);
  assert.equal(update.when, 'OLD."state" IN (1, 3)', message);
}

function validatePreservedInsertion(table: PhysicalTable): void {
  if (table.mutability.insert === undefined) return;
  const where = `table ${table.name}`;
  assert.equal(table.mutability.insert, "preserveExisting", `${where}: insertion mutability`);
  assert(
    table.owner === "entitlement" &&
      [
        "entitlement_resolver_definition_profile",
        "entitlement_quota_definition_profile",
        "entitlement_quota_definition_key",
      ].includes(table.name),
    `${where}: preserved insertion is not admitted for this owner and table`,
  );
  assert(
    table.mutability.update === "none" && table.mutability.delete === "none",
    `${where}: preserved insertion requires a fully immutable row`,
  );
  assert(
    !table.indexes.some((index) => index.unique),
    `${where}: preserved insertion supports primary-key conflicts only`,
  );
}

function validateInsertionStateProfile(
  table: PhysicalTable,
  enums: Map<string, ResolvedEnum>,
): void {
  if (table.insertionInvariant === undefined) return;
  assert.deepEqual(
    enums.get("identity.deletion_state")?.members,
    [
      { name: "pending", number: 1 },
      { name: "cancelled", number: 2 },
      { name: "purging", number: 3 },
      { name: "purged", number: 4 },
    ],
    `${table.name}: invalid deletion lifecycle state profile`,
  );
}

export function validateSchema(schema: PhysicalSchema, partial = false): void {
  const enums = new Map(schema.enums.map((entry) => [entry.name, entry]));
  const tables = new Map(schema.tables.map((entry) => [entry.name, entry]));
  assert.equal(tables.size, schema.tables.length, "manifest: duplicate table name");
  const indexNames = new Set<string>();
  for (const table of schema.tables) {
    validateInsertionInvariant(table);
    validatePreservedInsertion(table);
    validateInsertionStateProfile(table, enums);
    const where = `table ${table.name}`;
    assert(namePattern.test(table.name) && table.name.length <= maxName, `${where}: invalid name`);
    assert(table.columns.length > 0, `${where}: no columns`);
    const columns = new Map<string, PhysicalColumn>();
    for (const column of table.columns) {
      assert(
        namePattern.test(column.name) && column.name.length <= maxName,
        `${where}: invalid column name ${column.name}`,
      );
      assert(!columns.has(column.name), `${where}: duplicate column ${column.name}`);
      columns.set(column.name, column);
      if (column.kind === "enum") {
        assert(
          column.enumName && enums.has(column.enumName),
          `${where}.${column.name}: unknown enum ${column.enumName}`,
        );
      } else
        assert(column.enumName === undefined, `${where}.${column.name}: enum on a non-enum column`);
      if (column.kind !== "json")
        assert(column.jsonRoot === undefined, `${where}.${column.name}: root on a non-json column`);
      if (column.kind !== "text")
        assert(
          column.maxBytes === undefined,
          `${where}.${column.name}: maxBytes on a non-text column`,
        );
      if (column.monotonic)
        assert(
          column.sqlType === "INTEGER" && !column.nullable,
          `${where}.${column.name}: a monotonic column is a NOT NULL INTEGER`,
        );
    }
    assert(table.primaryKey.length > 0, `${where}: no primary key`);
    assert.equal(
      new Set(table.primaryKey).size,
      table.primaryKey.length,
      `${where}: duplicate primary key column`,
    );
    for (const key of table.primaryKey) {
      const column = columns.get(key);
      assert(column, `${where}: primary key column ${key} does not exist`);
      assert(!column.nullable, `${where}: primary key column ${key} is nullable`);
    }
    for (const index of table.indexes) {
      assert(!indexNames.has(index.name), `${where}: duplicate index name ${index.name}`);
      indexNames.add(index.name);
      assert(index.columns.length > 0, `${where}: index ${index.name} has no columns`);
      assert(index.path.length > 0, `${where}: index ${index.name} names no query path (QP-01)`);
      for (const entry of index.columns)
        assert(
          columns.has(indexColumnName(entry)),
          `${where}: index ${index.name} names unknown column ${entry}`,
        );
    }
    for (const fk of table.foreignKeys) {
      assert(
        fk.columns.length > 0 && fk.columns.length === fk.references.columns.length,
        `${where}: foreign key arity`,
      );
      for (const name of fk.columns)
        assert(columns.has(name), `${where}: foreign key column ${name} does not exist`);
      const target = tables.get(fk.references.table);
      if (!target && partial) continue;
      assert(target, `${where}: foreign key references unknown table ${fk.references.table}`);
      const targetColumns = new Map(target.columns.map((entry) => [entry.name, entry]));
      for (const name of fk.references.columns)
        assert(
          targetColumns.has(name),
          `${where}: foreign key target column ${fk.references.table}.${name} does not exist`,
        );
      const targetKey = fk.references.columns.join(",");
      const keys = [
        target.primaryKey.join(","),
        ...target.indexes
          .filter((entry) => entry.unique && entry.where === undefined)
          .map((entry) => entry.columns.join(",")),
      ];
      assert(
        keys.includes(targetKey),
        `${where}: foreign key target ${fk.references.table}(${targetKey}) is neither its primary key nor a unique index`,
      );
      fk.columns.forEach((name, position) => {
        const local = columns.get(name);
        const remote = targetColumns.get(fk.references.columns[position] ?? "");
        assert(
          local && remote && local.sqlType === remote.sqlType && local.kind === remote.kind,
          `${where}: foreign key ${name} type differs from its target`,
        );
      });
      if (fk.onDelete === "setNull")
        for (const name of fk.columns)
          assert(columns.get(name)?.nullable, `${where}: set null needs nullable ${name}`);
      if (fk.onDelete === "cascade")
        assert(
          target.mutability.delete === "any" && table.mutability.delete === "any",
          `${where}: cascade into or from a no-delete table`,
        );
    }
    const checkNames = new Set<string>();
    for (const check of table.checks) {
      assert(
        /^[a-z][a-z0-9_]*$/u.test(check.name) && !checkNames.has(check.name),
        `${where}: check name ${check.name}`,
      );
      checkNames.add(check.name);
    }
    const update = table.mutability.update;
    if (typeof update === "object")
      for (const name of update.columns)
        assert(columns.has(name), `${where}: mutability names unknown column ${name}`);
    if (table.fts5) {
      assert(table.fts5.name.startsWith(ownerPrefix(table)), `${where}: fts5 name`);
      for (const name of table.fts5.columns)
        assert(columns.has(name), `${where}: fts5 column ${name}`);
      assert(columns.has("scope_key"), `${where}: an FTS5 table needs a scope_key column`);
      assert(table.fts5.columns[0] === "scope_key", `${where}: scope_key is the first FTS5 column`);
    }
  }
  const usedEnums = new Set<string>();
  for (const table of schema.tables)
    for (const column of table.columns) if (column.enumName) usedEnums.add(column.enumName);
  const complete =
    !partial &&
    schema.owners.every((entry) => schema.tables.some((table) => table.owner === entry.owner));
  if (complete)
    for (const entry of schema.enums)
      assert(usedEnums.has(entry.name), `enum ${entry.name} is registered but used by no column`);
}

function ownerPrefix(table: PhysicalTable): string {
  return `${table.owner.replaceAll("-", "_")}_`;
}

/** The plan parameter kind a physical column is bound and read as through the named-plan bridge (worker/storage/plan-types.ts). */
export function planKindOf(
  kind: PhysicalKind,
): "int64" | "uint64" | "decimal" | "text" | "bytes" | "bool" {
  switch (kind) {
    case "bool":
      return "bool";
    case "int":
    case "int64":
    case "rev":
    case "instant":
    case "enum":
      return "int64";
    case "uint64":
      return "uint64";
    case "decimal":
      return "decimal";
    case "hash":
    case "bytes":
    case "proto":
      return "bytes";
    default:
      return "text";
  }
}

export function columnGroupChecks(table: PhysicalTable): ManifestCheck[] {
  return groupChecks(table);
}

export function columnDefinition(
  table: PhysicalTable,
  column: PhysicalColumn,
  enums: Map<string, ResolvedEnum>,
): string {
  const parts = [quote(column.name), column.sqlType];
  if (!column.nullable) parts.push("NOT NULL");
  const expression = columnCheck(column, enums);
  if (expression)
    parts.push(`CONSTRAINT ${quote(`ck_${table.name}__${column.name}`)} CHECK (${expression})`);
  if (column.generated)
    parts.push(
      `CONSTRAINT ${quote(`ck_${table.name}__${column.name}__derived`)} CHECK (${quote(column.name)} = ${column.generated})`,
    );
  return `  ${parts.join(" ")}`;
}

/** Both-null-or-both-present for every expanded field (money, aggregate reference) that is nullable. */
function groupChecks(table: PhysicalTable): ManifestCheck[] {
  const groups = new Map<string, string[]>();
  for (const column of table.columns) {
    if (!column.group || !column.nullable) continue;
    groups.set(column.group.field, [...(groups.get(column.group.field) ?? []), column.name]);
  }
  return [...groups.entries()].map(([field, names]) => ({
    name: `both_or_none_${field}`,
    sql: `(${names.map((name) => `${quote(name)} IS NULL`).join(" AND ")}) OR (${names.map((name) => `${quote(name)} IS NOT NULL`).join(" AND ")})`,
  }));
}

export function tableSql(table: PhysicalTable, enums: Map<string, ResolvedEnum>): string[] {
  validateInsertionInvariant(table);
  validatePreservedInsertion(table);
  validateInsertionStateProfile(table, enums);
  const statements: string[] = [];
  const lines = table.columns.map((column) => columnDefinition(table, column, enums));
  lines.push(
    `  CONSTRAINT ${quote(`pk_${table.name}`)} PRIMARY KEY (${table.primaryKey.map(quote).join(", ")})`,
  );
  table.foreignKeys.forEach((fk, position) => {
    const action = { restrict: "RESTRICT", cascade: "CASCADE", setNull: "SET NULL" }[fk.onDelete];
    lines.push(
      `  CONSTRAINT ${quote(`fk_${table.name}__${fk.columns.join("_")}`)} FOREIGN KEY (${fk.columns.map(quote).join(", ")}) REFERENCES ${quote(fk.references.table)} (${fk.references.columns.map(quote).join(", ")}) ON DELETE ${action}`,
    );
    void position;
  });
  for (const check of [...groupChecks(table), ...table.checks])
    lines.push(`  CONSTRAINT ${quote(`ck_${table.name}__${check.name}`)} CHECK (${check.sql})`);
  // A single INTEGER primary key column would be a rowid alias: SQLite then turns an inserted NULL into a generated value instead of
  // refusing it. Such a table is WITHOUT ROWID so that NOT NULL means what it says.
  const keyColumn =
    table.primaryKey.length === 1
      ? table.columns.find((column) => column.name === table.primaryKey[0])
      : undefined;
  const withoutRowid = keyColumn?.sqlType === "INTEGER" && !table.fts5;
  statements.push(
    `CREATE TABLE ${quote(table.name)} (\n${lines.join(",\n")}\n) STRICT${withoutRowid ? ", WITHOUT ROWID" : ""}`,
  );
  for (const index of table.indexes) {
    statements.push(
      `CREATE ${index.unique ? "UNIQUE " : ""}INDEX ${quote(index.name)} ON ${quote(table.name)} (${index.columns
        .map((entry) => {
          const match = /^(.*?)(\s+(?:ASC|DESC))?$/iu.exec(entry);
          return `${quote(match?.[1] ?? entry)}${match?.[2] ?? ""}`;
        })
        .join(", ")})${index.where ? ` WHERE ${index.where}` : ""}`,
    );
  }
  for (const trigger of triggerSql(table)) statements.push(trigger);
  return statements;
}

export function triggerSql(table: PhysicalTable): string[] {
  validateInsertionInvariant(table);
  validatePreservedInsertion(table);
  const out: string[] = [];
  if (table.insertionInvariant === "deletionLifecycleOriginal")
    out.push(
      `CREATE TRIGGER "tr_identity_account_deletion__original_insert" BEFORE INSERT ON "identity_account_deletion"\nWHEN EXISTS (SELECT 1 FROM "identity_account_deletion" WHERE "deletion_id" = NEW."deletion_id") OR (NEW."state" IN (1, 3) AND EXISTS (SELECT 1 FROM "identity_account_deletion" WHERE "user_id" = NEW."user_id" AND "state" IN (1, 3)))\nBEGIN\n  SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_identity_account_deletion');\nEND`,
    );
  const message = (kind: string) => `CHECK constraint failed: af_${kind}`;
  if (table.mutability.insert === "preserveExisting") {
    const key = table.primaryKey
      .map((name) => `existing.${quote(name)} IS NEW.${quote(name)}`)
      .join(" AND ");
    const equal = table.columns
      .map((column) => `existing.${quote(column.name)} IS NEW.${quote(column.name)}`)
      .join(" AND ");
    out.push(
      `CREATE TRIGGER ${quote(`tr_${table.name}__immutable_insert`)} BEFORE INSERT ON ${quote(table.name)}\nWHEN EXISTS (SELECT 1 FROM ${quote(table.name)} existing WHERE ${key})\nBEGIN\n  SELECT CASE WHEN EXISTS (SELECT 1 FROM ${quote(table.name)} existing WHERE ${key} AND ${equal}) THEN RAISE(IGNORE) ELSE RAISE(ABORT, ${sqlString(message(`immutable_${table.name}`))}) END;\nEND`,
    );
  }
  const update = table.mutability.update;
  if (update === "none") {
    out.push(
      `CREATE TRIGGER ${quote(`tr_${table.name}__immutable_update`)} BEFORE UPDATE ON ${quote(table.name)}\nBEGIN\n  SELECT RAISE(ABORT, ${sqlString(message(`immutable_${table.name}`))});\nEND`,
    );
  } else if (typeof update === "object") {
    const allowed = new Set(update.columns);
    const changed = table.columns
      .filter((column) => !allowed.has(column.name))
      .map((column) => `OLD.${quote(column.name)} IS NOT NEW.${quote(column.name)}`);
    const conditions = [
      ...(changed.length > 0 ? [`(${changed.join(" OR ")})`] : []),
      ...(update.when ? [`NOT (${update.when})`] : []),
    ];
    assert(conditions.length > 0, `${table.name}: a mutability object that limits nothing`);
    out.push(
      `CREATE TRIGGER ${quote(`tr_${table.name}__limited_update`)} BEFORE UPDATE ON ${quote(table.name)}\nWHEN ${conditions.join(" OR ")}\nBEGIN\n  SELECT RAISE(ABORT, ${sqlString(message(`immutable_${table.name}`))});\nEND`,
    );
  }
  if (table.mutability.delete === "none") {
    out.push(
      `CREATE TRIGGER ${quote(`tr_${table.name}__immutable_delete`)} BEFORE DELETE ON ${quote(table.name)}\nBEGIN\n  SELECT RAISE(ABORT, ${sqlString(message(`immutable_${table.name}`))});\nEND`,
    );
  }
  for (const column of table.columns) {
    if (!column.monotonic) continue;
    out.push(
      `CREATE TRIGGER ${quote(`tr_${table.name}__monotonic_${column.name}`)} BEFORE UPDATE OF ${quote(column.name)} ON ${quote(table.name)}\nWHEN NEW.${quote(column.name)} < OLD.${quote(column.name)}\nBEGIN\n  SELECT RAISE(ABORT, ${sqlString(message(`monotonic_${table.name}_${column.name}`))});\nEND`,
    );
  }
  return out;
}

/** The FTS5 virtual table and the triggers that keep its external-content index in step with the owning table. */
export function fts5Sql(table: PhysicalTable): string[] {
  const fts = table.fts5;
  if (!fts) return [];
  const names = fts.columns.map(quote).join(", ");
  const newValues = fts.columns.map((name) => `new.${quote(name)}`).join(", ");
  const oldValues = fts.columns.map((name) => `old.${quote(name)}`).join(", ");
  const ft = quote(fts.name);
  const t = quote(table.name);
  return [
    `CREATE VIRTUAL TABLE ${ft} USING fts5(${names}, content=${sqlString(table.name)}, content_rowid='rowid', tokenize=${sqlString(fts.tokenize)})`,
    `CREATE TRIGGER ${quote(`tr_${table.name}__fts_insert`)} AFTER INSERT ON ${t}\nBEGIN\n  INSERT INTO ${ft} (rowid, ${names}) VALUES (new.rowid, ${newValues});\nEND`,
    `CREATE TRIGGER ${quote(`tr_${table.name}__fts_delete`)} AFTER DELETE ON ${t}\nBEGIN\n  INSERT INTO ${ft} (${ft}, rowid, ${names}) VALUES ('delete', old.rowid, ${oldValues});\nEND`,
    `CREATE TRIGGER ${quote(`tr_${table.name}__fts_update`)} AFTER UPDATE ON ${t}\nBEGIN\n  INSERT INTO ${ft} (${ft}, rowid, ${names}) VALUES ('delete', old.rowid, ${oldValues});\n  INSERT INTO ${ft} (rowid, ${names}) VALUES (new.rowid, ${newValues});\nEND`,
  ];
}

export function enumMap(schema: PhysicalSchema): Map<string, ResolvedEnum> {
  return new Map(schema.enums.map((entry) => [entry.name, entry]));
}

/** Every statement that creates the whole manifest schema, in a dependency-neutral order. */
export function schemaStatements(
  schema: PhysicalSchema,
  filter: (table: PhysicalTable) => boolean = () => true,
  part: "all" | "tables" | "fts5" = "all",
): string[] {
  const enums = enumMap(schema);
  const selected = schema.tables.filter(filter);
  const statements: string[] = [];
  const virtual: string[] = [];
  for (const table of selected) {
    statements.push(...tableSql(table, enums));
    virtual.push(...fts5Sql(table));
  }
  return part === "tables" ? statements : part === "fts5" ? virtual : [...statements, ...virtual];
}

export function schemaHash(schema: PhysicalSchema): string {
  const canonical = JSON.stringify({ enums: schema.enums, tables: schema.tables });
  return createHash("sha256").update(canonical).digest("hex");
}

// ---------------------------------------------------------------------------------------------------------------
// Drift check: the numbered migrations applied to an empty database must equal the manifest.
// ---------------------------------------------------------------------------------------------------------------

export interface DatabaseShape {
  tables: Record<
    string,
    {
      columns: { name: string; type: string; notNull: boolean; primaryKeyPosition: number }[];
      foreignKeys: string[];
      indexes: string[];
      triggers: string[];
      strict: boolean;
      /** Every named CHECK with its normalized expression: a widened enum or a loosened rule is a difference, not only a missing name. */
      checks: Record<string, string>;
      /** Every index and trigger with its normalized definition (a trigger's WHEN condition and column list included). */
      definitions: Record<string, string>;
    }
  >;
}

const collapse = (sql: string) => sql.replace(/\s+/gu, " ").trim();

/** The named CHECK constraints of a CREATE TABLE text with their expressions, found by balanced parentheses outside quotes. */
export function extractChecks(sql: string): Record<string, string> {
  const found: [string, string][] = [];
  const pattern = /CONSTRAINT\s+"([^"]+)"\s+CHECK\s*\(/giu;
  for (let match = pattern.exec(sql); match; match = pattern.exec(sql)) {
    let depth = 1;
    let quoteMark = "";
    let index = pattern.lastIndex;
    for (; index < sql.length && depth > 0; index++) {
      const char = sql[index] as string;
      if (quoteMark) {
        if (char === quoteMark) quoteMark = "";
      } else if (char === "'" || char === '"') quoteMark = char;
      else if (char === "(") depth++;
      else if (char === ")") depth--;
    }
    found.push([match[1] ?? "", collapse(sql.slice(pattern.lastIndex, index - 1))]);
    pattern.lastIndex = index;
  }
  return Object.fromEntries(found.sort(([a], [b]) => a.localeCompare(b, "en")));
}

const afterWord = (sql: string, word: string) => sql.toLowerCase().includes(word);

/** Reads the physical structure of an open database with pragmas only. */
export function readShape(database: DatabaseSync): DatabaseShape {
  const rows = database
    .prepare(
      "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .all() as { name: string; sql: string }[];
  const virtualNames = new Set(
    rows.filter((row) => /^CREATE VIRTUAL TABLE/iu.test(row.sql)).map((row) => row.name),
  );
  const shadows = [...virtualNames].flatMap((name) =>
    ["_data", "_idx", "_content", "_docsize", "_config"].map((suffix) => `${name}${suffix}`),
  );
  const shape: DatabaseShape = { tables: {} };
  for (const row of rows) {
    if (virtualNames.has(row.name) || shadows.includes(row.name)) continue;
    const info = database.prepare(`PRAGMA table_info(${quote(row.name)})`).all() as {
      name: string;
      type: string;
      notnull: number;
      pk: number;
    }[];
    const foreign = database.prepare(`PRAGMA foreign_key_list(${quote(row.name)})`).all() as {
      id: number;
      seq: number;
      table: string;
      from: string;
      to: string;
      on_delete: string;
    }[];
    const grouped = new Map<number, typeof foreign>();
    for (const entry of foreign) grouped.set(entry.id, [...(grouped.get(entry.id) ?? []), entry]);
    const foreignKeys = [...grouped.values()].map((entries) => {
      const ordered = entries.sort((a, b) => a.seq - b.seq);
      return `${ordered.map((entry) => entry.from).join(",")}->${ordered[0]?.table}(${ordered.map((entry) => entry.to).join(",")}) ${ordered[0]?.on_delete}`;
    });
    const indexes = (
      database.prepare(`PRAGMA index_list(${quote(row.name)})`).all() as {
        name: string;
        unique: number;
        origin: string;
        partial: number;
      }[]
    )
      .filter((entry) => entry.origin === "c")
      .map((entry) => {
        const columns = (
          database.prepare(`PRAGMA index_xinfo(${quote(entry.name)})`).all() as {
            name: string | null;
            desc: number;
            key: number;
          }[]
        )
          .filter((column) => column.key === 1)
          .map((column) => `${column.name}${column.desc ? " DESC" : ""}`);
        const definition = database
          .prepare("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?")
          .get(entry.name) as { sql: string };
        const where = /\sWHERE\s(.*)$/isu.exec(definition.sql)?.[1] ?? "";
        return `${entry.name}|${entry.unique ? "unique" : "plain"}|${columns.join(",")}|${where}`;
      });
    const triggers = (
      database
        .prepare(
          "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ? ORDER BY name",
        )
        .all(row.name) as { name: string }[]
    ).map((entry) => entry.name);
    const checks = extractChecks(row.sql);
    const definitions: Record<string, string> = {};
    for (const entry of database
      .prepare(
        "SELECT name, sql FROM sqlite_master WHERE type IN ('index', 'trigger') AND tbl_name = ? AND sql IS NOT NULL ORDER BY name",
      )
      .all(row.name) as { name: string; sql: string }[])
      definitions[entry.name] = collapse(entry.sql);
    shape.tables[row.name] = {
      columns: info.map((column) => ({
        name: column.name,
        type: column.type,
        notNull: column.notnull === 1 || column.pk > 0,
        primaryKeyPosition: column.pk,
      })),
      foreignKeys: foreignKeys.sort(),
      indexes: indexes.sort(),
      triggers,
      strict: afterWord(row.sql.slice(row.sql.lastIndexOf(")")), "strict"),
      checks,
      definitions,
    };
  }
  return shape;
}

/** The shape the manifest promises, computed without executing it. */
export function expectedShape(schema: PhysicalSchema): DatabaseShape {
  const enums = enumMap(schema);
  const shape: DatabaseShape = { tables: {} };
  for (const table of schema.tables) {
    const generated = [...tableSql(table, enums), ...fts5Sql(table)];
    const checks = extractChecks(generated[0] ?? "");
    const definitions: Record<string, string> = {};
    for (const statement of generated) {
      const named = /^CREATE (?:UNIQUE )?(?:INDEX|TRIGGER) "([^"]+)"/u.exec(statement);
      if (named) definitions[named[1] ?? ""] = collapse(statement);
    }
    shape.tables[table.name] = {
      columns: table.columns.map((column) => ({
        name: column.name,
        type: column.sqlType,
        notNull: !column.nullable || table.primaryKey.includes(column.name),
        primaryKeyPosition: table.primaryKey.includes(column.name)
          ? table.primaryKey.indexOf(column.name) + 1
          : 0,
      })),
      foreignKeys: table.foreignKeys
        .map(
          (fk) =>
            `${fk.columns.join(",")}->${fk.references.table}(${fk.references.columns.join(",")}) ${{ restrict: "RESTRICT", cascade: "CASCADE", setNull: "SET NULL" }[fk.onDelete]}`,
        )
        .sort(),
      indexes: table.indexes
        .map(
          (index) =>
            `${index.name}|${index.unique ? "unique" : "plain"}|${index.columns.join(",")}|${index.where ?? ""}`,
        )
        .sort(),
      triggers: triggerSql(table)
        .map((statement) => /CREATE TRIGGER "([^"]+)"/u.exec(statement)?.[1] ?? "")
        .concat(
          fts5Sql(table)
            .filter((statement) => statement.startsWith("CREATE TRIGGER"))
            .map((statement) => /CREATE TRIGGER "([^"]+)"/u.exec(statement)?.[1] ?? ""),
        )
        .sort(),
      strict: true,
      checks,
      definitions: Object.fromEntries(
        Object.entries(definitions).sort(([a], [b]) => a.localeCompare(b, "en")),
      ),
    };
  }
  return shape;
}

export function compareShapes(actual: DatabaseShape, expected: DatabaseShape): string[] {
  const problems: string[] = [];
  for (const name of Object.keys(expected.tables))
    if (!(name in actual.tables))
      problems.push(`table ${name} is in the manifest but not in the migrations`);
  for (const name of Object.keys(actual.tables))
    if (!(name in expected.tables))
      problems.push(`table ${name} is in the migrations but not in the manifest`);
  for (const [name, want] of Object.entries(expected.tables)) {
    const have = actual.tables[name];
    if (!have) continue;
    const compare = (label: string, a: unknown, b: unknown) => {
      if (JSON.stringify(a) !== JSON.stringify(b))
        problems.push(
          `${name}: ${label} differ (migrations ${JSON.stringify(a)} manifest ${JSON.stringify(b)})`,
        );
    };
    compare("columns", have.columns, want.columns);
    compare("foreign keys", have.foreignKeys, want.foreignKeys);
    compare("indexes", have.indexes, want.indexes);
    compare("triggers", have.triggers, want.triggers);
    compare("check constraints", have.checks, want.checks);
    compare("index and trigger definitions", have.definitions, want.definitions);
    if (have.strict !== want.strict) problems.push(`${name}: STRICT differs`);
  }
  return problems;
}

/** Applies the numbered migrations to an empty in-memory database and returns the drift problems against the manifest. */
export function driftProblems(schema: PhysicalSchema, directory = migrationsDirectory): string[] {
  const database = new DatabaseSync(":memory:");
  try {
    database.exec("PRAGMA foreign_keys = ON");
    const files = readdirSync(directory)
      .filter((file) => /^\d{4}_.+\.sql$/u.test(file))
      .sort();
    for (const file of files) database.exec(readFileSync(path.join(directory, file), "utf8"));
    const shape = readShape(database);
    // The migration bookkeeping tables are part of the manifest like every other table.
    return compareShapes(shape, expectedShape(schema));
  } finally {
    database.close();
  }
}

// ---------------------------------------------------------------------------------------------------------------
// C# column maps
// ---------------------------------------------------------------------------------------------------------------

const csKind: Record<PhysicalKind, string> = {
  id: "Id",
  text: "Text",
  key: "Key",
  productId: "ProductId",
  modelId: "ModelId",
  bool: "Bool",
  int: "Int32",
  int64: "Int64",
  rev: "Rev",
  instant: "Instant",
  uint64: "Uint64",
  decimal: "Decimal",
  currency: "Currency",
  hash: "Hash",
  bytes: "Bytes",
  proto: "Proto",
  json: "Json",
  enum: "Enum",
};
const pascal = (name: string) =>
  name
    .split(/[_.-]/u)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join("");
const csString = (value: string) => JSON.stringify(value);

export function emitCSharp(
  schema: PhysicalSchema,
  lock: { highest: number; hash: string },
): string {
  const out: string[] = [];
  out.push("// <auto-generated>");
  out.push(
    "// Generated by eng/verification/physical-schema.ts from Physical/manifest; do not edit by hand.",
  );
  out.push("// </auto-generated>");
  out.push("// SPDX-License-Identifier: AGPL-3.0-only");
  out.push("namespace ArcForges.Cloud.Storage.Physical;");
  out.push("");
  out.push(
    "/// <summary>The checked-in physical schema of the Cloud D1 database: closed enum registry, tables and columns.</summary>",
  );
  out.push("internal static partial class PhysicalSchema");
  out.push("{");
  out.push(
    `    /// <summary>SHA-256 of the canonical expanded manifest (enum registry and every table).</summary>`,
  );
  out.push(`    public const string ManifestHash = ${csString(schemaHash(schema))};`);
  out.push("");
  out.push(
    `    /// <summary>The highest numbered migration whose checksum the migration lock holds (the StorageSchemaVersion).</summary>`,
  );
  out.push(`    public const int HighestMigration = ${lock.highest};`);
  out.push("");
  out.push(
    `    /// <summary>SHA-256 over the ordered sequence and checksum of every locked migration.</summary>`,
  );
  out.push(`    public const string MigrationLockHash = ${csString(lock.hash)};`);
  out.push("");
  out.push("    public static IReadOnlyList<PhysicalEnum> Enums { get; } =");
  out.push("    [");
  for (const entry of schema.enums) {
    out.push(
      `        new(${csString(entry.name)}, ${entry.preserveUnknown ? "true" : "false"}, [${entry.members.map((member) => `new(${csString(member.name)}, ${member.number})`).join(", ")}]),`,
    );
  }
  out.push("    ];");
  out.push("");
  for (const table of schema.tables) {
    out.push(`    public static PhysicalTable ${pascal(table.name)} { get; } = new(`);
    out.push(`        ${csString(table.name)},`);
    out.push(`        ${csString(table.owner)},`);
    out.push("        [");
    for (const column of table.columns) {
      const extras = [
        column.enumName ? `EnumName: ${csString(column.enumName)}` : "",
        column.jsonRoot ? `JsonRoot: PhysicalJsonRoot.${pascal(column.jsonRoot)}` : "",
        column.maxBytes !== undefined ? `MaxBytes: ${column.maxBytes}` : "",
      ].filter(Boolean);
      out.push(
        `            new(${csString(column.name)}, PhysicalKind.${csKind[column.kind]}, ${column.nullable ? "true" : "false"}${extras.length > 0 ? `, ${extras.join(", ")}` : ""}),`,
      );
    }
    out.push("        ],");
    out.push(`        [${table.primaryKey.map(csString).join(", ")}]);`);
    out.push("");
  }
  out.push("    public static IReadOnlyList<PhysicalTable> Tables { get; } =");
  out.push("    [");
  for (const table of schema.tables) out.push(`        ${pascal(table.name)},`);
  out.push("    ];");
  out.push("}");
  out.push("");
  return out.join("\n");
}

// ---------------------------------------------------------------------------------------------------------------
// Baseline migrations (emitted once for this task; later changes are authored migrations plus a manifest edit)
// ---------------------------------------------------------------------------------------------------------------

/** Module order of the baseline: infrastructure first, then every module in dependency-friendly order. */
export const baselineOrder = [
  "platform",
  "config",
  "identity",
  "device",
  "workspace",
  "entitlement",
  "commerce",
  "audit",
  "support",
  "agent",
  "chat",
  "task",
  "sync",
  "resource",
  "search",
  "notification",
  "policy",
  "scope",
  "package-catalog",
  "trustsafety",
];

export function emitBaseline(
  schema: PhysicalSchema,
): { file: string; module: string; text: string }[] {
  const results: { file: string; module: string; text: string }[] = [];
  const present = new Set(schema.tables.map((table) => table.owner));
  const order = baselineOrder.filter((entry) => present.has(entry));
  for (const owner of present) assert(order.includes(owner), `baseline order lacks owner ${owner}`);
  const bookkeeping = schemaStatements(schema, (table) => table.bootstrap);
  results.push({
    file: "0000_platform__bookkeeping.sql",
    module: "platform",
    text: `-- af-migration: module=platform mode=expand\n-- The migration bookkeeping tables (Design D1 profile section 6). The runner applies this file first, together with its own receipt.\n${bookkeeping.map((statement) => `${statement};\n`).join("\n")}`,
  });
  order.forEach((owner, position) => {
    const sequence = position + 1;
    const statements = schemaStatements(
      schema,
      (table) => table.owner === owner && !table.bootstrap,
      "tables",
    );
    const header = `-- af-migration: module=${owner} mode=expand\n-- Baseline physical schema of the ${owner} owner (generated from Physical/manifest/${owner}.json; Design D1 profile section 2).\n`;
    results.push({
      file: `${String(sequence).padStart(4, "0")}_${owner}__baseline.sql`,
      module: owner,
      text: `${header}${statements.map((statement) => `${statement};\n`).join("\n")}`,
    });
  });
  // Virtual tables are kept in their own migration: the provider's export cannot carry them (model 04 section 7), so an
  // operations procedure may need to drop and rebuild exactly this part.
  for (const owner of order) {
    const statements = schemaStatements(
      schema,
      (table) => table.owner === owner && !table.bootstrap,
      "fts5",
    );
    if (statements.length === 0) continue;
    const sequence = results.length;
    results.push({
      file: `${String(sequence).padStart(4, "0")}_${owner}__fts5.sql`,
      module: owner,
      text: `-- af-migration: module=${owner} mode=expand\n-- The D1 FTS5 virtual table and its index triggers (derived, rebuildable data; Design D1 profile section 8).\n${statements.map((statement) => `${statement};\n`).join("\n")}`,
    });
  }
  return results;
}

function main(argv: string[]): void {
  if (argv.includes("--validate") || argv.includes("--enums")) {
    // Authoring aid: tolerate foreign keys to owners whose manifest is not written yet.
    const partial = loadManifest(manifestDirectory, true);
    if (argv.includes("--enums")) {
      for (const entry of partial.enums)
        process.stdout
          .write(`${entry.name}: ${entry.members.map((member) => `${member.name}=${member.number}`).join(", ")}
`);
      return;
    }
    const database = new DatabaseSync(":memory:");
    for (const statement of schemaStatements(partial)) database.exec(statement);
    database.close();
    process.stdout
      .write(`manifest valid (partial): ${partial.tables.length} tables, ${partial.enums.length} enums
`);
    return;
  }
  const schema = loadManifest();
  const lock = lockIdentity(readLock(migrationsDirectory));
  if (argv.includes("--emit-baseline")) {
    for (const entry of emitBaseline(schema))
      writeFileSync(path.join(migrationsDirectory, entry.file), entry.text);
    return;
  }
  const generated = emitCSharp(schema, lock);
  if (argv.includes("--check")) {
    const problems: string[] = [];
    const current = existsSync(generatedCSharp) ? readFileSync(generatedCSharp, "utf8") : "";
    if (current.replaceAll("\r\n", "\n") !== generated)
      problems.push(
        `${path.relative(repositoryRoot, generatedCSharp)} is stale; run node eng/verification/physical-schema.ts`,
      );
    problems.push(...driftProblems(schema));
    if (problems.length > 0) {
      for (const problem of problems) process.stderr.write(`${problem}\n`);
      process.exitCode = 1;
      return;
    }
    process.stdout.write(
      `physical schema ok: ${schema.tables.length} tables, ${schema.enums.length} enums, ${schemaHash(schema).slice(0, 12)}\n`,
    );
    return;
  }
  writeFileSync(generatedCSharp, generated);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  main(process.argv.slice(2));
