// SPDX-License-Identifier: AGPL-3.0-only
// Conformance of the physical D1 schema (Design D1 profile section 2; data model 01 section 13 CV-01 to CV-03): the numbered
// migrations applied to an empty database equal the manifest, every table accepts a valid typical and a valid extreme row and
// returns every field exactly, every column check refuses its negative case, every declared foreign key and every immutability
// and monotonic trigger fires. SQLite is the oracle: it proves the SQL, the constraints and the triggers, not Cloudflare's network
// path or limits (the opt-in local D1 run repeats the type vectors against workerd's D1).
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import {
  columnCheck,
  compareShapes,
  driftProblems,
  enumMap,
  expectedShape,
  loadManifest,
  migrationsDirectory,
  readShape,
  tableSql,
  triggerSql,
  validateSchema,
  type PhysicalSchema,
  type PhysicalTable,
} from "../../eng/verification/physical-schema.ts";
import { classifyError } from "../../worker/storage/execute-plan.ts";
import {
  copyFileSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  buildAcceptedRow,
  bindRow,
  insertRow,
  insertStatement,
  readBack,
  rowsEqual,
  violatingValue,
  type Row,
} from "./support/physical-rows.ts";

const schema = loadManifest();
const enums = enumMap(schema);

function migratedDatabase(foreignKeys: boolean): DatabaseSync {
  const database = new DatabaseSync(":memory:");
  const files = readdirSync(migrationsDirectory)
    .filter((file) => /^\d{4}_.+\.sql$/u.test(file))
    .sort();
  for (const file of files)
    database.exec(readFileSync(path.join(migrationsDirectory, file), "utf8"));
  database.exec(`PRAGMA foreign_keys = ${foreignKeys ? "ON" : "OFF"}`);
  return database;
}

const tableOf = (name: string): PhysicalTable => {
  const table = schema.tables.find((entry) => entry.name === name);
  assert(table, name);
  return table;
};

test("the manifest covers every owner and keeps every table inside its owner's prefix", () => {
  assert.equal(schema.tables.length, 162);
  for (const owner of schema.owners) {
    const tables = schema.tables.filter((table) => table.owner === owner.owner);
    assert(tables.length > 0, `owner ${owner.owner} has no table`);
    for (const table of tables)
      assert(
        table.name.startsWith(owner.tablePrefix),
        `${table.name} is outside ${owner.tablePrefix}`,
      );
  }
  // The retired workspace membership table is not resurrected (WO-01 to WO-05).
  assert(!schema.tables.some((table) => /membership|invitation|seat/u.test(table.name)));
});

test("the numbered migrations applied to an empty database equal the manifest", () => {
  const database = migratedDatabase(true);
  assert.deepEqual(compareShapes(readShape(database), expectedShape(schema)), []);
  assert.deepEqual(database.prepare("PRAGMA foreign_key_check").all(), []);
  assert.deepEqual(
    database
      .prepare("PRAGMA integrity_check")
      .all()
      .map((row) => Object.values(row)[0]),
    ["ok"],
  );
});

test("every table accepts a valid typical row and a valid extreme row and returns every field exactly (CV-01)", () => {
  for (const variant of [{ boundary: false }, { boundary: true }]) {
    const database = migratedDatabase(false);
    let serial = 1;
    for (const table of schema.tables) {
      const built = buildAcceptedRow(database, schema, table, variant, serial++);
      insertRow(database, table, built.row);
      const rows = readBack(database, table);
      assert.equal(rows.length, 1, table.name);
      const stored = rows[0] as Row;
      assert(
        rowsEqual(table, stored, built.row),
        `${table.name} did not return the row it stored (${variant.boundary ? "extreme" : "typical"})`,
      );
      // Nullability: a nullable column that is null stays null and is not turned into a default.
      for (const column of table.columns)
        if (built.row[column.name] === null)
          assert.equal(stored[column.name], null, `${table.name}.${column.name}`);
    }
  }
});

test("every column refuses its negative case and every NOT NULL column refuses null (CV-03)", () => {
  const database = migratedDatabase(false);
  let serial = 1000;
  let refusals = 0;
  for (const table of schema.tables) {
    const built = buildAcceptedRow(database, schema, table, { boundary: false }, serial++);
    // Use a row with every nullable column filled, so that a refusal can only come from the column under test.
    const full = buildAcceptedRow(database, schema, table, { boundary: true }, serial++).row;
    for (const column of table.columns) {
      const bad = violatingValue(column, enums);
      if (bad !== undefined) {
        const row = { ...full, [column.name]: bad };
        assert.throws(
          () => insertRow(database, table, row),
          (error: Error) => {
            assert.match(
              error.message,
              /CHECK constraint failed/u,
              `${table.name}.${column.name}: ${error.message}`,
            );
            return true;
          },
        );
        refusals++;
      }
      if (!column.nullable) {
        const row = { ...built.row, [column.name]: null };
        assert.throws(
          () => insertRow(database, table, row),
          /NOT NULL constraint failed|PRIMARY KEY/u,
          `${table.name}.${column.name}`,
        );
        refusals++;
      }
    }
  }
  assert(refusals > 1500, `only ${refusals} negative cases ran`);
});

test("every declared foreign key is enforced, restrict by default and cascade where the model says so", () => {
  const database = migratedDatabase(true);
  let serial = 5000;
  let checked = 0;
  for (const table of schema.tables) {
    for (const fk of table.foreignKeys) {
      const row = buildAcceptedRow(
        migratedDatabase(false),
        schema,
        table,
        { boundary: true },
        serial++,
      ).row;
      // Every foreign key column is non-null in the extreme row, so the parent row is required.
      if (fk.columns.some((name) => row[name] === null)) continue;
      assert.throws(
        () => insertRow(database, table, row),
        /FOREIGN KEY constraint failed|CHECK constraint failed/u,
        `${table.name} -> ${fk.references.table}`,
      );
      checked++;
    }
  }
  assert(checked > 50, `only ${checked} foreign keys were exercised`);
});

test("restrict blocks deleting a referenced parent and cascade removes the children, on a real parent and child", () => {
  const database = migratedDatabase(true);
  const user = tableOf("identity_user");
  const email = tableOf("identity_email_address");
  const device = tableOf("device_device");
  const installation = tableOf("device_installation");
  const parent = buildAcceptedRow(
    migratedDatabase(false),
    schema,
    user,
    { boundary: false },
    1,
  ).row;
  insertRow(database, user, parent);
  const mail = buildAcceptedRow(migratedDatabase(false), schema, email, { boundary: false }, 2).row;
  mail.user_id = parent.user_id as string;
  insertRow(database, email, mail);
  const dev = buildAcceptedRow(migratedDatabase(false), schema, device, { boundary: false }, 3).row;
  dev.user_id = parent.user_id as string;
  insertRow(database, device, dev);
  const inst = buildAcceptedRow(
    migratedDatabase(false),
    schema,
    installation,
    { boundary: false },
    4,
  ).row;
  inst.device_id = dev.device_id as string;
  insertRow(database, installation, inst);
  // device.user_id is restrict: the user cannot be deleted while a device exists.
  assert.throws(
    () => database.exec(`DELETE FROM identity_user WHERE user_id = '${parent.user_id}'`),
    /FOREIGN KEY constraint failed/u,
  );
  // installation -> device is cascade: deleting the device removes its installation.
  database.exec(`DELETE FROM device_device WHERE device_id = '${dev.device_id}'`);
  assert.equal(database.prepare("SELECT COUNT(*) AS n FROM device_installation").get()?.n, 0);
  // identity_email_address -> identity_user is cascade: deleting the user removes the address.
  database.exec(`DELETE FROM identity_user WHERE user_id = '${parent.user_id}'`);
  assert.equal(database.prepare("SELECT COUNT(*) AS n FROM identity_email_address").get()?.n, 0);
});

function firstAccepted(database: DatabaseSync, table: PhysicalTable, serial: number): Row {
  const built = buildAcceptedRow(database, schema, table, { boundary: false }, serial);
  insertRow(database, table, built.row);
  return built.row;
}

const updateStatement = (table: PhysicalTable, column: string, valueSql: string) =>
  `UPDATE "${table.name}" SET "${column}" = ${valueSql} WHERE ${table.primaryKey.map((name) => `"${name}" = ?`).join(" AND ")}`;

test("append-only and immutable tables refuse update and delete with a message the Worker classifies as a constraint", () => {
  const database = migratedDatabase(false);
  let serial = 7000;
  let covered = 0;
  for (const table of schema.tables) {
    const row = firstAccepted(database, table, serial++);
    const keys = table.primaryKey.map((name) => row[name]) as (
      string | number | bigint | Uint8Array
    )[];
    const keyParams = keys.map((value) => (typeof value === "bigint" ? String(value) : value));
    const column = table.columns.find(
      (entry) =>
        !table.primaryKey.includes(entry.name) && entry.sqlType === "TEXT" && entry.kind === "text",
    );
    if (table.mutability.update === "none" && column) {
      const error = (() => {
        try {
          database
            .prepare(updateStatement(table, column.name, "'changed'"))
            .run(...(keyParams as never[]));
          return null;
        } catch (caught) {
          return caught as Error;
        }
      })();
      assert(error, `${table.name} accepted an update`);
      assert.match(error.message, new RegExp(`af_immutable_${table.name}`, "u"));
      assert.equal(classifyError(error, "write"), "constraint");
      covered++;
    }
    if (table.mutability.delete === "none") {
      const where = table.primaryKey.map((name) => `"${name}" = ?`).join(" AND ");
      const error = (() => {
        try {
          database
            .prepare(`DELETE FROM "${table.name}" WHERE ${where}`)
            .run(...(keyParams as never[]));
          return null;
        } catch (caught) {
          return caught as Error;
        }
      })();
      assert(error, `${table.name} accepted a delete`);
      assert.match(error.message, new RegExp(`af_immutable_${table.name}`, "u"));
      assert.equal(classifyError(error, "write"), "constraint");
      covered++;
    }
    if (table.mutability.delete === "any") {
      const where = table.primaryKey.map((name) => `"${name}" = ?`).join(" AND ");
      const result = database
        .prepare(`DELETE FROM "${table.name}" WHERE ${where}`)
        .run(...(keyParams as never[]));
      assert.equal(
        Number(result.changes),
        1,
        `${table.name} must allow the delete the model allows`,
      );
    }
  }
  assert(covered >= 30, `only ${covered} immutability cases ran`);
});

test("a limited-update table changes only the allowed columns and only while its predicate holds", () => {
  // capacity_policy_period: only effective_to, only while NULL.
  const database = migratedDatabase(false);
  const table = tableOf("entitlement_capacity_policy_period");
  const row = firstAccepted(database, table, 9000);
  const key = [row.policy_period_id as string];
  assert.throws(
    () => database.prepare(updateStatement(table, "burst_micro", "5")).run(...key),
    /af_immutable_entitlement_capacity_policy_period/u,
  );
  database.prepare(updateStatement(table, "effective_to", "1790000009000000")).run(...key);
  assert.throws(
    () => database.prepare(updateStatement(table, "effective_to", "1790000009000001")).run(...key),
    /af_immutable_entitlement_capacity_policy_period/u,
  );
  // sync_change: publish_seq is assigned once.
  const change = tableOf("sync_change");
  const changeBuilt = buildAcceptedRow(database, schema, change, { boundary: false }, 9100).row;
  const changeRow: Row = { ...changeBuilt, publish_seq: null, published_at: null };
  insertRow(database, change, changeRow);
  const changeKey = [changeRow.change_id as string];
  database
    .prepare(updateStatement(change, "publish_seq", "CAST('41' AS INTEGER)"))
    .run(...changeKey);
  assert.throws(
    () =>
      database
        .prepare(updateStatement(change, "publish_seq", "CAST('42' AS INTEGER)"))
        .run(...changeKey),
    /af_immutable_sync_change/u,
  );
  // migration receipt: progress only while applying.
  const receipt = tableOf("platform_migration_receipt");
  const receiptRow = firstAccepted(database, receipt, 9200);
  const receiptKey = [String(receiptRow.sequence)];
  assert.throws(
    () =>
      database
        .prepare(updateStatement(receipt, "checksum", `'${"b".repeat(64)}'`))
        .run(...receiptKey),
    /af_immutable_platform_migration_receipt/u,
  );
});

// A monotonic column that a cross-column check bounds needs its sibling set so that 5, 9 and 8 stay inside the bound.
const monotonicSiblings: Record<string, Record<string, bigint>> = {
  "platform_sequence_stream.last_sequence": { published_watermark: 0n },
  "platform_sequence_stream.published_watermark": { last_sequence: 100n },
};

test("a monotonic column may stay or rise and may never fall", () => {
  const database = migratedDatabase(false);
  let serial = 9500;
  let covered = 0;
  for (const table of schema.tables) {
    const monotonic = table.columns.filter((column) => column.monotonic);
    if (monotonic.length === 0) continue;
    for (const column of monotonic) {
      const local = migratedDatabase(false);
      const built = buildAcceptedRow(local, schema, table, { boundary: false }, serial++);
      const row = {
        ...built.row,
        ...monotonicSiblings[`${table.name}.${column.name}`],
        [column.name]: 5n,
      };
      insertRow(local, table, row);
      const key = table.primaryKey.map((name) =>
        typeof row[name] === "bigint" ? String(row[name]) : row[name],
      ) as never[];
      local.prepare(updateStatement(table, column.name, "CAST('5' AS INTEGER)")).run(...key);
      local.prepare(updateStatement(table, column.name, "CAST('9' AS INTEGER)")).run(...key);
      assert.throws(
        () =>
          local.prepare(updateStatement(table, column.name, "CAST('8' AS INTEGER)")).run(...key),
        new RegExp(`af_monotonic_${table.name}_${column.name}`, "u"),
        `${table.name}.${column.name}`,
      );
      covered++;
    }
  }
  assert(covered >= 8, `only ${covered} monotonic columns were exercised`);
  void database;
});

test("every declared index is used for a lookup on its leading columns (CV-02, shape only)", () => {
  const database = migratedDatabase(false);
  let checked = 0;
  for (const table of schema.tables) {
    for (const index of table.indexes) {
      const columns = index.columns.map((entry) => entry.replace(/\s+(?:ASC|DESC)$/iu, ""));
      const where = [
        ...columns.map((name) => `"${name}" = ?`),
        ...(index.where ? [`(${index.where})`] : []),
      ].join(" AND ");
      const plan = database
        .prepare(`EXPLAIN QUERY PLAN SELECT 1 FROM "${table.name}" WHERE ${where}`)
        .all(...columns.map(() => "x")) as { detail: string }[];
      const text = plan.map((entry) => entry.detail).join(" | ");
      assert.match(
        text,
        /USING (?:COVERING )?INDEX|USING INTEGER PRIMARY KEY/u,
        `${table.name} index ${index.name} is not used: ${text}`,
      );
      checked++;
    }
  }
  assert(checked > 150, `only ${checked} indexes were checked`);
});

test("every index names the query path it serves (QP-01) and the foreign keys across modules are exactly the declared ones", () => {
  const crossModule: string[] = [];
  for (const table of schema.tables) {
    for (const index of table.indexes)
      assert(index.path.trim().length > 3, `${table.name}: ${index.name}`);
    for (const fk of table.foreignKeys) {
      const target = schema.tables.find((entry) => entry.name === fk.references.table);
      if (target && target.owner !== table.owner)
        crossModule.push(`${table.name} -> ${fk.references.table}`);
    }
  }
  crossModule.sort();
  assert.deepEqual(crossModule, expectedCrossModuleForeignKeys);
});

// The foreign keys that model 01 declares across modules and the physical manifest keeps (model 04 section 2: preserve FKs).
// A new cross-module foreign key is an Architecture Owner decision: it changes this list in the same reviewed change.
const expectedCrossModuleForeignKeys: string[] = [
  "agent_model_descriptor -> config_revision",
  "agent_supplier_price_version -> config_revision",
  "agent_tariff_version -> config_revision",
  "audit_operator_proposal -> support_support_case",
  "chat_turn_promotion -> task_task",
  "commerce_checkout_attempt -> workspace_workspace",
  "commerce_compensation_adjustment -> audit_operator_proposal",
  "commerce_compensation_adjustment -> workspace_workspace",
  "commerce_credit_lot -> workspace_workspace",
  "commerce_credit_transaction -> workspace_workspace",
  "commerce_customer_settlement -> entitlement_capacity_reservation",
  "commerce_order -> workspace_workspace",
  "commerce_refund -> audit_operator_proposal",
  "commerce_refund -> workspace_workspace",
  "device_device -> identity_user",
  "entitlement_capacity_plan_assignment -> workspace_workspace",
  "entitlement_capacity_policy_period -> config_revision",
  "entitlement_service_term -> workspace_workspace",
  "identity_api_token -> workspace_workspace",
  "identity_session -> device_device",
  "notification_delivery -> identity_user",
  "package_catalog_publisher -> identity_user",
  "scope_scenario_version -> workspace_workspace",
  "scope_simulation_definition -> workspace_workspace",
  "scope_simulation_run -> entitlement_service_term",
  "scope_simulation_run -> workspace_workspace",
  "task_automation_definition -> workspace_workspace",
  "workspace_workspace -> identity_user",
];

test("the registry of closed enums has no duplicate number and every column uses a registered enum", () => {
  const registry: PhysicalSchema["enums"] = schema.enums;
  for (const entry of registry) {
    assert.equal(
      new Set(entry.members.map((member) => member.number)).size,
      entry.members.length,
      entry.name,
    );
    assert(
      entry.members.every((member) => member.number >= 1),
      entry.name,
    );
  }
  for (const table of schema.tables)
    for (const column of table.columns)
      if (column.kind === "enum")
        assert(enums.has(column.enumName ?? ""), `${table.name}.${column.name}`);
  void bindRow;
  void insertStatement;
});

test("every statement fits the D1 limits the oracle cannot see: patterns, columns and statement size", () => {
  // Found by running the vectors on workerd's D1: a LIKE or GLOB pattern above 50 bytes fails when it is evaluated, not when it is created.
  const patterns = /\b(?:GLOB|LIKE)\s+'((?:[^']|'')*)'/giu;
  let seen = 0;
  for (const file of readdirSync(migrationsDirectory).filter((entry) =>
    /^\d{4}_.+\.sql$/u.test(entry),
  )) {
    const text = readFileSync(path.join(migrationsDirectory, file), "utf8");
    for (const match of text.matchAll(patterns)) {
      assert(
        Buffer.byteLength(match[1] ?? "", "utf8") <= 50,
        `${file}: pattern of ${Buffer.byteLength(match[1] ?? "", "utf8")} bytes: ${match[1]}`,
      );
      seen++;
    }
  }
  assert(seen > 500, `only ${seen} patterns were inspected`);
  for (const table of schema.tables)
    assert(
      table.columns.length <= 100,
      `${table.name} has ${table.columns.length} columns (D1 allows 100)`,
    );
  const biggest = Math.max(
    ...schema.tables.flatMap((table) =>
      tableSql(table, enums).map((statement) => Buffer.byteLength(statement, "utf8")),
    ),
  );
  assert(biggest < 100_000, `a statement of ${biggest} bytes exceeds D1's 100 KB statement limit`);
});

test("an entitlement grant records a bounded reason exactly for operator sources, and the revision fence table exists (COM.16)", () => {
  const database = migratedDatabase(false);
  const grant = tableOf("entitlement_grant");
  const base = buildAcceptedRow(database, schema, grant, { boundary: false }, 12000).row;
  const attempt = (source: bigint, reason: string | null, serial: number) =>
    insertRow(database, grant, {
      ...base,
      grant_id: `0198a7c0-1c3e-7d4a-9b1f-${serial.toString(16).padStart(12, "0")}`,
      source,
      reason,
    });
  attempt(1n, null, 1);
  attempt(5n, "ticket 42", 2);
  attempt(6n, "x".repeat(512), 3);
  attempt(7n, "café 中", 4);
  assert.throws(() => attempt(5n, null, 5), /reason_required_for_operator_sources/u);
  assert.throws(() => attempt(1n, "why", 6), /reason_required_for_operator_sources/u);
  assert.throws(() => attempt(5n, "", 7), /reason_shape/u);
  assert.throws(() => attempt(5n, "x".repeat(513), 8), /reason_shape/u);
  assert.throws(() => attempt(5n, "line\nbreak", 9), /reason_shape/u);
  assert.throws(() => attempt(5n, "tab\there", 10), /reason_shape/u);
  const revision = tableOf("entitlement_revision");
  assert.deepEqual(revision.primaryKey, ["workspace_id"]);
  assert.equal(revision.foreignKeys.length, 0);
});

test("the drift check compares definitions, not names: a hand-edited migration with a re-hashed lock is caught", () => {
  const edits: { name: string; file: string; edit: (text: string) => string }[] = [
    {
      name: "an enum CHECK widened by one number",
      file: "0003_identity__baseline.sql",
      edit: (text) => text.replace(/("state" IN \(1, 2, 3, 4, 5)\)/u, "$1, 6)"),
    },
    {
      name: "a column removed from a limited-update trigger",
      file: "0001_platform__baseline.sql",
      edit: (text) => text.replace(/ OR OLD\."record_hash" IS NOT NEW\."record_hash"/u, ""),
    },
    {
      name: "the plan step locality rule loosened",
      file: "0012_task__baseline.sql",
      edit: (text) =>
        text.replace(
          /"tool_locality" = 1 AND "target_device_id" IS NULL/u,
          '"tool_locality" = 1 AND 1',
        ),
    },
    {
      name: "a partial index predicate dropped",
      file: "0013_sync__baseline.sql",
      edit: (text) => text.replace(/ WHERE "publish_seq" IS NOT NULL/u, ""),
    },
    {
      name: "an immutability trigger message changed",
      file: "0006_entitlement__baseline.sql",
      edit: (text) => text.replace("af_immutable_entitlement_grant", "af_other_entitlement_grant"),
    },
  ];
  for (const edit of edits) {
    const directory = mkdtempSync(path.join(tmpdir(), "af-drift-"));
    try {
      for (const file of readdirSync(migrationsDirectory))
        if (file.endsWith(".sql"))
          copyFileSync(path.join(migrationsDirectory, file), path.join(directory, file));
      const target = path.join(directory, edit.file);
      const original = readFileSync(target, "utf8");
      const changed = edit.edit(original);
      assert.notEqual(changed, original, `the edit "${edit.name}" matched nothing`);
      writeFileSync(target, changed);
      assert(driftProblems(schema, directory).length > 0, `the drift check missed: ${edit.name}`);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  }
  assert.deepEqual(driftProblems(schema), []);
});

test("every closed enum accepts exactly its registered numbers and refuses zero, a gap, the next number and a negative", () => {
  for (const entry of schema.enums) {
    const column = {
      name: "v",
      kind: "enum",
      sqlType: "INTEGER",
      nullable: false,
      monotonic: false,
      enumName: entry.name,
    } as const;
    const database = new DatabaseSync(":memory:");
    database.exec(
      `CREATE TABLE t (n INTEGER NOT NULL PRIMARY KEY, "v" INTEGER NOT NULL CHECK (${columnCheck(column, enums)})) STRICT`,
    );
    const registered = new Set(entry.members.map((member) => member.number));
    const highest = Math.max(...registered);
    let serial = 0;
    const store = (value: number) =>
      database.prepare("INSERT INTO t VALUES (?, ?)").run(serial++, value);
    for (const number of registered) store(number);
    const refused = [0, -1, highest + 1, 65536];
    for (let gap = 1; gap < highest; gap++) if (!registered.has(gap)) refused.push(gap);
    for (const number of refused)
      assert.throws(
        () => store(number),
        /CHECK constraint failed/u,
        `${entry.name} accepted ${number}`,
      );
  }
});

test("deletion insertion invariant is omitted from every old table and emits only its fixed owner trigger", () => {
  const table = tableOf("identity_account_deletion");
  assert.equal(table.insertionInvariant, "deletionLifecycleOriginal");
  for (const old of schema.tables.filter((entry) => entry !== table)) {
    assert(!Object.hasOwn(old, "insertionInvariant"), old.name);
    assert(!triggerSql(old).some((sql) => sql.includes("__original_insert")), old.name);
  }
  const absent = structuredClone(table);
  delete absent.insertionInvariant;
  assert.deepEqual(triggerSql(table).slice(1), triggerSql(absent));
  const sql = triggerSql(table)[0];
  assert(sql?.includes('WHERE "deletion_id" = NEW."deletion_id"'));
  assert(sql?.includes('NEW."state" IN (1, 3)'));
  assert(sql?.includes('WHERE "user_id" = NEW."user_id" AND "state" IN (1, 3)'));
  const database = migratedDatabase(true);
  try {
    assert.deepEqual(compareShapes(readShape(database), expectedShape(schema)), []);
  } finally {
    database.close();
  }
});

test("deletion insertion marker refuses unknown, foreign and every mismatched authority shape before SQL emission", () => {
  const columnOf = (table: PhysicalTable, name: string) => {
    const column = table.columns.find((entry) => entry.name === name);
    assert(column);
    return column;
  };
  const mutations: ((table: PhysicalTable) => void)[] = [
    (table) => {
      Object.assign(table, { insertionInvariant: "arbitrarySql" });
    },
    (table) => {
      table.owner = "workspace";
    },
    (table) => {
      table.name = "identity_foreign_table";
    },
    (table) => {
      table.primaryKey = ["user_id"];
    },
    (table) => {
      columnOf(table, "deletion_id").kind = "text";
    },
    (table) => {
      columnOf(table, "user_id").nullable = true;
    },
    (table) => {
      columnOf(table, "state").enumName = "identity.user_state";
    },
    (table) => {
      columnOf(table, "state").sqlType = "TEXT";
    },
    (table) => {
      columnOf(table, "state").generated = "1";
    },
    (table) => {
      const index = table.indexes.find((entry) => entry.unique);
      assert(index);
      index.where = '"state" IN (1, 2)';
    },
    (table) => {
      const index = table.indexes.find((entry) => entry.unique);
      assert(index);
      index.columns = ["realm_id"];
    },
    (table) => {
      const index = table.indexes.find((entry) => entry.unique);
      assert(index);
      index.unique = false;
    },
    (table) => {
      table.indexes.push({
        name: "ux_identity_account_deletion__realm_id",
        columns: ["realm_id"],
        path: "hostile",
        unique: true,
      });
    },
    (table) => {
      table.mutability.delete = "any";
    },
    (table) => {
      table.mutability.update = "any";
    },
    (table) => {
      const update = table.mutability.update;
      assert(typeof update === "object");
      update.columns.push("grace_ends_at");
    },
    (table) => {
      const update = table.mutability.update;
      assert(typeof update === "object");
      update.when = "1";
    },
  ];
  for (const mutate of mutations) {
    const copy = structuredClone(schema);
    const table = copy.tables.find((entry) => entry.name === "identity_account_deletion");
    assert(table);
    mutate(table);
    assert.throws(() => validateSchema(copy), /invalid deletion lifecycle insertion invariant/u);
    assert.throws(() => triggerSql(table), /invalid deletion lifecycle insertion invariant/u);
  }
  const copy = structuredClone(schema);
  const state = copy.enums.find((entry) => entry.name === "identity.deletion_state");
  assert(state);
  const purging = state.members.find((entry) => entry.name === "purging");
  assert(purging);
  purging.number = 7;
  assert.throws(() => validateSchema(copy), /invalid deletion lifecycle state profile/u);
  assert.throws(
    () => tableSql(tableOf("identity_account_deletion"), enumMap(copy)),
    /invalid deletion lifecycle state profile/u,
  );
});

test("strict physical drift refuses a missing or weakened original insertion trigger", () => {
  for (const replace of [false, true]) {
    const database = migratedDatabase(true);
    database.exec('DROP TRIGGER "tr_identity_account_deletion__original_insert"');
    if (replace)
      database.exec(
        `CREATE TRIGGER "tr_identity_account_deletion__original_insert" BEFORE INSERT ON "identity_account_deletion" WHEN 0 BEGIN SELECT RAISE(ABORT, 'CHECK constraint failed: af_immutable_identity_account_deletion'); END`,
      );
    const problems = compareShapes(readShape(database), expectedShape(schema));
    assert(
      problems.some(
        (problem) =>
          problem.includes("identity_account_deletion") && problem.includes("original_insert"),
      ),
      problems.join("\n"),
    );
    database.close();
  }
});
