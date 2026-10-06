// SPDX-License-Identifier: AGPL-3.0-only
// A line-oriented bridge that lets the C# recovery issuer/composer tests run a closed future-consumer fixture on the SQLite oracle (CLOUD.75). It opens an
// in-memory database with every committed migration, then answers one JSON line per request on stdin with one JSON line on stdout:
//
//   {"kind":"plan","body":"<ExecutePlanRequest JSON exactly as the host sends it>"}  -> the ExecutePlanResponse JSON the Worker would return
//   {"kind":"exec","sql":"..."}                                                      -> {"ok":true} or {"error":"..."}  (test fixtures only)
//   {"kind":"query","sql":"..."}                                                     -> {"rows":[[...]]}                (test assertions only)
//
// The plan path is the production Worker code (strict request parse, plan lookup, statement-by-statement argument checks, batch
// execution, error classification, exact result encoding) over node:sqlite. SQLite is not D1: the signature check, the network path and
// the provider's limits are not exercised (the opt-in workerd run repeats the engine-dependent cases).
import {
  serializeExecutePlanResponseJson,
  tryParseExecutePlanRequestJson,
} from "@arcforges/ai-internal";
import { createInterface } from "node:readline";
import { loadCatalog } from "../../../eng/migrations/catalog.ts";
import { executePlan, planKey } from "../../../worker/storage/execute-plan.ts";
import { manifestHash, plans } from "../../../worker/storage/plans.generated.ts";
import { createSqliteD1 } from "../../worker/support/sqlite-d1.ts";

import { expandGuard } from "../../../eng/verification/storage-plans.ts";
import { loadManifest } from "../../../eng/verification/physical-schema.ts";

const sql = loadCatalog()
  .map((migration) => migration.text)
  .join("\n");
const db = createSqliteD1(sql);
const index = new Map(plans.map((plan) => [planKey(plan.id, plan.version), plan]));
const generation = process.argv[2] ?? "1";
const base = plans.find((plan) => plan.id === "families.account-enrollment.create-user");
if (!base) throw new Error("Missing registered enrollment producer");
const guard = expandGuard(
  "kind=authorization module=platform key=recovery-current table=platform_recovery_epoch by=realm_id match=recovery_generation,state,rev",
  loadManifest(),
  "CLOUD.75 closed future-consumer fixture",
);
const fixture = {
  ...base,
  id: "families.account-enrollment.recovery-fixture",
  statements: [{ sql: guard.sql, params: guard.params, returns: null }, ...base.statements],
};
index.set(planKey(fixture.id, fixture.version), fixture);

type Row = unknown[];
const plain = (value: unknown): unknown =>
  typeof value === "bigint"
    ? value.toString()
    : value instanceof Uint8Array
      ? Array.from(value)
      : value;

async function answer(line: string): Promise<string> {
  const message = JSON.parse(line) as { kind: string; body?: string; sql?: string };
  if (message.kind === "plan") {
    const parsed = tryParseExecutePlanRequestJson(new TextEncoder().encode(message.body ?? ""));
    if (!parsed.ok) return JSON.stringify({ error: "unparseable request" });
    const response = await executePlan(parsed.value, {
      db,
      plans: index,
      manifestHash,
      recoveryGeneration: generation,
      nowMs: Date.now,
    });
    return new TextDecoder().decode(serializeExecutePlanResponseJson(response));
  }
  if (message.kind === "exec") {
    try {
      db.database.exec(message.sql ?? "");
      return JSON.stringify({ ok: true });
    } catch (error) {
      return JSON.stringify({ error: error instanceof Error ? error.message : String(error) });
    }
  }
  if (message.kind === "query") {
    try {
      const statement = db.database.prepare(message.sql ?? "");
      statement.setReturnArrays(true);
      statement.setReadBigInts(true);
      const rows = (statement.all() as unknown as Row[]).map((row) => row.map(plain));
      return JSON.stringify({ rows });
    } catch (error) {
      return JSON.stringify({ error: error instanceof Error ? error.message : String(error) });
    }
  }
  return JSON.stringify({ error: "unknown request" });
}

const reader = createInterface({ input: process.stdin, crlfDelay: Infinity });
let chain: Promise<void> = Promise.resolve();
reader.on("line", (line) => {
  chain = chain.then(async () => {
    process.stdout.write(`${await answer(line)}\n`);
  });
});
