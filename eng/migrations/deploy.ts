// SPDX-License-Identifier: AGPL-3.0-only
// The deployment-time caller of the D1 migration runner (CLOUD.70; Design D1 profile section 6): the one gated
// step of the deployment jobs that brings a deployed business database to the schema of the build that is about
// to be promoted. It never runs from the Container. It adds no runner behavior: it selects the database of the
// target from the deployment configuration (wrangler.json), reads the migration plan of the release manifest,
// asks the CLOUD.03 runner to apply it under the migrator lease and fence, prints the receipts and the
// compatibility record, and applies the compatible-rollback rule before the Worker or image is promoted.
//
// A failing step stops promotion: this command exits non-zero on any refusal or failure, the workflow steps that
// promote run only after it succeeded, and tooling/cloudflare.ts refuses to promote without the gate record this
// command writes for exactly the candidate being promoted.
//
//   node eng/migrations/deploy.ts deploy --target production|proof   gated live step (CI only, secret from the environment)
//   node eng/migrations/deploy.ts dry-run [--through N] [--allow-contract]   the same flow against an in-memory SQLite database
//
// Environment (names only): CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN (secret, never printed), optional
// D1_DATABASE_ID (overrides the lookup by the configured database name), GITHUB_* from the runner.
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defaultMigrationsDirectory, loadCatalog, lockIdentity, readLock } from "./catalog.ts";
import type { Migration } from "./catalog.ts";
import { type MigrationClient, RestMigrationClient, SqliteMigrationClient } from "./clients.ts";
import {
  applyPending,
  compatibility,
  type Compatibility,
  type CompatibilityInput,
  MigrationError,
  type MigrationStatus,
  type RunResult,
  status,
} from "./runner.ts";

export type Target = "production" | "proof";
export const targets: readonly Target[] = ["production", "proof"];

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const gateFile = (target: Target, root = repositoryRoot) =>
  path.join(root, "artifacts", `migration-gate-${target}.json`);

/** A refusal of the gate: nothing is promoted. The code is stable text for the job log. */
export class GateRefusal extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Target selection from the existing deployment configuration

export interface WranglerLike {
  d1_databases?: { binding?: string; database_name?: string }[];
  env?: Record<string, { d1_databases?: { binding?: string; database_name?: string }[] }>;
}

/**
 * The business database named for a target by wrangler.json: production by the top-level d1_databases, proof by
 * env.proof. null when the target declares none (the production Worker serves only the anonymous Hello method and
 * binds no database yet): then there is nothing to migrate and the step says so.
 */
export function databaseNameFor(config: WranglerLike, target: Target): string | null {
  const declared =
    target === "production" ? config.d1_databases : config.env?.[target]?.d1_databases;
  if (declared === undefined || declared.length === 0) return null;
  const business = declared.filter((entry) => entry.binding === "DB");
  if (business.length !== 1)
    throw new GateRefusal(
      "ambiguous-database",
      `${target} must declare exactly one D1 binding named DB (found ${business.length})`,
    );
  const name = (business[0] as { database_name?: string }).database_name;
  if (typeof name !== "string" || name === "")
    throw new GateRefusal("ambiguous-database", `${target} DB binding has no database_name`);
  return name;
}

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;

/** The database id: an explicit override, else an exact-name lookup. Nothing is created here. */
export async function resolveDatabaseId(options: {
  accountId: string;
  token: string;
  name: string;
  override?: string;
  fetch?: typeof fetch;
}): Promise<string> {
  if (options.override !== undefined && options.override !== "") {
    if (!uuid.test(options.override))
      throw new GateRefusal("bad-database-id", "D1_DATABASE_ID is not a database id");
    return options.override;
  }
  const doFetch = options.fetch ?? fetch;
  const url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(options.accountId)}/d1/database?name=${encodeURIComponent(options.name)}&per_page=100`;
  let reply: Response;
  try {
    reply = await doFetch(url, {
      headers: { authorization: `Bearer ${options.token}` },
      signal: AbortSignal.timeout(30_000),
    });
  } catch {
    throw new GateRefusal("lookup-failed", "the D1 database lookup could not be completed");
  }
  let body: { success?: boolean; result?: { uuid?: string; name?: string }[] } = {};
  try {
    body = (await reply.json()) as typeof body;
  } catch {
    // reported by status only
  }
  if (!reply.ok || body.success === false || !Array.isArray(body.result))
    throw new GateRefusal("lookup-failed", `the D1 database lookup failed (HTTP ${reply.status})`);
  const found = body.result.filter((entry) => entry.name === options.name);
  const id = found[0]?.uuid;
  if (found.length !== 1 || id === undefined || !uuid.test(id))
    throw new GateRefusal(
      "database-missing",
      `D1 database ${options.name} was not found exactly once; it is provisioned before the step`,
    );
  return id;
}

// ---------------------------------------------------------------------------------------------------------------
// The release manifest's migration plan

export interface ReleasePlan {
  /** The highest migration sequence this deployment applies, and the schema the promoted build is built for. */
  through: number;
  /** Consent to apply a contract migration (irreversible); the runner still demands cutover and the soak. */
  allowContract: boolean;
  source: "manifest" | "default";
}

/**
 * The migration plan of a deployment. The candidate's release manifest may carry
 * `migrations: { through: <sequence>, allowContract?: true }`; that is the only way backfill, cutover or contract
 * migrations are applied. Without it the deployment applies expand migrations only: it continues from the
 * schema the database is at while the next migration is an expand, and stops before any other mode.
 */
export function releasePlan(
  manifest: { migrations?: unknown },
  migrations: readonly Migration[],
  databaseSchemaVersion: number,
): ReleasePlan {
  const declared = manifest.migrations;
  if (declared === undefined) {
    let through = Math.max(databaseSchemaVersion, -1);
    while (migrations[through + 1]?.mode === "expand") through++;
    return { through, allowContract: false, source: "default" };
  }
  if (typeof declared !== "object" || declared === null || Array.isArray(declared))
    throw new GateRefusal("bad-plan", "the manifest's migrations entry is not an object");
  const entry = declared as { through?: unknown; allowContract?: unknown };
  const extra = Object.keys(entry).filter((key) => key !== "through" && key !== "allowContract");
  if (extra.length > 0)
    throw new GateRefusal("bad-plan", `unknown migration plan field: ${extra.join(", ")}`);
  const through = entry.through;
  if (
    !Number.isInteger(through) ||
    (through as number) < 0 ||
    (through as number) >= migrations.length
  )
    throw new GateRefusal(
      "bad-plan",
      `through must name an existing migration sequence 0..${migrations.length - 1}`,
    );
  if (entry.allowContract !== undefined && typeof entry.allowContract !== "boolean")
    throw new GateRefusal("bad-plan", "allowContract must be a boolean");
  const allowContract = entry.allowContract === true;
  const last = through as number;
  if (!allowContract) {
    const contract = migrations.find(
      (item) =>
        item.sequence <= last && item.mode === "contract" && item.sequence > databaseSchemaVersion,
    );
    if (contract)
      throw new GateRefusal(
        "contract-refused",
        `${contract.file} is irreversible: the plan reaches it without allowContract`,
      );
  }
  return { through: last, allowContract, source: "manifest" };
}

// ---------------------------------------------------------------------------------------------------------------
// The gate

export interface GateInput {
  client: MigrationClient;
  migrations: readonly Migration[];
  /** The release manifest (only its optional migrations entry is read here). */
  manifest: { migrations?: unknown };
  runner: string;
  now: () => number;
  compatibility: CompatibilityInput;
}

export interface GateReport {
  status: "passed";
  plan: ReleasePlan;
  lock: { highest: number; hash: string };
  buildSchemaVersion: number;
  before: Pick<
    MigrationStatus,
    "initialized" | "schemaVersion" | "readHorizon" | "writeHorizon" | "databaseAhead"
  >;
  run: RunResult;
  after: MigrationStatus;
  compatibility: Compatibility & { buildSchemaVersion: number };
}

const brief = (state: MigrationStatus) => ({
  initialized: state.initialized,
  schemaVersion: state.schemaVersion,
  readHorizon: state.readHorizon,
  writeHorizon: state.writeHorizon,
  databaseAhead: state.databaseAhead,
});

/**
 * Order of the step: read the state; refuse a database ahead of the build or a build the horizons exclude (before
 * anything is written); apply the plan under the lease and fence; read the state again and apply the
 * compatible-rollback rule to the build being promoted. Any refusal or runner failure throws.
 */
export async function runGate(input: GateInput): Promise<GateReport> {
  const before = await status(input.client, input.migrations, input.now);
  if (before.databaseAhead > 0)
    throw new GateRefusal(
      "database-ahead",
      `the database holds ${before.databaseAhead} migration(s) this build does not contain; an older build is never promoted over a newer schema`,
    );
  const plan = releasePlan(input.manifest, input.migrations, before.schemaVersion);
  if (before.initialized && plan.through < before.writeHorizon)
    throw new GateRefusal(
      "build-excluded",
      `this build (schema ${plan.through}) is below the database write horizon ${before.writeHorizon}`,
    );
  const run = await applyPending({
    client: input.client,
    migrations: input.migrations,
    runner: input.runner,
    now: input.now,
    compatibility: input.compatibility,
    stopAfter: plan.through,
    allowContract: plan.allowContract,
  });
  const after = await status(input.client, input.migrations, input.now);
  const verdict = compatibility(after, { schemaVersion: plan.through });
  if (!verdict.canWrite)
    throw new GateRefusal(
      "build-excluded",
      `the build (schema ${plan.through}) cannot use the migrated database: ${verdict.reason}`,
    );
  return {
    status: "passed",
    plan,
    lock: lockIdentity(readLock(defaultMigrationsDirectory)),
    buildSchemaVersion: plan.through,
    before: brief(before),
    run,
    after,
    compatibility: { ...verdict, buildSchemaVersion: plan.through },
  };
}

/** The job-log report: receipts, fence and compatibility record. It holds no credential by construction. */
export function formatReport(report: GateReport): string {
  return `${JSON.stringify(
    {
      status: report.status,
      plan: report.plan,
      lock: report.lock,
      buildSchemaVersion: report.buildSchemaVersion,
      before: report.before,
      fence: report.run.fence,
      applied: report.run.applied,
      alreadyCurrent: report.run.alreadyCurrent,
      schemaVersion: report.after.schemaVersion,
      readHorizon: report.after.readHorizon,
      writeHorizon: report.after.writeHorizon,
      receipts: report.after.receipts,
      pending: report.after.pending,
      compatibility: report.compatibility,
    },
    null,
    2,
  )}\n`;
}

/** Removes every secret value from text before it is printed or recorded. */
export function scrub(text: string, secrets: readonly (string | undefined)[]): string {
  let result = text;
  for (const secret of secrets)
    if (secret !== undefined && secret.length >= 8)
      result = result.split(secret).join("[redacted]");
  return result;
}

// ---------------------------------------------------------------------------------------------------------------
// Gate record: the proof that the step passed for exactly the candidate being promoted

export interface GateRecord {
  target: Target;
  revision: string;
  status: "passed" | "not-applicable" | "refused";
  detail: string;
}

export function writeGateRecord(record: GateRecord, root = repositoryRoot): void {
  const file = gateFile(record.target, root);
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, `${JSON.stringify(record, null, 2)}\n`);
}

/** Promotion requires the record of a passed (or not applicable) gate for this very revision and target. */
export function requireGatePassed(
  target: Target,
  revision: string,
  root = repositoryRoot,
): GateRecord {
  let record: GateRecord;
  try {
    record = JSON.parse(readFileSync(gateFile(target, root), "utf8")) as GateRecord;
  } catch {
    throw new GateRefusal("gate-missing", "the migration step did not run; nothing is promoted");
  }
  assert.equal(record.target, target, "the gate record is for another target");
  assert.equal(record.revision, revision, "the gate record is for another revision");
  if (record.status !== "passed" && record.status !== "not-applicable")
    throw new GateRefusal("gate-failed", "the migration step did not pass; nothing is promoted");
  return record;
}

// ---------------------------------------------------------------------------------------------------------------
// Context and command line

/** The live step runs only in the gated jobs of main: never in a pull request, never for a fork. */
export function requireContext(env: Record<string, string | undefined>, target: Target): void {
  const refuse = (message: string) => {
    throw new GateRefusal("context", message);
  };
  if (env.GITHUB_ACTIONS !== "true")
    refuse("the migration step runs only in the gated deployment jobs");
  if (env.GITHUB_REPOSITORY !== "ArcForges/Cloud")
    refuse("the migration step runs only in ArcForges/Cloud");
  if (env.GITHUB_REF !== "refs/heads/main") refuse("the migration step runs only on main");
  const event = target === "production" ? "push" : "workflow_dispatch";
  if (env.GITHUB_EVENT_NAME !== event) refuse(`the ${target} migration step runs only on ${event}`);
}

function runnerIdentity(env: Record<string, string | undefined>): string {
  return `gh-${env.GITHUB_RUN_ID ?? "local"}-${env.GITHUB_RUN_ATTEMPT ?? "1"}-${env.GITHUB_JOB ?? "job"}`;
}

export async function deployStep(
  target: Target,
  env: Record<string, string | undefined>,
  io: { out: (text: string) => void; fetch?: typeof fetch; root?: string; now?: () => number } = {
    out: (text) => process.stdout.write(text),
  },
): Promise<number> {
  const root = io.root ?? repositoryRoot;
  const secrets = [env.CLOUDFLARE_API_TOKEN];
  let revision = "unknown";
  try {
    requireContext(env, target);
    const account = env.CLOUDFLARE_ACCOUNT_ID ?? "";
    if (!/^[0-9a-f]{32}$/u.test(account))
      throw new GateRefusal("context", "CLOUDFLARE_ACCOUNT_ID is not set to an account id");
    const token = env.CLOUDFLARE_API_TOKEN ?? "";
    if (token === "")
      throw new GateRefusal("context", "the CLOUDFLARE_API_TOKEN secret is not set");
    const manifest = JSON.parse(
      readFileSync(path.join(root, "artifacts", "candidate", "manifest.json"), "utf8"),
    ) as { revision?: string; migrations?: unknown };
    revision = String(manifest.revision ?? "");
    if (!/^[0-9a-f]{40}$/u.test(revision) || revision !== env.GITHUB_SHA)
      throw new GateRefusal("context", "the sealed candidate is not the commit being deployed");
    const migrations = loadCatalog();
    const config = JSON.parse(
      readFileSync(path.join(root, "wrangler.json"), "utf8"),
    ) as WranglerLike;
    const name = databaseNameFor(config, target);
    if (name === null) {
      const detail = `${target} declares no D1 database; there is nothing to migrate`;
      io.out(`migration step: not applicable (${detail})\n`);
      writeGateRecord({ target, revision, status: "not-applicable", detail }, root);
      return 0;
    }
    const databaseId = await resolveDatabaseId({
      accountId: account,
      token,
      name,
      ...(env.D1_DATABASE_ID === undefined ? {} : { override: env.D1_DATABASE_ID }),
      ...(io.fetch === undefined ? {} : { fetch: io.fetch }),
    });
    const client = new RestMigrationClient({
      accountId: account,
      databaseId,
      apiToken: token,
      ...(io.fetch === undefined ? {} : { fetch: io.fetch }),
    });
    io.out(`migration step: ${target} database ${name}, release ${revision.slice(0, 12)}\n`);
    const report = await runGate({
      client,
      migrations,
      manifest,
      runner: runnerIdentity(env),
      now: io.now ?? Date.now,
      compatibility: {
        sourceRevision: revision,
        planManifestHash: env.PLAN_MANIFEST_HASH ?? "",
        abi: env.ABI_VERSION ?? "",
        runtime: env.RUNTIME_VERSION ?? "",
      },
    });
    io.out(scrub(formatReport(report), secrets));
    writeGateRecord(
      { target, revision, status: "passed", detail: `schema ${report.after.schemaVersion}` },
      root,
    );
    return 0;
  } catch (error) {
    const code =
      error instanceof GateRefusal || error instanceof MigrationError ? error.code : "failed";
    const message = scrub(error instanceof Error ? error.message : String(error), secrets);
    io.out(`migration step REFUSED (${code}): ${message}\nNothing is promoted.\n`);
    try {
      writeGateRecord({ target, revision, status: "refused", detail: code }, root);
    } catch {
      // The step still fails: the exit code is what stops the job.
    }
    return 1;
  }
}

/** The same gated flow against an in-memory SQLite database and the real catalog (offline, no secret). */
export async function dryRun(
  options: {
    migrations?: readonly Migration[];
    manifest?: { migrations?: unknown };
    now?: () => number;
  } = {},
): Promise<GateReport> {
  return runGate({
    client: new SqliteMigrationClient(),
    migrations: options.migrations ?? loadCatalog(),
    manifest: options.manifest ?? {},
    runner: "dry-run",
    now: options.now ?? Date.now,
    compatibility: { sourceRevision: "local", planManifestHash: "", abi: "", runtime: "" },
  });
}

export async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (command === "deploy") {
    const at = rest.indexOf("--target");
    const target = at >= 0 ? rest[at + 1] : undefined;
    if (target !== "production" && target !== "proof") {
      process.stderr.write(
        "usage: node eng/migrations/deploy.ts deploy --target production|proof\n",
      );
      return 2;
    }
    return deployStep(target, process.env);
  }
  if (command === "dry-run") {
    const at = rest.indexOf("--through");
    const manifest =
      at >= 0
        ? {
            migrations: {
              through: Number(rest[at + 1]),
              allowContract: rest.includes("--allow-contract"),
            },
          }
        : {};
    try {
      process.stdout.write(formatReport(await dryRun({ manifest })));
      return 0;
    } catch (error) {
      process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
      return 1;
    }
  }
  process.stderr.write("usage: node eng/migrations/deploy.ts deploy|dry-run\n");
  return 2;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url))
  process.exitCode = await main(process.argv.slice(2));
