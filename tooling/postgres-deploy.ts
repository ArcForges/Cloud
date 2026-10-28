// SPDX-License-Identifier: AGPL-3.0-only
// The PostgreSQL step of the protected deployments (AF-CTR-02; docs/postgres-store.md). Before anything is pushed or promoted, the
// deployment runs the sealed candidate image's own center executable (never a rebuilt one) with the migration role's direct
// connection: `admin ensure-database` for the acceptance database, then `migrate`, which applies the embedded migrations under the
// migration lock and reconciles the runtime role's grants; the result is the gate record that promotion requires. At promotion the
// runtime credential is rotated in the same process that uploads it as the Worker secret: the executable writes the pooled runtime
// URL into a runner-local file outside the artifact directories, Wrangler uploads it, and the file is removed. Before rotating, the
// deployment reads which slot the live Worker version uses from Cloudflare (its version message `runtime-slot=<slot>`) and never
// rotates that slot; only after Wrangler succeeded is the new slot confirmed as promoted (`admin confirm-runtime-credential`). No
// value of a credential is printed, logged, written to an artifact or passed on a command line: Docker receives the variables by
// name from the environment of its own process.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { readJson, root, run, writeJson } from "./process.ts";

export type PostgresTarget = "production" | "acceptance";

/** The deployment secret: the migration role's direct (unpooled) URL of the Neon project, in the GitHub cloudflare environment. */
export const directUrlSecret = "NEON_DATABASE_URL_DIRECT";

/** The center executable inside the sealed image. */
export const centerEntrypoint = "/app/arcforges-center";

export interface TargetSettings {
  /** The runtime group role; its rotation login roles are <role>_a and <role>_b. */
  runtimeRole: string;
  /** The database of the target, when it is not the one of the direct URL. */
  databaseName?: string;
  /** Whether the deployment creates the database when it does not exist. */
  ensureDatabase: boolean;
}

/**
 * Production uses the database of the direct URL and the runtime role arcforges_center_runtime. The acceptance environment (the
 * `proof` Worker) has its own database (arcforges_acceptance) and its own runtime role in the same Neon project and branch. Each
 * migration revokes CONNECT and TEMPORARY on its database from PUBLIC and grants CONNECT to its own runtime role only, so neither
 * runtime credential can connect to the other environment's database (and neither holds any privilege on the other's tables). Both
 * environments are migrated with the same owner credential (NEON_DATABASE_URL_DIRECT), which reaches both databases.
 */
export const postgresTargets: Record<PostgresTarget, TargetSettings> = {
  production: { runtimeRole: "arcforges_center_runtime", ensureDatabase: false },
  acceptance: {
    runtimeRole: "arcforges_acceptance_runtime",
    databaseName: "arcforges_acceptance",
    ensureDatabase: true,
  },
};

export function gateFile(target: PostgresTarget): string {
  return path.join(root, "artifacts", `postgres-gate-${target}.json`);
}

/** The variables the executable reads, by name; values come only from the deployment environment. */
export function centerVariables(
  target: PostgresTarget,
  environment: Readonly<Record<string, string | undefined>>,
): Record<string, string> {
  const direct = environment[directUrlSecret] ?? "";
  // The message names the secret and never echoes a value.
  assert(
    direct !== "",
    `Set the ${directUrlSecret} secret in the GitHub cloudflare environment (docs/deployment.md).`,
  );
  const settings = postgresTargets[target];
  const variables: Record<string, string> = {
    ARCFORGES_CENTER_MODE: "official-hosted",
    ARCFORGES_CENTER_MIGRATION_DATABASE_URL: direct,
    ARCFORGES_CENTER_RUNTIME_ROLE: settings.runtimeRole,
  };
  if (settings.databaseName !== undefined)
    variables.ARCFORGES_CENTER_DATABASE_NAME = settings.databaseName;
  return variables;
}

/** The docker arguments of one command of the sealed executable: names of variables only, never values. */
export function dockerArguments(
  image: string,
  names: readonly string[],
  command: readonly string[],
  options: { user?: string; secretsDirectory?: string } = {},
): string[] {
  const args = [
    "run",
    "--rm",
    "--read-only",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--memory",
    "256m",
  ];
  for (const name of names) {
    assert.match(name, /^[A-Z][A-Z0-9_]*$/u);
    args.push("--env", name);
  }
  if (options.secretsDirectory !== undefined) {
    assert(path.isAbsolute(options.secretsDirectory));
    args.push("--volume", `${options.secretsDirectory}:/secrets`);
  }
  if (options.user !== undefined) args.push("--user", options.user);
  args.push("--entrypoint", centerEntrypoint, image, ...command);
  return args;
}

/** Runs one command of the sealed executable and returns its JSON output (replaced by a fake in the offline tests). */
export type CenterRunner = (
  image: string,
  variables: Record<string, string>,
  command: string[],
  options?: { user?: string; secretsDirectory?: string },
) => Promise<Record<string, unknown>>;

/** A non-zero exit of the sealed executable; status 4 of confirm-runtime-credential is a slot this database never rotated. */
export class CenterExit extends Error {
  readonly status: number | null;
  constructor(message: string, status: number | null) {
    super(message);
    this.status = status;
  }
}

/** The exit status of `admin confirm-runtime-credential` for a slot the database never rotated. */
export const unknownSlotStatus = 4;

/** The live version's slot is unknown to the target database (it was recreated, or the target is new). */
export class SlotNeverRotated extends Error {}

/** Runs the sealed executable with the variables in the docker CLI's environment and returns its JSON output. */
async function center(
  image: string,
  variables: Record<string, string>,
  command: string[],
  options: { user?: string; secretsDirectory?: string } = {},
): Promise<Record<string, unknown>> {
  const args = dockerArguments(image, Object.keys(variables), command, options);
  const output = await new Promise<string>((resolve, reject) => {
    const child = spawn("docker", args, {
      cwd: root,
      windowsHide: true,
      // stderr carries the executable's JSON log lines, which name no credential.
      stdio: ["ignore", "pipe", "inherit"],
      env: { ...process.env, ...variables },
    });
    let text = "";
    child.stdout.on("data", (chunk: Buffer) => {
      text += chunk.toString();
    });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolve(text);
      else
        reject(
          new CenterExit(`arcforges-center ${command.join(" ")} exited with code ${code}.`, code),
        );
    });
  });
  return JSON.parse(output.trim().split("\n").at(-1) ?? "{}") as Record<string, unknown>;
}

export interface GateRecord {
  target: PostgresTarget;
  revision: string;
  status: "passed" | "failed";
  database?: string;
  version?: number;
  applied?: string[];
  runtimeRole?: string;
  databaseCreated?: boolean;
  /** The server's server_version_num (for example 180004), as the migration connection reported it. */
  serverVersionNum?: number;
  /** The PostgreSQL major the tests run, and whether the server's major is it (a mismatch is a warning, not a failure). */
  testedMajor?: number;
  serverMajorMatchesTested?: boolean;
  warnings?: string[];
  /** The comparison of the C# Hello's NEON_DATABASE_URL with the migration role (checkHelloCredential). */
  helloCredential?: HelloCredentialCheck;
  /** What the server records of statements (pg_stat_statements.track, log_statement, log_min_duration_statement). */
  logging?: Record<string, unknown>;
}

/** The result of checkHelloCredential; it names no value of either URL. */
export interface HelloCredentialCheck {
  status: "same-role" | "skipped";
  reason: string;
  sameDatabase?: boolean;
}

/**
 * The C# Hello and its rollback connect with NEON_DATABASE_URL. The migration revokes PUBLIC's CONNECT on the center's database,
 * which keeps only the owner (the migration role) and the runtime group, so NEON_DATABASE_URL must name the migration role.
 * Production compares the role and the database names; acceptance, which has its own database, compares the role only. An absent
 * NEON_DATABASE_URL (a target that does not carry it) is skipped. Neither URL nor any part of it is ever printed.
 */
export function checkHelloCredential(
  target: PostgresTarget,
  environment: Readonly<Record<string, string | undefined>>,
): HelloCredentialCheck {
  const hello = environment.NEON_DATABASE_URL ?? "";
  if (hello === "")
    return {
      status: "skipped",
      reason: "NEON_DATABASE_URL is not set for this step; nothing to compare",
    };
  const names = (value: string, name: string) => {
    let uri: URL;
    try {
      uri = new URL(value);
    } catch {
      throw new Error(`${name} is not a URL.`);
    }
    return {
      user: decodeURIComponent(uri.username),
      database: decodeURIComponent(uri.pathname.replace(/^\//u, "")),
    };
  };
  const helloNames = names(hello, "NEON_DATABASE_URL");
  const migration = names(environment[directUrlSecret] ?? "", directUrlSecret);
  if (helloNames.user === "" || helloNames.user !== migration.user)
    throw new Error(
      `NEON_DATABASE_URL names another role than the migration role (${directUrlSecret}). The migration revokes PUBLIC's CONNECT on the center's database, which would lock that role out of the C# Hello and its rollback. Grant it CONNECT on the database first (as the owner: GRANT CONNECT ON DATABASE <database> TO <that role>), then re-run the deployment.`,
    );
  if (target === "acceptance")
    return {
      status: "same-role",
      reason:
        "NEON_DATABASE_URL names the migration role (acceptance has its own database; the role is compared)",
    };
  const sameDatabase = helloNames.database === migration.database;
  return {
    status: "same-role",
    sameDatabase,
    reason: sameDatabase
      ? "NEON_DATABASE_URL names the migration role and the center's database"
      : "NEON_DATABASE_URL names the migration role and another database, which the migration does not change",
  };
}

/** Records a passed migration result in the gate record; it refuses a result that is not current, reconciled and versioned. */
export function recordMigration(record: GateRecord, result: Record<string, unknown>): void {
  assert.equal(result.state, "current", "the database is not at the build's migrations");
  assert.equal(result.grants, "reconciled", "the runtime role's grants were not reconciled");
  const serverVersionNum = Number(result.serverVersionNum);
  assert(
    Number.isInteger(serverVersionNum) && serverVersionNum >= 100000,
    "the migration reported no server version",
  );
  record.database = String(result.database);
  record.version = Number(result.version);
  record.runtimeRole = String(result.runtimeRole);
  record.serverVersionNum = serverVersionNum;
  record.testedMajor = Number(result.testedMajor);
  record.serverMajorMatchesTested = result.serverMajorMatchesTested === true;
  if (typeof result.logging === "object" && result.logging !== null)
    record.logging = result.logging as Record<string, unknown>;
  if (!record.serverMajorMatchesTested)
    record.warnings = [
      ...(record.warnings ?? []),
      `the server's PostgreSQL major ${Math.floor(serverVersionNum / 10000)} differs from the tested major ${record.testedMajor}`,
    ];
  record.applied = Array.isArray(result.ran)
    ? (result.ran as { name?: unknown }[]).map((step) => String(step.name))
    : [];
  record.status = "passed";
}

/** Loads the sealed candidate image and checks that it is the manifest's. */
export async function loadCandidateImage(candidate: {
  image: string;
  imageId: string;
}): Promise<void> {
  await run("docker", ["load", "--input", "artifacts/candidate/docker-image.tar"]);
  const imageId = await run(
    "docker",
    ["image", "inspect", candidate.image, "--format", "{{.Id}}"],
    true,
  );
  assert.equal(imageId, candidate.imageId, "Loaded image is not the sealed candidate image.");
}

/** The gated PostgreSQL step: ensure the database (acceptance), migrate, and record the gate. */
export async function migrateTarget(target: PostgresTarget): Promise<GateRecord> {
  const { verifyCandidate } = await import("./project.ts");
  const candidate = await verifyCandidate();
  assert.equal(candidate.dirty, false, "Uncommitted local builds cannot deploy.");
  const variables = centerVariables(target, process.env);
  const record: GateRecord = { target, revision: candidate.revision, status: "failed" };
  try {
    // Before anything runs: the revocation of PUBLIC's CONNECT must not lock out the C# Hello's role.
    record.helloCredential = checkHelloCredential(target, process.env);
    await loadCandidateImage(candidate);
    if (postgresTargets[target].ensureDatabase) {
      const ensured = await center(candidate.image, variables, ["admin", "ensure-database"]);
      record.databaseCreated = ensured.created === true;
    }
    recordMigration(record, await center(candidate.image, variables, ["migrate"]));
  } finally {
    await writeJson(gateFile(target), record);
  }
  return record;
}

/** Promotion refuses without the passed gate record of exactly this target and revision. */
export function requirePostgresGate(
  record: GateRecord | undefined,
  target: PostgresTarget,
  revision: string,
): void {
  if (record === undefined)
    throw new Error("the PostgreSQL migration step did not run; nothing is promoted");
  assert.equal(record.target, target, "the PostgreSQL gate record is for another target");
  assert.equal(record.revision, revision, "the PostgreSQL gate record is for another revision");
  if (record.status !== "passed")
    throw new Error("the PostgreSQL migration step did not pass; nothing is promoted");
}

export async function readGate(target: PostgresTarget): Promise<GateRecord | undefined> {
  try {
    return await readJson<GateRecord>(gateFile(target));
  } catch {
    return undefined;
  }
}

export interface CredentialOptions {
  /** Runs the sealed executable; the default runs it in Docker. */
  runner?: CenterRunner;
  /** The deployment environment that holds the direct URL; the default is this process's environment. */
  environment?: Readonly<Record<string, string | undefined>>;
  /** Attempts of the confirmation after a successful promotion (default 3) and the delay before the second one (default 5 s). */
  confirmAttempts?: number;
  confirmDelayMs?: number;
  /** Reads the runtime slots of the live Worker versions from Cloudflare (readLiveSlots); without it the record decides. */
  liveSlots?: () => Promise<LiveSlots>;
  /** Where the decisions are logged; the default is the job log. */
  log?: (line: string) => void;
}

export type Slot = "a" | "b";

/** The runtime slots of the live Worker versions. */
export interface LiveSlots {
  /** The slots named by the live versions' messages. */
  labelled: Slot[];
  /** Live versions whose message names no slot (deployed before the store, or by hand). */
  unlabelled: number;
  /** Why the live versions could not be read; then the record decides. */
  unreadable?: string;
}

/** The Worker version message that labels a version with its runtime slot (`wrangler deploy --message`). */
export function slotLabel(slot: string): string {
  assert.match(slot, /^[ab]$/u, "a runtime slot is a or b");
  return `runtime-slot=${slot}`;
}

export function slotOfMessage(message: unknown): Slot | undefined {
  if (typeof message !== "string") return undefined;
  return /(?:^|\s)runtime-slot=([ab])(?:\s|$)/u.exec(message)?.[1] as Slot | undefined;
}

/** Runs one Wrangler command with the deployment's token and returns its standard output. */
export type WranglerReader = (args: string[]) => Promise<string>;

/**
 * Reads the live versions of the Worker (`wrangler deployments status --json`) and each version's message
 * (`wrangler versions view <id> --json`, annotation workers/message). Any failure is reported as unreadable, never thrown.
 */
export async function readLiveSlots(
  wrangler: WranglerReader,
  configArguments: readonly string[],
): Promise<LiveSlots> {
  try {
    const deployment = JSON.parse(
      await wrangler(["deployments", "status", "--json", ...configArguments]),
    ) as { versions?: { version_id?: unknown; percentage?: unknown }[] };
    const versions = (deployment.versions ?? []).filter(
      (version) => Number(version.percentage) > 0,
    );
    if (versions.length === 0)
      return { labelled: [], unlabelled: 0, unreadable: "the live deployment lists no version" };
    const live: LiveSlots = { labelled: [], unlabelled: 0 };
    for (const version of versions) {
      const id = String(version.version_id);
      assert.match(id, /^[0-9a-f-]{36}$/u, "unexpected version id");
      const view = JSON.parse(
        await wrangler(["versions", "view", id, "--json", ...configArguments]),
      ) as { annotations?: Record<string, unknown> };
      const slot = slotOfMessage(view.annotations?.["workers/message"]);
      if (slot === undefined) live.unlabelled++;
      else live.labelled.push(slot);
    }
    return live;
  } catch (error) {
    return {
      labelled: [],
      unlabelled: 0,
      unreadable: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * The live slot the rotation must not touch. Live versions on both slots, or on a labelled and an unlabelled credential (a
 * gradual rollout), refuse the rotation; no label, or no reading, leaves the decision to the database record.
 */
export function chooseLiveSlot(live: LiveSlots): { slot?: Slot; note: string } {
  if (live.unreadable !== undefined)
    return {
      note: `the live Worker versions could not be read (${live.unreadable}); the rotation follows the database record`,
    };
  const slots = [...new Set(live.labelled)];
  if (slots.length > 1)
    throw new Error(
      "Live Worker versions use both runtime slots (a gradual rollout), so no slot can be rotated. Finish or roll back the rollout, then re-run the deployment.",
    );
  if (slots.length === 1 && live.unlabelled > 0)
    throw new Error(
      `Live Worker versions use runtime slot ${slots[0]} and an unlabelled credential (a gradual rollout), so no slot can be rotated safely. Finish or roll back the rollout, then re-run the deployment.`,
    );
  if (slots.length === 0)
    return {
      note: "the live Worker version carries no runtime slot label (no earlier store deployment); the rotation follows the database record",
    };
  return {
    slot: slots[0],
    note: `the live Worker version uses runtime slot ${slots[0]} (Cloudflare)`,
  };
}

/** The message of a confirmation that failed after the promotion: the slot, the state left behind and the recovery. */
export function confirmationFailure(
  target: PostgresTarget,
  slot: string,
  attempts: number,
  reason: string,
): string {
  const settings = postgresTargets[target];
  const database =
    settings.databaseName === undefined
      ? ""
      : ` and ARCFORGES_CENTER_DATABASE_NAME=${settings.databaseName}`;
  return [
    `The ${target} Worker version is deployed with the runtime credential of slot ${slot}, but recording that promotion failed after ${attempts} attempts (${reason}).`,
    `The runtime credential record is now behind the live revision. The next deployment reads the live version's slot from Cloudflare and records it before rotating; only if Cloudflare cannot be read then would it rotate slot ${slot}, which the live revision uses, and that revision's new database connections would fail until the next deployment is promoted.`,
    `Recover before the next deployment: run \`arcforges-center admin confirm-runtime-credential --slot ${slot}\` with the owner's direct URL in ARCFORGES_CENTER_MIGRATION_DATABASE_URL, ARCFORGES_CENTER_MODE=official-hosted, ARCFORGES_CENTER_RUNTIME_ROLE=${settings.runtimeRole}${database}, or, as the owner in the Neon SQL editor of that database, \`UPDATE platform.runtime_credential SET promoted_at = now() WHERE slot = '${slot}' AND promoted_at IS NULL\` (docs/postgres-store.md).`,
  ].join(" ");
}

/**
 * Records that the deployment carrying the slot's credential was promoted, with bounded retries; it throws the recovery message
 * of confirmationFailure when every attempt failed, and SlotNeverRotated at once when the database never rotated the slot.
 */
export async function confirmRuntimeCredential(
  target: PostgresTarget,
  image: string,
  slot: string,
  options: CredentialOptions = {},
): Promise<Record<string, unknown>> {
  assert.match(slot, /^[ab]$/u, "the rotation reported no slot");
  const runner = options.runner ?? center;
  const attempts = options.confirmAttempts ?? 3;
  const delay = options.confirmDelayMs ?? 5000;
  const variables = centerVariables(target, options.environment ?? process.env);
  let reason = "";
  for (let attempt = 1; attempt <= attempts; attempt++) {
    try {
      return await runner(image, variables, [
        "admin",
        "confirm-runtime-credential",
        "--slot",
        slot,
      ]);
    } catch (error) {
      if (error instanceof CenterExit && error.status === unknownSlotStatus)
        throw new SlotNeverRotated(`slot ${slot} was never rotated in the ${target} database`);
      // The executable's errors name no credential (its stderr is the job log).
      reason = error instanceof Error ? error.message : String(error);
      if (attempt < attempts) await new Promise((resolve) => setTimeout(resolve, delay * attempt));
    }
  }
  throw new Error(confirmationFailure(target, slot, attempts, reason));
}

/**
 * Rotates the target's runtime credential with the loaded candidate image and hands the Worker secret and the rotation to publish,
 * which uploads it with the version message slotLabel(rotation.slot); the runner-local file is removed afterwards whatever happens.
 * Before rotating it reads the live versions' slots: a labelled live slot is confirmed first (self-healing a record that a
 * cancelled or failed confirmation left behind) and named to the rotation, which then takes the other slot. The rotation proves
 * through the pooled endpoint that the new credential connects as its login role and can neither create a table nor read an
 * ungranted one. Only when publish succeeded is the new slot confirmed as promoted; a failed publish leaves it unconfirmed.
 */
export async function withRuntimeCredential(
  target: PostgresTarget,
  image: string,
  publish: (secrets: Record<string, string>, rotation: Record<string, unknown>) => Promise<void>,
  options: CredentialOptions = {},
): Promise<Record<string, unknown>> {
  const runner = options.runner ?? center;
  const log = options.log ?? ((line: string) => console.log(line));
  const live = options.liveSlots
    ? await options.liveSlots()
    : { labelled: [], unlabelled: 0, unreadable: "not read by this deployment" };
  const choice = chooseLiveSlot(live);
  log(`Runtime credential (${target}): ${choice.note}.`);
  const rotate = ["admin", "rotate-runtime-credential"];
  if (choice.slot !== undefined) {
    try {
      const healed = await confirmRuntimeCredential(target, image, choice.slot, options);
      if (healed.alreadyConfirmed === false)
        log(
          `Runtime credential (${target}): recorded the live slot ${choice.slot} as promoted; the record was behind the live version.`,
        );
    } catch (error) {
      if (!(error instanceof SlotNeverRotated)) throw error;
      // The database was recreated or the target is new: the live version holds no credential for this database.
      log(
        `Runtime credential (${target}): the live version's slot ${choice.slot} was never rotated in this database (it was recreated, or the target is new), so the live version holds no credential for it; nothing to record, and the other slot is rotated.`,
      );
    }
    rotate.push("--live-slot", choice.slot);
  }
  const variables = centerVariables(target, options.environment ?? process.env);
  const directory = await mkdtemp(path.join(os.tmpdir(), "arcforges-runtime-"));
  let rotation: Record<string, unknown>;
  try {
    await chmod(directory, 0o700);
    variables.ARCFORGES_CENTER_RUNTIME_SECRET_FILE = "/secrets/runtime.json";
    // The container runs as the runner's own user so it can write into the private directory.
    const user =
      typeof process.getuid === "function" && typeof process.getgid === "function"
        ? `${process.getuid()}:${process.getgid()}`
        : undefined;
    rotation = await runner(image, variables, rotate, { secretsDirectory: directory, user });
    const secrets = JSON.parse(
      await readFile(path.join(directory, "runtime.json"), "utf8"),
    ) as Record<string, string>;
    assert.deepEqual(
      Object.keys(secrets),
      ["ARCFORGES_CENTER_DATABASE_URL"],
      "unexpected runtime secret file",
    );
    await publish(secrets, rotation);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
  let confirmation: Record<string, unknown>;
  try {
    confirmation = await confirmRuntimeCredential(target, image, String(rotation.slot), options);
  } catch (error) {
    if (!(error instanceof SlotNeverRotated)) throw error;
    // The slot was rotated moments ago: the database changed under the deployment.
    throw new Error(confirmationFailure(target, String(rotation.slot), 1, error.message));
  }
  return { ...rotation, promotedAt: confirmation.promotedAt };
}

async function main(): Promise<void> {
  const [command, flag, value] = process.argv.slice(2);
  if (
    command !== "migrate" ||
    flag !== "--target" ||
    (value !== "production" && value !== "acceptance")
  )
    throw new Error("Use: node tooling/postgres-deploy.ts migrate --target production|acceptance");
  assert.equal(
    process.env.GITHUB_ACTIONS,
    "true",
    "The PostgreSQL deployment step runs in CI only.",
  );
  assert.equal(process.env.GITHUB_REPOSITORY, "ArcForges/Cloud");
  assert.equal(process.env.GITHUB_REF, "refs/heads/main", "Only main deploys.");
  const record = await migrateTarget(value);
  console.log(
    `PostgreSQL ${value}: database ${record.database} at version ${record.version}; applied ${record.applied?.length ?? 0}; runtime role ${record.runtimeRole}; server_version_num ${record.serverVersionNum} (tested major ${record.testedMajor}); C# Hello credential: ${record.helloCredential?.reason}.`,
  );
  for (const warning of record.warnings ?? []) console.warn(`Warning: ${warning}.`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) await main();
