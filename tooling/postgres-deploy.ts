// SPDX-License-Identifier: AGPL-3.0-only
// The PostgreSQL step of the protected deployments (AF-CTR-02; docs/postgres-store.md). Before anything is pushed or promoted, the
// deployment runs the sealed candidate image's own center executable (never a rebuilt one) with the migration role's direct
// connection: `admin ensure-database` for the acceptance database, then `migrate`, which applies the embedded migrations under the
// migration lock and reconciles the runtime role's grants; the result is the gate record that promotion requires. At promotion the
// runtime credential is rotated in the same process that uploads it as the Worker secret: the executable writes the pooled runtime
// URL into a runner-local file outside the artifact directories, Wrangler uploads it, and the file is removed. No value of a
// credential is printed, logged, written to an artifact or passed on a command line: Docker receives the variables by name from the
// environment of its own process.
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
 * `proof` Worker) has its own database and its own runtime role in the same Neon project, so neither credential reaches the other.
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
      else reject(new Error(`arcforges-center ${command.join(" ")} exited with code ${code}.`));
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
    await loadCandidateImage(candidate);
    if (postgresTargets[target].ensureDatabase) {
      const ensured = await center(candidate.image, variables, ["admin", "ensure-database"]);
      record.databaseCreated = ensured.created === true;
    }
    const result = await center(candidate.image, variables, ["migrate"]);
    assert.equal(result.state, "current", "the database is not at the build's migrations");
    assert.equal(result.grants, "reconciled", "the runtime role's grants were not reconciled");
    record.database = String(result.database);
    record.version = Number(result.version);
    record.runtimeRole = String(result.runtimeRole);
    record.applied = Array.isArray(result.ran)
      ? (result.ran as { name?: unknown }[]).map((step) => String(step.name))
      : [];
    record.status = "passed";
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

/**
 * Rotates the target's runtime credential with the loaded candidate image and hands the Worker secret to publish, which uploads
 * it; the runner-local file is removed afterwards whatever happens. The rotation proves through the pooled endpoint that the new
 * credential connects as its login role and can neither create a table nor read an ungranted one.
 */
export async function withRuntimeCredential(
  target: PostgresTarget,
  image: string,
  publish: (secrets: Record<string, string>) => Promise<void>,
): Promise<Record<string, unknown>> {
  const variables = centerVariables(target, process.env);
  const directory = await mkdtemp(path.join(os.tmpdir(), "arcforges-runtime-"));
  try {
    await chmod(directory, 0o700);
    variables.ARCFORGES_CENTER_RUNTIME_SECRET_FILE = "/secrets/runtime.json";
    // The container runs as the runner's own user so it can write into the private directory.
    const user =
      typeof process.getuid === "function" && typeof process.getgid === "function"
        ? `${process.getuid()}:${process.getgid()}`
        : undefined;
    const rotation = await center(image, variables, ["admin", "rotate-runtime-credential"], {
      secretsDirectory: directory,
      user,
    });
    const secrets = JSON.parse(
      await readFile(path.join(directory, "runtime.json"), "utf8"),
    ) as Record<string, string>;
    assert.deepEqual(
      Object.keys(secrets),
      ["ARCFORGES_CENTER_DATABASE_URL"],
      "unexpected runtime secret file",
    );
    await publish(secrets);
    return rotation;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
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
    `PostgreSQL ${value}: database ${record.database} at version ${record.version}; applied ${record.applied?.length ?? 0}; runtime role ${record.runtimeRole}.`,
  );
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) await main();
