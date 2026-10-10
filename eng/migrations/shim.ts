// SPDX-License-Identifier: AGPL-3.0-only
// The Node shim of the D1 migration tooling (CLOUD.84 U9, U10, S41(1)). It forwards argv and environment to the migrator and makes no
// migration decision: the decisions are the C# rules in src/ArcForges.Cloud.Storage.D1 (MigrationRunner and Deploy), run by the
// `migrate` command of tools/ArcForges.Cloud.Generation.
//
// In a deployment job the migrator is the sealed archive that the candidate job produced (artifacts/candidate/arcforges-migrator.tar).
// The shim checks its SHA-256 against the candidate manifest before it extracts and runs it, so a job never runs a migrator that the
// candidate did not seal. Outside a candidate (local development and the quality job) it runs the same tool project with dotnet run.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
export const sealedArchiveName = "arcforges-migrator.tar";
export const toolProject = "tools/ArcForges.Cloud.Generation";

export interface Invocation {
  command: string;
  args: string[];
  env: NodeJS.ProcessEnv;
}

/** The invocation of the migrator for development: the tool project through dotnet run. Argument order is kept. */
export function developmentInvocation(argv: readonly string[], env: NodeJS.ProcessEnv): Invocation {
  return {
    command: "dotnet",
    args: ["run", "--project", toolProject, "--", "migrate", ...argv],
    env,
  };
}

/** The invocation of a sealed migrator extracted to a directory: its executable, then the migrate command. */
export function sealedInvocation(
  executable: string,
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
): Invocation {
  return { command: executable, args: ["migrate", ...argv], env };
}

/** The SHA-256 of the sealed archive, which must equal the digest the candidate manifest records for it. */
export function verifySealedArchive(archive: Uint8Array, manifestText: string): void {
  const manifest = JSON.parse(manifestText) as { files?: Record<string, string> };
  const expected = manifest.files?.[sealedArchiveName];
  const actual = createHash("sha256").update(archive).digest("hex");
  if (expected === undefined || expected !== actual)
    throw new Error("the sealed migrator does not match the candidate manifest; nothing is run");
}

/**
 * The migrator to run: the sealed archive when a candidate is present (checked and extracted), else the tool project. A deployment job
 * (GitHub Actions running the deploy command) never builds the migrator from source (AGENTS.md; CLOUD.84 S41(1), S45(3)): without the
 * candidate manifest it refuses. Only a local run, or a CI source check that reads the tree, may build from source.
 */
export function prepareInvocation(
  argv: readonly string[],
  env: NodeJS.ProcessEnv,
  root: string,
): Invocation {
  const manifestPath = path.join(root, "artifacts", "candidate", "manifest.json");
  if (!existsSync(manifestPath)) {
    if (env.GITHUB_ACTIONS === "true" && argv[0] === "deploy")
      throw new Error("the candidate manifest is absent in a deployment job; nothing is built or run");
    return developmentInvocation(argv, env);
  }
  const archivePath = path.join(root, "artifacts", "candidate", sealedArchiveName);
  if (!existsSync(archivePath))
    throw new Error("the candidate has no sealed migrator; nothing is run");
  verifySealedArchive(readFileSync(archivePath), readFileSync(manifestPath, "utf8"));
  const directory = mkdtempSync(path.join(root, "artifacts", "migrator-"));
  mkdirSync(directory, { recursive: true });
  // Relative, forward-slash paths keep a drive letter out of the archive arguments (a GNU tar on Windows reads "C:" as a host).
  const posix = (file: string) => path.relative(root, file).split(path.sep).join("/");
  const extracted = spawnSync("tar", ["-xf", posix(archivePath), "-C", posix(directory)], {
    cwd: root,
    stdio: "inherit",
  });
  if (extracted.status !== 0)
    throw new Error("the sealed migrator could not be extracted; nothing is run");
  return sealedInvocation(path.join(directory, "ArcForges.Cloud.Generation"), argv, env);
}

/** Runs the migrator with the given arguments and the process environment, and returns its exit code. */
export function runMigrator(
  argv: readonly string[],
  env: NodeJS.ProcessEnv = process.env,
  root = repositoryRoot,
): number {
  let invocation: Invocation;
  try {
    invocation = prepareInvocation(argv, env, root);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    return 1;
  }
  const result = spawnSync(invocation.command, invocation.args, {
    cwd: root,
    env: invocation.env,
    stdio: "inherit",
  });
  if (result.error) {
    process.stderr.write(`the migrator could not be started (${result.error.name}); nothing is run
`);
    return 1;
  }
  return result.status ?? 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runMigrator(process.argv.slice(2));
}
